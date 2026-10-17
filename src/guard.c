#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "policy_header.h"

#define MAX_POLICY (32u * 1024u * 1024u)
static volatile sig_atomic_t stopping;
static int watch_fd = -1;
static char state_dir[1024];

static void logline(const char *message) {
    time_t now = time(NULL); struct tm tm; char stamp[64];
    localtime_r(&now, &tm); strftime(stamp, sizeof(stamp), "%F %T", &tm);
    printf("%s %s\n", stamp, message); fflush(stdout);
}
static void stop(int sig) { (void)sig; stopping = 1; if (watch_fd >= 0) close(watch_fd); }
static unsigned char *read_file(const char *path, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return NULL;
    size_t used = 0, capacity = 4096; unsigned char *data = malloc(capacity);
    if (!data) { close(fd); return NULL; }
    for (;;) {
        if (used == capacity) {
            if (capacity >= MAX_POLICY) { free(data); close(fd); return NULL; }
            capacity *= 2; void *next = realloc(data, capacity);
            if (!next) { free(data); close(fd); return NULL; } data = next;
        }
        ssize_t n = read(fd, data + used, capacity - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { free(data); close(fd); return NULL; }
        if (!n) break; used += n;
    }
    close(fd); *length = used; return data;
}
static bool config_offset(const unsigned char *data, size_t length, size_t *offset) {
    struct policy_header header;
    if (!policy_header_read(data,length,&header)) return false;
    *offset=header.config_offset;return true;
}

// Read the real enforcement result in a disposable ordinary app domain, not the root domain.
// 0 protected, 2 exposed, 3 inconclusive. The parent keeps its credentials and SELinux domain.
static int probe_child(void) {
    void *lib = dlopen("libselinux.so", RTLD_NOW);
    int (*setcontext)(const char *) = lib ? dlsym(lib, "setcon") : NULL;
    if (!setcontext || setgroups(0, NULL) || setgid(65534) || setuid(65534) ||
        setcontext("u:r:untrusted_app:s0")) return 3;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return 3;
    // send() autobinds. An explicit bind() would test a different SELinux permission.
    struct { struct nlmsghdr header; struct ifinfomsg link; } request = {
        .header = { .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                    .nlmsg_type = RTM_GETLINK, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                    .nlmsg_seq = 1 },
        .link = { .ifi_family = AF_UNSPEC }
    };
    int n = send(fd, &request, sizeof(request), 0); int error = errno; close(fd);
    if (n >= 0) return 2;
    return error == EACCES || error == EPERM ? 0 : 3;
}
static int probe(void) {
    pid_t child = fork(); if (child < 0) return 3;
    if (!child) { signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); _exit(probe_child()); }
    int status; while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 3;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
}
static bool enforcing(void) {
    size_t size; unsigned char *data = read_file("/sys/fs/selinux/enforce", &size);
    bool result = data && size && data[0] == '1'; free(data); return result;
}
static bool restore_flags(void) {
    const char *stock_paths[] = { "/odm/etc/selinux/precompiled_sepolicy",
                                 "/vendor/etc/selinux/precompiled_sepolicy" };
    uint32_t stock_flags = 0;
    for (unsigned i = 0; i < sizeof(stock_paths)/sizeof(*stock_paths); ++i) {
        size_t length = 0, offset = 0; unsigned char *stock = read_file(stock_paths[i], &length);
        if (stock && config_offset(stock, length, &offset)) stock_flags=policy_le32(stock+offset);
        free(stock); if ((stock_flags & ANDROID_FLAGS) == ANDROID_FLAGS) break;
    }
    if ((stock_flags & ANDROID_FLAGS) != ANDROID_FLAGS) {
        logline("Stock policy does not enable both Android flags; no change made"); return false;
    }
    size_t length = 0, offset = 0;
    unsigned char *policy = read_file("/sys/fs/selinux/policy", &length);
    if (!policy || !config_offset(policy, length, &offset)) {
        free(policy); logline("Cannot validate exported policy; no change made"); return false;
    }
    char backup[1200]; snprintf(backup, sizeof(backup), "%s/policy-before-last-restore.bin", state_dir);
    int fd = open(backup, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, policy, length) != (ssize_t)length) {
        if (fd >= 0) close(fd); free(policy); logline("Backup failed; no change made"); return false;
    }
    fsync(fd); close(fd);
    uint32_t old_flags=policy_le32(policy+offset);
    uint32_t flags = (old_flags & ~ANDROID_FLAGS) | (stock_flags & ANDROID_FLAGS);
    policy_config_write(policy,offset,flags);
    fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    // SELinux expects the complete binary policy in one write transaction.
    ssize_t written = fd >= 0 ? write(fd, policy, length) : -1;
    int error = errno; if (fd >= 0) close(fd); free(policy);
    if (written != (ssize_t)length) {
        char text[256]; snprintf(text, sizeof(text), "Policy load rejected: %s", strerror(error));
        logline(text); return false;
    }
    logline("Restored stock Android Netlink flags; all current access rules retained"); return true;
}
static int ensure(void) {
    if (!enforcing()) { logline("SELinux is permissive; not changing enforcement mode or policy"); return 3; }
    int result = probe();
    if (result == 0) { logline("Protected: ordinary app RTM_GETLINK is denied"); return 0; }
    if (result != 2) { logline("App-domain probe inconclusive; no change made"); return 3; }
    logline("Exposed: ordinary app RTM_GETLINK accepted");
    if (!restore_flags()) return 3;
    result = probe();
    logline(result == 0 ? "Verified: ordinary app RTM_GETLINK is denied" : "Verification failed; no retry loop");
    return result;
}
int main(int argc, char **argv) {
    bool check_only = argc > 1 && !strcmp(argv[1], "--check");
    bool watch = argc > 1 && !strcmp(argv[1], "--watch");
    if (getuid() != 0 || argc < 2 || (!check_only && !watch && strcmp(argv[1], "--once"))) {
        fprintf(stderr, "Usage (root): %s --check | --once | --watch\n", argv[0]); return 1;
    }
    if (check_only) { int result = probe(); printf("%s\n", result == 0 ? "PROTECTED" : result == 2 ? "EXPOSED" : "UNKNOWN"); return result; }
    // Module installers can pass extra pipe descriptors. Do not keep their sessions open.
    if (watch) {
        (void)setsid(); (void)chdir("/");
        if (syscall(__NR_close_range, 3u, ~0u, 0u) < 0)
            for (int fd = 3; fd < 4096; ++fd) close(fd);
    }
    char exe[1024]; ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if (n < 0) return 1; exe[n] = 0;
    char *slash = strrchr(exe, '/'); if (!slash) return 1; *slash = 0;
    slash = strrchr(exe, '/'); if (!slash) return 1; *slash = 0;
    snprintf(state_dir, sizeof(state_dir), "%s/state", exe); mkdir(state_dir, 0700);
    char lockpath[1200]; snprintf(lockpath, sizeof(lockpath), "%s/guard.lock", state_dir);
    int lock = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) { logline("Another guard already running"); return 1; }
    if (!watch) return ensure();
    watch_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SELINUX);
    struct sockaddr_nl address = { .nl_family = AF_NETLINK, .nl_groups = 1 };
    if (watch_fd < 0 || bind(watch_fd, (void *)&address, sizeof(address))) {
        logline("Cannot subscribe to SELinux policy events; performing one check only"); return ensure();
    }
    signal(SIGTERM, stop); signal(SIGINT, stop); signal(SIGHUP, SIG_IGN);
    logline("Watching SELinux policy events; no periodic polling"); ensure();
    while (!stopping) {
        unsigned char data[8192]; ssize_t size = recv(watch_fd, data, sizeof(data), 0);
        if (size < 0) { if (errno == EINTR) continue; break; }
        bool relevant = false;
        for (struct nlmsghdr *h = (void *)data; NLMSG_OK(h, size); h = NLMSG_NEXT(h, size))
            if (h->nlmsg_type == 0x10 || h->nlmsg_type == 0x11) relevant = true;
        if (relevant) ensure();
    }
    logline("Guard stopped"); return 0;
}
