# 参考来源

SELinux policydb 文件格式与 Android Netlink 标志参考 [Android kernel/common](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/security/selinux/)。内核为 GPL-2.0-only；本仓库不包含或链接该内核源码。

模块实现为独立的用户态程序，使用 NDK 系统头文件和运行期的系统 libselinux 接口。
