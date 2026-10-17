#!/system/bin/sh
MODDIR=${0%/*}
[ -f "$MODDIR/guard.pid" ] || exit 0
GUARD_PID=$(cat "$MODDIR/guard.pid")
case "$GUARD_PID" in ''|*[!0-9]*) exit 0 ;; esac
GUARD_EXE=$(readlink "/proc/$GUARD_PID/exe" 2>/dev/null)
case "$GUARD_EXE" in "$MODDIR/bin/netlink-privacy-guard"|"$MODDIR/bin/netlink-privacy-guard (deleted)") kill "$GUARD_PID" 2>/dev/null ;; esac
