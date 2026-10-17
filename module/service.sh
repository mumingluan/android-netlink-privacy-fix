#!/system/bin/sh
MODDIR=${0%/*}
if [ -f "$MODDIR/guard.pid" ]; then
  GUARD_PID=$(cat "$MODDIR/guard.pid")
  case "$GUARD_PID" in ''|*[!0-9]*) ;; *)
    [ "$(readlink "/proc/$GUARD_PID/exe" 2>/dev/null)" = "$MODDIR/bin/netlink-privacy-guard" ] && exit 0
  esac
fi
umask 077
"$MODDIR/bin/netlink-privacy-guard" --watch >> "$MODDIR/guard.log" 2>&1 < /dev/null &
echo $! > "$MODDIR/guard.pid"
