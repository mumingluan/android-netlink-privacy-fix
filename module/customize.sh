#!/system/bin/sh
[ "$ARCH" = arm64 ] || abort "This build requires arm64."
[ "$API" -ge 33 ] || abort "This build requires Android 13 or later."
OLD_DIR=/data/adb/modules/android_netlink_privacy_fix
if [ -f "$OLD_DIR/guard.pid" ]; then
  OLD_PID=$(cat "$OLD_DIR/guard.pid")
  case "$OLD_PID" in ''|*[!0-9]*) ;; *)
    OLD_EXE=$(readlink "/proc/$OLD_PID/exe" 2>/dev/null)
    case "$OLD_EXE" in "$OLD_DIR/bin/netlink-privacy-guard"|"$OLD_DIR/bin/netlink-privacy-guard (deleted)") kill "$OLD_PID" 2>/dev/null ;; esac
  esac
fi
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/netlink-privacy-guard" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
MODULE_HOT_INSTALL_REQUEST=true
MODULE_HOT_RUN_SCRIPT=service.sh
ui_print "- Restores Android Netlink privacy flags from this phone's stock policy"
ui_print "- Existing access rules and enforcement mode are preserved"
ui_print "- Event-driven guard; no periodic polling"
