#!/system/bin/sh
MODDIR=${0%/*}
"$MODDIR/bin/netlink-privacy-guard" --check
tail -15 "$MODDIR/guard.log"
