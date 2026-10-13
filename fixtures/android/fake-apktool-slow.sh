#!/bin/sh
# Test double for the Apktool launcher: a wrapper that does NOT exec, so a slow
# decode leaves a grandchild behind unless the whole process group is killed.
# Records "<wrapper pid>" and "<background sleep pid>" in $SLOW_PIDFILE.
if [ "$1" = "--version" ]; then echo "9.9.9-slow"; exit 0; fi
echo "$$" > "$SLOW_PIDFILE"
sleep 300 &
echo "$!" >> "$SLOW_PIDFILE"
sleep 300
