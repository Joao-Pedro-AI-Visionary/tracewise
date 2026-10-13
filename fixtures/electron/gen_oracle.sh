#!/bin/bash
# Regenerates fixtures/electron/oracle_capture_electron_scenario.json with the ORIGINAL REA server.
#
#   fixtures/electron/gen_oracle.sh [out.json]
#
# Needs: the REA checkout at /workspace/rea-map (built), Electron 44.7.0 at
# /workspace/tools/electron-44.7.0, Xvfb. REA is run against a private X display so no
# window reaches the desktop. The oracle server leaks its Electron processes on Linux
# (its cleanup cannot read the run token Chromium rewrites in /proc/<pid>/environ), so this script
# kills every process of the pinned Electron when it is done. Do not run it while the Rust tests
# that launch Electron are running.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELECTRON="${TRACEWISE_TEST_ELECTRON:-/workspace/tools/electron-44.7.0/electron}"
APP="$HERE/readiness_app"
OUT="${1:-$HERE/oracle_capture_electron_scenario.json}"
SCENARIO="$HERE/scenario_readiness.json"
WORK="$(mktemp -d)"
trap 'pkill -KILL -f "$ELECTRON" 2>/dev/null || true; pkill -f "Xvfb :$NUM" 2>/dev/null || true; rm -rf "$WORK"' EXIT
NUM=$((300 + RANDOM % 400))
Xvfb ":$NUM" -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 &
sleep 1.5
sed -e "s|{ELECTRON}|$ELECTRON|g" -e "s|{APP}|$APP|g" "$SCENARIO" > "$WORK/scenario.json"
DISPLAY=":$NUM" python3 "$HERE/../rea_oracle.py" capture_electron_scenario "@$WORK/scenario.json" "$WORK/raw.json"
# Paths of this checkout and of the Electron become placeholders so the golden does not depend on where it was made.
sed -e "s|$APP|{APP}|g" -e "s|$ELECTRON|{ELECTRON}|g" "$WORK/raw.json" > "$OUT"
echo "wrote $OUT"
