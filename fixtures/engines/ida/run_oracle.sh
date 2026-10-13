#!/usr/bin/env bash
# Regenerate an IDA parity golden with the ORIGINAL REA (the oracle) talking to the fake
# upstream server in fake_ida_mcp.mjs.
#
#   fixtures/engines/ida/run_oracle.sh <registration> <calls.json> <out.json>
#
# <registration> is `legacy` (REA's attached mode), `modern` (its headless mode), `none` (no
# REA_IDA_MCP_CONFIG at all) or `file:NAME` (a registration NAME that already exists in the
# private directory). The registration, the copy of sample_elf and the fake live in a fixed
# private directory so that every path that reaches Evidence (artifact location, registration
# digest, profile digest) is identical for the oracle and for the Rust test, wherever the
# repository is checked out. The environment is inherited, so a caller can set the
# FAKE_IDA_* switches of the fake server. `generate_variants.py` drives this script for the
# fault and registration variants.
set -euo pipefail
profile=${1:?registration legacy|modern|none|file:NAME}
calls=$(realpath "${2:?calls.json}")
out=$(realpath -m "${3:?out.json}")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
dir=/tmp/tracewise-ida-parity

mkdir -p -m 700 "$dir"
cp "$repo/fixtures/engines/sample_elf" "$dir/sample_elf"
cp "$here/fake_ida_mcp.mjs" "$dir/fake_ida_mcp.mjs"

registration=""
case "$profile" in
  legacy|modern)
    if [ "$profile" = legacy ]; then mode=attached; else mode=headless; fi
    printf '{"command":"node","args":["%s/fake_ida_mcp.mjs","--profile","%s"],"mode":"%s"}\n' \
      "$dir" "$profile" "$mode" >"$dir/$profile.json"
    registration="$dir/$profile.json"
    ;;
  none) ;;
  file:*) registration="$dir/${profile#file:}" ;;
  *) echo "unknown registration $profile" >&2; exit 2 ;;
esac

# IDA must be the only candidate: no Ghidra, no Hopper, no provider selector.
unset GHIDRA_INSTALL_DIR JAVA_HOME REA_ANALYSIS_PROVIDER HOPPER_LAUNCHER_PATH REA_IDA_MCP_CONFIG
if [ -n "$registration" ]; then export REA_IDA_MCP_CONFIG="$registration"; fi
python3 "$repo/fixtures/engines/oracle_session.py" "$calls" "$out"
