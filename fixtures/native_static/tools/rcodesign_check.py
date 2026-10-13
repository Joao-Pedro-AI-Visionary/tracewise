#!/usr/bin/env python3
"""Manual cross-check of inspect_signature against rcodesign (apple-codesign 0.29.0).

NOT reproducible from the repository: it walks Mach-O files that happen to exist on the machine
(node-pty prebuilds and similar) and needs `rcodesign` (cargo install apple-codesign --locked) and a
built `target/debug/tracewise`. It compares signed state, CDHash, identifier, team and
hardened-runtime flag. Usage: rcodesign_check.py <rcodesign> <file>...
"""
import json
import re
import subprocess
import sys

HERE = __file__.rsplit("/", 1)[0]


def tracewise(path):
    calls = [{"name": "open_binary", "arguments": {"path": path}}, {"name": "inspect_signature", "arguments": {}}]
    out = subprocess.run([sys.executable, HERE + "/tw_session.py", json.dumps(calls), "/tmp/rcs.json"], check=True, capture_output=True)
    result = json.load(open("/tmp/rcs.json"))[1]
    return result.get("structuredContent", {}).get("normalized_result")


def main():
    rcodesign, files = sys.argv[1], sys.argv[2:]
    bad = checked = compared_hashes = 0
    for path in files:
        info = subprocess.run([rcodesign, "print-signature-info", path], capture_output=True, text=True).stdout
        mine = tracewise(path)
        if mine is None:
            continue
        checked += 1
        signed = "signature: null" not in info
        if mine["signed"] != signed:
            print("SIGNED MISMATCH", path)
            bad += 1
            continue
        if not signed:
            continue
        # `rcodesign` prints the code directory digests as `sha256: <64 hex>` lines; the first one that
        # follows `file_sha256` is the code directory hash that our CDHash truncates to 20 bytes.
        cd = re.search(r"(?m)^\s+sha256: ([0-9a-f]{64})$", info)
        ident = re.search(r"identifier: (.+)", info)
        if ident and ident.group(1).strip() != mine["identifier"]:
            print("IDENTIFIER MISMATCH", path, ident.group(1), mine["identifier"])
            bad += 1
        if cd and mine["cdhashes"]:
            compared_hashes += 1
            if not cd.group(1).startswith(mine["cdhashes"][0]):
                print("CDHASH MISMATCH", path, cd.group(1)[:40], mine["cdhashes"][0])
                bad += 1
        runtime = "RUNTIME" in info
        if bool(mine["hardened_runtime"]) != runtime:
            print("RUNTIME MISMATCH", path)
            bad += 1
    print("checked", checked, "cdhashes compared", compared_hashes, "bad", bad)


main()
