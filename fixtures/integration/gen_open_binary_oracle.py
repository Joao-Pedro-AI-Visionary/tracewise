#!/usr/bin/env python3
"""Record the ORIGINAL REA's answer to `open_binary` for every target of open_binary_cases.json.

usage: gen_open_binary_oracle.py            (writes open_binary_oracle.json next to this file)

Each case runs in its own REA server process, with the fixtures of this checkout. The checkout
path is stored as `$ROOT` so the file does not depend on where it was generated. `REA_NODE` and
`REA_ROOT` select the node binary and the compiled REA (defaults: the build machine's).
"""
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
FIXTURES = os.path.join(ROOT, "fixtures", "native_static")
NODE = os.environ.get("REA_NODE", "node")
REA_ROOT = os.environ.get("REA_ROOT", "/workspace/rea-map/src")


def open_binary(path):
    process = subprocess.Popen(
        [NODE, os.path.join(REA_ROOT, "scripts/rea.mjs"), "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=REA_ROOT,
    )
    counter = [0]

    def request(method, params=None, notify=False):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if not notify:
            counter[0] += 1
            message["id"] = counter[0]
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        if notify:
            return None
        while True:
            reply = json.loads(process.stdout.readline())
            if reply.get("id") == counter[0]:
                return reply

    request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "oracle", "version": "1"}})
    request("notifications/initialized", notify=True)
    reply = request("tools/call", {"name": "open_binary", "arguments": {"path": path}})
    process.kill()
    return reply.get("result", reply)


def main():
    cases = json.load(open(os.path.join(HERE, "open_binary_cases.json")))
    out = []
    for case in cases:
        path = case["path"].replace("$FIX", FIXTURES)
        result = open_binary(path)
        text = json.dumps(result).replace(ROOT, "$ROOT")
        out.append({"id": case["id"], "path": case["path"], "result": json.loads(text)})
    with open(os.path.join(HERE, "open_binary_oracle.json"), "w") as handle:
        json.dump(out, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
