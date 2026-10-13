#!/usr/bin/env python3
"""Drive the ORIGINAL REA MCP server over stdio with an ordered list of tool calls
that share one session (open_binary first, then the engine tools).

usage: oracle_session.py <calls.json> <out.json>

calls.json: [{"name": "open_binary", "arguments": {...}}, ...]
out.json:   [{"name":..., "arguments":..., "result": <MCP CallToolResult>}, ...]

The environment is inherited, so pass GHIDRA_INSTALL_DIR / JAVA_HOME (real Ghidra) or
HOPPER_LAUNCHER_PATH (fake Hopper; also REA_ORACLE_NODE_ARGS='["--import","<force_darwin.mjs>"]') or
REA_IDA_MCP_CONFIG (fake IDA) exactly like the Rust server reads them.
"""
import json
import os
import subprocess
import sys

NODE = "/tmp/node-v22.20.0-linux-x64/bin/node"
REA = "/workspace/rea-map/src"
extra = json.loads(os.environ.get("REA_ORACLE_NODE_ARGS", "[]"))
p = subprocess.Popen(
    [NODE, *extra, REA + "/scripts/rea.mjs", "mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=open(os.environ["REA_ORACLE_STDERR"], "w") if os.environ.get("REA_ORACLE_STDERR") else subprocess.DEVNULL,
    text=True,
    cwd=REA,
)
i = 0


def rq(method, params=None, notify=False):
    global i
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if not notify:
        i += 1
        msg["id"] = i
    p.stdin.write(json.dumps(msg) + "\n")
    p.stdin.flush()
    if notify:
        return None
    while True:
        line = p.stdout.readline()
        if not line:
            raise SystemExit("oracle closed stdout")
        r = json.loads(line)
        if r.get("id") == i:
            return r


rq("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "oracle", "version": "1"}})
rq("notifications/initialized", notify=True)
calls = json.load(open(sys.argv[1], encoding="utf-8"))
out = []
try:
    for c in calls:
        r = rq("tools/call", {"name": c["name"], "arguments": c.get("arguments", {})})
        out.append({"name": c["name"], "arguments": c.get("arguments", {}), "result": r.get("result", r)})
finally:
    try:
        rq("tools/call", {"name": "close_binary", "arguments": {}})
    except BaseException:
        pass
    p.kill()
    if sys.argv[2].endswith(".gz"):
        import gzip
        with open(sys.argv[2], "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as z:
                z.write(json.dumps(out, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    else:
        json.dump(out, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
