#!/usr/bin/env python3
"""Call the ORIGINAL REA MCP server over stdio for many calls in one session.

usage: oracle_batch.py <calls.json> <out.json>
calls.json is a list of {"tool": str, "args": object}; out.json receives the
list of MCP results in the same order. Used by the adb admission/validation
parity tests, where the calls have no device side effects.
"""
import json
import subprocess
import sys

NODE = "/tmp/node-v22.20.0-linux-x64/bin/node"
REA = "/workspace/rea-map/src/scripts/rea.mjs"

proc = subprocess.Popen(
    [NODE, REA, "mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    cwd="/workspace/rea-map/src",
)
counter = 0


def request(method, params=None, notify=False):
    global counter
    message = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    if not notify:
        counter += 1
        message["id"] = counter
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    if notify:
        return None
    while True:
        reply = json.loads(proc.stdout.readline())
        if reply.get("id") == counter:
            return reply


request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "oracle", "version": "1"}})
request("notifications/initialized", notify=True)
calls = json.load(open(sys.argv[1], encoding="utf-8"))
results = []
for call in calls:
    reply = request("tools/call", {"name": call["tool"], "arguments": call["args"]})
    results.append(reply.get("result", reply))
json.dump(results, open(sys.argv[2], "w", encoding="utf-8"), indent=1)
proc.kill()
