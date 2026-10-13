#!/usr/bin/env python3
"""Run every scenario of scenarios.json against the ORIGINAL REA server (the oracle).

usage: gen_oracle.py [scenario-id-prefix ...]
Writes oracle/<id>.json with one MCP result per call. Paths in the results are the
absolute worktree paths; the Rust test normalizes that prefix.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Paths of the machine that generated the committed oracle files; override with the environment.
NODE = os.environ.get("REA_NODE", "node")
REA_ROOT = os.environ.get("REA_ROOT", "/workspace/rea-map/src")
PWNTOOLS_PYTHON = os.environ.get("REA_PWNTOOLS_PYTHON", "/workspace/tools/pwntools-4.15.0/venv/bin/python")


def resolve(value, results):
    """Replace {"$result": n} by the structured content of call n of this scenario."""
    if isinstance(value, dict):
        if "$result" in value:
            base = results[value["$result"]].get("structuredContent")
            if value.get("inner"):
                base = base["normalized_result"]["substeps"][0]["evidence"]
            base = dict(base)
            for key in value.get("drop", []):
                base.pop(key, None)
            for key, item in value.get("set", {}).items():
                base[key] = item
            return base
        return {k: resolve(v, results) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, results) for v in value]
    return value


def session(calls, offset=0):
    os.environ["REA_PWNTOOLS_PYTHON"] = PWNTOOLS_PYTHON
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
    results = []
    for call in calls:
        arguments = resolve(call.get("arguments", {}), results[offset:])
        reply = request("tools/call", {"name": call["name"], "arguments": arguments})
        results.append(reply.get("result", reply))
    process.kill()
    return results


def substitute(value):
    if isinstance(value, str):
        return value.replace("$FIX", HERE)
    if isinstance(value, list):
        return [substitute(v) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v) for k, v in value.items()}
    return value


def main():
    scenarios = json.load(open(os.path.join(HERE, "scenarios.json"), encoding="utf-8"))
    prefixes = sys.argv[1:]
    os.makedirs(os.path.join(HERE, "oracle"), exist_ok=True)
    for scenario in scenarios:
        if prefixes and not any(scenario["id"].startswith(p) for p in prefixes):
            continue
        calls = []
        if scenario.get("open"):
            calls.append({"name": "open_binary", "arguments": {"path": os.path.join(HERE, scenario["open"])}})
        calls.extend(substitute(scenario["calls"]))
        offset = 1 if scenario.get("open") else 0
        results = session(calls, offset)
        if scenario.get("open"):
            results = results[1:]
        with open(os.path.join(HERE, "oracle", scenario["id"] + ".json"), "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=1, ensure_ascii=False)
        print(scenario["id"], "ok" if not any(r.get("isError") for r in results) else "error")


if __name__ == "__main__":
    main()
