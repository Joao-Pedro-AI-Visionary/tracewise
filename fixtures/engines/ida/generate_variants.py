#!/usr/bin/env python3
"""Regenerate a variants golden with the ORIGINAL REA (the oracle).

usage: generate_variants.py <variants.json> <out.json>

variants.json: [{"name", "profile", "env": {...}, "files": {name: text}, "server": {...}, "calls": [...]}, ...]
  profile  legacy | modern | none | file:NAME  (see run_oracle.sh)
  env      FAKE_IDA_* switches of the fake server, exported for the REA process
  files    registration files to create in the fixed private directory first
  server   optional {"profile", "port"}: serve the fake over HTTP on that port while REA runs
out.json:  {name: [{"name", "arguments", "result"}, ...], ...}
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PARITY = "/tmp/tracewise-ida-parity"

variants = json.load(open(sys.argv[1], encoding="utf-8"))
os.makedirs(PARITY, mode=0o700, exist_ok=True)
results = {}
for variant in variants:
    for name, text in variant.get("files", {}).items():
        with open(os.path.join(PARITY, name), "w", encoding="utf-8") as handle:
            handle.write(text)
    with tempfile.TemporaryDirectory() as scratch:
        calls = os.path.join(scratch, "calls.json")
        out = os.path.join(scratch, "out.json")
        json.dump(variant["calls"], open(calls, "w", encoding="utf-8"))
        env = dict(os.environ, **variant.get("env", {}))
        server = None
        if "server" in variant:
            # An HTTP registration needs the fake listening before REA connects.
            spec = variant["server"]
            server = subprocess.Popen(
                ["node", os.path.join(HERE, "fake_ida_mcp.mjs"), "--profile", spec["profile"], "--http", str(spec["port"])],
                stdout=subprocess.PIPE,
                env=env,
            )
            if not server.stdout.readline().startswith(b"listening"):
                raise SystemExit("the fake HTTP server did not start")
        try:
            subprocess.run(["bash", os.path.join(HERE, "run_oracle.sh"), variant["profile"], calls, out], check=True, env=env)
        finally:
            if server is not None:
                server.terminate()
                server.wait()
        results[variant["name"]] = json.load(open(out, encoding="utf-8"))
json.dump(results, open(sys.argv[2], "w", encoding="utf-8"), indent=1)
