#!/usr/bin/env python3
"""Run REA's unchanged pwntools bridge adapters directly, WITHOUT the 3 GiB address-space limit.

REA runs `bridge/pwntools/*_impl.py` under RLIMIT_AS=3 GiB. pwntools' PLT inference
needs more than that for the second and third Unicorn instance, so under REA the
`linkage.plt` map is incomplete on this host ("Could not populate PLT: ..."). This
script produces the unconstrained upstream result so the tracewise port can be compared
with what the adapter computes when its emulation completes.

usage: gen_bridge_reference.py <layout|crash> <python> <out-dir> <file>...
"""
import json
import os
import subprocess
import sys
import tempfile

BRIDGE = "/workspace/rea-map/src/bridge/pwntools"


def run(kind, python, path):
    impl = os.path.join(BRIDGE, "layout_impl.py" if kind == "layout" else "recorded_crash_impl.py")
    with tempfile.TemporaryDirectory() as root:
        request = os.path.join(root, "request.json")
        reply = os.path.join(root, "reply.json")
        with open(request, "w") as handle:
            json.dump({"snapshot_path": path, "reply_path": reply}, handle)
        # The bridge's own resource limiter is skipped: call inspect directly.
        driver = (
            "import json,sys,os\n"
            "from pathlib import Path\n"
            "os.environ['PWNLIB_NOTERM']='1'\n"
            "g={'__name__':'bridge_impl','__file__':%r}\n"
            "exec(compile(open(%r).read(),%r,'exec'),g)\n"
            "inspect=g['inspect_elf'] if 'inspect_elf' in g else g['inspect_core']\n"
            "failure=g['LayoutFailure'] if 'LayoutFailure' in g else g['CoreFailure']\n"
            "try:\n"
            "    value=inspect(Path(%r), Path(%r))\n"
            "    print(json.dumps({'ok':True,'value':value}))\n"
            "except failure as e:\n"
            "    print(json.dumps({'ok':False,'reason':e.reason,'message':str(e)}))\n"
        ) % (impl, impl, impl, path, os.path.join(root, "cache"))
        process = subprocess.run([python, "-I", "-c", driver], capture_output=True, text=True)
        try:
            reply_value = json.loads(process.stdout.strip().splitlines()[-1])
        except Exception:
            reply_value = {"ok": False, "reason": "driver", "message": process.stdout + process.stderr}
        reply_value["stderr"] = process.stderr
        return reply_value


def main():
    kind, python, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)
    for path in sys.argv[4:]:
        result = run(kind, python, path)
        with open(os.path.join(out_dir, os.path.basename(path) + ".json"), "w") as handle:
            json.dump(result, handle, indent=1)
        print(os.path.basename(path), result.get("ok"), repr(result.get("stderr", ""))[:120])


if __name__ == "__main__":
    main()
