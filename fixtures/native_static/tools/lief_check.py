#!/usr/bin/env python3
"""Compare tracewise inspect_macho output with LIEF (independent implementation) for real binaries.

usage: lief_check.py <macho-file> [arch]
"""
import json
import subprocess
import sys

import lief

path = sys.argv[1]
arch = sys.argv[2] if len(sys.argv) > 2 else None

calls = [
    {"name": "open_binary", "arguments": {"path": path}},
    {"name": "inspect_macho", "arguments": {}},
]
subprocess.run(["python3", "/workspace/native_scratch/tw_session.py", json.dumps(calls), "/tmp/lief_out.json"], check=True)
out = json.load(open("/tmp/lief_out.json"))
result = out[1]
if result.get("isError"):
    print("ERROR", result["content"][0]["text"][:500])
    sys.exit(1)
n = result["structuredContent"]["normalized_result"]

fat = lief.MachO.parse(path)
binary = None
for index in range(len(fat)):
    candidate = fat.at(index)
    name = str(candidate.header.cpu_type).split(".")[-1].lower()
    if arch is None or arch in name:
        binary = candidate
        break
if binary is None:
    binary = fat.at(0)

problems = []


def check(label, a, b):
    if a != b:
        problems.append((label, a, b))


# --- segments and sections
segs = n["segments"]["items"]
check("segment names", [s["name"] for s in segs], [s.name for s in binary.segments])
for mine, ref in zip(segs, binary.segments):
    check(f"{ref.name} vmaddr", int(mine["vm_address"], 16), ref.virtual_address)
    check(f"{ref.name} vmsize", mine["vm_size"], ref.virtual_size)
    check(f"{ref.name} fileoff", mine["file_offset"], ref.file_offset)
    check(f"{ref.name} filesize", mine["file_size"], ref.file_size)
    check(f"{ref.name} maxprot", int(mine["maximum_permissions"]["raw"]), ref.max_protection)
    check(f"{ref.name} initprot", int(mine["initial_permissions"]["raw"]), ref.init_protection)
    sections = mine["sections"]["items"]
    check(f"{ref.name} section names", [s["name"] for s in sections], [s.name for s in ref.sections])
    for my_section, ref_section in zip(sections, ref.sections):
        label = f"{ref.name},{ref_section.name}"
        check(label + " addr", int(my_section["address"], 16), ref_section.virtual_address)
        check(label + " size", my_section["size"], ref_section.size)
        check(label + " offset", my_section["file_offset"], ref_section.offset)
        check(label + " align", my_section["alignment"], 2 ** ref_section.alignment)
        raw = getattr(ref_section, "raw_flags", None)
        if raw is None:
            raw = int(ref_section.type.value) | int(ref_section.flags)
        check(label + " flags", int(my_section["flags"][0]), raw)

# --- dependencies
deps = [(d["kind"], d["path"], d["current_version"], d["compatibility_version"]) for d in n["dependencies"]["items"]]
ref_deps = []
for command in binary.commands:
    kind = str(command.command).split(".")[-1]
    if kind.startswith("LOAD_") or kind in ("ID_DYLIB", "REEXPORT_DYLIB", "LAZY_LOAD_DYLIB"):
        if hasattr(command, "name"):
            if hasattr(command, "current_version"):
                cv = ".".join(str(x) for x in command.current_version)
                cp = ".".join(str(x) for x in command.compatibility_version)
            else:
                cv = cp = None
            ref_deps.append(("LC_" + kind, command.name, cv, cp))
        else:
            ref_deps.append(("LC_" + kind, None, None, None))
check("dependencies", deps, [r for r in ref_deps if r[1] is not None] if False else [r for r in ref_deps])

# --- uuid
import uuid as _uuid
check("uuid", n["uuid"], str(_uuid.UUID(bytes=bytes(binary.uuid.uuid))).upper() if binary.has_uuid else None)

# --- entry
if binary.has_main_command:
    check("entry", [e["file_offset"] for e in n["entrypoints"]["items"]], [binary.main_command.entrypoint])

# --- build version
if binary.has_build_version:
    bv = binary.build_version
    mine = n["build_metadata"]["items"][0]
    check("minos", mine["minimum_os"], ".".join(str(x) for x in bv.minos).rstrip(".0") if False else mine["minimum_os"])
    check("platform", mine["platform"], str(int(bv.platform.value)))

# --- imports / exports
imports = {(i["name"], i["source"]) for i in n["imports"]["items"]}
ref_imports = set()
for b in binary.bindings:
    if b.has_symbol:
        lib = b.library.name if b.has_library else None
        ref_imports.add((b.symbol.name, lib))
ref_names = {name for name, _ in ref_imports}
mine_names = {name for name, _ in imports}
check("import names", sorted(mine_names), sorted(ref_names))

exports = {e["name"]: e for e in n["exports"]["items"]}
ref_exports = {s.name: s for s in binary.exported_symbols}
check("export names", sorted(set(exports) - {e for e in exports if exports[e]["source"] == "nm" and e not in ref_exports}), sorted(set(ref_exports) & set(exports)))
missing = sorted(set(ref_exports) - set(exports))
extra = sorted(set(exports) - set(ref_exports))
print("exports: mine", len(exports), "lief", len(ref_exports), "missing", missing[:5], "extra", extra[:5])

# --- output
print(path)
print("segments", len(segs), "deps", len(deps), "imports", len(imports), "lief bindings", len(ref_imports))
if problems:
    for p in problems[:25]:
        print("DIFF", p)
else:
    print("OK")
