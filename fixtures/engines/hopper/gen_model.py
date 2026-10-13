#!/usr/bin/env python3
"""Generate fixtures/engines/hopper/sample_model.json from fixtures/engines/sample_elf.

The model feeds fake_hopper_launcher.py, a stand-in for Hopper's embedded Python API. It is
derived from objdump/readelf output of the sample binary; the generated JSON is committed so
tests do not depend on binutils.

usage: gen_model.py <sample_elf> <sample.c> <out.json>
"""
import json
import re
import subprocess
import sys

elf, source_path, out_path = sys.argv[1:4]
PROCEDURES = {
    "engine_leaf": "int engine_leaf(int value)",
    "engine_branch": "int engine_branch(int value)",
    "engine_apply": "int engine_apply(int (*callback)(int), int value)",
    "engine_measure": "unsigned long engine_measure(const char *text)",
    "engine_entry": "int engine_entry(int argc)",
    "main": "int main(int argc, char **argv)",
    "puts@plt": "int puts(const char *s)",
    "strlen@plt": "unsigned long strlen(const char *s)",
    "printf@plt": "int printf(const char *format, ...)",
}
DISPLAY_NAMES = {"puts@plt": "puts", "strlen@plt": "strlen", "printf@plt": "printf"}

listing = subprocess.check_output(["objdump", "-d", "-M", "intel", elf], text=True)
sections_text = subprocess.check_output(["readelf", "-SW", elf], text=True)
program_text = subprocess.check_output(["readelf", "-lW", elf], text=True)

sections = {}
for match in re.finditer(r"\]\s+(\.\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", sections_text):
    name, addr, off, size = match.group(1), int(match.group(2), 16), int(match.group(3), 16), int(match.group(4), 16)
    sections[name] = {"addr": addr, "offset": off, "size": size}

loads = []
for match in re.finditer(r"LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)", program_text):
    loads.append({"offset": int(match.group(1), 16), "vaddr": int(match.group(2), 16), "filesz": int(match.group(3), 16), "memsz": int(match.group(4), 16)})

data = open(elf, "rb").read()


def read_memory(address, length):
    result = bytearray()
    for index in range(length):
        value = 0
        for load in loads:
            if load["vaddr"] <= address + index < load["vaddr"] + load["memsz"]:
                delta = address + index - load["vaddr"]
                value = data[load["offset"] + delta] if delta < load["filesz"] else 0
                break
        result.append(value)
    return bytes(result)


# --- instructions per function ---
functions = {}
current = None
header = re.compile(r"^([0-9a-f]+) <(.+)>:$")
line = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(.*)$")
cont = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*$")
for raw in listing.splitlines():
    m = header.match(raw)
    if m:
        name = m.group(2)
        current = functions.setdefault(name, {"entry": int(m.group(1), 16), "instructions": []}) if name in PROCEDURES else None
        continue
    if current is None:
        continue
    m = line.match(raw)
    if m:
        address = int(m.group(1), 16)
        raw_bytes = m.group(2).split()
        text = m.group(3)
        comment = ""
        if "#" in text:
            text, comment = text.split("#", 1)
        text = text.strip()
        parts = text.split(None, 1)
        mnemonic = parts[0]
        arguments = [a.strip() for a in re.split(r",(?![^\[]*\])", parts[1])] if len(parts) > 1 else []
        refs = []
        target = re.search(r"\b([0-9a-f]{6})\b", " ".join(arguments)) if mnemonic.startswith(("call", "j")) else None
        if target:
            refs.append(int(target.group(1), 16))
        commented = re.search(r"\b([0-9a-f]{6})\b", comment)
        if commented:
            refs.append(int(commented.group(1), 16))
        arguments = [re.sub(r"\s+<[^>]*>", "", a) for a in arguments]
        current["instructions"].append({"address": address, "length": len(raw_bytes), "mnemonic": mnemonic, "args": arguments, "refs": refs})
        continue
    m = cont.match(raw)
    if m and current["instructions"]:
        current["instructions"][-1]["length"] += len(m.group(2).split())

source = open(source_path).read()


def function_source(name):
    match = re.search(r"((?:__attribute__\(\([^)]*\)\)\s*)?[\w\s\*\(\),]*\b" + re.escape(name) + r"\([^)]*\)\s*\{.*?^\})", source, re.S | re.M)
    return match.group(1).strip() if match else "// " + name


procedures = []
for name, info in sorted(functions.items(), key=lambda item: item[1]["entry"]):
    instructions = info["instructions"]
    addresses = [i["address"] for i in instructions]
    leaders = {instructions[0]["address"]}
    for index, ins in enumerate(instructions):
        branch = ins["mnemonic"].startswith("j") or ins["mnemonic"] == "ret"
        if branch and index + 1 < len(instructions):
            leaders.add(instructions[index + 1]["address"])
        if ins["mnemonic"].startswith("j"):
            for ref in ins["refs"]:
                if ref in addresses:
                    leaders.add(ref)
    ordered = sorted(leaders)
    blocks = []
    for position, start in enumerate(ordered):
        end_exclusive = ordered[position + 1] if position + 1 < len(ordered) else instructions[-1]["address"] + instructions[-1]["length"]
        members = [i for i in instructions if start <= i["address"] < end_exclusive]
        last = members[-1]
        successors = []
        if last["mnemonic"].startswith("j"):
            successors.extend(r for r in last["refs"] if r in addresses)
            if last["mnemonic"] != "jmp":
                successors.append(end_exclusive)
        elif last["mnemonic"] != "ret":
            successors.append(end_exclusive) if end_exclusive in addresses else None
        blocks.append({"start": start, "end": last["address"], "successors": successors})
    locals_found = sorted({int(m.group(1), 16) for i in instructions for a in i["args"] for m in [re.search(r"rbp-0x([0-9a-f]+)", a)] if m})
    procedures.append({
        "entry": info["entry"],
        "name": DISPLAY_NAMES.get(name, name),
        "signature": PROCEDURES[name],
        "pseudocode": function_source(name) if name in functions and not name.endswith("@plt") else "// imported stub " + DISPLAY_NAMES.get(name, name),
        "locals": [{"name": "var_%x" % d, "displacement": -d} for d in locals_found],
        "instructions": instructions,
        "blocks": blocks,
    })

names = {p["entry"]: p["name"] for p in procedures}
symbols = subprocess.check_output(["nm", elf], text=True)
for match in re.finditer(r"^([0-9a-f]+) [dDrR] (engine_banner|engine_counter)$", symbols, re.M):
    names[int(match.group(1), 16)] = match.group(2)
names[0x402026] = "aEngineLeafMessage"

segments = []
for name, first, last, parts in [
    ("TEXT", ".init", ".fini", [".init", ".plt", ".text", ".fini"]),
    ("RODATA", ".rodata", ".rodata", [".rodata"]),
    ("DATA", ".data", ".bss", [".data", ".bss"]),
]:
    start = sections[first]["addr"]
    end = sections[last]["addr"] + sections[last]["size"]
    segments.append({
        "name": name,
        "start": start,
        "length": end - start,
        "sections": [{"name": p, "start": sections[p]["addr"], "length": sections[p]["size"]} for p in parts],
        "bytes_hex": read_memory(start, end - start).hex(),
    })

strings = [
    {"display": "ENGINE_FIXTURE_BANNER", "address": 0x402010, "length": 22},
    {"display": "ENGINE_LEAF_MESSAGE", "address": 0x402026, "length": 20},
]
model = {
    "image_base": loads[0]["vaddr"] if loads else 0,
    "segments": segments,
    "procedures": procedures,
    "names": {str(k): v for k, v in sorted(names.items())},
    "strings": strings,
    "file_offsets": loads,
}
json.dump(model, open(out_path, "w"), indent=1, sort_keys=True)
print("procedures:", [p["name"] for p in procedures])
