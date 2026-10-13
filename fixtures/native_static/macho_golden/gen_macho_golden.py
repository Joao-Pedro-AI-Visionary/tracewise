#!/usr/bin/env python3
"""Rebuild a Mach-O file from a captured `otool -l` text and replay the capture through REA.

The captures are the Apple tool outputs under `rea-map/src/tests/fixtures/native-macos`
(MIT, REA). For every capture this writes
  <name>.macho       a Mach-O whose load commands equal the capture (data blobs synthesized)
  <name>.otool.txt   the capture, with the `otool -h` header prepended when it had none
  <name>.scenario.json / <name>.expected.json
                     the captured outputs and what the ORIGINAL REA produces from them

usage: python3 gen_macho_golden.py <rea-fixtures-dir> <out-dir>
"""
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

LC = {
    "LC_SEGMENT_64": 0x19, "LC_SYMTAB": 0x2, "LC_DYSYMTAB": 0xB, "LC_LOAD_DYLIB": 0xC, "LC_ID_DYLIB": 0xD,
    "LC_LOAD_DYLINKER": 0xE, "LC_UUID": 0x1B, "LC_CODE_SIGNATURE": 0x1D, "LC_REEXPORT_DYLIB": 0x8000001F,
    "LC_FUNCTION_STARTS": 0x26, "LC_MAIN": 0x80000028, "LC_DATA_IN_CODE": 0x29, "LC_SOURCE_VERSION": 0x2A,
    "LC_BUILD_VERSION": 0x32, "LC_DYLD_EXPORTS_TRIE": 0x80000033, "LC_DYLD_CHAINED_FIXUPS": 0x80000034,
}
DATA_COMMANDS = {"LC_CODE_SIGNATURE", "LC_FUNCTION_STARTS", "LC_DATA_IN_CODE", "LC_DYLD_EXPORTS_TRIE",
                 "LC_DYLD_CHAINED_FIXUPS"}


def parse_otool(text):
    commands = []
    current = None
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"^Load command (\d+)$", line)
        if match:
            current = {"index": int(match.group(1)), "fields": {}, "sections": []}
            commands.append(current)
            section = None
            continue
        if current is None:
            continue
        if line == "Section":
            section = {}
            current["sections"].append(section)
            continue
        match = re.match(r"^((?:time stamp)|\S+(?:\s+version)?)\s+(.+)$", line)
        if not match:
            continue
        target = section if section is not None else current["fields"]
        target[match.group(1)] = match.group(2).strip()
    return commands


def num(value):
    return int(value, 16) if value.lower().startswith("0x") else int(value.split()[0])


def pad(data, size):
    if len(data) > size:
        raise ValueError("blob larger than its command field: %d > %d" % (len(data), size))
    return data + bytes(size - len(data))


def version_word(text):
    parts = [int(p) for p in text.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def source_version_word(text):
    parts = [int(p) for p in text.split(".")]
    while len(parts) < 5:
        parts.append(0)
    a, b, c, d, e = parts
    return (a << 40) | (b << 30) | (c << 20) | (d << 10) | e


def encode_command(command):
    fields = command["fields"]
    name = fields["cmd"]
    cmd = LC[name]
    size = num(fields["cmdsize"])
    if name == "LC_SEGMENT_64":
        body = struct.pack("<16sQQQQIIII", fields["segname"].encode(), num(fields["vmaddr"]), num(fields["vmsize"]),
                           num(fields["fileoff"]), num(fields["filesize"]), num(fields["maxprot"]),
                           num(fields["initprot"]), num(fields["nsects"]), num(fields["flags"]))
        for section in command["sections"]:
            align = int(re.match(r"2\^(\d+)", section["align"]).group(1))
            body += struct.pack("<16s16sQQIIIIIIII", section["sectname"].encode(), section["segname"].encode(),
                                num(section["addr"]), num(section["size"]), num(section["offset"]), align,
                                num(section["reloff"]), num(section["nreloc"]), num(section["flags"]),
                                num(section["reserved1"]), num(section["reserved2"]), 0)
    elif name in DATA_COMMANDS:
        body = struct.pack("<II", num(fields["dataoff"]), num(fields["datasize"]))
    elif name == "LC_SYMTAB":
        body = struct.pack("<IIII", num(fields["symoff"]), num(fields["nsyms"]), num(fields["stroff"]),
                           num(fields["strsize"]))
    elif name == "LC_DYSYMTAB":
        keys = ["ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym", "tocoff", "ntoc",
                "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms", "indirectsymoff", "nindirectsyms",
                "extreloff", "nextrel", "locreloff", "nlocrel"]
        body = b"".join(struct.pack("<I", num(fields[k])) for k in keys)
    elif name == "LC_LOAD_DYLINKER":
        path = re.sub(r"\s+\(offset \d+\)$", "", fields["name"])
        body = struct.pack("<I", 12) + path.encode() + b"\0"
    elif name == "LC_UUID":
        body = bytes.fromhex(fields["uuid"].replace("-", ""))
    elif name == "LC_BUILD_VERSION":
        ntools = num(fields["ntools"])
        body = struct.pack("<IIII", num(fields["platform"]), version_word(fields["minos"]),
                           version_word(fields["sdk"]), ntools)
        for tool, version in command.get("tools", []):
            body += struct.pack("<II", tool, version_word(version))
    elif name == "LC_SOURCE_VERSION":
        body = struct.pack("<Q", source_version_word(fields["version"]))
    elif name == "LC_MAIN":
        body = struct.pack("<QQ", num(fields["entryoff"]), num(fields["stacksize"]))
    elif name in ("LC_LOAD_DYLIB", "LC_ID_DYLIB", "LC_REEXPORT_DYLIB"):
        path = re.sub(r"\s+\(offset \d+\)$", "", fields["name"])
        stamp = int(fields["time stamp"].split()[0])
        body = struct.pack("<IIII", 24, stamp, version_word(fields["current version"]),
                           version_word(fields["compatibility version"])) + path.encode() + b"\0"
    else:
        raise ValueError("unsupported command " + name)
    data = struct.pack("<II", cmd, size) + body
    return pad(data, size)


def parse_build_tools(text):
    """Tools of each LC_BUILD_VERSION block (the field map keeps only the last)."""
    tools = {}
    index = None
    pending = None
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"^Load command (\d+)$", line)
        if match:
            index = int(match.group(1))
            tools[index] = []
            pending = None
            continue
        match = re.match(r"^tool\s+(\S+)$", line)
        if match and index is not None:
            pending = int(match.group(1))
            continue
        match = re.match(r"^version\s+(\S+)$", line)
        if match and pending is not None and index is not None:
            tools[index].append((pending, match.group(1)))
            pending = None
    return tools


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def export_trie(entries):
    """Radix trie of (name, flags, offset) entries, as ld64 lays it out (shared prefixes)."""

    class Node:
        def __init__(self):
            self.terminal = None
            self.edges = []  # (label, Node)

    def insert(node, name, info):
        for index, (label, child) in enumerate(node.edges):
            common = 0
            while common < min(len(label), len(name)) and label[common] == name[common]:
                common += 1
            if common == 0:
                continue
            if common < len(label):
                split = Node()
                split.edges.append((label[common:], child))
                node.edges[index] = (label[:common], split)
                child = split
            if common == len(name):
                child.terminal = info
            else:
                insert(child, name[common:], info)
            return
        leaf = Node()
        leaf.terminal = info
        node.edges.append((name, leaf))

    root = Node()
    for name, flags, offset in entries:
        insert(root, name, (flags, offset))

    def encode(node, offsets):
        terminal = b""
        if node.terminal is not None:
            terminal = uleb(node.terminal[0]) + uleb(node.terminal[1])
        out = uleb(len(terminal)) + terminal + bytes([len(node.edges)])
        for label, child in node.edges:
            out += label.encode() + b"\0" + uleb(offsets[id(child)])
        return out

    order = []

    def collect(node):
        order.append(node)
        for _, child in node.edges:
            collect(child)

    collect(root)
    offsets = {id(n): 0 for n in order}
    for _ in range(4):
        cursor = 0
        for node in order:
            offsets[id(node)] = cursor
            cursor += len(encode(node, offsets))
    return b"".join(encode(node, offsets) for node in order)


def chained_fixups(imports, segment_count):
    """imports: [(name, lib_ordinal_byte, weak)] in DYLD_CHAINED_IMPORT format 1."""
    starts = struct.pack("<I", segment_count) + bytes(4 * segment_count)
    starts_offset = 32
    imports_offset = starts_offset + len(starts)
    symbols_offset = imports_offset + 4 * len(imports)
    symbols = b"\0"
    entries = b""
    for name, ordinal, weak in imports:
        entries += struct.pack("<I", ordinal | (int(weak) << 8) | (len(symbols) << 9))
        symbols += name.encode() + b"\0"
    header = struct.pack("<IIIIIII", 0, starts_offset, imports_offset, symbols_offset, len(imports), 1, 0)
    return pad(header, starts_offset) + starts + entries + symbols


def symbol_table(symbols, strsize):
    """symbols: [(name, n_type, n_sect, value)] -> (nlist64 bytes, string table)."""
    strings = b"\0"
    entries = b""
    for name, n_type, n_sect, value in symbols:
        entries += struct.pack("<IBBHQ", len(strings), n_type, n_sect, 0, value)
        strings += name.encode() + b"\0"
    return entries, pad(strings, strsize)


def build(text, header_flags, blobs):
    commands = parse_otool(text)
    tools = parse_build_tools(text)
    for command in commands:
        if command["fields"]["cmd"] == "LC_BUILD_VERSION":
            command["tools"] = tools.get(command["index"], [])
    encoded = [encode_command(c) for c in commands]
    sizeofcmds = sum(len(e) for e in encoded)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, len(commands), sizeofcmds, header_flags, 0)
    end = 0
    for command in commands:
        fields = command["fields"]
        if fields["cmd"] == "LC_SEGMENT_64":
            end = max(end, num(fields["fileoff"]) + num(fields["filesize"]))
    image = bytearray(end)
    image[0:len(header)] = header
    cursor = len(header)
    for blob in encoded:
        image[cursor:cursor + len(blob)] = blob
        cursor += len(blob)
    for command in commands:
        fields = command["fields"]
        name = fields["cmd"]
        if name in blobs and name in DATA_COMMANDS:
            data = blobs[name]
            offset = num(fields["dataoff"])
            image[offset:offset + len(data)] = pad(data, num(fields["datasize"]))
        if name == "LC_SYMTAB" and "symbols" in blobs:
            entries, strings = symbol_table(blobs["symbols"], num(fields["strsize"]))
            image[num(fields["symoff"]):num(fields["symoff"]) + len(entries)] = entries
            image[num(fields["stroff"]):num(fields["stroff"]) + len(strings)] = strings
    header_text = (
        "Mach header\n      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags\n"
        " 0xfeedfacf 16777228          0  0x00           2 %5d %10d 0x%08x\n" % (len(commands), sizeofcmds, header_flags)
    )
    return bytes(image), header_text


def replay(scenario, out):
    path = os.path.join(HERE, out + ".scenario.json")
    with open(path, "w") as handle:
        json.dump(scenario, handle, indent=1)
    expected = os.path.join(HERE, out + ".expected.json")
    subprocess.run(["node", os.path.join(HERE, "replay_rea.mjs"), path, expected], check=True)


def main(rea_fixtures, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    native = os.path.join(rea_fixtures, "native-macos")

    def read(*parts):
        with open(os.path.join(native, *parts), encoding="utf-8") as handle:
            return handle.read()

    # --- Golden 1: a source-built executable with the real `otool -h` header (native-macho-header).
    capture = read("native-macho-header", "otool-header-load.txt")
    loads = capture[capture.index("Load command 0"):]
    blobs = {
        "LC_DYLD_CHAINED_FIXUPS": chained_fixups([], 4),
        "LC_DYLD_EXPORTS_TRIE": export_trie([("__mh_execute_header", 0, 0), ("_main", 0, 816), ("_owned_value", 0, 808)]),
        "symbols": [("__mh_execute_header", 0x0F, 1, 0x100000000), ("_main", 0x0F, 1, 0x100000330),
                    ("_owned_value", 0x0F, 1, 0x100000328)],
    }
    image, header_text = build(loads, 0x00200085, blobs)
    with open(os.path.join(out_dir, "header_capture.macho"), "wb") as handle:
        handle.write(image)
    otool_text = capture.replace("/owned/fixture:\nMach header", "$ARTIFACT:\nMach header", 1)
    # The capture holds `otool -h` and `otool -l` as two runs; REA runs them as one.
    otool_text = re.sub(r"\n/owned/fixture:\nLoad command 0", "\nLoad command 0", otool_text, count=1)
    scenario = {
        "operation": "inspect_macho",
        "outputs": {
            "file": "Mach-O 64-bit executable arm64\n",
            "lipo": "Non-fat file: fixture is architecture: arm64\n",
            "otool": otool_text,
            "nm": "__mh_execute_header\n_main\n_owned_value\n",
            "dyld_info:-imports": "fixture [arm64]:\n    -imports:\n",
            "dyld_info:-exports": "fixture [arm64]:\n    -exports:\n        offset      symbol\n"
                                   "        0x00000000  __mh_execute_header\n        0x00000330  _main\n"
                                   "        0x00000328  _owned_value\n",
            "dwarfdump": "UUID: 633B21A4-D14A-3312-A5AD-B3CB919DAC72 (arm64) fixture\n",
            "vtool": "fixture:\nLoad command 9\n      cmd LC_BUILD_VERSION\n",
        },
    }
    replay(scenario, os.path.join("header_capture"))
    with open(os.path.join(out_dir, "header_capture.otool.txt"), "w") as handle:
        handle.write(capture)

    # --- Golden 2: the dyld inventory capture (imports, exports, nm).
    capture = read("dyld-inventory", "otool.txt")
    loads = capture[capture.index("Load command 0"):]
    blobs = {
        "LC_DYLD_CHAINED_FIXUPS": chained_fixups([("_puts", 1, False), ("_fixture_weak", 0xFD, False)], 4),
        "LC_DYLD_EXPORTS_TRIE": export_trie([
            ("__mh_execute_header", 0, 0), ("_fixture_absolute", 2, 0x42), ("_fixture_export", 0, 0x468),
            ("_fixture_weak", 4, 0x460), ("_main", 0, 0x470)]),
        "symbols": [("__mh_execute_header", 0x0F, 1, 0x100000000), ("_fixture_absolute", 0x03, 0, 0x42),
                    ("_fixture_export", 0x0F, 1, 0x100000468), ("_fixture_weak", 0x0F, 1, 0x100000460),
                    ("_main", 0x0F, 1, 0x100000470), ("_puts", 0x01, 0, 0)],
    }
    image, header_text = build(loads, 0x00200085, blobs)
    with open(os.path.join(out_dir, "dyld_inventory.macho"), "wb") as handle:
        handle.write(image)
    otool_text = "$ARTIFACT:\n" + header_text + loads
    scenario = {
        "operation": "inspect_macho",
        "outputs": {
            "file": read("dyld-inventory", "file.txt"),
            "lipo": read("dyld-inventory", "lipo.txt"),
            "otool": otool_text,
            "nm": read("dyld-inventory", "nm.txt"),
            "dyld_info:-imports": read("dyld-inventory", "imports.txt"),
            "dyld_info:-exports": read("dyld-inventory", "exports.txt"),
            "dwarfdump": read("dyld-inventory", "dwarfdump.txt"),
            "vtool": read("dyld-inventory", "vtool.txt"),
        },
    }
    replay(scenario, "dyld_inventory")
    with open(os.path.join(out_dir, "dyld_inventory.otool.txt"), "w") as handle:
        handle.write("$ARTIFACT:\n" + header_text + loads)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
