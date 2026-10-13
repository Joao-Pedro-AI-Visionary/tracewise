#!/usr/bin/env python3
"""PE32/PE32+ resource fixtures (port of REA `src/native/pe/PeResources.fixture.ts`).

Usage: python3 gen_pe.py <output-dir>
"""
import os
import struct
import sys


def icon_group():
    out = bytearray(34)
    struct.pack_into("<H", out, 2, 1)
    struct.pack_into("<H", out, 4, 2)
    for index, ident in enumerate((1, 99)):
        at = 6 + index * 14
        out[at] = 16
        out[at + 1] = 16
        struct.pack_into("<H", out, at + 4, 1)
        struct.pack_into("<H", out, at + 6, 32)
        struct.pack_into("<I", out, at + 8, 4)
        struct.pack_into("<H", out, at + 12, ident)
    return bytes(out)


DEFAULT_RESOURCES = [
    (3, 1, 1033, b"ICON"),
    (3, 1, 1041, b"JAPN"),
    (10, "7", 1033, b"Hello"),
    (10, 7, 1041, b"World"),
    (14, 42, 1033, icon_group()),
]


def pe_resource_fixture(plus=False, resources=None):
    resources = DEFAULT_RESOURCES if resources is None else resources
    tree = {}
    for rtype, name, language, payload in resources:
        parent = tree
        for depth, ident in enumerate((rtype, name, language)):
            key = (type(ident).__name__, str(ident))
            child = parent.get(key)
            if child is None:
                child = (ident, (rtype, name, language, payload) if depth == 2 else {})
                parent[key] = child
            if depth < 2:
                parent = child[1]
    section = bytearray(65536)
    cursor = [0]

    def allocate(size, alignment=4):
        cursor[0] = -(-cursor[0] // alignment) * alignment
        at = cursor[0]
        cursor[0] += size
        return at

    leaves = []
    entry_offsets = []
    directories = []

    def emit(node):
        children = list(node.values())
        children.sort(
            key=lambda c: (0, c[0]) if isinstance(c[0], str) else (1, c[0])
        )
        at = allocate(16 + len(children) * 8)
        directories.append(at)
        named = sum(1 for c in children if isinstance(c[0], str))
        struct.pack_into("<H", section, at + 12, named)
        struct.pack_into("<H", section, at + 14, len(children) - named)
        for index, (ident, value) in enumerate(children):
            entry = at + 16 + index * 8
            entry_offsets.append(entry)
            if isinstance(ident, str):
                encoded = ident.encode("utf-16-le")
                name_at = allocate(len(encoded) + 2, 2)
                struct.pack_into("<H", section, name_at, len(encoded) // 2)
                section[name_at + 2 : name_at + 2 + len(encoded)] = encoded
                struct.pack_into("<I", section, entry, 0x80000000 + name_at)
            else:
                struct.pack_into("<I", section, entry, ident)
            if isinstance(value, dict):
                struct.pack_into("<I", section, entry + 4, 0x80000000 + emit(value))
            else:
                data_at = allocate(16)
                struct.pack_into("<I", section, entry + 4, data_at)
                leaves.append((data_at, value))
        return at

    emit(tree)
    for data_at, resource in leaves:
        payload = resource[3]
        payload_at = allocate(len(payload))
        section[payload_at : payload_at + len(payload)] = payload
        struct.pack_into("<I", section, data_at, 0x2000 + payload_at)
        struct.pack_into("<I", section, data_at + 4, len(payload))
        struct.pack_into("<I", section, data_at + 8, 65001)
    raw_size = -(-cursor[0] // 512) * 512
    data = bytearray(0x400 + raw_size)
    struct.pack_into("<H", data, 0, 0x5A4D)
    struct.pack_into("<I", data, 60, 0x80)
    struct.pack_into("<I", data, 0x80, 0x4550)
    struct.pack_into("<H", data, 0x84, 0x8664 if plus else 0x14C)
    struct.pack_into("<H", data, 0x86, 1)
    optional_size = 240 if plus else 224
    struct.pack_into("<H", data, 0x94, optional_size)
    struct.pack_into("<H", data, 0x98, 0x20B if plus else 0x10B)
    struct.pack_into("<I", data, 0x98 + 60, 0x400)
    struct.pack_into("<I", data, 0x98 + (108 if plus else 92), 16)
    directory_at = 0x98 + (112 if plus else 96) + 16
    struct.pack_into("<I", data, directory_at, 0x2000)
    struct.pack_into("<I", data, directory_at + 4, cursor[0])
    section_at = 0x98 + optional_size
    data[section_at : section_at + 5] = b".rsrc"
    struct.pack_into("<I", data, section_at + 8, cursor[0])
    struct.pack_into("<I", data, section_at + 12, 0x2000)
    struct.pack_into("<I", data, section_at + 16, raw_size)
    struct.pack_into("<I", data, section_at + 20, 0x400)
    data[0x400 : 0x400 + raw_size] = section[:raw_size]
    return {
        "bytes": data,
        "directory_at": directory_at,
        "section_at": section_at,
        "entry_offsets": [at + 0x400 for at in entry_offsets],
        "directory_offsets": [at + 0x400 for at in directories],
        "data_offsets": [at + 0x400 for at, _ in leaves],
    }


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(bytes(data))


def main(out):
    fx32 = pe_resource_fixture(False)
    fx64 = pe_resource_fixture(True)
    write(os.path.join(out, "resource32.exe"), fx32["bytes"])
    write(os.path.join(out, "resource64.exe"), fx64["bytes"])
    absent = pe_resource_fixture()
    absent["bytes"][absent["directory_at"] : absent["directory_at"] + 8] = bytes(8)
    write(os.path.join(out, "absent.exe"), absent["bytes"])
    damaged = pe_resource_fixture()
    struct.pack_into("<I", damaged["bytes"], damaged["directory_at"] + 4, 17)
    write(os.path.join(out, "damaged.exe"), damaged["bytes"])
    inconsistent = pe_resource_fixture()
    struct.pack_into("<I", inconsistent["bytes"], inconsistent["directory_at"] + 4, 0)
    write(os.path.join(out, "inconsistent.exe"), inconsistent["bytes"])
    write(os.path.join(out, "notpe.exe"), b"MZ" + bytes(100))
    write(os.path.join(out, "empty.exe"), b"")
    write(os.path.join(out, "truncated.exe"), fx32["bytes"][:0x200])
    unicode_named = pe_resource_fixture(True, [
        (10, "Résumé☃", 1033, b"abc"),
        (10, "ALPHA", 1033, b"def"),
        (3, 5, 0, b""),
        (14, 5, 1033, icon_group()),
    ])
    write(os.path.join(out, "unicode.exe"), unicode_named["bytes"])
    # Two language entries with the same identity in one directory.
    duplicate = pe_resource_fixture(False, [(3, 1, 1033, b"A"), (3, 1, 1041, b"B")])
    leaf_dir = duplicate["directory_offsets"][-1]
    struct.pack_into("<I", duplicate["bytes"], leaf_dir + 16 + 8, 1033)
    write(os.path.join(out, "duplicate.exe"), duplicate["bytes"])
    # A subdirectory pointing back at the root.
    cyclic = pe_resource_fixture()
    struct.pack_into("<I", cyclic["bytes"], cyclic["entry_offsets"][1] + 4, 0x80000000)
    write(os.path.join(out, "cyclic.exe"), cyclic["bytes"])
    # Unaligned resource directory offset.
    unaligned = pe_resource_fixture()
    struct.pack_into("<I", unaligned["bytes"], unaligned["entry_offsets"][0] + 4, 0x80000002)
    write(os.path.join(out, "unaligned.exe"), unaligned["bytes"])
    # Entry counts that disagree with encoded identities (named count too high).
    counts = pe_resource_fixture()
    struct.pack_into("<H", counts["bytes"], counts["directory_offsets"][0] + 12, 2)
    write(os.path.join(out, "counts.exe"), counts["bytes"])
    # Leaf at the wrong depth.
    shallow = pe_resource_fixture()
    struct.pack_into("<I", shallow["bytes"], shallow["entry_offsets"][0] + 4, shallow["data_offsets"][0] - 0x400)
    write(os.path.join(out, "shallow.exe"), shallow["bytes"])
    # Two resources sharing one payload range (exact sharing is allowed).
    shared = pe_resource_fixture(False, [(3, 1, 1033, b"SAME"), (3, 2, 1033, b"SAME")])
    first, second = shared["data_offsets"][0], shared["data_offsets"][1]
    shared["bytes"][second : second + 4] = shared["bytes"][first : first + 4]
    write(os.path.join(out, "shared.exe"), shared["bytes"])
    # Overlapping, non-identical payload ranges.
    overlap = pe_resource_fixture(False, [(3, 1, 1033, b"ABCDEFGH"), (3, 2, 1033, b"IJKLMNOP")])
    first, second = overlap["data_offsets"][0], overlap["data_offsets"][1]
    rva = struct.unpack_from("<I", overlap["bytes"], first)[0]
    struct.pack_into("<I", overlap["bytes"], second, rva + 2)
    write(os.path.join(out, "overlap.exe"), overlap["bytes"])
    # Icon group whose declared image count disagrees with its length.
    badicon = pe_resource_fixture()
    group_payload = struct.unpack_from("<I", badicon["bytes"], badicon["data_offsets"][-1])[0] - 0x2000 + 0x400
    struct.pack_into("<H", badicon["bytes"], group_payload + 4, 3)
    write(os.path.join(out, "badicon.exe"), badicon["bytes"])
    # Resource directory whose RVA lies beyond every section.
    far = pe_resource_fixture()
    struct.pack_into("<I", far["bytes"], far["directory_at"], 0x90000)
    write(os.path.join(out, "far.exe"), far["bytes"])
    # PE with no resource table (16 directories declared, zero entry).
    no_tree = pe_resource_fixture()
    struct.pack_into("<I", no_tree["bytes"], 0x98 + 92, 2)
    write(os.path.join(out, "twodirs.exe"), no_tree["bytes"])


if __name__ == "__main__":
    main(sys.argv[1])
