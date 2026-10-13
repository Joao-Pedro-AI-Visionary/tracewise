#!/usr/bin/env python3
"""Synthetic Linux x86-64 ELF core files (same note layouts the kernel writes).

usage: python3 gen_cores.py <output-dir>
"""
import os
import struct
import sys

REGISTERS = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi",
             "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]

NT_PRSTATUS, NT_FPREGSET, NT_PRPSINFO, NT_AUXV, NT_SIGINFO, NT_FILE = 1, 2, 3, 6, 0x53494749, 0x46494C45


def pad4(data):
    return data + bytes(-len(data) % 4)


def note(owner, ntype, desc, namesz=None, descsz=None):
    namesz = len(owner) if namesz is None else namesz
    descsz = len(desc) if descsz is None else descsz
    return struct.pack("<III", namesz, descsz, ntype) + pad4(owner) + pad4(desc)


def prstatus(pid=4242, cursig=11, registers=None, signo=11, size=336):
    out = bytearray(336)
    struct.pack_into("<iii", out, 0, signo, 0, 0)
    struct.pack_into("<h", out, 12, cursig)
    struct.pack_into("<iiii", out, 32, pid, 1, pid, pid)
    for index, name in enumerate(REGISTERS):
        value = (registers or {}).get(name, 0x1000 + index)
        struct.pack_into("<Q", out, 112 + index * 8, value)
    return bytes(out[:size])


def siginfo(signo=11, code=1, errno=0, addr=0xDEADBEEF, size=128):
    out = bytearray(128)
    struct.pack_into("<iii", out, 0, signo, errno, code)
    struct.pack_into("<Q", out, 16, addr)
    return bytes(out[:size])


def nt_file(entries):
    body = struct.pack("<QQ", len(entries), 4096)
    names = b""
    for start, end, offset, name in entries:
        body += struct.pack("<QQQ", start, end, offset)
        names += name.encode() + b"\0"
    return body + names


def core(notes, loads=(), osabi=0, abi=0, e_type=4, machine=62, ident_version=1, header_version=1, ei_class=2,
         ei_data=1, phentsize=56, pt_note_extra=b"", note_flags=0, load_filesz_extra=0):
    note_blob = b"".join(notes) + pt_note_extra
    phnum = 1 + len(loads)
    header_size = 64 + phentsize * phnum
    note_offset = header_size
    data_offset = note_offset + len(note_blob)
    out = bytearray(data_offset)
    out[0:4] = b"\x7fELF"
    out[4] = ei_class
    out[5] = ei_data
    out[6] = ident_version
    out[7] = osabi
    out[8] = abi
    struct.pack_into("<HHIQQQIHHHHHH", out, 16, e_type, machine, header_version, 0, 64, 0, 0, 64, phentsize, phnum, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", out, 64, 4, note_flags, note_offset, 0, 0, len(note_blob), 0, 4)
    cursor = data_offset
    payload = b""
    for index, (vaddr, blob, memsz) in enumerate(loads):
        struct.pack_into(
            "<IIQQQQQQ", out, 64 + phentsize * (index + 1), 1, 6, cursor, vaddr, 0,
            len(blob) + load_filesz_extra, memsz, 4096,
        )
        payload += blob
        cursor += len(blob)
    out[note_offset:data_offset] = note_blob
    return bytes(out) + payload


def write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def main(directory):
    os.makedirs(directory, exist_ok=True)
    core_owner = b"CORE\0"
    loads = [(0x400000, bytes(range(256)) * 4, 0x1000), (0x7FFFF0000000, b"\x00" * 64, 0x2000)]
    basic_notes = [
        note(core_owner, NT_PRSTATUS, prstatus(4242, 11, {"rip": 0x401136, "rsp": 0x7FFFFFFFE000, "rdi": 0x1122334455667788})),
        note(core_owner, NT_PRSTATUS, prstatus(4243, 0, {"rip": 0x401200})),
        note(core_owner, NT_PRPSINFO, bytes(136)),
        note(core_owner, NT_SIGINFO, siginfo(11, 1, 0, 0xDEADBEEF)),
        note(core_owner, NT_AUXV, struct.pack("<QQQQ", 6, 4096, 0, 0)),
        note(core_owner, NT_FILE, nt_file([(0x400000, 0x401000, 0, "/tmp/crash-target")])),
        note(b"LINUX\0", 0x202, bytes(64)),
    ]
    files = {
        "basic": core(basic_notes, loads),
        "segv_code2": core([note(core_owner, NT_PRSTATUS, prstatus()), note(core_owner, NT_SIGINFO, siginfo(11, 2, 7, 0x10))]),
        "segv_code3": core([note(core_owner, NT_SIGINFO, siginfo(11, 3, 0, 0x10))]),
        "sigill": core([note(core_owner, NT_PRSTATUS, prstatus(77, 4, signo=4)), note(core_owner, NT_SIGINFO, siginfo(4, 1, 0, 0x55))]),
        "negative": core([note(core_owner, NT_PRSTATUS, prstatus(-5, -3, {"rip": 0xFFFFFFFFFFFFFFFF}))]),
        "no_notes": core([], loads),
        "no_load": core([note(core_owner, NT_PRSTATUS, prstatus())]),
        "foreign_owner": core([note(b"GNU\0", 5, bytes(16)), note(b"LINUX\0", NT_PRSTATUS, prstatus()), note(b"CORE\0", 99, bytes(8))]),
        "unterminated_owner": core([note(b"CORE", NT_PRSTATUS, prstatus(), namesz=4)]),
        "empty_owner": core([note(b"", 1, b"", namesz=0, descsz=0)]),
        "short_prstatus": core([note(core_owner, NT_PRSTATUS, prstatus(size=300))]),
        "short_siginfo": core([note(core_owner, NT_SIGINFO, siginfo(size=24))]),
        "note_padding": core(basic_notes[:1], pt_note_extra=bytes(7)),
        "note_dirty_tail": core(basic_notes[:1], pt_note_extra=b"\x00\x00\x01\x00\x00"),
        "note_overflow": core([note(core_owner, NT_PRSTATUS, prstatus())[:-8]]),
        "load_filesz_gt_memsz": core(basic_notes[:1], [(0x400000, bytes(64), 16)]),
        "load_beyond_file": core(basic_notes[:1], [(0x400000, bytes(64), 0x1000)], load_filesz_extra=1 << 20),
        "osabi_gnu": core(basic_notes[:2], osabi=3),
        "osabi_freebsd": core(basic_notes[:2], osabi=9),
        "abi_version_1": core(basic_notes[:2], abi=1),
        "ident_version_2": core(basic_notes[:2], ident_version=2),
        "header_version_2": core(basic_notes[:2], header_version=2),
        "elf32": core(basic_notes[:2], ei_class=1),
        "big_endian": core(basic_notes[:2], ei_data=2),
        "type_exec": core(basic_notes[:2], e_type=2),
        "machine_arm": core(basic_notes[:2], machine=40),
        "small_phentsize": core(basic_notes[:2], phentsize=40),
        "not_elf": b"definitely not an ELF core file ......",
        "short_ident": b"\x7fELF\x02\x01\x01",
        "short_header": core(basic_notes[:2])[:40],
        "empty": b"",
    }
    for name, data in files.items():
        write(os.path.join(directory, name + ".core"), data)
    # Program headers beyond the file.
    d = bytearray(files["basic"])
    struct.pack_into("<Q", d, 32, len(d) + 4096)
    write(os.path.join(directory, "phdr_beyond.core"), bytes(d))
    # Segment count carried by section header zero (e_phnum == PN_XNUM).
    d = bytearray(files["basic"])
    struct.pack_into("<H", d, 56, 0xFFFF)
    write(os.path.join(directory, "phnum_xnum.core"), bytes(d))


if __name__ == "__main__":
    main(sys.argv[1])
