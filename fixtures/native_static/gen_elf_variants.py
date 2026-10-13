#!/usr/bin/env python3
"""Damaged and unusual ELF fixtures derived from the compiled samples.

usage: python3 gen_elf_variants.py <elf-dir>   (reads pie_default, nopie_plain, object.o, relr_pie)
"""
import os
import struct
import sys


def read(path):
    with open(path, "rb") as handle:
        return bytearray(handle.read())


def write(path, data):
    with open(path, "wb") as handle:
        handle.write(bytes(data))


class Elf:
    def __init__(self, data):
        self.data = data
        (self.e_type, self.e_machine, _, self.e_entry, self.e_phoff, self.e_shoff, self.e_flags, _,
         self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", data, 16
        )

    def section(self, index):
        base = self.e_shoff + index * self.e_shentsize
        return base, struct.unpack_from("<IIQQQQIIQQ", self.data, base)

    def segment(self, index):
        base = self.e_phoff + index * self.e_phentsize
        return base, struct.unpack_from("<IIQQQQQQ", self.data, base)

    def find_section(self, type_):
        for index in range(self.e_shnum):
            base, fields = self.section(index)
            if fields[1] == type_:
                return index, base, fields
        raise KeyError(type_)

    def find_segment(self, type_):
        for index in range(self.e_phnum):
            base, fields = self.segment(index)
            if fields[0] == type_:
                return index, base, fields
        raise KeyError(type_)


def main(directory):
    out = os.path.join(directory, "variants")
    os.makedirs(out, exist_ok=True)
    pie = read(os.path.join(directory, "pie_default"))
    plain = read(os.path.join(directory, "nopie_plain"))
    obj = read(os.path.join(directory, "object.o"))

    def variant(name, data):
        write(os.path.join(out, name), data)

    # Identification and header level failures.
    variant("not_elf", b"this is not an ELF file at all, only text")
    variant("empty", b"")
    variant("short_ident", pie[:10])
    variant("short_header", pie[:40])
    d = bytearray(pie); d[4] = 1; variant("elf32", d)
    d = bytearray(pie); d[5] = 2; variant("big_endian", d)
    d = bytearray(pie); struct.pack_into("<H", d, 18, 40); variant("arm", d)
    d = bytearray(pie); struct.pack_into("<H", d, 16, 4); variant("core_type", d)
    d = bytearray(pie); struct.pack_into("<H", d, 16, 0); variant("type_none", d)
    # Section table problems.
    variant("truncated_sections", pie[:3000])
    variant("truncated_tiny", pie[:200])
    d = bytearray(pie); struct.pack_into("<Q", d, 40, 0); struct.pack_into("<H", d, 60, 0); struct.pack_into("<H", d, 62, 0); variant("sectionless", d)
    d = bytearray(pie); struct.pack_into("<H", d, 62, 0); variant("no_shstrndx", d)
    d = bytearray(pie); struct.pack_into("<H", d, 62, 200); variant("shstrndx_out_of_range", d)
    d = bytearray(pie); struct.pack_into("<H", d, 62, 1); variant("shstrndx_not_strtab", d)
    d = bytearray(pie); struct.pack_into("<H", d, 62, 0xff10); variant("shstrndx_reserved", d)
    d = bytearray(pie); struct.pack_into("<H", d, 62, 0xffff); variant("shstrndx_xindex_small", d)
    d = bytearray(pie); struct.pack_into("<H", d, 58, 10); variant("small_shentsize", d)
    elf = Elf(pie)
    # A section that points outside the file.
    d = bytearray(pie)
    index, base, fields = elf.find_section(1)  # first PROGBITS
    struct.pack_into("<Q", d, base + 24, len(pie) + 4096)
    variant("section_offset_beyond", d)
    # Symbol table problems.
    sym_index, sym_base, sym_fields = elf.find_section(2)  # SYMTAB
    d = bytearray(pie)
    struct.pack_into("<I", d, sym_fields[4] + 24 * 3, 0x7fffff)
    variant("symbol_name_out_of_range", d)
    d = bytearray(pie); struct.pack_into("<Q", d, sym_base + 56, 8); variant("symbol_entsize_small", d)
    d = bytearray(pie); struct.pack_into("<I", d, sym_base + 40, 1); variant("symbol_bad_link", d)
    # Relocation problems.
    rel_index, rel_base, rel_fields = elf.find_section(4)  # first RELA
    d = bytearray(pie); struct.pack_into("<Q", d, rel_fields[4] + 8, (9999 << 32) | 6); variant("reloc_bad_symbol", d)
    d = bytearray(pie); struct.pack_into("<Q", d, rel_base + 56, 8); variant("reloc_entsize_wrong", d)
    # Segment problems.
    dyn_index, dyn_base, dyn_fields = elf.find_segment(2)
    d = bytearray(pie); struct.pack_into("<Q", d, dyn_base + 32, 16); variant("dynamic_unterminated", d)
    load_index, load_base, load_fields = elf.find_segment(1)
    d = bytearray(pie); struct.pack_into("<Q", d, load_base + 40, 8); variant("load_memsz_small", d)
    interp_index, interp_base, interp_fields = elf.find_segment(3)
    d = bytearray(pie); struct.pack_into("<Q", d, interp_base + 32, 4); variant("interp_unterminated", d)
    d = bytearray(pie); struct.pack_into("<Q", d, load_base + 8, len(pie) + 8192); variant("segment_offset_beyond", d)
    d = bytearray(pie); struct.pack_into("<H", d, 54, 8); variant("small_phentsize", d)
    # Dynamic string table tags.
    d = bytearray(pie)
    strtab_pos = None
    for n in range(dyn_fields[5] // 16):
        tag, value = struct.unpack_from("<qQ", d, dyn_fields[2] + n * 16)
        if tag == 5:
            strtab_pos = dyn_fields[2] + n * 16
    struct.pack_into("<q", d, strtab_pos, 0x6ffffef5)
    variant("dynamic_no_strtab", d)
    # Static executable without sections, and stripped section names.
    variant("object_truncated_rela", obj[: obj.find(b".rela") if False else len(obj) - 400])
    # nopie_plain with its GNU_STACK marked executable and with no GNU_STACK / RELRO type renamed.
    elfp = Elf(plain)
    stack_index, stack_base, stack_fields = elfp.find_segment(0x6474E551)
    d = bytearray(plain); struct.pack_into("<I", d, stack_base + 4, 7); variant("stack_executable", d)
    d = bytearray(plain); struct.pack_into("<I", d, stack_base, 0x6474E5FF); variant("stack_missing", d)


if __name__ == "__main__":
    main(sys.argv[1])
