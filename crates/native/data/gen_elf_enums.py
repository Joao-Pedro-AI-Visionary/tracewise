#!/usr/bin/env python3
"""Dump the pyelftools 0.33 enumerations used by the ELF layout port.

pyelftools is in the public domain (Unlicense). Run with the interpreter that has
pyelftools 0.33 installed:  python gen_elf_enums.py > elf_enums.json

Construct's Enum decodes through a reverse mapping built in dictionary order, so a
later name wins for a shared value; the Rust side applies the same rule.
"""
import json

from elftools.elf import enums as e


def table(mapping):
    return [[name, value] for name, value in mapping.items() if name != "_default_"]


tables = {
    "e_type": e.ENUM_E_TYPE,
    "e_machine": e.ENUM_E_MACHINE,
    "p_type": e.ENUM_P_TYPE_BASE,
    "sh_type": e.ENUM_SH_TYPE_AMD64,
    "st_bind": e.ENUM_ST_INFO_BIND,
    "st_type": e.ENUM_ST_INFO_TYPE,
    "st_visibility": e.ENUM_ST_VISIBILITY,
    "st_shndx": e.ENUM_ST_SHNDX,
    "d_tag": e.ENUM_D_TAG_COMMON,
    "core_note_type": e.ENUM_CORE_NOTE_N_TYPE,
}
print(json.dumps({key: table(value) for key, value in tables.items()}, indent=0))
