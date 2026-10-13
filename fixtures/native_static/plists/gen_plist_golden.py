#!/usr/bin/env python3
"""Property-list fixtures and what the ORIGINAL REA derives from them.

For each plist this writes the file, replays the plutil view of it (JSON conversion, XML
conversion, `file -b`) through REA's NativeMacOSProvider and stores REA's inspect_plist result
as <name>.expected.json. The native decoder is compared with it in
`crates/server/tests/native_static_macho_test.rs`.

usage: python3 gen_plist_golden.py <out-dir>
"""
import datetime
import json
import os
import plistlib
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPLAY = os.path.join(HERE, "..", "macho_golden", "replay_rea.mjs")

SIMPLE = {
    "CFBundleIdentifier": "com.example.fixture",
    "CFBundleExecutable": "Fixture",
    "CFBundleName": "Fixture",
    "CFBundleVersion": "42",
    "CFBundleShortVersionString": "1.2.3",
    "LSMinimumSystemVersion": "12.0",
    "Count": 3,
    "Ratio": 0.5,
    "Flag": True,
    "Nested": {"Items": [1, 2, "três", {"k": "v"}], "Empty": []},
    "Unicode": "café \U0001f600",
}
TYPED = {
    "CFBundleIdentifier": "com.example.typed",
    "Blob": b"\x00\x01\xfe\xff",
    "When": datetime.datetime(2020, 1, 2, 3, 4, 5),
    "List": [b"ab", datetime.datetime(1999, 12, 31, 23, 59, 59)],
}


def write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def replay(name, plist_path, file_text, json_text, json_exit, xml_text, out):
    scenario = {
        "operation": "inspect_plist",
        "parameters": {"path": plist_path},
        "target": {"path": "/private/fixture", "sourcePath": os.path.dirname(plist_path)},
        "outputs": {"file": file_text, "plutil:json": json_text, "plutil:xml1": xml_text},
        "exitCodes": {"plutil:json": json_exit},
        "stderr": {"plutil:json": "" if json_exit == 0 else "%s: Invalid object in plist for destination format\n" % plist_path},
    }
    scenario_path = os.path.join(out, name + ".scenario.json")
    json.dump(scenario, open(scenario_path, "w"), indent=1)
    subprocess.run(["node", REPLAY, scenario_path, os.path.join(out, name + ".expected.json")], check=True)
    os.remove(scenario_path)


def main(out):
    os.makedirs(out, exist_ok=True)
    cases = {}
    xml_simple = plistlib.dumps(SIMPLE, fmt=plistlib.FMT_XML)
    binary_simple = plistlib.dumps(SIMPLE, fmt=plistlib.FMT_BINARY)
    write(os.path.join(out, "xml_simple.plist"), xml_simple)
    write(os.path.join(out, "binary_simple.plist"), binary_simple)
    simple_json = json.dumps(SIMPLE, ensure_ascii=False)
    cases["xml_simple"] = ("XML 1.0 document text, ASCII text\n", simple_json, 0, xml_simple.decode())
    cases["binary_simple"] = ("Apple binary property list\n", simple_json, 0, xml_simple.decode())
    xml_typed = plistlib.dumps(TYPED, fmt=plistlib.FMT_XML)
    write(os.path.join(out, "xml_typed.plist"), xml_typed)
    write(os.path.join(out, "binary_typed.plist"), plistlib.dumps(TYPED, fmt=plistlib.FMT_BINARY))
    cases["xml_typed"] = ("XML 1.0 document text, ASCII text\n", "", 1, xml_typed.decode())
    cases["binary_typed"] = ("Apple binary property list\n", "", 1, xml_typed.decode())
    big = (
        b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        b"<key>CFBundleName</key><string>Big</string>"
        b"<key>Max</key><integer>18446744073709551615</integer>"
        b"<key>Min</key><integer>-9223372036854775808</integer>"
        b"<key>Near</key><integer>9007199254740993</integer>"
        b"<key>Safe</key><integer>9007199254740991</integer>"
        b"<key>Real</key><real>1e+21</real>"
        b"<key>Ratio</key><real>0.5</real></dict></plist>"
    )
    write(os.path.join(out, "xml_bigint.plist"), big)
    big_json = '{"CFBundleName":"Big","Max":18446744073709551615,"Min":-9223372036854775808,"Near":9007199254740993,"Safe":9007199254740991,"Real":1e+21,"Ratio":0.5}'
    cases["xml_bigint"] = ("XML 1.0 document text, ASCII text\n", big_json, 0, big.decode())
    for name, (file_text, json_text, json_exit, xml_text) in cases.items():
        replay(name, os.path.join(os.path.abspath(out), name + ".plist"), file_text, json_text, json_exit, xml_text, out)
    # Inputs REA rejects (or reads as text), kept for the error scenarios of the native test.
    write(os.path.join(out, "json.plist"), b'{"CFBundleName":"Json","n":1}')
    write(os.path.join(out, "not_plist.txt"), b"hello world\n")
    write(os.path.join(out, "empty.plist"), b"")
    write(os.path.join(out, "truncated.plist"), b"<plist><dict>")
    write(os.path.join(out, "proto.plist"),
          b'<plist><dict><key>__proto__</key><string>x</string><key>CFBundleName</key><string>P</string></dict></plist>')


if __name__ == "__main__":
    main(sys.argv[1])
