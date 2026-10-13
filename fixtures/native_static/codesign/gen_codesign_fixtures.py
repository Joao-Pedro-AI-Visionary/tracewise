#!/usr/bin/env python3
"""Signed Mach-O fixtures for inspect_signature, produced with rcodesign (apple-codesign 0.29.0).

usage: python3 gen_codesign_fixtures.py <base.macho> <out-dir> <rcodesign-bin>

<base.macho> is `macho_golden/dyld_inventory.macho` (generated, no third-party code). The
script strips its placeholder LC_CODE_SIGNATURE, derives an x86_64 variant, and signs:
  unsigned_arm64.macho       no signature
  adhoc_arm64.macho          ad hoc
  cert_arm64.macho           self-signed Developer ID profile, runtime flag, entitlements, Apple
                             timestamp (network: http://timestamp.apple.com/ts01)
  universal_signed.macho     x86_64 + arm64, both cert-signed
  universal_mixed.macho      x86_64 unsigned + arm64 cert-signed
The committed outputs are the artifacts the tests read; they are not regenerated in CI.
"""
import os
import struct
import subprocess
import sys
import tempfile

ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/><key>com.apple.security.network.client</key><true/><key>com.apple.security.application-groups</key><array><string>group.example</string></array><key>count</key><integer>3</integer></dict></plist>
"""


def strip_signature(data):
    data = bytearray(data)
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    at = 32
    commands = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        commands.append((cmd, at, size))
        at += size
    cmd, position, size = [c for c in commands if c[0] == 0x1D][0]
    signature_offset, _ = struct.unpack_from("<II", data, position + 8)
    del data[position:position + size]
    data += bytes(size)
    struct.pack_into("<I", data, 16, ncmds - 1)
    struct.pack_into("<I", data, 20, sizeofcmds - size)
    at = 32
    for _ in range(ncmds - 1):
        cmd, size = struct.unpack_from("<II", data, at)
        if cmd == 0x19 and bytes(data[at + 8:at + 24]).rstrip(b"\0") == b"__LINKEDIT":
            fileoff, _ = struct.unpack_from("<QQ", data, at + 40)
            struct.pack_into("<Q", data, at + 48, signature_offset - fileoff)
        at += size
    del data[signature_offset:]
    return bytes(data)


def as_x86_64(data):
    data = bytearray(data)
    struct.pack_into("<II", data, 4, 0x01000007, 3)
    return bytes(data)


def fat(slices):
    """slices: [(cputype, cpusubtype, bytes)], 2^14 aligned like ld64's lipo output."""
    align = 14
    header = struct.pack(">II", 0xCAFEBABE, len(slices))
    offset = 1 << align
    entries = b""
    body = b""
    cursor = offset
    for cputype, cpusubtype, content in slices:
        entries += struct.pack(">IIIII", cputype, cpusubtype, cursor, len(content), align)
        body += bytes(cursor - offset - len(body)) + content
        cursor = offset + len(body)
        cursor = (cursor + (1 << align) - 1) & ~((1 << align) - 1)
    blob = header + entries
    blob += bytes(offset - len(blob)) + body
    return blob


def main(base, out, rcodesign):
    os.makedirs(out, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        arm = os.path.join(work, "arm64.macho")
        x86 = os.path.join(work, "x86_64.macho")
        original = open(base, "rb").read()
        open(arm, "wb").write(strip_signature(original))
        open(x86, "wb").write(as_x86_64(strip_signature(original)))
        subprocess.run([rcodesign, "generate-self-signed-certificate", "--algorithm", "ecdsa", "--profile",
                        "developer-id-application", "--person-name", "Fixture Signer", "--team-id", "ABCDE12345",
                        "--pem-filename", os.path.join(work, "dev")], check=True, capture_output=True)
        ent = os.path.join(work, "ent.xml")
        open(ent, "w").write(ENTITLEMENTS)
        pem = ["--pem-file", os.path.join(work, "dev.crt"), "--pem-file", os.path.join(work, "dev.key")]

        def sign(source, target, adhoc=False, identifier="com.example.fixture"):
            command = [rcodesign, "sign", "--binary-identifier", identifier]
            if not adhoc:
                command += ["--code-signature-flags", "runtime", "--entitlements-xml-path", ent] + pem
                command += ["--timestamp-url", "http://timestamp.apple.com/ts01"]
            subprocess.run(command + [source, target], check=True, capture_output=True)

        open(os.path.join(out, "unsigned_arm64.macho"), "wb").write(open(arm, "rb").read())
        sign(arm, os.path.join(out, "adhoc_arm64.macho"), adhoc=True, identifier="com.example.adhoc")
        sign(arm, os.path.join(out, "cert_arm64.macho"))
        sign(x86, os.path.join(work, "x86_signed.macho"))
        arm_signed = open(os.path.join(out, "cert_arm64.macho"), "rb").read()
        x86_signed = open(os.path.join(work, "x86_signed.macho"), "rb").read()
        x86_unsigned = open(x86, "rb").read()
        open(os.path.join(out, "universal_signed.macho"), "wb").write(
            fat([(0x01000007, 3, x86_signed), (0x0100000C, 0, arm_signed)]))
        open(os.path.join(out, "universal_mixed.macho"), "wb").write(
            fat([(0x01000007, 3, x86_unsigned), (0x0100000C, 0, arm_signed)]))


if __name__ == "__main__":
    main(*sys.argv[1:4])
