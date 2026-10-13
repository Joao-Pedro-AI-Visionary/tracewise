#!/usr/bin/env python3
"""Regenerate the native_static fixtures (Mach-O bundles, NIBArchive, plists).

The Mach-O and NIBArchive encoders mirror the REA test helpers
(`src/artifacts/apple/MachoImage.fixture.ts`, `NibArchive.fixture.ts`) field by
field, so the oracle (REA) and tracewise read byte-identical inputs.

Usage: python3 gen_fixtures.py <output-dir>
"""
import datetime
import os
import plistlib
import shutil
import struct
import sys

LC = {
    "LOAD_DYLIB": 0xC,
    "ID_DYLIB": 0xD,
    "LOAD_WEAK_DYLIB": 0x80000018,
    "REEXPORT_DYLIB": 0x8000001F,
    "LAZY_LOAD_DYLIB": 0x20,
    "LOAD_UPWARD_DYLIB": 0x80000023,
    "RPATH": 0x8000001C,
    "DYLD_ENVIRONMENT": 0x27,
    "CODE_SIGNATURE": 0x1D,
    "BUILD_VERSION": 0x32,
    "VERSION_MIN_MACOSX": 0x24,
    "VERSION_MIN_IPHONEOS": 0x25,
}
CPU = {
    "i386": (7, 3),
    "arm64": (0x0100000C, 0),
    "arm64e": (0x0100000C, 0x80000002),
    "x86_64": (0x01000007, 3),
}
FILE_TYPE = {"execute": 2, "dylib": 6, "bundle": 8}


def command_with_string(command, fields, text):
    name = text.encode()
    name_offset = 8 + len(fields) * 4 + 4
    size = -(-(name_offset + len(name) + 1) // 8) * 8
    out = bytearray(size)
    struct.pack_into("<III", out, 0, command, size, name_offset)
    for index, value in enumerate(fields):
        struct.pack_into("<I", out, 12 + index * 4, value)
    out[name_offset : name_offset + len(name)] = name
    return bytes(out)


def dylib_command(command, name, current=0x10000, compat=0x10000):
    return command_with_string(command, [2, current, compat], name)


def dylib_use_command(command, name, flags):
    return command_with_string(command, [0x1A741800, 0x10000, 0x10000, flags], name)


def rpath_command(path):
    return command_with_string(LC["RPATH"], [], path)


def dyld_environment_command(value):
    return command_with_string(LC["DYLD_ENVIRONMENT"], [], value)


def code_signature_command():
    return struct.pack("<IIII", LC["CODE_SIGNATURE"], 16, 0, 0)


def build_version_command(platform):
    out = bytearray(24)
    struct.pack_into("<III", out, 0, LC["BUILD_VERSION"], 24, platform)
    return bytes(out)


def macho_image(cpu="arm64", file_type=FILE_TYPE["execute"], commands=(), wide=True):
    header_size = 32 if wide else 28
    body = b"".join(commands)
    out = bytearray(header_size + len(body) + 16)
    cpu_type, cpu_subtype = CPU[cpu]
    struct.pack_into(
        "<IIIIII",
        out,
        0,
        0xFEEDFACF if wide else 0xFEEDFACE,
        cpu_type,
        cpu_subtype,
        file_type,
        len(commands),
        len(body),
    )
    out[header_size : header_size + len(body)] = body
    return bytes(out)


def fat_image(slices, wide=False, little=False):
    entry = 32 if wide else 20
    offsets = []
    end = 4096
    for _, data in slices:
        offsets.append(end)
        end += -(-len(data) // 4096) * 4096
    out = bytearray(end)
    e = "<" if little else ">"
    struct.pack_into(e + "II", out, 0, 0xCAFEBABF if wide else 0xCAFEBABE, len(slices))
    for index, (cpu, data) in enumerate(slices):
        base = 8 + index * entry
        offset = offsets[index]
        struct.pack_into(e + "II", out, base, CPU[cpu][0], CPU[cpu][1])
        if wide:
            struct.pack_into(e + "QQI", out, base + 8, offset, len(data), 12)
        else:
            struct.pack_into(e + "III", out, base + 8, offset, len(data), 12)
        out[offset : offset + len(data)] = data
    return bytes(out)


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            byte |= 0x80
        out.append(byte)
        if value == 0:
            return bytes(out)


def encode_value(value):
    if isinstance(value, bool):
        return bytes([4 if value else 5])
    if value is None:
        return bytes([9])
    if isinstance(value, int):
        return bytes([2]) + struct.pack("<i", value)
    if isinstance(value, dict):
        return bytes([10]) + struct.pack("<I", value["ref"])
    data = value.encode()
    return bytes([8]) + varint(len(data)) + data


def encode_nib(classes, objects):
    keys = []
    for _, values in objects:
        for key in values:
            if key not in keys:
                keys.append(key)
    value_records = []
    for _, values in objects:
        for key, value in values.items():
            value_records.append(varint(keys.index(key)) + encode_value(value))
    value_start = 0
    records = []
    for class_index, values in objects:
        count = len(values)
        records.append(varint(class_index) + varint(value_start) + varint(count))
        value_start += count
    objects_blob = b"".join(records)
    keys_blob = b"".join(varint(len(k.encode())) + k.encode() for k in keys)
    values_blob = b"".join(value_records)
    classes_blob = b"".join(varint(len(c.encode())) + varint(0) + c.encode() for c in classes)
    objects_offset = 50
    keys_offset = objects_offset + len(objects_blob)
    values_offset = keys_offset + len(keys_blob)
    classes_offset = values_offset + len(values_blob)
    header = bytearray(50)
    header[0:10] = b"NIBArchive"
    struct.pack_into(
        "<IIIIIIIIII",
        header,
        10,
        1,
        10,
        len(objects),
        objects_offset,
        len(keys),
        keys_offset,
        value_start,
        values_offset,
        len(classes),
        classes_offset,
    )
    return bytes(header) + objects_blob + keys_blob + values_blob + classes_blob


def write(path, data, mode="wb"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as handle:
        handle.write(data)


def info_plist(executable):
    return (
        "<plist><dict><key>CFBundleExecutable</key><string>%s</string></dict></plist>" % executable
    ).encode()


# ---------------------------------------------------------------------------
# bundles
# ---------------------------------------------------------------------------


def make_fixture_app(root):
    app = os.path.join(root, "Fixture.app")
    write(os.path.join(app, "Contents/Info.plist"), info_plist("App"))
    write(
        os.path.join(app, "Contents/MacOS/App"),
        macho_image(
            commands=[
                build_version_command(1),
                rpath_command("@executable_path/../Frameworks"),
                dylib_command(LC["LOAD_DYLIB"], "@rpath/libcore.dylib"),
            ]
        ),
    )
    write(
        os.path.join(app, "Contents/Frameworks/libcore.dylib"),
        macho_image(file_type=FILE_TYPE["dylib"], commands=[build_version_command(1)]),
    )


def make_rich_app(root):
    app = os.path.join(root, "Rich.app")
    write(os.path.join(app, "Contents/Info.plist"), info_plist("Rich"))
    main = macho_image(
        commands=[
            build_version_command(1),
            rpath_command("@executable_path/../Frameworks"),
            rpath_command("@loader_path/../Plugins"),
            rpath_command("/opt/absolute"),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libcore.dylib"),
            dylib_command(LC["LOAD_WEAK_DYLIB"], "@rpath/libweak.dylib"),
            dylib_command(LC["REEXPORT_DYLIB"], "@rpath/libre.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@executable_path/../Frameworks/libexec.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@loader_path/libsibling.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "/usr/lib/libSystem.B.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "libleaf.dylib"),
            dylib_command(LC["LAZY_LOAD_DYLIB"], "@rpath/liblazy.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libmissing.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libx86only.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libplat.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libnotdylib.dylib"),
            dylib_command(LC["LOAD_UPWARD_DYLIB"], "@rpath/libup.dylib"),
            dylib_use_command(LC["LOAD_DYLIB"], "@rpath/libuse.dylib", 0x1 | 0x8),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libalias.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libfat.dylib"),
            dylib_command(LC["LOAD_DYLIB"], "@rpath/libbad.dylib"),
            dyld_environment_command("DYLD_PRINT_RPATHS=1"),
            code_signature_command(),
        ]
    )
    write(os.path.join(app, "Contents/MacOS/Rich"), main)
    fw = os.path.join(app, "Contents/Frameworks")
    dylib = lambda name, extra=(), cpu="arm64", platform=1: macho_image(  # noqa: E731
        cpu=cpu,
        file_type=FILE_TYPE["dylib"],
        commands=[build_version_command(platform), dylib_command(LC["ID_DYLIB"], name)] + list(extra),
    )
    write(
        os.path.join(fw, "libcore.dylib"),
        dylib("@rpath/libcore.dylib", [dylib_command(LC["LOAD_DYLIB"], "@loader_path/libnested.dylib")]),
    )
    write(os.path.join(fw, "libnested.dylib"), dylib("@loader_path/libnested.dylib"))
    write(os.path.join(fw, "libre.dylib"), dylib("@rpath/libre.dylib"))
    write(os.path.join(fw, "libexec.dylib"), dylib("@executable_path/../Frameworks/libexec.dylib"))
    write(os.path.join(fw, "liblazy.dylib"), dylib("@rpath/liblazy.dylib"))
    write(os.path.join(fw, "libx86only.dylib"), dylib("@rpath/libx86only.dylib", cpu="x86_64"))
    write(os.path.join(fw, "libplat.dylib"), dylib("@rpath/libplat.dylib", platform=2))
    write(os.path.join(fw, "libnotdylib.dylib"), macho_image(commands=[build_version_command(1)]))
    write(os.path.join(fw, "libup.dylib"), dylib("@rpath/libup.dylib"))
    write(os.path.join(fw, "libuse.dylib"), dylib("@rpath/libuse.dylib"))
    write(
        os.path.join(fw, "libfat.dylib"),
        fat_image(
            [
                ("arm64", dylib("@rpath/libfat.dylib")),
                ("x86_64", dylib("@rpath/libfat.dylib", cpu="x86_64")),
            ]
        ),
    )
    # A load command that runs past sizeofcmds.
    broken = bytearray(macho_image(file_type=FILE_TYPE["dylib"], commands=[build_version_command(1)]))
    struct.pack_into("<I", broken, 20, 4000)
    write(os.path.join(fw, "libbad.dylib"), bytes(broken[:100]))
    write(os.path.join(app, "Contents/MacOS/libsibling.dylib"), dylib("@loader_path/libsibling.dylib"))
    write(os.path.join(app, "Contents/Resources/data.bin"), b"not a mach-o file at all")
    os.makedirs(os.path.join(app, "Contents/Plugins"), exist_ok=True)
    link = os.path.join(fw, "libalias.dylib")
    if os.path.lexists(link):
        os.remove(link)
    os.symlink("libcore.dylib", link)
    escape = os.path.join(fw, "libescape.dylib")
    if os.path.lexists(escape):
        os.remove(escape)
    os.symlink("/usr/lib/libSystem.B.dylib", escape)
    # Second process root: an XPC service sharing the app frameworks through ../../../../.
    helper = os.path.join(app, "Contents/XPCServices/Helper.xpc/Contents/MacOS/Helper")
    write(
        helper,
        macho_image(
            cpu="x86_64",
            commands=[
                build_version_command(1),
                rpath_command("@executable_path/../../../../../Frameworks"),
                dylib_command(LC["LOAD_DYLIB"], "@rpath/libcore.dylib"),
            ],
        ),
    )
    write(
        os.path.join(app, "Contents/XPCServices/Helper.xpc/Contents/Info.plist"),
        info_plist("Helper"),
    )


def make_flat_ios_app(root):
    app = os.path.join(root, "Flat.app")
    write(os.path.join(app, "Info.plist"), info_plist("Flat"))
    write(
        os.path.join(app, "Flat"),
        macho_image(
            commands=[
                build_version_command(2),
                rpath_command("@executable_path/Frameworks"),
                dylib_command(LC["LOAD_DYLIB"], "@rpath/Kit.framework/Kit"),
            ]
        ),
    )
    write(
        os.path.join(app, "Frameworks/Kit.framework/Kit"),
        macho_image(
            file_type=FILE_TYPE["dylib"],
            commands=[build_version_command(2), dylib_command(LC["ID_DYLIB"], "@rpath/Kit.framework/Kit")],
        ),
    )


def keyed_archive(objects, top):
    return {"$archiver": "NSKeyedArchiver", "$version": 100000, "$objects": objects, "$top": top}


def class_descriptor(name, *supers):
    return {"$classname": name, "$classes": [name, *supers, "NSObject"]}


UID = plistlib.UID


def xml_ready(value):
    if isinstance(value, UID):
        return {"CF$UID": value.data}
    if isinstance(value, dict):
        return {k: xml_ready(v) for k, v in value.items()}
    if isinstance(value, list):
        return [xml_ready(v) for v in value]
    return value


def make_ib_app(root):
    app = os.path.join(root, "Ib.app")
    write(os.path.join(app, "Contents/Info.plist"), info_plist("Ib"))
    write(
        os.path.join(app, "Contents/MacOS/Ib"),
        macho_image(commands=[build_version_command(1)]),
    )
    res = os.path.join(app, "Contents/Resources")
    # AppKit-style NIBArchive: window with a view, a button, an outlet and an action.
    classes = [
        "NSIBObjectData",  # 0
        "NSWindowTemplate",  # 1
        "NSView",  # 2
        "NSButton",  # 3
        "NSString",  # 4
        "NSNibOutletConnector",  # 5
        "NSNibControlConnector",  # 6
        "NSCustomObject",  # 7
        "NSArray",  # 8
        "NSClassSwapper",  # 9
    ]
    objects = [
        (0, {"NSRoot": {"ref": 1}}),  # 0
        (1, {"NSWindowView": {"ref": 2}, "NSWindowTitle": {"ref": 11}}),  # 1
        (2, {"NSSubviews": {"ref": 8}, "NSIdentifier": {"ref": 12}}),  # 2
        (3, {"NSSuperview": {"ref": 2}, "NSTitle": {"ref": 13}, "NSEnabled": True, "NSTag": 7}),  # 3
        (7, {"NSClassName": {"ref": 14}}),  # 4 file's owner
        (5, {"NSSource": {"ref": 4}, "NSDestination": {"ref": 3}, "NSLabel": {"ref": 15}}),  # 5
        (6, {"NSSource": {"ref": 3}, "NSDestination": {"ref": 4}, "NSLabel": {"ref": 16}}),  # 6
        (4, {"NS.bytes": "unused"}),  # 7
        (8, {"NS.object.0": {"ref": 3}}),  # 8
        (9, {"NSClassName": {"ref": 17}, "NSOriginalClassName": {"ref": 18}}),  # 9 class swapper
        (4, {"NS.bytes": "ignored"}),  # 10
        (4, {"NS.bytes": "Main Window"}),  # 11
        (4, {"NS.bytes": "rootView"}),  # 12
        (4, {"NS.bytes": "Click me"}),  # 13
        (4, {"NS.bytes": "Controller"}),  # 14
        (4, {"NS.bytes": "okButton"}),  # 15
        (4, {"NS.bytes": "doIt:"}),  # 16
        (4, {"NS.bytes": "MyButton"}),  # 17
        (4, {"NS.bytes": "NSButton"}),  # 18
    ]
    write(os.path.join(res, "Main.storyboardc/Window.nib"), encode_nib(classes, objects))
    write(os.path.join(res, "Plain.nib"), encode_nib(classes, objects[:4]))
    # UIKit-style NIBArchive with runtime connections.
    ui_classes = [
        "UINib",
        "UIView",
        "UIButton",
        "UIRuntimeOutletConnection",
        "UIRuntimeEventConnection",
        "NSString",
        "UIProxyObject",
        "NSArray",
    ]
    ui_objects = [
        (0, {}),  # 0
        (1, {"UISubviews": {"ref": 6}}),  # 1
        (2, {"UISuperview": {"ref": 1}, "UIAccessibilityLabel": {"ref": 8}}),  # 2
        (6, {"UIProxiedObjectIdentifier": {"ref": 9}}),  # 3
        (3, {"UISource": {"ref": 3}, "UIDestination": {"ref": 2}, "UILabel": {"ref": 10}}),  # 4
        (4, {"UISource": {"ref": 2}, "UIDestination": {"ref": 3}, "UILabel": {"ref": 11}, "UIEventMask": 64}),  # 5
        (7, {"UINibEncoderEmptyKey": {"ref": 2}}),  # 6
        (5, {"NS.bytes": "x"}),  # 7
        (5, {"NS.bytes": "Submit"}),  # 8
        (5, {"NS.bytes": "IBFilesOwner"}),  # 9
        (5, {"NS.bytes": "submitButton"}),  # 10
        (5, {"NS.bytes": "submit:"}),  # 11
    ]
    write(os.path.join(res, "Base.lproj/Mobile.storyboardc/View.nib"), encode_nib(ui_classes, ui_objects))
    # ibtool-style document in XML plist form.
    ibtool = {
        "com.apple.ibtool.document.objects": {
            "10": {"customClass": "AppDelegate", "label": "App Delegate", "objectID": "10"},
            "2": {"customClass": "NSButton", "label": "OK", "objectID": "2", "frame": [0, 0, 80.5, 20]},
            "3": {"class": "NSLayoutConstraint"},
            "x7": {"isa": "NSWindow", "title": "Main"},
        },
        "com.apple.ibtool.document.connections": {
            "10": [
                {"type": "IBOutletConnection", "destination-id": "2", "label": "okButton"},
                {"type": "IBActionConnection", "destination-id": "10", "label": "perform:"},
                {"type": "IBSegue", "destination-id": "missing-scene", "label": "show"},
                {"type": "Weird", "destination-id": "2"},
            ],
            "2": [{"connectionType": "action", "destinationId": "10", "selector": "clicked:"}],
        },
        "com.apple.ibtool.document.hierarchy": [
            {"objectID": "10", "children": [{"objectID": "2", "children": []}, {"objectID": "ghost", "children": []}]}
        ],
        "com.apple.ibtool.document.classes": {"AppDelegate": {}},
    }
    write(os.path.join(res, "Legacy.nib"), plistlib.dumps(ibtool, fmt=plistlib.FMT_XML))
    write(os.path.join(res, "LegacyBinary.nib"), plistlib.dumps(ibtool, fmt=plistlib.FMT_BINARY))
    # Keyed-archive document (older compiled XIBs).
    keyed_objects = [
        "$null",
        {"$class": UID(5), "NS.objects": [UID(2), UID(3)]},
        {"$class": UID(6), "objectID": UID(7), "label": UID(8), "subviews": UID(1)},
        {"$class": UID(9), "source": UID(2), "destination": UID(3), "label": UID(8)},
        class_descriptor("NSArray"),
        class_descriptor("NSArray"),
        class_descriptor("NSView"),
        "v1",
        "Window",
        class_descriptor("NSNibOutletConnector"),
    ]
    keyed_objects[5] = class_descriptor("NSArray")
    keyed_objects[4] = class_descriptor("NSMutableArray")
    write(
        os.path.join(res, "Keyed.nib"),
        plistlib.dumps(xml_ready(keyed_archive(keyed_objects, {"root": UID(1)})), fmt=plistlib.FMT_XML),
    )
    # Not a recognizable archive and one that cannot be decoded at all.
    write(os.path.join(res, "Broken.nib"), b"\x00\x01 this is not a nib")
    write(os.path.join(res, "Empty.nib"), b"")
    # Plain (non-archiver) plist and keyed archives for inspect_keyed_archive.
    write(os.path.join(res, "Settings.plist"), plistlib.dumps({"a": 1, "b": [1, 2]}, fmt=plistlib.FMT_XML))
    when = datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    rich_objects = [
        "$null",
        {"$class": UID(8), "NS.objects": [UID(2), UID(3), UID(4), UID(999), UID(0), UID(1)]},
        "plain string",
        {
            "$class": UID(9),
            "count": 42,
            "negative": -7,
            "big": 2**62,
            "bigneg": -(2**63),
            "ratio": 1.5,
            "whole": 2.0,
            "flag": True,
            "none": False,
            "when": when.replace(tzinfo=None),
            "blob": b"\x00\x01\x02\xff",
            "nested": {"list": [UID(2), 1, "x"], "deep": {"uid": UID(2)}},
            "owner": UID(1),
            "missing": UID(7),
            "emoji": "snowman ☃ \U0001F600",
        },
        {"$class": UID(9), "name": UID(2), "mask": 2**53 + 1},
        3.25,
        7,
        class_descriptor("NSMutableArray", "NSArray"),
        class_descriptor("Fixture.Record"),
    ]
    top = {"root": UID(1), "alt": UID(3)}
    write(os.path.join(res, "Rich.plist"), plistlib.dumps(keyed_archive(rich_objects, top), fmt=plistlib.FMT_BINARY))
    write(os.path.join(res, "RichXml.plist"), plistlib.dumps(xml_ready(keyed_archive(rich_objects, top)), fmt=plistlib.FMT_XML))
    write(os.path.join(res, "Sub/Dir/Nested.plist"), plistlib.dumps(keyed_archive(["$null", "x"], {"root": UID(1)}), fmt=plistlib.FMT_BINARY))
    # Wrong $archiver and no $top.
    write(os.path.join(res, "Other.plist"), plistlib.dumps({"$archiver": "Other", "$objects": []}, fmt=plistlib.FMT_XML))
    write(os.path.join(res, "NoTop.plist"), plistlib.dumps(xml_ready(keyed_archive(["$null"], {})), fmt=plistlib.FMT_XML))
    write(os.path.join(res, "Café.plist"), plistlib.dumps(xml_ready(keyed_archive(["$null", "x"], {"root": UID(1)})), fmt=plistlib.FMT_XML))
    os.symlink("Rich.plist", os.path.join(res, "Link.plist")) if not os.path.lexists(os.path.join(res, "Link.plist")) else None
    write(os.path.join(res, "Truncated.plist"), plistlib.dumps(keyed_archive(rich_objects, top), fmt=plistlib.FMT_BINARY)[:-20])


DOC_RUNTIME = "6080604052348015600e575f80fd5b50600436106030575f3560e01c80632125b65b146034578063b69ef8a8146044575b5f80fd5b6044603f3660046046565b505050565b005b5f805f606084860312156057575f80fd5b833563ffffffff811681146069575f80fd5b925060208401356001600160a01b03811681146083575f80fd5b915060408401356001600160e01b0381168114609d575f80fd5b80915050925092509256"


def make_evm(out):
    os.makedirs(out, exist_ok=True)
    runtime = bytes.fromhex(DOC_RUNTIME)
    cbor = b"\xa2" + b"\x64ipfs" + b"\x58\x22" + bytes(range(34)) + b"\x64solc" + b"\x43\x00\x08\x14"
    with_metadata = runtime + cbor + len(cbor).to_bytes(2, "big")
    seed = 12345
    noise = bytearray()
    for _ in range(2048):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        noise.append((seed >> 16) & 0xFF)
    files = {
        "doc.hex": DOC_RUNTIME.encode(),
        "doc_prefixed.hex": ("  0x" + DOC_RUNTIME + "\n\t").encode(),
        "doc_upper.hex": ("0X" + DOC_RUNTIME.upper()).encode(),
        "doc.bin": runtime,
        "meta.hex": with_metadata.hex().encode(),
        "meta.bin": with_metadata,
        "empty.hex": b"",
        "empty.bin": b"",
        "tiny.hex": b"60006000f3",
        "odd.hex": b"600",
        "spaced.hex": b"6000 6000f3",
        "nonutf8.hex": b"\xff\xfe00",
        "bom.hex": b"\xef\xbb\xbf6000",
        "ef00.bin": b"\xef\x00\x01\x01\x00\x04\x02\x00\x01",
        "ef00.hex": b"ef000101",
        "zeros.bin": bytes(64),
        "noise.bin": bytes(noise),
        "noise.hex": bytes(noise).hex().encode(),
        "stop.bin": b"\x00",
    }
    for name, data in files.items():
        write(os.path.join(out, name), data)
    os.makedirs(os.path.join(out, "dir.hex"), exist_ok=True)
    link = os.path.join(out, "link.hex")
    if os.path.lexists(link):
        os.remove(link)
    os.symlink("doc.hex", link)


def main():
    out = sys.argv[1]
    for name in ("Fixture.app", "Rich.app", "Flat.app", "Ib.app"):
        shutil.rmtree(os.path.join(out, name), ignore_errors=True)
    make_fixture_app(out)
    make_rich_app(out)
    make_flat_ios_app(out)
    make_ib_app(out)
    write(os.path.join(out, "plain/Info.plist"), plistlib.dumps({"CFBundleName": "Plain"}, fmt=plistlib.FMT_XML))
    make_evm(os.path.join(os.path.dirname(out), "evm"))
    import gen_pe
    gen_pe.main(os.path.join(os.path.dirname(out), "pe"))


if __name__ == "__main__":
    main()
