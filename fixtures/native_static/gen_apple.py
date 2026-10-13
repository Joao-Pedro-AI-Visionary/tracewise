#!/usr/bin/env python3
"""Apple application layouts for project_apple_application_graph.

usage: python3 gen_apple.py <output-dir>

Mach-O content comes from gen_fixtures.macho_image so the inventory classifies these files
as `mach-o`, exactly as the REA oracle does for the same bytes.
"""
import os
import shutil
import stat
import sys
import zipfile

import gen_fixtures as g


def write(path, data=b""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    with open(path, "wb") as handle:
        handle.write(data)


MACHO = g.macho_image(file_type=g.FILE_TYPE["execute"], commands=[g.build_version_command(1)])
DYLIB = g.macho_image(file_type=g.FILE_TYPE["dylib"], commands=[g.build_version_command(1)])
PLIST = b'<?xml version="1.0"?><plist version="1.0"><dict/></plist>'


def plist_exec(name):
    return ('<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>%s</string></dict></plist>' % name).encode()


JS = b'__d(function(g,r,i,a,m,e,d){console.log("hello");},0,[]);\n' * 4


def populate_mac(root):
    base = os.path.join(root, "Contents")
    write(os.path.join(base, "Info.plist"), plist_exec("Mac"))
    write(os.path.join(base, "MacOS/Mac"), MACHO)
    write(os.path.join(base, "MacOS/libfoo.so"), DYLIB)
    write(os.path.join(base, "Frameworks/libswiftCore.dylib"), DYLIB)
    write(os.path.join(base, "Frameworks/Kit.framework/Versions/A/Kit"), DYLIB)
    write(os.path.join(base, "Frameworks/Kit.framework/Versions/A/Resources/Info.plist"), PLIST)
    os.symlink("A", os.path.join(base, "Frameworks/Kit.framework/Versions/Current"))
    os.symlink("Versions/Current/Kit", os.path.join(base, "Frameworks/Kit.framework/Kit"))
    write(os.path.join(base, "Frameworks/Two.framework/Versions/A/Two"), DYLIB)
    write(os.path.join(base, "Frameworks/Two.framework/Versions/B/Two"), DYLIB)
    write(os.path.join(base, "Frameworks/Two.framework/Versions/B/Resources/Info.plist"), PLIST)
    write(os.path.join(base, "Frameworks/Two.framework/Versions/.DS_Store"), b"x")
    write(os.path.join(base, "Frameworks/React.framework/React"), DYLIB)
    write(os.path.join(base, "Frameworks/hermes.framework/hermes"), DYLIB)
    write(os.path.join(base, "Frameworks/Flutter.framework/Flutter"), DYLIB)
    write(os.path.join(base, "Frameworks/UnityFramework.framework/UnityFramework"), DYLIB)
    write(os.path.join(base, "Resources/main.jsbundle"), JS)
    write(os.path.join(base, "Resources/plain.js"), JS)
    write(os.path.join(base, "Resources/data.bin"), b"\x00\x01\x02")
    write(os.path.join(base, "Resources/._data.bin"), b"\x00\x05\x16\x07")
    write(os.path.join(base, "Resources/Z.bundle/Info.plist"), PLIST)
    write(os.path.join(base, "Resources/Z.bundle/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "PlugIns/Y.bundle/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "PlugIns/Share.appex/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "PlugIns/Share.appex/Contents/MacOS/Share"), MACHO)
    write(os.path.join(base, "PlugIns/Gen.qlgenerator/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "PlugIns/Imp.mdimporter/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "XPCServices/Svc.xpc/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "XPCServices/Svc.xpc/Contents/MacOS/Svc"), MACHO)
    write(os.path.join(base, "Library/LoginItems/Login.app/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "Library/LoginItems/Login.app/Contents/MacOS/Login"), MACHO)
    write(os.path.join(base, "Library/SystemExtensions/Net.systemextension/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "Library/SystemExtensions/Net.systemextension/Contents/MacOS/Net"), MACHO)
    write(os.path.join(base, "Library/SystemExtensions/Drv.dext/Info.plist"), PLIST)
    write(os.path.join(base, "Library/LaunchServices/com.example.helper"), MACHO)
    write(os.path.join(base, "Library/LaunchDaemons/com.example.helper.plist"), PLIST)
    write(os.path.join(base, "Library/LaunchAgents/com.example.agent.plist"), PLIST)
    write(os.path.join(base, "Library/LaunchAgents/notes.txt"), b"x")
    write(os.path.join(base, "Helpers/tool"), MACHO)
    write(os.path.join(base, "Helpers/Helper.app/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "Helpers/Helper.app/Contents/MacOS/Helper"), MACHO)
    write(os.path.join(base, "Nested/Other.app/Contents/Info.plist"), PLIST)
    write(os.path.join(base, "Nested/Other.app/Contents/MacOS/Other"), MACHO)
    write(os.path.join(base, "_CodeSignature/CodeResources"), PLIST)
    write(os.path.join(base, "embedded.provisionprofile"), b"profile")
    write(os.path.join(base, "Frameworks/Kit.framework/Versions/A/_CodeSignature/CodeResources"), PLIST)


def populate_ios(root, prefix):
    write(os.path.join(root, prefix, "Info.plist"), plist_exec("Fixture"))
    write(os.path.join(root, prefix, "Fixture"), MACHO)
    write(os.path.join(root, prefix, "embedded.mobileprovision"), b"profile")
    write(os.path.join(root, prefix, "_CodeSignature/CodeResources"), PLIST)
    write(os.path.join(root, prefix, "main.jsbundle"), JS)
    write(os.path.join(root, prefix, "app.js"), JS)
    write(os.path.join(root, prefix, "Watch/watch.js"), JS)
    write(os.path.join(root, prefix, "Frameworks/React.framework/React"), DYLIB)
    write(os.path.join(root, prefix, "Frameworks/libswiftCore.dylib"), DYLIB)
    write(os.path.join(root, prefix, "Frameworks/libswift_Concurrency.dylib"), DYLIB)
    write(os.path.join(root, prefix, "Frameworks/libfoo.dylib"), DYLIB)
    write(os.path.join(root, prefix, "PlugIns/Share.appex/Info.plist"), PLIST)
    write(os.path.join(root, prefix, "PlugIns/Share.appex/Share"), MACHO)
    write(os.path.join(root, prefix, "Watch/Watch.app/Info.plist"), PLIST)
    write(os.path.join(root, prefix, "Watch/Watch.app/Watch"), MACHO)
    write(os.path.join(root, prefix, "Assets.car"), b"car")
    write(os.path.join(root, prefix, "._Fixture"), b"\x00\x05\x16\x07")


def zip_dir(source, target, root_prefix=None, symlinks=()):
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for directory, _, files in sorted(os.walk(source)):
            for name in sorted(files):
                full = os.path.join(directory, name)
                relative = os.path.relpath(full, source)
                if root_prefix:
                    relative = root_prefix + "/" + relative
                info = zipfile.ZipInfo(relative, date_time=(2020, 1, 1, 0, 0, 0))
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                with open(full, "rb") as handle:
                    archive.writestr(info, handle.read(), zipfile.ZIP_DEFLATED)
        for name, target_name in symlinks:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFLNK | 0o755) << 16
            archive.writestr(info, target_name)


def main(out):
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    mac = os.path.join(out, "Mac.app")
    populate_mac(mac)
    # Loose directory holding two applications and an installer sibling.
    loose = os.path.join(out, "Loose")
    populate_mac(os.path.join(loose, "One.app"))
    write(os.path.join(loose, "Two.app/Contents/Info.plist"), PLIST)
    write(os.path.join(loose, "Two.app/Contents/MacOS/Two"), MACHO)
    write(os.path.join(loose, "installer.pkg"), b"pkg")
    write(os.path.join(loose, "README.txt"), b"readme")
    # Application directories with unusual shapes.
    os.makedirs(os.path.join(out, "Empty.app"))
    write(os.path.join(out, "NoContents.app/Info.plist"), plist_exec("Exec"))
    write(os.path.join(out, "NoContents.app/Exec"), MACHO)
    write(os.path.join(out, "Shallow.app/Info.plist"), plist_exec("Shallow"))
    write(os.path.join(out, "Shallow.app/Shallow"), MACHO)
    write(os.path.join(out, "Shallow.app/Frameworks/React.framework/React"), DYLIB)
    write(os.path.join(out, "Upper.app/CONTENTS/MACOS/Upper"), MACHO)
    write(os.path.join(out, "Upper.app/CONTENTS/INFO.PLIST"), plist_exec("Upper"))
    write(os.path.join(out, "Upper.app/CONTENTS/_CODESIGNATURE/CODERESOURCES"), PLIST)
    write(os.path.join(out, "Upper.app/CONTENTS/RESOURCES/._side"), b"x")
    write(os.path.join(out, "Upper.app/__MACOSX/Contents/Info.plist"), PLIST)
    write(os.path.join(out, "NoApp/readme.txt"), b"nothing here")
    write(os.path.join(out, "NoApp/lib.dylib"), DYLIB)
    # IPA / ZIP archives.
    ios = os.path.join(out, "_ios_src")
    populate_ios(ios, "Payload/Fixture.app")
    zip_dir(ios, os.path.join(out, "Fixture.ipa"),
            symlinks=[("Payload/Fixture.app/Frameworks/Alias.framework", "React.framework")])
    zip_dir(ios, os.path.join(out, "Fixture.zip"))
    macsrc = os.path.join(out, "_zip_src")
    populate_mac(os.path.join(macsrc, "Zipped.app"))
    zip_dir(macsrc, os.path.join(out, "Zipped.zip"))
    zip_dir(os.path.join(out, "NoApp"), os.path.join(out, "NoApp.zip"))
    lower = os.path.join(out, "_lower_src")
    populate_ios(lower, "payload/Lower.app")
    zip_dir(lower, os.path.join(out, "Lower.ipa"))
    shutil.rmtree(ios)
    shutil.rmtree(macsrc)
    shutil.rmtree(lower)
    # Many JavaScript bundles x many native libraries: exercises the bridge candidate budget.
    heavy = os.path.join(out, "Heavy.app")
    write(os.path.join(heavy, "Info.plist"), plist_exec("Main"))
    write(os.path.join(heavy, "Main"), MACHO)
    # Paths stay below Windows' MAX_PATH when the repository is checked out there.
    for i in range(120):
        write(os.path.join(heavy, "Scripts/%s/bundle%03d.js" % ("s" * 60, i)), JS + bytes([i]))
    for i in range(100):
        write(os.path.join(heavy, "Libs/%s/lib%03d.dylib" % ("n" * 60, i)), DYLIB + bytes([i]))


if __name__ == "__main__":
    main(sys.argv[1])
