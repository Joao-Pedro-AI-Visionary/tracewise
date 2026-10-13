#!/bin/sh
# Test double for the Apktool launcher: oversized manifest and strings.xml.
if [ "$1" = "--version" ]; then echo "2.9.9-huge"; exit 0; fi
out=""
while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done
mkdir -p "$out/res/values"
printf "versionInfo:\n  versionCode: 1\n" > "$out/apktool.yml"
{ printf "<manifest package=\"big.manifest\">"; head -c 700000 /dev/zero | tr "\000" "a"; printf "</manifest>"; } > "$out/AndroidManifest.xml"
{ printf "<resources>"; head -c 9000000 /dev/zero | tr "\000" "x"; printf "</resources>"; } > "$out/res/values/strings.xml"
