#!/bin/sh
# Test double for the Apktool launcher: decodes into a workspace that exceeds the projection limits.
if [ "$1" = "--version" ]; then printf "\n  2.9.9-fake  \nsecond line\n"; exit 0; fi
out=""
while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done
mkdir -p "$out/res/values" "$out/res/values-de" "$out/res/values-pt-rBR" "$out/res/values-night" "$out/res/layout" "$out/res/values-empty"
printf "version: 2.9.9\nversionInfo:\n  versionCode: 45.1\n  versionName: x y\n  versionName: ignored\nsdkInfo:\n  minSdkVersion: 21\n  targetSdkVersion: \"34\"\n" > "$out/apktool.yml"
printf "<?xml version=\"1.0\"?><manifest xmlns:android=\"x\" package=\"org.example.fake\" a=\"b\"></manifest>" > "$out/AndroidManifest.xml"
{
  echo "<resources>"
  i=0
  while [ $i -lt 2500 ]; do echo "    <string name=\"s$i\">value &amp; $i </string>"; i=$((i+1)); done
  echo "    <string name=\"html\">a<b>b</b></string>"
  echo "</resources>"
} > "$out/res/values/strings.xml"
printf "<resources><string name=\"hallo\" translatable=\"false\">Welt</string></resources>" > "$out/res/values-de/strings.xml"
printf "<resources><string name=\"ola\">Mundo</string></resources>" > "$out/res/values-pt-rBR/strings.xml"
printf "<resources><string name=\"dark\">  night  </string></resources>" > "$out/res/values-night/strings.xml"
i=0
while [ $i -lt 40 ]; do printf "<x/>" > "$out/res/layout/l$i.xml"; i=$((i+1)); done
echo "I: Using fake Apktool"
