#!/bin/sh
# Test double for the Apktool launcher: reports a version, then fails every decode.
if [ "$1" = "--version" ]; then echo "2.0.0-fake"; exit 0; fi
echo "boom on stdout"
echo "W: failure details on stderr" >&2
exit 3
