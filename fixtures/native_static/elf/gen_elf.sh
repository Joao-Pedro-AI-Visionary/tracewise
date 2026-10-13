#!/bin/sh
# Rebuild the ELF fixtures (x86-64 Linux, gcc/binutils of the host).
set -e
cd "$(dirname "$0")"
gcc -O0 -g0 -o pie_default sample.c
gcc -O0 -g0 -no-pie -fno-stack-protector -Wl,-z,norelro -Wl,-z,lazy -o nopie_lazy sample.c
gcc -O0 -g0 -no-pie -fstack-protector-all -Wl,-z,relro -Wl,-z,lazy -o nopie_partial sample.c
gcc -O0 -g0 -no-pie -fcf-protection=none -Wl,-z,norelro -Wl,-z,lazy -o nopie_plain sample.c
gcc -O0 -g0 -static -nostdlib -o tiny_static tiny.c
gcc -O0 -g0 -c -o object.o sample.c
gcc -O0 -g0 -fPIC -c -o object_pic.o sample.c
gcc -O0 -g0 -shared -fPIC -o libsample.so lib.c
gcc -O0 -g0 -Wl,-z,pack-relative-relocs -o relr_pie sample.c
gcc -O0 -g0 -Wl,-z,execstack -no-pie -o execstack_exe sample.c
gcc -O2 -s -o stripped_pie sample.c
gcc -O0 -g0 -Wl,-z,now -no-pie -o full_relro sample.c
gcc -O0 -g -o debug_pie sample.c
