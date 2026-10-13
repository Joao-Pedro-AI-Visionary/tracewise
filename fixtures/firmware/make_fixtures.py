#!/usr/bin/env python3
"""Regenerate the deterministic firmware samples used by the firmware parity tests.

  sample.bin  junk header | gzip(tar{one.txt, rand.bin}) | padding | xz | junk tail
  links.bin   plain tar with a directory, a regular file and a symlink
  random.bin  4096 pseudo-random bytes with no known signature

Everything is byte-for-byte reproducible (fixed gzip/tar metadata, seeded PRNG),
so the Binwalk and Unblob reports do not depend on when the fixtures were made.
"""
import gzip
import io
import lzma
import os
import random
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))


def tar_bytes(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for info, data in members:
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def file_info(name, size):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    return info


def main():
    prng = random.Random(1234)
    rand_payload = prng.randbytes(3000)
    one = b"hello firmware file one\n"
    inner = tar_bytes([(file_info("./one.txt", len(one)), one), (file_info("./rand.bin", len(rand_payload)), rand_payload)])
    gz = io.BytesIO()
    with gzip.GzipFile(filename="a.tar", mode="wb", fileobj=gz, mtime=0) as handle:
        handle.write(inner)
    sample = b"\x00" * 64 + b"HDRJUNK" + b"\xff" * 57 + gz.getvalue() + b"\x00" * 100 + lzma.compress(b"lzma payload " * 50) + b"\x11" * 200
    open(os.path.join(HERE, "sample.bin"), "wb").write(sample)

    directory = tarfile.TarInfo("./dir")
    directory.type = tarfile.DIRTYPE
    directory.mode = 0o755
    link = tarfile.TarInfo("./dir/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "real.txt"
    data = b"real file\n"
    links = tar_bytes([(directory, None), (file_info("./dir/real.txt", len(data)), data), (link, None)])
    open(os.path.join(HERE, "links.bin"), "wb").write(links)

    open(os.path.join(HERE, "random.bin"), "wb").write(random.Random(99).randbytes(4096))


if __name__ == "__main__":
    main()
