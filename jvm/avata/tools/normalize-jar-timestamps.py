#!/usr/bin/env python3
"""
Post-process a jar (ZIP) file to canonicalize all entry timestamps
to 1980-01-01 00:00:00 (the ZIP epoch — earlier values silently
round to this anyway, so picking it is the lossless canonical
choice).

Why this exists: OpenJDK 8's `jar` tool stamps wallclock-derived
timestamps into the central-directory entries of the output jar
even when the underlying file mtimes have been pinned via
`touch -t`.  The result is two consecutive `make rt.jar` runs on
the same machine producing jars that differ in 4 bytes (the
2-second-granular DOS time field of each local + central header).

This script reads the input jar, walks every ZipInfo, sets
`date_time = (1980, 1, 1, 0, 0, 0)`, and writes a fresh jar with
identical content but canonical timestamps.

Idempotent: running it twice produces the same output.  Stable
across machines + Python versions: stdlib `zipfile` writes a
fixed-format DOS timestamp from the supplied date_time tuple.

Usage:
    normalize-jar-timestamps.py <input.jar> <output.jar>

Or in-place (overwrites the input):
    normalize-jar-timestamps.py <jar>
"""

import sys
import zipfile
from pathlib import Path


CANONICAL_DATE_TIME = (1980, 1, 1, 0, 0, 0)


def normalize(src: Path, dst: Path) -> None:
    # Read everything into memory first so we can safely write back
    # to the same path (the common Makefile-driven invocation pattern
    # is `normalize foo.jar foo.jar`).
    with zipfile.ZipFile(src, "r") as src_zf:
        entries = []
        for info in src_zf.infolist():
            data = src_zf.read(info.filename)
            entries.append((info, data))

    # Sort by filename so the output entry order is stable regardless
    # of the input order.  (The jar pipeline already sorts via
    # `LC_ALL=C find ... | sort` but defensively re-sort here so the
    # tool is self-contained.)
    entries.sort(key=lambda pair: pair[0].filename)

    with zipfile.ZipFile(
        dst, "w", compression=zipfile.ZIP_STORED, allowZip64=False
    ) as dst_zf:
        for info, data in entries:
            # Replace the timestamp + clear any external_attr bits
            # that might leak per-build state (e.g. umask).  Keep
            # the filename and the file content exactly.
            new_info = zipfile.ZipInfo(filename=info.filename)
            new_info.date_time = CANONICAL_DATE_TIME
            new_info.compress_type = zipfile.ZIP_STORED
            # Strip extended attributes (creation/access time, etc.)
            # that some platforms leak into the extra field.
            new_info.extra = b""
            # Preserve unix permissions from the input but zero the
            # "host system" upper bits so the field is stable across
            # build hosts.
            new_info.external_attr = info.external_attr & 0xFFFF
            dst_zf.writestr(new_info, data)


def main(argv: list[str]) -> int:
    if len(argv) == 2:
        src = Path(argv[1])
        dst = src
    elif len(argv) == 3:
        src = Path(argv[1])
        dst = Path(argv[2])
    else:
        sys.stderr.write(
            "usage: normalize-jar-timestamps.py <input.jar> [<output.jar>]\n"
        )
        return 2

    if not src.exists():
        sys.stderr.write(f"input jar not found: {src}\n")
        return 1

    # When src == dst, normalize to a temp path then rename atomically.
    if src.resolve() == dst.resolve():
        tmp = dst.with_suffix(dst.suffix + ".normalize.tmp")
        normalize(src, tmp)
        tmp.replace(dst)
    else:
        normalize(src, dst)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
