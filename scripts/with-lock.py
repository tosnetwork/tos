#!/usr/bin/env python3
"""Run a command while holding an exclusive lock on a file.

usage: with-lock.py LOCKFILE COMMAND [ARG...]

A portable stand-in for util-linux flock(1), which macOS does not ship. The
lock is fcntl.flock on LOCKFILE (created if absent) and is held until the
command exits; the command's exit status is returned.
"""

from __future__ import annotations

import fcntl
import subprocess
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    lockfile, command = argv[0], argv[1:]
    with open(lockfile, "a") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return subprocess.run(command).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
