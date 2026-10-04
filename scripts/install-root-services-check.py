#!/usr/bin/env python3
"""Checks install-root-services.sh runs before it publishes a snapshot.

  base PATH       PATH and every ancestor are directories, not symlinks, owned by
                  root (or by the installing user when not root), and not writable
                  by anyone else; an ancestor may be other-writable only if it is
                  root-owned and sticky.
  sources DIR...  no symlink anywhere in the source trees that are copied.
  snapshot DEST   nothing in DEST reaches outside it: every symlink resolves inside
                  DEST, every path a .pth file adds is inside DEST, and every ELF
                  file has no RPATH/RUNPATH outside $ORIGIN and resolves each
                  dependency inside DEST or a system library directory, as the
                  system loader (not the file's own interpreter) resolves it.

Exits non-zero naming every problem. Runs under the system interpreter with -I -S
so nothing from the checkout or the environment is imported.
"""

import os
import stat
import subprocess
import sys
from pathlib import Path

SYSTEM_LIBRARY_DIRS = (
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
)
SYSTEM_LOADERS = ("/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1")
ELF_MAGIC = b"\x7fELF"


def trusted_owner(uid):
    return uid == 0 or uid == os.geteuid()


def check_base(path):
    problems = []
    path = Path(os.path.abspath(path))
    for index, current in enumerate([path, *path.parents]):
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if index == 0:
                continue  # the installer creates BASE itself
            problems.append(f"{current}: missing")
            continue
        if stat.S_ISLNK(info.st_mode):
            problems.append(f"{current}: is a symlink")
            continue
        if not stat.S_ISDIR(info.st_mode):
            problems.append(f"{current}: not a directory")
            continue
        if not trusted_owner(info.st_uid):
            problems.append(f"{current}: owned by uid {info.st_uid}")
        # In a root-owned sticky ancestor nobody can replace an entry they do not own.
        sticky_ancestor = index > 0 and info.st_mode & stat.S_ISVTX and info.st_uid == 0
        if info.st_mode & stat.S_IWGRP and not sticky_ancestor:
            problems.append(f"{current}: group-writable")
        if info.st_mode & stat.S_IWOTH and not sticky_ancestor:
            problems.append(f"{current}: writable by everyone")
    return problems


def check_sources(roots):
    problems = []
    for root in roots:
        for directory, dirs, files in os.walk(root):
            for name in dirs + files:
                entry = Path(directory) / name
                if entry.is_symlink():
                    problems.append(f"{entry}: symlink in a copied source tree")
    return problems


def inside(path, root):
    path = os.path.realpath(path)
    return path == root or path.startswith(root + os.sep)


def system_library(path):
    return os.path.realpath(path).startswith(SYSTEM_LIBRARY_DIRS)


def loader():
    for candidate in SYSTEM_LOADERS:
        if os.path.exists(candidate):
            return candidate
    raise SystemExit("no system dynamic loader found")


def elf_problems(path, root):
    problems = []
    dynamic = subprocess.run(
        ["readelf", "-d", "-W", str(path)], capture_output=True, text=True, check=False
    )
    for line in dynamic.stdout.splitlines():
        if "(RPATH)" in line or "(RUNPATH)" in line:
            value = line.split("[", 1)[1].rsplit("]", 1)[0]
            for entry in value.split(":"):
                if entry and not entry.startswith("$ORIGIN"):
                    problems.append(f"{path}: search path {entry} outside the snapshot")
    if "(NEEDED)" not in dynamic.stdout:
        return problems
    listed = subprocess.run(
        [loader(), "--list", str(path)], capture_output=True, text=True, check=False
    )
    if listed.returncode != 0:
        return [*problems, f"{path}: dependencies do not resolve: {listed.stderr.strip()[:200]}"]
    for line in listed.stdout.splitlines():
        line = line.strip()
        if "=>" in line:
            target = line.split("=>", 1)[1].strip().split(" (", 1)[0].strip()
        elif line.startswith("/"):
            target = line.split(" (", 1)[0].strip()
        else:
            continue  # linux-vdso and similar
        if not target or target == "not found":
            problems.append(f"{path}: unresolved dependency: {line}")
        elif not (inside(target, root) or system_library(target)):
            problems.append(f"{path}: loads {target} from outside the snapshot")
    return problems


def check_snapshot(dest):
    root = os.path.realpath(dest)
    problems = []
    for directory, dirs, files in os.walk(root):
        for name in dirs + files:
            entry = Path(directory) / name
            if entry.is_symlink():
                if not inside(entry, root):
                    problems.append(f"{entry}: links outside the snapshot to {os.readlink(entry)}")
                continue
            if not entry.is_file():
                continue
            if name.endswith(".pth"):
                for line in entry.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith(("#", "import ", "import\t")):
                        continue
                    added = Path(directory) / line
                    if not inside(added, root):
                        problems.append(f"{entry}: adds {line} outside the snapshot")
            with entry.open("rb") as handle:
                if handle.read(4) == ELF_MAGIC:
                    problems.extend(elf_problems(entry, root))
    return problems


def main(argv):
    if len(argv) < 2 or argv[0] not in ("base", "sources", "snapshot"):
        print(__doc__, file=sys.stderr)
        return 2
    command, arguments = argv[0], argv[1:]
    if command == "base" and len(arguments) == 1:
        problems = check_base(arguments[0])
    elif command == "sources":
        problems = check_sources(arguments)
    elif command == "snapshot" and len(arguments) == 1:
        problems = check_snapshot(arguments[0])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
