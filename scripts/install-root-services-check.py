#!/usr/bin/env python3
"""Checks install-root-services.sh runs before it publishes a snapshot.

  base PATH       PATH and every ancestor are directories, not symlinks, owned by
                  root (or by the installing user when not root), and not writable
                  by anyone else; an ancestor may be other-writable only if it is
                  root-owned and sticky.
  sources DIR...  no symlink anywhere in the source trees that are copied.
  snapshot DEST   nothing in DEST reaches outside it. Resolution is followed one
                  component and one link at a time, as the kernel does, and every
                  step must stay inside DEST or on its already checked ancestors:
                  a link that ends inside but passes through a link or directory
                  elsewhere is refused. This holds for every symlink, every path a
                  .pth file adds, and every RPATH/RUNPATH entry with $ORIGIN
                  expanded (whether or not that directory exists yet; empty
                  entries and other loader tokens are refused). A .pth line that
                  executes code is refused unless it is one of the reviewed lines
                  below and the module it imports is in the same directory. Every
                  ELF dependency, as the system loader (not the file's own
                  interpreter) resolves it, is inside DEST or a system library
                  directory.

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
MAX_LINKS = 40
# Executable .pth lines a supported environment contains, each with the module it
# imports from its own site-packages: uv's virtualenv hook and setuptools' distutils
# shim. Anything else that executes is refused.
REVIEWED_PTH_LINES = {
    "import _virtualenv": ("_virtualenv.py",),
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local')"
    " == 'local'; enabled and __import__('_distutils_hack').add_shim();": (
        "_distutils_hack/__init__.py",
    ),
}


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


def within(path, root):
    return path == root or path.startswith(root + os.sep)


def on_the_way(path, root):
    """`path` is DEST, inside it, or one of its ancestors (checked by `base`)."""
    return within(path, root) or within(root, path) or path == "/"


def resolution_problem(path, root, allow_missing=False):
    """Follow `path` like the kernel; name the first step that leaves DEST.

    With `allow_missing`, a missing tail is judged by where it would be.
    """
    parts = [part for part in str(path).split("/") if part]
    current, links = "/", 0
    while parts:
        part = parts.pop(0)
        if part == ".":
            continue
        if part == "..":
            current = os.path.dirname(current) or "/"
            continue
        step = os.path.join(current, part)
        if not on_the_way(step, root):
            return f"passes through {step}"
        try:
            info = os.lstat(step)
        except FileNotFoundError:
            if not allow_missing:
                return f"{step} does not exist"
            tail = os.path.normpath(os.path.join(step, *parts))
            return None if within(tail, root) else f"would be {tail}"
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > MAX_LINKS:
                return "too many links"
            target = os.readlink(step)
            if target.startswith("/"):
                current = "/"
            parts = [part for part in target.split("/") if part] + parts
            continue
        current = step
    return None if within(current, root) else f"ends at {current}"


def inside(path, root):
    return resolution_problem(path, root) is None


def system_library(path):
    return os.path.realpath(path).startswith(SYSTEM_LIBRARY_DIRS)


def loader():
    for candidate in SYSTEM_LOADERS:
        if os.path.exists(candidate):
            return candidate
    raise SystemExit("no system dynamic loader found")


def search_path_problems(path, value, root):
    origin = os.path.dirname(os.path.realpath(path))
    problems = []
    for entry in value.split(":"):
        if not entry:
            problems.append(f"{path}: empty search path entry (the working directory)")
            continue
        expanded = entry.replace("${ORIGIN}", origin)
        if expanded.startswith("$ORIGIN"):
            expanded = origin + expanded[len("$ORIGIN") :]
        if "$" in expanded:
            problems.append(f"{path}: unsupported loader token in search path {entry}")
            continue
        if not expanded.startswith("/"):
            problems.append(f"{path}: relative search path {entry}")
            continue
        problem = resolution_problem(expanded, root, allow_missing=True)
        if problem:
            problems.append(f"{path}: search path {entry} outside the snapshot ({problem})")
    return problems


def elf_problems(path, root):
    problems = []
    dynamic = subprocess.run(
        ["readelf", "-d", "-W", str(path)], capture_output=True, text=True, check=False
    )
    if dynamic.returncode != 0:
        return [f"{path}: readelf failed: {dynamic.stderr.strip()[:200]}"]
    for line in dynamic.stdout.splitlines():
        if "(RPATH)" in line or "(RUNPATH)" in line:
            value = line.split("[", 1)[1].rsplit("]", 1)[0]
            problems.extend(search_path_problems(path, value, root))
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


def pth_problems(path, root):
    problems = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("import ", "import\t")):
            modules = REVIEWED_PTH_LINES.get(line)
            if modules is None:
                problems.append(f"{path}: executes unreviewed code: {line[:120]}")
                continue
            for module in modules:
                if resolution_problem(path.parent / module, root):
                    problems.append(f"{path}: imports {module}, which is not in the snapshot")
            continue
        problem = resolution_problem(path.parent / line, root, allow_missing=True)
        if problem:
            problems.append(f"{path}: adds {line} outside the snapshot ({problem})")
    return problems


def check_snapshot(dest):
    root = os.path.realpath(dest)
    problems = []
    for directory, dirs, files in os.walk(root):
        for name in dirs + files:
            entry = Path(directory) / name
            if entry.is_symlink():
                problem = resolution_problem(entry, root)
                if problem:
                    target = os.readlink(entry)
                    problems.append(f"{entry}: links outside the snapshot to {target} ({problem})")
                continue
            if not entry.is_file():
                continue
            if name.endswith(".pth"):
                problems.extend(pth_problems(entry, root))
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
