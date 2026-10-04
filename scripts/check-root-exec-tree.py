#!/usr/bin/env python3
"""Refuse to run root code that someone else could have changed.

The local development services run as root from a source checkout: Python
scripts, the tostester sources, the virtual environment and its interpreter,
and native libraries and binaries from the build tree. Whoever can change any
of those runs code as root. The user who ran the installer with sudo already
could; nobody else may.

Every given path, every file and directory beneath a --tree, every symlink
target met on the way, and every ancestor directory of all of these must:

- belong to root or the trusted user;
- not be writable by others, except an ancestor directory with the sticky bit,
  where nobody can replace an entry they do not own;
- be group-writable only if no account outside root and the trusted user is in
  that group, as a member or by primary group.

An --ignore path is skipped exactly (not its children): only for a file that
is never executed or imported, such as a tool's lock file it recreates with
open permissions.

Uses only the standard library so a root-owned copy runs with the system
interpreter, independent of the tree it checks.
"""

import argparse
import grp
import os
import pwd
import stat
import sys
from pathlib import Path

REPORT_LIMIT = 20


class Checker:
    def __init__(self, trusted_uid, ignored=()):
        self.trusted = {0, trusted_uid}
        self.ignored = {os.path.abspath(path) for path in ignored}
        self.seen = set()
        self.problems = []
        self.private_groups = {}

    def group_is_private(self, gid):
        if gid not in self.private_groups:
            try:
                members = set(grp.getgrgid(gid).gr_mem)
            except KeyError:
                members = set()
            uids = set()
            for name in members:
                try:
                    uids.add(pwd.getpwnam(name).pw_uid)
                except KeyError:
                    # An unresolvable member is an unknown principal.
                    uids.add(-1)
            uids.update(p.pw_uid for p in pwd.getpwall() if p.pw_gid == gid)
            self.private_groups[gid] = uids <= self.trusted
        return self.private_groups[gid]

    def judge(self, path, info, ancestor):
        if info.st_uid not in self.trusted:
            self.problems.append(f"{path}: owned by uid {info.st_uid}")
        mode = info.st_mode
        if stat.S_ISLNK(mode):
            return  # a link's own mode is meaningless; its target is checked
        if mode & stat.S_IWOTH and not (ancestor and stat.S_ISDIR(mode) and mode & stat.S_ISVTX):
            self.problems.append(f"{path}: writable by everyone")
        if mode & stat.S_IWGRP and not self.group_is_private(info.st_gid):
            self.problems.append(
                f"{path}: writable by group {info.st_gid}, which has other members"
            )

    def ancestors(self, path):
        for parent in Path(os.path.abspath(path)).parents:
            self.visit(parent, ancestor=True)

    def visit(self, path, ancestor=False):
        path = Path(os.path.abspath(path))
        key = (str(path), ancestor)
        if key in self.seen or (not ancestor and str(path) in self.ignored):
            return None
        self.seen.add(key)
        try:
            info = os.lstat(path)
        except OSError as error:
            self.problems.append(f"{path}: {error.strerror}")
            return None
        self.judge(path, info, ancestor)
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.path.realpath(path))
            self.ancestors(target)
            self.visit(target)
            if target.is_dir():
                self.tree(target)
        return info

    def tree(self, root):
        root = Path(os.path.abspath(root))
        if (str(root), "tree") in self.seen:
            return
        self.seen.add((str(root), "tree"))
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=self.walk_error):
            for name in dirs + files:
                # Symlinked directories appear in `dirs` but os.walk does not descend;
                # visit() follows them explicitly.
                self.visit(Path(directory) / name)

    def walk_error(self, error):
        self.problems.append(f"{error.filename}: {error.strerror}")

    def check_path(self, path, walk):
        self.ancestors(path)
        info = self.visit(path)
        if walk and info is not None and stat.S_ISDIR(info.st_mode):
            self.tree(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--trusted-uid", type=int, required=True)
    parser.add_argument("--tree", type=Path, action="append", default=[])
    parser.add_argument("--path", type=Path, action="append", default=[])
    parser.add_argument("--ignore", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    if args.trusted_uid < 0:
        parser.error("--trusted-uid must not be negative")
    if not args.tree and not args.path:
        parser.error("name at least one --tree or --path")
    checker = Checker(args.trusted_uid, args.ignore)
    for path in args.tree:
        checker.check_path(path, walk=True)
    for path in args.path:
        checker.check_path(path, walk=False)
    if checker.problems:
        print(
            f"refusing to run as root: {len(checker.problems)} path(s) another user can change",
            file=sys.stderr,
        )
        for problem in checker.problems[:REPORT_LIMIT]:
            print(f"  {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
