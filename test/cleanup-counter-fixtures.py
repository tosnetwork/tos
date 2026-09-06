#!/usr/bin/env python3
"""Explicit legacy fixture cleanup; never targets other build artifacts.

Requires an idle test host. Preserves top-level diagnostic files in a compressed
archive before removing exact, validated fixture directories. Dry-run by default.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--keep-newest", type=int, default=10)
    args = parser.parse_args()
    if args.keep_newest < 0:
        parser.error("--keep-newest must be nonnegative")
    root = args.build.resolve(strict=True)
    if not (root / "CMakeCache.txt").is_file():
        raise SystemExit("Refusing a directory without CMakeCache.txt")
    targets = sorted(p for p in root.iterdir()
                     if re.fullmatch(r"counter-integration-[0-9a-f]{12}", p.name)
                     and p.is_dir() and not p.is_symlink())
    targets.sort(key=lambda p: p.stat().st_mtime_ns)
    retained = min(len(targets), args.keep_newest)
    if retained:
        targets = targets[:-retained]
    # Inspect command lines and open descriptors, not merely directory timestamps.
    # Ignore this script and its parent shell; callers must prevent new test runs
    # during this explicit maintenance operation.
    def check_idle():
        listing = subprocess.check_output(["ps", "-eo", "pid=,comm=,args="], text=True)
        for line in listing.splitlines():
            fields = line.strip().split(None, 2)
            if len(fields) < 3 or int(fields[0]) in (os.getpid(), os.getppid()):
                continue
            if fields[1] in ("ctest", "test-tos-collat", "create-state") or (
                fields[1] == "cmake" and "test-counter-disk-integration.cmake" in fields[2]
            ):
                raise SystemExit("Refusing cleanup while test process is live: " + line)
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                links = [proc / "cwd", *(proc / "fd").iterdir()]
                for link in links:
                    try:
                        path = os.readlink(link)
                    except FileNotFoundError:
                        continue
                    if path.startswith(str(root / "counter-integration-")):
                        raise SystemExit(f"Live fixture reference: {link} -> {path}")
            except (FileNotFoundError, ProcessLookupError):
                pass
            except PermissionError:
                # Other users cannot run these private fixtures unnoticed: also
                # require the process-list check and an operator-controlled idle host.
                pass
    check_idle()
    print(json.dumps({"build": str(root), "directories": len(targets), "retained": retained, "delete": args.delete}), flush=True)
    if not args.delete or not targets:
        return
    archive = root / f"counter-fixture-diagnostics-{time.time_ns()}.tar.gz"
    with tarfile.open(archive, "x:gz") as output:
        for directory in targets:
            for entry in directory.iterdir():
                if entry.is_file() and not entry.is_symlink():
                    output.add(entry, arcname=f"{directory.name}/{entry.name}", recursive=False)
    # Close and verify the archive before any destructive operation.
    with tarfile.open(archive, "r:gz") as saved:
        files = len(saved.getmembers())
    check_idle()
    for directory in targets:
        if directory.parent != root or directory.is_symlink():
            raise SystemExit("Fixture changed during cleanup: " + str(directory))
        shutil.rmtree(directory)
    print(json.dumps({"removed": len(targets), "diagnostic_files": files, "archive": str(archive)}), flush=True)


if __name__ == "__main__":
    main()
