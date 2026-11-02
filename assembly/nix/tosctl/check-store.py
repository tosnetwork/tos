#!/usr/bin/env python3
"""Require that building the tosctl Nix package imports only its fileset, not the repository.

Nix 2.35 evaluates the repository-root flake without copying its tracked tree into the store;
older releases copy all of it (about 800 MB). After a build this checks:

- the running Nix is at least 2.35;
- the package source (a store path) is within SIZE_LIMIT and contains none of the
  repository's excluded paths or sentinels that only a whole-repository import would bring;
- among everything the VM check's derivation needs, the only store path holding this
  repository's sources is that package source.

With --red-control it instead imports the whole repository (builtins.fetchGit of the local
checkout) and requires the same source checks to refuse it.

usage: check-store.py SOURCE_STORE_PATH VM_CHECK_DRV
       check-store.py --red-control
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INPUTS = json.loads((ROOT / "assembly/nix/tosctl/inputs.json").read_text())
SIZE_LIMIT = 160 * 1024 * 1024
MINIMUM_NIX = (2, 35)
# Present in the repository, never in the package source.
SENTINELS = ["validator-engine/validator-engine.cpp", "third-party/rocksdb"] + INPUTS["exclude"]
REPOSITORY_MARKER = "tosctl/src/Cargo.toml"


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def nix(*args):
    return subprocess.run(["nix", *args], check=True, capture_output=True, text=True).stdout


def check_nix_version():
    text = nix("--version")
    match = re.search(r"(\d+)\.(\d+)", text)
    require(match, f"cannot read the Nix version from {text!r}")
    version = (int(match.group(1)), int(match.group(2)))
    require(version >= MINIMUM_NIX, f"Nix {text.strip()} is older than 2.35")
    return text.strip()


def size(path):
    return sum(p.lstat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def check_source(source):
    require(source.is_dir(), f"{source} is not a directory")
    total = size(source)
    require(total <= SIZE_LIMIT, f"package source is {total} bytes, over {SIZE_LIMIT}")
    present = [s for s in SENTINELS if (source / s).exists()]
    require(not present, f"package source contains excluded or repository paths: {present}")
    suffixes = [
        p.relative_to(source).as_posix()
        for suffix in INPUTS["exclude_suffixes"]
        for p in source.rglob("*" + suffix)
    ]
    require(not suffixes, f"package source contains excluded files: {suffixes[:5]}")
    return total


def check_closure(source, drv):
    requisites = nix("path-info", "--recursive", drv).split()
    repository = [p for p in requisites if (Path(p) / REPOSITORY_MARKER).exists()]
    require(
        repository == [str(source)],
        f"repository sources among the VM check's inputs: {repository}, expected [{source}]",
    )
    whole = [p for p in requisites if (Path(p) / SENTINELS[0]).exists()]
    require(not whole, f"a whole-repository import is an input: {whole}")
    return len(requisites)


def red_control():
    imported = nix(
        "eval", "--impure", "--raw", "--expr", f'(builtins.fetchGit "{ROOT}").outPath'
    ).strip()
    try:
        check_source(Path(imported))
    except Failure as error:
        print(f"TOSCTL_NIX_STORE_RED_CONTROL_OK: a whole-repository import is refused ({error})")
        return 0
    print("TOSCTL_NIX_STORE_FAILED: a whole-repository import passed the source checks")
    return 1


def main():
    if sys.argv[1:] == ["--red-control"]:
        return red_control()
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    source, drv = Path(sys.argv[1]), sys.argv[2]
    try:
        version = check_nix_version()
        total = check_source(source)
        count = check_closure(source, drv)
    except (Failure, subprocess.CalledProcessError) as error:
        print(f"TOSCTL_NIX_STORE_FAILED: {error}", file=sys.stderr)
        return 1
    print(
        f"TOSCTL_NIX_STORE_OK: {version}; package source {total} bytes; {count} build inputs; "
        "no whole-repository import"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
