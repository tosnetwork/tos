#!/usr/bin/env python3
"""Freeze the X02 four-node runtime binding from already prepared, immutable inputs.

Indexes, by size and SHA-256, every file the X02 binding contract
(scripts/x02_four_node_binding.py) requires: the native build's binaries, the pinned
interpreter and its standard library, the dependency site-packages, the Stage A source
roots and the listed driver scripts, plus the pinned host executables. It writes the
binding JSON once (refusing to overwrite) and then checks it with verify_binding itself.

This tool prepares nothing: the U24 rootfs, the native build, the runtime and the clean
source checkout must already exist at their final paths. It must be run from that clean
source checkout (the binding records its own Git common directory).

usage: x02_freeze_binding.py --scenario D --native-source-sha SHA --build-root DIR
       --interpreter PATH --stdlib-root DIR --dependency-root DIR --stage-output DIR
       --output FILE
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / "scripts"))

import x02_four_node_binding as closure  # noqa: E402

DRIVER_SCRIPTS = (
    "scripts/validator-election-stage-a.py",
    "scripts/x02_stage_a_child.py",
    "scripts/x02_four_node_binding.py",
    "scripts/x01_window_evidence.py",
    "scripts/x02_config34_proof.py",
)


def receipt(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    info = path.lstat()
    return {"sha256": digest.hexdigest(), "bytes": info.st_size}


def index_root(root: Path, files: dict) -> None:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise SystemExit(f"refusing to freeze a symbolic link: {path}")
        if path.is_file():
            files[str(path)] = receipt(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=sorted(closure.SCENARIO_WINDOWS), required=True)
    parser.add_argument("--native-source-sha", required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--interpreter", type=Path, required=True)
    parser.add_argument("--stdlib-root", type=Path, required=True)
    parser.add_argument("--dependency-root", type=Path, action="append", required=True)
    parser.add_argument("--stage-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    status = subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain"], text=True)
    if any(not line.startswith("??") for line in status.splitlines()):
        raise SystemExit("source checkout has tracked modifications; freeze only a clean commit")
    version = subprocess.check_output(
        [str(args.interpreter), "-I", "-c", "import sys; print(list(sys.version_info[:3]))"],
        text=True,
    )
    binding = {
        "schema": "tos.x02.four-node-binding.v2",
        "scenario": args.scenario,
        "partial_engine": "nft-ordinal-v1" if args.scenario == "P" else None,
        "native_source_sha": args.native_source_sha,
        "python_version": json.loads(version),
        "interpreter": str(args.interpreter),
        "interpreter_stdlib_root": str(args.stdlib_root),
        "runtime_roots": [str(args.stdlib_root)],
        "dependency_roots": [str(root) for root in args.dependency_root],
        "build_root": str(args.build_root),
        "source_root": str(SOURCE),
        "rootfs_root": "/datax/n6-unit-agents/Z02/u24-rootfs",
        "git_common_root": closure.repository_git_common_root(),
        "bwrap_path": "/usr/bin/bwrap",
        "stage_output": str(args.stage_output),
    }
    binding["stage_argv"] = closure.expected_stage_argv(binding)
    binding["host_files"] = {
        path: {"sha256": receipt(Path(path))["sha256"]}
        for path in sorted(closure.expected_host_files(binding))
    }
    files: dict[str, dict] = {}
    for root in (
        SOURCE / "test/tostester/src",
        SOURCE / "crypto/fift/lib",
        SOURCE / "crypto/smartcont",
        args.build_root / "crypto/smartcont",
        *args.dependency_root,
        args.stdlib_root,
    ):
        index_root(root, files)
    for relative in closure.BINARY_PATHS:
        path = args.build_root / relative
        files[str(path)] = receipt(path)
    for relative in DRIVER_SCRIPTS:
        files[str(SOURCE / relative)] = receipt(SOURCE / relative)
    files[str(args.interpreter)] = receipt(args.interpreter)
    binding["files"] = dict(sorted(files.items()))
    binding["native_binary_sha256"] = files[
        str(args.build_root / "validator-engine/validator-engine")
    ]["sha256"]

    raw = (json.dumps(binding, indent=1, sort_keys=True) + "\n").encode()
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    closure.verify_binding(json.loads(raw), host=True)
    print(
        json.dumps(
            {
                "binding": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "files": len(files),
                "native_binary_sha256": binding["native_binary_sha256"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
