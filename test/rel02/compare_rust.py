#!/usr/bin/env python3
"""Require complete Rust roots from both architectures and the pinned chain oracle."""

import argparse
import json
from pathlib import Path

import run_rust as gate


def check_artifact(path, architecture, manifest, manifest_hash, topology_hash):
    receipt = json.loads(gate.bounded_read(path, gate.MAX_METADATA))
    required = {
        "schema": 2,
        "architecture": architecture,
        "transactions": 576,
        "carried_edges": 474,
        "anchors": 102,
        "manifest_sha256": manifest_hash,
        "topology_sha256": topology_hash,
        "limits": {
            "address_space": gate.ADDRESS_SPACE,
            "file_bytes": gate.MAX_OUTPUT,
            "wall_seconds": gate.TIMEOUT,
        },
    }
    for field, expected in required.items():
        if receipt.get(field) != expected:
            raise ValueError(f"{architecture}: receipt {field} differs")
    for field in (
        "dump_sha256",
        "native_output_sha256",
        "rust_output_sha256",
        "native_binary_sha256",
        "rust_binary_sha256",
    ):
        value = receipt.get(field, "")
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError(f"{architecture}: invalid {field}")
    roots = gate.bounded_read(path.with_suffix(".roots.tsv"), gate.MAX_DIAGNOSTICS)
    if gate.digest(roots) != receipt["rust_output_sha256"]:
        raise ValueError(f"{architecture}: Rust output digest differs")
    if len(gate.check_rust_roots(roots, manifest["expected"])) != 576:
        raise ValueError(f"{architecture}: incomplete Rust roots")
    return receipt, roots


def compare_results(left, right):
    for field in ("dump_sha256", "native_output_sha256", "rust_output_sha256"):
        if left[0][field] != right[0][field]:
            raise ValueError(f"cross-architecture {field} differs")
    if left[1] != right[1]:
        raise ValueError("cross-architecture Rust roots differ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("x86_64", type=Path)
    parser.add_argument("arm64", type=Path)
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).parent / "corpus/manifest.json"
    )
    parser.add_argument(
        "--topology", type=Path, default=Path(__file__).parent / "replay-topology.json"
    )
    args = parser.parse_args()
    manifest_bytes = gate.bounded_read(args.manifest, gate.MAX_METADATA)
    manifest = json.loads(manifest_bytes)
    topology_hash = gate.digest(gate.bounded_read(args.topology, gate.MAX_METADATA))
    artifacts = [
        check_artifact(path, arch, manifest, gate.digest(manifest_bytes), topology_hash)
        for path, arch in ((args.x86_64, "x86_64"), (args.arm64, "aarch64"))
    ]
    compare_results(*artifacts)
    print("PASS: both architectures; 576 transaction/Account/ShardAccount roots agree")


if __name__ == "__main__":
    main()
