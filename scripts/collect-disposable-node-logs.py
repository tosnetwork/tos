#!/usr/bin/env python3
"""Retain bounded diagnostic tails, never disposable node keys or databases."""

import json
from pathlib import Path

NETWORKS = (
    "build/quantum-*-ci/network",
    "build/explorer-rpc-*-v16/attempt-*/network",
    "build/node-sync-init-block/network",
    "build/node-sync-init-block/nonlocal-*",
    "test/integration/.network",
    "test/integration/.pq-unsafe-rotation-ci/*",
    "test/integration/.pq-consensus-key-rotation-ci/*",
)
FILE_BYTES = 1024 * 1024
TOTAL_BYTES = 32 * FILE_BYTES
MAX_FILES = 64


def collect(root: Path) -> None:
    root = root.resolve()
    destination = root / "build/disposable-node-logs"
    destination.mkdir(parents=True, exist_ok=True)
    candidates = set()
    for pattern in NETWORKS:
        for network in root.glob(pattern):
            for source in network.glob("node*/**/*"):
                if (
                    source.name in {"log", "stderr", "session-logs", "LOG"}
                    or source.match("*.log*")
                    or source.name.startswith("LOG.old.")
                ):
                    candidates.add(source)
    remaining = TOTAL_BYTES
    index = []
    for source in sorted(candidates, key=lambda p: (p.name != "log", str(p))):
        if remaining == 0 or len(index) == MAX_FILES:
            break
        if source.is_symlink() or not source.is_file():
            continue
        resolved = source.resolve()
        if not resolved.is_relative_to(root) or "keyring" in resolved.parts:
            continue
        relative = source.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as stream:
            size = stream.seek(0, 2)
            stream.seek(max(0, size - min(FILE_BYTES, remaining)))
            data = stream.read(min(FILE_BYTES, remaining))
        target.write_bytes(data)
        remaining -= len(data)
        index.append({"path": str(relative), "original_bytes": size, "retained_bytes": len(data)})
    (destination / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    print(f"Retained {len(index)} node logs, {TOTAL_BYTES - remaining} bytes")


if __name__ == "__main__":
    collect(Path.cwd())
