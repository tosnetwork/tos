#!/usr/bin/env python3
"""Check pinned tool bytes before execution or extraction."""

import argparse
import hashlib
import json
from pathlib import Path

PINS = Path(__file__).with_name("build-tool-pins.json")


def verify(name: str, path: Path, manifest: Path = PINS) -> None:
    pin = json.loads(manifest.read_text())[name]
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != pin["sha256"]:
        raise ValueError(f"tool integrity check failed: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    verify(args.name, args.path)
    print(f"Verified {args.name}")


if __name__ == "__main__":
    main()
