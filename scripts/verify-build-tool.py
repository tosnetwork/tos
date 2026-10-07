#!/usr/bin/env python3
"""Check pinned tool bytes before execution or extraction.

`verify-build-tool.py NAME PATH` checks PATH against the pin's SHA-256 (and its
upstream SHA-1 when the pin records one). `verify-build-tool.py --url NAME`
prints the pinned download URL, so scripts fetch exactly the bytes the pin
describes instead of repeating the URL.
"""

import argparse
import hashlib
import json
from pathlib import Path

PINS = Path(__file__).with_name("build-tool-pins.json")


def load_pin(name: str, manifest: Path = PINS) -> dict:
    pins = json.loads(manifest.read_text())
    if name not in pins:
        raise ValueError(f"no pin for build tool: {name}")
    return pins[name]


def verify(name: str, path: Path, manifest: Path = PINS) -> None:
    pin = load_pin(name, manifest)
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            sha256.update(chunk)
            sha1.update(chunk)
    if sha256.hexdigest() != pin["sha256"]:
        raise ValueError(f"tool integrity check failed: {name}")
    upstream_sha1 = pin.get("upstream_sha1")
    if upstream_sha1 is not None and sha1.hexdigest() != upstream_sha1:
        raise ValueError(f"tool integrity check failed: {name} (upstream SHA-1)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="store_true", help="print the pinned URL of NAME")
    parser.add_argument("name")
    parser.add_argument("path", type=Path, nargs="?")
    args = parser.parse_args()
    if args.url:
        if args.path is not None:
            parser.error("--url takes only a tool name")
        print(load_pin(args.name)["url"])
        return
    if args.path is None:
        parser.error("a path to verify is required")
    verify(args.name, args.path)
    print(f"Verified {args.name}")


if __name__ == "__main__":
    main()
