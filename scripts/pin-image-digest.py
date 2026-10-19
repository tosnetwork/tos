#!/usr/bin/env python3
"""Pin the node image in deployment manifests to a released digest.

The release image workflow writes image-release.json: the image name, the
digest of the multi-architecture index it pushed and attested, the tag, the
source commit and the run that built it. This script rewrites every manifest's
node image to that digest and records where it came from in the comment above
the image line, so a manifest change is reviewable against its provenance.

  pin-image-digest.py --record image-release.json docker/tos-*.yaml
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

IMAGE = "ghcr.io/tosnetwork/tos"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v[0-9A-Za-z._-]+$")
RUN_URL_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/actions/runs/[0-9]+$")
IMAGE_LINE_RE = re.compile(r"^(?P<indent>[ ]*)image: " + re.escape(IMAGE) + r"[@:]\S*$")
PROVENANCE_PREFIX = "# image-provenance:"


class PinError(Exception):
    pass


def load_record(path: Path) -> dict[str, str]:
    record = json.loads(path.read_text())
    checks = {
        "image": lambda value: value == IMAGE,
        "digest": DIGEST_RE.fullmatch,
        "tag": TAG_RE.fullmatch,
        "source_commit": COMMIT_RE.fullmatch,
        "run_url": RUN_URL_RE.fullmatch,
    }
    for field, valid in checks.items():
        value = record.get(field)
        if not isinstance(value, str) or not valid(value):
            raise PinError(f"{path}: field {field!r} is missing or malformed: {value!r}")
    if record["digest"] == "sha256:" + "0" * 64:
        raise PinError(f"{path}: the all-zero digest is the unreleased placeholder, not a release")
    return record


def pin(text: str, record: dict[str, str], name: str) -> str:
    """Rewrite the image line; the caller has already removed its old provenance comment."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    pinned = 0
    for line in lines:
        match = IMAGE_LINE_RE.match(line.rstrip("\n"))
        if not match:
            out.append(line)
            continue
        indent = match["indent"]
        out.append(
            f"{indent}{PROVENANCE_PREFIX} release {record['tag']} built from {record['source_commit']}\n"
            f"{indent}# by {record['run_url']}\n"
            f"{indent}image: {IMAGE}@{record['digest']}\n"
        )
        pinned += 1
    if pinned != 1:
        raise PinError(f"{name}: expected exactly one {IMAGE} image line, found {pinned}")
    return "".join(out)


def strip_provenance(text: str) -> str:
    """Remove the provenance comment block directly above the image line."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if IMAGE_LINE_RE.match(line.rstrip("\n")):
            start = index
            while start > 0 and lines[start - 1].strip().startswith("#"):
                start -= 1
            block = lines[start:index]
            if block and block[0].strip().startswith(PROVENANCE_PREFIX):
                del lines[start:index]
            break
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("manifests", type=Path, nargs="+")
    args = parser.parse_args(argv)
    try:
        record = load_record(args.record)
        updated = {}
        for manifest in args.manifests:
            updated[manifest] = pin(strip_provenance(manifest.read_text()), record, str(manifest))
    except (PinError, json.JSONDecodeError) as error:
        print(f"PIN_IMAGE_DIGEST_REFUSED: {error}", file=sys.stderr)
        return 1
    for manifest, text in updated.items():
        manifest.write_text(text)
        print(f"{manifest}: {IMAGE}@{record['digest']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
