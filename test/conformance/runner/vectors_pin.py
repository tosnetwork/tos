#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""The external vectors repository: manifest and pin.

Most fixtures live in a separate repository (see ../VECTORS and ../README.md). This tool belongs to
the tree that consumes them, so the checks do not trust code in the vectors repository.

    vectors_pin.py manifest <vectors dir>
        Write <dir>/MANIFEST.json: every fixture and blob file with size, SHA-256, harness, family,
        fixture count and the reference commits that filled it. Run by whoever updates the vectors.
    vectors_pin.py check <vectors dir> [<pin file>]
        Require the checkout to be at the pinned commit with no local changes, and MANIFEST.json to
        list exactly the files present with matching sizes and digests.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_PIN = HERE.parent / "VECTORS"
MANIFEST = "MANIFEST.json"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


UNLISTED = {MANIFEST, "README.md", ".gitattributes", "LICENSE"}


def vector_files(root: Path) -> list[Path]:
    """Every file of the checkout except git metadata and the top-level documents."""
    files: list[Path] = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if (
            not path.is_file()
            or ".git" in rel.parts
            or (len(rel.parts) == 1 and rel.name in UNLISTED)
        ):
            continue
        files.append(path)
    return sorted(files)


def build_manifest(root: Path) -> dict[str, Any]:
    entries: dict[str, Any] = {}
    for path in vector_files(root):
        rel = path.relative_to(root).as_posix()
        entry: dict[str, Any] = {"size": path.stat().st_size, "sha256": digest(path)}
        if path.name.endswith(".jsonl") and path.parent.name == "fixtures":
            family = c.load_family(path)
            entry.update(
                {
                    "harness": family.harness,
                    "family": family.family,
                    "fixtures": len(family.fixtures),
                    "reference_commits": sorted(
                        {f["metadata"]["reference_commit"] for f in family.fixtures}
                    ),
                }
            )
        entries[rel] = entry
    if not entries:
        raise c.FixtureError(f"{root}: no fixture files")
    return {"manifest_version": 1, "files": entries}


def read_pin(pin: Path) -> dict[str, str]:
    data = cast(dict[str, Any], json.loads(pin.read_text()))
    c.t.keys(data, {"repository", "commit"}, {"repository", "commit"}, str(pin))
    c.t.text(data["commit"], c.t.COMMIT_RE, f"{pin}: commit")
    return {"repository": str(data["repository"]), "commit": str(data["commit"])}


def git(root: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        raise c.FixtureError(f"git {' '.join(args)} in {root}: {done.stderr.strip()}")
    return done.stdout.strip()


def check(root: Path, pin_path: Path) -> list[str]:
    problems: list[str] = []
    pin = read_pin(pin_path)
    head = git(root, "rev-parse", "HEAD")
    if head != pin["commit"]:
        problems.append(f"checkout is at {head}, {pin_path.name} pins {pin['commit']}")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        problems.append("checkout has local changes")
    manifest_path = root / MANIFEST
    if not manifest_path.exists():
        return [*problems, f"{MANIFEST} missing"]
    listed = cast(dict[str, Any], json.loads(manifest_path.read_text())["files"])
    present = {p.relative_to(root).as_posix(): p for p in vector_files(root)}
    for rel in sorted(listed.keys() - present.keys()):
        problems.append(f"listed but missing: {rel}")
    for rel in sorted(present.keys() - listed.keys()):
        problems.append(f"present but not listed: {rel}")
    for rel in sorted(listed.keys() & present.keys()):
        entry = cast(dict[str, Any], listed[rel])
        path = present[rel]
        if entry.get("size") != path.stat().st_size or entry.get("sha256") != digest(path):
            problems.append(f"size or digest differs: {rel}")
    return problems


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 2 and argv[0] == "manifest":
            root = Path(argv[1])
            manifest = build_manifest(root)
            (root / MANIFEST).write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
            files = cast(dict[str, Any], manifest["files"])
            total = sum(cast(dict[str, Any], e).get("fixtures", 0) for e in files.values())
            print(f"manifest: {len(files)} files, {total} fixtures")
            return 0
        if len(argv) in (2, 3) and argv[0] == "check":
            pin = Path(argv[2]) if len(argv) == 3 else DEFAULT_PIN
            problems = check(Path(argv[1]), pin)
            for problem in problems:
                print(f"PIN {problem}")
            print("vectors pin OK" if not problems else f"vectors pin FAILED ({len(problems)})")
            return 1 if problems else 0
    except (c.FixtureError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
