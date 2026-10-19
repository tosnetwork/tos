#!/usr/bin/env python3
"""Plan or apply the source-level Token naming migration in a clean checkout.

This is a source migration, never an on-chain balance or database migration.
Binary contracts must be rebuilt separately, not patched in place.
"""

from __future__ import annotations

import argparse
import binascii
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

LEGACY = re.compile(r"jetton", re.IGNORECASE)
URL = re.compile(r"https?://[^\s<>\"'`]+")
LEGAL_LINE = re.compile(r"(?im)^.*(?:SPDX-License-Identifier:|Copyright\s|copyright\s).*$")
SELF_FILES = {
    "scripts/migrate-token-naming.py",
    "scripts/test-token-naming.py",
    "scripts/check-token-naming.py",
    "scripts/token-rename-workbench.py",
    "doc/token-naming-migration.md",
    "doc/token-naming-manifest.json",
    "scripts/x02_four_node_inputs.json",
    "Changelog.md",
    "recent_changelog.md",
}
OLD_GETTER_ID = binascii.crc_hqx(b"get_jetton_data", 0) | 0x10000
NEW_GETTER_ID = binascii.crc_hqx(b"get_token_data", 0) | 0x10000


def immutable(path: str) -> bool:
    parts = Path(path).parts
    name = Path(path).name
    return (
        path in SELF_FILES
        or path.startswith("third-party/")
        or "evidence" in parts
        or "raw" in parts
        or name.startswith(("LICENSE", "COPYING", "NOTICE"))
        or path.endswith((".log", ".patch", ".diff"))
    )


def spelling(match: re.Match[str]) -> str:
    old = match.group()
    if old.isupper():
        return "TOKEN"
    if old[0].isupper():
        return "Token"
    return "token"


def rename(path: str) -> str:
    # A license moves with its source directory, but its bytes never change.
    parts = Path(path).parts
    retained = (
        path in SELF_FILES
        or path.startswith("third-party/")
        or "evidence" in parts
        or "raw" in parts
        or path.endswith((".log", ".patch", ".diff"))
    )
    return path if retained else LEGACY.sub(spelling, path.replace("JettonMinter", "TokenMaster"))


def replace_terms(text: str) -> str:
    # The client already exports TokenData as an FT/NFT union. Do not collide
    # with that type when renaming the contract-specific five-field result.
    text = text.replace("JettonMinter", "TokenMaster")
    text = text.replace("JETTON_MINTER_CODE_HEX", "TOKEN_MASTER_CODE_HEX")
    text = text.replace("JettonData", "FungibleTokenData")
    text = text.replace("TokenKind::Jetton", "TokenKind::Fungible")
    text = text.replace("Jetton = 0, Nft = 1", "Fungible = 0, Nft = 1")
    text = LEGACY.sub(spelling, text)
    return re.sub(r"\bTEP[- ]74\b", "TOS Token V1", text)


def transform(path: str, text: str, retained_paths: tuple[str, ...] = ()) -> str:
    if immutable(path):
        return text
    saved: list[str] = []

    def protect(value: str) -> str:
        if "\x00" in value:
            raise ValueError("NUL in text input")
        index = len(saved)
        saved.append(value)
        return f"\x00{index}\x00"

    def protect_url(match: re.Match[str]) -> str:
        value = match.group()
        parsed = urlsplit(value)
        # Only live links into this repository move with the source. External
        # citations and links to immutable commits must remain truthful.
        live = parsed.netloc == "github.com" and (
            parsed.path.startswith("/tosnetwork/tos/blob/main/")
            or parsed.path.startswith("/tosnetwork/tos/tree/main/")
        )
        return value if live else protect(value)

    text = URL.sub(protect_url, text)
    text = LEGAL_LINE.sub(lambda match: protect(match.group()), text)
    for name in sorted(retained_paths, key=len, reverse=True):
        if name in text:
            text = text.replace(name, protect(name))
    # Some generated textual compiler fixtures spell out the getter ID. Change
    # this ID only in a file tied to the renamed contract, not arbitrary numbers.
    if "get_jetton_data" in text or LEGACY.search(path):
        text = re.sub(r"(?<=method_id\()106029(?=\))", str(NEW_GETTER_ID), text)
    text = replace_terms(text)
    text = re.sub(r"\x00(\d+)\x00", lambda match: saved[int(match.group(1))], text)
    return text


@dataclasses.dataclass(frozen=True)
class Edit:
    old: str
    new: str
    mode: str
    before_sha256: str
    after_sha256: str
    data: bytes = dataclasses.field(repr=False)

    def receipt(self) -> dict[str, str]:
        return {
            "old_path": self.old,
            "new_path": self.new,
            "mode": self.mode,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
        }


def tracked(root: Path) -> dict[str, str]:
    output = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root)
    result: dict[str, str] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, _oid, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise RuntimeError("resolve unmerged index entries before migration")
        result[os.fsdecode(raw_path)] = mode
    return result


def plan(root: Path) -> list[Edit]:
    entries = tracked(root)
    retained = tuple(name for name in entries if rename(name) == name and immutable(name) and LEGACY.search(name))
    targets: dict[str, str] = {}
    edits: list[Edit] = []
    for name, mode in sorted(entries.items()):
        if mode == "160000":
            continue
        target = rename(name)
        if target in targets:
            raise RuntimeError(f"path collision: {targets[target]} and {name} -> {target}")
        targets[target] = name
        path = root / name
        if mode == "120000":
            before = os.fsencode(os.readlink(path))
            after = before if immutable(name) else os.fsencode(rename(os.fsdecode(before)))
        elif mode in {"100644", "100755"}:
            before = path.read_bytes()
            after = before
            if b"\0" not in before and not immutable(name):
                try:
                    after = transform(name, before.decode("utf-8"), retained).encode("utf-8")
                except UnicodeDecodeError:
                    pass
        else:
            raise RuntimeError(f"unsupported file mode: {mode} {name}")
        if target != name or after != before:
            if target != name and (root / target).exists():
                raise RuntimeError(f"refusing to overwrite existing path: {target}")
            edits.append(Edit(name, target, mode, hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest(), after))
    return edits


def apply(root: Path, edits: list[Edit]) -> None:
    # Complete planning/collision checks before changing a single file.
    for edit in edits:
        old = root / edit.old
        target = root / edit.new
        target.parent.mkdir(parents=True, exist_ok=True)
        if edit.mode == "120000":
            old.unlink()
            target.symlink_to(os.fsdecode(edit.data))
        else:
            target.write_bytes(edit.data)
            target.chmod(0o755 if edit.mode == "100755" else 0o644)
            if edit.old != edit.new:
                old.unlink()
    # Stage exactly the planned paths, not temporary build output or credentials.
    paths = sorted({name for edit in edits for name in (edit.old, edit.new)})
    for offset in range(0, len(paths), 100):
        subprocess.run(["git", "add", "--all", "--", *paths[offset : offset + 100]], cwd=root, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    if args.apply and args.check:
        parser.error("--apply and --check are mutually exclusive")
    root = args.root.resolve()
    if args.apply and subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root).strip():
        raise RuntimeError("migration requires a clean working tree and index")
    edits = plan(root)
    print(json.dumps({"planned_files": len(edits), "renamed_paths": sum(edit.old != edit.new for edit in edits), "getter_id": NEW_GETTER_ID}))
    if args.check:
        for edit in edits[:50]:
            print(f"remaining migration: {edit.old} -> {edit.new}", file=sys.stderr)
        return 1 if edits else 0
    if args.apply:
        apply(root, edits)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps({"source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(), "files": [edit.receipt() for edit in edits]}, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"token migration failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
