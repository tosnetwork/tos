"""Inventory committed workflow bytes; never execute YAML or claim CI parity.

Only local Git objects are read. Fetch the desired refs separately. The report
binds both commits and their complete workflow directory trees, including modes.
This is phase-zero drift detection, not a YAML parser or a local CI executor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

FORMAT = "tos-workflow-inventory-v1"
MODES = {"040000", "100644", "100755", "120000", "160000"}


class InventoryError(ValueError):
    """An inventory cannot be established without ambiguity."""


def _oid(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
        raise InventoryError("Invalid full object identity")
    return value


def _git(repo: Path, *args: str, allowed: tuple[int, ...] = (0,)) -> bytes:
    # Ambient object-directory, replacement and injected config settings must
    # not make --repo silently inspect a different set of objects.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_NO_LAZY_FETCH="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        LC_ALL="C",
    )
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *args],
            capture_output=True,
            check=False,
            timeout=30,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError(f"Cannot read local Git objects: {exc}") from exc
    if result.returncode not in allowed:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise InventoryError(f"Git failed ({result.returncode}): {detail}")
    return result.stdout


def tree_oid(entries: dict[str, list[str]], oid_length: int) -> str:
    """Reproduce the directory object identity, not a hash of a JSON rendering."""
    if oid_length not in (40, 64) or not isinstance(entries, dict):
        raise InventoryError("Invalid tree inventory")
    for name, entry in entries.items():
        if (
            not isinstance(name, str)
            or not name
            or "/" in name
            or "\0" in name
            or name in {".", ".."}
            or not isinstance(entry, list)
            or len(entry) != 2
        ):
            raise InventoryError("Invalid direct tree entry")
        mode, oid = entry
        if not isinstance(mode, str) or mode not in MODES or len(_oid(oid)) != oid_length:
            raise InventoryError("Invalid mode or mixed object formats")
    ordered = sorted(
        entries,
        key=lambda name: (name + ("/" if entries[name][0] == "040000" else "")).encode(),
    )
    payload = b"".join(
        entries[name][0].lstrip("0").encode()
        + b" "
        + name.encode()
        + b"\0"
        + bytes.fromhex(entries[name][1])
        for name in ordered
    )
    data = f"tree {len(payload)}\0".encode() + payload
    if oid_length == 40:
        return hashlib.sha1(data, usedforsecurity=False).hexdigest()
    return hashlib.sha256(data).hexdigest()


def workflow_count(entries: dict[str, list[str]]) -> int:
    count = 0
    for name, (mode, _) in entries.items():
        if name.endswith((".yml", ".yaml")):
            if mode not in {"100644", "100755"}:
                raise InventoryError(f"Workflow is not an ordinary file: {name!r}")
            count += 1
    if count == 0:
        raise InventoryError("No workflow files; empty evidence is not success")
    return count


def snapshot(repo: Path, ref: str) -> dict[str, Any]:
    if not ref or ref.startswith("-") or any(char in ref for char in "\0\r\n"):
        raise InventoryError("Invalid commit ref")
    # Older Git versions may ignore the lazy-fetch environment switch. Refuse
    # promisor repositories rather than implicitly downloading missing objects.
    promisor = _git(
        repo,
        "config",
        "--local",
        "--get-regexp",
        r"^(extensions\.partialclone|remote\..*\.promisor)$",
        allowed=(0, 1),
    )
    if promisor:
        raise InventoryError("Use a non-promisor local checkout for an offline inventory")
    commit = _oid(
        _git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
        .decode()
        .strip()
    )
    tree = _oid(_git(repo, "rev-parse", "--verify", f"{commit}:.github/workflows").decode().strip())
    if _git(repo, "cat-file", "-t", tree).strip() != b"tree":
        raise InventoryError("The workflow path is not a directory")
    entries: dict[str, list[str]] = {}
    for record in _git(repo, "ls-tree", "-z", tree).split(b"\0"):
        if not record:
            continue
        header, name_bytes = record.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        name = name_bytes.decode("utf-8")
        if name in entries:
            raise InventoryError("Duplicate tree entry")
        expected_kind = "tree" if mode == "040000" else "commit" if mode == "160000" else "blob"
        if kind != expected_kind:
            raise InventoryError("Unexpected tree entry type")
        entries[name] = [mode, oid]
    result = {
        "commit": commit,
        "tree": tree,
        "workflow_count": workflow_count(entries),
        "entries": entries,
    }
    validate_snapshot(result)
    return result


def changes(base: dict[str, Any], candidate: dict[str, Any]) -> dict[str, list[str]]:
    before, after = base["entries"], candidate["entries"]
    return {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "modified": sorted(
            name for name in before.keys() & after.keys() if before[name] != after[name]
        ),
    }


def validate_snapshot(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"commit", "tree", "workflow_count", "entries"}:
        raise InventoryError("Invalid snapshot fields")
    commit, tree = _oid(value["commit"]), _oid(value["tree"])
    if len(commit) != len(tree) or tree_oid(value["entries"], len(tree)) != tree:
        raise InventoryError("Workflow directory identity does not match its entries")
    if type(value["workflow_count"]) is not int or value["workflow_count"] != workflow_count(
        value["entries"]
    ):
        raise InventoryError("Workflow count does not match its entries")


def validate_report(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"format", "base", "candidate", "changes"}:
        raise InventoryError("Invalid report fields")
    if value["format"] != FORMAT:
        raise InventoryError("Unsupported inventory format")
    validate_snapshot(value["base"])
    validate_snapshot(value["candidate"])
    if len(value["base"]["commit"]) != len(value["candidate"]["commit"]):
        raise InventoryError("Snapshots use different repository object formats")
    if value["changes"] != changes(value["base"], value["candidate"]):
        raise InventoryError("Change list does not match the two snapshots")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_report(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique)
    validate_report(value)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base")
    parser.add_argument("--candidate")
    parser.add_argument("--expect", type=Path, help="Fail on any source or workflow-tree drift")
    parser.add_argument(
        "--verify-baseline", type=Path, help="Check metadata consistency only; no repository reads"
    )
    args = parser.parse_args(argv)
    try:
        if args.verify_baseline:
            if args.base or args.candidate or args.expect:
                raise InventoryError("Baseline verification cannot be combined with ref comparison")
            report = read_report(args.verify_baseline)
            print(
                json.dumps(
                    {"metadata_consistent": True, "ci_result": None, "changes": report["changes"]},
                    indent=2,
                )
            )
            return 0
        if not args.base or not args.candidate:
            raise InventoryError("Both --base and --candidate are required")
        report = {
            "format": FORMAT,
            "base": snapshot(args.repo, args.base),
            "candidate": snapshot(args.repo, args.candidate),
        }
        report["changes"] = changes(report["base"], report["candidate"])
        validate_report(report)
        expected = read_report(args.expect) if args.expect else None
        print(json.dumps(report, indent=2, sort_keys=True))
        if expected is not None and report != expected:
            print(
                "Inventory drift: review the new commits and workflow trees; "
                "no CI result is implied.",
                file=sys.stderr,
            )
            return 1
        return 0
    except (InventoryError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Inventory error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
