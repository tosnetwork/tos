"""The committed evidence index of a local end-to-end run, and its checker.

The index holds hashes, outcomes and identities: of the binaries, the chain,
the pool, the Bond and every receipt. The receipts themselves stay outside
git under a retention root. A checker that is handed the retention root
recomputes every hash; one that is not checks the structure only and says so.
A missing retained file is never reported as verified.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from localnet_common import PROVENANCE_BINARIES, LocalnetError, sha256_file

INDEX_SCHEMA = "tos.shield.localnet.evidence-index.v1"
RETENTION_SCHEMA = "tos.shield.localnet.retention.v1"
REQUIRED = {
    "schema",
    "result",
    "checked_utc",
    "base_commit",
    "revisions",
    "binaries",
    "chain",
    "pool",
    "bond",
    "tor",
    "amounts",
    "steps",
    "controls",
    "proving",
    "raw_retention_root",
    "privacy",
}
HEX64 = 64
COMMIT_ID = 40


def hex64(value: Any) -> bool:
    return lowercase_hex(value, HEX64)


def lowercase_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def check_structure(index: Any) -> list[str]:
    """Every problem with the index's shape; an empty list is a sound shape."""
    problems: list[str] = []
    if not isinstance(index, dict):
        return ["the index is not an object"]
    if index.get("schema") != INDEX_SCHEMA:
        problems.append(f"schema is not {INDEX_SCHEMA}")
    missing = REQUIRED - set(index)
    if missing:
        problems.append(f"missing fields: {sorted(missing)}")
        return problems
    if index["result"] not in ("PASS", "FAIL"):
        problems.append("result is neither PASS nor FAIL")
    if not lowercase_hex(index["base_commit"], COMMIT_ID):
        problems.append("base_commit is not a full commit id")
    # The binaries built from this repository must name the commit and source
    # path that built them. A system tool such as strace is identified by its
    # digest alone, and a build claim on it must still be well formed.
    for name in PROVENANCE_BINARIES:
        if name not in index["binaries"]:
            problems.append(f"binary {name} is missing from the index")
    for name, binary in index["binaries"].items():
        if not isinstance(binary, dict) or not hex64(binary.get("sha256")):
            problems.append(f"binary {name} has no sha256")
            continue
        source = binary.get("source")
        if source is None and name not in PROVENANCE_BINARIES:
            continue
        if (
            not isinstance(source, dict)
            or not lowercase_hex(source.get("commit"), COMMIT_ID)
            or not isinstance(source.get("path"), str)
            or not source["path"]
        ):
            problems.append(f"binary {name} does not say which commit and source path built it")
    for key in ("zerostate_root", "zerostate_file"):
        if not hex64(index["chain"].get(key)):
            problems.append(f"chain.{key} is not a digest")
    if index["chain"].get("global_id") != 3:
        problems.append("the chain is not an isolated local network (global id 3)")
    for key in (
        "code_hash",
        "initial_data_hash",
        "pool_config_hash",
        "profile_hash",
        "groth16_vk_hash",
    ):
        if not hex64(index["pool"].get(key)):
            problems.append(f"pool.{key} is not a digest")
    if index["pool"].get("development_verifying_key") is not False:
        problems.append("the pool does not say it carries a ceremony key")
    if not isinstance(index["tor"], str) or "offline" not in index["tor"]:
        problems.append("tor does not state the offline stand-in")
    steps = index["steps"]
    if not isinstance(steps, list) or not steps:
        problems.append("steps is empty")
    else:
        for step in steps:
            for key in ("name", "outcome", "receipt", "sha256"):
                if key not in step:
                    problems.append(f"a step lacks {key}")
            if step.get("outcome") not in ("PASS", "FAIL", "SKIP"):
                problems.append(f"step {step.get('name')} has outcome {step.get('outcome')!r}")
            if not hex64(step.get("sha256")):
                problems.append(f"step {step.get('name')} has no receipt digest")
    controls = index["controls"]
    if not isinstance(controls, list) or not controls:
        problems.append("controls is empty")
    else:
        for control in controls:
            if control.get("outcome") != "RED":
                problems.append(f"control {control.get('name')} did not go red")
            if not hex64(control.get("sha256")):
                problems.append(f"control {control.get('name')} has no receipt digest")
    if index["result"] == "PASS":
        failed = [s["name"] for s in steps if isinstance(s, dict) and s.get("outcome") == "FAIL"]
        if failed:
            problems.append(f"PASS with failed steps {failed}")
    return problems


def check_receipts(index: dict[str, Any], retention_root: Path, index_sha256: str) -> list[str]:
    """Recompute every receipt digest from the retained files, bind the
    retention record to this index file (by its digest), and recompute every
    file the record retains, including the connection traces the receipts
    cite."""
    problems: list[str] = []
    for entry in [*index["steps"], *index["controls"]]:
        path = retention_root / str(entry["receipt"])
        if not path.is_file():
            problems.append(f"{entry['name']}: retained receipt {entry['receipt']} is missing")
            continue
        if sha256_file(path) != entry["sha256"]:
            problems.append(f"{entry['name']}: retained receipt does not match its digest")
            continue
        problems.extend(_check_cited_traces(entry["name"], path, retention_root))
    retention = retention_root / "EVIDENCE-RETENTION.json"
    if not retention.is_file():
        problems.append("no EVIDENCE-RETENTION.json at the retention root")
        return problems
    record = json.loads(retention.read_text())
    if record.get("schema") != RETENTION_SCHEMA:
        problems.append("the retention record has the wrong schema")
    if record.get("index_sha256") != index_sha256:
        problems.append("the retention record does not retain this index")
    files = record.get("files")
    if not isinstance(files, list) or not files:
        problems.append("the retention record names no files")
        return problems
    retained = {str(entry.get("path")) for entry in files if isinstance(entry, dict)}
    for entry in files:
        if not isinstance(entry, dict) or not hex64(entry.get("sha256")):
            problems.append(f"retained file {entry!r} has no digest")
            continue
        path = retention_root / str(entry["path"])
        if not path.is_file():
            problems.append(f"retained file {entry['path']} is missing")
        elif path.stat().st_size != entry.get("bytes") or sha256_file(path) != entry["sha256"]:
            problems.append(f"retained file {entry['path']} does not match its digest")
    for name in ("receipts", "traces"):
        for path in sorted((retention_root / name).glob("*")):
            if path.is_file() and f"{name}/{path.name}" not in retained:
                problems.append(f"{name}/{path.name} is present but not retained by the record")
    return problems


def _check_cited_traces(name: str, receipt: Path, retention_root: Path) -> list[str]:
    """A receipt that cites a connection trace by digest must have that trace
    retained with that digest; a verdict about where the client connected is
    worth nothing without the trace it was read from."""
    problems: list[str] = []
    try:
        facts = json.loads(receipt.read_text()).get("facts", {})
    except (OSError, ValueError):
        return [f"{name}: retained receipt is not JSON"]
    for connections in _find_connections(facts):
        trace, digest = connections.get("trace"), connections.get("trace_sha256")
        if not isinstance(trace, str) or not hex64(digest):
            problems.append(f"{name}: a connection verdict cites no trace")
            continue
        path = retention_root / "traces" / trace
        if not path.is_file():
            problems.append(f"{name}: cited trace {trace} is missing")
        elif sha256_file(path) != digest:
            problems.append(f"{name}: cited trace {trace} does not match its digest")
    return problems


def _find_connections(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            if key == "connections" and isinstance(inner, dict):
                found.append(inner)
            else:
                found.extend(_find_connections(inner))
    elif isinstance(value, list):
        for inner in value:
            found.extend(_find_connections(inner))
    return found


def verify(index_path: Path, retention_root: Path | None) -> tuple[str, list[str]]:
    """`("verified" | "structure-only", problems)`. Receipts are verified only
    when the retention root is given and every file is present and matches."""
    index = json.loads(index_path.read_text())
    problems = check_structure(index)
    if problems or retention_root is None:
        return "structure-only", problems
    problems = check_receipts(index, retention_root, sha256_file(index_path))
    return ("verified" if not problems else "structure-only"), problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    parser.add_argument(
        "--retention-root",
        type=Path,
        help="recompute every receipt digest from the retained files under this root",
    )
    args = parser.parse_args()
    try:
        level, problems = verify(args.index, args.retention_root)
    except (OSError, ValueError, LocalnetError) as error:
        print(f"REFUSED: {error}")
        return 2
    for problem in problems:
        print(f"PROBLEM: {problem}")
    if problems:
        print(f"REFUSED: {len(problems)} problem(s); evidence not verified")
        return 1
    print(f"OK: {level} ({args.index})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
