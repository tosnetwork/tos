#!/usr/bin/env python3
"""Validate the Slice 4 release-package surrogate."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


REQUIRED_DOCS = (
    "doc/tos-postponement-policy.md",
    "doc/tos-slice-4-policy.md",
    "doc/slice-4-bounded-postponement-guide.md",
    "doc/slice-4-behaviour-conformance.md",
    "doc/slice-4-release-notes.md",
    "doc/slice-4-release-surrogate-trial.md",
)

GENERATED_EXAMPLES = (
    ("jetton", "examples/slice4/jetton-behaviour-scaffold", "jetton-positive"),
    ("nft", "examples/slice4/nft-behaviour-scaffold", "nft-positive"),
    ("multisig", "examples/slice4/multisig-behaviour-scaffold", "multisig-positive"),
)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tol", default=str(root / "build" / "tol" / "tol"))
    parser.add_argument("--tol-tester", default=str(root / "tol-tester" / "tol-tester.py"))
    parser.add_argument("--fift", default=str(root / "build" / "crypto" / "fift"))
    parser.add_argument("--fiftpath", default=str(root / "crypto" / "fift" / "lib"))
    return parser.parse_args()


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    res = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    if res.returncode != 0:
        if res.stdout:
            print(res.stdout, end="")
        if res.stderr:
            print(res.stderr, end="", file=sys.stderr)
        raise SystemExit(f"command failed with exit code {res.returncode}: {' '.join(cmd)}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise SystemExit(f"{path}: invalid JSON: {e}") from e


def validate_behaviour_entries(root: Path, manifest_path: Path) -> None:
    data = load_json(manifest_path)
    entries = data.get("behaviour_conformance")
    require(isinstance(entries, list) and entries, f"{manifest_path}: missing behaviour_conformance")
    for entry in entries:
        require(entry.get("mode") in ("raw", "generated"), f"{manifest_path}: invalid behaviour mode")
        behaviour_manifest = root / entry["manifest"]
        require(behaviour_manifest.exists(), f"{manifest_path}: behaviour manifest missing: {entry['manifest']}")
        behaviour_data = load_json(behaviour_manifest)
        require(behaviour_data.get("behaviour") == entry.get("behaviour"), f"{manifest_path}: behaviour mismatch")


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    tol = Path(args.tol)
    tester = Path(args.tol_tester)
    require(tol.exists(), f"{tol}: tol executable not found")
    require(tester.exists(), f"{tester}: tol-tester.py not found")

    for doc in REQUIRED_DOCS:
        path = root / doc
        require(path.exists() and path.stat().st_size > 0, f"{doc}: required Slice 4 doc missing or empty")

    run([sys.executable, str(root / "scripts" / "check-slice-4-behaviour-manifests.py")])
    run([str(tol), "--check-only", str(root / "examples" / "slice4" / "postponed-auction.tol")])

    env = os.environ.copy()
    env["TOL_EXECUTABLE"] = str(tol)
    env["FIFT_EXECUTABLE"] = args.fift
    env["FIFTPATH"] = args.fiftpath

    run([sys.executable, str(tester), "tests", "slice4"], cwd=root / "tol-tester", env=env)

    validated = []
    for pattern, relative_dir, test_filter in GENERATED_EXAMPLES:
        project = root / relative_dir
        require(project.is_dir(), f"{project}: generated Slice 4 example missing")
        run([str(tol), "--check-only", str(project / "src" / "main.tol")])
        run([sys.executable, str(tester), "tests", test_filter], cwd=project, env=env)
        for relative in (
            "manifest.json",
            f"replay/{pattern}-replay.json",
            "deploy/deploy.json",
            "artifacts/opcodes.json",
            "artifacts/method-ids.json",
            "artifacts/error-codes.json",
            "artifacts/replay-trace.json",
        ):
            load_json(project / relative)
        validate_behaviour_entries(root, project / "manifest.json")
        validated.append(pattern)

    print(f"Validated Slice 4 release package: {', '.join(validated)} generated examples, postponement reference, manifests, and docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
