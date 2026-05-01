#!/usr/bin/env python3
"""Validate the Slice 5 repo-side release-candidate package."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


PATTERNS = (
    ("auction", "examples/slice5/auction-scaffold", "auction-positive"),
    ("governance", "examples/slice5/governance-scaffold", "governance-positive"),
    ("oracle", "examples/slice5/oracle-scaffold", "oracle-positive"),
    ("payment-channel", "examples/slice5/payment-channel-scaffold", "payment-channel-positive"),
)

EXTERNAL_CANDIDATES = (
    (
        "dex-price-oracle",
        "examples/slice5/dex-price-oracle",
        "src/dex-price-oracle.tol",
        "dex-price-oracle",
    ),
    (
        "tos-stream-channel",
        "examples/slice5/tos-stream-channel",
        "src/tos-stream-channel.tol",
        "tos-stream-channel",
    ),
    (
        "tos-council-fund",
        "examples/slice5/tos-council-fund",
        "src/tos-council-fund.tol",
        "tos-council-fund",
    ),
    (
        "tos-escrowed-auction",
        "examples/slice5/tos-escrowed-auction",
        "src/tos-escrowed-auction.tol",
        "tos-escrowed-auction",
    ),
)

REQUIRED_DOCS = (
    "doc/slice-5-author-guide.md",
    "doc/slice-5-audit-checklist.md",
    "doc/slice-5-compatibility-matrix.md",
    "doc/slice-5-external-author-round-2-prompt.md",
    "doc/slice-5-external-author-trials.md",
    "doc/slice-5-release-checklist.md",
    "doc/slice-5-release-notes.md",
    "doc/slice-5-release-surrogate-trial.md",
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


def validate_generated_manifest(root: Path, manifest_path: Path) -> None:
    data = load_json(manifest_path)
    require(data.get("schema") == "slice-5-generated-project", f"{manifest_path}: bad schema")
    abi_manifest = root / data.get("abi_manifest", "")
    require(abi_manifest.exists(), f"{manifest_path}: ABI manifest missing: {abi_manifest}")
    for entry in data.get("behaviour_conformance", []):
        require(entry.get("mode") in ("raw", "generated"), f"{manifest_path}: invalid behaviour mode")
        behaviour_path = root / entry.get("manifest", "")
        require(behaviour_path.exists(), f"{manifest_path}: behaviour manifest missing: {behaviour_path}")
        behaviour = load_json(behaviour_path)
        require(behaviour.get("behaviour") == entry.get("behaviour"), f"{manifest_path}: behaviour mismatch")


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    tol = Path(args.tol)
    tester = Path(args.tol_tester)
    require(tol.exists(), f"{tol}: tol executable not found")
    require(tester.exists(), f"{tester}: tol-tester.py not found")

    for doc in REQUIRED_DOCS:
        path = root / doc
        require(path.exists() and path.stat().st_size > 0, f"{doc}: required Slice 5 doc missing or empty")

    run([sys.executable, str(root / "scripts" / "check-slice-5-abi-manifests.py")])

    env = os.environ.copy()
    env["TOL_EXECUTABLE"] = str(tol)
    env["FIFT_EXECUTABLE"] = args.fift
    env["FIFTPATH"] = args.fiftpath

    validated = []
    for pattern, relative_dir, test_filter in PATTERNS:
        project = root / relative_dir
        require(project.is_dir(), f"{project}: generated Slice 5 example missing")
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
        validate_generated_manifest(root, project / "manifest.json")
        validated.append(pattern)

    external = []
    for name, relative_dir, source_relative, test_filter in EXTERNAL_CANDIDATES:
        project = root / relative_dir
        require(project.is_dir(), f"{project}: external candidate missing")
        run([str(tol), "--check-only", str(project / source_relative)])
        run([sys.executable, str(tester), "tests", test_filter], cwd=project, env=env)
        manifest = load_json(project / "manifest.json")
        require(manifest.get("abi_manifest"), f"{project}: external candidate ABI manifest missing")
        require((root / manifest["abi_manifest"]).exists(), f"{project}: ABI manifest not found")
        for relative in manifest.get("observability", {}).values():
            load_json(project / relative)
        validate_generated_manifest(root, project / "manifest.json")
        external.append(name)

    require(len(external) >= 3, "Slice 5 external adoption gate requires 3 recorded candidates")
    print(
        f"Validated Slice 5 release candidate: {', '.join(validated)} generated examples, "
        f"{len(external)} external candidate(s), ABI manifests, docs, and artifacts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
