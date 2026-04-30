#!/usr/bin/env python3
"""Validate the Slice 3 release-package surrogate."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


EXAMPLE_PROJECTS = (
    ("jetton", "examples/slice3/jetton-author-trial", "jetton-positive"),
    ("nft", "examples/slice3/nft-author-trial", "nft-positive"),
)

REQUIRED_DOCS = (
    "doc/slice-3-release-notes.md",
    "doc/slice-3-compatibility-matrix.md",
    "doc/slice-3-audit-checklist.md",
    "doc/slice-3-external-author-trial.md",
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


def validate_json(path: Path) -> None:
    try:
        with path.open("r", encoding="utf-8") as f:
            json.load(f)
    except json.JSONDecodeError as e:
        raise SystemExit(f"{path}: invalid JSON: {e}") from e


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    tol = Path(args.tol)
    tester = Path(args.tol_tester)
    require(tol.exists(), f"{tol}: tol executable not found")
    require(tester.exists(), f"{tester}: tol-tester.py not found")

    for doc in REQUIRED_DOCS:
        path = root / doc
        require(path.exists(), f"{path}: required release package doc missing")
        require(path.stat().st_size > 0, f"{path}: release package doc is empty")

    env = os.environ.copy()
    env["TOL_EXECUTABLE"] = str(tol)
    env["FIFT_EXECUTABLE"] = args.fift
    env["FIFTPATH"] = args.fiftpath

    validated = []
    for pattern, relative_dir, test_filter in EXAMPLE_PROJECTS:
        project = root / relative_dir
        require(project.is_dir(), f"{project}: example project missing")
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
            validate_json(project / relative)
        validated.append(pattern)

    print(f"Validated Slice 3 release-package surrogate: {', '.join(validated)} examples and {len(REQUIRED_DOCS)} docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
