#!/usr/bin/env python3
"""Generate and verify Slice 3 `tol new --pattern ...` scaffolds."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


PATTERNS = ("jetton", "nft", "wallet", "multisig")


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


def validate_json(path: Path) -> None:
    with path.open("r", encoding="utf-8") as f:
        json.load(f)


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    tol = Path(args.tol)
    tester = Path(args.tol_tester)
    if not tol.exists():
        raise SystemExit(f"{tol}: tol executable not found")
    if not tester.exists():
        raise SystemExit(f"{tester}: tol-tester.py not found")

    env = os.environ.copy()
    env["TOL_EXECUTABLE"] = str(tol)
    env["FIFT_EXECUTABLE"] = args.fift
    env["FIFTPATH"] = args.fiftpath

    with tempfile.TemporaryDirectory(prefix="slice3-scaffold-") as tmp:
        tmpdir = Path(tmp)
        for pattern in PATTERNS:
            project = tmpdir / pattern
            run([str(tol), "new", "--pattern", pattern, "--output", str(project)])
            run([str(tol), "--check-only", str(project / "src" / "main.tol")])
            # tol-tester keeps artifacts under a path derived from the test file
            # name; pass a relative tests dir so generated temp paths do not
            # collide with the real .tol files.
            run([sys.executable, str(tester), "tests"], cwd=project, env=env)
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
        print(f"Validated {len(PATTERNS)} Slice 3 scaffold pattern(s): {', '.join(PATTERNS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
