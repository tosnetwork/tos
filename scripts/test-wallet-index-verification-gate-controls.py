#!/usr/bin/env python3
"""Red-before control for the wallet-index serving gate.

Removes the service's refusal of an index that is not Full, rebuilds the
service, and requires the gate regression to fail; then restores the source,
rebuilds and requires it to pass. The source is restored in `finally` and its
hash is checked.
"""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "services/index-main.cpp"
GUARD = "    if (state.ok() != tos_wallet_index::VerificationState::Full) {"
REMOVED = "    if (false) {"


def build(build_dir: Path, jobs: int) -> None:
    subprocess.run(
        ["cmake", "--build", str(build_dir), "--target", "tos-wallet-index", "-j", str(jobs)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def gate(build_dir: Path) -> int:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/test_wallet_index_verification_gate.py"),
            "--index-binary",
            str(build_dir / "services/tos-wallet-index"),
            "--snapshot-binary",
            str(build_dir / "services/tos-wallet-index-snapshot"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    original = SOURCE.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    text = original.decode()
    if text.count(GUARD) != 1:
        raise RuntimeError("serving gate anchor is not unique")
    build(build_dir, args.jobs)
    if gate(build_dir) != 0:
        print("the gate regression fails on the unmodified source", file=sys.stderr)
        return 1
    try:
        SOURCE.write_text(text.replace(GUARD, REMOVED, 1))
        build(build_dir, args.jobs)
        red = gate(build_dir) != 0
    finally:
        SOURCE.write_bytes(original)
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != digest:
        raise RuntimeError("service source was not restored")
    build(build_dir, args.jobs)
    green = gate(build_dir) == 0
    if not red:
        print("removing the serving gate left the regression passing", file=sys.stderr)
        return 1
    if not green:
        print("the restored service fails the gate regression", file=sys.stderr)
        return 1
    print("WALLET_INDEX_VERIFICATION_GATE_CONTROL_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
