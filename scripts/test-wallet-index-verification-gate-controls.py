#!/usr/bin/env python3
"""Red-before controls for the wallet-index serving gate.

Each control removes one guard, rebuilds the service, and requires the gate
regression to fail; the source is then restored and the regression must pass.
The guards are the service's startup refusal of a Refused index, the
JSON-RPC refusal of every index query while the index is not verified, and
the Quarantined state a fresh index holds until the service has decided
between a replay from block 1 and a build. A control naming the failure it
expects requires the regression to fail with it: the fresh index's control
must fail on an answered query. Sources are restored in `finally` and their
hashes are checked.
"""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROLS = [
    (
        "startup refusal",
        ROOT / "services/index-main.cpp",
        "    if (state.ok() == VerificationState::Refused) {",
        "    if (false) {",
        None,
    ),
    (
        "query refusal",
        ROOT / "validator-engine/json-rpc-server.cpp",
        "  if (opts_.index_only && opts_.index_serving && !opts_.index_serving()) {",
        "  if (false) {",
        None,
    ),
    (
        "fresh index held until decided",
        ROOT / "services/index-main.cpp",
        "      deciding = true;\n      gate.set(VerificationState::Quarantined);",
        "      deciding = true;",
        "query answered",
    ),
]


def build(build_dir: Path, jobs: int) -> None:
    subprocess.run(
        [
            "cmake",
            "--build",
            str(build_dir),
            "--target",
            "tos-wallet-index",
            "tos-wallet-index-snapshot",
            "wallet-index-source-fixture",
            "-j",
            str(jobs),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def gate(build_dir: Path) -> tuple[int, str]:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/test_wallet_index_verification_gate.py"),
            "--index-binary",
            str(build_dir / "services/tos-wallet-index"),
            "--snapshot-binary",
            str(build_dir / "services/tos-wallet-index-snapshot"),
            "--source-fixture-binary",
            str(build_dir / "wallet-index-source-fixture"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    return result.returncode, result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    for name, source, guard, _, _ in CONTROLS:
        if source.read_text().count(guard) != 1:
            raise RuntimeError(f"{name} anchor is not unique")
    build(build_dir, args.jobs)
    if gate(build_dir)[0] != 0:
        print("the gate regression fails on the unmodified source", file=sys.stderr)
        return 1
    failed = []
    for name, source, guard, removed, expected in CONTROLS:
        original = source.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        try:
            source.write_text(original.decode().replace(guard, removed, 1))
            build(build_dir, args.jobs)
            code, output = gate(build_dir)
            red = code != 0 and (expected is None or expected in output)
        finally:
            source.write_bytes(original)
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"{source} was not restored")
        build(build_dir, args.jobs)
        green = gate(build_dir)[0] == 0
        print(f"{name}: red={red} green={green}")
        if not red or not green:
            failed.append(name)
    if failed:
        print("controls failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("WALLET_INDEX_VERIFICATION_GATE_CONTROL_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
