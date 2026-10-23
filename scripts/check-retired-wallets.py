#!/usr/bin/env python3
"""Detect retired wallet implementations. Enforcement is opt-in until deletion lands."""

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKENS = re.compile(
    r"(?<![a-zA-Z0-9_])wallet[-_]v[45](?![0-9])|WalletV[45]|walletV[45]|(?<![a-zA-Z0-9_])WALLET_V[45]|"
    r"V4R[12]|V5R1|wallet[._]v[45][._]|(?<![a-zA-Z0-9_])wallet_v[45]|wallet v[45] r[12]",
    re.IGNORECASE,
)
# These are executable guard definitions, not supported wallet consumers.
GUARD_FILES = frozenset({"scripts/check-retired-wallets.py", "scripts/test_retired_wallets.py"})
COMPILER_FIXTURE = "crypto/func/auto-tests/legacy_tests/wallet-v4/"


def violations(root, paths, historical=()):
    """Check paths and textual content; historical exceptions are exact file names."""
    historical = frozenset(historical)
    found = []
    for name in sorted(paths):
        if name in GUARD_FILES or name in historical or name.startswith(COMPILER_FIXTURE):
            continue
        if TOKENS.search(name):
            found.append(f"{name}: retired wallet path")
        raw = (root / name).read_bytes()
        if b"\0" in raw:
            continue
        for line, text in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
            if TOKENS.search(text):
                found.append(f"{name}:{line}: retired wallet reference")
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enforce", action="store_true", help="enable only with final deletion")
    args = parser.parse_args()
    if not args.enforce:
        print("RETIREMENT ENFORCEMENT INACTIVE: guard self-tests are not removal proof")
        return 0
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    findings = violations(ROOT, [name for name in paths if name])
    if findings:
        print("\n".join(findings))
        return 1
    print("Retired wallet source guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
