#!/usr/bin/env python3
"""Check bounded frozen simulation inputs and their source/profile provenance."""

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = [
    "pre-funded-deployment-1",
    "pre-funded-deployment-2",
    "primary",
    "primary-replay",
    "primary-forged",
    "primary-domain",
    "rescue",
    "rescue-replay",
    "rescue-forged",
    "rescue-domain",
    "send",
    "bad-mode",
    "max-actions",
]


# Require the complete generating source closure; a shortened manifest must fail.
SOURCES = [
    "crypto/smartcont/auth-policy.fc",
    "crypto/smartcont/pq-bytes.fc",
    "crypto/smartcont/pq.fc",
    "crypto/smartcont/stdlib.fc",
    "crypto/smartcont/wallet-quantum-auth.fc",
    "crypto/smartcont/wallet-quantum-common.fc",
    "crypto/smartcont/wallet-quantum-possession-probe.fc",
    "crypto/smartcont/wallet-quantum-self-pay-common.fc",
    "crypto/smartcont/wallet-quantum-self-pay.fc",
    "crypto/smartcont/wallet-v5-action-list.fc",
    "crypto/smc-envelope/QuantumSelfPayCode.h",
    "scripts/update-self-pay-simulation-fixtures.py",
    "test/auth-extensions/cells.py",
    "test/auth-extensions/native.py",
    "test/mldsa-auth/protocol.py",
    "test/wallet-quantum/fee_tx_parity.py",
    "test/wallet-quantum/test_auth_policy.py",
    "test/wallet-quantum/test_self_pay.py",
    "test/wallet-quantum/test_self_pay_recovery.py",
    "tosctl/src/executor/real_boc/default_config.boc",
]


def check(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    if (
        manifest.get("format") != "tos-self-pay-simulation-inputs/1"
        or manifest.get("cases") != NAMES
    ):
        raise ValueError("simulation fixture matrix differs")
    if set(manifest["files"]) != {"config.boc", "scenarios.tsv"}:
        raise ValueError("unexpected simulation fixture files")
    for name, digest in manifest["files"].items():
        data = (directory / name).read_bytes()
        if len(data) > (1 << 20) or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("simulation fixture content differs")
    if [
        line.split("\t", 1)[0] for line in (directory / "scenarios.tsv").read_text().splitlines()
    ] != NAMES:
        raise ValueError("simulation fixture rows differ")
    if set(manifest["sources"]) != set(SOURCES):
        raise ValueError("simulation fixture source closure differs")
    for name, digest in manifest["sources"].items():
        relative = Path(name)
        source = (ROOT / relative).resolve()
        if relative.is_absolute() or ".." in relative.parts or not source.is_relative_to(ROOT):
            raise ValueError("simulation fixture source path refused")
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError("simulation fixture source changed: " + name)
    pin = re.search(
        r'"([0-9a-f]{64})"', (ROOT / "crypto/smc-envelope/QuantumSelfPayCode.h").read_text()
    )
    if pin is None or manifest["code_hash"] != pin.group(1):
        raise ValueError("simulation fixture code profile differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixtures", type=Path, default=ROOT / "test/pq-native/data/self-pay-simulation"
    )
    args = parser.parse_args()
    check(args.fixtures)
    print("Simulation input matrix, file hashes and current source/profile identities match")


if __name__ == "__main__":
    main()
