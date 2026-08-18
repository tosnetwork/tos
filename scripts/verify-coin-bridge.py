#!/usr/bin/env python3
"""Verify security-critical invariants of the TOS coin bridge sources."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "crosschain/coin-bridge"

REQUIRED_SOURCES = [
    "tvm/ethereum/bridge_code.fc",
    "tvm/ethereum/multisig-code.fc",
    "tvm/ethereum/votes-collector.fc",
    "tvm/ethereum/bridge-config.fc",
    "tvm/ethereum/stdlib.fc",
    "tvm/bsc/bridge_code.fc",
    "tvm/bsc/multisig-code.fc",
    "tvm/bsc/votes-collector.fc",
    "tvm/bsc/bridge-config.fc",
    "tvm/bsc/stdlib.fc",
    "tvm/tests/funcer.js",
    "evm/contracts/Bridge.sol",
    "evm/contracts/WrappedTOS.sol",
    "evm/contracts/SignatureChecker.sol",
    "evm/contracts/TosUtils.sol",
]

# Legacy naming from the source chain must not reappear anywhere in the
# vendored sources; the NOTICE file carries the upstream attribution instead.
LEGACY_PATTERN = re.compile(
    r"\bTON\b|\bton\b|\btons\b|\bTONs\b|Ton[A-Z]|\bToncoin|\btoncoin"
    r"|WrappedTON|TonUtil|STGRAMS|LDGRAMS|\bGram|\bgrams?\b"
)
BRANDING_EXTS = {".fc", ".fif", ".sol", ".ts", ".js", ".md", ".py"}
BRANDING_SKIP_PARTS = {"node_modules", "artifacts", "build", "cache", "typechain-types", "coverage"}
BRANDING_SKIP_NAMES = {"NOTICE.md", "package-lock.json"}


def require_text(path: Path, needles: list[str]) -> None:
    if not path.is_file():
        raise AssertionError(f"missing required source: {path.relative_to(REPO_ROOT)}")
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise AssertionError(f"{path.relative_to(REPO_ROOT)} missing invariants: {missing}")


def verify_required_sources() -> None:
    missing = [rel for rel in REQUIRED_SOURCES if not (PROJECT / rel).is_file()]
    if missing:
        raise AssertionError(f"missing required contracts: {missing}")


def verify_no_deployment_artifacts() -> None:
    forbidden_names = {"build.txt", "build-testnet.txt"}
    for path in PROJECT.rglob("*"):
        if not path.is_file() or set(path.parts) & BRANDING_SKIP_PARTS:
            continue
        if path.name in forbidden_names or path.suffix in {".boc", ".addr"}:
            raise AssertionError(f"deployed artifact must not be vendored: {path}")
        if path.name.startswith("uf_public_keys"):
            raise AssertionError(f"historical oracle set must not be vendored: {path}")


def verify_no_legacy_branding() -> None:
    for path in sorted(PROJECT.rglob("*")):
        if not path.is_file() or path.suffix not in BRANDING_EXTS:
            continue
        if set(path.parts) & BRANDING_SKIP_PARTS or path.name in BRANDING_SKIP_NAMES:
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if LEGACY_PATTERN.search(line):
                raise AssertionError(
                    f"legacy source-chain naming in {path.relative_to(REPO_ROOT)}:{i}: {line.strip()}"
                )


def verify_tvm_sources() -> None:
    expected_params = {"ethereum": 71, "bsc": 72}
    for network, param in expected_params.items():
        c = PROJECT / "tvm" / network
        require_text(c / "bridge-config.fc", [
            f"config_param({param})",
            f"config_param(-{param})",
        ])
        require_text(c / "bridge_code.fc", [
            "create_swap_from_tos",
            "calculate_fee",
            "flat_reward",
            "network_fee",
            "state_flags",
            "total_locked",
        ])
        require_text(c / "multisig-code.fc", ["check_signature", "recv_external"])
        require_text(c / "votes-collector.fc", ["get_bridge_config"])
        require_text(c / "stdlib.fc", ['"STTOMIS"', '"LDTOMIS"'])


def verify_evm_sources() -> None:
    c = PROJECT / "evm/contracts"
    require_text(c / "Bridge.sol", [
        "contract Bridge is SignatureChecker, BridgeInterface, WrappedTOS",
        "require(signatures.length >= 2 * oraclesSet.length / 3",
        "require(!finishedVotings[digest]",
        "finishedVotings[digest] = true",
        "require(isOracle[signer]",
        "require(next_signer > last_signer",
        "require(!isOracle[newSet[i]]",
        'require(newOracles.length > 2, "New set is too short")',
    ])
    require_text(c / "WrappedTOS.sol", [
        'require(allowBurn, "Burn is currently disabled")',
        "_burn(msg.sender, amount)",
    ])
    require_text(c / "SignatureChecker.sol", [
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
        "if (v != 27 && v != 28)",
        'require(ecrecover(prefixedHash, v, r, s) == sig.signer, "Wrong signature")',
    ])
    require_text(c / "TosUtils.sol", ["bytes32 tx_hash", "uint64 lt"])


def run_model_tests() -> None:
    subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(PROJECT / "tests"), "-p", "test_*.py", "-v"],
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-model", action="store_true")
    args = parser.parse_args()
    verify_required_sources()
    verify_no_deployment_artifacts()
    verify_no_legacy_branding()
    verify_tvm_sources()
    verify_evm_sources()
    if not args.skip_model:
        run_model_tests()
    print("coin bridge source and protocol invariants verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
