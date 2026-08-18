#!/usr/bin/env python3
"""Verify source provenance and security-critical invariants of the Toncoin bridge port."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "crosschain/legacy-toncoin-bridge"
EXPECTED_COMMITS = {
    "tvm-ethereum": "9b606d5b0c886a7b1bd4732a0ecaf0d5d2351354",
    "tvm-bsc": "01b5a05e13b1dd735821dfe2b208ad5c2dd5dec2",
    "evm": "f78adaf8bee30133a6231d7cfe36c9b29dd28613",
}


def require_text(path: Path, needles: list[str]) -> None:
    if not path.is_file():
        raise AssertionError(f"missing required source: {path.relative_to(REPO_ROOT)}")
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise AssertionError(f"{path.relative_to(REPO_ROOT)} missing invariants: {missing}")


def verify_lock() -> None:
    lock_path = PROJECT / "UPSTREAM.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("production_status") != "disabled-until-independent-audit-and-governance-activation":
        raise AssertionError("production gate was removed")
    for name, commit in EXPECTED_COMMITS.items():
        actual = lock["upstreams"][name]["commit"]
        if actual != commit:
            raise AssertionError(f"{name} upstream moved: {actual} != {commit}")


def verify_manifest() -> None:
    manifest = PROJECT / "SOURCE_MANIFEST.sha256"
    if not manifest.is_file():
        raise AssertionError("missing SOURCE_MANIFEST.sha256")
    seen: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, rel = line.split("  ", 1)
        path = PROJECT / rel
        if not path.is_file():
            raise AssertionError(f"manifest file missing: {rel}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise AssertionError(f"manifest mismatch: {rel}")
        seen.add(rel)
    required = {
        "tvm/ethereum/bridge_code.fc",
        "tvm/ethereum/multisig-code.fc",
        "tvm/ethereum/votes-collector.fc",
        "tvm/bsc/bridge_code.fc",
        "tvm/bsc/multisig-code.fc",
        "tvm/bsc/votes-collector.fc",
        "evm/contracts/Bridge.sol",
        "evm/contracts/WrappedTON.sol",
        "evm/contracts/SignatureChecker.sol",
        "evm/contracts/TonUtils.sol",
    }
    missing = required - seen
    if missing:
        raise AssertionError(f"manifest omits required contracts: {sorted(missing)}")


def verify_no_deployment_artifacts() -> None:
    forbidden_names = {"build.txt", "build-testnet.txt"}
    for path in PROJECT.rglob("*"):
        if not path.is_file() or "node_modules" in path.parts or "build" in path.parts:
            continue
        if path.name in forbidden_names or path.suffix in {".boc", ".addr"}:
            raise AssertionError(f"deployed upstream artifact must not be vendored: {path}")
        if path.name.startswith("uf_public_keys"):
            raise AssertionError(f"historical oracle set must not be vendored: {path}")


def verify_tvm_sources() -> None:
    expected_params = {"ethereum": 71, "bsc": 72}
    for network, param in expected_params.items():
        c = PROJECT / "tvm" / network
        require_text(c / "bridge-config.fc", [
            f"config_param({param})",
            f"config_param(-{param})",
        ])
        require_text(c / "bridge_code.fc", [
            "create_swap_from_ton",
            "calculate_fee",
            "flat_reward",
            "network_fee",
            "state_flags",
            "total_locked",
        ])
        require_text(c / "multisig-code.fc", ["check_signature", "recv_external"])
        require_text(c / "votes-collector.fc", ["get_bridge_config"])
        require_text(c / "stdlib.fc", ['"STTOMIS"', '"LDTOMIS"'])
        for name in ("stdlib.fc", "bridge_code.fc", "multisig-code.fc", "votes-collector.fc"):
            text = (c / name).read_text(encoding="utf-8")
            if '"STGRAMS"' in text or '"LDGRAMS"' in text:
                raise AssertionError(f"{network}/{name} still uses pre-TOS assembler mnemonics")


def verify_evm_sources() -> None:
    c = PROJECT / "evm/contracts"
    require_text(c / "Bridge.sol", [
        "contract Bridge is SignatureChecker, BridgeInterface, WrappedTON",
        "require(signatures.length >= 2 * oraclesSet.length / 3",
        "require(!finishedVotings[digest]",
        "finishedVotings[digest] = true",
        "require(isOracle[signer]",
        "require(next_signer > last_signer",
        "require(!isOracle[newSet[i]]",
        'require(newOracles.length > 2, "New set is too short")',
    ])
    require_text(c / "WrappedTON.sol", [
        'require(allowBurn, "Burn is currently disabled")',
        "_burn(msg.sender, amount)",
    ])
    require_text(c / "SignatureChecker.sol", [
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
        "if (v != 27 && v != 28)",
        'require(ecrecover(prefixedHash, v, r, s) == sig.signer, "Wrong signature")',
    ])
    require_text(c / "TonUtils.sol", ["bytes32 tx_hash", "uint64 lt"])


def run_model_tests() -> None:
    subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(PROJECT / "tests"), "-p", "test_*.py", "-v"],
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-model", action="store_true")
    args = parser.parse_args()
    verify_lock()
    verify_manifest()
    verify_no_deployment_artifacts()
    verify_tvm_sources()
    verify_evm_sources()
    if not args.skip_model:
        run_model_tests()
    print("legacy Toncoin bridge source and protocol invariants verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
