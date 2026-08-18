#!/usr/bin/env python3
"""Verify source provenance and security-critical invariants of the bridge port."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "crosschain/legacy-jusdt-bridge"
EXPECTED_COMMITS = {
    "tvm": "4e7ec44a651e6b455ce5a09ed1383535fae3a637",
    "evm": "ac5f58a6d28857d7b653d8f76f7d8ca58811a1c3",
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
        "tvm/contracts/jetton-bridge.fc",
        "tvm/contracts/jetton-minter.fc",
        "tvm/contracts/jetton-wallet.fc",
        "tvm/contracts/multisig.fc",
        "tvm/contracts/votes-collector.fc",
        "evm/contracts/Bridge.sol",
        "evm/contracts/SignatureChecker.sol",
        "evm/contracts/TonUtils.sol",
    }
    missing = required - seen
    if missing:
        raise AssertionError(f"manifest omits required contracts: {sorted(missing)}")


def verify_no_deployment_artifacts() -> None:
    forbidden_names = {
        "build-mainnet.txt",
        "build-testnet.txt",
        "deploy-mainnet-bridge.ts",
    }
    for path in PROJECT.rglob("*"):
        if not path.is_file():
            continue
        if path.name in forbidden_names or path.suffix in {".boc", ".addr"}:
            raise AssertionError(f"deployed upstream artifact must not be vendored: {path}")
        if path.name.startswith("uf_public_keys_"):
            raise AssertionError(f"historical oracle set must not be vendored: {path}")


def verify_tvm_sources() -> None:
    c = PROJECT / "tvm/contracts"
    require_text(c / "config.fc", [
        "config_param(CONFIG_PARAM_ID)",
        "config_param(- CONFIG_PARAM_ID)",
        "STATE_BURN_SUSPENDED",
        "STATE_SWAPS_SUSPENDED",
        "STATE_GOVERNANCE_SUSPENDED",
    ])
    require_text(c / "jetton-bridge.fc", [
        "op::execute_voting::swap",
        "throw_unless(error::mint_fee_not_matched, msg_value == bridge_mint_fee)",
        "calculate_minter_address(wrapped_token_data)",
        "throw_unless(error::minter_not_sender",
        "emit_log_simple(LOG_BURN",
        "emit_log_simple(LOG_SWAP_PAID",
    ])
    require_text(c / "jetton-wallet.fc", [
        "throw_unless(error::not_enough_funds, jetton_amount > 0)",
        "throw_unless(error::burn_fee_not_matched, msg_value == bridge_burn_fee)",
        "state_flags & STATE_BURN_SUSPENDED",
        ".store_uint(destination_address, 160)",
    ])
    require_text(c / "jetton-minter.fc", [
        "sender_wc == -1",
        "sender_address_hash == bridge_address_hash",
        "calculate_user_jetton_wallet_address",
        "https://tos.network/bridge/token/",
    ])
    require_text(c / "multisig.fc", ["recv_external", "check_signature", "cnt >= k", "send_raw_message"])
    require_text(c / "votes-collector.fc", ["udict_add?", "get_jetton_bridge_config", "STATE_COLLECTOR_SIGNATURE_REMOVAL_SUSPENDED"])

    expected_params = {
        "ethereum.fc": (79, 1),
        "bsc.fc": (81, 56),
        "polygon.fc": (82, 137),
    }
    for name, (param, chain_id) in expected_params.items():
        require_text(PROJECT / "tvm/params" / name, [
            f"const int CONFIG_PARAM_ID = {param};",
            f"const int MY_CHAIN_ID = {chain_id};",
            "const int WORKCHAIN = 0;",
        ])


def verify_evm_sources() -> None:
    c = PROJECT / "evm/contracts"
    require_text(c / "Bridge.sol", [
        "contract Bridge is SignatureChecker, ReentrancyGuard",
        "nonReentrant",
        "safeTransferFrom",
        "newBalance <= 2 ** 120 - 1",
        "signatures.length >= (2 * oracleSet.length + 2) / 3",
        "require(next_signer > last_signer",
        "require(!finishedVotings[digest]",
        "finishedVotings[_id] = true",
        "require(newOracles[i] != address(0)",
        "require(!isOracle[newOracles[i]]",
    ])
    require_text(c / "SignatureChecker.sol", [
        "address(this)",
        "block.chainid",
        "data.token",
        "data.tx.tx_hash",
        "uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
        "v == 27 || v == 28",
    ])
    require_text(c / "TonUtils.sol", ["uint256 amount", "bytes32 tx_hash", "uint64 lt"])


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
    print("legacy jUSDT bridge source and protocol invariants verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
