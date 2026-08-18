#!/usr/bin/env python3
"""Verify security-critical invariants of the TOS token bridge sources."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "crosschain/token-bridge"

REQUIRED_SOURCES = [
    "tvm/contracts/jetton-bridge.fc",
    "tvm/contracts/jetton-minter.fc",
    "tvm/contracts/jetton-wallet.fc",
    "tvm/contracts/multisig.fc",
    "tvm/contracts/votes-collector.fc",
    "tvm/contracts/config.fc",
    "tvm/contracts/stdlib.fc",
    "tvm/params/ethereum.fc",
    "tvm/params/bsc.fc",
    "tvm/params/polygon.fc",
    "evm/contracts/Bridge.sol",
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
    forbidden_names = {
        "build-mainnet.txt",
        "build-testnet.txt",
        "deploy-mainnet-bridge.ts",
    }
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
        "https://bridge.tos.network/token/",
    ])
    require_text(c / "multisig.fc", ["recv_external", "check_signature", "cnt >= k", "send_raw_message"])
    require_text(c / "votes-collector.fc", ["udict_add?", "get_jetton_bridge_config", "STATE_COLLECTOR_SIGNATURE_REMOVAL_SUSPENDED"])
    require_text(c / "stdlib.fc", ['"STTOMIS"', '"LDTOMIS"'])

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
        "oracleSetHash == uint256(keccak256(abi.encode(oracleSet)))",
        'require(initiallyDisabledTokens[i] != address(0), "Zero token in disabled list")',
        'require(nonce > lastLockStatusNonce, "Stale lock status nonce")',
        'require(nonce > lastDisableTokenNonce[tokenAddress], "Stale disable token nonce")',
    ])
    require_text(c / "SignatureChecker.sol", [
        "address(this)",
        "block.chainid",
        "data.token",
        "data.tx.tx_hash",
        "uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
        "v == 27 || v == 28",
    ])
    require_text(c / "TosUtils.sol", ["uint256 amount", "bytes32 tx_hash", "uint64 lt"])


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
    print("token bridge source checks and protocol model passed")
    print("note: these are source-text and model checks; behavior is proven by the EVM and TVM suites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
