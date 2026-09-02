#!/usr/bin/env python3
"""Verify security-critical invariants of the TOS coin bridge sources."""

from __future__ import annotations

import argparse
import json
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
    "tvm/tests/eth2tos.js",
    "tvm/tests/replay-wrong-global-id.js",
    "tvm/tests/migrate.js",
    "tvm/tests/change-fee-floor.js",
    "tvm/tests/tos2eth-zero-destination.js",
    "evm/contracts/Bridge.sol",
    "evm/contracts/WrappedTOS.sol",
    "evm/contracts/SignatureChecker.sol",
    "evm/contracts/TosUtils.sol",
    "evm/test/chainid-domain-separation.js",
    "evm/test/utils/utils.js",
    "evm/test/vectors/chain-id-domain-separation.json",
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
    harness = REPO_ROOT / "crosschain/tvm-test-harness/funcer.js"
    if not harness.is_file():
        raise AssertionError("missing the shared TVM test harness")


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
            # The network fee must cover the fixed 0.1 receipt each swap pays
            # from the bridge balance, or every swap drains the bridge.
            "throw_unless(392, network_fee >= 110000000)",
            # A zero external destination is unspendable; refuse the swap.
            "throw_unless(307, destination_address != 0)",
            # A migration transfer must be recognized and locked by the
            # receiving bridge, not left as sweepable plain balance.
            "if (op == 0xf00d) {",
            "total_locked += msg_value;",
            "store_coins(total_locked); ;; echoed back in a bounce, for exact restoration",
            "total_locked += restored;",
            # The migrating bridge stops backing funds that left it.
            "total_locked = 0;",
        ])
        require_text(c / "multisig-code.fc", [
            "check_signature",
            "recv_external",
            'int get_global_id() asm "GLOBALID";',
            "var hash = slice_hash(in_msg);",
            "int query_wallet_id = in_msg~load_uint(32);",
            "throw_unless(42, query_wallet_id == wallet_id);",
            "int query_global_id = in_msg~load_int(32);",
            "throw_unless(44, query_global_id == get_global_id());",
            "throw_unless(36, slice_hash(msg) == slice_hash(in_msg));",
        ])
        require_text(c / "votes-collector.fc", ["get_bridge_config"])
        require_text(c / "stdlib.fc", ['"STTOMIS"', '"LDTOMIS"'])


def verify_evm_sources() -> None:
    c = PROJECT / "evm/contracts"
    require_text(c / "Bridge.sol", [
        "contract Bridge is SignatureChecker, BridgeInterface, WrappedTOS",
        "require(!finishedVotings[digest]",
        "finishedVotings[digest] = true",
        "require(isOracle[signer]",
        "require(next_signer > last_signer",
        "require(!isOracle[newSet[i]]",
        'require(newSet[i] != address(0), "Zero oracle in Set")',
        'require(newSet.length > 2, "Set is too short")',
        'require(oracleSetHash > lastOracleSetHash, "Stale oracle set hash")',
        'require(nonce > lastBurnStatusNonce, "Stale burn status nonce")',
        "require(signatures.length >= (2 * oraclesSet.length + 2) / 3",
    ])
    require_text(c / "WrappedTOS.sol", [
        'require(allowBurn, "Burn is currently disabled")',
        "_burn(msg.sender, amount)",
        # Burns outside the 64-bit release range or to the zero TOS address
        # destroy wrapped coins with nothing unlocked on the other side.
        'require(amount > 0 && amount <= type(uint64).max, "Burn amount out of range")',
        'require(addr.address_hash != bytes32(0), "Burn to zero address")',
    ])
    signature_checker = c / "SignatureChecker.sol"
    require_text(signature_checker, [
        "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
        "if (v != 27 && v != 28)",
        'require(ecrecover(prefixedHash, v, r, s) == sig.signer, "Wrong signature")',
        "function getChainId() internal pure returns (uint256 id)",
        "assembly { id := chainid() }",
    ])
    signature_text = signature_checker.read_text(encoding="utf-8")
    if signature_text.count("getChainId(),") != 3:
        raise AssertionError("all three EVM vote digests must bind getChainId()")
    for magic in ("0xDA7A", "0x5e7", "0xB012"):
        pattern = re.compile(
            rf"{magic},\s*address\(this\),\s*getChainId\(\),",
            re.MULTILINE,
        )
        if not pattern.search(signature_text):
            raise AssertionError(
                f"{magic} digest must use magic,address(this),chainId field order"
            )
    require_text(c / "TosUtils.sol", ["bytes32 tx_hash", "uint64 lt"])


def verify_domain_separation_artifacts() -> None:
    vector_path = PROJECT / "evm/test/vectors/chain-id-domain-separation.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    if vector.get("schema") != "tos.coin-bridge.chain-id-domain-separation.v1":
        raise AssertionError("unexpected chain-ID golden-vector schema")
    if int(vector.get("chainId", 0)) <= 0:
        raise AssertionError("golden vector must pin a positive chain ID")
    digest_pattern = re.compile(r"^0x[0-9a-f]{64}$")
    expected = vector.get("expected", {})
    for name in ("swapDigest", "oracleSetDigest", "burnStatusDigest"):
        if not digest_pattern.fullmatch(expected.get(name, "")):
            raise AssertionError(f"golden vector has no valid {name}")

    require_text(PROJECT / "evm/test/chainid-domain-separation.js", [
        "same contract address",
        'expectRevert("swap replay"',
        'expectRevert("oracle-set replay"',
        'expectRevert("burn-status replay"',
        'expectRevert("legacy swap"',
        'expectRevert("legacy oracle set"',
        'expectRevert("legacy burn status"',
    ])
    require_text(PROJECT / "NOTICE.md", [
        "chain-ID domain separation",
        "magic, address(this), chainId, fields",
        "chain-id-domain-separation.json",
    ])


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
    verify_domain_separation_artifacts()
    if not args.skip_model:
        run_model_tests()
    print("coin bridge source checks and protocol model passed")
    print("note: these are source-text and model checks; behavior is proven by the EVM and TVM suites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
