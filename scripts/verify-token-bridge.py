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
    "tvm/contracts/token-bridge.fc",
    "tvm/contracts/token-minter.fc",
    "tvm/contracts/token-wallet.fc",
    "tvm/contracts/multisig.fc",
    "tvm/contracts/votes-collector.fc",
    "tvm/contracts/config.fc",
    "tvm/contracts/settlement.fc",
    "tvm/contracts/stdlib.fc",
    "tvm/params/ethereum.fc",
    "tvm/params/bsc.fc",
    "tvm/params/polygon.fc",
    "tvm/params/tron.fc",
    "tvm/tests/replay-wrong-global-id.js",
    "tvm/tests/weak-owner-key.js",
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


def require_helper_copy(directory: Path) -> None:
    """The weak-key list must stay byte-identical to the one the chain's own contracts use."""
    canonical = (REPO_ROOT / "crypto/smartcont/strong-ed25519-key.fc").read_bytes()
    copy = directory / "strong-ed25519-key.fc"
    if not copy.is_file() or copy.read_bytes() != canonical:
        raise AssertionError(
            f"{copy.relative_to(REPO_ROOT)} must be a byte-identical copy of "
            "crypto/smartcont/strong-ed25519-key.fc"
        )


# What a quorum may make the oracle multisig send: a bounceable vote, in send
# mode 0 to 3, of at most MAX_VOTE_VALUE, with no StateInit, to a masterchain
# bridge its own StateInit lists. One check site, every guard its own code.
MULTISIG_GUARDS = [
    "  check_proposed_query(in_msg, allowed);",
    "  throw_unless(46, allowed_bridge?(dest, allowed));",
    "  throw_unless(47, (flags & 11) == 2);",
    "  throw_unless(48, mode < 4);",
    "  throw_unless(49, (value <= MAX_VOTE_VALUE) & (extra == 0));",
    "  throw_if(50, rest~load_uint(1));",
    "  throw_if(51, allowed.dict_empty?());",
    "const int MAX_VOTE_VALUE = 10000000000;",
    "cell get_allowed_bridges() method_id",
]

# new-multisig.fif takes the allowlist, refuses an empty, non-masterchain or
# repeated entry, and has no time-lock argument.
MULTISIG_SCRIPT = [
    "$# 6 < ' usage if",
    "swap -1 <> {",
    "256 udict!+ not {",
    "allowed\n",
]


def require_multisig_never_reads_config(path: Path) -> None:
    """The multisig's allowlist is its own: a missing or changed ConfigParam cannot widen it."""
    # A source check only; scripts/build-token-bridge.sh also refuses any
    # configuration instruction in the compiled multisig.
    text = path.read_text(encoding="utf-8")
    includes = re.findall(r'#include\s+"([^"]+)"', text)
    if "config_param" in text or any("config" in name for name in includes):
        raise AssertionError(f"{path.relative_to(REPO_ROOT)} must not read ConfigParam")
    script = (path.parent / "new-multisig.fif").read_text(encoding="utf-8")
    if "spend-delay" in script:
        raise AssertionError("new-multisig.fif must not take a time-lock argument")


def verify_required_sources() -> None:
    missing = [rel for rel in REQUIRED_SOURCES if not (PROJECT / rel).is_file()]
    if missing:
        raise AssertionError(f"missing required contracts: {missing}")
    harness = REPO_ROOT / "crosschain/tvm-test-harness/funcer.js"
    if not harness.is_file():
        raise AssertionError("missing the shared TVM test harness")


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
    require_text(
        c / "config.fc",
        [
            "config_param(CONFIG_PARAM_ID)",
            "config_param(- CONFIG_PARAM_ID)",
            "STATE_BURN_SUSPENDED",
            "STATE_SWAPS_SUSPENDED",
            "STATE_GOVERNANCE_SUSPENDED",
        ],
    )
    require_text(
        c / "token-bridge.fc",
        [
            "op::execute_voting::swap",
            "throw_unless(error::mint_fee_not_matched, msg_value == bridge_mint_fee)",
            "throw_unless(error::wrong_namespace, (evm_chain_id == b_evm_chain) & (evm_bridge == b_evm_bridge) & (b_evm_chain == MY_CHAIN_ID))",
            "throw_unless(error::wrong_external_chain_id, chain_id == MY_CHAIN_ID)",
            "calculate_minter_address(wrapped_token_data)",
            "require_generation(generation);",
            "require_open_swap(n);",
            "require_bridge_capacity();",
            "require_window(s, c_mint_ack, MINT_WINDOW);",
            # LOG_BURN commits with the RECORDED decision: mode 0, never ignored.
            "send_raw_message(burn_log_message(destination, amount, token_address, owner_hash), 0);",
            "emit_mandatory(LOG_SWAP_CANCELLED",
            "throw_unless(error::underfunded, msg_value_of_in() >= get_cancel_cost());",
        ],
    )
    require_text(
        c / "token-wallet.fc",
        [
            "throw_unless(error::not_enough_funds, token_amount > 0)",
            "throw_unless(error::burn_fee_not_matched, msg_value == bridge_burn_fee)",
            "state_flags & STATE_BURN_SUSPENDED",
            "throw_if(error::zero_destination, destination_address == 0);",
            "throw_unless(error::life_mismatch, wallet_life == w_born);",
            "require_cell_capacity(WALLET_WORST_CELLS, 0);",
            # Reported transfers (SETTLEMENT-PROTOCOL.md section 20).
            "throw_unless(error::not_canonical_destination, canonical_basechain?(to_owner_address));",
            "throw_if(error::refusal_pending, recorded);",
            "throw_unless(error::payload_too_large, fits);",
            "throw_unless(error::refusals_full, w_refusals_count < REFUSALS_LIMIT);",
            "} elseif (w_refusals_count < REFUSALS_LIMIT) {",
            "const int REPORT_MARGIN = 10;",
            "recorded = total <= MAX_SUPPLY ? total : earlier;",
            "return max(get_compute_fee(false, R_GAS_LIMIT), wallet_gas_consumption);",
            "+ wallet_min_tos_for_storage;",
        ],
    )
    verify_reported_transfers(c)
    require_text(
        c / "token-minter.fc",
        [
            "calculate_user_token_wallet_address",
            "https://bridge.tos.network/token/",
            "(used + amount <= MAX_SUPPLY) & (MINTER_WORST_CELLS <= cell_limit(false))",
            "(m_holders_count >= HOLDER_LIMIT) | (MINTER_WORST_CELLS > cell_limit(false))",
            "emit_mandatory(LOG_LIABILITY_STRANDED",
            "throw_unless(error::bad_floor, floor <= entered_high(m_mints, m_mint_wm));",
        ],
    )
    verify_mandatory_logs(c / "settlement.fc")
    verify_settlement_handlers_skip_config(c)
    require_text(
        c / "multisig.fc",
        [
            "recv_external",
            "check_signature",
            "cnt >= k",
            "send_raw_message",
            'int get_global_id() asm "GLOBALID";',
            "int query_global_id = in_msg~load_int(32);",
            "throw_unless(44, query_global_id == get_global_id());",
            # An owner key anyone can sign for authorizes nothing: refused when
            # the initial data is built and before every stored key's signature.
            '#include "strong-ed25519-key.fc";',
            "  require_strong_owner_keys(owners_info);",
            "  require_strong_owner_key(public_key);",
            "    require_strong_owner_key(key);",
            "  require_strong_owner_key(root_key);",
            *MULTISIG_GUARDS,
        ],
    )
    require_multisig_never_reads_config(c / "multisig.fc")
    require_text(c / "new-multisig.fif", MULTISIG_SCRIPT)
    require_helper_copy(c)
    require_text(
        c / "votes-collector.fc",
        ["udict_add?", "get_token_bridge_config", "STATE_COLLECTOR_SIGNATURE_REMOVAL_SUSPENDED"],
    )
    require_text(c / "stdlib.fc", ['"STTOMIS"', '"LDTOMIS"', '"GETGASFEE"', '"GETFORWARDFEE"'])

    expected_params = {
        "ethereum.fc": (79, 1),
        "bsc.fc": (81, 56),
        "polygon.fc": (82, 137),
        "tron.fc": (83, 728126428),
    }
    for name, (param, chain_id) in expected_params.items():
        require_text(
            PROJECT / "tvm/params" / name,
            [
                f"const int CONFIG_PARAM_ID = {param};",
                f"const int MY_CHAIN_ID = {chain_id};",
                "const int WORKCHAIN = 0;",
            ],
        )


def function_bodies(text: str) -> dict[str, str]:
    """FunC function definitions at column 0, by name, with their bodies."""
    bodies: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    header = re.compile(
        r"^(?:\(.*?\)|[A-Za-z_][\w,() ]*?)\s+([A-Za-z_][\w?']*)\s*\(.*\)\s*[\w ]*\{\s*$"
    )
    while i < len(lines):
        m = header.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        depth = lines[i].count("{") - lines[i].count("}")
        j = i + 1
        while j < len(lines) and depth > 0:
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        bodies[name] = "\n".join(lines[i + 1 : j])
        i = j
    return bodies


CONFIG_READERS = {"get_token_bridge_config", "get_external_bridge_address"}


def verify_settlement_handlers_skip_config(contracts: Path) -> None:
    """No settlement handler reaches a ConfigParam 79 reader.

    Completions must run while the configuration is absent or changed. Every
    `on_*` handler of the bridge, the minter and the wallet is a settlement
    entry; the check follows calls through every function defined in the
    contract and the files it includes.
    """
    shared = ""
    for inc in ("settlement.fc", "utils.fc", "config.fc", "stdlib.fc"):
        path = contracts / inc
        if path.is_file():
            shared += path.read_text(encoding="utf-8") + "\n"
    call = re.compile(r"[~.]?([A-Za-z_][\w?']*)\s*\(")
    for name in ("token-bridge.fc", "token-minter.fc", "token-wallet.fc"):
        bodies = function_bodies(shared + (contracts / name).read_text(encoding="utf-8"))
        entries = [f for f in bodies if f.startswith("on_")]
        if len(entries) < 4:
            raise AssertionError(f"{name}: found only {len(entries)} settlement handlers")
        for entry in entries:
            seen, todo = set(), [entry]
            while todo:
                f = todo.pop()
                if f in seen:
                    continue
                seen.add(f)
                if f in CONFIG_READERS:
                    raise AssertionError(f"{name}: settlement handler {entry} reaches {f}")
                for callee in call.findall(bodies.get(f, "")):
                    if callee in bodies or callee in CONFIG_READERS:
                        todo.append(callee)


REPORTED_OPCODES = {
    "op::reported_transfer": "0x52545231",
    "op::internal_transfer_reported": "0x52544931",
    "op::transfer_delivered": "0x52544431",
    "op::transfer_refused": "0x52544631",
    "op::transfer_rereported": "0x52545232",
    "op::rereport_refusal": "0x52545131",
    "op::clear_refusal": "0x52544331",
    "op::provide_balance": "0x52544231",
    "op::take_balance": "0x52544232",
}

BOUNCE_ON_FAIL = "SEND_MODE_BOUNCE_ON_ACTION_FAIL"


def sends(body: str) -> list[str]:
    return re.findall(r"send_raw_message\((.*?)\);", body, flags=re.S)


def verify_reported_transfers(contracts: Path) -> None:
    """The reported transfer's ordering and send-mode invariants.

    Each one is what keeps every way the transfer can end reported: the
    recipient's wallet caps its gas before it spends anything and bounces on
    every failure; the paying wallet raises its gas for a refusal before it
    loads anything, cannot throw while it restores, and never lets the refusal
    report roll the restore back.
    """
    text = (contracts / "token-wallet.fc").read_text(encoding="utf-8")
    shared = "".join(
        (contracts / inc).read_text(encoding="utf-8") + "\n"
        for inc in ("settlement.fc", "utils.fc", "config.fc", "stdlib.fc", "messages.fc")
    )
    bodies = function_bodies(shared + text)
    for name in (
        "recv_internal",
        "send_reported_tokens",
        "receive_reported_tokens",
        "reported_need",
        "on_reported_bounce",
        "on_rereport_refusal",
        "on_clear_refusal",
        "on_provide_balance",
    ):
        if name not in bodies:
            raise AssertionError(f"token-wallet.fc: {name} is missing")
    recv = bodies["recv_internal"]
    branch = recv.split("if (op == op::internal_transfer_reported) {", 1)
    if len(branch) != 2 or not re.match(
        r"\s*(;;[^\n]*\n\s*)*throw_unless\(error::reported_underfunded, "
        r"msg_value >= get_compute_fee\(false, R_GAS_LIMIT\)\);\s*set_gas_limit\(R_GAS_LIMIT\);",
        branch[1],
    ):
        raise AssertionError(
            "token-wallet.fc: R must require the message to pay for R_GAS_LIMIT,"
            " then cap its gas, first in its branch"
        )
    if recv.index("op == op::internal_transfer_reported") > recv.index("get_token_bridge_config()"):
        raise AssertionError("token-wallet.fc: R must cap its gas before reading the configuration")
    if recv.index("set_gas_limit(S_BOUNCE_GAS);") > recv.index("load_data();"):
        raise AssertionError(
            "token-wallet.fc: S must raise its gas for a refusal before loading its data"
        )
    r_sends = sends(bodies["receive_reported_tokens"])
    if len(r_sends) != 3:
        raise AssertionError("token-wallet.fc: R sends the notification, the report and the excess")
    for send in r_sends:
        if "SEND_MODE_IGNORE_ERRORS" not in send and BOUNCE_ON_FAIL not in send:
            raise AssertionError(
                f"token-wallet.fc: R's send must bounce on an action failure: {send}"
            )
    if not any("report.end_cell()" in s and BOUNCE_ON_FAIL in s for s in r_sends):
        raise AssertionError(
            "token-wallet.fc: R's delivery report must commit with the credit (+16)"
        )
    send = bodies["send_reported_tokens"]
    if not (
        "compute_data_size?(msg_body, REPORTED_BODY_CELLS)" in send
        and send.index("throw_unless(error::payload_too_large, fits);")
        < send.index("reported_need(")
    ):
        raise AssertionError("token-wallet.fc: S must cap its body's cells before pricing it")
    if not any(BOUNCE_ON_FAIL in s for s in sends(bodies["send_reported_tokens"])):
        raise AssertionError(
            "token-wallet.fc: S's message to R must bounce on an action failure (+16)"
        )
    notification = [
        s for s in sends(bodies["receive_tokens"]) if "SEND_MODE_IGNORE_ERRORS" not in s
    ]
    if len(notification) != 1 or BOUNCE_ON_FAIL not in notification[0]:
        raise AssertionError(
            "token-wallet.fc: the ordinary notification must bounce on an action failure (+16)"
        )
    # The refusal is the only way the tokens come back: its handler must not
    # throw, and its report must not roll the restore back.
    seen, todo = set(), ["on_reported_bounce"]
    call = re.compile(r"[~.]?([A-Za-z_][\w?']*)\s*\(")
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        body = bodies.get(f, "")
        if re.search(r"\bthrow(_if|_unless)?\(", body):
            raise AssertionError(f"token-wallet.fc: the refusal handler reaches a throw in {f}")
        todo.extend(c for c in call.findall(body) if c in bodies)
    if "SEND_MODE_IGNORE_ERRORS" not in bodies["on_reported_bounce"]:
        raise AssertionError("token-wallet.fc: the refusal report must ignore errors (+2)")
    need = bodies["reported_need"]
    for term in (
        "forward_tos_amount + report_tos_amount",
        "fee_of(msg, false)",
        "REPORT_MARGIN * get_forward_fee(false, 32 + 256, 1)",
        "REPORT_MARGIN * reported_compute_fee(wallet_gas_consumption)",
        "get_compute_fee(false, S_TRANSFER_GAS)",
        "REPORT_MARGIN * get_forward_fee(false, 0, body_cells + 2)",
        "wallet_min_tos_for_storage",
    ):
        if term not in need:
            raise AssertionError(
                f"token-wallet.fc: the reported transfer's value check lacks {term}"
            )
    opcodes = (contracts / "op-codes.fc").read_text(encoding="utf-8")
    for name, value in REPORTED_OPCODES.items():
        if f"const int {name} = {value};" not in opcodes:
            raise AssertionError(f"op-codes.fc: {name} must stay {value}")


def verify_mandatory_logs(settlement: Path) -> None:
    """A mandatory log is sent in mode 0: if it cannot be sent, its leg rolls back."""
    bodies = function_bodies(settlement.read_text(encoding="utf-8"))
    body = bodies.get("emit_mandatory", "")
    if not re.search(r"\.end_cell\(\), 0\);", body):
        raise AssertionError("settlement.fc: emit_mandatory must send in mode 0")
    send = bodies.get("send_settlement", "")
    if not re.search(r"\.end_cell\(\), 1\);", send):
        raise AssertionError("settlement.fc: send_settlement must send in mode 1, never +2")


def verify_evm_sources() -> None:
    c = PROJECT / "evm/contracts"
    require_text(
        c / "Bridge.sol",
        [
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
            'require(generation != 0, "No active generation")',
            'require(lockNonce <= MAX_LOCK_NONCE, "Lock nonces exhausted")',
            'require(record.status == LOCK_OPEN, "Lock is not refundable")',
            'require(newGeneration == generation + 1, "Generation must follow the current one")',
            'require(nonce > lastGenerationNonce, "Stale generation nonce")',
            'require(lockCaps[token].total != 0, "lock: token has no lock cap")',
            "_consumeLockCap(token, received, newBalance);",
            'require(received <= cap.perLock, "lock: over the per-lock cap")',
            'require(newBalance <= cap.total, "lock: over the token cap")',
            'require(hourUsed <= cap.hourly, "lock: over the hourly cap")',
            'require(dayUsed <= cap.daily, "lock: over the daily cap")',
            'require(nonce > lastLockCapNonce[token], "Stale lock cap nonce")',
        ],
    )
    require_text(
        c / "SignatureChecker.sol",
        [
            "address(this)",
            "block.chainid",
            "data.token",
            "data.tx.tx_hash",
            "uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
            "v == 27 || v == 28",
            "abi.encode(0x4EF0, address(this), block.chainid, n, lockGeneration, locker, token, amount)",
            "abi.encode(0x6E4E, address(this), block.chainid, newGeneration, tosBridge, tosLife, nonce)",
            "abi.encode(0xCA95, address(this), block.chainid, token, total, perLock, hourly, daily, nonce)",
        ],
    )
    require_text(c / "TosUtils.sol", ["uint256 amount", "bytes32 tx_hash", "uint64 lt"])


def run_model_tests() -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(PROJECT / "tests"),
            "-p",
            "test_*.py",
            "-v",
        ],
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
    print(
        "note: these are source-text and model checks; behavior is proven by the EVM and TVM suites"
    )
    print(
        "      (the token-bridge sandbox and scripts/test-token-bridge-tvm.sh execute the compiled contracts)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
