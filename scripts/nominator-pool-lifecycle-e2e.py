#!/usr/bin/env python3
"""Take a nominator pool through one complete staking round on a local network.

Everything else in the tree tests a piece of this: the contract compiles, the
message builders emit the right opcodes, the daemon knows which nudges a pool
needs. None of that answers the only question a depositor cares about, which is
whether money put into a pool comes back out with a share of what it earned.

So this runs the whole path against a real chain and real blocks:

    basechain wallets deposit with a text comment
    the validator posts its own funds and stakes the pooled total
    the Elector accepts the pool as a participant and elects it
    the validator set turns over, and the pool is told each time
    the holding period expires and the stake is recovered
    rewards are split, and a nominator withdraws what they are owed

It also exercises the two refusals that decide whether a pool survives contact
with reality: a queued withdrawal blocks the next stake outright, and the
recover path stays shut until the pool has counted enough validator set
changes. Both are easy to write off as edge cases; both take a pool out of
service permanently when nothing handles them.

The accelerated profile keeps the stake limits, contracts and message paths and
shortens election timing, so a full round takes minutes rather than a day.
Every transition below is a real block, but this timing profile does not
establish production-duration liveness, storage-rent economics, or APR.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import fcntl
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

from contract import WalletV1, WalletV1Blueprint  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Builder,
    Cell,
    CurrencyCollection,
    InternalMsgInfo,
    MessageAny,
    StateInit,
    Transaction,
    WalletMessage,
)
from pytosiq_core.boc.deserialize import BocError  # noqa: E402
from pytosiq_core.tlb.tlb import TlbError  # noqa: E402
from pytosiq_core.tlb.config import ConfigParam8  # noqa: E402
from tostester.install import Install  # noqa: E402
from tostester.key import Key  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402
from tostester.pq_initial_validator import (  # noqa: E402
    make_deterministic_pq_initial_validator,
    make_deterministic_pq_spare_validator,
)
from tostester.pq_election_fixture import (  # noqa: E402
    ControllerFixture,
    PoolFixture,
    assert_controller_identity,
    build_production_pool_stake_order,
    compile_controller_code,
    elector_reply,
    make_controller_fixture,
    make_pool_fixture,
    parse_past_elections_list,
    participant_ids_from_runmethod,
    require_pq_stake_authorization_binding,
)
from tostester.zerostate import VALIDATOR_ECONOMICS_FAUCET_TOS  # noqa: E402
from tosapi import tos_api, toslib_api  # noqa: E402

T = TypeVar("T")

NANO = 1_000_000_000
ELECTOR = Address((-1, bytes.fromhex("33" * 32)))

# pool.fc constants.
MIN_TOS_FOR_STORAGE = 10 * NANO
DEPOSIT_PROCESSING_FEE = 1 * NANO
MIN_STAKE_TO_SEND = 500 * NANO

# Pool configuration under test.
VALIDATOR_REWARD_SHARE_BPS = 4000  # 40%
MAX_NOMINATORS = 40
MIN_VALIDATOR_STAKE = 5_000 * NANO
MIN_NOMINATOR_STAKE = 100 * NANO

# The network's minimum stake is 10,000 TOS, which is the whole point: the
# validator cannot reach it alone, and the eight Agent-bound proxies supply the
# remaining principal (with the max-factor surplus reported separately).
NETWORK_MIN_STAKE = 10_000 * NANO
ELECTOR_CONFIRMATION_ALLOWANCE = 1 * NANO
# The multi-nominator pool forwards the exact order amount. Its controller's
# forwarding fee comes out of that value before the Elector reserves 1 TOS.
CONTROLLER_FORWARDING_ALLOWANCE = 1 * NANO
POOL_STAKE_VALUE = NETWORK_MIN_STAKE + ELECTOR_CONFIRMATION_ALLOWANCE + CONTROLLER_FORWARDING_ALLOWANCE
# ConfigParam 40's worst tier is TM$2500 plus a quarter of the stake, so the
# validator has to have posted at least that before pool.fc will stake.
VALIDATOR_OWN_DEPOSIT = 5_100 * NANO
NOMINATOR_DEPOSIT = 1_000 * NANO
OPENFOX_AGENT_COUNT = 8
CONTROL_NOMINATOR_COUNT = 1
NOMINATOR_COUNT = OPENFOX_AGENT_COUNT + CONTROL_NOMINATOR_COUNT
CAMPAIGN_RUN_ID_MIN_LENGTH = 8
CAMPAIGN_RUN_ID_MAX_LENGTH = 128
EVIDENCE_ATTEMPT_MARKER_SCHEMA = "tos.validator.nominator-reward-attempt.v1"

# The integrated profile uses the same Agent Accounts that the companion
# OpenFox campaign pays on this genesis.  These values are deliberately small:
# each account starts with a bounded thirty TOS, sends five to the pool, and the
# pool records four after its fixed one-TOS processing fee.  The validator
# supplies the rest of the network minimum; changing campaign custody policy
# or manufacturing a second signing path would make the identity proof weaker.
INTEGRATED_AGENT_ACCOUNT_FUNDING = 30 * NANO
INTEGRATED_NOMINATOR_DEPOSIT = 5 * NANO
INTEGRATED_MIN_NOMINATOR_STAKE = 4 * NANO
INTEGRATED_VALIDATOR_OWN_DEPOSIT = 9_970 * NANO
INTEGRATED_MIN_VALIDATOR_STAKE = 9_969 * NANO
INTEGRATED_POOL_VALIDATOR_FUNDING = 11_000 * NANO
INTEGRATED_OWNER_FUNDING = 35 * NANO
INTEGRATED_DIRECT_VALIDATOR_FUNDING = 300_000 * NANO
INTEGRATED_FAUCET_FUNDING = 2_000_000 * NANO
INTEGRATED_RPC_COUNT = 3
INTEGRATED_NETWORK = "tos:local-accelerated-unified-campaign"
INTEGRATED_EVIDENCE_CLASS = "SAME_GENESIS_CAMPAIGN_WALLETS"
INTEGRATED_NETWORK_ID = "tos:local-three-node"
LEGACY_LOCAL_GLOBAL_ID = 3
INTEGRATED_WORKCHAIN_ID = 0
INTEGRATED_READY_SCHEMA = "tos.openfox.same-genesis-campaign-network-ready.v1"
TASK_SEND_FINALIZED_SCHEMA = "tos.agent-account.task-send-finalized.v1"
TASK_SEND_PROCESS_VIEW_SCOPE = (
    "distinct RPC process views; no independent-operator or Byzantine-finality claim"
)
TASK_SEND_BLOCK_REFERENCE_SCOPE = (
    "RPC-asserted transaction and block identifiers; no inclusion proof was verified"
)
SIDECAR_NETWORK = "tos:local-accelerated-nominator-pool-sidecar"
SIDECAR_EVIDENCE_CLASS = "IDENTITY_BOUND_SIMULATION"
INTEGRATED_OPERATOR_ACTION_LIMIT = (
    "Delegation and withdrawal are operator-scripted low-level custody harness actions, "
    "not autonomous OpenFox AI or PersonalAuthority capital decisions."
)
INTEGRATED_SINGLE_HOST_LIMIT = (
    "All validators and RPC process views run on one host under one operator; no "
    "independent-host, Byzantine-finality, or external-demand claim is made."
)

# A validator whose stake is frozen cannot enter the next election, which
# opens before the current round ends, so continuous participation costs two
# stake principals. This is the same arithmetic the economics document uses to
# size a validator's genesis allocation.
DIRECT_VALIDATOR_FUNDING = 20_100 * NANO
POOL_VALIDATOR_FUNDING = 6_000 * NANO
NOMINATOR_FUNDING = NOMINATOR_DEPOSIT + 100 * NANO
# A basechain wallet with no standing in the pool: not the validator, not a
# depositor. It exists to prove that recovering a staked pool and paying its
# depositors out needs nobody's permission.
RESCUER_FUNDING = 50 * NANO
POOL_DEPLOY_VALUE = 20 * NANO

# pool.fc requires at least one TOS of message value to process a stake; the
# rest of what it forwards comes from its own balance.
POOL_STAKE_GAS = 2 * NANO
SUPPORT_POOL_CAPITAL = 2 * POOL_STAKE_VALUE + 20 * NANO
MAX_FACTOR = 1 << 16
POOL_STATE_IDLE = 0
POOL_STATE_SENT = 1
POOL_STATE_STAKED = 2


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def raw_address(address: Address) -> str:
    return f"{address.wc}:{address.hash_part.hex()}"


def _decoded_transaction(raw_transaction: Any) -> Transaction:
    if not raw_transaction.data:
        raise ValueError("raw transaction has no BOC for bounce/abort classification")
    return Transaction.deserialize(Cell.one_from_boc(raw_transaction.data).begin_parse())


def _relay_query_id(message: MessageAny, *, bounced: bool) -> int | None:
    """Read the pool's relay query ID, including the VM's bounced-body prefix."""
    if not isinstance(message.info, InternalMsgInfo) or message.info.bounced != bounced:
        return None
    body = message.body.begin_parse()
    if bounced and (body.remaining_bits < 32 or body.load_uint(32) != 0xFFFFFFFF):
        return None
    if body.remaining_bits < 96 or body.load_uint(32) != 0x5051726C:
        return None
    return body.load_uint(64)


def _pool_order_transaction_lt(transactions: list[Any], query_id: int) -> str | None:
    for raw_transaction in transactions:
        transaction = _decoded_transaction(raw_transaction)
        message = transaction.in_msg
        if message is None or not isinstance(message.info, InternalMsgInfo):
            continue
        body = message.body.begin_parse()
        if body.remaining_bits >= 96 and body.load_uint(32) == 0x4E73744B:
            if body.load_uint(64) == query_id:
                return str(transaction.lt)
    return None


def _queued_stake_refusal(transactions: list[Any], query_id: int) -> dict[str, Any] | None:
    """Require this order's pool transaction to abort at the queue guard (85)."""
    for raw_transaction in transactions:
        transaction = _decoded_transaction(raw_transaction)
        message = transaction.in_msg
        if message is None or not isinstance(message.info, InternalMsgInfo):
            continue
        body = message.body.begin_parse()
        if body.remaining_bits < 96 or body.load_uint(32) != 0x4E73744B:
            continue
        if body.load_uint(64) != query_id:
            continue
        description = transaction.description
        compute = getattr(description, "compute_ph", None)
        if getattr(description, "aborted", None) is True and getattr(compute, "exit_code", None) == 85:
            return {
                "transaction_lt": str(transaction.lt),
                "transaction_boc_base64": base64.b64encode(raw_transaction.data).decode(),
                "transaction_boc_sha256": hashlib.sha256(raw_transaction.data).hexdigest(),
                "exit_code": 85,
            }
    return None


async def _transactions_since(
    client: Any, address: Address, baseline: Any, *, max_pages: int = 64
) -> tuple[list[Any], int, bool, Any]:
    """Page backwards until the pre-order cursor is reached, not just one 10-tx page."""
    state = await client.raw_get_account_state(address)
    cursor = state.last_transaction_id
    if cursor is None:
        raise RuntimeError("account has no transaction cursor after stake order")
    latest_cursor = cursor
    transactions: list[Any] = []
    pages = 0
    while pages < max_pages:
        if cursor.lt < baseline.lt:
            raise RuntimeError("transaction cursor crossed the pre-order baseline")
        if cursor.lt == baseline.lt:
            if cursor.hash != baseline.hash:
                raise RuntimeError("pre-order transaction hash changed")
            return transactions, pages, True, latest_cursor
        response = await client.raw_get_transactions(address, cursor)
        pages += 1
        baseline_in_page = False
        for item in response.transactions:
            transaction_id = item.transaction_id
            if transaction_id is not None and transaction_id.lt == baseline.lt:
                if transaction_id.hash != baseline.hash:
                    raise RuntimeError("pre-order transaction hash changed in history page")
                baseline_in_page = True
        transactions.extend(
            item for item in response.transactions
            if item.transaction_id is not None and item.transaction_id.lt > baseline.lt
        )
        if baseline_in_page:
            return transactions, pages, True, latest_cursor
        previous = response.previous_transaction_id
        if previous is None or previous.lt >= cursor.lt:
            raise RuntimeError("transaction history did not advance toward the pre-order cursor")
        if previous.lt < baseline.lt:
            raise RuntimeError("history page crossed the pre-order cursor without its exact transaction")
        cursor = previous
    return transactions, pages, False, latest_cursor


def stakeable_election_id_from_live_status(
    participant_output: str, chain_utime: int, *, minimum_window_seconds: int = 30
) -> int:
    """Require an open Elector window, not merely a nonempty election dictionary.

    `active_election_id` remains nonzero after `elect_close`. Use the Elector's
    own close and finished fields and a fresh lite-server chain timestamp. The
    small remaining-window allowance is for this harness's authorization and
    wallet delivery, not a change to any consensus or election parameter.
    """
    start = re.search(r"^result:\s*\[", participant_output, re.MULTILINE)
    if start is None:
        raise ValueError("participant_list_extended has no parseable election window")
    depth = 1
    end = start.end()
    while end < len(participant_output) and depth:
        if participant_output[end] == "[":
            depth += 1
        elif participant_output[end] == "]":
            depth -= 1
        end += 1
    if depth:
        raise ValueError("participant_list_extended has an unterminated result stack")
    stack = participant_output[start.end():end - 1]
    prefix = re.match(r"\s*(\d+)\s+(\d+)\s+", stack)
    suffix = re.search(r"\s+(-?\d+)\s+(-?\d+)\s*$", stack)
    if prefix is None or suffix is None:
        raise ValueError("participant_list_extended has no parseable election window")
    elect_at, elect_close = map(int, prefix.groups())
    failed, finished = map(int, suffix.groups())
    if elect_at == 0 or failed != 0 or finished != 0:
        return 0
    return elect_at if elect_close - chain_utime > minimum_window_seconds else 0


def recoverable_support_election_ids(
    *, submitted: set[int], recovered: set[int], current_set_id: int,
    current_set_hash: int, known_set_hashes: dict[int, int],
    retired_past: dict[int, dict[str, int]], live_past: dict[int, dict[str, int]],
    chain_utime: int, credit: int,
) -> list[int]:
    """Require a retired set's observed *reset* unfreeze time and actual credit.

    Elector removes a past-election record when it creates the pool credit.
    An absent record alone is not maturity: we must have seen that record
    after the set retired, then see it disappear and see the owner credit.
    """
    eligible: list[int] = []
    for election_id in sorted(submitted - recovered):
        observed = retired_past.get(election_id)
        set_hash = known_set_hashes.get(election_id)
        if (
            election_id == current_set_id or set_hash is None or observed is None
            or observed["vset_hash"] != set_hash or current_set_hash == set_hash
            or election_id in live_past or chain_utime < observed["unfreeze_at"]
        ):
            continue
        eligible.append(election_id)
    return eligible if credit >= len(eligible) * NETWORK_MIN_STAKE else []


def support_keeper_poll_seconds(
    *, chain_utime: int, retired_past: dict[int, dict[str, int]],
    submitted: dict[int, set[int]], recovered: dict[int, set[int]],
) -> int:
    """Poll near an actual retired-set unfreeze before the next window closes.

    This only schedules observation. It does not infer maturity or authorize a
    recovery; recoverable_support_election_ids still checks the live chain.
    """
    for index, elections in submitted.items():
        for election_id in elections - recovered[index]:
            record = retired_past.get(election_id)
            if record is not None and record["unfreeze_at"] - chain_utime <= 60:
                return 5
    return 20


def elector_credit_from_output(output: str) -> int:
    match = re.search(r"result:\s*\[\s*(\d+)", output)
    if match is None:
        raise ValueError(f"cannot parse compute_returned_stake: {output[-800:]}")
    return int(match.group(1))


def support_election_retention_state(
    election_id: int, *, current_set_id: int, known_set_hashes: dict[int, int],
    live_past: dict[int, dict[str, int]], retired_past: dict[int, dict[str, int]],
    chain_utime: int, credit: int,
) -> str:
    set_hash = known_set_hashes.get(election_id)
    if set_hash is None:
        return "set-hash-unobserved"
    if election_id == current_set_id:
        return "active-retained"
    record = live_past.get(election_id)
    if record is not None:
        if record["vset_hash"] != set_hash:
            return "past-hash-mismatch"
        return "retired-frozen" if chain_utime < record["unfreeze_at"] else "retired-awaiting-unfreeze"
    observed = retired_past.get(election_id)
    if observed is None or observed["vset_hash"] != set_hash:
        return "retired-reset-unobserved"
    if chain_utime < observed["unfreeze_at"]:
        return "retired-record-absent-before-unfreeze"
    return "matured-owner-credit" if credit > 0 else "retired-record-absent-no-credit"


def pool_controller_bounce(
    transactions: list[Any], controller: Address, query_id: int
) -> dict[str, Any] | None:
    """Find this order's actual bounced relay, not merely an idle pool state."""
    for raw_transaction in transactions:
        raw_message = raw_transaction.in_msg
        if (
            raw_message is None or raw_message.source is None
            or Address(raw_message.source.account_address) != controller
        ):
            continue
        transaction = _decoded_transaction(raw_transaction)
        message = transaction.in_msg
        if (
            message is not None
            and isinstance(message.info, InternalMsgInfo)
            and message.info.src == controller
            and _relay_query_id(message, bounced=True) == query_id
        ):
            return {"transaction_lt": str(transaction.lt), "bounced": True}
    return None


def controller_relay_result(
    transactions: list[Any], pool: Address, query_id: int
) -> dict[str, Any] | None:
    """Report whether the exact pool relay reached and aborted in its controller."""
    for raw_transaction in transactions:
        raw_message = raw_transaction.in_msg
        if (
            raw_message is None or raw_message.source is None
            or Address(raw_message.source.account_address) != pool
        ):
            continue
        transaction = _decoded_transaction(raw_transaction)
        message = transaction.in_msg
        if (
            message is not None
            and isinstance(message.info, InternalMsgInfo)
            and message.info.src == pool
            and _relay_query_id(message, bounced=False) == query_id
        ):
            return {
                "transaction_lt": str(transaction.lt),
                "aborted": getattr(transaction.description, "aborted", None),
            }
    return None


def validate_campaign_run_id(value: str) -> str:
    """Return an exact, bounded cross-artifact run identifier."""
    if not isinstance(value, str) or not (
        CAMPAIGN_RUN_ID_MIN_LENGTH <= len(value) <= CAMPAIGN_RUN_ID_MAX_LENGTH
    ):
        raise ValueError(
            "campaign run id must be between "
            f"{CAMPAIGN_RUN_ID_MIN_LENGTH} and {CAMPAIGN_RUN_ID_MAX_LENGTH} ASCII characters"
        )
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*[A-Za-z0-9]", value) is None:
        raise ValueError(
            "campaign run id must start and end with an ASCII alphanumeric and "
            "contain only ASCII alphanumerics, '.', '_', ':', or '-'"
        )
    return value


def canonical_raw_address(value: str, *, workchain: int = 0) -> str:
    """Return one lowercase raw address or fail without accepting aliases."""
    pattern = rf"{workchain}:[0-9a-f]{{64}}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"expected a lowercase raw workchain-{workchain} address")
    if value.split(":", 1)[1] == "0" * 64:
        raise ValueError("zero account identifiers are not valid campaign accounts")
    return value


def canonical_network_hash(value: bytes) -> str:
    if len(value) != 32 or value == bytes(32):
        raise ValueError("network hashes must be nonzero 32-byte values")
    return "sha256:" + value.hex()


def read_owner_private_json(path: Path) -> tuple[dict[str, Any], bytes]:
    """Read a bounded owner-private regular JSON file without following links."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError(f"expected an owner-private regular file: {path}")
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError(f"file must be owned by this user and mode 0600: {path}")
        if details.st_size <= 0 or details.st_size > 4 * 1024 * 1024:
            raise ValueError(f"owner-private JSON must be between 1 byte and 4 MiB: {path}")
        chunks: list[bytes] = []
        remaining = details.st_size + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) != details.st_size:
        raise ValueError(f"owner-private JSON changed while being read: {path}")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid owner-private JSON at {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"owner-private JSON root must be an object: {path}")
    return document, raw


def validate_inherited_vault_environment() -> None:
    """Require inherited custody without ever returning or logging its URL."""
    value = os.environ.get("VAULT_URL")
    if not value:
        raise ValueError("integrated mode requires an inherited VAULT_URL")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "file":
        return
    if parsed.netloc not in ("", "localhost"):
        raise ValueError("file VAULT_URL must refer to a local owner-private vault")
    vault_path = Path(urllib.parse.unquote(parsed.path))
    try:
        details = vault_path.lstat()
    except OSError as error:
        raise ValueError("inherited file vault is unavailable") from error
    if (
        vault_path.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise ValueError("inherited file vault must be owned by this user and mode 0600")


def write_owner_private_json(path: Path, value: Any) -> None:
    """Atomically publish machine-consumed JSON with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def integrated_operator_provenance(campaign_run_id: str, endpoint: str, index: int) -> str:
    """Derive a public process-view pin for one same-host local RPC process."""
    campaign_run_id = validate_campaign_run_id(campaign_run_id)
    if index < 0 or index >= INTEGRATED_RPC_COUNT:
        raise ValueError("integrated RPC operator index is out of range")
    digest = hashlib.sha256()
    digest.update(b"tos.openfox.integrated-rpc-operator.v1\0")
    for part in (campaign_run_id.encode(), endpoint.encode(), str(index).encode()):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return "sha256:" + digest.hexdigest()


def integrated_genesis_attempt_binding(campaign_run_id: str, attempt_id: str) -> str:
    """Commit publicly to the private durable attempt scope without disclosing it."""
    campaign_run_id = validate_campaign_run_id(campaign_run_id)
    if re.fullmatch(r"[0-9a-f]{64}", attempt_id) is None:
        raise ValueError("integrated genesis attempt ID must be 32-byte lowercase hex")
    digest = hashlib.sha256()
    digest.update(b"tos.openfox.integrated-genesis-attempt.v1\0")
    for part in (campaign_run_id.encode(), attempt_id.encode()):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return "sha256:" + digest.hexdigest()


def integrated_network_global_id(campaign_run_id: str, attempt_id: str) -> int:
    """Derive a per-genesis positive int32 domain, disjoint from legacy local ID 3."""
    campaign_run_id = validate_campaign_run_id(campaign_run_id)
    binding = integrated_genesis_attempt_binding(campaign_run_id, attempt_id)
    digest = hashlib.sha256()
    digest.update(b"tos.openfox.integrated-network-global-id.v2\0")
    for part in (campaign_run_id.encode(), binding.encode()):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    value = digest.digest()
    # The high positive int32 quadrant is test-only and cannot produce 0 or 3.
    return 0x4000_0000 | (int.from_bytes(value[:4], "big") & 0x3FFF_FFFF)


@dataclass
class EvidenceAttempt:
    marker_path: Path
    marker_raw: bytes
    attempt_id: str
    lock_path: Path
    lock_descriptor: int


def evidence_attempt_marker_path(evidence_out: Path) -> Path:
    """Return the fail-closed marker paired with one stable evidence path."""
    return evidence_out.with_name(f".{evidence_out.name}.in-progress")


def evidence_attempt_lock_path(evidence_out: Path) -> Path:
    """Return the persistent producer/consumer lock paired with evidence."""
    return evidence_out.with_name(f".{evidence_out.name}.lock")


def fsync_directory(path: Path) -> None:
    """Persist directory-entry changes before they become release evidence."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def begin_evidence_attempt(evidence_out: Path, campaign_run_id: str) -> EvidenceAttempt:
    """Durably invalidate any older stable evidence before a new attempt runs."""
    campaign_run_id = validate_campaign_run_id(campaign_run_id)
    evidence_out.parent.mkdir(parents=True, exist_ok=True)
    marker_path = evidence_attempt_marker_path(evidence_out)
    lock_path = evidence_attempt_lock_path(evidence_out)
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    try:
        details = os.fstat(lock_descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise RuntimeError(f"expected a regular evidence attempt lock: {lock_path}")
        os.fchmod(lock_descriptor, 0o600)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(lock_descriptor)
        raise RuntimeError(f"evidence attempt lock is already held: {lock_path}") from error
    except Exception:
        os.close(lock_descriptor)
        raise
    attempt_id = secrets.token_hex(32)
    marker_raw = (
        json.dumps(
            {
                "schema": EVIDENCE_ATTEMPT_MARKER_SCHEMA,
                "campaign_run_id": campaign_run_id,
                "attempt_id": attempt_id,
                "started_at": utc_now(),
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(marker_path, flags, 0o600)
    except FileExistsError as error:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
        raise RuntimeError(
            f"unresolved evidence attempt marker already exists: {marker_path}"
        ) from error
    except Exception:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
        raise
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as marker:
            marker.write(marker_raw)
            marker.flush()
            os.fsync(marker.fileno())
    except Exception:
        marker_path.unlink(missing_ok=True)
        fsync_directory(evidence_out.parent)
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
        raise
    fsync_directory(evidence_out.parent)
    return EvidenceAttempt(
        marker_path=marker_path,
        marker_raw=marker_raw,
        attempt_id=attempt_id,
        lock_path=lock_path,
        lock_descriptor=lock_descriptor,
    )


def release_evidence_attempt_lock(attempt: EvidenceAttempt) -> None:
    """Release one live attempt lock without resolving its durable marker."""
    if attempt.lock_descriptor < 0:
        return
    descriptor = attempt.lock_descriptor
    attempt.lock_descriptor = -1
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def read_regular_file(path: Path) -> bytes:
    """Read a regular file without following a replacement symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise RuntimeError(f"expected a regular file: {path}")
    except Exception:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "rb", closefd=True) as source:
        return source.read()


def finalize_evidence_attempt(evidence_out: Path, attempt: EvidenceAttempt, encoded: str) -> None:
    """Publish one durable result, then durably clear its exact attempt marker."""
    expected_marker = evidence_attempt_marker_path(evidence_out)
    expected_lock = evidence_attempt_lock_path(evidence_out)
    if attempt.marker_path != expected_marker or attempt.lock_path != expected_lock:
        raise RuntimeError("evidence attempt marker does not match its stable evidence path")
    if attempt.lock_descriptor < 0:
        raise RuntimeError("evidence attempt lock was released before finalization")
    if read_regular_file(attempt.marker_path) != attempt.marker_raw:
        raise RuntimeError("evidence attempt marker changed before finalization")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=evidence_out.parent,
        prefix=f".{evidence_out.name}.{attempt.attempt_id}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        if read_regular_file(attempt.marker_path) != attempt.marker_raw:
            raise RuntimeError("evidence attempt marker changed while publishing evidence")
        os.replace(temporary, evidence_out)
        fsync_directory(evidence_out.parent)
        attempt.marker_path.unlink()
        fsync_directory(evidence_out.parent)
        release_evidence_attempt_lock(attempt)
    finally:
        temporary.unlink(missing_ok=True)


def election_reward_distribution(
    returned_credit: int,
    stake_amount_sent: int,
    validator_reward_share_bps: int,
    active_principal: dict[int, int],
) -> tuple[int, int, int, dict[int, int]]:
    """Compute the election-only lower bound separate from keeper residual."""
    if returned_credit < 0 or stake_amount_sent < 0:
        raise ValueError("stake and returned credit must not be negative")
    if validator_reward_share_bps < 0 or validator_reward_share_bps > 10_000:
        raise ValueError("validator reward share must be valid basis points")
    if any(index < 0 or amount < 0 for index, amount in active_principal.items()):
        raise ValueError("active principal map is invalid")
    gross_reward = returned_credit - stake_amount_sent
    positive_reward = max(0, gross_reward)
    validator_reward = positive_reward * validator_reward_share_bps // 10_000
    nominator_reward = positive_reward - validator_reward
    total_active = sum(active_principal.values())
    floors = {
        index: nominator_reward * amount // total_active if total_active > 0 else 0
        for index, amount in active_principal.items()
    }
    return gross_reward, validator_reward, nominator_reward, floors


def internal_message(
    src: Address,
    dest: Address,
    amount: int,
    body: Cell,
    *,
    init: StateInit | None = None,
) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=False,
                bounced=False,
                src=src,
                dest=dest,
                value=CurrencyCollection(tomis=amount),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=init,
            body=body,
        ),
    )


def text_command(command: str) -> Cell:
    """A nominator's whole interface: a plain transfer with a comment.

    pool.fc reads op 0 followed by one ASCII byte, which is what lets a
    depositor act from any wallet that can attach a comment.
    """
    builder = Builder().store_uint(0, 32)
    for char in command:
        builder.store_uint(ord(char), 8)
    return builder.end_cell()


def pool_message(opcode: int, query_id: int, *, extra: Cell | None = None) -> Cell:
    builder = Builder().store_uint(opcode, 32).store_uint(query_id, 64)
    if extra is not None:
        builder.store_slice(extra.begin_parse())
    return builder.end_cell()


def store_coins(builder: Builder, amount: int) -> Builder:
    length = (amount.bit_length() + 7) // 8
    builder.store_uint(length, 4)
    if length:
        builder.store_uint(amount, length * 8)
    return builder


def build_pool_state_init(
    code: Cell,
    *,
    validator_account: bytes,
    controller_account: bytes,
    reward_share_bps: int,
    max_nominators: int,
    min_validator_stake: int,
    min_nominator_stake: int,
) -> StateInit:
    """The initial storage pool.fc's save_data expects, in its exact order."""
    # Two accounts where there was one: the validator commands the pool, the controller
    # stands in the election with its money.
    config = (
        Builder()
        .store_bytes(validator_account)
        .store_bytes(controller_account)
        .store_uint(reward_share_bps, 16)
        .store_uint(max_nominators, 16)
    )
    store_coins(config, min_validator_stake)
    store_coins(config, min_nominator_stake)

    data = Builder().store_uint(0, 8).store_uint(0, 16)
    store_coins(data, 0)  # stake_amount_sent
    store_coins(data, 0)  # validator_amount
    data.store_ref(config.end_cell())
    data.store_bit(0)  # nominators
    data.store_bit(0)  # withdraw_requests
    data.store_uint(0, 32)  # stake_at
    data.store_uint(0, 256)  # saved_validator_set_hash
    data.store_uint(0, 8)  # validator_set_changes_count
    data.store_uint(0, 32)  # validator_set_change_time
    data.store_uint(0, 32)  # stake_held_for
    data.store_bit(0)  # config_proposal_votings
    return StateInit(code=code, data=data.end_cell())


@dataclass
class PoolData:
    state: int
    nominators_count: int
    stake_amount_sent: int
    validator_amount: int
    stake_at: int
    validator_set_changes_count: int

    @property
    def state_name(self) -> str:
        return {0: "idle", 1: "sent", 2: "staked"}.get(self.state, "unknown")


@dataclass
class Config34Selection:
    utime_since: int
    utime_until: int
    total: int
    main: int
    total_weight: int
    validator_adnl_pairs: list[tuple[str, str]]
    weights: list[int]


def require_lifecycle_funding_budget(*, integrated: bool, agent_count: int) -> dict[str, int]:
    """Refuse a fixture whose known Genesis transfers or pool principals cannot fit."""
    if agent_count != OPENFOX_AGENT_COUNT:
        raise ValueError(f"lifecycle needs {OPENFOX_AGENT_COUNT} agent nominators")
    faucet = (
        INTEGRATED_FAUCET_FUNDING
        if integrated else VALIDATOR_ECONOMICS_FAUCET_TOS * NANO
    )
    primary_wallet = INTEGRATED_POOL_VALIDATOR_FUNDING if integrated else POOL_VALIDATOR_FUNDING
    support_wallet = INTEGRATED_DIRECT_VALIDATOR_FUNDING if integrated else DIRECT_VALIDATOR_FUNDING
    nominators = (
        agent_count * INTEGRATED_OWNER_FUNDING
        + CONTROL_NOMINATOR_COUNT * (INTEGRATED_NOMINATOR_DEPOSIT + 2 * NANO)
        if integrated else (agent_count + CONTROL_NOMINATOR_COUNT) * NOMINATOR_FUNDING
    )
    controller_deployments = 5 * 10 * NANO
    committed = (
        primary_wallet + 4 * support_wallet + nominators
        + RESCUER_FUNDING + controller_deployments
    )
    faucet_fee_reserve = 100 * NANO
    if committed + faucet_fee_reserve > faucet:
        raise ValueError(
            "Genesis faucet cannot fund the lifecycle fixture: "
            f"committed={committed} reserve={faucet_fee_reserve} faucet={faucet}"
        )
    support_need = 10 * NANO + SUPPORT_POOL_CAPITAL + 2 * POOL_STAKE_GAS
    if support_wallet < support_need:
        raise ValueError(
            "support wallet cannot fund deployment plus two pool stakes: "
            f"required={support_need} funded={support_wallet}"
        )
    primary_own_deposit = (
        INTEGRATED_VALIDATOR_OWN_DEPOSIT if integrated else VALIDATOR_OWN_DEPOSIT
    )
    primary_need = POOL_DEPLOY_VALUE + primary_own_deposit + 2 * POOL_STAKE_GAS
    if primary_wallet < primary_need:
        raise ValueError(
            "primary validator wallet cannot fund deployment, own deposit and stake gas: "
            f"required={primary_need} funded={primary_wallet}"
        )
    return {
        "faucet_nanotos": faucet,
        "committed_nanotos": committed,
        "faucet_uncommitted_nanotos": faucet - committed,
        "support_wallet_nanotos": support_wallet,
        "support_wallet_required_nanotos": support_need,
        "primary_wallet_nanotos": primary_wallet,
        "primary_wallet_required_nanotos": primary_need,
        "support_pool_capital_nanotos": SUPPORT_POOL_CAPITAL,
    }


def parse_pq_validator_adnl_pairs(output: str) -> list[tuple[str, str]]:
    """Keep each PQ controller ID paired with the ADNL in its own Config34 record."""
    markers = list(re.finditer(r"\bvalidator_pq\b", output))
    identities = list(re.finditer(
        r"\bvalidator_pq\s+validator_id:x([0-9A-Fa-f]{64})", output
    ))
    if len(markers) != len(identities):
        raise ValueError("ConfigParam 34 has a PQ record without a validator ID")
    pairs: list[tuple[str, str]] = []
    for index, identity in enumerate(identities):
        end = identities[index + 1].start() if index + 1 < len(identities) else len(output)
        adnl = re.findall(r"\badnl_addr:x([0-9A-Fa-f]{64})", output[identity.end():end])
        if len(adnl) != 1:
            raise ValueError(
                f"ConfigParam 34 PQ validator {identity.group(1)} has {len(adnl)} ADNL IDs"
            )
        pairs.append((identity.group(1).lower(), adnl[0].lower()))
    if len(set(pairs)) != len(pairs) or len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("ConfigParam 34 repeats a PQ validator ID")
    if len({adnl for _, adnl in pairs}) != len(pairs):
        raise ValueError("ConfigParam 34 repeats a PQ validator ADNL ID")
    return pairs


@dataclass
class AgentBinding:
    name: str
    agent_id: str
    campaign_wallet_label: str = ""
    campaign_account_address: str = ""


@dataclass(frozen=True)
class IntegratedAgentProfile:
    binding: AgentBinding
    profile_name: str
    owner_wallet_alias: str
    deployment_id: str
    state_identity: dict[str, Any] | None = None


@dataclass(frozen=True)
class IntegratedWorkingConfig:
    path: Path
    rpc_address: str
    rpc_url: str
    operator_provenance: str


@dataclass
class Nominator:
    index: int
    wallet: WalletV1 | None
    key: Key | None
    agent: AgentBinding | None = None
    address: Address | None = None
    agent_profile_name: str = ""
    tosctl_config: Path | None = None
    deployment_id: str = ""
    state_identity: dict[str, Any] | None = None
    deposited: int = 0
    deposit_message_value: int = NOMINATOR_DEPOSIT
    funded_balance: int = 0
    wallet_balance_before_deposit: int = 0
    wallet_balance_after_deposit: int = 0
    principal_before_recovery: int | None = None
    principal_after_recovery: int | None = None
    payout_entitlement: int | None = None
    payout_wallet_before: int | None = None
    payout_wallet_after: int | None = None

    @property
    def reward(self) -> int | None:
        if self.principal_before_recovery is None or self.principal_after_recovery is None:
            return None
        return self.principal_after_recovery - self.principal_before_recovery

    @property
    def delegation_address(self) -> Address:
        if self.address is not None:
            return self.address
        if self.wallet is None:
            raise RuntimeError("nominator has neither a wallet nor an explicit address")
        return self.wallet.address


def valid_nominator_funding_observation(nominator: Nominator) -> bool:
    """Return true only for an exact, spendable pre-deposit balance trail."""
    return (
        nominator.funded_balance > nominator.deposit_message_value
        and nominator.wallet_balance_before_deposit == nominator.funded_balance
        and 0 < nominator.wallet_balance_after_deposit < nominator.wallet_balance_before_deposit
        and nominator.wallet_balance_before_deposit - nominator.wallet_balance_after_deposit
        >= nominator.deposit_message_value
    )


DEFAULT_AGENT_BINDINGS = [
    AgentBinding("security-auditor", "agent:openfox:security-auditor"),
    AgentBinding("software-builder", "agent:openfox:software-builder"),
    AgentBinding("evidence-verifier", "agent:openfox:evidence-verifier"),
    AgentBinding("storage-provider", "agent:openfox:storage-provider"),
    AgentBinding("data-curator", "agent:openfox:data-curator"),
    AgentBinding("localization-writer", "agent:openfox:localization-writer"),
    AgentBinding("transaction-operator", "agent:openfox:transaction-operator"),
    AgentBinding("guarantor-analyst", "agent:openfox:guarantor-analyst"),
]


def load_agent_bindings(path: Path | None) -> tuple[list[AgentBinding], str]:
    """Load the eight public Agent identities used by the companion campaign.

    The lifecycle deliberately creates fresh wallets on its accelerated sidecar
    genesis.  The manifest binds those test-only wallets to the same logical
    Agents without importing campaign custody secrets or pretending the two
    networks share balances.
    """
    if path is None:
        canonical = json.dumps(
            [binding.__dict__ for binding in DEFAULT_AGENT_BINDINGS],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return list(DEFAULT_AGENT_BINDINGS), "sha256:" + hashlib.sha256(canonical).hexdigest()

    raw = path.read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("agent manifest exceeds 4 MiB")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid agent manifest JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("agents"), list):
        raise ValueError("agent manifest must contain an agents array")
    if document.get("schema") != "tos.openfox.eight-agent-market-campaign.v1":
        raise ValueError("agent manifest schema is not the eight-Agent campaign schema")
    if len(document["agents"]) != OPENFOX_AGENT_COUNT:
        raise ValueError(f"agent manifest must contain exactly {OPENFOX_AGENT_COUNT} agents")

    bindings: list[AgentBinding] = []
    for index, entry in enumerate(document["agents"]):
        if not isinstance(entry, dict):
            raise ValueError(f"agent manifest entry {index} must be an object")
        name = entry.get("name")
        agent_id = entry.get("agent_id")
        wallet = entry.get("wallet", "")
        target = entry.get("target", "")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"agent manifest entry {index} has no name")
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError(f"agent manifest entry {index} has no agent_id")
        if not isinstance(wallet, str):
            raise ValueError(f"agent manifest entry {index} wallet must be a string")
        if not isinstance(target, str) or re.fullmatch(r"0:[0-9a-fA-F]{64}", target) is None:
            raise ValueError(
                f"agent manifest entry {index} target must be a raw basechain account address"
            )
        bindings.append(
            AgentBinding(
                name.strip(),
                agent_id.strip(),
                wallet.strip(),
                target.lower(),
            )
        )
    if len({binding.name for binding in bindings}) != len(bindings):
        raise ValueError("agent manifest names must be unique")
    if len({binding.agent_id for binding in bindings}) != len(bindings):
        raise ValueError("agent manifest agent_id values must be unique")
    if len({binding.campaign_wallet_label for binding in bindings}) != len(bindings):
        raise ValueError("agent manifest wallet profile names must be unique")
    if len({binding.campaign_account_address for binding in bindings}) != len(bindings):
        raise ValueError("agent manifest target account addresses must be unique")
    return bindings, "sha256:" + hashlib.sha256(raw).hexdigest()


def prepare_integrated_working_configs(
    source: dict[str, Any],
    bindings: list[AgentBinding],
    destination: Path,
    rpc_addresses: list[str],
    campaign_run_id: str,
) -> tuple[list[IntegratedAgentProfile], list[IntegratedWorkingConfig]]:
    """Clone public profiles while retaining vault references, never key bytes."""
    campaign_run_id = validate_campaign_run_id(campaign_run_id)
    if len(bindings) != OPENFOX_AGENT_COUNT:
        raise ValueError(f"integrated mode requires exactly {OPENFOX_AGENT_COUNT} Agents")
    if len(rpc_addresses) != INTEGRATED_RPC_COUNT or len(set(rpc_addresses)) != len(rpc_addresses):
        raise ValueError(f"integrated mode requires {INTEGRATED_RPC_COUNT} distinct RPC addresses")
    source_profiles = source.get("agent_wallets")
    if not isinstance(source_profiles, dict):
        raise ValueError("source tosctl config has no agent_wallets object")

    profiles: list[IntegratedAgentProfile] = []
    selected: dict[str, dict[str, Any]] = {}
    owner_wallets: dict[str, dict[str, Any]] = {}
    for index, binding in enumerate(bindings):
        profile_name = binding.campaign_wallet_label
        if not profile_name or profile_name not in source_profiles:
            raise ValueError(
                f"source tosctl config has no campaign Agent Wallet profile {profile_name!r}"
            )
        raw_profile = source_profiles[profile_name]
        if not isinstance(raw_profile, dict):
            raise ValueError(f"Agent Wallet profile {profile_name!r} is not an object")
        profile = copy.deepcopy(raw_profile)
        source_address = profile.get("agent_account_address")
        target = canonical_raw_address(binding.campaign_account_address)
        if source_address != target:
            raise ValueError(
                f"Agent Wallet profile {profile_name!r} is not the manifest campaign account"
            )
        deployment_id = profile.get("agent_account_deployment_id")
        if (
            not isinstance(deployment_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", deployment_id) is None
            or deployment_id == "0" * 64
        ):
            raise ValueError(f"Agent Wallet profile {profile_name!r} has no fixed deployment ID")
        owner_wallet = profile.get("wallet")
        controller_key = profile.get("controller_key")
        if (
            not isinstance(owner_wallet, dict)
            or not isinstance(owner_wallet.get("key"), dict)
            or set(owner_wallet["key"]) != {"name"}
            or not isinstance(owner_wallet["key"].get("name"), str)
            or not owner_wallet["key"]["name"]
            or owner_wallet.get("workchain") != 0
            or not isinstance(controller_key, dict)
            or set(controller_key) != {"name"}
            or not isinstance(controller_key.get("name"), str)
            or not controller_key["name"]
        ):
            raise ValueError(f"Agent Wallet profile {profile_name!r} has invalid vault references")
        policy = profile.get("policy")
        if (
            not isinstance(policy, dict)
            or not isinstance(policy.get("max_per_tx"), int)
            or policy["max_per_tx"] < INTEGRATED_NOMINATOR_DEPOSIT
            or not isinstance(policy.get("daily_limit"), int)
            or policy["daily_limit"] < INTEGRATED_NOMINATOR_DEPOSIT + NANO
            or not isinstance(policy.get("default_task_timeout_secs"), int)
            or policy["default_task_timeout_secs"] < 300
        ):
            raise ValueError(
                f"Agent Wallet profile {profile_name!r} cannot authorize the bounded d/w test"
            )
        profile["agent_account_address"] = None
        selected[profile_name] = profile
        owner_alias = f"integrated-owner-{index + 1:02d}"
        owner_wallets[owner_alias] = copy.deepcopy(owner_wallet)
        profiles.append(
            IntegratedAgentProfile(
                binding=binding,
                profile_name=profile_name,
                owner_wallet_alias=owner_alias,
                deployment_id=deployment_id,
            )
        )

    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    configs: list[IntegratedWorkingConfig] = []
    for index, rpc_address in enumerate(rpc_addresses):
        operator_directory = destination / f"operator-{index + 1:02d}"
        operator_directory.mkdir(mode=0o700)
        document = copy.deepcopy(source)
        document["wallets"] = copy.deepcopy(owner_wallets)
        document["agent_wallets"] = copy.deepcopy(selected)
        for profile_name, profile in document["agent_wallets"].items():
            runtime = profile.get("runtime")
            if isinstance(runtime, dict):
                custody = operator_directory / "economic-custody" / profile_name
                custody.mkdir(parents=True, exist_ok=True, mode=0o700)
                custody.chmod(0o700)
                runtime["economic_custody_journal_directory"] = str(custody)
        for key in ("agent_tasks", "pools", "bindings"):
            if key in document:
                document[key] = {}
        rpc_url = f"http://{rpc_address}/jsonRPC"
        provenance = integrated_operator_provenance(campaign_run_id, rpc_url, index)
        document["chain_rpc"] = {
            "urls": [rpc_url],
            "api_key": None,
            "operator_provenance": provenance,
        }
        path = operator_directory / "tosctl-config.json"
        write_owner_private_json(path, document)
        configs.append(
            IntegratedWorkingConfig(
                path=path,
                rpc_address=rpc_address,
                rpc_url=rpc_url,
                operator_provenance=provenance,
            )
        )
    return profiles, configs


def json_rpc_call(
    address: str, method: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    ).encode()
    request = urllib.request.Request(
        f"http://{address}/jsonRPC",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        document = json.loads(response.read().decode())
    if not isinstance(document, dict) or document.get("error") is not None:
        raise RuntimeError(f"JSON-RPC {address} {method} failed")
    if document.get("result") is None:
        raise RuntimeError(f"JSON-RPC {address} {method} returned no result")
    return document


def canonical_agent_state_identity(state: dict[str, Any]) -> dict[str, Any]:
    """Reduce build-state JSON to the public fields that determine StateInit."""

    def hex32(name: str, *, optional: bool = False) -> str | None:
        value = state.get(name)
        if optional and value is None:
            return None
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"Agent Account build-state {name} is not canonical")
        return value

    try:
        address = raw_address(Address(state["address"]))
        owner = raw_address(Address(state["owner"]))
        workchain = state["workchain"]
        state_boc = base64.b64decode(state["state_init_boc"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Agent Account build-state identity is malformed") from error
    if workchain != INTEGRATED_WORKCHAIN_ID or not state_boc:
        raise ValueError("Agent Account build-state is outside the integrated basechain")
    policy: dict[str, int] = {}
    for name in ("max_per_tx", "daily_limit", "default_task_timeout_secs"):
        value = state.get(name)
        if not isinstance(value, int) or value <= 0:
            raise ValueError(f"Agent Account build-state {name} must be positive")
        policy[name] = value
    return {
        "address": canonical_raw_address(address),
        "workchain_id": workchain,
        "owner": canonical_raw_address(owner),
        "controller_pubkey": hex32("controller_pubkey"),
        "deployment_id": hex32("deployment_id"),
        "policy": policy,
        "metadata_hash": hex32("metadata_hash", optional=True),
        "service_endpoint_hash": hex32("service_endpoint_hash", optional=True),
        "code_hash": hex32("code_hash"),
        "data_hash": hex32("data_hash"),
        "state_init_boc_digest": "sha256:" + hashlib.sha256(state_boc).hexdigest(),
    }


def integrated_action_id(
    campaign_run_id: str,
    network_domain: dict[str, Any],
    deployment_id: str,
    agent_id: str,
    pool_address: str,
    action: str,
    amount_nanotos: int,
    body_hash: str,
) -> str:
    """Bind a controller journal action to the complete experiment domain."""
    campaign_run_id = validate_campaign_run_id(campaign_run_id)
    if action not in ("deposit", "withdraw"):
        raise ValueError("integrated pool action must be deposit or withdraw")
    expected_keys = {
        "network_id",
        "global_id",
        "workchain_id",
        "zero_state_root_hash",
        "zero_state_file_hash",
    }
    if set(network_domain) != expected_keys:
        raise ValueError("integrated action network domain is incomplete or ambiguous")
    if (
        network_domain.get("network_id") != INTEGRATED_NETWORK_ID
        or not isinstance(network_domain.get("global_id"), int)
        or network_domain.get("global_id") in (0, LEGACY_LOCAL_GLOBAL_ID)
        or network_domain.get("workchain_id") != INTEGRATED_WORKCHAIN_ID
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(network_domain.get("zero_state_root_hash")))
        is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(network_domain.get("zero_state_file_hash")))
        is None
    ):
        raise ValueError("integrated action network domain is not canonical")
    if re.fullmatch(r"[0-9a-f]{64}", deployment_id) is None:
        raise ValueError("integrated action deployment ID is not canonical")
    canonical_raw_address(pool_address, workchain=-1)
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("integrated action Agent ID is empty")
    if not isinstance(amount_nanotos, int) or amount_nanotos <= 0:
        raise ValueError("integrated action amount must be positive")
    if re.fullmatch(r"tvm-cell-sha256:[0-9a-f]{64}", body_hash) is None:
        raise ValueError("integrated action body hash is not canonical")
    digest = hashlib.sha256()
    digest.update(b"tos.openfox.integrated-pool-action.v1\0")
    domain = json.dumps(network_domain, sort_keys=True, separators=(",", ":"))
    for part in (
        campaign_run_id,
        domain,
        deployment_id,
        agent_id,
        pool_address,
        action,
        str(amount_nanotos),
        body_hash,
    ):
        encoded = part.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def read_controller_action_record(config_path: Path, action_id: str) -> dict[str, Any]:
    """Read the exact private custody record selected by one stable action ID."""
    journal_path = (
        config_path.parent / ".tosctl-agent-controller-journal" / "controller-actions.json"
    )
    document, _ = read_owner_private_json(journal_path)
    if document.get("schema") != "tos.agent-account.controller-journal.v2":
        raise RuntimeError("controller custody journal schema mismatch")
    records = document.get("records")
    if not isinstance(records, list):
        raise RuntimeError("controller custody journal has no records")
    selected = [
        record
        for record in records
        if isinstance(record, dict) and record.get("idempotency_key") == action_id
    ]
    if len(selected) != 1:
        raise RuntimeError("controller custody journal action is missing or ambiguous")
    # The BOC itself remains in owner-private custody; public evidence retains
    # only its digest and the exact signed claim fields.
    record = copy.deepcopy(selected[0])
    record.pop("exact_signed_boc_base64", None)
    return record


def normalize_rpc_transactions(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = response.get("result")
    if isinstance(result, dict):
        result = result.get("transactions")
    if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
        raise RuntimeError("getTransactions result is malformed")
    return result


def canonical_rpc_block_id(block_id: Any) -> dict[str, Any]:
    if not isinstance(block_id, dict):
        raise RuntimeError("finalized transaction omitted its block checkpoint")
    try:
        root = base64.b64decode(block_id["root_hash"], validate=True)
        file_hash = base64.b64decode(block_id["file_hash"], validate=True)
        workchain = int(block_id["workchain"])
        shard = str(block_id["shard"])
        seqno = int(block_id["seqno"])
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("finalized transaction block checkpoint is malformed") from error
    return {
        "workchain": workchain,
        "shard": shard,
        "seqno": seqno,
        "root_hash": canonical_network_hash(root),
        "file_hash": canonical_network_hash(file_hash),
    }


def match_agent_pool_transaction(
    entry: dict[str, Any], sender: Address, target: Address, amount: int, body_hash: str
) -> dict[str, Any] | None:
    """Return finalized transaction binding when its exact pool message matches."""
    encoded = entry.get("data")
    if not isinstance(encoded, str) or not encoded:
        return None
    try:
        boc = base64.b64decode(encoded, validate=True)
        transaction_cell = Cell.one_from_boc(boc)
        transaction = Transaction.deserialize(transaction_cell.begin_parse())
    except (TypeError, ValueError, TlbError, BocError, IndexError):
        return None
    if transaction.account_addr != sender.hash_part or getattr(
        transaction.description, "aborted", True
    ):
        return None
    matching = [
        (message, message.cell)
        for message in transaction.out_msgs
        if isinstance(message.info, InternalMsgInfo)
        and message.cell is not None
        and message.info.src == sender
        and message.info.dest == target
        and message.info.value.tomis == amount
        and "tvm-cell-sha256:" + message.body.hash.hex() == body_hash
    ]
    if len(matching) != 1:
        return None
    message, message_cell = matching[0]
    assert message_cell is not None
    tx_id = entry.get("transaction_id")
    rpc_hash = tx_id.get("hash") if isinstance(tx_id, dict) else entry.get("hash")
    rpc_lt = tx_id.get("lt") if isinstance(tx_id, dict) else entry.get("lt")
    return {
        "account": raw_address(sender),
        "transaction_lt": str(rpc_lt if rpc_lt is not None else transaction.lt),
        "transaction_cell_hash": "tvm-cell-sha256:" + transaction_cell.hash.hex(),
        "rpc_transaction_hash": rpc_hash,
        "transaction_boc_digest": "sha256:" + hashlib.sha256(boc).hexdigest(),
        "out_message_cell_hash": "tvm-cell-sha256:" + message_cell.hash.hex(),
        "source": raw_address(message.info.src),
        "target": raw_address(message.info.dest),
        "value_nanotos": message.info.value.tomis,
        "body_hash": "tvm-cell-sha256:" + message.body.hash.hex(),
        "block_checkpoint": canonical_rpc_block_id(entry.get("block_id")),
    }


def task_send_resolution_mismatches(
    resolution: Any,
    *,
    expected_wallet: str,
    expected_action_id: str,
    expected_source_account: str,
    expected_deployment_id: str,
    expected_destination: str,
    expected_amount_nanotos: int,
    expected_body_hash: str,
    expected_network_domain: dict[str, Any],
    finalized_transaction: dict[str, Any],
) -> list[str]:
    """Name every failed binding without including custody or transaction values.

    The independent Python observer decodes enough of the transaction to prove
    the unique target/value/body effect.  It must not reserialize that decoded
    message and call the result its on-chain cell hash: Agent Account task-send
    deliberately stores even a small body by reference.  ``MessageAny`` retains
    the original parsed cell so this function can bind that representation-level
    hash, while the raw transaction hash and BOC digest independently commit to
    the same outbound dictionary.
    """
    mismatches: list[str] = []

    def check(field: str, condition: bool) -> None:
        if not condition:
            mismatches.append(field)

    def plain_int(value: Any) -> bool:
        return type(value) is int

    def digest(value: Any, prefix: str) -> bool:
        return (
            isinstance(value, str)
            and re.fullmatch(rf"{re.escape(prefix)}[0-9a-f]{{64}}", value) is not None
        )

    if not isinstance(resolution, dict):
        return ["resolution"]

    check("schema", resolution.get("schema") == TASK_SEND_FINALIZED_SCHEMA)
    check("wallet", resolution.get("wallet") == expected_wallet)
    check("action_id", resolution.get("action_id") == expected_action_id)
    check("source_account", resolution.get("source_account") == expected_source_account)
    check("deployment_id", resolution.get("deployment_id") == expected_deployment_id)
    check("destination", resolution.get("destination") == expected_destination)
    check("amount_nanotos", resolution.get("amount_nanotos") == expected_amount_nanotos)
    check("body_hash", resolution.get("body_hash") == expected_body_hash)
    check(
        "exact_signed_boc_digest",
        digest(resolution.get("exact_signed_boc_digest"), "sha256:"),
    )
    check(
        "submitted_message_cell_hash",
        digest(resolution.get("submitted_message_cell_hash"), "tvm-cell-sha256:"),
    )
    check("network_domain", resolution.get("network_domain") == expected_network_domain)
    check("state", resolution.get("state") == "resolved")
    check(
        "process_view_scope",
        resolution.get("process_view_scope") == TASK_SEND_PROCESS_VIEW_SCOPE,
    )
    check(
        "block_reference_scope",
        resolution.get("block_reference_scope") == TASK_SEND_BLOCK_REFERENCE_SCOPE,
    )
    check(
        "independent_operator_domains_proven",
        resolution.get("independent_operator_domains_proven") is False,
    )

    controller_epoch = resolution.get("controller_epoch")
    seqno = resolution.get("seqno")
    finalized_controller_epoch = resolution.get("finalized_controller_epoch")
    finalized_seqno = resolution.get("finalized_seqno")
    claim_state_typed = plain_int(controller_epoch) and plain_int(seqno)
    finalized_state_typed = plain_int(finalized_controller_epoch) and plain_int(finalized_seqno)
    check("controller_state.claim_tuple", claim_state_typed)
    check("controller_state.finalized_tuple", finalized_state_typed)
    check(
        "controller_state.advanced",
        claim_state_typed
        and finalized_state_typed
        and (finalized_controller_epoch, finalized_seqno) > (controller_epoch, seqno),
    )

    transaction = resolution.get("transaction")
    observations = resolution.get("observations")
    quorum = resolution.get("quorum")
    transaction_is_object = isinstance(transaction, dict)
    observations_are_array = isinstance(observations, list) and all(
        isinstance(item, dict) for item in observations
    )
    check("transaction", transaction_is_object)
    check("observations", observations_are_array)
    check("quorum", isinstance(quorum, dict))

    if isinstance(quorum, dict):
        check("quorum.members", quorum.get("members") == INTEGRATED_RPC_COUNT)
        check("quorum.threshold", quorum.get("threshold") == 2)
        check("quorum.agreeing", plain_int(quorum.get("agreeing")))
    if observations_are_array:
        assert isinstance(observations, list)
        check("observations.strict_majority", 2 <= len(observations) <= INTEGRATED_RPC_COUNT)
        check(
            "quorum.agreeing_count",
            isinstance(quorum, dict) and quorum.get("agreeing") == len(observations),
        )
        check(
            "observations.distinct_endpoints",
            all(isinstance(item.get("endpoint"), str) and item["endpoint"] for item in observations)
            and len({item["endpoint"] for item in observations}) == len(observations),
        )
        check(
            "observations.distinct_locators",
            all(digest(item.get("locator_identity_digest"), "sha256:") for item in observations)
            and len({item["locator_identity_digest"] for item in observations})
            == len(observations),
        )
        check(
            "observations.selected_transaction_member",
            transaction_is_object and transaction in observations,
        )
        common_observation_fields = (
            "transaction_hash",
            "transaction_lt",
            "transaction_utime",
            "transaction_boc_digest",
            "outbound_message_cell_hash",
            "outbound_body_hash",
            "block_workchain",
            "block_shard",
            "block_seqno",
            "block_root_hash",
            "block_file_hash",
            "finalized_controller_epoch",
            "finalized_seqno",
        )
        check(
            "observations.common_exact_tuple",
            transaction_is_object
            and all(
                item.get(field) == transaction.get(field)
                for item in observations
                for field in common_observation_fields
            ),
        )
        check(
            "observations.masterchain_checkpoints",
            all(
                plain_int(item.get("observed_masterchain_seqno"))
                and item["observed_masterchain_seqno"] >= 0
                for item in observations
            ),
        )

    if transaction_is_object:
        assert isinstance(transaction, dict)
        check(
            "transaction.transaction_hash",
            digest(transaction.get("transaction_hash"), "sha256:"),
        )
        check(
            "transaction.transaction_boc_digest",
            digest(transaction.get("transaction_boc_digest"), "sha256:"),
        )
        check(
            "transaction.outbound_message_cell_hash",
            digest(transaction.get("outbound_message_cell_hash"), "tvm-cell-sha256:"),
        )
        check(
            "transaction.outbound_body_hash",
            transaction.get("outbound_body_hash") == expected_body_hash,
        )
        check(
            "transaction.scalar_types",
            all(
                plain_int(transaction.get(field))
                for field in (
                    "transaction_lt",
                    "transaction_utime",
                    "block_workchain",
                    "block_shard",
                    "block_seqno",
                    "observed_masterchain_seqno",
                    "finalized_controller_epoch",
                    "finalized_seqno",
                )
            ),
        )
        check(
            "transaction.finalized_controller_epoch",
            transaction.get("finalized_controller_epoch") == finalized_controller_epoch,
        )
        check(
            "transaction.finalized_seqno",
            transaction.get("finalized_seqno") == finalized_seqno,
        )

    # Rebind the resolver winner to the independently decoded exact transaction
    # and its unique semantic pool effect.  The raw cell/BOC identities are the
    # representation-preserving bridge; no lossy MessageAny reserialization is
    # used as evidence.
    independent_cell_hash = finalized_transaction.get("transaction_cell_hash")
    expected_transaction_hash = None
    if digest(independent_cell_hash, "tvm-cell-sha256:"):
        expected_transaction_hash = "sha256:" + independent_cell_hash.removeprefix(
            "tvm-cell-sha256:"
        )
    check("effect.account", finalized_transaction.get("account") == expected_source_account)
    check("effect.source", finalized_transaction.get("source") == expected_source_account)
    check("effect.destination", finalized_transaction.get("target") == expected_destination)
    check(
        "effect.amount_nanotos",
        finalized_transaction.get("value_nanotos") == expected_amount_nanotos,
    )
    check("effect.body_hash", finalized_transaction.get("body_hash") == expected_body_hash)
    check("effect.transaction_cell_hash", expected_transaction_hash is not None)
    check(
        "effect.outbound_message_cell_hash",
        digest(finalized_transaction.get("out_message_cell_hash"), "tvm-cell-sha256:"),
    )
    if transaction_is_object:
        assert isinstance(transaction, dict)
        check(
            "effect.transaction_hash",
            expected_transaction_hash is not None
            and transaction.get("transaction_hash") == expected_transaction_hash,
        )
        check(
            "effect.transaction_lt",
            str(transaction.get("transaction_lt"))
            == str(finalized_transaction.get("transaction_lt")),
        )
        check(
            "effect.transaction_boc_digest",
            transaction.get("transaction_boc_digest")
            == finalized_transaction.get("transaction_boc_digest"),
        )
        check(
            "effect.outbound_message_identity",
            transaction.get("outbound_message_cell_hash")
            == finalized_transaction.get("out_message_cell_hash"),
        )

    checkpoint = finalized_transaction.get("block_checkpoint")
    check("effect.block_checkpoint", isinstance(checkpoint, dict))
    if transaction_is_object and isinstance(checkpoint, dict):
        assert isinstance(transaction, dict)
        check(
            "effect.block_workchain",
            transaction.get("block_workchain") == checkpoint.get("workchain"),
        )
        check(
            "effect.block_shard",
            str(transaction.get("block_shard")) == str(checkpoint.get("shard")),
        )
        check("effect.block_seqno", transaction.get("block_seqno") == checkpoint.get("seqno"))
        check(
            "effect.block_root_hash",
            transaction.get("block_root_hash") == checkpoint.get("root_hash"),
        )
        check(
            "effect.block_file_hash",
            transaction.get("block_file_hash") == checkpoint.get("file_hash"),
        )
    return mismatches


@dataclass
class Report:
    started_at: str = field(default_factory=utc_now)
    events: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)


class PoolLifecycle:
    def __init__(
        self,
        install: Install,
        run_dir: Path,
        base_port: int,
        *,
        campaign_run_id: str,
        agent_bindings: list[AgentBinding] | None = None,
        agent_manifest_digest: str = "",
        evidence_out: Path | None = None,
        evidence_attempt: EvidenceAttempt | None = None,
        integrated_source_config: Path | None = None,
        tosctl_path: Path | None = None,
        rpc_base_port: int = 0,
        product_rpc_address: str | None = None,
        ready_out: Path | None = None,
        hold_until: Path | None = None,
    ) -> None:
        self.install = install
        self.run_dir = run_dir
        self.network_dir = run_dir / "network"
        self.artifacts_dir = run_dir / "artifacts"
        self.base_port = base_port
        self.campaign_run_id = validate_campaign_run_id(campaign_run_id)
        self.agent_bindings = list(agent_bindings or DEFAULT_AGENT_BINDINGS)
        if len(self.agent_bindings) != OPENFOX_AGENT_COUNT:
            raise ValueError(f"exactly {OPENFOX_AGENT_COUNT} Agent bindings are required")
        self.agent_manifest_digest = agent_manifest_digest
        self.evidence_out = evidence_out
        self.evidence_attempt = evidence_attempt
        if (self.evidence_out is None) != (self.evidence_attempt is None):
            raise ValueError("stable evidence output and attempt marker must be supplied together")
        self.integrated_source_config = integrated_source_config
        self.integrated_mode = integrated_source_config is not None
        if self.integrated_mode and self.evidence_attempt is None:
            raise ValueError(
                "integrated mode requires a durable evidence attempt before genesis creation"
            )
        self.genesis_attempt_scope_binding = (
            integrated_genesis_attempt_binding(
                self.campaign_run_id, self.evidence_attempt.attempt_id
            )
            if self.integrated_mode and self.evidence_attempt is not None
            else None
        )
        self.network_global_id = (
            integrated_network_global_id(self.campaign_run_id, self.evidence_attempt.attempt_id)
            if self.integrated_mode
            else LEGACY_LOCAL_GLOBAL_ID
        )
        self.tosctl_path = tosctl_path
        self.rpc_base_port = rpc_base_port
        self.product_rpc_address = product_rpc_address
        self.ready_out = ready_out
        self.hold_until = hold_until
        if self.integrated_mode and (
            self.tosctl_path is None
            or self.rpc_base_port <= 0
            or self.rpc_base_port + INTEGRATED_RPC_COUNT - 1 > 65_535
            or self.ready_out is None
        ):
            raise ValueError(
                "integrated mode requires tosctl, three valid RPC ports, and a ready output"
            )
        self.lite_config = run_dir / "lite-client.json"
        self.report = Report()
        self.network: Network | None = None
        self.nodes: list[FullNode] = []
        self.wallets: list[WalletV1] = []
        self.nominators: list[Nominator] = []
        self.all_nominators: list[Nominator] = []
        self.client: Any = None
        self.rescuer: WalletV1 | None = None
        # Messages the validator sends once its stake is in. A pool whose
        # depositors depend on the validator staying responsive is a pool that
        # traps them when it stops, so this has to stay at zero through
        # recovery and exit.
        self.validator_sends_after_stake = 0
        self.count_validator_sends = False
        self.pool_address: Address | None = None
        self.pool_code: Cell | None = None
        self.controller_code: Cell | None = None
        self.single_pool_code: Cell | None = None
        self.controllers: list[ControllerFixture] = []
        self.support_pools: dict[int, PoolFixture] = {}
        self.support_submitted: dict[int, set[int]] = {index: set() for index in range(1, 5)}
        self.support_recovered: dict[int, set[int]] = {index: set() for index in range(1, 5)}
        self.support_recovery_attempted: dict[int, set[int]] = {
            index: set() for index in range(1, 5)
        }
        self.support_set_hashes: dict[int, int] = {}
        self.support_retired_past: dict[int, dict[str, int]] = {}
        self.support_snapshot_number = 0
        self.stake_feedback_baselines: dict[int, tuple[Any, Any]] = {}
        self.pool_reward_evidence: dict[str, Any] = {}
        self.pool_validator_selection: dict[str, Any] = {}
        self.integrated_profiles: list[IntegratedAgentProfile] = []
        self.working_configs: list[IntegratedWorkingConfig] = []
        self.rpc_readiness: list[dict[str, Any]] = []
        self.network_domain: dict[str, Any] | None = None
        self.source_config_digest = ""
        self.report_written = False
        self.final_report: dict[str, Any] | None = None
        self.ready_written = False
        self.agent_account_state_identities: dict[str, dict[str, Any]] = {}
        self.agent_action_evidence: list[dict[str, Any]] = []
        self.campaign_start_positions: list[dict[str, Any]] = []
        self.queued_leaver: Nominator | None = None
        self.failures: list[str] = []

    @property
    def nominator_deposit_value(self) -> int:
        return INTEGRATED_NOMINATOR_DEPOSIT if self.integrated_mode else NOMINATOR_DEPOSIT

    @property
    def min_nominator_stake(self) -> int:
        return INTEGRATED_MIN_NOMINATOR_STAKE if self.integrated_mode else MIN_NOMINATOR_STAKE

    @property
    def validator_own_deposit(self) -> int:
        return INTEGRATED_VALIDATOR_OWN_DEPOSIT if self.integrated_mode else VALIDATOR_OWN_DEPOSIT

    @property
    def min_validator_stake(self) -> int:
        return INTEGRATED_MIN_VALIDATOR_STAKE if self.integrated_mode else MIN_VALIDATOR_STAKE

    @property
    def pool_validator_funding(self) -> int:
        return INTEGRATED_POOL_VALIDATOR_FUNDING if self.integrated_mode else POOL_VALIDATOR_FUNDING

    @property
    def direct_validator_funding(self) -> int:
        return (
            INTEGRATED_DIRECT_VALIDATOR_FUNDING
            if self.integrated_mode
            else DIRECT_VALIDATOR_FUNDING
        )

    @property
    def agent_subject(self) -> str:
        return "campaign Agent Account" if self.integrated_mode else "identity-bound sidecar proxy"

    # ----- plumbing -------------------------------------------------------

    def event(self, name: str, **details: Any) -> None:
        record = {"at": utc_now(), "event": name, **details}
        self.report.events.append(record)
        print(f"[{record['at']}] {name} {json.dumps(details, default=str)}", flush=True)

    def check(self, name: str, passed: bool, **details: Any) -> bool:
        self.report.checks.append({"at": utc_now(), "check": name, "passed": passed, **details})
        status = "PASS" if passed else "FAIL"
        print(f"  {status}  {name} {json.dumps(details, default=str)}", flush=True)
        if not passed:
            self.failures.append(name)
        return passed

    async def retry(
        self,
        action: Callable[[], Awaitable[T]],
        *,
        timeout: float,
        description: str,
        predicate: Callable[[T], bool],
        interval: float = 2.0,
    ) -> T:
        deadline = time.monotonic() + timeout
        last: Any = None
        while time.monotonic() < deadline:
            try:
                last = await action()
                if predicate(last):
                    return last
            except Exception as error:  # noqa: BLE001 - reported below
                last = error
            await asyncio.sleep(interval)
        raise TimeoutError(f"{description}: gave up after {timeout}s, last={last!r}")

    @property
    def integrated_rpc_addresses(self) -> list[str]:
        if not self.integrated_mode:
            return []
        return [f"127.0.0.1:{self.rpc_base_port + index}" for index in range(INTEGRATED_RPC_COUNT)]

    def prepare_integrated_mode(self) -> None:
        if not self.integrated_mode:
            return
        assert self.integrated_source_config is not None
        assert self.tosctl_path is not None
        assert self.ready_out is not None
        assert self.evidence_attempt is not None
        if (
            self.evidence_attempt.lock_descriptor < 0
            or read_regular_file(self.evidence_attempt.marker_path)
            != self.evidence_attempt.marker_raw
        ):
            raise ValueError("integrated genesis requires its live durable evidence attempt")
        try:
            marker = json.loads(self.evidence_attempt.marker_raw)
        except json.JSONDecodeError as error:
            raise ValueError("integrated evidence attempt marker is malformed") from error
        if (
            marker.get("schema") != EVIDENCE_ATTEMPT_MARKER_SCHEMA
            or marker.get("campaign_run_id") != self.campaign_run_id
            or marker.get("attempt_id") != self.evidence_attempt.attempt_id
        ):
            raise ValueError("integrated evidence attempt does not bind this campaign run")
        validate_inherited_vault_environment()
        if not self.tosctl_path.is_file() or not os.access(self.tosctl_path, os.X_OK):
            raise ValueError(f"tosctl binary is unavailable or not executable: {self.tosctl_path}")
        if self.ready_out.exists():
            raise ValueError(
                f"refusing to replace an existing readiness descriptor: {self.ready_out}"
            )
        if self.hold_until is not None and self.hold_until.exists():
            raise ValueError(f"hold-until stop file already exists: {self.hold_until}")
        reservations: list[socket.socket] = []
        try:
            for address in self.integrated_rpc_addresses:
                host, port = address.rsplit(":", 1)
                reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                reservation.bind((host, int(port)))
                reservations.append(reservation)
        except OSError as error:
            raise ValueError(f"integrated JSON-RPC port is unavailable: {address}") from error
        finally:
            for reservation in reservations:
                reservation.close()
        source, raw = read_owner_private_json(self.integrated_source_config)
        self.source_config_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.integrated_profiles, self.working_configs = prepare_integrated_working_configs(
            source,
            self.agent_bindings,
            self.run_dir / "tosctl",
            self.integrated_rpc_addresses,
            self.campaign_run_id,
        )

    async def tosctl(self, config: Path, *args: str, timeout: float = 180) -> str:
        if not self.integrated_mode or self.tosctl_path is None:
            raise RuntimeError("tosctl execution is only available in integrated mode")
        process = await asyncio.create_subprocess_exec(
            str(self.tosctl_path),
            *args,
            "-c",
            str(config),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(os.environ),
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError(f"tosctl {' '.join(args[:3])} timed out")
        if process.returncode != 0:
            details = (stdout + stderr).decode(errors="replace")
            vault_url = os.environ.get("VAULT_URL", "")
            if vault_url:
                details = details.replace(vault_url, "<redacted-vault-url>")
            raise RuntimeError(f"tosctl {' '.join(args[:3])} failed: {details[-2000:]}")
        return stdout.decode()

    async def tosctl_json(self, config: Path, *args: str) -> dict[str, Any]:
        raw = await self.tosctl(config, *args, "--format", "json")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError("tosctl returned invalid JSON") from error
        if not isinstance(document, dict):
            raise RuntimeError("tosctl JSON result is not an object")
        return document

    @staticmethod
    def config_global_id_from_rpc(response: dict[str, Any]) -> int:
        try:
            encoded = response["result"]["config"]["bytes"]
            cell = Cell.one_from_boc(base64.b64decode(encoded, validate=True))
            parser = cell.begin_parse()
            value = parser.load_int(32)
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("JSON-RPC ConfigParam 19 is malformed") from error
        if parser.remaining_bits != 0 or parser.refs:
            raise RuntimeError("JSON-RPC ConfigParam 19 has trailing data")
        return value

    async def wait_integrated_rpc_readiness(self) -> None:
        if not self.integrated_mode:
            return
        assert self.network is not None
        expected_root = base64.b64encode(self.network.zerostate.masterchain.root_hash).decode()
        expected_file = base64.b64encode(self.network.zerostate.masterchain.file_hash).decode()

        async def wait_one(index: int, config: IntegratedWorkingConfig) -> dict[str, Any]:
            response = await self.retry(
                lambda: asyncio.to_thread(json_rpc_call, config.rpc_address, "getMasterchainInfo"),
                timeout=120,
                description=f"integrated validator RPC {index + 1} readiness",
                predicate=lambda value: value.get("result") is not None,
                interval=0.5,
            )
            config19 = await asyncio.to_thread(
                json_rpc_call,
                config.rpc_address,
                "getConfigParam",
                {"param": 19},
            )
            result = response["result"]
            init = result.get("init") or {}
            global_id = self.config_global_id_from_rpc(config19)
            if (
                init.get("root_hash") != expected_root
                or init.get("file_hash") != expected_file
                or global_id != self.network_global_id
            ):
                raise RuntimeError(f"integrated validator RPC {index + 1} network mismatch")
            return {
                "process_view_index": index + 1,
                "url": config.rpc_url,
                "process_view_provenance": config.operator_provenance,
                "operator_scope": "same-host-single-operator",
                "ready": True,
                "observed_at": utc_now(),
            }

        self.rpc_readiness = list(
            await asyncio.gather(
                *(wait_one(index, config) for index, config in enumerate(self.working_configs))
            )
        )
        self.network_domain = {
            "network_id": INTEGRATED_NETWORK_ID,
            "global_id": self.network_global_id,
            "workchain_id": INTEGRATED_WORKCHAIN_ID,
            "zero_state_root_hash": canonical_network_hash(
                self.network.zerostate.masterchain.root_hash
            ),
            "zero_state_file_hash": canonical_network_hash(
                self.network.zerostate.masterchain.file_hash
            ),
        }
        genesis_attempt_scope = {
            "binding": self.genesis_attempt_scope_binding,
            "global_id": self.network_global_id,
            "derivation": "campaign_run_id+durable-evidence-attempt-id",
        }
        self.check(
            "three distinct RPC process views under one local operator expose the exact unified genesis",
            len(self.rpc_readiness) == INTEGRATED_RPC_COUNT
            and len({entry["url"] for entry in self.rpc_readiness}) == INTEGRATED_RPC_COUNT
            and len({entry["process_view_provenance"] for entry in self.rpc_readiness})
            == INTEGRATED_RPC_COUNT,
            network_domain=self.network_domain,
            process_views=self.rpc_readiness,
            operator_scope="same-host-single-operator",
            genesis_attempt_scope=genesis_attempt_scope,
        )

    async def lite(self, *commands: str, timeout: float = 30.0) -> str:
        args = [
            str(self.install.build_dir / "lite-client/lite-client"),
            "-C",
            str(self.lite_config),
            "-v",
            "1",
        ]
        for command in commands:
            args += ["-c", command]

        def run() -> str:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr

        return await asyncio.to_thread(run)

    async def runmethod(self, address: str, method: str, *params: str) -> str:
        command = " ".join(["runmethod", address, method, *params])
        return await self.lite("time", command)

    async def balance(self, address: Address) -> int:
        assert self.client is not None
        return (await self.client.raw_get_account_state(address)).balance

    @staticmethod
    def _stack_tokens(payload: str) -> list[str]:
        """Split a lite-client result stack into one token per slot.

        Cells and empty tuples render as ``C{...}`` and ``()`` rather than as
        numbers. Dropping them and indexing what is left shifts every field
        after the two dictionaries, which is the kind of mistake that reads a
        duration as a counter and reports success without ever having checked
        anything.
        """
        tokens: list[str] = []
        index = 0
        while index < len(payload):
            char = payload[index]
            if char.isspace():
                index += 1
            elif payload.startswith("C{", index):
                close = payload.index("}", index)
                tokens.append(payload[index : close + 1])
                index = close + 1
            elif char == "(":
                close = payload.index(")", index)
                tokens.append(payload[index : close + 1])
                index = close + 1
            else:
                end = index
                while end < len(payload) and not payload[end].isspace():
                    end += 1
                tokens.append(payload[index:end])
                index = end
        return tokens

    async def pool_data(self) -> PoolData:
        assert self.pool_address is not None
        output = await self.runmethod(raw_address(self.pool_address), "get_pool_data")
        match = re.search(r"^result:\s*\[(.*)\]\s*$", output, re.MULTILINE)
        if match is None:
            raise RuntimeError(f"get_pool_data returned no result:\n{output[-1500:]}")
        tokens = self._stack_tokens(match.group(1))
        if len(tokens) < 17:
            raise RuntimeError(f"unexpected get_pool_data stack: {tokens}")

        def number(index: int) -> int:
            token = tokens[index]
            if not token.lstrip("-").isdigit():
                raise RuntimeError(f"stack slot {index} is not a number: {token}")
            return int(token)

        # Slot order follows pool.fc's save_data, with the config flattened into it:
        # 4 through 9 are its six fields, 10 and 11 the nominator and withdraw-request
        # dictionaries. The config gained the controller address, so everything after it
        # sits one slot later than it used to.
        return PoolData(
            state=number(0),
            nominators_count=number(1),
            stake_amount_sent=number(2),
            validator_amount=number(3),
            stake_at=number(12),
            validator_set_changes_count=number(14),
        )

    async def active_election_id(self) -> int:
        output = await self.runmethod(raw_address(ELECTOR), "active_election_id")
        for token in reversed(output.split()):
            if token.lstrip("-").isdigit():
                return int(token)
        return 0

    async def stakeable_election_id(self, *, capture_query_id: int | None = None) -> int:
        """Read the Elector's acceptance window against this lite-server's chain time."""
        assert self.client is not None
        output = await self.runmethod(raw_address(ELECTOR), "participant_list_extended")
        state = await self.client.raw_get_account_state(ELECTOR)
        selected = stakeable_election_id_from_live_status(output, state.sync_utime)
        if capture_query_id is not None:
            # Keep the exact getter and chain-time read used by the final
            # pre-send decision, rather than inferring it from a keeper poll.
            path = self.artifacts_dir / f"pool-stake-pre-send-window-{capture_query_id}.json"
            raw = json.dumps({
                "query_id": str(capture_query_id),
                "chain_utime": state.sync_utime,
                "participant_list_extended": output,
                "stakeable_election_id": selected,
            }, indent=2, sort_keys=True).encode() + b"\n"
            path.write_bytes(raw)
            self.event(
                "pool_stake_pre_send_window", query_id=capture_query_id,
                chain_utime=state.sync_utime, stakeable_election_id=selected,
                raw_path=str(path), raw_sha256=hashlib.sha256(raw).hexdigest(),
            )
        return selected

    async def config34_selection(self) -> Config34Selection:
        output = await self.lite("time", "getconfig 34")

        def required(pattern: str, label: str) -> int:
            match = re.search(pattern, output)
            if match is None:
                raise RuntimeError(f"cannot parse ConfigParam 34 {label}")
            return int(match.group(1))

        return Config34Selection(
            utime_since=required(r"utime_since:(\d+)", "utime_since"),
            utime_until=required(r"utime_until:(\d+)", "utime_until"),
            total=required(r"\btotal:(\d+)", "total"),
            main=required(r"\bmain:(\d+)", "main"),
            total_weight=required(r"total_weight:(\d+)", "total_weight"),
            validator_adnl_pairs=parse_pq_validator_adnl_pairs(output),
            weights=[int(value) for value in re.findall(r"\bweight:(\d+)", output)],
        )

    async def record_pool_validator_selection(self, election_id: int) -> None:
        controller_id = self.controllers[0].address.hash_part.hex()
        adnl_id = self.nodes[0].validator_key.id.hex()
        selection = await self.retry(
            self.config34_selection,
            timeout=900,
            description="pool validator appears in the elected ConfigParam 34",
            predicate=lambda value: (
                value.utime_since == election_id
                and (controller_id, adnl_id) in value.validator_adnl_pairs
            ),
            interval=5,
        )
        index = selection.validator_adnl_pairs.index((controller_id, adnl_id))
        selected_weight = selection.weights[index] if index < len(selection.weights) else None
        self.pool_validator_selection = {
            "selection_status": "selected",
            "election_id": election_id,
            "controller_validator_id": controller_id,
            "validator_adnl_id": adnl_id,
            "selected_pair": selection.validator_adnl_pairs[index],
            "selected_weight": selected_weight,
            "validator_set_utime_since": selection.utime_since,
            "validator_set_utime_until": selection.utime_until,
            "validator_set_total": selection.total,
            "validator_set_main": selection.main,
            "validator_set_total_weight": selection.total_weight,
        }
        self.check(
            "the pool validator is selected into ConfigParam 34",
            selected_weight is not None and selected_weight > 0,
            **self.pool_validator_selection,
        )

    async def elector_returned_stake(self) -> int:
        """Return the Elector's exact credit for the pool before recovery."""
        assert self.pool_address is not None
        return await self.elector_returned_stake_for(self.pool_address)

    async def elector_returned_stake_for(self, pool_address: Address) -> int:
        """Read matured credit by its owner account, never by validator ID."""
        output = await self.runmethod(
            raw_address(ELECTOR),
            "compute_returned_stake",
            "0x" + pool_address.hash_part.hex(),
        )
        return elector_credit_from_output(output)

    async def wallet_seqno(self, wallet: WalletV1) -> int:
        return (await wallet.current).seqno

    async def send(
        self,
        wallet: WalletV1,
        *,
        dest: Address,
        amount: int,
        body: Cell,
        label: str,
        init: StateInit | None = None,
    ) -> None:
        before = await self.wallet_seqno(wallet)
        await wallet.send(
            internal_message(wallet.address, dest, amount, body, init=init),
            seqno=before,
        )
        await self.retry(
            lambda: self.wallet_seqno(wallet),
            timeout=60,
            description=f"{label} accepted",
            predicate=lambda value: value > before,
        )
        if self.count_validator_sends and self.wallets and wallet is self.wallets[0]:
            self.validator_sends_after_stake += 1
        self.event("message_sent", label=label, dest=raw_address(dest), amount=amount)

    async def send_nominator(
        self,
        nominator: Nominator,
        *,
        amount: int,
        body: Cell,
        label: str,
        action: str,
    ) -> None:
        assert self.pool_address is not None
        if not self.integrated_mode or nominator.agent is None:
            if nominator.wallet is None:
                raise RuntimeError("sidecar nominator wallet is missing")
            await self.send(
                nominator.wallet,
                dest=self.pool_address,
                amount=amount,
                body=body,
                label=label,
            )
            return
        if not nominator.agent_profile_name or nominator.tosctl_config is None:
            raise RuntimeError("integrated nominator has no Agent Account custody profile")
        if self.ready_written:
            raise RuntimeError("Agent Account task-send is forbidden after ready publication")
        if self.network_domain is None or not nominator.deployment_id:
            raise RuntimeError("integrated Agent Account action has no complete network identity")
        body_boc = base64.b64encode(body.to_boc()).decode()
        body_hash = "tvm-cell-sha256:" + body.hash.hex()
        action_id = integrated_action_id(
            self.campaign_run_id,
            self.network_domain,
            nominator.deployment_id,
            nominator.agent.agent_id,
            raw_address(self.pool_address),
            action,
            amount,
            body_hash,
        )
        await self.tosctl(
            nominator.tosctl_config,
            "agent",
            "account",
            "task-send",
            f"--wallet={nominator.agent_profile_name}",
            f"--target={raw_address(self.pool_address)}",
            f"--value={amount // NANO}.{amount % NANO:09d}",
            f"--body-boc={body_boc}",
            f"--valid-until={int(time.time()) + 300}",
            f"--action-id={action_id}",
            "--yes",
        )
        finalized = await self.await_finalized_agent_action(
            nominator,
            action_id=action_id,
            action=action,
            amount=amount,
            body_hash=body_hash,
        )
        self.agent_action_evidence.append(finalized)
        self.event(
            "campaign_agent_account_pool_message",
            agent=nominator.agent.name,
            sender=raw_address(nominator.delegation_address),
            ledger_key=raw_address(nominator.delegation_address),
            payout_address=raw_address(nominator.delegation_address),
            target=raw_address(self.pool_address),
            action=action,
            action_id=action_id,
            amount_nanotos=amount,
            body_hash=body_hash,
            finalized_transaction=finalized["finalized_transaction"],
            authorization_boundary=(
                "operator-driven low-level task-send harness; this is not an autonomous "
                "OpenFox PersonalAuthority decision"
            ),
        )

    async def await_finalized_agent_action(
        self,
        nominator: Nominator,
        *,
        action_id: str,
        action: str,
        amount: int,
        body_hash: str,
    ) -> dict[str, Any]:
        """Bind one custody claim to its finalized exact internal pool message."""
        assert self.pool_address is not None
        assert nominator.tosctl_config is not None
        assert nominator.agent is not None
        assert self.network_domain is not None
        sender = nominator.delegation_address

        async def observation(config: IntegratedWorkingConfig) -> dict[str, Any] | None:
            info = await asyncio.to_thread(
                json_rpc_call,
                config.rpc_address,
                "getAddressInformation",
                {"address": raw_address(sender)},
            )
            try:
                cursor = info["result"]["last_transaction_id"]
                lt = str(cursor["lt"])
                tx_hash = cursor["hash"]
            except (KeyError, TypeError) as error:
                raise RuntimeError("Agent Account RPC cursor is malformed") from error
            if lt == "0":
                return None
            response = await asyncio.to_thread(
                json_rpc_call,
                config.rpc_address,
                "getTransactions",
                {
                    "address": raw_address(sender),
                    "lt": lt,
                    "hash": tx_hash,
                    "limit": 20,
                },
            )
            for entry in normalize_rpc_transactions(response):
                match = match_agent_pool_transaction(
                    entry, sender, self.pool_address, amount, body_hash
                )
                if match is not None:
                    return match
            return None

        primary = await self.retry(
            lambda: observation(self.working_configs[0]),
            timeout=120,
            description=f"campaign Agent Account {action} finalized transaction",
            predicate=lambda value: value is not None,
            interval=1,
        )
        assert primary is not None
        process_views = []
        for index, config in enumerate(self.working_configs):
            viewed = await self.retry(
                lambda config=config: observation(config),
                timeout=120,
                description=f"RPC process view {index + 1} observes Agent Account {action}",
                predicate=lambda value, primary=primary: (
                    value is not None
                    and value["transaction_cell_hash"] == primary["transaction_cell_hash"]
                    and value["block_checkpoint"] == primary["block_checkpoint"]
                ),
                interval=1,
            )
            assert viewed is not None
            process_views.append(
                {
                    "process_view_index": index + 1,
                    "transaction_cell_hash": viewed["transaction_cell_hash"],
                    "block_checkpoint": viewed["block_checkpoint"],
                }
            )

        resolution = await self.resolve_finalized_agent_action(
            nominator,
            action_id=action_id,
            amount=amount,
            body_hash=body_hash,
            finalized_transaction=primary,
        )
        record = read_controller_action_record(nominator.tosctl_config, action_id)
        claim_domain = record.get("network_domain")
        expected_journal_domain = {
            "network_id": f"tos:global-id:{self.network_domain['global_id']}",
            "global_id": self.network_domain["global_id"],
            "zero_state_root_hash": self.network_domain["zero_state_root_hash"],
            "zero_state_file_hash": self.network_domain["zero_state_file_hash"],
            "workchain_id": self.network_domain["workchain_id"],
        }
        journal_matches = (
            raw_address(Address(record.get("account", ""))) == raw_address(sender)
            and raw_address(Address(record.get("target", ""))) == raw_address(self.pool_address)
            and record.get("network_global_id") == self.network_domain["global_id"]
            and claim_domain == expected_journal_domain
            and record.get("deployment_id") == nominator.deployment_id
            and isinstance(record.get("controller_epoch"), int)
            and isinstance(record.get("seqno"), int)
            and record.get("value_atomic") == amount
            and record.get("body_hash") == body_hash
            and record.get("action_kind") == "agent-task-send"
            and record.get("idempotency_key") == action_id
            and record.get("status") == "resolved"
            and re.fullmatch(r"sha256:[0-9a-f]{64}", str(record.get("exact_signed_boc_digest")))
            is not None
            and isinstance(record.get("exact_winner_resolution"), dict)
            and record["exact_winner_resolution"].get("evidence_kind")
            == "tos.agent-account.task-send-finalized.v1"
            and record["exact_winner_resolution"].get("evidence") == resolution
            and re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(record["exact_winner_resolution"].get("evidence_digest")),
            )
            is not None
        )
        if not journal_matches:
            raise RuntimeError("controller custody journal does not bind the finalized pool action")
        return {
            "action": action,
            "action_id": action_id,
            "campaign_run_id": self.campaign_run_id,
            "network_domain": self.network_domain,
            "deployment_id": nominator.deployment_id,
            "agent_id": nominator.agent.agent_id,
            "campaign_account_address": raw_address(sender),
            "pool_address": raw_address(self.pool_address),
            "amount_nanotos": amount,
            "body_hash": body_hash,
            "controller_epoch": record["controller_epoch"],
            "seqno": record["seqno"],
            "exact_signed_boc_digest": record["exact_signed_boc_digest"],
            "journal_status_at_observation": record["status"],
            "task_send_resolution": resolution,
            "exact_winner_evidence_digest": record["exact_winner_resolution"]["evidence_digest"],
            "retry_boundary": (
                "single broadcast attempt; task-send journal reconciles finalized seqno before "
                "any caller-authorized retry, and this harness never retries an ambiguous broadcast"
            ),
            "finalized_transaction": primary,
            "rpc_process_views": process_views,
            "pool_ledger_key": raw_address(sender),
        }

    async def resolve_finalized_agent_action(
        self,
        nominator: Nominator,
        *,
        action_id: str,
        amount: int,
        body_hash: str,
        finalized_transaction: dict[str, Any],
    ) -> dict[str, Any]:
        """Resolve one already-observed task-send through the production custody interface."""
        assert nominator.tosctl_config is not None
        assert nominator.agent_profile_name is not None
        assert nominator.deployment_id is not None
        assert self.pool_address is not None
        assert self.network_domain is not None
        if len(self.working_configs) != INTEGRATED_RPC_COUNT:
            raise RuntimeError("task-send resolution requires exactly three frozen RPC configs")
        raw = await self.tosctl(
            nominator.tosctl_config,
            "agent",
            "account",
            "task-send-resolve",
            f"--wallet={nominator.agent_profile_name}",
            f"--action-id={action_id}",
            "--quorum-config",
            str(self.working_configs[1].path),
            str(self.working_configs[2].path),
            "--max-transactions=1000",
        )
        try:
            resolution = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError("tosctl task-send resolver returned invalid JSON") from error
        if not isinstance(resolution, dict):
            raise RuntimeError("tosctl task-send resolver result is not an object")
        expected_journal_domain = {
            "network_id": f"tos:global-id:{self.network_domain['global_id']}",
            "global_id": self.network_domain["global_id"],
            "zero_state_root_hash": self.network_domain["zero_state_root_hash"],
            "zero_state_file_hash": self.network_domain["zero_state_file_hash"],
            "workchain_id": self.network_domain["workchain_id"],
        }
        mismatches = task_send_resolution_mismatches(
            resolution,
            expected_wallet=nominator.agent_profile_name,
            expected_action_id=action_id,
            expected_source_account=raw_address(nominator.delegation_address),
            expected_deployment_id=nominator.deployment_id,
            expected_destination=raw_address(self.pool_address),
            expected_amount_nanotos=amount,
            expected_body_hash=body_hash,
            expected_network_domain=expected_journal_domain,
            finalized_transaction=finalized_transaction,
        )
        if mismatches:
            raise RuntimeError(
                "task-send resolver evidence mismatch fields: " + ", ".join(mismatches)
            )
        return resolution

    # ----- phases ---------------------------------------------------------

    def prepare_pq_election_fixture(self) -> None:
        """Bind five admitted controller identities before Genesis is assembled."""
        require_pq_stake_authorization_binding(
            tos_api.Engine_validator_pqStakeAuthorization
        )
        builder = subprocess.run(
            ["cargo", "build", "--manifest-path", "tosctl/src/Cargo.toml",
             "-p", "contracts", "--example", "pq_pool_stake_order", "--locked"],
            cwd=REPO, text=True, capture_output=True, check=False,
        )
        if builder.returncode:
            raise RuntimeError(
                "cannot build production PQ pool order bridge: " + builder.stderr[-4000:]
            )
        self.controller_code = compile_controller_code(
            self.install, self.artifacts_dir / "compiled-controller"
        )
        self.single_pool_code = Cell.one_from_boc(bytes.fromhex(
            (REPO / "crypto/smartcont/single-nominator-pool/single-nominator-code.hex")
            .read_text().strip()
        ))
        self.controllers = [
            make_controller_fixture(
                self.install, self.artifacts_dir / "controller-keys",
                self.controller_code, index,
            )
            for index in range(5)
        ]

    async def bring_up_network(self) -> None:
        if self.controller_code is None or len(self.controllers) != 5:
            raise RuntimeError("PQ controller policy and five identities must precede Genesis")
        network = Network(self.install, self.network_dir, base_port=self.base_port)
        self.network = network
        if self.integrated_mode:
            network.config.global_id = self.network_global_id
            # The two-hour hold spans many accelerated election rounds.  This
            # test-only faucet and per-validator bound keep election upkeep
            # alive without changing the sidecar/default economics profile.
            network.config.validator_election_experiment_faucet_balance_nanotos = (
                INTEGRATED_FAUCET_FUNDING
            )
        elif self.product_rpc_address is not None:
            # The product CLI provisions an additional operator wallet and
            # single-nominator pool beyond the ordinary lifecycle fixture.
            # Make that test-only genesis budget explicit instead of letting
            # a faucet send advance seqno while its unfunded out-message fails.
            network.config.validator_election_experiment_faucet_balance_nanotos = (
                150_000 * NANO
            )
        network.config.shard_validators = 4
        network.config.validator_economics_profile = True
        network.config.validator_election_stage_a_profile = True
        # Funding/deploying the live pool fixture can consume the 600-second
        # default first set before its initial election accepts a stake. Keep
        # ConfigParam 15 accelerated, but leave enough first-set time for the
        # fixture to enter that election before its close; later sets remain
        # on the explicit Stage A test schedule below.  A 300-second elected
        # set left only a 60-second interval between the first stake's actual
        # unfreeze and the third election's close; four support-pool recoveries
        # and the primary recovery could not finish within it.  Keep the
        # production schedule untouched and give this recovery rehearsal a
        # 600-second elected period instead.
        network.config.bootstrap_validator_set_valid_for = 1200
        network.config.validator_election_stage_a_elected_for = 600
        network.config.global_version = 16
        network.config.validator_controller_code_hash = self.controller_code.hash

        dht = network.create_dht_node()
        for validator_index, controller in enumerate(self.controllers):
            node = network.create_full_node()
            if validator_index < 4:
                make_deterministic_pq_initial_validator(
                    node, validator_index, validator_id=controller.address.hash_part
                )
            else:
                make_deterministic_pq_spare_validator(
                    node, validator_index, validator_id=controller.address.hash_part
                )
            assert_controller_identity(node, controller, index=validator_index + 1)
            node.announce_to(dht)
            self.nodes.append(node)

        # Genesis economics permits exactly four validators. The fifth node
        # custodizes its controller-bound PQ key but is not in Genesis; node
        # authorization can sign its first pool stake before set membership.

        await dht.run(StartOptions(threads=2, verbosity=3))
        for index, node in enumerate(self.nodes):
            arguments: list[str] = []
            if self.product_rpc_address is not None and index == 0:
                arguments = ["--json-rpc-address", self.product_rpc_address]
            elif self.integrated_mode and index < INTEGRATED_RPC_COUNT:
                arguments = [
                    "--json-rpc-address",
                    self.integrated_rpc_addresses[index],
                ]
            await node.run(StartOptions(threads=4, verbosity=3, args=arguments))

        self.lite_config.write_text(self.nodes[0]._liteserver_config.to_json())
        await asyncio.wait_for(network.wait_mc_block(seqno=3), timeout=180)
        self.client = await self.nodes[0].toslib_client()
        await self.verify_live_controller_policy()
        await self.wait_integrated_rpc_readiness()
        self.event(
            "network_ready",
            validators=len(self.nodes),
            rpc_process_views=len(self.rpc_readiness),
            operator_scope="same-host-single-operator" if self.integrated_mode else None,
            network_domain=self.network_domain,
            genesis_attempt_scope=(
                {
                    "binding": self.genesis_attempt_scope_binding,
                    "global_id": self.network_global_id,
                    "derivation": "campaign_run_id+durable-evidence-attempt-id",
                }
                if self.integrated_mode
                else None
            ),
        )

    async def verify_live_controller_policy(self) -> None:
        if self.client is None or self.controller_code is None:
            raise AssertionError("controller policy read-back lacks client or compiled code")
        policy = await self.client.get_config_param(47)
        view = policy.begin_parse()
        admitted = view.load_dict(256)
        expected = int.from_bytes(self.controller_code.hash, "big")
        if admitted is None or set(admitted) != {expected}:
            raise AssertionError(
                "live ConfigParam 47 does not admit exactly the lifecycle controller code: "
                f"expected={self.controller_code.hash.hex()} "
                f"actual={[] if admitted is None else [f'{key:064x}' for key in admitted]}"
            )
        if view.remaining_bits or view.remaining_refs:
            raise AssertionError("live ConfigParam 47 contains trailing data")
        version = ConfigParam8.deserialize((await self.client.get_config_param(8)).begin_parse())
        if version.version != 16:
            raise AssertionError(f"live PQ fixture version {version.version}, expected 16")
        self.event(
            "controller_policy_read_back", parameter=47,
            admitted_code_hash=self.controller_code.hash.hex(), global_version=version.version,
        )

    async def deploy_integrated_agent_accounts(self, faucet: WalletV1) -> None:
        """Deploy manifest Agent Accounts with existing vault keys and IDs."""
        if not self.integrated_mode or not self.working_configs:
            raise RuntimeError("integrated Agent Account deployment is not configured")
        primary = self.working_configs[0].path
        built: list[tuple[IntegratedAgentProfile, Address, Address, dict[str, Any]]] = []
        for profile in self.integrated_profiles:
            primary_identity: dict[str, Any] | None = None
            for config in self.working_configs:
                state = await self.tosctl_json(
                    config.path,
                    "agent",
                    "account",
                    "build-state",
                    "--wallet",
                    profile.profile_name,
                    "--workchain",
                    "0",
                )
                identity = canonical_agent_state_identity(state)
                state_address = identity["address"]
                if (
                    state_address != profile.binding.campaign_account_address
                    or identity["deployment_id"] != profile.deployment_id
                ):
                    raise RuntimeError(
                        f"Agent Account build-state target mismatch for {profile.binding.name}"
                    )
                if primary_identity is None:
                    primary_identity = identity
                elif identity != primary_identity:
                    raise RuntimeError(
                        f"Agent Account StateInit identity differs across RPC configs for "
                        f"{profile.binding.name}"
                    )
            assert primary_identity is not None
            owner = Address(primary_identity["owner"])
            target = Address(profile.binding.campaign_account_address)
            if owner.wc != 0 or target.wc != 0:
                raise RuntimeError("integrated Agent Account owner and target must be basechain")
            self.agent_account_state_identities[profile.binding.agent_id] = primary_identity
            built.append((profile, owner, target, primary_identity))

        for profile, owner, target, identity in built:
            await self.send(
                faucet,
                dest=owner,
                amount=INTEGRATED_OWNER_FUNDING,
                body=Builder().end_cell(),
                label=f"integrated-owner-{profile.binding.name}-fund",
            )
            await self.retry(
                lambda owner=owner: self.balance(owner),
                timeout=60,
                description=f"integrated owner {profile.binding.name} funded",
                predicate=lambda value: value >= INTEGRATED_OWNER_FUNDING - NANO // 10,
            )
            await self.tosctl(
                primary,
                "wallet",
                "activate",
                "--name",
                profile.owner_wallet_alias,
            )
            deployed = await self.tosctl_json(
                primary,
                "agent",
                "account",
                "deploy",
                "--wallet",
                profile.profile_name,
                "--from",
                profile.owner_wallet_alias,
                "--workchain",
                "0",
                "--amount",
                f"{INTEGRATED_AGENT_ACCOUNT_FUNDING // NANO}",
                "--yes",
            )
            if raw_address(Address(deployed.get("address", ""))) != raw_address(target):
                raise RuntimeError(
                    f"deployed Agent Account target mismatch for {profile.binding.name}"
                )
            funded_balance = await self.retry(
                lambda target=target: self.balance(target),
                timeout=90,
                description=f"campaign Agent Account {profile.binding.name} funded",
                predicate=lambda value: value > INTEGRATED_NOMINATOR_DEPOSIT,
            )
            self.event(
                "campaign_agent_account_deployed",
                agent=profile.binding.name,
                campaign_account_address=raw_address(target),
                configured_owner_funding_message_value_nanotos=INTEGRATED_OWNER_FUNDING,
                configured_deploy_message_value_nanotos=INTEGRATED_AGENT_ACCOUNT_FUNDING,
                observed_post_deploy_balance_nanotos=funded_balance,
                accounting_boundary=(
                    "configured message values are operator inputs; observed balance is the "
                    "separate chain measurement after deployment effects"
                ),
            )
            self.nominators.append(
                Nominator(
                    index=len(self.nominators),
                    wallet=None,
                    key=None,
                    agent=profile.binding,
                    address=target,
                    agent_profile_name=profile.profile_name,
                    tosctl_config=primary,
                    deployment_id=profile.deployment_id,
                    state_identity=identity,
                    funded_balance=funded_balance,
                    deposit_message_value=INTEGRATED_NOMINATOR_DEPOSIT,
                )
            )

        # Deployment persists the address only in the primary config.  The
        # other two owner-private RPC views use the same immutable profile and
        # need the same explicit target for OpenFox corroboration/status calls.
        for config in self.working_configs[1:]:
            document, _ = read_owner_private_json(config.path)
            for profile in self.integrated_profiles:
                document["agent_wallets"][profile.profile_name]["agent_account_address"] = (
                    profile.binding.campaign_account_address
                )
            write_owner_private_json(config.path, document)

        # Corroborate deployed getters through all three process views before
        # making the two secondary configs read-only.  This demonstrates
        # agreement between process observations on one host, not independent
        # operator or Byzantine finality.
        getter_observations: dict[str, list[dict[str, Any]]] = {}
        for profile in self.integrated_profiles:
            expected = self.agent_account_state_identities[profile.binding.agent_id]
            views: list[dict[str, Any]] = []
            for index, config in enumerate(self.working_configs):
                status = await self.retry(
                    lambda config=config, profile=profile: self.tosctl_json(
                        config.path,
                        "agent",
                        "account",
                        "status",
                        "--wallet",
                        profile.profile_name,
                        "--workchain",
                        "0",
                    ),
                    timeout=90,
                    description=(
                        f"Agent Account {profile.binding.name} visible through RPC process "
                        f"view {index + 1}"
                    ),
                    predicate=lambda value: (
                        value.get("matches_profile") is True
                        and value.get("template_matches") is True
                    ),
                    interval=1,
                )
                try:
                    status_address = raw_address(Address(status["address"]))
                    status_owner = raw_address(Address(status["owner"]))
                except (KeyError, TypeError, ValueError) as error:
                    raise RuntimeError("Agent Account status identity is malformed") from error
                policy = expected["policy"]
                matches = (
                    status_address == expected["address"]
                    and status_owner == expected["owner"]
                    and status.get("deployment_id") == expected["deployment_id"]
                    and status.get("controller_pubkey") == expected["controller_pubkey"]
                    and status.get("code_hash") == expected["code_hash"]
                    and status.get("metadata_hash") == expected["metadata_hash"]
                    and status.get("service_endpoint_hash") == expected["service_endpoint_hash"]
                    and status.get("max_per_tx") == policy["max_per_tx"]
                    and status.get("daily_limit") == policy["daily_limit"]
                    and status.get("default_task_timeout_secs")
                    == policy["default_task_timeout_secs"]
                    and status.get("template_matches") is True
                    and status.get("matches_profile") is True
                )
                if not matches:
                    raise RuntimeError(
                        f"Agent Account getter mismatch for {profile.binding.name} "
                        f"on RPC process view {index + 1}"
                    )
                views.append(
                    {
                        "process_view_index": index + 1,
                        "matches_profile": True,
                        "template_matches": True,
                        "controller_epoch": status.get("controller_epoch"),
                        "seqno": status.get("seqno"),
                    }
                )
            getter_observations[profile.binding.agent_id] = views
        for config in self.working_configs[1:]:
            os.chmod(config.path, 0o400)

        self.all_nominators.extend(self.nominators)
        exact_bindings = {
            nominator.agent.agent_id: raw_address(nominator.delegation_address)
            for nominator in self.nominators
            if nominator.agent is not None
        }
        self.check(
            "every campaign Agent Account target is rebuilt and deployed without exporting keys",
            len(exact_bindings) == OPENFOX_AGENT_COUNT
            and all(
                exact_bindings[binding.agent_id] == binding.campaign_account_address
                for binding in self.agent_bindings
            ),
            bindings=exact_bindings,
            state_init_identities=self.agent_account_state_identities,
            getter_process_views=getter_observations,
            source_config_digest=self.source_config_digest,
            custody="inherited VAULT_URL; no key material exported",
            owner_funding_per_account_nanotos=INTEGRATED_OWNER_FUNDING,
            campaign_account_funding_per_account_nanotos=INTEGRATED_AGENT_ACCOUNT_FUNDING,
            working_config_permissions={
                str(config.path): oct(stat.S_IMODE(config.path.stat().st_mode))
                for config in self.working_configs
            },
        )

    async def fund_wallets(self) -> None:
        assert self.network is not None
        faucet = self.network.zerostate.main_wallet(self.client)

        for index in range(len(self.nodes)):
            funding = self.pool_validator_funding if index == 0 else self.direct_validator_funding
            before = await self.wallet_seqno(faucet)
            wallet = await faucet.deploy(
                WalletV1Blueprint(workchain=-1),
                CurrencyCollection(tomis=funding),
                seqno=before,
            )
            await self.retry(
                lambda: self.wallet_seqno(faucet),
                timeout=60,
                description=f"validator wallet {index} funded",
                predicate=lambda value, before=before: value > before,
            )
            self.wallets.append(wallet)

        if self.integrated_mode:
            await self.deploy_integrated_agent_accounts(faucet)
            first_control_index = OPENFOX_AGENT_COUNT
        else:
            first_control_index = 0

        # Default mode creates eight identity-bound sidecar proxies. Integrated
        # mode already deployed the exact eight campaign Agent Accounts above.
        # Both modes add one lifecycle-only post-stake zero-reward control.
        count = (
            CONTROL_NOMINATOR_COUNT
            if self.integrated_mode
            else len(self.agent_bindings) + CONTROL_NOMINATOR_COUNT
        )
        for offset in range(count):
            index = first_control_index + offset
            before = await self.wallet_seqno(faucet)
            funding = (
                self.nominator_deposit_value + 2 * NANO
                if self.integrated_mode
                else NOMINATOR_FUNDING
            )
            wallet = await faucet.deploy(
                WalletV1Blueprint(workchain=0),
                CurrencyCollection(tomis=funding),
                seqno=before,
            )
            await self.retry(
                lambda: self.wallet_seqno(faucet),
                timeout=60,
                description=f"nominator wallet {index} funded",
                predicate=lambda value, before=before: value > before,
            )
            binding = (
                self.agent_bindings[index]
                if not self.integrated_mode and index < len(self.agent_bindings)
                else None
            )
            funded_balance = await self.retry(
                lambda wallet=wallet: self.balance(wallet.address),
                timeout=60,
                description=f"nominator wallet {index} balance observed",
                predicate=lambda value: value > self.nominator_deposit_value,
            )
            nominator = Nominator(
                index=index,
                wallet=wallet,
                key=wallet.key,
                agent=binding,
                funded_balance=funded_balance,
                deposit_message_value=self.nominator_deposit_value,
            )
            self.nominators.append(nominator)
            self.all_nominators.append(nominator)

        before = await self.wallet_seqno(faucet)
        self.rescuer = await faucet.deploy(
            WalletV1Blueprint(workchain=0),
            CurrencyCollection(tomis=RESCUER_FUNDING),
            seqno=before,
        )
        await self.retry(
            lambda: self.wallet_seqno(faucet),
            timeout=60,
            description="rescuer wallet funded",
            predicate=lambda value, before=before: value > before,
        )

        self.event(
            "wallets_funded",
            validators=len(self.wallets),
            nominators=len(self.nominators),
            openfox_holders=sum(n.agent is not None for n in self.nominators),
            lifecycle_controls=sum(n.agent is None for n in self.nominators),
            rescuer=raw_address(self.rescuer.address),
        )
        self.check(
            "nominator wallets are in the basechain",
            all(n.delegation_address.wc == 0 for n in self.nominators),
        )
        self.check(
            "every nominator funding balance is positively observed",
            all(n.funded_balance > n.deposit_message_value for n in self.nominators),
        )

    async def deploy_pool(self) -> None:
        """Deploy the pool from the compiled artifact, at its derived address."""
        if self.network is None or self.client is None:
            raise AssertionError("PQ pool deployment needs a running chain")
        if self.controller_code is None or self.single_pool_code is None:
            raise AssertionError("PQ pool deployment needs compiled controller and pool code")
        if len(self.controllers) != len(self.nodes) or len(self.wallets) != len(self.nodes):
            raise AssertionError("each PQ validator needs a controller and operator wallet")
        faucet = self.network.zerostate.main_wallet(self.client)
        for index, controller in enumerate(self.controllers):
            await self.send(
                faucet, dest=controller.address, amount=10 * NANO,
                body=Cell.empty(), init=controller.state_init,
                label=f"controller-{index + 1}-deploy",
            )
            async def controller_code() -> bytes:
                return (await self.client.raw_get_account_state(controller.address)).code

            code_boc = await self.retry(
                controller_code, timeout=60,
                description=f"controller {index + 1} deployment",
                predicate=bool,
            )
            actual_code = Cell.one_from_boc(code_boc).hash
            if actual_code != self.controller_code.hash:
                raise AssertionError(
                    f"controller {index + 1} deployed unexpected code: "
                    f"expected={self.controller_code.hash.hex()} actual={actual_code.hex()}"
                )

        build = subprocess.run(
            [str(REPO / "scripts/build-nominator-pool-v1.sh")],
            capture_output=True,
            text=True,
            check=True,
        )
        artifact = None
        for line in build.stdout.splitlines():
            if line.startswith("output="):
                artifact = Path(line.split("=", 1)[1])
        if artifact is None:
            raise RuntimeError("build script did not report an output path")
        self.pool_code = Cell.one_from_boc(artifact.read_bytes())

        validator_wallet = self.wallets[0]
        validator_account = validator_wallet.address.hash_part
        state_init = build_pool_state_init(
            self.pool_code,
            validator_account=validator_account,
            controller_account=self.controllers[0].address.hash_part,
            reward_share_bps=VALIDATOR_REWARD_SHARE_BPS,
            max_nominators=MAX_NOMINATORS,
            min_validator_stake=self.min_validator_stake,
            min_nominator_stake=self.min_nominator_stake,
        )
        self.pool_address = Address((-1, state_init.serialize().hash))

        # pool.fc always reads an opcode, so a bare value transfer would abort
        # and leave the account uninitialized. op 1 is its accept-coins path.
        await self.send(
            validator_wallet,
            dest=self.pool_address,
            amount=POOL_DEPLOY_VALUE,
            body=pool_message(1, int(time.time())),
            label="pool-deploy",
            init=state_init,
        )
        data = await self.retry(
            self.pool_data,
            timeout=90,
            description="pool deployed and answering get-methods",
            predicate=lambda value: value.state == POOL_STATE_IDLE,
        )
        self.event(
            "pool_deployed",
            address=raw_address(self.pool_address),
            code_hash=self.pool_code.hash.hex(),
            state=data.state_name,
        )
        self.check("pool starts idle with no nominators", data.nominators_count == 0)

        for index in range(1, len(self.nodes)):
            wallet = self.wallets[index]
            pool = make_pool_fixture(
                self.single_pool_code, wallet.address, self.controllers[index].address
            )
            self.support_pools[index] = pool
            await self.send(
                wallet, dest=pool.address, amount=10 * NANO,
                body=Cell.empty(), init=pool.state_init,
                label=f"support-pool-{index + 1}-deploy",
            )
            async def support_pool_code() -> bytes:
                return (await self.client.raw_get_account_state(pool.address)).code

            code_boc = await self.retry(
                support_pool_code, timeout=60,
                description=f"support pool {index + 1} deployment",
                predicate=bool,
            )
            actual_code = Cell.one_from_boc(code_boc).hash
            if actual_code != self.single_pool_code.hash:
                raise AssertionError(
                    f"support pool {index + 1} deployed unexpected code: "
                    f"expected={self.single_pool_code.hash.hex()} actual={actual_code.hex()}"
                )
            # Two concurrent election principals are required to keep the
            # network rotating while the primary pool waits to recover.
            capital = SUPPORT_POOL_CAPITAL
            await self.send(
                wallet, dest=pool.address, amount=capital,
                body=Cell.empty(), label=f"support-pool-{index + 1}-capital",
            )
            observed_capital = await self.retry(
                lambda: self.balance(pool.address), timeout=60,
                description=f"support pool {index + 1} funded",
                predicate=lambda value: value >= capital,
            )
            self.event(
                "support_pool_ready", validator=index + 1,
                pool=raw_address(pool.address),
                controller=raw_address(self.controllers[index].address),
                code_hash=actual_code.hex(), capital_nanotos=observed_capital,
            )

    async def deposit(self) -> None:
        agent_nominators = [n for n in self.nominators if n.agent is not None]
        for nominator in agent_nominators:
            assert self.pool_address is not None
            nominator.wallet_balance_before_deposit = await self.balance(
                nominator.delegation_address
            )
            await self.send_nominator(
                nominator,
                amount=self.nominator_deposit_value,
                body=text_command("d"),
                label=f"nominator-{nominator.index}-deposit",
                action="deposit",
            )
            nominator.deposited = self.nominator_deposit_value - DEPOSIT_PROCESSING_FEE
            nominator.wallet_balance_after_deposit = await self.retry(
                lambda nominator=nominator: self.balance(nominator.delegation_address),
                timeout=90,
                description=f"nominator {nominator.index} deposit debited",
                predicate=lambda value, nominator=nominator: (
                    value < nominator.wallet_balance_before_deposit
                    and nominator.wallet_balance_before_deposit - value
                    >= nominator.deposit_message_value
                ),
            )

        data = await self.retry(
            self.pool_data,
            timeout=120,
            description=f"all {self.agent_subject} deposits recorded",
            predicate=lambda value: value.nominators_count == len(agent_nominators),
        )
        self.check(
            f"every {self.agent_subject} is on the pool's ledger",
            data.nominators_count == len(agent_nominators),
            recorded=data.nominators_count,
        )
        agent_positions = {
            n.agent.agent_id: await self.nominator_amount(n)
            for n in self.nominators
            if n.agent is not None
        }
        self.check(
            f"every {self.agent_subject} delegates only part of its funded balance",
            len(agent_positions) == OPENFOX_AGENT_COUNT
            and all(
                value == self.nominator_deposit_value - DEPOSIT_PROCESSING_FEE
                for value in agent_positions.values()
            )
            and all(
                valid_nominator_funding_observation(n)
                for n in self.nominators
                if n.agent is not None
            ),
            delegated_principal=agent_positions,
            deposit_message_value_nanotos=self.nominator_deposit_value,
            deposit_processing_fee_nanotos=DEPOSIT_PROCESSING_FEE,
        )
        if self.integrated_mode:
            self.check(
                "each campaign Agent Account sends exactly 5 TOS and records exactly 4 TOS",
                self.nominator_deposit_value == 5 * NANO
                and DEPOSIT_PROCESSING_FEE == NANO
                and all(value == 4 * NANO for value in agent_positions.values()),
                sender_addresses={
                    n.agent.agent_id: raw_address(n.delegation_address)
                    for n in agent_nominators
                    if n.agent is not None
                },
                deposit_message_value_nanotos=self.nominator_deposit_value,
                deposit_processing_fee_nanotos=DEPOSIT_PROCESSING_FEE,
                recorded_principal_nanotos=4 * NANO,
            )

        # The validator's own funds go in through the deposit opcode, which is
        # what the punishment guard measures.
        await self.send(
            self.wallets[0],
            dest=self.pool_address,
            amount=self.validator_own_deposit,
            body=pool_message(4, int(time.time())),
            label="validator-own-deposit",
        )
        data = await self.retry(
            self.pool_data,
            timeout=90,
            description="validator's own stake recorded",
            predicate=lambda value: value.validator_amount >= self.min_validator_stake,
        )
        self.check(
            "validator's own funds cover the minimum it must post",
            data.validator_amount >= self.min_validator_stake,
            validator_amount=data.validator_amount,
            required=self.min_validator_stake,
        )

    async def record_campaign_start_positions(self) -> None:
        """Freeze the eight liquid/locked positions before any election reward."""
        if not self.integrated_mode:
            return
        positions: list[dict[str, Any]] = []
        for nominator in self.nominators:
            if nominator.agent is None:
                continue
            active, pending = await self.nominator_components(nominator)
            positions.append(
                {
                    "agent": nominator.agent.name,
                    "agent_id": nominator.agent.agent_id,
                    "campaign_account_address": raw_address(nominator.delegation_address),
                    "liquid_balance_nanotos": await self.balance(nominator.delegation_address),
                    "locked_active_nanotos": active,
                    "locked_pending_nanotos": pending,
                    "locked_total_nanotos": active + pending,
                    "captured_at": utc_now(),
                }
            )
        self.campaign_start_positions = positions
        self.check(
            "all eight campaign Agent Accounts have explicit liquid and locked start positions",
            len(positions) == OPENFOX_AGENT_COUNT
            and all(position["liquid_balance_nanotos"] > 0 for position in positions)
            and all(position["locked_total_nanotos"] == 4 * NANO for position in positions),
            positions=positions,
        )

    async def deposit_control_while_staked(self) -> None:
        """Deposit a same-sized control only after the election stake is active.

        Its value is retained as pending principal and must receive exactly no
        reward for this round.  This distinguishes stake-time participation
        from merely having a wallet label or sending money before recovery.
        """
        assert self.pool_address is not None
        control = next((n for n in self.nominators if n.agent is None), None)
        if control is None:
            raise RuntimeError("lifecycle control nominator is missing")
        control.wallet_balance_before_deposit = await self.balance(control.delegation_address)
        if control.wallet is None:
            raise RuntimeError("post-stake control wallet is missing")
        await self.send(
            control.wallet,
            dest=self.pool_address,
            amount=self.nominator_deposit_value,
            body=text_command("d"),
            label="post-stake-control-deposit",
        )
        control.deposited = self.nominator_deposit_value - DEPOSIT_PROCESSING_FEE
        control.wallet_balance_after_deposit = await self.balance(control.delegation_address)
        active, pending = await self.retry(
            lambda: self.nominator_components(control),
            timeout=90,
            description="post-stake control deposit recorded as pending",
            predicate=lambda value: value == (0, control.deposited),
        )
        data = await self.pool_data()
        self.check(
            "a post-stake control deposit is pending and not reward-active",
            active == 0
            and pending == control.deposited
            and data.nominators_count == OPENFOX_AGENT_COUNT + CONTROL_NOMINATOR_COUNT,
            active=active,
            pending=pending,
            nominators=data.nominators_count,
        )

    async def leave_while_idle(self) -> None:
        """Between rounds a nominator can simply walk away.

        pool.fc pays out immediately when the pool is idle, because the money
        is right there. This is the benign case, and it is worth pinning
        because the hostile one below looks identical from the outside.
        """
        assert self.pool_address is not None
        leaver = next((n for n in self.nominators if n.agent is None), None)
        if leaver is None:
            raise RuntimeError("lifecycle control nominator is missing")
        before = await self.balance(leaver.wallet.address)
        await self.send(
            leaver.wallet,
            dest=self.pool_address,
            amount=NANO,
            body=text_command("w"),
            label="idle-withdrawal",
        )
        data = await self.retry(
            self.pool_data,
            timeout=90,
            description="idle withdrawal settles immediately",
            predicate=lambda value: value.nominators_count == len(self.nominators) - 1,
        )
        after = await self.retry(
            lambda: self.balance(leaver.wallet.address),
            timeout=90,
            description="the leaver is paid",
            predicate=lambda value: value > before,
        )
        self.check(
            "leaving between rounds pays out without waiting",
            data.nominators_count == len(self.nominators) - 1 and after > before,
            paid=after - before,
            deposited=leaver.deposited,
        )
        self.nominators = [n for n in self.nominators if n is not leaver]
        self.check(
            "the non-participant control has no pool position",
            data.nominators_count == len(self.nominators),
            wallet=raw_address(leaver.wallet.address),
            nominators=data.nominators_count,
        )

    async def queue_withdrawal_while_staked(self) -> None:
        """Asking to leave mid-round leaves a request the pool cannot settle.

        The principal is with the Elector, so the contract can only write the
        request down. What matters is what that request then does to the pool:
        it blocks the next stake outright, and recovery does not clear it.
        """
        assert self.pool_address is not None
        leaver = next(
            (n for n in reversed(self.nominators) if n.agent is not None),
            None,
        )
        if leaver is None:
            raise RuntimeError("no OpenFox holder is available for the queued-withdrawal test")
        self.queued_leaver = leaver
        await self.send_nominator(
            leaver,
            amount=NANO,
            body=text_command("w"),
            label="staked-withdrawal-request",
            action="withdraw",
        )
        await asyncio.sleep(8)
        queued = await self.has_withdraw_requests()
        data = await self.pool_data()
        self.check(
            "a mid-round request is recorded rather than paid",
            queued and data.nominators_count == len(self.nominators),
            queued=queued,
            nominators=data.nominators_count,
        )

    async def has_withdraw_requests(self) -> bool:
        assert self.pool_address is not None
        output = await self.runmethod(raw_address(self.pool_address), "has_withdraw_requests")
        match = re.search(r"result:\s*\[\s*(-?\d+)", output)
        if match is None:
            raise RuntimeError(f"cannot parse has_withdraw_requests: {output[-800:]}")
        return int(match.group(1)) != 0

    async def stake_must_be_refused(self, election_id: int) -> None:
        """The refusal that takes a pool out of service without saying so."""
        assert self.client is not None and self.pool_address is not None
        query_id = await self.stake_through_pool(election_id, label="stake-blocked-by-queue")
        pool_baseline, _ = self.stake_feedback_baselines[query_id]

        async def refusal() -> dict[str, Any] | None:
            transactions, _, complete, _ = await _transactions_since(
                self.client, self.pool_address, pool_baseline
            )
            return _queued_stake_refusal(transactions, query_id) if complete else None

        refused = await self.retry(
            refusal, timeout=120, description="queued stake order rejected by pool VM85",
            predicate=lambda value: value is not None,
        )
        data = await self.pool_data()
        self.check(
            "a queued withdrawal keeps the pool out of the next election",
            refused is not None and data.state == POOL_STATE_IDLE,
            state=data.state_name, query_id=query_id, refusal=refused,
        )

    async def drain_withdraw_queue(self) -> None:
        """What the daemon's maintenance pass does, and why it has to."""
        assert self.pool_address is not None
        leaver = self.queued_leaver
        if leaver is None or leaver not in self.nominators:
            raise RuntimeError("queued OpenFox holder is missing")
        before = await self.balance(leaver.delegation_address)
        leaver.payout_entitlement = await self.nominator_amount(leaver)
        leaver.payout_wallet_before = before
        await self.send(
            self.rescuer,
            dest=self.pool_address,
            amount=NANO // 5,
            body=pool_message(2, int(time.time()), extra=Builder().store_uint(8, 8).end_cell()),
            label="process-withdraw-requests",
        )
        data = await self.retry(
            self.pool_data,
            timeout=120,
            description="withdraw queue drained",
            predicate=lambda value: value.nominators_count == len(self.nominators) - 1,
        )
        after = await self.retry(
            lambda: self.balance(leaver.delegation_address),
            timeout=90,
            description="the queued leaver is paid",
            predicate=lambda value: value > before,
        )
        leaver.payout_wallet_after = after
        self.check(
            "draining the queue pays the leaver and frees the pool",
            data.nominators_count == len(self.nominators) - 1 and after > before,
            paid=after - before,
            pool_entitlement=leaver.payout_entitlement,
        )
        self.nominators = [n for n in self.nominators if n is not leaver]
        self.queued_leaver = None
        self.check(
            "the queue is empty afterwards",
            not await self.has_withdraw_requests(),
        )

    async def support_chain_snapshot(self, label: str) -> dict[str, Any]:
        """Keep raw chain reads for every support owner and election window."""
        assert self.client is not None
        self.support_snapshot_number += 1
        prefix = f"support-{self.support_snapshot_number:04d}"

        def preserve(name: str, output: str) -> str:
            path = self.artifacts_dir / f"{prefix}-{name}.txt"
            path.write_text(output)
            return str(path)

        config_raw = await self.lite("time", "getconfig 34")
        past_raw = await self.runmethod(raw_address(ELECTOR), "past_elections_list")
        participant_raw = await self.runmethod(raw_address(ELECTOR), "participant_list_extended")
        elector_state = await self.client.raw_get_account_state(ELECTOR)
        current = re.search(r"utime_since:(\d+)", config_raw)
        if current is None:
            raise RuntimeError("support snapshot cannot identify live ConfigParam 34")
        current_id = int(current.group(1))
        current_hash = int.from_bytes((await self.client.get_config_param(34)).hash, "big")
        past = parse_past_elections_list(past_raw)
        prior_hash = self.support_set_hashes.get(current_id)
        if prior_hash is not None and prior_hash != current_hash:
            raise RuntimeError(f"support election {current_id} ConfigParam 34 hash changed")
        self.support_set_hashes[current_id] = current_hash
        for election_id, record in past.items():
            known_hash = self.support_set_hashes.get(election_id)
            if known_hash is not None and record["vset_hash"] != known_hash:
                raise RuntimeError(f"support election {election_id} past vset hash changed")
            if (
                election_id != current_id and known_hash is not None
                and record["unfreeze_at"] > elector_state.sync_utime
            ):
                # This is the actual time reset by update_active_vset_id,
                # not election_id + elected_for + frozen_for.
                previous = self.support_retired_past.get(election_id)
                if previous is not None and record["unfreeze_at"] < previous["unfreeze_at"]:
                    raise RuntimeError(
                        f"support election {election_id} unfreeze time moved backwards"
                    )
                self.support_retired_past[election_id] = dict(record)
        pools: dict[int, dict[str, Any]] = {}
        for index, pool in sorted(self.support_pools.items()):
            account = await self.client.raw_get_account_state(pool.address)
            pool_raw = await self.runmethod(raw_address(pool.address), "get_pool_data")
            credit_raw = await self.runmethod(
                raw_address(ELECTOR), "compute_returned_stake",
                "0x" + pool.address.hash_part.hex(),
            )
            pools[index] = {
                "address": raw_address(pool.address),
                "balance_nanotos": account.balance,
                "account_sync_utime": account.sync_utime,
                "pool_data_raw": preserve(f"pool-{index}-get_pool_data", pool_raw),
                "credit_raw": preserve(f"pool-{index}-compute_returned_stake", credit_raw),
                "elector_credit_nanotos": elector_credit_from_output(credit_raw),
                "submitted_election_ids": sorted(self.support_submitted[index]),
                "recovered_election_ids": sorted(self.support_recovered[index]),
            }
            pools[index]["election_retention"] = {
                election_id: support_election_retention_state(
                    election_id, current_set_id=current_id,
                    known_set_hashes=self.support_set_hashes,
                    live_past=past, retired_past=self.support_retired_past,
                    chain_utime=elector_state.sync_utime,
                    credit=pools[index]["elector_credit_nanotos"],
                )
                for election_id in self.support_submitted[index]
            }
        snapshot = {
            "label": label,
            "chain_utime": elector_state.sync_utime,
            "current_config34_since": current_id,
            "current_config34_hash": current_hash,
            "past_elections": past,
            "retired_past_observed": dict(self.support_retired_past),
            "stakeable_election_id": stakeable_election_id_from_live_status(
                participant_raw, elector_state.sync_utime
            ),
            "config34_raw": preserve("getconfig-34", config_raw),
            "past_elections_raw": preserve("past_elections_list", past_raw),
            "participant_list_raw": preserve("participant_list_extended", participant_raw),
            "pool_data_semantics": (
                "single-nominator get_pool_data reports compatibility state/counters; "
                "neither is used to prove Elector credit maturity"
            ),
            "pools": pools,
        }
        self.event("support_chain_snapshot", **snapshot)
        return snapshot

    async def recover_support_pool(
        self, index: int, election_ids: list[int], before: dict[str, Any]
    ) -> None:
        """Recover only chain-matured owner credit via that pool's own opcode."""
        assert self.client is not None
        pool = self.support_pools[index]
        owner = before["pools"][index]
        credit = owner["elector_credit_nanotos"]
        baseline = (await self.client.raw_get_account_state(pool.address)).last_transaction_id
        if baseline is None:
            raise RuntimeError(f"support pool {index} has no pre-recovery transaction cursor")
        query_id = time.time_ns()
        # A refused or unobserved fee-bearing recovery must not be sent again
        # by the next keeper tick merely because its credit remains visible.
        self.support_recovery_attempted[index].update(election_ids)
        self.event(
            "support_recovery_order", index=index, election_ids=election_ids,
            query_id=query_id, credit_nanotos=credit,
            balance_before_nanotos=owner["balance_nanotos"],
            baseline_lt=str(baseline.lt), baseline_hash=baseline.hash.hex(),
        )
        await self.send(
            self.wallets[index], dest=pool.address, amount=NANO,
            body=pool_message(0x47657424, query_id),
            label=f"support-pool-{index}-recover-stake",
        )
        deadline = time.monotonic() + 60
        last_scan: dict[str, Any] = {}
        while time.monotonic() < deadline:
            transactions, pages, complete, latest = await _transactions_since(
                self.client, pool.address, baseline
            )
            last_scan = {
                "transactions_scanned": len(transactions), "pages_scanned": pages,
                "baseline_covered": complete, "latest_lt": str(latest.lt),
            }
            if not complete:
                raise RuntimeError(f"support pool {index} recovery history is incomplete: {last_scan}")
            reply = elector_reply(transactions, query_id)
            if reply is not None:
                opcode, detail = reply
                reply_boc = None
                for transaction in transactions:
                    message = transaction.in_msg
                    if (
                        message is None or message.source is None
                        or Address(message.source.account_address) != ELECTOR
                        or not isinstance(message.msg_data, toslib_api.Msg_dataRaw)
                    ):
                        continue
                    body = Cell.one_from_boc(message.msg_data.body).begin_parse()
                    if body.remaining_bits >= 96 and body.load_uint(32) == opcode \
                            and body.load_uint(64) == query_id:
                        reply_boc = message.msg_data.body.hex()
                        break
                self.event(
                    "support_recovery_reply", index=index, query_id=query_id,
                    opcode=f"0x{opcode:08x}", detail=detail,
                    reply_boc_hex=reply_boc, **last_scan,
                )
                if opcode != 0xF96F7324 or detail != 0 or reply_boc is None:
                    raise AssertionError(
                        f"support pool {index} recovery refused: opcode=0x{opcode:08x} "
                        f"detail={detail}, query_id={query_id}"
                    )
                await self.retry(
                    lambda: self.elector_returned_stake_for(pool.address),
                    timeout=60, description=f"support pool {index} credit consumed",
                    predicate=lambda value: value == 0,
                )
                balance_after = await self.retry(
                    lambda: self.balance(pool.address), timeout=60,
                    description=f"support pool {index} credit returned to owner",
                    predicate=lambda value: value >= owner["balance_nanotos"] + credit - 2 * NANO,
                )
                self.support_recovered[index].update(election_ids)
                self.event(
                    "support_pool_recovered", index=index, election_ids=election_ids,
                    query_id=query_id, balance_before_nanotos=owner["balance_nanotos"],
                    balance_after_nanotos=balance_after, credit_nanotos=credit,
                )
                await self.support_chain_snapshot(f"support-{index}-recovered")
                return
            await asyncio.sleep(2)
        raise TimeoutError(
            f"support pool {index} recovery reply for query {query_id} not observed: {last_scan}"
        )

    async def keep_elections_alive(self) -> None:
        """Rotate support validators, reusing only chain-proven matured capital."""
        while True:
            poll_seconds = 20
            try:
                snapshot = await self.support_chain_snapshot("keeper-poll")
                election_id = snapshot["stakeable_election_id"]
                for index in range(1, len(self.nodes)):
                    pool = snapshot["pools"][index]
                    eligible = recoverable_support_election_ids(
                        submitted=self.support_submitted[index],
                        recovered=self.support_recovered[index],
                        current_set_id=snapshot["current_config34_since"],
                        current_set_hash=snapshot["current_config34_hash"],
                        known_set_hashes=self.support_set_hashes,
                        retired_past=self.support_retired_past,
                        live_past=snapshot["past_elections"],
                        chain_utime=snapshot["chain_utime"],
                        credit=pool["elector_credit_nanotos"],
                    )
                    if eligible and not any(
                        election in self.support_recovery_attempted[index]
                        for election in eligible
                    ):
                        await self.recover_support_pool(index, eligible, snapshot)
                        pool["balance_nanotos"] = await self.balance(self.support_pools[index].address)
                    if not election_id or election_id in self.support_submitted[index]:
                        continue
                    if pool["balance_nanotos"] < POOL_STAKE_VALUE + MIN_TOS_FOR_STORAGE:
                        continue
                    if await self.stakeable_election_id() != election_id:
                        break
                    await self.stake_support_pool(index, election_id)
                    self.support_submitted[index].add(election_id)
                poll_seconds = support_keeper_poll_seconds(
                    chain_utime=snapshot["chain_utime"],
                    retired_past=self.support_retired_past,
                    submitted=self.support_submitted,
                    recovered=self.support_recovered,
                )
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - report the missed rotation
                self.event("keep_elections_alive_error", error=repr(error))
            await asyncio.sleep(poll_seconds)

    async def authorized_pool_order(
        self, index: int, election_id: int, pool_address: Address, *, query_id: int | None = None
    ) -> Cell:
        """Node authority plus the production builder; no local stake signer."""
        node = self.nodes[index]
        controller = self.controllers[index]
        request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(
            election_date=election_id,
            max_factor=MAX_FACTOR,
            adnl_addr=node.validator_key.id,
            stake_owner=pool_address.hash_part,
        )
        auth = request.parse_result(await node.engine_console.request(request))
        if auth.validator_id != controller.address.hash_part:
            raise AssertionError(f"validator {index + 1} authorized the wrong controller")
        if auth.key_id != controller.consensus.key_id:
            raise AssertionError(f"validator {index + 1} authorized the wrong consensus key")
        if auth.algorithm_id != 1 or auth.public_key != controller.consensus.public_key:
            raise AssertionError(f"validator {index + 1} authorization differs from its bound key")
        return build_production_pool_stake_order(
            REPO / "tosctl/src/target/debug/examples/pq_pool_stake_order",
            query_id=time.time_ns() if query_id is None else query_id, stake_amount=POOL_STAKE_VALUE,
            stake_at=election_id, max_factor=MAX_FACTOR,
            adnl_addr=node.validator_key.id, algorithm_id=auth.algorithm_id,
            public_key=auth.public_key, signature=auth.signature,
            witness=controller.birth_witness,
        )

    async def stake_support_pool(self, index: int, election_id: int) -> None:
        """Keep a PQ controller-backed candidate beside the primary pool."""
        pool = self.support_pools[index]
        body = await self.authorized_pool_order(index, election_id, pool.address)
        await self.send(
            self.wallets[index], dest=pool.address, amount=POOL_STAKE_GAS,
            body=body, label=f"support-validator-{index}-pool-stake",
        )
        controller_id = int.from_bytes(self.controllers[index].address.hash_part, "big")
        await self.retry(
            lambda: self.elector_participant_ids(), timeout=120,
            description=f"support controller {index + 1} accepted by Elector",
            predicate=lambda ids: controller_id in ids,
        )

    async def elector_participant_ids(self) -> set[int]:
        return participant_ids_from_runmethod(
            await self.runmethod(raw_address(ELECTOR), "participant_list_extended")
        )

    async def stake_through_pool(self, election_id: int, *, label: str) -> int:
        if self.pool_address is None:
            raise AssertionError("primary pool is not deployed")
        query_id = time.time_ns()
        body = await self.authorized_pool_order(
            0, election_id, self.pool_address, query_id=query_id
        )
        cursor_evidence: dict[str, Any] = {}
        if label in ("pool-stake", "pool-stake-after-drain", "stake-blocked-by-queue"):
            assert self.client is not None
            pool_cursor = (await self.client.raw_get_account_state(
                self.pool_address
            )).last_transaction_id
            controller_cursor = (await self.client.raw_get_account_state(
                self.controllers[0].address
            )).last_transaction_id
            if pool_cursor is None or controller_cursor is None:
                raise RuntimeError("cannot establish pre-order pool/controller transaction cursors")
            self.stake_feedback_baselines[query_id] = (pool_cursor, controller_cursor)
            cursor_evidence = {
                "pool_pre_order_cursor_lt": str(pool_cursor.lt),
                "pool_pre_order_cursor_hash": pool_cursor.hash.hex(),
                "controller_pre_order_cursor_lt": str(controller_cursor.lt),
                "controller_pre_order_cursor_hash": controller_cursor.hash.hex(),
            }
        if await self.stakeable_election_id(capture_query_id=query_id) != election_id:
            raise RuntimeError(
                f"pool stake election window closed or changed before send: {election_id}"
            )
        self.event(
            "pool_stake_order", label=label, election_id=election_id,
            query_id=query_id, **cursor_evidence,
        )
        await self.send(
            self.wallets[0], dest=self.pool_address, amount=POOL_STAKE_GAS,
            body=body, label=label,
        )
        return query_id

    async def record_pool_stake_feedback(self, query_id: int, *, label: str) -> None:
        """Record exact on-chain feedback without treating an absent reply as a refusal."""
        assert self.client is not None and self.pool_address is not None
        controller_address = self.controllers[0].address
        pool_baseline, controller_baseline = self.stake_feedback_baselines[query_id]
        details: dict[str, Any] = {
            "label": label, "query_id": query_id,
            "elector_reply": None, "controller_bounce": None,
            "controller_relay": None,
            "pool_order_transaction_lt": None,
            "pool_transactions_scanned": 0, "controller_transactions_scanned": 0,
            "pool_pages_scanned": 0, "controller_pages_scanned": 0,
            "pool_window_complete": False, "controller_window_complete": False,
            "pool_pre_order_cursor_lt": str(pool_baseline.lt),
            "pool_pre_order_cursor_hash": pool_baseline.hash.hex(),
            "controller_pre_order_cursor_lt": str(controller_baseline.lt),
            "controller_pre_order_cursor_hash": controller_baseline.hash.hex(),
            "pool_latest_cursor_lt": None, "controller_latest_cursor_lt": None,
            "collection_errors": {},
        }
        try:
            pool_transactions, pages, complete, latest = await _transactions_since(
                self.client, self.pool_address, pool_baseline
            )
            details["pool_transactions_scanned"] = len(pool_transactions)
            details["pool_pages_scanned"] = pages
            details["pool_window_complete"] = complete
            details["pool_latest_cursor_lt"] = str(latest.lt)
            details["pool_order_transaction_lt"] = _pool_order_transaction_lt(
                pool_transactions, query_id
            )
            details["elector_reply"] = elector_reply(pool_transactions, query_id)
            details["controller_bounce"] = pool_controller_bounce(
                pool_transactions, controller_address, query_id
            )
        except Exception as error:  # noqa: BLE001 - preserve the original stake timeout
            details["collection_errors"]["pool"] = repr(error)
        try:
            controller_transactions, pages, complete, latest = await _transactions_since(
                self.client, controller_address, controller_baseline
            )
            details["controller_transactions_scanned"] = len(controller_transactions)
            details["controller_pages_scanned"] = pages
            details["controller_window_complete"] = complete
            details["controller_latest_cursor_lt"] = str(latest.lt)
            details["controller_relay"] = controller_relay_result(
                controller_transactions, self.pool_address, query_id
            )
        except Exception as error:  # noqa: BLE001 - preserve the original stake timeout
            details["collection_errors"]["controller"] = repr(error)
        details["classification"] = (
            "INCONCLUSIVE" if not details["pool_window_complete"]
            or details["pool_order_transaction_lt"] is None
            else "ELECTOR_REPLY_OBSERVED" if details["elector_reply"] is not None
            else "CONTROLLER_BOUNCE_OBSERVED" if details["controller_bounce"] is not None
            else "INCONCLUSIVE"
        )
        self.event("pool_stake_feedback", **details)

    async def nominator_components(self, nominator: Nominator) -> tuple[int, int]:
        assert self.pool_address is not None
        output = await self.runmethod(
            raw_address(self.pool_address),
            "get_nominator_data",
            "0x" + nominator.delegation_address.hash_part.hex(),
        )
        match = re.search(r"result:\s*\[\s*(\d+)\s+(\d+)", output)
        if match is None:
            raise RuntimeError(f"cannot parse get_nominator_data: {output[-800:]}")
        return int(match.group(1)), int(match.group(2))

    async def nominator_amount(self, nominator: Nominator) -> int:
        amount, pending = await self.nominator_components(nominator)
        return amount + pending

    async def announce_validator_set_changes(self, *, target: int) -> None:
        """Tell the pool the validator set moved, until it has counted enough.

        Nothing does this on its own, and until the count is high enough the
        recover path refuses outright -- with every nominator's principal still
        at the Elector. This is the single most consequential thing a keeper
        does for a pool.
        """
        assert self.pool_address is not None
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            data = await self.pool_data()
            if data.validator_set_changes_count >= target:
                self.check(
                    "the pool has counted enough validator set changes to recover",
                    True,
                    counted=data.validator_set_changes_count,
                    required=target,
                )
                return
            # Sent by the rescuer, not the validator. pool.fc puts no sender
            # restriction on this, and that is the whole point: the counter it
            # advances is what unlocks recovery.
            await self.send(
                self.rescuer,
                dest=self.pool_address,
                amount=NANO // 5,
                body=pool_message(6, int(time.time())),
                label="update-validator-set",
            )
            await asyncio.sleep(15)
        self.check(
            "the pool has counted enough validator set changes to recover",
            False,
            counted=(await self.pool_data()).validator_set_changes_count,
            required=target,
        )

    async def recover(self) -> None:
        assert self.pool_address is not None
        before = {n.index: await self.nominator_amount(n) for n in self.nominators}
        pool_before = await self.pool_data()
        staked = pool_before.stake_amount_sent
        returned_credit = await self.retry(
            self.elector_returned_stake,
            timeout=900,
            description="the Elector exposes a positive matured pool credit",
            predicate=lambda value: value > staked,
            interval=5,
        )
        active_principal: dict[int, int] = {}
        pending_principal: dict[int, int] = {}
        for nominator in self.all_nominators:
            amount, pending = await self.nominator_components(nominator)
            active_principal[nominator.index] = amount
            pending_principal[nominator.index] = pending
        total_active_principal = sum(active_principal.values())
        total_pending_principal = sum(pending_principal.values())
        reward_active_principal = pool_before.validator_amount + total_active_principal
        total_ledger_principal = reward_active_principal + total_pending_principal
        (
            gross_election_reward,
            validator_election_reward,
            nominator_election_reward,
            election_reward_floor,
        ) = election_reward_distribution(
            returned_credit,
            staked,
            VALIDATOR_REWARD_SHARE_BPS,
            active_principal,
        )

        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            await self.send(
                self.rescuer,
                dest=self.pool_address,
                amount=NANO // 2,
                body=pool_message(0x47657424, int(time.time())),
                label="recover-stake",
            )
            await asyncio.sleep(15)
            if (await self.pool_data()).state == POOL_STATE_IDLE:
                break

        data = await self.pool_data()
        self.check(
            "the stake comes back and the pool goes idle",
            data.state == POOL_STATE_IDLE and data.stake_amount_sent == 0,
            state=data.state_name,
            stake_amount_sent=data.stake_amount_sent,
        )
        remaining_credit = await self.retry(
            self.elector_returned_stake,
            timeout=60,
            description="Elector consumed the primary pool's recovered credit",
            predicate=lambda value: value == 0,
        )
        self.check(
            "the Elector no longer holds a recoverable primary-pool credit",
            remaining_credit == 0,
            remaining_credit_nanotos=remaining_credit,
        )

        after = {n.index: await self.nominator_amount(n) for n in self.nominators}
        for nominator in self.nominators:
            nominator.principal_before_recovery = before[nominator.index]
            nominator.principal_after_recovery = after[nominator.index]
        grew = [index for index, value in after.items() if value > before[index]]
        self.check(
            "every nominator's principal is at least what it was",
            all(after[index] >= before[index] for index in after),
            before=before,
            after=after,
        )
        agents = [n for n in self.nominators if n.agent is not None]
        control = next((n for n in self.nominators if n.agent is None), None)
        agent_rewards = {n.agent.agent_id: n.reward for n in agents if n.agent is not None}
        agent_election_floors = {
            n.agent.agent_id: election_reward_floor[n.index] for n in agents if n.agent is not None
        }
        self.check(
            f"every {self.agent_subject} gets positive ledger credit with an election-reward lower bound",
            len(agent_rewards) == OPENFOX_AGENT_COUNT
            and gross_election_reward > 0
            and all(reward > 0 for reward in agent_election_floors.values())
            and all(
                agent_rewards[agent_id] is not None and agent_rewards[agent_id] >= floor
                for agent_id, floor in agent_election_floors.items()
            ),
            rewards=agent_rewards,
            election_reward_floor=agent_election_floors,
            gross_election_reward=gross_election_reward,
        )
        self.check(
            "the post-stake control receives zero reward for this round",
            control is not None and control.reward == 0,
            reward=control.reward if control is not None else None,
        )
        self.pool_reward_evidence = {
            "stake_amount_sent_nanotos": staked,
            "effective_stake_nanotos": NETWORK_MIN_STAKE,
            "reward_active_principal_at_stake_nanotos": reward_active_principal,
            "pending_principal_nanotos": total_pending_principal,
            "total_ledger_principal_nanotos": total_ledger_principal,
            "non_reward_effective_surplus_nanotos": max(
                0, reward_active_principal - NETWORK_MIN_STAKE
            ),
            "surplus_earns_network_reward": False,
            "elector_returned_credit_nanotos": returned_credit,
            "gross_election_reward_nanotos": gross_election_reward,
            "validator_election_reward_nanotos": validator_election_reward,
            "nominator_election_reward_nanotos": nominator_election_reward,
            "election_id": pool_before.stake_at,
            "validator_reward_share_bps": VALIDATOR_REWARD_SHARE_BPS,
            "nominator_ledger_reward_nanotos": sum(
                reward for reward in agent_rewards.values() if reward is not None
            ),
            "agent_election_reward_floor_nanotos": agent_election_floors,
            "ledger_delta_attribution": "exact",
            "election_reward_attribution": "lower-bound-only",
            "attribution_caveat": (
                "the pool recovery reply combines Elector credit with residual keeper message "
                "value; exact ledger deltas can exceed the election-derived lower bound"
            ),
        }
        self.event(
            "distribution",
            staked=staked,
            rewarded_nominators=grew,
            before=before,
            after=after,
            openfox_agent_rewards=agent_rewards,
            post_stake_control_reward=control.reward if control is not None else None,
        )

    async def check_solvency(self) -> None:
        """The invariant nothing in the contract enforces.

        pool.fc's ledger says what each nominator is owed; the balance is what
        is actually there. Storage rent moves the second and not the first, so
        the two only stay equal while something is watching them.
        """
        assert self.pool_address is not None
        balance = await self.balance(self.pool_address)
        # The post-stake control wallet is created up front but does not yet
        # exist in the contract's nominator dictionary on the first call. The
        # getter deliberately throws 86 for an absent address, so only query
        # positions whose deposit has been confirmed by the lifecycle.
        recorded_nominators = [n for n in self.nominators if n.deposited > 0]
        owed = sum([await self.nominator_amount(n) for n in recorded_nominators])
        self.check(
            "the pool covers nominator obligations plus its storage reserve",
            balance >= owed + MIN_TOS_FOR_STORAGE,
            balance=balance,
            owed=owed,
            reserve=MIN_TOS_FOR_STORAGE,
        )

    async def run_fift(self, script: Path, *args: str) -> str:
        command = [str(self.install.fift_exe)]
        for include in self.install.fift_include_dirs:
            command += ["-I", str(include)]
        command += ["-s", str(script), *args]

        def run() -> str:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=True)
            return result.stdout

        return await asyncio.to_thread(run)

    async def finalize_integrated_evidence_boundary(self) -> None:
        """Prove all scripted custody actions ended before ready publication."""
        if not self.integrated_mode:
            return
        expected_actions = OPENFOX_AGENT_COUNT + 1
        deposits = [item for item in self.agent_action_evidence if item["action"] == "deposit"]
        withdrawals = [item for item in self.agent_action_evidence if item["action"] == "withdraw"]
        for item in withdrawals:
            nominator = next(
                (
                    candidate
                    for candidate in self.all_nominators
                    if candidate.agent is not None and candidate.agent.agent_id == item["agent_id"]
                ),
                None,
            )
            if nominator is not None:
                item["withdrawal_settlement"] = {
                    "pool_entitlement_nanotos": nominator.payout_entitlement,
                    "wallet_balance_before_nanotos": nominator.payout_wallet_before,
                    "wallet_balance_after_nanotos": nominator.payout_wallet_after,
                    "wallet_credit_nanotos": (
                        nominator.payout_wallet_after - nominator.payout_wallet_before
                        if nominator.payout_wallet_after is not None
                        and nominator.payout_wallet_before is not None
                        else None
                    ),
                    "payout_address": raw_address(nominator.delegation_address),
                }
        self.check(
            "every scripted campaign Agent Account pool action is journal-bound and finalized before ready",
            len(self.agent_action_evidence) == expected_actions
            and len(deposits) == OPENFOX_AGENT_COUNT
            and len(withdrawals) == 1
            and len({item["action_id"] for item in self.agent_action_evidence}) == expected_actions
            and all(item["amount_nanotos"] == 5 * NANO for item in deposits)
            and withdrawals[0]["amount_nanotos"] == NANO
            and withdrawals[0].get("withdrawal_settlement", {}).get("wallet_credit_nanotos", 0) > 0,
            actions=self.agent_action_evidence,
            primary_config_only=str(self.working_configs[0].path),
            secondary_configs_read_only=[
                {
                    "path": str(config.path),
                    "mode": oct(stat.S_IMODE(config.path.stat().st_mode)),
                }
                for config in self.working_configs[1:]
            ],
            authorization_boundary=INTEGRATED_OPERATOR_ACTION_LIMIT,
        )

    async def current_rpc_checkpoints(self) -> list[dict[str, Any]]:
        checkpoints = []
        for index, config in enumerate(self.working_configs):
            response = await asyncio.to_thread(
                json_rpc_call, config.rpc_address, "getMasterchainInfo"
            )
            block = response.get("result", {}).get("last")
            checkpoints.append(
                {
                    "process_view_index": index + 1,
                    "observed_at": utc_now(),
                    "block": canonical_rpc_block_id(block),
                }
            )
        return checkpoints

    async def write_readiness_descriptor(self) -> None:
        if not self.integrated_mode:
            return
        assert self.ready_out is not None
        assert self.network_domain is not None
        if self.final_report is None or self.final_report.get("passed") is not True:
            raise RuntimeError("refusing to publish ready before a complete passing lifecycle")
        ready_positions: list[dict[str, Any]] = []
        for nominator in self.all_nominators:
            if nominator.agent is None:
                continue
            locked = (
                0
                if nominator.payout_entitlement is not None
                else await self.nominator_amount(nominator)
            )
            ready_positions.append(
                {
                    "agent": nominator.agent.name,
                    "agent_id": nominator.agent.agent_id,
                    "campaign_account_address": raw_address(nominator.delegation_address),
                    "delegation_wallet": raw_address(nominator.delegation_address),
                    "configured_deploy_message_value_nanotos": (INTEGRATED_AGENT_ACCOUNT_FUNDING),
                    "liquid_balance_nanotos": await self.balance(nominator.delegation_address),
                    "locked_pool_ledger_nanotos": locked,
                    "deployment_id": nominator.deployment_id,
                    "state_init_identity": nominator.state_identity,
                }
            )
        report_path = self.evidence_out or (self.run_dir / "report.json")
        report_raw = report_path.read_bytes()
        descriptor = {
            "schema": INTEGRATED_READY_SCHEMA,
            "status": "ready",
            "ready_at": utc_now(),
            "campaign_run_id": self.campaign_run_id,
            "network": INTEGRATED_NETWORK,
            "evidence_class": INTEGRATED_EVIDENCE_CLASS,
            "network_domain": self.network_domain,
            "genesis_attempt_scope": {
                "binding": self.genesis_attempt_scope_binding,
                "global_id": self.network_global_id,
                "derivation": "campaign_run_id+durable-evidence-attempt-id",
            },
            "operator_scope": "same-host-single-operator",
            "rpc_process_views": self.rpc_readiness,
            "current_block_checkpoints": await self.current_rpc_checkpoints(),
            "tosctl_configs": {
                "primary_action_config": str(self.working_configs[0].path),
                "secondary_read_only_configs": [
                    str(config.path) for config in self.working_configs[1:]
                ],
            },
            "campaign_start_positions": self.campaign_start_positions,
            "campaign_ready_positions": ready_positions,
            "pool": {
                "address": raw_address(self.pool_address),
                "code_hash": self.pool_code.hash.hex(),
                "min_nominator_stake_nanotos": self.min_nominator_stake,
                "deposit_message_value_nanotos": self.nominator_deposit_value,
                "deposit_processing_fee_nanotos": DEPOSIT_PROCESSING_FEE,
                "recorded_principal_per_agent_nanotos": 4 * NANO,
            },
            "completed_before_ready": {
                "deposits": OPENFOX_AGENT_COUNT,
                "positive_rewards": all(
                    nominator.reward is not None and nominator.reward > 0
                    for nominator in self.all_nominators
                    if nominator.agent is not None
                ),
                "withdrawal_settlements": 1,
                "task_send_actions": len(self.agent_action_evidence),
            },
            "task_send_after_ready": False,
            "authorization_boundary": INTEGRATED_OPERATOR_ACTION_LIMIT,
            "claim_limit": INTEGRATED_SINGLE_HOST_LIMIT,
            "post_ready_claim_boundary": (
                "This descriptor proves only the completed pre-ready delegation lifecycle. "
                "The companion OpenFox completion artifact must independently prove the "
                "subsequent campaign duration, network continuity, and payment outcomes."
            ),
            "lifecycle_evidence": {
                "path": str(report_path),
                "digest": "sha256:" + hashlib.sha256(report_raw).hexdigest(),
            },
            "hold_until_stop_file": str(self.hold_until) if self.hold_until else None,
        }
        write_owner_private_json(self.ready_out, descriptor)
        self.ready_written = True
        self.event(
            "integrated_network_ready_published",
            descriptor=str(self.ready_out),
            network_domain=self.network_domain,
            genesis_attempt_scope={
                "binding": self.genesis_attempt_scope_binding,
                "global_id": self.network_global_id,
                "derivation": "campaign_run_id+durable-evidence-attempt-id",
            },
            task_send_after_ready=False,
        )

    async def hold_integrated_network(self) -> None:
        if not self.integrated_mode or self.hold_until is None:
            return
        self.event("integrated_network_hold_started", stop_file=str(self.hold_until))
        last_health = 0.0
        while not self.hold_until.exists():
            now = time.monotonic()
            if now - last_health >= 15:
                checkpoints = await self.current_rpc_checkpoints()
                self.event("integrated_network_hold_health", checkpoints=checkpoints)
                last_health = now
            await asyncio.sleep(2)
        details = self.hold_until.lstat()
        if self.hold_until.is_symlink() or not stat.S_ISREG(details.st_mode):
            raise RuntimeError("hold-until stop marker must be a regular file")
        self.event("integrated_network_hold_completed", stop_file=str(self.hold_until))

    async def execute(self) -> int:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        upkeep: asyncio.Task | None = None
        try:
            self.prepare_integrated_mode()
            self.event(
                "prelaunch_funding_budget",
                **require_lifecycle_funding_budget(
                    integrated=self.integrated_mode, agent_count=len(self.agent_bindings)
                ),
            )
            self.prepare_pq_election_fixture()
            await self.bring_up_network()
            await self.fund_wallets()
            await self.deploy_pool()
            await self.deposit()
            await self.record_campaign_start_positions()
            await self.check_solvency()

            # One owner of the other validators' stakes, so nobody enters the
            # same election twice. Each of them holds exactly two principals,
            # and spending both on one round leaves the network unable to elect
            # a successor -- which looks identical to the contract refusing to
            # recover.
            upkeep = asyncio.create_task(self.keep_elections_alive())

            election_id = await self.retry(
                self.stakeable_election_id,
                timeout=900,
                description="an election has a live stake acceptance window",
                predicate=lambda value: value > 0,
            )
            self.event("election_open", election_id=election_id)
            query_id = await self.stake_through_pool(election_id, label="pool-stake")
            try:
                data = await self.retry(
                    self.pool_data,
                    timeout=180,
                    description="the Elector accepts the pool's stake",
                    predicate=lambda value: value.state == POOL_STATE_STAKED,
                )
            except Exception:
                try:
                    await self.record_pool_stake_feedback(query_id, label="pool-stake")
                except Exception as evidence_error:  # noqa: BLE001 - preserve stake failure
                    self.event("pool_stake_feedback_error", error=repr(evidence_error))
                raise
            await self.record_pool_stake_feedback(query_id, label="pool-stake")
            self.check(
                "the pool is a participant in the election",
                data.state == POOL_STATE_STAKED
                and data.stake_at == election_id
                and data.stake_amount_sent >= NETWORK_MIN_STAKE,
                stake_amount_sent=data.stake_amount_sent,
                stake_at=data.stake_at,
                expected_election_id=election_id,
            )

            await self.deposit_control_while_staked()
            await self.record_pool_validator_selection(election_id)

            # From here the validator does nothing. Everything that follows --
            # telling the pool the set moved, pulling the stake back from the
            # Elector, settling the withdrawal queue -- is driven by a wallet
            # with no standing in the pool at all.
            self.count_validator_sends = True

            await self.queue_withdrawal_while_staked()
            await self.announce_validator_set_changes(target=2)
            await self.recover()

            # The post-stake control becomes ordinary principal only after the
            # distribution.  It can now leave while idle, proving both its
            # zero reward for the prior round and ordinary withdrawal liveness.
            await self.leave_while_idle()

            self.check(
                "recovering does not settle a queued withdrawal",
                await self.has_withdraw_requests(),
            )

            next_election = await self.retry(
                self.stakeable_election_id,
                timeout=900,
                description="the next election has a live stake acceptance window",
                predicate=lambda value: value > 0 and value != election_id,
            )
            # This leg is the validator deliberately trying to stake and being
            # refused, which is the opposite of abandoning the pool. It is not
            # part of the exit path, so it does not count against the claim
            # that the exit path needs nothing from them.
            self.count_validator_sends = False
            await self.stake_must_be_refused(next_election)
            self.count_validator_sends = True

            await self.drain_withdraw_queue()

            # The property a depositor actually needs when a validator stops
            # answering: their principal came back, and getting it back took
            # nothing from the validator.
            self.check(
                "a staked pool is recovered and paid out without the validator",
                self.validator_sends_after_stake == 0,
                validator_messages_during_recovery_and_payout=self.validator_sends_after_stake,
            )
            self.count_validator_sends = False

            await self.check_solvency()

            # A pool that has lost depositors can fall below the network's
            # minimum stake and lose the ability to participate at all. From
            # outside that is indistinguishable from still being blocked by the
            # queue it just cleared, so name it before staking rather than
            # letting the next wait time out ambiguously.
            pool_balance = await self.balance(self.pool_address)
            self.check(
                "the pool still holds enough to meet the network minimum",
                pool_balance >= POOL_STAKE_VALUE + MIN_TOS_FOR_STORAGE,
                balance=pool_balance,
                required=POOL_STAKE_VALUE + MIN_TOS_FOR_STORAGE,
                nominators_remaining=len(self.nominators),
            )

            # A fresh id rather than the one captured before the queue was
            # drained: draining takes long enough that the earlier election has
            # closed, and the Elector refuses a stake for a finished one --
            # which looks exactly like the pool still being blocked.
            final_election = await self.retry(
                self.stakeable_election_id,
                timeout=900,
                description="an election with an open pool-stake acceptance window",
                predicate=lambda value: value > 0,
            )
            # The election may rotate while the retry returns; do not sign or
            # send for an ID whose live accepting window just closed.
            if await self.stakeable_election_id() != final_election:
                raise RuntimeError("final pool-stake election changed or closed before the order")
            final_query_id = await self.stake_through_pool(
                final_election, label="pool-stake-after-drain"
            )
            try:
                data = await self.retry(
                    self.pool_data,
                    timeout=180,
                    description="the pool can stake again once the queue is clear",
                    predicate=lambda value: value.state == POOL_STATE_STAKED,
                )
            except TimeoutError:
                await self.record_pool_stake_feedback(
                    final_query_id, label="pool-stake-after-drain"
                )
                raise
            self.check(
                "draining the queue lets the pool back into an election",
                data.state == POOL_STATE_STAKED,
                state=data.state_name,
            )
            await self.finalize_integrated_evidence_boundary()
            self.write_report()
            await self.write_readiness_descriptor()
            await self.hold_integrated_network()
        except Exception as error:  # noqa: BLE001 - recorded in the report
            self.event("aborted", error=repr(error))
            self.failures.append(f"aborted: {error!r}")
        finally:
            if upkeep is not None:
                upkeep.cancel()
                try:
                    await upkeep
                except asyncio.CancelledError:
                    pass
            await self.shutdown()

        self.write_report()
        return 1 if self.failures else 0

    async def shutdown(self) -> None:
        if self.network is not None:
            # Network owns the DHT as well as the validators. Stopping only
            # self.nodes leaves its DHT child running after the report is written.
            try:
                await self.network.aclose()
            except Exception as error:  # noqa: BLE001 - preserve the run report
                self.event("network_shutdown_error", error=repr(error))
                self.failures.append(f"network shutdown failed: {error!r}")

    def write_report(self) -> None:
        if self.report_written:
            return
        # Everything this run is supposed to establish, whether or not it got
        # there. A release gate reading only the checks that ran cannot tell a
        # leg that passed from one the run never reached, and an aborted run
        # would look like a shorter clean one. Absence has to be visible.
        expected = [
            "the pool covers nominator obligations plus its storage reserve",
            "every nominator funding balance is positively observed",
            f"every {self.agent_subject} is on the pool's ledger",
            f"every {self.agent_subject} delegates only part of its funded balance",
            "validator's own funds cover the minimum it must post",
            "a post-stake control deposit is pending and not reward-active",
            "leaving between rounds pays out without waiting",
            "the non-participant control has no pool position",
            "the pool is a participant in the election",
            "the pool validator is selected into ConfigParam 34",
            "a mid-round request is recorded rather than paid",
            "the pool has counted enough validator set changes to recover",
            "the stake comes back and the pool goes idle",
            "every nominator's principal is at least what it was",
            f"every {self.agent_subject} gets positive ledger credit with an election-reward lower bound",
            "the post-stake control receives zero reward for this round",
            "recovering does not settle a queued withdrawal",
            "a queued withdrawal keeps the pool out of the next election",
            "draining the queue pays the leaver and frees the pool",
            "a staked pool is recovered and paid out without the validator",
            "the pool still holds enough to meet the network minimum",
            "draining the queue lets the pool back into an election",
        ]
        if self.integrated_mode:
            expected += [
                "three distinct RPC process views under one local operator expose the exact unified genesis",
                "every campaign Agent Account target is rebuilt and deployed without exporting keys",
                "each campaign Agent Account sends exactly 5 TOS and records exactly 4 TOS",
                "all eight campaign Agent Accounts have explicit liquid and locked start positions",
                "every scripted campaign Agent Account pool action is journal-bound and finalized before ready",
            ]
        observed = {entry["check"] for entry in self.report.checks}
        not_exercised = [name for name in expected if name not in observed]

        agent_rewards = []
        for nominator in self.all_nominators:
            if nominator.agent is None:
                continue
            election_floor = self.pool_reward_evidence.get(
                "agent_election_reward_floor_nanotos", {}
            ).get(nominator.agent.agent_id)
            reward_record = {
                "agent": nominator.agent.name,
                "agent_id": nominator.agent.agent_id,
                "campaign_wallet_label": nominator.agent.campaign_wallet_label or None,
                "campaign_account_address": nominator.agent.campaign_account_address or None,
                "delegation_wallet": raw_address(nominator.delegation_address),
                "wallet_funding_nanotos": nominator.funded_balance,
                "wallet_balance_before_deposit_nanotos": nominator.wallet_balance_before_deposit,
                "wallet_balance_after_deposit_nanotos": nominator.wallet_balance_after_deposit,
                "deposit_message_value_nanotos": nominator.deposit_message_value,
                "deposit_processing_fee_nanotos": DEPOSIT_PROCESSING_FEE,
                "recorded_principal_nanotos": nominator.deposited,
                "principal_before_recovery_nanotos": nominator.principal_before_recovery,
                "principal_after_recovery_nanotos": nominator.principal_after_recovery,
                "ledger_reward_delta_nanotos": nominator.reward,
                "election_reward_floor_nanotos": election_floor,
                "attribution_status": (
                    "POSITIVE_LOWER_BOUND"
                    if nominator.reward is not None
                    and election_floor is not None
                    and election_floor > 0
                    and nominator.reward >= election_floor
                    else "NOT_ESTABLISHED"
                ),
                "withdrawal_payout": (
                    {
                        "pool_entitlement_nanotos": nominator.payout_entitlement,
                        "wallet_balance_before_nanotos": nominator.payout_wallet_before,
                        "wallet_balance_after_nanotos": nominator.payout_wallet_after,
                        "wallet_credit_nanotos": (
                            nominator.payout_wallet_after - nominator.payout_wallet_before
                            if nominator.payout_wallet_before is not None
                            and nominator.payout_wallet_after is not None
                            else None
                        ),
                    }
                    if nominator.payout_entitlement is not None
                    else None
                ),
            }
            if self.integrated_mode:
                reward_record["configured_deploy_message_value_nanotos"] = (
                    INTEGRATED_AGENT_ACCOUNT_FUNDING
                )
            agent_rewards.append(reward_record)

        all_nominators = [nominator for nominator in self.all_nominators if nominator.agent is None]
        control = all_nominators[0] if all_nominators else None

        report = {
            "schema": "tos.validator.nominator-reward-experiment.v1",
            "started_at": self.report.started_at,
            "finished_at": utc_now(),
            "network": INTEGRATED_NETWORK if self.integrated_mode else SIDECAR_NETWORK,
            "evidence_class": (
                INTEGRATED_EVIDENCE_CLASS if self.integrated_mode else SIDECAR_EVIDENCE_CLASS
            ),
            "campaign_run_id": self.campaign_run_id,
            "agent_manifest_digest": self.agent_manifest_digest,
            "pool_address": raw_address(self.pool_address) if self.pool_address else None,
            "pool_code_hash": self.pool_code.hash.hex() if self.pool_code else None,
            "pool_config": {
                "validator_reward_share_bps": VALIDATOR_REWARD_SHARE_BPS,
                "max_nominators": MAX_NOMINATORS,
                "min_validator_stake_nanotos": self.min_validator_stake,
                "min_nominator_stake_nanotos": self.min_nominator_stake,
                "network_minimum_effective_stake_nanotos": NETWORK_MIN_STAKE,
                "max_stake_factor": 1,
            },
            "validator_selection": self.pool_validator_selection,
            "reward_evidence": self.pool_reward_evidence,
            "agent_nominator_rewards": agent_rewards,
            "post_stake_control": (
                {
                    "delegation_wallet": raw_address(control.delegation_address),
                    "recorded_principal_nanotos": control.deposited,
                    "principal_before_recovery_nanotos": control.principal_before_recovery,
                    "principal_after_recovery_nanotos": control.principal_after_recovery,
                    "ledger_reward_delta_nanotos": control.reward,
                    "expected_reward_nanotos": 0,
                }
                if control is not None
                else None
            ),
            "claim_limits": [
                (
                    "The delegation wallets are the campaign Agent Accounts on the same genesis used for campaign payments."
                    if self.integrated_mode
                    else "The sidecar wallets are bound to logical OpenFox Agent identities but are not the campaign wallets on the other genesis."
                ),
                "The accelerated election timing is test-only and is not a mainnet APR or production liveness claim.",
                "Only the effective stake earns network reward; pool surplus has no marginal reward at max_stake_factor=1.",
                "Ledger reward delta is exact, but Elector reward attribution is a lower bound because recovery also carries residual keeper value.",
                "Rewards compound inside the pool ledger until a separate withdrawal pays the wallet.",
            ]
            + (
                [INTEGRATED_OPERATOR_ACTION_LIMIT, INTEGRATED_SINGLE_HOST_LIMIT]
                if self.integrated_mode
                else []
            ),
            "checks": self.report.checks,
            "not_exercised": not_exercised,
            "events": self.report.events,
            "failures": self.failures,
            # Complete only when nothing failed and nothing was skipped, so a
            # gate can require this single field instead of restating the list.
            "passed": not self.failures and not not_exercised,
        }
        if self.integrated_mode:
            if self.network_domain is None:
                self.failures.append("integrated network domain was not established")
                report["failures"] = self.failures
                report["passed"] = False
            else:
                report["network_domain"] = self.network_domain
        self.final_report = report
        path = self.run_dir / "report.json"
        encoded = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
        path.write_text(encoded)
        if self.evidence_out is not None:
            assert self.evidence_attempt is not None
            finalize_evidence_attempt(self.evidence_out, self.evidence_attempt, encoded)
        self.report_written = True
        print(f"\nreport: {path}")
        if not_exercised:
            print(f"not exercised ({len(not_exercised)}):")
            for name in not_exercised:
                print(f"  - {name}")
        if report["passed"]:
            print("result: PASS")
        else:
            reasons = []
            if self.failures:
                reasons.append(f"{len(self.failures)} failed")
            if not_exercised:
                reasons.append(f"{len(not_exercised)} not exercised")
            print("result: FAIL (" + ", ".join(reasons) + ")")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=REPO / "build", help="built binaries")
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=REPO / "test/integration/.nominator-pool-lifecycle",
        help="where the network, artifacts and report are written",
    )
    parser.add_argument("--base-port", type=int, default=21000)
    parser.add_argument(
        "--campaign-run-id",
        type=validate_campaign_run_id,
        required=True,
        help="exact bounded identifier shared with the companion OpenFox campaign",
    )
    parser.add_argument(
        "--agent-manifest",
        type=Path,
        required=True,
        help="public eight-Agent OpenFox manifest used to bind sidecar wallets",
    )
    parser.add_argument(
        "--evidence-out",
        type=Path,
        help="optional stable path for an atomic copy of the final JSON evidence",
    )
    parser.add_argument(
        "--integrated-source-config",
        type=Path,
        help=(
            "owner-private tosctl config containing the eight real campaign Agent Account "
            "profiles; enables same-genesis integrated mode"
        ),
    )
    parser.add_argument(
        "--tosctl",
        type=Path,
        help="tosctl binary used by integrated mode (keys stay behind inherited VAULT_URL)",
    )
    parser.add_argument(
        "--rpc-base-port",
        type=int,
        default=23000,
        help="first of three same-host validator JSON-RPC process-view ports",
    )
    parser.add_argument(
        "--ready-out",
        type=Path,
        help="owner-private same-genesis descriptor published only after the lifecycle passes",
    )
    parser.add_argument(
        "--hold-until",
        type=Path,
        help="optional absent stop-file path; keep the live network up until it appears",
    )
    args = parser.parse_args()
    integrated_options = (args.tosctl, args.ready_out, args.hold_until)
    if args.integrated_source_config is None and any(
        option is not None for option in integrated_options
    ):
        parser.error("integrated options require --integrated-source-config")
    if args.integrated_source_config is not None and (
        args.tosctl is None or args.ready_out is None or args.evidence_out is None
    ):
        parser.error(
            "--integrated-source-config requires --tosctl, --ready-out, and --evidence-out"
        )
    return args


async def async_main() -> int:
    args = parse_args()
    evidence_attempt = (
        begin_evidence_attempt(args.evidence_out, args.campaign_run_id)
        if args.evidence_out is not None
        else None
    )
    install = Install(args.build_dir, REPO)
    run_dir = args.run_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    agent_bindings, manifest_digest = load_agent_bindings(args.agent_manifest)
    return await PoolLifecycle(
        install,
        run_dir,
        args.base_port,
        campaign_run_id=args.campaign_run_id,
        agent_bindings=agent_bindings,
        agent_manifest_digest=manifest_digest,
        evidence_out=args.evidence_out,
        evidence_attempt=evidence_attempt,
        integrated_source_config=args.integrated_source_config,
        tosctl_path=args.tosctl,
        rpc_base_port=args.rpc_base_port,
        ready_out=args.ready_out,
        hold_until=args.hold_until,
    ).execute()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
