"""Test-only accounts for a real PQ stake through a single-nominator pool to the elector.

A member of an election is named by the account that sends its stake to the elector.
Here that is an upstream single-nominator pool: its operator wallet orders the stake,
the pool forwards the elector body unchanged, and the node's configured validator id
must be the pool's address. The pool and elector bodies come from the production Rust
builder, never from a second Python encoder.
"""

from __future__ import annotations

import inspect
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pytosiq_core import Address, Builder, Cell, StateInit
from tosapi import toslib_api

ELECTOR = Address((-1, bytes.fromhex("33" * 32)))
NEW_STAKE_OP = 0x4E73744B
STAKE_ACCEPTED_OP = 0xF374484C
STAKE_RETURNED_OP = 0xEE6F454C
RECOVERED_OP = 0xF96F7324
MLDSA44_ALGORITHM_ID = 1
MLDSA44_PUBLIC_KEY_BYTES = 1312
MLDSA44_SIGNATURE_BYTES = 2420

_AUTHORIZATION_FIELDS = {
    "validator_id",
    "key_id",
    "algorithm_id",
    "public_key",
    "signature",
}


def require_pq_stake_authorization_binding(response_type: type) -> None:
    """Fail before node boot when ignored generated Python TL is stale."""
    actual = set(inspect.signature(response_type).parameters)
    missing = _AUTHORIZATION_FIELDS - actual
    if missing:
        raise RuntimeError(
            "generated Python TL stake authorization is stale: "
            f"missing={sorted(missing)}; run uv run python test/tostester/generate_tl.py"
        )


@dataclass(frozen=True)
class PoolFixture:
    address: Address
    state_init: StateInit


@dataclass(frozen=True)
class StakeOrder:
    """The fields of a pool NEW_STAKE order, in the order the pool and elector parse them."""

    query_id: int
    stake_amount: int | None
    algorithm_id: int
    public_key: bytes
    stake_at: int
    max_factor: int
    adnl_addr: bytes
    signature: bytes


def make_pool_fixture(code: Cell, owner: Address, validator: Address) -> PoolFixture:
    """An upstream single-nominator pool: storage is exactly (owner, validator).

    The validator wallet is the one that may order a stake; the pool itself is the
    account that reaches the elector, so its address is the election member id.
    """
    if owner.wc != -1 or validator.wc != -1:
        raise ValueError("PQ election fixture needs masterchain owner and validator wallets")
    data = Builder().store_address(owner).store_address(validator).end_cell()
    init = StateInit(code=code, data=data)
    return PoolFixture(Address((-1, init.serialize().hash)), init)


def build_production_pool_stake_order(
    executable: Path,
    *,
    query_id: int,
    stake_amount: int,
    stake_at: int,
    max_factor: int,
    adnl_addr: bytes,
    algorithm_id: int,
    public_key: bytes,
    signature: bytes,
) -> Cell:
    """Invoke the Rust nominator::new_stake builder, not a second Python encoder."""
    if algorithm_id != MLDSA44_ALGORITHM_ID:
        raise ValueError(
            f"production pool order requires ML-DSA-44 algorithm 1, got {algorithm_id}"
        )
    if query_id <= 0 or stake_amount <= 0:
        raise ValueError("pool stake order needs a positive query ID and amount")
    payload = {
        "query_id": query_id,
        "stake_amount": stake_amount,
        "stake_at": stake_at,
        "max_factor": max_factor,
        "adnl_addr_hex": adnl_addr.hex(),
        "public_key_hex": public_key.hex(),
        "signature_hex": signature.hex(),
    }
    result = subprocess.run(
        [str(executable)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"production PQ pool stake builder failed ({result.returncode}): {result.stderr.strip()}"
        )
    try:
        return Cell.one_from_boc(bytes.fromhex(result.stdout.strip()))
    except ValueError as error:
        raise RuntimeError("production PQ pool stake builder returned invalid BOC hex") from error


def _pq_bytes(cell: Cell, expected: int, label: str) -> bytes:
    root = cell.begin_parse()
    remaining = root.load_uint(32)
    if remaining != expected:
        raise ValueError(f"{label} is {remaining} bytes, expected {expected}")
    if root.remaining_bits or root.remaining_refs != 1:
        raise ValueError(f"{label} root is not a length and one chunk reference")
    chunk = root.load_ref()
    data = bytearray()
    while remaining:
        part = chunk.begin_parse()
        take = min(127, remaining)
        data.extend(part.load_bytes(take))
        remaining -= take
        if part.remaining_bits:
            raise ValueError(f"{label} chunk has trailing bits")
        if remaining:
            if part.remaining_refs != 1:
                raise ValueError(f"{label} chunk chain ends early")
            chunk = part.load_ref()
        elif part.remaining_refs:
            raise ValueError(f"{label} chunk chain continues past its length")
    return bytes(data)


def parse_stake_order(body: Cell, *, with_amount: bool) -> StakeOrder:
    """Read a NEW_STAKE body in the parser order of the pool (with_amount) or the elector."""
    view = body.begin_parse()
    if view.load_uint(32) != NEW_STAKE_OP:
        raise ValueError("body is not a NEW_STAKE order")
    query_id = view.load_uint(64)
    stake_amount = view.load_coins() if with_amount else None
    algorithm_id = view.load_uint(16)
    public_key = _pq_bytes(view.load_ref(), MLDSA44_PUBLIC_KEY_BYTES, "public key")
    stake_at = view.load_uint(32)
    max_factor = view.load_uint(32)
    adnl_addr = view.load_bytes(32)
    signature = _pq_bytes(view.load_ref(), MLDSA44_SIGNATURE_BYTES, "signature")
    if view.remaining_bits or view.remaining_refs:
        raise ValueError("NEW_STAKE order has trailing data")
    return StakeOrder(
        query_id, stake_amount, algorithm_id, public_key, stake_at, max_factor, adnl_addr, signature
    )


def elector_body_from_pool_order(order: Cell) -> Cell:
    """The body a pool forwards: the order without its leading stake amount.

    A wallet that stakes directly sends exactly this body, with the stake as the value.
    """
    view = order.begin_parse()
    if view.load_uint(32) != NEW_STAKE_OP:
        raise ValueError("pool order is not a NEW_STAKE order")
    query_id = view.load_uint(64)
    view.load_coins()
    return (
        Builder().store_uint(NEW_STAKE_OP, 32).store_uint(query_id, 64).store_slice(view).end_cell()
    )


def elector_reply(transactions: list[Any], query_id: int) -> tuple[int, int] | None:
    """Find the elector's answer to one request, ignoring other sources and request IDs.

    Answers carry op and query_id; acceptance, refusal and error answers add a 32-bit
    detail, a recovery adds nothing.
    """
    for transaction in transactions:
        message = transaction.in_msg
        if message is None or message.source is None:
            continue
        source_text = message.source.account_address
        if not source_text or Address(source_text) != ELECTOR:
            continue
        if not isinstance(message.msg_data, toslib_api.Msg_dataRaw):
            continue
        reply = Cell.one_from_boc(message.msg_data.body).begin_parse()
        if reply.remaining_bits < 96:
            continue
        opcode = reply.load_uint(32)
        if reply.load_uint(64) != query_id:
            continue
        if opcode == RECOVERED_OP:
            if not reply.remaining_bits and not reply.remaining_refs:
                return opcode, 0
            continue
        if reply.remaining_bits >= 32:
            return opcode, reply.load_uint(32)
    return None


def elector_return_reason(transactions: list[Any], query_id: int) -> int | None:
    reply = elector_reply(transactions, query_id)
    return reply[1] if reply is not None and reply[0] == STAKE_RETURNED_OP else None


def participant_ids_from_runmethod(output: str) -> set[int]:
    """Read outer validator IDs from lite-client's decimal get-method stack."""
    match = re.search(r"\bresult:\s*\[[^\n]*?\(\s*(.*?)\s*\)\s+0\s+0\s*\]", output)
    if match is None:
        raise ValueError("participant_list_extended has no parseable result")
    ids = {int(value) for value in re.findall(r"\[(\d+)\s+\[", match.group(1))}
    if not ids:
        raise ValueError("participant_list_extended has no validator entries")
    return ids


def parse_past_elections_list(output: str) -> dict[int, dict[str, int]]:
    """Read the Elector's actual, possibly reset unfreeze times."""
    result = re.search(r"\bresult:\s*\[(.*?)\]\s*remote result", output, re.S)
    if result is None:
        raise ValueError("Elector past_elections_list has no trusted result")
    body = result.group(1)
    entries = re.findall(r"\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", body)
    if len(entries) != len(re.findall(r"\[\s*\d+", body)):
        raise ValueError("Elector past_elections_list has an unparsed record")
    if not entries and not re.fullmatch(r"\s*\(\s*\)\s*", body):
        raise ValueError("Elector past_elections_list has an unknown empty shape")
    parsed = {
        int(election_id): {
            "unfreeze_at": int(unfreeze_at),
            "vset_hash": int(vset_hash),
            "stake_held": int(stake_held),
        }
        for election_id, unfreeze_at, vset_hash, stake_held in entries
    }
    if len(parsed) != len(entries):
        raise ValueError("Elector past_elections_list repeats an election ID")
    return parsed


def assert_staking_identity(node, staking_account: Address, *, index: int) -> None:
    """The node's configured validator id must be the account that sends its stake."""
    held = node.pq_initial_validator
    if held is None:
        raise AssertionError(f"validator {index} has no PQ consensus identity")
    expected = staking_account.hash_part
    if held.validator_id != expected:
        raise AssertionError(
            f"validator {index} staking account and PQ validator_id differ: "
            f"staking_account={expected.hex()} validator_id={held.validator_id.hex()}"
        )
