"""The staking account is fixed before a node joins the Genesis committee, and the
stake orders the rehearsals send are the production builder's bytes."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
import dataclasses
from typing import Any, TypedDict

import pytest
from contract.pq_auth import byte_chain
from pytosiq_core import Address, Builder, Cell
from pytosiq_core.tlb.tlb import require
from tosapi import tos_api, toslib_api
from tostester.pq_election_fixture import (
    assert_staking_identity,
    build_production_pool_stake_order,
    elector_body_from_pool_order,
    elector_reply,
    elector_return_reason,
    make_pool_fixture,
    parse_stake_order,
    participant_ids_from_runmethod,
    require_pq_stake_authorization_binding,
)

ROOT = Path(__file__).resolve().parents[4]
STAKE_ORDER_BUILDER = Path(
    os.environ.get(
        "TOS_PQ_POOL_STAKE_ORDER",
        ROOT / "tosctl/src/target/debug/examples/pq_pool_stake_order",
    )
)


def _pq_bytes(data: bytes) -> Cell:
    return Builder().store_uint(len(data), 32).store_ref(byte_chain(data)).end_cell()


def _order_fields(query_id: int = 19) -> dict[str, Any]:
    return {
        "query_id": query_id,
        "stake_amount": 10_000_000_000_000,
        "stake_at": 1_700_000_000,
        "max_factor": 65_536,
        "adnl_addr": bytes([0x22]) * 32,
        "public_key": bytes([0x11]) * 1312,
        "signature": bytes([0x33]) * 2420,
    }


def _hand_built_pool_order(fields: dict[str, Any]) -> Cell:
    """The single-nominator parser order, written out once to test the reader."""
    return (
        Builder()
        .store_uint(0x4E73744B, 32)
        .store_uint(fields["query_id"], 64)
        .store_coins(fields["stake_amount"])
        .store_uint(1, 16)
        .store_ref(_pq_bytes(fields["public_key"]))
        .store_uint(fields["stake_at"], 32)
        .store_uint(fields["max_factor"], 32)
        .store_bytes(fields["adnl_addr"])
        .store_ref(_pq_bytes(fields["signature"]))
        .end_cell()
    )


def _from(source: Address, body: Cell) -> SimpleNamespace:
    return SimpleNamespace(
        in_msg=SimpleNamespace(
            source=toslib_api.AccountAddress(source.to_str()),
            msg_data=toslib_api.Msg_dataRaw(body=body.to_boc()),
        )
    )


def test_elector_recovery_answer_has_no_trailing_amount():
    elector = Address((-1, bytes.fromhex("33" * 32)))
    bare = Builder().store_uint(0xF96F7324, 32).store_uint(9, 64).end_cell()
    assert elector_reply([_from(elector, bare)], 9) == (0xF96F7324, 0)
    with_amount = Builder().store_uint(0xF96F7324, 32).store_uint(9, 64).store_coins(5).end_cell()
    assert elector_reply([_from(elector, with_amount)], 9) is None


def test_only_the_elector_answers_a_stake():
    pool = Address((-1, bytes([0x51]) * 32))
    accepted = Builder().store_uint(0xF374484C, 32).store_uint(127, 64).store_uint(0, 32).end_cell()
    assert elector_reply([_from(pool, accepted)], 127) is None
    assert elector_reply([_from(Address((-1, bytes.fromhex("33" * 32))), accepted)], 127) == (
        0xF374484C,
        0,
    )


def test_pq_stake_authorization_generated_binding_is_complete():
    require_pq_stake_authorization_binding(tos_api.Engine_validator_pqStakeAuthorization)

    class StaleResponse:
        def __init__(self, validator_id, key_id, signature):
            pass

    with pytest.raises(RuntimeError, match="missing=\\['algorithm_id', 'public_key'\\]"):
        require_pq_stake_authorization_binding(StaleResponse)


def test_participant_ids_use_decimal_outer_ids_not_hex_text():
    output = (
        "result: [ 123 120 100 230 ([16 [111 222 16 333]] "
        "[32 [444 555 32 666]]) 0 0 ]\n"
        "remote result (not to be trusted): [ 123 120 100 230 ([99 [0]]) 0 0 ]"
    )
    assert participant_ids_from_runmethod(output) == {16, 32}
    with pytest.raises(ValueError, match="no validator entries"):
        participant_ids_from_runmethod("result: [ 123 120 100 230 () 0 0 ]")


def test_staking_identity_and_pool_roles_are_bound_by_state_init():
    owner = Address((-1, bytes([0x55]) * 32))
    validator = Address((-1, bytes([0x66]) * 32))
    pool = make_pool_fixture(Cell.empty(), owner, validator)
    assert pool.address.hash_part == pool.state_init.serialize().hash
    roles = require(pool.state_init.data).begin_parse()
    assert roles.load_address() == owner
    assert roles.load_address() == validator
    assert roles.remaining_bits == 0 and roles.remaining_refs == 0
    with pytest.raises(ValueError, match="masterchain"):
        make_pool_fixture(Cell.empty(), Address((0, bytes(32))), validator)

    held = SimpleNamespace(validator_id=pool.address.hash_part, key_id=bytes([7]) * 32)
    node = SimpleNamespace(pq_initial_validator=held)
    assert_staking_identity(node, pool.address, index=1)
    held.validator_id = validator.hash_part
    with pytest.raises(AssertionError, match="staking account and PQ validator_id differ"):
        assert_staking_identity(node, pool.address, index=1)
    with pytest.raises(AssertionError, match="no PQ consensus identity"):
        assert_staking_identity(SimpleNamespace(pq_initial_validator=None), pool.address, index=1)


def test_stake_order_reader_follows_the_pool_and_elector_parser_order():
    """A shape-only parse cannot catch adjacent fixed-width field swaps."""
    fields = _order_fields()
    order = _hand_built_pool_order(fields)
    parsed = parse_stake_order(order, with_amount=True)
    assert parsed.query_id == 19
    assert parsed.stake_amount == fields["stake_amount"]
    assert parsed.algorithm_id == 1
    assert parsed.public_key == fields["public_key"]
    assert parsed.stake_at == fields["stake_at"]
    assert parsed.max_factor == fields["max_factor"]
    assert parsed.adnl_addr == fields["adnl_addr"]
    assert parsed.signature == fields["signature"]

    direct = elector_body_from_pool_order(order)
    forwarded = parse_stake_order(direct, with_amount=False)
    assert forwarded.stake_amount is None
    assert forwarded == dataclasses.replace(parsed, stake_amount=None)
    with pytest.raises(ValueError, match="trailing data"):
        parse_stake_order(Builder().store_cell(order).store_uint(0, 1).end_cell(), with_amount=True)
    with pytest.raises(ValueError):
        parse_stake_order(order, with_amount=False)


@pytest.mark.skipif(
    not STAKE_ORDER_BUILDER.is_file(),
    reason="production pool order builder not built "
    "(cargo build -p contracts --example pq_pool_stake_order)",
)
def test_production_builder_writes_the_pool_parser_order():
    fields = _order_fields(23)
    built = build_production_pool_stake_order(STAKE_ORDER_BUILDER, algorithm_id=1, **fields)
    assert built.hash == _hand_built_pool_order(fields).hash
    parsed = parse_stake_order(built, with_amount=True)
    assert (parsed.stake_at, parsed.max_factor, parsed.adnl_addr) == (
        fields["stake_at"],
        fields["max_factor"],
        fields["adnl_addr"],
    )


def test_live_rehearsal_arguments_reach_the_production_builder_bridge(monkeypatch):
    """Execute the caller's keyword interface; a source marker cannot bind it."""
    seen = {}

    def fake_run(command, *, input, text, capture_output, check):
        seen.update(json.loads(input))
        assert command == ["/diagnostic/pq_pool_stake_order"]
        assert text and capture_output and not check
        return SimpleNamespace(returncode=0, stdout=Cell.empty().to_boc().hex(), stderr="")

    monkeypatch.setattr("tostester.pq_election_fixture.subprocess.run", fake_run)

    class StakeArguments(TypedDict):
        query_id: int
        stake_amount: int
        stake_at: int
        max_factor: int
        adnl_addr: bytes
        public_key: bytes
        signature: bytes

    args: StakeArguments = {
        "query_id": 3,
        "stake_amount": 11000000000000,
        "stake_at": 1700000000,
        "max_factor": 65536,
        "adnl_addr": bytes([34]) * 32,
        "public_key": bytes([17]) * 1312,
        "signature": bytes([51]) * 2420,
    }
    result = build_production_pool_stake_order(
        Path("/diagnostic/pq_pool_stake_order"), algorithm_id=1, **args
    )
    assert result == Cell.empty()
    assert set(seen) == {
        "query_id",
        "stake_amount",
        "stake_at",
        "max_factor",
        "adnl_addr_hex",
        "public_key_hex",
        "signature_hex",
    }
    assert seen["query_id"] == 3 and seen["stake_at"] == 1_700_000_000
    assert seen["adnl_addr_hex"] == (bytes([0x22]) * 32).hex()
    assert seen["public_key_hex"] == (bytes([0x11]) * 1312).hex()
    assert seen["signature_hex"] == (bytes([0x33]) * 2420).hex()
    with pytest.raises(ValueError, match="algorithm 1"):
        build_production_pool_stake_order(
            Path("/diagnostic/pq_pool_stake_order"), algorithm_id=2, **args
        )


def test_elector_reason_reader_skips_source_less_wallet_externals_and_pins_query():
    query_id = 0xE1EC7
    body = (
        Builder()
        .store_uint(0xEE6F454C, 32)
        .store_uint(query_id, 64)
        .store_uint(8, 32)
        .end_cell()
        .to_boc()
    )
    external = SimpleNamespace(
        in_msg=SimpleNamespace(
            source=toslib_api.AccountAddress(""), msg_data=toslib_api.Msg_dataRaw(body=body)
        )
    )
    elector = Address((-1, bytes.fromhex("33" * 32)))
    returned = SimpleNamespace(
        in_msg=SimpleNamespace(
            source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
            msg_data=toslib_api.Msg_dataRaw(body=body),
        )
    )
    assert elector_return_reason([external, returned], query_id) == 8
    assert elector_return_reason([external, returned], query_id + 1) is None
    assert elector_return_reason([external], query_id) is None
    accepted_body = (
        Builder()
        .store_uint(0xF374484C, 32)
        .store_uint(query_id, 64)
        .store_uint(0, 32)
        .end_cell()
        .to_boc()
    )
    accepted = SimpleNamespace(
        in_msg=SimpleNamespace(
            source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
            msg_data=toslib_api.Msg_dataRaw(body=accepted_body),
        )
    )
    assert elector_reply([external, accepted], query_id) == (0xF374484C, 0)
    assert elector_return_reason([accepted], query_id) is None
    unknown_body = (
        Builder()
        .store_uint(0xFFFFFFFF, 32)
        .store_uint(query_id, 64)
        .store_uint(7, 32)
        .end_cell()
        .to_boc()
    )
    unknown = SimpleNamespace(
        in_msg=SimpleNamespace(
            source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
            msg_data=toslib_api.Msg_dataRaw(body=unknown_body),
        )
    )
    assert elector_reply([external, unknown], query_id) == (0xFFFFFFFF, 7)
    recovered_body = (
        Builder().store_uint(0xF96F7324, 32).store_uint(query_id, 64).end_cell().to_boc()
    )
    recovered = SimpleNamespace(
        in_msg=SimpleNamespace(
            source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
            msg_data=toslib_api.Msg_dataRaw(body=recovered_body),
        )
    )
    assert elector_reply([recovered], query_id) == (0xF96F7324, 0), (
        "elector mature recovery has no trailing 32-bit detail"
    )
    assert elector_reply([recovered], query_id + 1) is None
    unknown_short_body = (
        Builder().store_uint(0xF96F7325, 32).store_uint(query_id, 64).end_cell().to_boc()
    )
    unknown_short = SimpleNamespace(
        in_msg=SimpleNamespace(
            source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
            msg_data=toslib_api.Msg_dataRaw(body=unknown_short_body),
        )
    )
    assert elector_reply([unknown_short], query_id) is None, (
        "a source-matched 96-bit reply is not automatically mature recovery"
    )
