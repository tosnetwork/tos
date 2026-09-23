"""The controller identity is fixed before a node joins the Genesis committee."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytosiq_core import Address, Cell
from pytosiq_core import Builder
from tosapi import toslib_api

from tostester.install import Install
from tostester.pq_election_fixture import (
    assert_controller_identity,
    build_pool_stake_order,
    build_production_pool_stake_order,
    elector_reply,
    elector_return_reason,
    make_controller_fixture,
    make_pool_fixture,
    participant_ids_from_runmethod,
)

ROOT = Path(__file__).resolve().parents[4]


def test_participant_ids_use_decimal_outer_ids_not_hex_text():
    output = (
        "result: [ 123 120 100 230 ([16 [111 222 16 333]] "
        "[32 [444 555 32 666]]) 0 0 ]\n"
        "remote result (not to be trusted): [ 123 120 100 230 ([99 [0]]) 0 0 ]"
    )
    assert participant_ids_from_runmethod(output) == {16, 32}
    with pytest.raises(ValueError, match="no validator entries"):
        participant_ids_from_runmethod("result: [ 123 120 100 230 () 0 0 ]")


def test_controller_identity_and_pool_roles_are_bound_by_state_init(tmp_path):
    controller = make_controller_fixture(
        Install(ROOT / "build", ROOT), tmp_path / "keys", Cell.empty(), 0
    )
    assert len(controller.birth_witness.bits) == 544
    assert controller.address.hash_part == controller.state_init.serialize().hash

    held = SimpleNamespace(
        validator_id=controller.address.hash_part,
        key_id=controller.consensus.key_id,
    )
    node = SimpleNamespace(pq_initial_validator=held)
    assert_controller_identity(node, controller, index=1)

    held.validator_id = bytes(32)
    with pytest.raises(AssertionError, match="controller address and PQ validator_id differ"):
        assert_controller_identity(node, controller, index=1)
    held.validator_id = controller.address.hash_part
    held.key_id = bytes(32)
    with pytest.raises(AssertionError, match="controller-bound consensus key and node key differ"):
        assert_controller_identity(node, controller, index=1)

    owner = Address((-1, bytes([0x55]) * 32))
    pool = make_pool_fixture(Cell.empty(), owner, controller.address)
    roles = pool.state_init.data.begin_parse()
    assert roles.load_address() == owner
    assert roles.load_address() == owner
    assert roles.load_address() == controller.address
    assert roles.remaining_bits == 0 and roles.remaining_refs == 0


def test_pool_stake_order_round_trips_every_field_in_contract_parser_order():
    """A shape-only pool parse cannot catch adjacent fixed-width field swaps."""
    def pq_bytes(cell: Cell) -> bytes:
        root = cell.begin_parse()
        remaining = root.load_uint(32)
        assert root.remaining_bits == 0 and root.remaining_refs == 1
        chunk = root.load_ref()
        data = bytearray()
        while remaining:
            part = chunk.begin_parse()
            take = min(127, remaining)
            data.extend(part.load_bytes(take))
            remaining -= take
            assert part.remaining_bits == 0
            if remaining:
                assert part.remaining_refs == 1
                chunk = part.load_ref()
            else:
                assert part.remaining_refs == 0
        return bytes(data)

    witness = Cell.empty()
    body = build_pool_stake_order(
        query_id=19, stake_amount=10_000_000_000_000, stake_at=1_700_000_000,
        max_factor=65_536, adnl_addr=bytes([0x22]) * 32, algorithm_id=1,
        public_key=bytes([0x11]) * 1312, signature=bytes([0x33]) * 2420,
        witness=witness,
    )
    view = body.begin_parse()
    assert view.load_uint(32) == 0x4E73744B, "wrong pool NEW_STAKE opcode"
    assert view.load_uint(64) == 19, "wrong stake query ID"
    assert view.load_coins() == 10_000_000_000_000, "wrong declared pool stake"
    assert view.load_uint(32) == 1_700_000_000, "stake_at moved from pool parser order"
    assert view.load_uint(32) == 65_536, "max_factor moved from pool parser order"
    assert view.load_bytes(32) == bytes([0x22]) * 32, "ADNL moved from pool parser order"
    assert view.load_uint(16) == 1, "algorithm_id moved from pool parser order"
    assert pq_bytes(view.load_ref()) == bytes([0x11]) * 1312, "public key changed"
    assert pq_bytes(view.load_ref()) == bytes([0x33]) * 2420, "signature changed"
    assert view.load_maybe_ref() == witness, "birth witness is not the trailing maybe-ref"
    assert view.remaining_bits == 0 and view.remaining_refs == 0, "pool order has trailing data"


def test_live_rehearsal_arguments_reach_the_production_builder_bridge(monkeypatch):
    """Execute the caller's keyword interface; a source marker cannot bind it."""
    seen = {}

    def fake_run(command, *, input, text, capture_output, check):
        seen.update(json.loads(input))
        assert command == ["/diagnostic/pq_pool_stake_order"]
        assert text and capture_output and not check
        return SimpleNamespace(returncode=0, stdout=Cell.empty().to_boc().hex(), stderr="")

    monkeypatch.setattr("tostester.pq_election_fixture.subprocess.run", fake_run)
    witness = Builder().store_uint(7, 32).end_cell()
    args = dict(
        query_id=3, stake_amount=11_000_000_000_000, stake_at=1_700_000_000,
        max_factor=65_536, adnl_addr=bytes([0x22]) * 32,
        public_key=bytes([0x11]) * 1312, signature=bytes([0x33]) * 2420,
        witness=witness,
    )
    result = build_production_pool_stake_order(
        Path("/diagnostic/pq_pool_stake_order"), algorithm_id=1, **args
    )
    assert result == Cell.empty()
    assert seen["query_id"] == 3 and seen["stake_at"] == 1_700_000_000
    assert seen["adnl_addr_hex"] == (bytes([0x22]) * 32).hex()
    assert seen["public_key_hex"] == (bytes([0x11]) * 1312).hex()
    assert seen["signature_hex"] == (bytes([0x33]) * 2420).hex()
    assert seen["witness_boc_hex"] == witness.to_boc().hex()
    with pytest.raises(ValueError, match="algorithm 1"):
        build_production_pool_stake_order(
            Path("/diagnostic/pq_pool_stake_order"), algorithm_id=2, **args
        )


def test_elector_reason_reader_skips_source_less_wallet_externals_and_pins_query():
    query_id = 0xE1EC7
    body = (
        Builder().store_uint(0xEE6F454C, 32).store_uint(query_id, 64)
        .store_uint(8, 32).end_cell().to_boc()
    )
    external = SimpleNamespace(in_msg=SimpleNamespace(
        source=toslib_api.AccountAddress(""), msg_data=toslib_api.Msg_dataRaw(body=body)
    ))
    elector = Address((-1, bytes.fromhex("33" * 32)))
    returned = SimpleNamespace(in_msg=SimpleNamespace(
        source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
        msg_data=toslib_api.Msg_dataRaw(body=body),
    ))
    assert elector_return_reason([external, returned], query_id) == 8
    assert elector_return_reason([external, returned], query_id + 1) is None
    assert elector_return_reason([external], query_id) is None
    accepted_body = (
        Builder().store_uint(0xF374484C, 32).store_uint(query_id, 64)
        .store_uint(0, 32).end_cell().to_boc()
    )
    accepted = SimpleNamespace(in_msg=SimpleNamespace(
        source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
        msg_data=toslib_api.Msg_dataRaw(body=accepted_body),
    ))
    assert elector_reply([external, accepted], query_id) == (0xF374484C, 0)
    assert elector_return_reason([accepted], query_id) is None
    unknown_body = (
        Builder().store_uint(0xFFFFFFFF, 32).store_uint(query_id, 64)
        .store_uint(7, 32).end_cell().to_boc()
    )
    unknown = SimpleNamespace(in_msg=SimpleNamespace(
        source=toslib_api.AccountAddress(elector.to_str(is_user_friendly=True)),
        msg_data=toslib_api.Msg_dataRaw(body=unknown_body),
    ))
    assert elector_reply([external, unknown], query_id) == (0xFFFFFFFF, 7)
