"""The controller identity is fixed before a node joins the Genesis committee."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from pytosiq_core import Address, Cell

from tostester.install import Install
from tostester.pq_election_fixture import (
    assert_controller_identity,
    make_controller_fixture,
    make_pool_fixture,
)

ROOT = Path(__file__).resolve().parents[4]


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
