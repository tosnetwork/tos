from __future__ import annotations

import pytest
import tostester.network as network_module
from tostester.network import FullNode
from types import SimpleNamespace
from tostester.pq_initial_validator import (
    make_deterministic_pq_initial_validator,
    make_deterministic_pq_spare_validator,
)


class FakeNode:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, bytes]] = []
        self.spare_calls: list[tuple[bytes, bytes]] = []

    def make_initial_pq_validator(self, validator_id: bytes, seed: bytes) -> None:
        self.calls.append((validator_id, seed))

    def make_noninitial_pq_validator(self, validator_id: bytes, seed: bytes) -> None:
        self.spare_calls.append((validator_id, seed))


def test_deterministic_pq_initial_validator_is_stable_and_indexed() -> None:
    first = FakeNode()
    repeated = FakeNode()
    second = FakeNode()

    make_deterministic_pq_initial_validator(first, 0)
    make_deterministic_pq_initial_validator(repeated, 0)
    make_deterministic_pq_initial_validator(second, 1)

    assert first.calls == repeated.calls
    assert first.calls != second.calls
    assert all(len(value) == 32 for value in first.calls[0])


@pytest.mark.parametrize("index", [-1, 2**32, True])
def test_deterministic_pq_initial_validator_rejects_invalid_index(index: int) -> None:
    with pytest.raises(ValueError, match="outside uint32"):
        make_deterministic_pq_initial_validator(FakeNode(), index)


def test_spare_has_same_deterministic_key_but_never_enters_initial_registration() -> None:
    controller = bytes([0x42]) * 32
    initial = FakeNode()
    spare = FakeNode()
    make_deterministic_pq_initial_validator(initial, 4, validator_id=controller)
    make_deterministic_pq_spare_validator(spare, 4, validator_id=controller)
    assert initial.calls == spare.spare_calls
    assert spare.calls == []


def test_four_genesis_one_spare_topology_is_constructed_by_distinct_calls() -> None:
    nodes = [FakeNode() for _ in range(5)]
    for index, node in enumerate(nodes):
        controller = bytes([index + 1]) * 32
        if index < 4:
            make_deterministic_pq_initial_validator(node, index, validator_id=controller)
        else:
            make_deterministic_pq_spare_validator(node, index, validator_id=controller)
    assert sum(bool(node.calls) for node in nodes) == 4
    assert sum(bool(node.spare_calls) for node in nodes) == 1
    assert nodes[4].calls == []


def test_full_node_spare_custody_does_not_mark_genesis(monkeypatch) -> None:
    observed = []
    monkeypatch.setattr(
        FullNode, "_provision_pq_validator",
        lambda _self, validator_id, seed: observed.append((validator_id, seed)),
    )
    node = object.__new__(FullNode)
    node._is_initial_validator = False
    node.make_noninitial_pq_validator(bytes([0x41]) * 32, bytes([0x42]) * 32)
    assert len(observed) == 1
    assert node.is_initial_validator is False
    node.make_initial_pq_validator(bytes([0x43]) * 32, bytes([0x44]) * 32)
    assert node.is_initial_validator is True
    with pytest.raises(ValueError, match="initial validator"):
        node.make_noninitial_pq_validator(bytes([0x45]) * 32, bytes([0x46]) * 32)


def test_network_zerostate_receives_four_pq_initial_validators_not_spare(
    monkeypatch, tmp_path
) -> None:
    initial = [SimpleNamespace(is_initial_validator=True, pq_initial_validator=index)
               for index in range(4)]
    spare = SimpleNamespace(is_initial_validator=False, pq_initial_validator=4)
    network = object.__new__(network_module.Network)
    network._status = network_module._Status.INITED
    network._directory = tmp_path
    network._install = object()
    network._Network__network_config = object()
    network._Network__full_nodes = [*initial, spare]
    network._Network__zerostate = None
    seen = {}

    def fake_zerostate(_install, _state_dir, _config, classical, pq):
        seen["classical"] = classical
        seen["pq"] = pq
        return object()

    monkeypatch.setattr(network_module, "create_zerostate", fake_zerostate)
    network._get_or_generate_zerostate()
    assert seen == {"classical": [], "pq": [0, 1, 2, 3]}
