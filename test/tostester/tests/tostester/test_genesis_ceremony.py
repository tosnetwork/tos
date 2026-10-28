"""Every genesis PQ validator starts with the genesis ceremony's signing ledger.

A validator without a signing ledger signs nothing until a fence block, and a new chain
whose validators all wait never produces one. The harness therefore runs
`tos-pq-consensus-key init-signing-ledger --genesis-ceremony` for each genesis PQ
validator before its first start. No node is started here: the engine start is replaced,
so nothing binds a port.
"""

import asyncio
import hashlib
import os
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from tostester.install import Install
from tostester.network import FullNode, Network

REPO = Path(__file__).resolve().parents[4]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build"))
# Far from any port a local network uses; nothing is bound in these tests anyway.
BASE_PORT = 47000


def ledger(node: FullNode) -> Path:
    return node.directory / "consensus" / "signing-ledger" / "ledger"


async def start_without_engine(node: FullNode) -> None:
    """FullNode.run up to the engine start, which is replaced by nothing."""

    async def no_engine(*_args, **_kwargs) -> None:
        return None

    node._run = no_engine  # pyright: ignore[reportAttributeAccessIssue]
    await node.run()


def in_network(tmp_path: Path, body: Callable[[Network], Awaitable[None]]) -> None:
    install = Install(BUILD_DIR, REPO)
    if not install.pq_consensus_key_exe.exists():
        pytest.skip(f"no built tos-pq-consensus-key under {BUILD_DIR}; set TOS_BUILD_DIR")

    async def run() -> None:
        async with Network(install, tmp_path / "network", base_port=BASE_PORT) as network:
            network.config.auth_network_tag = hashlib.sha256(b"genesis-ceremony-test").digest()
            await body(network)

    asyncio.run(run())


def genesis_validator(network: Network, index: int) -> FullNode:
    node = network.create_full_node()
    node.make_initial_pq_validator(
        hashlib.sha256(f"ceremony-validator-id-{index}".encode()).digest(),
        hashlib.sha256(f"ceremony-validator-seed-{index}".encode()).digest(),
    )
    return node


def test_first_start_runs_the_ceremony_for_each_genesis_validator(tmp_path):
    async def body(network: Network) -> None:
        nodes = [genesis_validator(network, i) for i in range(2)]
        candidate = network.create_full_node()
        candidate.make_noninitial_pq_validator(
            hashlib.sha256(b"ceremony-candidate-id").digest(),
            hashlib.sha256(b"ceremony-candidate-seed").digest(),
        )
        observer = network.create_full_node()
        for node in [*nodes, candidate, observer]:
            await start_without_engine(node)
        for node in nodes:
            assert ledger(node).is_file(), node.directory
        # A later validator never runs it: its identity may have signed elsewhere.
        assert not ledger(candidate).exists()
        assert not ledger(observer).exists()

    in_network(tmp_path, body)


def test_a_ledger_already_there_is_kept(tmp_path):
    async def body(network: Network) -> None:
        node = genesis_validator(network, 0)
        node.run_genesis_ceremony()
        first = ledger(node).read_bytes()
        inode = ledger(node).stat().st_ino
        node.run_genesis_ceremony()
        assert ledger(node).read_bytes() == first
        assert ledger(node).stat().st_ino == inode

    in_network(tmp_path, body)


def test_without_the_ceremony_no_ledger_is_made(tmp_path):
    async def body(network: Network) -> None:
        node = genesis_validator(network, 0)
        node.without_genesis_ceremony()
        await start_without_engine(node)
        assert not ledger(node).exists()

    in_network(tmp_path, body)


def test_the_ceremony_is_refused_for_a_node_that_is_not_a_genesis_validator(tmp_path):
    async def body(network: Network) -> None:
        node = network.create_full_node()
        with pytest.raises(RuntimeError, match="genesis PQ validator"):
            node.run_genesis_ceremony()

    in_network(tmp_path, body)
