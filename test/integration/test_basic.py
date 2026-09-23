"""Co-located functional regression for the current PQ validator path."""

import argparse
import asyncio
import hashlib
import json
import logging
import shutil
from pathlib import Path

from contract import WalletV1Blueprint, tos
from tostester.install import Install
from tostester.n6_cluster import (
    SustainedObservationConfig,
    block_id_text,
    observe_sustained_consensus,
)
from tostester.network import FullNode, Network, StartOptions
from tostester.pq_launch_limits import MAX_SHARD_COMMITTEE


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validators", type=int, default=4)
    parser.add_argument("--sustain-blocks", type=int, default=10)
    parser.add_argument("--working-dir", type=Path)
    parser.add_argument("--trace-adnl-queries", action="store_true")
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


async def main(args: argparse.Namespace):
    if not 4 <= args.validators <= MAX_SHARD_COMMITTEE:
        raise ValueError(
            "functional validator count must be in the enforced launch range "
            f"4..{MAX_SHARD_COMMITTEE}"
        )
    if args.sustain_blocks < 2:
        raise ValueError("functional sustained observation must cover at least two blocks")

    repo_root = Path(__file__).resolve().parents[2]
    if args.working_dir is None:
        working_dir = repo_root / "test/integration/.network"
        shutil.rmtree(working_dir, ignore_errors=True)
        working_dir.mkdir(exist_ok=True)
    else:
        working_dir = args.working_dir.resolve()
        working_dir.mkdir(parents=True, exist_ok=False)

    install = Install(repo_root / "build", repo_root)
    install.toslibjson.client_set_verbosity_level(4 if args.trace_adnl_queries else 3)

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H-%M-%S",
    )

    async with Network(install, working_dir) as network:
        dht = network.create_dht_node()

        network.config.shard_validators = args.validators
        consensus = network.config.mc_consensus
        require(consensus is not None, "functional Genesis does not enable Simplex consensus")

        nodes: list[FullNode] = []
        for index in range(args.validators):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"functional-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"functional-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            nodes.append(node)
        require(
            len(nodes) == args.validators and network.config.shard_validators == args.validators,
            "requested functional committee size did not control the booted topology",
        )

        async with asyncio.TaskGroup() as start_group:
            _ = start_group.create_task(dht.run())
            for node in nodes:
                _ = start_group.create_task(
                    node.run(StartOptions(verbosity=4 if args.trace_adnl_queries else 3))
                )

        await network.wait_mc_block(seqno=1)

        actor_stats = await nodes[0].engine_console.get_actor_stats()
        require(
            "= ACTORS STATS =" in actor_stats and "= PERF COUNTERS =" in actor_stats,
            "validator engine did not expose actor stats and performance counters",
        )

        _ = await network.wait_block(workchain=0, shard=-(2**63), seqno=1)

        client = await nodes[0].toslib_client()
        main_wallet = network.zerostate.main_wallet(client)

        new_wallet = await main_wallet.deploy(WalletV1Blueprint(workchain=0), tos(1))

        async def balance_changed():
            while True:
                state = await client.raw_get_account_state(new_wallet.address)
                if state.balance > 0:
                    break
                await asyncio.sleep(0.5)

        await asyncio.wait_for(balance_changed(), timeout=10)

        wallet_state = await main_wallet.current
        require(
            wallet_state.seqno == 1, "wallet deployment did not advance the source wallet seqno"
        )

        sustained = await observe_sustained_consensus(
            nodes,
            SustainedObservationConfig(
                blocks=args.sustain_blocks,
                seconds=None,
                target_block_rate_ms=consensus.target_block_rate_ms,
                slow_interval_factor=3.0,
            ),
            block_id_text(network.zerostate.as_block()),
            simplex_validator_names=[node.name for node in nodes],
        )
        require(
            sustained["masterchain_blocks_produced"] >= args.sustain_blocks,
            "functional cluster did not sustain the requested number of blocks",
        )
        result = {
            "scenario": "pq-validator-functional-regression",
            "validators_requested": args.validators,
            "validators_booted": len(nodes),
            "wallet_deployed": True,
            "wallet_balance_changed": True,
            "wallet_seqno": wallet_state.seqno,
            "actor_stats_and_perf_counters": True,
            "sustained_observation": sustained,
            "evidence_class": "COLOCATED_DIAGNOSTIC_ONLY",
            "release_evidence_eligible": False,
        }
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(parse_args()), 5 * 60))
