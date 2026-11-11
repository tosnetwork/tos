"""Co-located functional regression for the current PQ validator path."""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import shutil
from pathlib import Path

from contract import WalletV1Blueprint, tos
from tostester.install import Install
from tostester.n6_cluster import (
    SustainedObservationConfig,
    block_id_text,
    lite_admission_drop_warnings,
    lite_connection_budget,
    observe_sustained_consensus,
)
from tostester.network import FullNode, Network, StartOptions
from tostester.pq_launch_limits import MAX_SHARD_COMMITTEE

from toslib import ToslibError


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


SHARD_CLIENT_STATE_CAPABILITY = 8  # liteserver capability: getMasterchainInfoExt mode 1


async def check_shard_client_state(client, node: FullNode, install: Install) -> dict[str, object]:
    """getMasterchainInfoExt mode 1 names a masterchain block from the shard client's state.

    The head advertised by default (mode 0) can name shard blocks the shard client has not applied
    yet, so a lookup of one of them can answer NOTREADY. Every shard top under the mode-1 head
    must be served. Unknown mode bits stay refused, and lite-client exposes the query."""
    default = await client.get_masterchain_info_ext(0)
    applied = await client.get_masterchain_info_ext(1)
    require(
        default.capabilities & SHARD_CLIENT_STATE_CAPABILITY
        and applied.capabilities & SHARD_CLIENT_STATE_CAPABILITY,
        f"liteserver does not advertise the shard-client-state capability: {applied.capabilities}",
    )
    require(default.mode == 0 and applied.mode == 1, "getMasterchainInfoExt did not echo the mode")
    require(
        applied.last.workchain == -1 and applied.last.seqno > 0,
        f"mode 1 did not name a masterchain block: {applied.last}",
    )
    shard_tops = (await client.get_shards(applied.last)).shards
    require(bool(shard_tops), "mode-1 masterchain block has no shards")
    for top in shard_tops:
        served = await client.lookup_block(top.workchain, top.shard, seqno=top.seqno)
        require(
            served.seqno == top.seqno and served.root_hash == top.root_hash,
            f"shard top {top} under the mode-1 head was not served as the same block",
        )
    try:
        await client.get_masterchain_info_ext(2)
    except ToslibError as error:
        require("unsupported getMasterchainInfo mode" in str(error), f"mode 2: {error}")
    else:
        raise AssertionError("getMasterchainInfoExt mode 2 was not refused")

    config_path = node.directory / "lite-client-shard-client-state.json"
    config_path.write_text(node.liteserver_config.to_json())
    process = await asyncio.create_subprocess_exec(
        str(install.lite_client_exe),
        "-C",
        str(config_path),
        "-r",
        "-t",
        "30",
        "-c",
        "lastshardclient",
        cwd=node.directory,
        env=os.environ.copy(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output = (await asyncio.wait_for(process.communicate(), timeout=45.0))[0].decode(
        errors="replace"
    )
    require(
        process.returncode == 0 and "latest masterchain block in shard client state is" in output,
        f"lite-client lastshardclient failed (rc {process.returncode}): {output[-500:]}",
    )
    return {
        "default_head_seqno": default.last.seqno,
        "shard_client_head_seqno": applied.last.seqno,
        "shard_tops_served": len(shard_tops),
        "lite_client_lastshardclient": True,
    }


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

        shard_client_state = await check_shard_client_state(client, nodes[0], install)

        assert consensus is not None
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
            lite_budget=lite_connection_budget(),
        )
        require(
            sustained["masterchain_blocks_produced"] >= args.sustain_blocks,
            "functional cluster did not sustain the requested number of blocks",
        )
        # The server refuses a query only on a handler error or an oversized answer, so any
        # refused query means something failed; the check fails whether or not it was answered.
        admission_drops = lite_admission_drop_warnings({node.name: node.log_path for node in nodes})
        require(
            not any(admission_drops.values()),
            f"a liteserver dropped queries past its admission budget: {admission_drops}",
        )
        result = {
            "scenario": "pq-validator-functional-regression",
            "validators_requested": args.validators,
            "validators_booted": len(nodes),
            "wallet_deployed": True,
            "wallet_balance_changed": True,
            "wallet_seqno": wallet_state.seqno,
            "actor_stats_and_perf_counters": True,
            "shard_client_state": shard_client_state,
            "sustained_observation": sustained,
            "lite_admission_drop_warnings": admission_drops,
            "evidence_class": "COLOCATED_DIAGNOSTIC_ONLY",
            "release_evidence_eligible": False,
        }
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(parse_args()), 5 * 60))
