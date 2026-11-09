#!/usr/bin/env python3
"""Shard-scaling bench: the same contract load on 1, 2 or 4 basechain shards.

The question is what splitting the basechain buys, not what a user transfer
costs (bench/run_local_bench.py measures that). So the load carries no
per-transaction client work at all:

1. Boot a local PQ validator net through tostester with the basechain forced
   to 2^split shards (min_split = max_split = split) and wait for the split.
2. Deploy ``--accounts`` copies of bench/shard/hop.fc from the genesis wallet
   in one deployment tree; their addresses spread over every shard.
3. One internal start message launches ``--chains`` message chains, each of
   which forks ``--forks`` times. Every hop executes on the receiving copy and
   sends the next hop, inside its own shard with probability ``--local`` and
   to a uniformly random copy otherwise. The chains stop at a deadline.
4. Scan every basechain shard block over the window and match each to the
   collating validator's own record (transactions, bytes, gas, limit
   categories, cross-shard messages imported).

Run it once per split with everything else fixed; the per-shard and total
transaction rates are the result. Numbers are local engineering evidence on
one host: every validator runs every shard here, so a host that saturates
caps the total, which a network of separate machines would not.

Outputs (under --out): results.json and blocks.csv.
"""

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "bench/shard"), str(ROOT / "test/tostester/src")]

import hopbench  # noqa: E402
from contract.pq_auth import transfer_message  # noqa: E402
from pqbench import chain  # noqa: E402
from pytosiq_core import Address, WalletMessage  # noqa: E402
from tostester.install import Install  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402

from toslib import ToslibClient  # noqa: E402

NANO = 1_000_000_000
log = logging.getLogger("shard-bench")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--build", type=Path, default=ROOT / "build")
    p.add_argument("--out", type=Path, required=True, help="new directory for all outputs")
    p.add_argument("--validators", type=int, default=4)
    p.add_argument(
        "--split", type=int, default=0, help="basechain split depth: 2^split shards (0..4)"
    )
    p.add_argument("--accounts", type=int, default=4096, help="hop accounts")
    p.add_argument(
        "--chains", type=int, default=128, help="chains the start message launches (1..255)"
    )
    p.add_argument("--forks", type=int, default=4, help="times each chain forks in two (0..12)")
    p.add_argument(
        "--local",
        type=float,
        default=1.0,
        help="probability that a hop stays in its sender's shard (0..1)",
    )
    p.add_argument("--duration", type=int, default=120, help="measured seconds")
    p.add_argument("--warmup", type=int, default=30, help="seconds after the start excluded")
    p.add_argument("--account-funding", type=float, default=1.0, help="TOS kept by each account")
    p.add_argument("--load-funding", type=float, default=200000.0, help="TOS the chains spend")
    p.add_argument("--hops", type=int, default=4_000_000_000, help="hop budget of each chain")
    p.add_argument("--block-limits", choices=("production", "dev"), default="production")
    p.add_argument("--block-limit-mul", type=int, default=1)
    p.add_argument("--shard-wait", type=int, default=900, help="seconds to wait for the split")
    p.add_argument("--connections-per-node", type=int, default=4)
    p.add_argument("--node-verbosity", type=int, default=1)
    p.add_argument("--seed", default="tos-shard-bench", help="public run seed")
    p.add_argument("--thermal-log", type=Path, default=None, help="thermal guard log to record")
    a = p.parse_args()
    if not 0 <= a.split <= 4:
        p.error("--split must be in [0, 4]")
    if not 1 <= a.chains <= hopbench.MAX_CHAINS:
        p.error("--chains must be in [1, 255]")
    if not 0 <= a.forks <= 12:
        p.error("--forks must be in [0, 12]")
    if a.accounts < 2 or a.accounts >= 1 << 32:
        p.error("--accounts must be in [2, 2^32)")
    if a.duration <= 10 or a.warmup < 0:
        p.error("--duration must exceed 10 s and --warmup must not be negative")
    if a.account_funding <= 0 or a.load_funding <= 0:
        p.error("funding must be positive")
    if a.block_limits == "production" and a.block_limit_mul != 1:
        p.error("--block-limit-mul applies only to --block-limits dev")
    a.local_scaled = hopbench.local_scaled(a.local)
    return a


def nano(value: float) -> int:
    return round(value * NANO)


class ShardScanner:
    """Walks every basechain shard's blocks from where it started, by header back-links."""

    def __init__(self, pool: chain.ClientPool):
        self.pool = pool
        self.last: dict[int, int] = {}
        self.blocks: list[hopbench.ScannedBlock] = []
        self.shard_sets: list[tuple[float, list[str]]] = []
        self._stop = asyncio.Event()

    async def heads(self) -> dict[int, Any]:
        info = await self.pool.call("get_masterchain_info")
        shards = await self.pool.call("get_shards", info.last)
        return {s.shard: s for s in shards.shards if s.workchain == 0}

    async def start_position(self) -> None:
        heads = await self.heads()
        self.last = {shard: head.seqno for shard, head in heads.items()}
        self.shard_sets.append((time.time(), sorted(hopbench.shard_label(s) for s in heads)))

    async def _walk(self, shard: int, head) -> None:
        stop_at = self.last.get(shard)
        found = []
        block = head
        while stop_at is None or block.seqno > stop_at:
            header = await self.pool.call("get_block_header", block)
            found.append(
                hopbench.ScannedBlock(
                    shard, block.seqno, int(header.gen_utime), bytes(block.root_hash)
                )
            )
            prev = [p for p in header.prev_blocks if p.workchain == 0 and p.shard == shard]
            if stop_at is None or not prev:
                break  # a shard first seen now, or the start of a split
            block = prev[0]
        self.blocks.extend(found)
        self.last[shard] = max(head.seqno, stop_at or 0)

    async def run(self, poll: float = 0.3) -> None:
        if not self.last:
            await self.start_position()
        while not self._stop.is_set():
            heads = await self.heads()
            labels = sorted(hopbench.shard_label(s) for s in heads)
            if labels != self.shard_sets[-1][1]:
                self.shard_sets.append((time.time(), labels))
                log.warning("basechain shard set changed: %s", labels)
            await asyncio.gather(*(self._walk(shard, head) for shard, head in heads.items()))
            try:
                await asyncio.wait_for(self._stop.wait(), poll)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()


async def wait_split(scanner: ShardScanner, split: int, timeout: float) -> list[int]:
    """Wait until the basechain is exactly the 2^split shards of depth split."""
    want = 1 << split
    deadline = time.time() + timeout
    while time.time() < deadline:
        heads = await scanner.heads()
        if len(heads) == want and all(hopbench.shard_depth(s) == split for s in heads):
            return sorted(heads, key=lambda s: s & hopbench.U64)
        await asyncio.sleep(2)
    raise RuntimeError(f"the basechain did not reach {want} shards within {timeout:g}s")


async def chain_now(pool: chain.ClientPool) -> int:
    info = await pool.call("get_masterchain_info")
    return int((await pool.call("get_block_header", info.last)).gen_utime)


async def send_from_genesis(main, message, what: str, timeout: float = 120) -> None:
    seqno = (await main.current).seqno
    await main.send(WalletMessage(send_mode=3, message=message), seqno)
    deadline = time.time() + timeout
    while (await main.current).seqno <= seqno:
        if time.time() > deadline:
            raise RuntimeError(f"the genesis wallet never sent: {what}")
        await asyncio.sleep(0.3)


async def wait_deployed(pool: chain.ClientPool, addresses: list[Address], timeout: float) -> None:
    started = time.time()
    pending = list(addresses)
    while pending:
        if time.time() - started > timeout:
            raise RuntimeError(f"{len(pending)} hop accounts never became active")
        states: dict[bytes, bool] = {}
        for i in range(0, len(pending), 1024):
            states.update(await chain.account_active(pool, pending[i : i + 1024]))
        pending = [x for x in pending if not states.get(x.hash_part)]
        if pending:
            log.info("deployment: %d of %d not active yet", len(pending), len(addresses))
            await asyncio.sleep(2)


async def fill_unmatched(
    pool: chain.ClientPool, blocks: list[hopbench.ScannedBlock], lo: int, hi: int
):
    """Blocks with no collation record (log rotated or missing) get counted through the liteserver."""
    missing = [b for b in blocks if b.collation is None and lo <= b.gen_utime < hi]
    for b in missing:
        block = await pool.call("lookup_block", 0, b.shard, b.seqno, cost=3)
        b.transactions = len(await pool.call("get_block_transactions", block, cost=2))
    return len(missing)


def package_temperatures() -> list[float] | None:
    try:
        out = subprocess.run(["sensors"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    temps = []
    for line in out.splitlines():
        if line.startswith("Package id") and "+" in line:
            try:
                temps.append(float(line.split("+", 1)[1].split("°", 1)[0]))
            except ValueError:
                continue
    return temps or None


def source_commit() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def write_blocks_csv(path: Path, blocks: list[hopbench.ScannedBlock]) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "shard",
                "seqno",
                "gen_utime",
                "transactions",
                "bytes",
                "gas",
                "cat_bytes",
                "cat_gas",
                "cat_lt_delta",
                "cross_shard_in",
                "queue_after",
                "cpu_seconds",
            ]
        )
        for b in sorted(blocks, key=lambda b: (b.shard & hopbench.U64, b.seqno)):
            c = b.collation
            w.writerow(
                [hopbench.shard_label(b.shard), b.seqno, b.gen_utime, b.transactions]
                + (
                    [
                        c.bytes,
                        c.gas,
                        c.categories["bytes"],
                        c.categories["gas"],
                        c.categories["lt_delta"],
                        c.cross_shard_in,
                        c.queue_after,
                        f"{c.cpu_seconds:.4f}",
                    ]
                    if c
                    else [""] * 8
                )
            )


async def main(a: argparse.Namespace) -> int:
    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(a.out / "bench.log")],
    )
    for name in ("tostester", "tostester.network", "dht-0", *(f"node-{i}" for i in range(1, 32))):
        logging.getLogger(name).setLevel(logging.WARNING)
    commit = source_commit()
    code = hopbench.build(a.build, a.out / "contracts")
    seed = hashlib.sha256(a.seed.encode()).digest()
    family = hopbench.HopFamily(code, int.from_bytes(seed[:8], "big"), a.accounts)
    addresses = family.addresses()
    placement: dict[str, int] = {}
    for x in addresses:
        label = hopbench.shard_label(hopbench.shard_of(x.hash_part, a.split))
        placement[label] = placement.get(label, 0) + 1
    log.info("hop accounts per shard at depth %d: %s", a.split, placement)

    install = Install(a.build, ROOT)
    install.toslibjson.client_set_verbosity_level(1)
    working_dir = a.out / "network"
    working_dir.mkdir()
    opened: list[chain.PacedClient] = []
    async with Network(install, working_dir) as network:
        if network.config.auth_network_tag is None:
            network.config.auth_network_tag = hashlib.sha256(b"tos-shard-bench").digest()
        network.config.shard_validators = a.validators
        network.config.split = a.split
        network.config.production_block_limits = a.block_limits == "production"
        if a.block_limits == "dev":
            network.config.block_limit_mul = a.block_limit_mul
        global_id = network.config.global_id
        dht = network.create_dht_node()
        nodes: list[FullNode] = []
        for index in range(a.validators):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"shard-bench-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"shard-bench-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            nodes.append(node)
        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for node in nodes:
                group.create_task(node.run(StartOptions(verbosity=a.node_verbosity)))
        await network.wait_mc_block(seqno=1)
        boot = time.time()
        log.info("net up: %d validators, global id %d", a.validators, global_id)
        client = await nodes[0].toslib_client()

        async def connect(node, name):
            c = ToslibClient(node.liteserver_config, install.toslibjson)
            await c.init()
            paced = chain.PacedClient(c, name)
            opened.append(paced)
            return paced

        try:
            readers = [
                await connect(node, f"{node.name}/{k}")
                for node in nodes
                for k in range(a.connections_per_node)
            ]
            pool = chain.ClientPool(readers)
            scanner = ShardScanner(pool)
            shards = await wait_split(scanner, a.split, a.shard_wait)
            split_seconds = time.time() - boot
            log.info(
                "basechain at %d shards after %.0fs: %s",
                len(shards),
                split_seconds,
                [hopbench.shard_label(s) for s in shards],
            )
            chain_config = await chain.config_snapshot(
                pool, params=(12, 20, 21, 22, 23, 24, 25, 28, 29)
            )

            main_wallet = network.zerostate.main_wallet(client)
            balance = int((await client.raw_get_account_state(main_wallet.address)).balance)
            deploy_value = a.accounts * nano(a.account_funding)
            load_value = nano(a.load_funding)
            if deploy_value + load_value + nano(10) > balance:
                raise SystemExit("the genesis wallet cannot fund this sizing")

            t = time.time()
            await send_from_genesis(
                main_wallet,
                transfer_message(
                    main_wallet.address,
                    addresses[0],
                    deploy_value,
                    body=hopbench.deploy_body(0, a.accounts),
                    init=family.state_init(0),
                ),
                "deployment",
            )
            await wait_deployed(pool, addresses, timeout=900)
            deploy_seconds = time.time() - t
            log.info("deployed %d hop accounts in %.1fs", a.accounts, deploy_seconds)

            await scanner.start_position()
            scan_task = asyncio.create_task(scanner.run())
            start = await chain_now(pool)
            deadline = start + a.warmup + a.duration + 30
            await send_from_genesis(
                main_wallet,
                transfer_message(
                    main_wallet.address,
                    addresses[0],
                    load_value,
                    body=hopbench.start_body(
                        a.chains, a.hops, a.forks, a.local_scaled, a.split, deadline, a.accounts
                    ),
                ),
                "start",
            )
            started = await chain_now(pool)
            lo, hi = started + a.warmup, started + a.warmup + a.duration
            temps: list[float] = []
            log.info(
                "load started at %d: %d chains x 2^%d forks, local %.2f; window [%d, %d)",
                started,
                a.chains,
                a.forks,
                a.local,
                lo,
                hi,
            )
            while await chain_now(pool) < hi + 5:
                t_now = package_temperatures()
                if t_now:
                    temps.append(max(t_now))
                await asyncio.sleep(5)
            scanner.stop()
            await scan_task
            await asyncio.sleep(3)  # the last collation records reach session-logs

            records = hopbench.collations(working_dir)
            for b in scanner.blocks:
                b.collation = records.get(b.root_hash)
                if b.collation is not None:
                    b.transactions = b.collation.transactions
            filled = await fill_unmatched(pool, scanner.blocks, lo, hi)
            summary = hopbench.summarize(scanner.blocks, lo, hi)
            summary["unmatched_blocks_counted_by_liteserver"] = filled
            write_blocks_csv(
                a.out / "blocks.csv", [b for b in scanner.blocks if lo <= b.gen_utime < hi]
            )
            tail = hopbench.tail_ratio(scanner.blocks, lo, hi)
            report = {
                "scope": "LOCAL_ENGINEERING_EVIDENCE_ONLY: one host, every validator runs every shard",
                "workload": "hop chains between bench/shard/hop.fc copies; internal messages only",
                "source_commit": commit,
                "contract_code_hash": code.hash.hex(),
                "host": {
                    "platform": platform.platform(),
                    "cpus": os.cpu_count(),
                    "affinity": sorted(os.sched_getaffinity(0)),
                },
                "parameters": {
                    "validators": a.validators,
                    "split": a.split,
                    "accounts": a.accounts,
                    "chains": a.chains,
                    "forks": a.forks,
                    "concurrent_chains": a.chains << a.forks,
                    "local": a.local,
                    "warmup": a.warmup,
                    "duration": a.duration,
                    "block_limits": a.block_limits,
                    "block_limit_mul": a.block_limit_mul,
                    "load_funding_tos": a.load_funding,
                },
                "accounts_per_shard": placement,
                "split_seconds": split_seconds,
                "deploy_seconds": deploy_seconds,
                "shard_sets": scanner.shard_sets,
                "load_tail_ratio": tail,
                "load_thinned": tail is not None and tail < 0.7,
                "package_temperature_max": max(temps) if temps else None,
                "thermal_log": str(a.thermal_log) if a.thermal_log else None,
                "chain_config": chain_config,
                "result": summary,
            }
            (a.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            log.info(
                "result: split %d, %d shards, %.1f tx/s total (%s), tail ratio %s",
                a.split,
                summary["shard_count"],
                summary["tx_per_second"],
                ", ".join(f"{s['shard'][:4]}: {s['tx_per_second']:.1f}" for s in summary["shards"]),
                f"{tail:.2f}" if tail is not None else "n/a",
            )
        finally:
            for c in opened:
                await c.client.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(parse_args())))
