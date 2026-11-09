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

``--remote`` instead runs one bounded burst against existing JSON-RPC
endpoints (bench/shard/remote.py); run ``--remote --help`` for its options.
"""

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

if __name__ == "__main__" and "--remote" in sys.argv[1:]:
    # Remote mode reads and sends over JSON-RPC only: dispatch before any
    # liteserver or local-net module is imported.
    from shard import remote

    sys.exit(remote.main(sys.argv[1:]))

from contract.pq_auth import transfer_message  # noqa: E402
from pqbench import chain  # noqa: E402
from pytosiq_core import Address, WalletMessage  # noqa: E402
from tostester.install import Install  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402

from shard import hopbench, t2collect  # noqa: E402
from shard.rpc import PacedRpc  # noqa: E402
from shard.t2check import BlockRef  # noqa: E402
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
        "--chains", type=int, default=128, help="chains the start message launches (1..254)"
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
    p.add_argument(
        "--with-init",
        action="store_true",
        help="every hop carries its target's StateInit (larger messages)",
    )
    p.add_argument(
        "--verify-sender",
        action="store_true",
        help="every hop recomputes its sender's address and checks it (more gas)",
    )
    p.add_argument(
        "--payload",
        type=int,
        default=0,
        help=f"bytes every hop forwards unchanged (0..{hopbench.MAX_PAYLOAD})",
    )
    p.add_argument("--block-limits", choices=("production", "dev"), default="production")
    p.add_argument("--block-limit-mul", type=int, default=1)
    p.add_argument("--shard-wait", type=int, default=900, help="seconds to wait for the split")
    p.add_argument("--connections-per-node", type=int, default=4)
    p.add_argument("--node-verbosity", type=int, default=1)
    p.add_argument("--seed", default="tos-shard-bench", help="public run seed")
    p.add_argument("--thermal-log", type=Path, default=None, help="thermal guard log to record")
    p.add_argument(
        "--t2-check",
        action="store_true",
        help="open JSON-RPC on every node and check layout, continuity and conservation",
    )
    p.add_argument(
        "--rpc-share", type=float, default=0.5, help="share of the per-IP JSON-RPC budget"
    )
    p.add_argument(
        "--drain-wait", type=int, default=600, help="seconds to wait for the queue to drain"
    )
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
    if not 0 <= a.payload <= hopbench.MAX_PAYLOAD:
        p.error(f"--payload must be in [0, {hopbench.MAX_PAYLOAD}]")
    if not 0 < a.rpc_share <= 1:
        p.error("--rpc-share must be in (0, 1]")
    a.local_scaled = hopbench.local_scaled(a.local)
    a.flags = (hopbench.FLAG_WITH_INIT if a.with_init else 0) | (
        hopbench.FLAG_VERIFY_SENDER if a.verify_sender else 0
    )
    return a


def nano(value: float) -> int:
    return round(value * NANO)


class ShardScanner:
    """Walks every basechain shard's blocks from where it started, by header back-links.

    Every call goes to one node's liteserver: a shard head read from one node's
    masterchain state may not be applied yet on another node, which then
    answers LITE_SERVER_NOTREADY for a block that exists.
    """

    NOT_READY_ATTEMPTS = 20

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

    async def _header(self, block):
        """A block's header, waiting out a node that has not applied it yet."""
        for attempt in range(self.NOT_READY_ATTEMPTS):
            try:
                return await self.pool.call("get_block_header", block)
            except Exception as error:
                if (
                    "LITE_SERVER_NOTREADY" not in str(error)
                    or attempt + 1 == self.NOT_READY_ATTEMPTS
                ):
                    raise
                await asyncio.sleep(0.25)
        raise AssertionError("unreachable")

    async def _walk(self, shard: int, head) -> None:
        stop_at = self.last.get(shard)
        found = []
        block = head
        while stop_at is None or block.seqno > stop_at:
            header = await self._header(block)
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


async def chain_now(pool: chain.ClientPool, attempts: int = 20) -> int:
    """The latest masterchain block's time, read from one liteserver.

    Both reads go to the same connection: another node may not have applied
    the block yet and would answer LITE_SERVER_NOTREADY.
    """
    client = pool.pick()
    for attempt in range(attempts):
        try:
            info = await client.call("get_masterchain_info")
            return int((await client.call("get_block_header", info.last)).gen_utime)
        except Exception as error:
            if "LITE_SERVER_NOTREADY" not in str(error) or attempt + 1 == attempts:
                raise
            await asyncio.sleep(0.25)
    raise AssertionError("unreachable")


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


async def cross_check(
    pool: chain.ClientPool, blocks: list[hopbench.ScannedBlock], lo: int, hi: int, samples: int = 24
) -> dict[str, Any]:
    """Recount a spread of window blocks through the liteserver's transaction list.

    The window rate comes from the collators' own records; this checks those
    records against the chain for an evenly spaced sample of blocks.
    """
    matched = sorted(
        (b for b in blocks if b.collation is not None and lo <= b.gen_utime < hi),
        key=lambda b: (b.gen_utime, b.shard & hopbench.U64, b.seqno),
    )
    step = max(1, len(matched) // samples)
    picked = matched[::step][:samples]
    mismatches = []
    for b in picked:
        block = await pool.call("lookup_block", 0, b.shard, b.seqno, cost=3)
        counted = len(await pool.call("get_block_transactions", block, cost=2))
        if counted != b.transactions:
            mismatches.append(
                {
                    "shard": hopbench.shard_label(b.shard),
                    "seqno": b.seqno,
                    "record": b.transactions,
                    "chain": counted,
                }
            )
    return {"sampled": len(picked), "mismatches": mismatches}


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


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def raw(address: Address) -> str:
    return f"{address.wc}:{address.hash_part.hex()}"


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
        rpc_ports: list[int] = []
        for index in range(a.validators):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"shard-bench-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"shard-bench-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            nodes.append(node)
            rpc_ports.append(free_port() if a.t2_check else 0)
        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for node, port in zip(nodes, rpc_ports):
                args = ("--json-rpc-address", f"127.0.0.1:{port}") if a.t2_check else ()
                group.create_task(node.run(StartOptions(verbosity=a.node_verbosity, args=args)))
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
            scan_pool = chain.ClientPool(
                [await connect(nodes[-1], f"scan/{k}") for k in range(a.connections_per_node)]
            )
            scanner = ShardScanner(scan_pool)
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

            rpc = PacedRpc(f"http://127.0.0.1:{rpc_ports[0]}/jsonRPC", a.rpc_share)
            opening = None
            if a.t2_check:
                opening = await t2collect.wait_empty_queue(rpc, 120)
                log.info("T2 opening boundary: %s", opening)
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
                        a.chains,
                        a.hops,
                        a.forks,
                        a.local_scaled,
                        a.split,
                        deadline,
                        a.accounts,
                        a.flags,
                        hopbench.payload_cell(a.payload),
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
            filled = await fill_unmatched(scan_pool, scanner.blocks, lo, hi)
            summary = hopbench.summarize(scanner.blocks, lo, hi)
            summary["unmatched_blocks_counted_by_liteserver"] = filled
            summary["liteserver_cross_check"] = await cross_check(scan_pool, scanner.blocks, lo, hi)
            if summary["liteserver_cross_check"]["mismatches"]:
                log.error(
                    "collation records disagree with the chain: %s",
                    summary["liteserver_cross_check"],
                )
            write_blocks_csv(
                a.out / "blocks.csv", [b for b in scanner.blocks if lo <= b.gen_utime < hi]
            )
            tail = hopbench.tail_ratio(scanner.blocks, lo, hi)
            t2 = None
            if opening is not None:
                while await chain_now(pool) < deadline + 5:
                    await asyncio.sleep(2)
                closing = await t2collect.wait_empty_queue(rpc, a.drain_wait)
                log.info("T2 closing boundary: %s", closing)
                observed = [
                    BlockRef(0, b.shard, b.seqno, b.root_hash.hex()) for b in scanner.blocks
                ]
                verdict = await t2collect.check_window(
                    rpc,
                    opening,
                    closing,
                    {raw(x) for x in addresses},
                    {raw(main_wallet.address)},
                    a.out / "t2",
                    observed,
                    finality=[rpc]
                    + [
                        PacedRpc(f"http://127.0.0.1:{port}/jsonRPC", a.rpc_share)
                        for port in rpc_ports[1:]
                    ],
                )
                t2 = {
                    k: verdict[k]["stats"] | {"status": verdict[k]["status"]}
                    for k in ("layout", "continuity", "conservation")
                } | {
                    "status": verdict["status"],
                    "finalized_mc": verdict["finalized_mc"],
                    "layout_changes": verdict["layout_changes"],
                    "rpc": verdict["rpc"],
                }
                log.info("T2 verdict: %s", json.dumps(t2))
            report = {
                "scope": "LOCAL_ENGINEERING_EVIDENCE_ONLY: one host, every validator runs every shard",
                "workload": (
                    "hop chains between bench/shard/hop.fc copies; internal messages only; "
                    f"StateInit on every hop: {a.with_init}, sender check: {a.verify_sender}, "
                    f"payload: {a.payload} bytes"
                ),
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
                    "with_init": a.with_init,
                    "verify_sender": a.verify_sender,
                    "payload_bytes": a.payload,
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
                "t2": t2,
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
