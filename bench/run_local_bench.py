#!/usr/bin/env python3
"""Local PQ performance bench: boot a validator net, deploy Quantum wallets, measure TPS.

One process runs the whole bench so every number comes from one chain and one
clock:

1. Boot a local PQ validator net through tostester (Simplex, one basechain shard).
2. Fund a few self-pay Quantum deployer wallets from the genesis wallet; each
   deploys its fixed share of load wallets with ML-DSA-44-signed externals of
   up to 255 actions.
3. For each offered rate: pre-sign one ML-DSA-44 external per transfer, send at
   the offered rate through sender connections paced under the node's
   per-identity external admission window, scan every basechain block, drain,
   then read every load wallet's PRIMARY nonce to account for each transfer.

Outputs (under --out): results.json, plus per stage blocks.csv and timeline.csv.
Numbers are local engineering evidence on one host, not public capacity.
"""

import argparse
import asyncio
import csv
import datetime
import hashlib
import json
import logging
import math
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from pytosiq_core import Address  # noqa: E402

from contract import tos  # noqa: E402
from pqbench import chain, contracts, sender  # noqa: E402
from pqbench.signer import BatchSigner  # noqa: E402
from pqbench.workload import (  # noqa: E402
    MAX_ACTIONS,
    QSP_PRIMARY_CONTEXT,
    QuantumWallet,
    primary_nonce,
    quantum_seed,
    sinks,
)
from toslib import ToslibClient  # noqa: E402
from tostester.install import Install  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402

NANO = 1_000_000_000
# The node refuses external messages above 64 KiB; keep headroom.
EXT_MESSAGE_BUDGET = 60_000
LOAD_CLASS = "quantum-wallet"
# Sender workers open their connections before the first scheduled send.
SENDER_STARTUP_SECONDS = 30
log = logging.getLogger("bench")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--build", type=Path, default=ROOT / "build")
    p.add_argument("--signer", type=Path, default=ROOT / "build/bench-pq-signer/bench-pq-signer")
    p.add_argument("--out", type=Path, required=True, help="new directory for all outputs")
    p.add_argument("--validators", type=int, default=4)
    p.add_argument("--wallets", type=int, default=2000, help="Quantum load wallets")
    p.add_argument("--rates", default="10,50,100,250", help="offered transfers/s per stage")
    p.add_argument("--duration", type=int, default=300, help="seconds of sending per stage")
    p.add_argument("--warmup", type=int, default=30, help="seconds excluded from steady-state TPS")
    p.add_argument("--drain", type=int, default=60, help="seconds to wait after sending")
    p.add_argument("--min-reuse", type=float, default=10.0,
                   help="minimum seconds between two transfers from the same wallet")
    p.add_argument("--transfer-value", type=float, default=0.001, help="TOS moved per transfer")
    p.add_argument("--wallet-funding", type=float, default=2.0, help="TOS per load wallet")
    p.add_argument("--sinks", type=int, default=256)
    p.add_argument("--deployers", type=int, default=8, help="parallel Quantum deployer wallets (1..32)")
    p.add_argument("--signer-threads", type=int, default=8,
                   help="ML-DSA-44 signing threads (kept low by default: signing bursts heat the host)")
    p.add_argument("--max-senders", type=int, default=512,
                   help="cap on sending connections; a node admits 30 externals per 10 s from each")
    p.add_argument("--connections-per-node", type=int, default=4,
                   help="read connections per validator (each admits ~48 queries/s here)")
    p.add_argument("--block-limit-mul", type=int, default=1, help=">1 raises block limits (unleashed runs only)")
    p.add_argument("--seed", default="tos-local-pq-bench", help="public run seed (keys are test material)")
    p.add_argument("--stop-on-saturation", action="store_true")
    p.add_argument("--thermal-log", type=Path,
                   help="log of a thermal guard attached to this run's process group; stages overlapping a pause are invalid")
    p.add_argument("--keep-running", action="store_true", help="leave the net up after the bench (Ctrl-C ends)")
    a = p.parse_args()
    a.rates = [float(r) for r in a.rates.split(",") if r.strip()]
    if not a.rates or any(not 0 < r <= 100_000 for r in a.rates):
        p.error("rates must be positive")
    if not 4 <= a.validators <= 21:
        p.error("validators must be 4..21")
    if not 1 <= a.wallets <= 1_000_000:
        p.error("wallets must be 1..1000000")
    if not 1 <= a.deployers <= 32:
        p.error("deployers must be 1..32")
    if a.duration < 10 or a.warmup < 0 or a.warmup >= a.duration or a.drain < 5:
        p.error("need duration >= 10, 0 <= warmup < duration, drain >= 5")
    if a.duration + a.drain + 600 > 3500:
        p.error("duration + drain must leave the 3600 s request validity window room for signing")
    for name in ("transfer_value", "wallet_funding"):
        if getattr(a, name) <= 0:
            p.error(f"--{name.replace('_', '-')} must be positive")
    if a.block_limit_mul < 1:
        p.error("block limit multiplier must be >= 1")
    return a


def nano(value: float) -> int:
    return int(round(value * NANO))


class Bench:
    def __init__(self, args, network: Network, client, pool: chain.ClientPool, scan: chain.PacedClient,
                 signer: BatchSigner, code, net_id: int, auth_tag: bytes):
        self.a, self.network, self.client, self.pool, self.scan = args, network, client, pool, scan
        self.signer, self.code, self.net_id, self.auth_tag = signer, code, net_id, auth_tag
        self.run_seed = hashlib.sha256(args.seed.encode()).digest()
        self.sinks = sinks(args.sinks, self.run_seed)
        self.classes: dict[bytes, str] = {s.hash_part: "sink" for s in self.sinks}
        self.nonces: dict[bytes, int] = {}
        self.wallets: list[QuantumWallet] = []
        self.deployers: list[QuantumWallet] = []
        self.deploy_seconds = 0.0
        self.deployed_accounts = 0

    def check_reuse(self) -> None:
        peak = max(self.a.rates)
        if self.a.wallets / peak < self.a.min_reuse:
            raise SystemExit(
                f"{self.a.wallets} wallets at {peak:g}/s reuse a wallet every {self.a.wallets / peak:.1f}s "
                f"(< --min-reuse {self.a.min_reuse}); raise --wallets"
            )

    def derive(self, tag: str, count: int) -> list[QuantumWallet]:
        seeds = [quantum_seed(self.run_seed, tag, i) for i in range(count)]
        keys = self.signer.public_keys(seeds)
        return [QuantumWallet.derive(self.code["quantum"], self.net_id, self.auth_tag, self.run_seed,
                                     tag, i, keys[i], seeds[i]) for i in range(count)]

    async def _now(self) -> int:
        info = await self.pool.call("get_masterchain_info")
        header = await self.pool.call("get_block_header", info.last)
        return int(header.gen_utime)

    async def wait_nonce(self, wallet: QuantumWallet, nonce: int, what: str, timeout: float = 180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = (await chain.read_data(self.pool, [wallet.address]))[wallet.address.hash_part]
            if data is not None and primary_nonce(data) >= nonce:
                return
            await asyncio.sleep(0.5)
        raise RuntimeError(f"the chain never reached: {what}")

    async def wait_active(self, addresses: list[Address], what: str, timeout: float = 900):
        deadline = time.time() + timeout
        pending = list(addresses)
        stalls = 0
        while pending and time.time() < deadline:
            states = {}
            for i in range(0, len(pending), 2000):
                states.update(await chain.account_active(self.pool, pending[i : i + 2000]))
            before = len(pending)
            pending = [a for a in pending if not states.get(a.hash_part)]
            stalls = stalls + 1 if pending and len(pending) == before else 0
            if stalls >= 5:
                report = {"missing": len(pending), "deployers": {}}
                for d in self.deployers:
                    report["deployers"][d.address.to_str(False)] = await chain.action_report(self.pool, d.address)
                (self.a.out / "deployment-failure.json").write_text(json.dumps(report, indent=2) + "\n")
                raise RuntimeError(f"{what}: {len(pending)} accounts stopped activating; "
                                   "see deployment-failure.json")
            if pending:
                log.info("%s: %d of %d not active yet", what, len(pending), len(addresses))
                await asyncio.sleep(2)
        if pending:
            raise RuntimeError(f"{what}: {len(pending)} accounts never became active")

    async def deploy_share(self, deployer: QuantumWallet, share: list[tuple], what: str) -> None:
        """Deploy (wallet, funding) items with ML-DSA-44-signed externals sized under the limit."""
        queue = list(share)
        while queue:
            nonce = self.nonces[deployer.address.hash_part]
            deadline = await self._now() + 600
            take = min(MAX_ACTIONS, len(queue))
            while True:
                actions = [w.deployment_message(deployer.address, v) for w, v in queue[:take]]
                request = deployer.request(nonce, actions, deadline)
                size = len(deployer.external(request, bytes(2420)).serialize().to_boc())
                if size <= EXT_MESSAGE_BUDGET or take == 1:
                    break
                take = max(1, take * EXT_MESSAGE_BUDGET // size - 1)
            [signature] = self.signer.sign([(deployer.pq_seed, request.hash)], QSP_PRIMARY_CONTEXT)
            ext = deployer.external(request, signature)
            await self.pool.pick_sender().call("raw_send_message", ext.serialize().to_boc())
            await self.wait_nonce(deployer, nonce + 1, f"{what} nonce {nonce + 1}")
            self.nonces[deployer.address.hash_part] = nonce + 1
            del queue[:take]
            log.info("%s: %d left", what, len(queue))

    async def deploy(self) -> None:
        a = self.a
        main = self.network.zerostate.main_wallet(self.client)
        main_balance = int((await self.client.raw_get_account_state(main.address)).balance)
        t = time.time()
        self.wallets = self.derive("load", a.wallets)
        log.info("derived %d ML-DSA-44 PRIMARY keys in %.1fs", len(self.wallets), time.time() - t)
        for w in self.wallets:
            self.classes[w.address.hash_part] = LOAD_CLASS
        items = [(w, nano(a.wallet_funding)) for w in self.wallets]
        # Each deployer owns a fixed share and is funded for exactly that share:
        # with a shared queue a fast deployer outruns its funding, and send mode
        # 3 then skips every action it cannot afford without failing the external.
        count = max(1, min(a.deployers, math.ceil(len(items) / MAX_ACTIONS / 4)))
        shares = [items[i::count] for i in range(count)]
        # The reserve covers forwarding each StateInit plus the deployer's own
        # execution; it only has to make an unaffordable action impossible.
        fundings = [sum(v for _, v in share) + len(share) * nano(0.25) + nano(50) for share in shares]
        total = sum(fundings) + nano(10)
        log.info("genesis wallet %.1f TOS; bench needs %.1f TOS", main_balance / NANO, total / NANO)
        if total > main_balance:
            raise SystemExit("the genesis wallet cannot fund this sizing; lower --wallets or funding")
        self.deployers = self.derive("deployer", count)
        seqno = (await main.current).seqno
        for d, funding in zip(self.deployers, fundings):
            self.classes[d.address.hash_part] = "deployer"
            await main.deploy(_Blueprint(d), tos(funding / NANO), seqno)
            seqno += 1
            while (await main.current).seqno < seqno:
                await asyncio.sleep(0.3)
        await self.wait_active([d.address for d in self.deployers], "deployers")
        for d in self.deployers:
            self.nonces[d.address.hash_part] = 0
        t = time.time()
        await asyncio.gather(*(self.deploy_share(d, share, f"deployment/{i}")
                               for i, (d, share) in enumerate(zip(self.deployers, shares))))
        await self.wait_active([w.address for w in self.wallets], "load wallets")
        self.deploy_seconds = time.time() - t
        self.deployed_accounts = len(self.wallets)
        log.info("deployed %d Quantum wallets in %.1fs", len(self.wallets), self.deploy_seconds)

    async def counters(self) -> dict[bytes, int]:
        data = await chain.read_data(self.pool, [w.address for w in self.wallets])
        out = {}
        for key, cell in data.items():
            if cell is None:
                raise RuntimeError("a Quantum load wallet has no state")
            out[key] = primary_nonce(cell)
        return out

    async def stage(self, rate: float) -> dict:
        """One offered rate: pre-sign, send from worker processes, scan, drain, reconcile."""
        a = self.a
        count = int(rate * a.duration)
        wallets, n = self.wallets, len(self.wallets)
        start = await self.counters()
        deadline = await self._now() + a.duration + a.drain + 600
        transfer = nano(a.transfer_value)
        t_sign = time.time()
        requests = []
        for k in range(count):
            w = wallets[k % n]
            requests.append((w, w.request(start[w.address.hash_part] + k // n,
                                          [w.transfer(self.sinks[k % len(self.sinks)], transfer)], deadline)))
        signatures = self.signer.sign([(w.pq_seed, r.hash) for w, r in requests], QSP_PRIMARY_CONTEXT)
        messages = [w.external(r, sig) for (w, r), sig in zip(requests, signatures)]
        sign_seconds = time.time() - t_sign
        log.info("quantum @ %g/s: %d transfers pre-signed in %.1fs", rate, count, sign_seconds)

        scanner = chain.Scanner(self.scan, self.classes)
        scanner.track = {w.address.hash_part for w in wallets}
        await scanner.start_position()
        scan_task = asyncio.create_task(scanner.run())
        bocs = [m.serialize().to_boc() for m in messages]
        senders = min(a.max_senders, max(len(self.configs), math.ceil(rate * 1.5 / chain.SOURCE_SEND_RATE)))
        t0, records = await asyncio.to_thread(
            sender.distributed_send, ROOT, a.build, self.configs, bocs, rate, senders,
            chain.SOURCE_SEND_RATE, SENDER_STARTUP_SECONDS)
        t_sent = time.time()
        await asyncio.sleep(a.drain)
        scanner.stop()
        await scan_task
        end = await self.counters()
        executed = sum(end[w.address.hash_part] - start[w.address.hash_part] for w in wallets)
        result = self.summarize(rate, count, records, scanner, executed, t0, t_sent, sign_seconds)
        result["sender_connections"] = senders
        result["gas_sample"] = await chain.gas_sample(self.pool, {LOAD_CLASS: [w.address for w in wallets]})
        result["cpu_package_celsius_end"] = package_temperatures()
        # A guard pause stops the validators and the generator together; such a
        # stage measures the pause, not the chain, and must be rerun.
        stage_end = time.time()
        events = guard_events(a.thermal_log)
        overlapping = [(kind, round(t, 1)) for kind, t in events if t0 - 5 <= t <= stage_end]
        before = [k for k, t in events if t < t0 - 5]
        if before and before[-1] == "paused":
            overlapping.insert(0, ("paused-before-stage", round(t0, 1)))
        result["thermal_guard_events"] = overlapping
        result["valid"] = not overlapping and a.thermal_log is not None
        if a.thermal_log is None:
            result["invalid_reason"] = "no --thermal-log: guard pauses cannot be excluded"
        elif overlapping:
            result["invalid_reason"] = "thermal guard paused the run during this stage; rerun it"
        if not result["valid"]:
            result["saturated"] = None
        stage_dir = a.out / f"stage-quantum-{rate:g}"
        (stage_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result

    def summarize(self, rate, count, records, scanner, executed, t0, t_sent, sign_seconds) -> dict:
        a = self.a
        accepted = sum(1 for r in records if r.ok)
        refused = len(records) - accepted
        errors: dict[str, int] = {}
        for r in records:
            if not r.ok and r.error:
                # Group by reason, not by the per-message transaction hash inside it.
                reason = r.error.split(" by transaction ")[0] + (
                    " (" + r.error.split("exitcode=")[1].split(",")[0] + ")" if "exitcode=" in r.error else "")
                errors[reason] = errors.get(reason, 0) + 1
        lo, hi = t0 + a.warmup, t_sent
        window = [b for b in scanner.rows if lo <= b.observed <= hi]
        span = max(1e-9, hi - lo)
        steady_tx = sum(b.total for b in window) / span
        steady_transfers = sum(b.by_class.get(LOAD_CLASS, 0) for b in window) / span
        send_lag = [r.sent - r.scheduled for r in records]
        # Inclusion latency: pair each wallet's sends with its observed executions in order.
        sends_by_wallet: dict[bytes, list[float]] = {}
        for r in records:
            sends_by_wallet.setdefault(self.wallets[r.index % len(self.wallets)].address.hash_part, []).append(r.sent)
        latencies = sorted(seen - s for key, sent in sends_by_wallet.items()
                           for s, seen in zip(sent, scanner.first_seen.get(key, [])))

        def pct(p):
            return round(latencies[min(len(latencies) - 1, int(p * len(latencies)))], 3) if latencies else None

        blocks = scanner.rows
        intervals = [b2.gen_utime - b1.gen_utime for b1, b2 in zip(blocks, blocks[1:])]
        result = {
            "workload": "quantum",
            "offered_rate": rate,
            "transfers_planned": count,
            "messages_sent": len(records),
            "messages_accepted_by_node": accepted,
            "messages_refused_by_node": refused,
            "refusal_reasons": dict(sorted(errors.items(), key=lambda kv: -kv[1])[:5]),
            "transfers_executed": executed,
            "transfers_unaccounted": count - executed,
            "executed_fraction": round(executed / count, 4) if count else None,
            "send_seconds": round(t_sent - t0, 2),
            "sign_seconds": round(sign_seconds, 2),
            "max_send_lag_s": round(max(send_lag), 3) if send_lag else None,
            "completed_transfer_rate": round(executed / max(1e-9, t_sent - t0), 2),
            "steady_transfer_tps": round(steady_transfers, 2),
            "steady_total_tx_tps": round(steady_tx, 2),
            "inclusion_latency_s": {"p50": pct(0.5), "p90": pct(0.9), "p99": pct(0.99),
                                    "max": round(latencies[-1], 3) if latencies else None,
                                    "samples": len(latencies)},
            "blocks": len(blocks),
            "max_tx_per_block": max((b.total for b in blocks), default=0),
            "mean_block_interval_s": round(sum(intervals) / len(intervals), 3) if intervals else None,
        }
        below = bool(result["executed_fraction"] is not None
                     and (result["executed_fraction"] < 0.95 or steady_transfers < 0.9 * rate))
        # Saturation means the chain fell behind. A shortfall that the generator,
        # the node's ingress limits or the observer can explain is not that. A
        # refusal because the wallet's previous request is still unexecuted is
        # the chain's backlog showing through, so it does not count here.
        admission = sum(n for reason, n in errors.items()
                        if "rate limit" in reason or "admission" in reason or "NOTREADY" in reason)
        bottlenecks = []
        if admission:
            bottlenecks.append("node admission refusals")
        if send_lag and max(send_lag) > 1.0:
            bottlenecks.append("generator fell behind its schedule")
        if blocks and blocks[-1].observed - blocks[-1].gen_utime > 5:
            bottlenecks.append("block scanner lagged the chain")
        result["admission_refusals"] = admission
        result["below_offered_rate"] = below
        result["non_chain_bottlenecks"] = bottlenecks
        result["saturated"] = below and not bottlenecks
        stage_dir = a.out / f"stage-quantum-{rate:g}"
        stage_dir.mkdir(parents=True, exist_ok=False)
        classes = sorted({c for b in blocks for c in b.by_class})
        with (stage_dir / "blocks.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["seqno", "gen_utime", "observed", "total_tx", *classes])
            for b in blocks:
                w.writerow([b.seqno, b.gen_utime, f"{b.observed:.3f}", b.total, *[b.by_class.get(c, 0) for c in classes]])
        with (stage_dir / "timeline.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["second", "messages_sent", "messages_refused", "tx_observed", f"{LOAD_CLASS}_tx"])
            seconds = int(math.ceil(t_sent - t0 + a.drain)) + 1
            sent, refused_s, tx, wtx = [0] * seconds, [0] * seconds, [0] * seconds, [0] * seconds
            for r in records:
                i = min(seconds - 1, max(0, int(r.sent - t0)))
                sent[i] += 1
                refused_s[i] += 0 if r.ok else 1
            for b in blocks:
                i = min(seconds - 1, max(0, int(b.observed - t0)))
                tx[i] += b.total
                wtx[i] += b.by_class.get(LOAD_CLASS, 0)
            for i in range(seconds):
                w.writerow([i, sent[i], refused_s[i], tx[i], wtx[i]])
        log.info("stage result: %s", json.dumps({k: result[k] for k in (
            "offered_rate", "transfers_executed", "transfers_planned", "steady_transfer_tps",
            "steady_total_tx_tps", "saturated", "non_chain_bottlenecks")}))
        return result


class _Blueprint:
    """Adapter so the genesis wallet's deploy() can fund a Quantum wallet's StateInit."""

    def __init__(self, wallet: QuantumWallet):
        self.state_init, self.address = wallet.state_init, wallet.address

    def materialize(self, provider):
        return self.address


def package_temperatures() -> list[float] | None:
    """CPU package temperatures, so a stage on a throttling host can be recognised."""
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


def guard_events(path: Path | None) -> list[tuple[str, float]]:
    """Pause/resume events from a thermal guard log ("paused at 90C HH:MM:SS", UTC)."""
    if path is None or not path.is_file():
        return []
    today = datetime.datetime.now(datetime.UTC).date()
    events = []
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] in ("paused", "resumed") and parts[1] == "at":
            try:
                t = datetime.datetime.strptime(parts[3], "%H:%M:%S").time()
            except ValueError:
                continue
            stamp = datetime.datetime.combine(today, t, tzinfo=datetime.UTC).timestamp()
            if stamp > time.time() + 60:  # the event was before midnight UTC
                stamp -= 86400
            events.append((parts[0], stamp))
    return events


def source_commit() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


async def main(a: argparse.Namespace) -> int:
    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    commit = source_commit()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(a.out / "bench.log")])
    for name in ("tostester", "tostester.network") + tuple(f"node-{i}" for i in range(1, 32)) + ("dht-0",):
        logging.getLogger(name).setLevel(logging.WARNING)
    signer = BatchSigner(a.signer, a.signer_threads)
    code = contracts.build(a.build, a.out / "contracts")
    install = Install(a.build, ROOT)
    install.toslibjson.client_set_verbosity_level(1)
    working_dir = a.out / "network"
    working_dir.mkdir()
    results: list[dict] = []
    started = time.time()
    async with Network(install, working_dir) as network:
        if network.config.auth_network_tag is None:
            network.config.auth_network_tag = hashlib.sha256(b"tos-local-pq-bench").digest()
        auth_tag = network.config.auth_network_tag
        network.config.shard_validators = a.validators
        network.config.block_limit_mul = a.block_limit_mul
        net_id = network.config.global_id
        dht = network.create_dht_node()
        nodes: list[FullNode] = []
        for index in range(a.validators):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"bench-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"bench-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            nodes.append(node)
        async with asyncio.TaskGroup() as group:
            group.create_task(dht.run())
            for node in nodes:
                group.create_task(node.run(StartOptions(verbosity=1)))
        await network.wait_mc_block(seqno=1)
        await network.wait_block(workchain=0, shard=chain.BASECHAIN_SHARD, seqno=1)
        log.info("net up: %d validators, global id %d", a.validators, net_id)
        client = await nodes[0].toslib_client()
        opened: list[chain.PacedClient] = []

        async def connect(node, name, **kw):
            c = ToslibClient(node.liteserver_config, install.toslibjson)
            await c.init()
            paced = chain.PacedClient(c, name, **kw)
            opened.append(paced)
            return paced

        try:
            readers = [await connect(node, f"{node.name}/{k}") for node in nodes
                       for k in range(a.connections_per_node)]
            # Deployment senders live here; stage load is sent from worker
            # processes (bench/pqbench/sender.py), one identity per connection.
            senders = [await connect(nodes[k % len(nodes)], f"deploy-send{k}", qps=chain.SOURCE_SEND_RATE,
                                     inflight=4) for k in range(2 * len(nodes))]
            scan = await connect(nodes[-1], "scanner")
            pool = chain.ClientPool(readers, senders)
            log.info("client pool: %d read connections (%.0f queries/s), %d senders (%.0f externals/s)",
                     len(readers), pool.qps, len(senders), pool.send_rate)
            bench = Bench(a, network, client, pool, scan, signer, code, net_id, auth_tag)
            bench.configs = [node.liteserver_config.to_json() for node in nodes]
            bench.check_reuse()
            chain_config = await chain.config_snapshot(pool)
            await bench.deploy()
            for rate in a.rates:
                result = await bench.stage(rate)
                results.append(result)
                if a.stop_on_saturation and result["saturated"] is True:
                    log.info("saturated at %g/s; skipping higher rates", rate)
                    break
            report = {
                "scope": "LOCAL_ENGINEERING_EVIDENCE_ONLY: one host, co-located validators; not public capacity",
                "workload": "self-pay Quantum wallet, ML-DSA-44 PRIMARY, one external per transfer",
                "source_commit": commit,
                "host": {"platform": platform.platform(), "cpus": os.cpu_count(),
                         "affinity": sorted(os.sched_getaffinity(0))},
                "validators": a.validators,
                "global_id": net_id,
                "block_limit_mul": a.block_limit_mul,
                "limits_profile": ("local test genesis: basechain block gas soft/hard 100M (deployment"
                                   " profile is lower); see chain_config for the exact parameters"),
                "chain_config": chain_config,
                "wallets": a.wallets,
                "max_senders": a.max_senders,
                "deployed_accounts": bench.deployed_accounts,
                "deploy_seconds": round(bench.deploy_seconds, 1),
                "wall_seconds": round(time.time() - started, 1),
                "read_retries": sum(c.retries for c in opened),
                "stages": results,
            }
            (a.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({"stages": [{k: s[k] for k in ("offered_rate", "steady_transfer_tps",
                                                             "executed_fraction", "valid", "saturated")}
                                         for s in results]}, indent=2))
            if a.keep_running:
                log.info("bench done; net stays up (Ctrl-C to stop)")
                await asyncio.Event().wait()
        finally:
            for c in opened:
                await c.client.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(parse_args())))
