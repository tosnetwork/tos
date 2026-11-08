#!/usr/bin/env python3
"""Local PQ performance bench: boot a validator net, deploy load accounts, measure TPS.

One process runs the whole bench so every number comes from one chain and one
clock:

1. Boot a local PQ validator net through tostester (Simplex, one basechain shard).
2. Deploy the load accounts from the genesis wallet: relayers, classical Wallet
   V5 accounts and, for the PQ workload, one ML-DSA-44 module per strict PQ
   Wallet V5.
3. For each workload and offered rate: pre-sign every message, send at the
   offered rate, keep scanning every basechain block, drain, then read every
   load wallet's counter to account for each message exactly.

Outputs (under --out): results.json, plus per stage blocks.csv and timeline.csv.
Numbers are local engineering evidence on one host, not public capacity.
"""

import argparse
import asyncio
import csv
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
from pqbench import chain, contracts  # noqa: E402
from pqbench.signer import BatchSigner  # noqa: E402
from pqbench.workload import (  # noqa: E402
    MAX_ACTIONS,
    WORKLOADS,
    ClassicalWallet,
    PqWallet,
    pq_seed,
    sinks,
    submission,
)
from tostester.install import Install  # noqa: E402
from tostester.network import FullNode, Network, StartOptions  # noqa: E402
from toslib import ToslibClient  # noqa: E402

NANO = 1_000_000_000
# The node refuses external messages above 64 KiB; keep headroom for the signed envelope.
EXT_MESSAGE_BUDGET = 60_000
log = logging.getLogger("bench")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--build", type=Path, default=ROOT / "build")
    p.add_argument("--signer", type=Path, default=ROOT / "build/bench-pq-signer/bench-pq-signer")
    p.add_argument("--out", type=Path, required=True, help="new directory for all outputs")
    p.add_argument("--validators", type=int, default=4)
    p.add_argument("--workloads", default="classical,pq-relay")
    p.add_argument("--wallets", type=int, default=2000, help="load wallets per workload")
    p.add_argument("--rates", default="10,50,100,250", help="offered transfers/s per stage")
    p.add_argument("--duration", type=int, default=300, help="seconds of sending per stage")
    p.add_argument("--warmup", type=int, default=30, help="seconds excluded from steady-state TPS")
    p.add_argument("--drain", type=int, default=60, help="seconds to wait after sending")
    p.add_argument("--min-reuse", type=float, default=10.0,
                   help="minimum seconds between two messages from the same account")
    p.add_argument("--relay-batch", type=int, default=16, help="AUTH submissions per relayer external")
    p.add_argument("--relay-value", type=float, default=0.1, help="TOS attached to each submission")
    p.add_argument("--transfer-value", type=float, default=0.001, help="TOS moved per transfer")
    p.add_argument("--wallet-funding", type=float, default=2.0, help="TOS per load wallet")
    p.add_argument("--module-funding", type=float, default=0.5, help="TOS per ML-DSA-44 module")
    p.add_argument("--sinks", type=int, default=256)
    p.add_argument("--deployers", type=int, default=8, help="parallel deployment wallets (1..32)")
    p.add_argument("--signer-threads", type=int, default=8,
                   help="ML-DSA-44 signing threads (kept low by default: signing bursts heat the host)")
    p.add_argument("--send-concurrency", type=int, default=256)
    p.add_argument("--connections-per-node", type=int, default=4,
                   help="liteserver connections per validator (each admits ~48 queries/s here)")
    p.add_argument("--block-limit-mul", type=int, default=1, help=">1 raises block limits (unleashed runs only)")
    p.add_argument("--seed", default="tos-local-pq-bench", help="public run seed (keys are test material)")
    p.add_argument("--stop-on-saturation", action="store_true")
    p.add_argument("--thermal-log", type=Path,
                   help="log of a thermal guard attached to this run's process group; stages overlapping a pause are invalid")
    p.add_argument("--keep-running", action="store_true", help="leave the net up after the bench (Ctrl-C ends)")
    a = p.parse_args()
    a.workloads = [w.strip() for w in a.workloads.split(",") if w.strip()]
    a.rates = [float(r) for r in a.rates.split(",") if r.strip()]
    if not a.workloads or any(w not in WORKLOADS for w in a.workloads):
        p.error(f"workloads must be from {WORKLOADS}")
    if not a.rates or any(not 0 < r <= 100_000 for r in a.rates):
        p.error("rates must be positive")
    if not 4 <= a.validators <= 21:
        p.error("validators must be 4..21")
    if not 1 <= a.wallets <= 1_000_000:
        p.error("wallets must be 1..1000000")
    if not 1 <= a.relay_batch <= MAX_ACTIONS:
        p.error(f"relay batch must be 1..{MAX_ACTIONS}")
    if a.duration < 10 or a.warmup < 0 or a.warmup >= a.duration or a.drain < 5:
        p.error("need duration >= 10, 0 <= warmup < duration, drain >= 5")
    if a.duration + a.drain + 600 > 3500:
        p.error("duration + drain must leave the 3600 s AUTH validity window room for signing")
    for name in ("relay_value", "transfer_value", "wallet_funding", "module_funding"):
        if getattr(a, name) <= 0:
            p.error(f"--{name.replace('_', '-')} must be positive")
    if not 1 <= a.deployers <= 32:
        p.error("deployers must be 1..32")
    if a.block_limit_mul < 1:
        p.error("block limit multiplier must be >= 1")
    return a


def nano(value: float) -> int:
    return int(round(value * NANO))


class Bench:
    def __init__(self, args, network: Network, client, pool: chain.ClientPool, code, net_id: int):
        self.a, self.network, self.client, self.pool, self.code = args, network, client, pool, code
        self.net_id = net_id
        self.run_seed = hashlib.sha256(args.seed.encode()).digest()
        self.sinks = sinks(args.sinks, self.run_seed)
        self.classes: dict[bytes, str] = {s.hash_part: "sink" for s in self.sinks}
        self.seqnos: dict[bytes, int] = {}
        self.max_rate = max(args.rates)

    # ---- sizing -----------------------------------------------------------

    def relayer_count(self) -> int:
        if "pq-relay" not in self.a.workloads:
            return 0
        return max(1, math.ceil(self.max_rate * self.a.min_reuse / self.a.relay_batch))

    def check_reuse(self) -> None:
        if self.a.wallets / self.max_rate < self.a.min_reuse:
            raise SystemExit(
                f"{self.a.wallets} wallets at {self.max_rate}/s reuse a wallet every "
                f"{self.a.wallets / self.max_rate:.1f}s (< --min-reuse {self.a.min_reuse}); "
                "raise --wallets"
            )

    # ---- deployment -------------------------------------------------------

    async def wait_seqno(self, wallet: ClassicalWallet, seqno: int, what: str, timeout: float = 180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            states = await chain.read_wallet_states(self.pool, [wallet.address])
            state = states[wallet.address.hash_part]
            if state is not None and state.seqno >= seqno:
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
                missing: dict[str, int] = {}
                for address in pending:
                    name = self.classes.get(address.hash_part, "other")
                    missing[name] = missing.get(name, 0) + 1
                report = {"missing_by_class": missing, "deployers": {}}
                for d in getattr(self, "deployers", []):
                    report["deployers"][d.address.to_str(False)] = await chain.action_report(self.pool, d.address)
                (self.a.out / "deployment-failure.json").write_text(json.dumps(report, indent=2) + "\n")
                raise RuntimeError(
                    f"{what}: {len(pending)} accounts stopped activating ({missing}); "
                    "see deployment-failure.json")
            if pending:
                log.info("%s: %d of %d not active yet", what, len(pending), len(addresses))
                await asyncio.sleep(2)
        if pending:
            raise RuntimeError(f"{what}: {len(pending)} accounts never became active")

    async def send_batches(self, payers: list[ClassicalWallet], items: list[tuple], what: str):
        """Deploy (blueprint, funding) items through the payers in parallel.

        Each external carries as many deployments as fit the external message
        size limit (and at most 255 actions).
        """
        queue = list(items)
        sent = 0

        async def worker(payer: ClassicalWallet):
            nonlocal sent
            while queue:
                seqno = self.seqnos[payer.address.hash_part]
                _, now = await self._now()
                if not queue:  # another payer took the rest while this one waited
                    break
                take = min(MAX_ACTIONS, len(queue))
                while True:
                    chunk = queue[:take]
                    messages = [bp.deployment_message(payer.address, value) for bp, value in chunk]
                    boc = payer.external(seqno, messages, now + 600).serialize().to_boc()
                    if len(boc) <= EXT_MESSAGE_BUDGET or take == 1:
                        break
                    take = max(1, take * EXT_MESSAGE_BUDGET // len(boc) - 1)
                del queue[:take]
                await self.pool.call("raw_send_message", boc)
                await self.wait_seqno(payer, seqno + 1, f"{what} external from {payer.address.to_str(False)}")
                self.seqnos[payer.address.hash_part] = seqno + 1
                sent += take
                log.info("%s: %d of %d delivered", what, sent, len(items))

        await asyncio.gather(*(worker(p) for p in payers))

    async def _now(self):
        info = await self.pool.call("get_masterchain_info")
        header = await self.pool.call("get_block_header", info.last)
        return info.last.seqno, int(header.gen_utime)

    async def deploy(self):
        a = self.a
        main = self.network.zerostate.main_wallet(self.client)
        main_balance = int((await self.client.raw_get_account_state(main.address)).balance)
        relayers = self.relayer_count()
        relayer_funding = 0
        if relayers:
            stages = sum(a.rates) * a.duration
            relayer_funding = math.ceil(stages * nano(a.relay_value) * 1.2 / relayers) + nano(10)

        deployments: list[tuple] = []
        self.relayers = [
            ClassicalWallet.derive(self.code["wallet"], self.net_id, self.run_seed, "relayer", i)
            for i in range(relayers)
        ]
        for r in self.relayers:
            self.classes[r.address.hash_part] = "relayer"
            deployments.append((r.blueprint, relayer_funding))
        self.classical: list[ClassicalWallet] = []
        if "classical" in a.workloads:
            self.classical = [
                ClassicalWallet.derive(self.code["wallet"], self.net_id, self.run_seed, "classical", i)
                for i in range(a.wallets)
            ]
            for w in self.classical:
                self.classes[w.address.hash_part] = "classical-wallet"
                deployments.append((w.blueprint, nano(a.wallet_funding)))
        self.pq: list[PqWallet] = []
        if "pq-relay" in a.workloads:
            seeds = [pq_seed(self.run_seed, i) for i in range(a.wallets)]
            t = time.time()
            keys = self.signer.public_keys(seeds)
            log.info("derived %d ML-DSA-44 keys in %.1fs", len(keys), time.time() - t)
            self.pq = [
                PqWallet.derive(self.code["wallet"], self.code["module"], self.net_id,
                                self.run_seed, i, keys[i], seeds[i])
                for i in range(a.wallets)
            ]
            for w in self.pq:
                self.classes[w.module.address.hash_part] = "module"
                self.classes[w.address.hash_part] = "pq-wallet"
                deployments.append((w.module, nano(a.module_funding)))
                deployments.append((w.wallet, nano(a.wallet_funding)))

        # Each deployer owns a fixed share and is funded for exactly that share:
        # with a shared queue a fast deployer outruns its funding, and send mode
        # 3 then skips every action it cannot afford without failing the external.
        count = max(1, min(a.deployers, math.ceil(len(deployments) / MAX_ACTIONS / 8)))
        shares = [deployments[i::count] for i in range(count)]
        # Forwarding a StateInit costs far less than this reserve; it only has to
        # make an unaffordable action impossible, not be tight.
        fundings = [sum(v for _, v in share) + len(share) * nano(0.25) + nano(50) for share in shares]
        total = sum(fundings) + nano(10)
        log.info("genesis wallet %.1f TOS; bench needs %.1f TOS", main_balance / NANO, total / NANO)
        if total > main_balance:
            raise SystemExit("the genesis wallet cannot fund this sizing; lower --wallets or funding")

        # The genesis wallet sends one message per external, so it funds only a few deployers.
        self.deployers = [
            ClassicalWallet.derive(self.code["wallet"], self.net_id, self.run_seed, "deployer", i)
            for i in range(count)
        ]
        seqno = (await main.current).seqno
        for d, funding in zip(self.deployers, fundings):
            self.classes[d.address.hash_part] = "deployer"
            await main.deploy(d.blueprint, tos(funding / NANO), seqno)
            seqno += 1
            while (await main.current).seqno < seqno:
                await asyncio.sleep(0.3)
        await self.wait_active([d.address for d in self.deployers], "deployers")
        for d in self.deployers:
            self.seqnos[d.address.hash_part] = 0

        t = time.time()
        await asyncio.gather(*(self.send_batches([d], share, f"deployment/{i}")
                               for i, (d, share) in enumerate(zip(self.deployers, shares))))
        targets = [bp.address for bp, _ in deployments]
        await self.wait_active(targets, "load accounts")
        log.info("deployed %d accounts in %.1fs", len(targets), time.time() - t)
        for r in self.relayers:
            self.seqnos[r.address.hash_part] = 0
        self.deploy_seconds = time.time() - t
        self.deployed_accounts = len(targets)

    # ---- stages -----------------------------------------------------------

    async def stage(self, workload: str, rate: float) -> dict:
        a = self.a
        count = int(rate * a.duration)
        wallets = self.classical if workload == "classical" else self.pq
        n = len(wallets)
        start_states = await chain.read_wallet_states(self.pool, [w.address for w in wallets])
        _, now = await self._now()
        valid_until = now + a.duration + a.drain + 600
        transfer = nano(a.transfer_value)
        t_sign = time.time()
        if workload == "classical":
            messages = []
            for k in range(count):
                w = wallets[k % n]
                state = start_states[w.address.hash_part]
                assert state is not None
                seqno = state.seqno + k // n
                messages.append(w.external(seqno, [w.transfer(self.sinks[k % len(self.sinks)], transfer)], valid_until))
            per_message_offered = 1
        else:
            requests = []
            for k in range(count):
                w = wallets[k % n]
                state = start_states[w.address.hash_part]
                assert state is not None and state.auth is not None
                requests.append((w, w.request(state.auth.nonce + k // n,
                                              self.sinks[k % len(self.sinks)], transfer, valid_until)))
            signatures = self.signer.sign([(w.pq_seed, r.commitment) for w, r in requests])
            batch = a.relay_batch
            messages = []
            for j in range(0, count, batch):
                relayer = self.relayers[(j // batch) % len(self.relayers)]
                seqno = self.seqnos[relayer.address.hash_part]
                self.seqnos[relayer.address.hash_part] = seqno + 1
                subs = [
                    submission(relayer.address, w.module.address, r, signatures[j + i], nano(a.relay_value), j + i)
                    for i, (w, r) in enumerate(requests[j : j + batch])
                ]
                ext = relayer.external(seqno, subs, valid_until)
                if j == 0 and len(ext.serialize().to_boc()) > EXT_MESSAGE_BUDGET:
                    raise SystemExit(f"--relay-batch {batch} exceeds the external message size limit; lower it")
                messages.append(ext)
            per_message_offered = batch
        sign_seconds = time.time() - t_sign
        log.info("%s @ %g/s: %d transfers pre-signed in %.1fs", workload, rate, count, sign_seconds)

        scanner = chain.Scanner(self.scan_client, self.classes)
        scanner.track = {w.address.hash_part for w in wallets}
        await scanner.start_position()
        scan_task = asyncio.create_task(scanner.run())
        t0 = time.time()
        records = await chain.paced_send(self.pool, messages, rate / per_message_offered, a.send_concurrency)
        t_sent = time.time()
        await asyncio.sleep(a.drain)
        scanner.stop()
        await scan_task
        end_states = await chain.read_wallet_states(self.pool, [w.address for w in wallets])

        executed = 0
        for w in wallets:
            s0, s1 = start_states[w.address.hash_part], end_states[w.address.hash_part]
            assert s0 is not None and s1 is not None
            executed += (s1.seqno - s0.seqno) if workload == "classical" else (s1.auth.nonce - s0.auth.nonce)
        if workload == "pq-relay":
            relayer_states = await chain.read_wallet_states(self.pool, [r.address for r in self.relayers])
            for r in self.relayers:
                live = relayer_states[r.address.hash_part]
                if live is not None:
                    self.seqnos[r.address.hash_part] = live.seqno
        result = self.summarize(workload, rate, count, per_message_offered, records, scanner,
                                executed, t0, t_sent, sign_seconds)
        if workload == "classical":
            classes = {"classical-wallet": [w.address for w in wallets]}
        else:
            classes = {"module": [w.module.address for w in wallets], "pq-wallet": [w.address for w in wallets],
                       "relayer": [r.address for r in self.relayers]}
        result["gas_sample"] = await chain.gas_sample(self.pool, classes)
        result["cpu_package_celsius_end"] = package_temperatures()
        # A guard pause stops the validators and the generator together; such a
        # stage measures the pause, not the chain, and must be rerun.
        stage_end = time.time()
        overlapping = [(kind, round(t, 1)) for kind, t in guard_events(a.thermal_log)
                       if t0 - 5 <= t <= stage_end]
        paused_before = [k for k, t in guard_events(a.thermal_log) if t < t0 - 5]
        if paused_before and paused_before[-1] == "paused":
            overlapping.insert(0, ("paused-before-stage", round(t0, 1)))
        result["thermal_guard_events"] = overlapping
        result["valid"] = not overlapping and a.thermal_log is not None
        if a.thermal_log is None:
            result["invalid_reason"] = "no --thermal-log: guard pauses cannot be excluded"
        elif overlapping:
            result["invalid_reason"] = "thermal guard paused the run during this stage; rerun it"
        if not result["valid"]:
            result["saturated"] = None
        stage_dir = a.out / f"stage-{workload}-{rate:g}"
        (stage_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result

    def summarize(self, workload, rate, count, per_message, records, scanner, executed, t0, t_sent, sign_seconds):
        a = self.a
        accepted = sum(1 for r in records if r.ok)
        refused = len(records) - accepted
        errors: dict[str, int] = {}
        for r in records:
            if not r.ok and r.error:
                errors[r.error] = errors.get(r.error, 0) + 1
        wallet_class = "classical-wallet" if workload == "classical" else "pq-wallet"
        lo, hi = t0 + a.warmup, t_sent
        window = [b for b in scanner.rows if lo <= b.observed <= hi]
        span = max(1e-9, hi - lo)
        steady_tx = sum(b.total for b in window) / span
        steady_transfers = sum(b.by_class.get(wallet_class, 0) for b in window) / span
        steady_verifications = sum(b.by_class.get("module", 0) for b in window) / span
        send_lag = [r.sent - r.scheduled for r in records]
        # Inclusion latency: pair each wallet's sends with its observed executions in order.
        latencies = []
        sends_by_wallet: dict[bytes, list[float]] = {}
        wallets = self.classical if workload == "classical" else self.pq
        for r in records:
            for k in range(r.index * per_message, min(count, (r.index + 1) * per_message)):
                sends_by_wallet.setdefault(wallets[k % len(wallets)].address.hash_part, []).append(r.sent)
        for key, sent in sends_by_wallet.items():
            for s, seen in zip(sent, scanner.first_seen.get(key, [])):
                latencies.append(seen - s)
        latencies.sort()

        def pct(p):
            return round(latencies[min(len(latencies) - 1, int(p * len(latencies)))], 3) if latencies else None

        blocks = scanner.rows
        intervals = [b2.gen_utime - b1.gen_utime for b1, b2 in zip(blocks, blocks[1:])]
        result = {
            "workload": workload,
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
            "steady_pq_verifications_per_s": round(steady_verifications, 2),
            "inclusion_latency_s": {"p50": pct(0.5), "p90": pct(0.9), "p99": pct(0.99),
                                    "max": round(latencies[-1], 3) if latencies else None,
                                    "samples": len(latencies)},
            "blocks": len(blocks),
            "max_tx_per_block": max((b.total for b in blocks), default=0),
            "mean_block_interval_s": round(sum(intervals) / len(intervals), 3) if intervals else None,
        }
        below = bool(
            result["executed_fraction"] is not None
            and (result["executed_fraction"] < 0.95 or steady_transfers < 0.9 * rate)
        )
        # Saturation means the chain fell behind. A shortfall that the generator,
        # the node's admission limits or the observer can explain is not that.
        bottlenecks = []
        if refused:
            bottlenecks.append("node admission refusals")
        if send_lag and max(send_lag) > 1.0:
            bottlenecks.append("generator fell behind its schedule")
        if blocks and blocks[-1].observed - blocks[-1].gen_utime > 5:
            bottlenecks.append("block scanner lagged the chain")
        result["below_offered_rate"] = below
        result["non_chain_bottlenecks"] = bottlenecks
        result["saturated"] = below and not bottlenecks
        stage_dir = a.out / f"stage-{workload}-{rate:g}"
        stage_dir.mkdir(parents=True, exist_ok=False)
        classes = sorted({c for b in blocks for c in b.by_class})
        with (stage_dir / "blocks.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["seqno", "gen_utime", "observed", "total_tx", *classes])
            for b in blocks:
                w.writerow([b.seqno, b.gen_utime, f"{b.observed:.3f}", b.total, *[b.by_class.get(c, 0) for c in classes]])
        with (stage_dir / "timeline.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["second", "messages_sent", "messages_refused", "tx_observed", f"{wallet_class}_tx"])
            seconds = int(math.ceil(t_sent - t0 + a.drain)) + 1
            sent = [0] * seconds
            refused_s = [0] * seconds
            tx = [0] * seconds
            wtx = [0] * seconds
            for r in records:
                i = min(seconds - 1, max(0, int(r.sent - t0)))
                sent[i] += 1
                refused_s[i] += 0 if r.ok else 1
            for b in blocks:
                i = min(seconds - 1, max(0, int(b.observed - t0)))
                tx[i] += b.total
                wtx[i] += b.by_class.get(wallet_class, 0)
            for i in range(seconds):
                w.writerow([i, sent[i], refused_s[i], tx[i], wtx[i]])
        (stage_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        log.info("stage result: %s", json.dumps({k: result[k] for k in (
            "workload", "offered_rate", "transfers_executed", "transfers_planned",
            "steady_transfer_tps", "steady_total_tx_tps", "saturated")}))
        return result


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
    import datetime

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
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(a.out / "bench.log")])
    # Node output stays in each node's own log; the console carries bench progress.
    for name in ("tostester", "tostester.network") + tuple(f"node-{i}" for i in range(1, 32)) + ("dht-0",):
        logging.getLogger(name).setLevel(logging.WARNING)
    signer = BatchSigner(a.signer, a.signer_threads)
    code = contracts.build(a.build, a.out / "contracts")
    install = Install(a.build, ROOT)
    install.toslibjson.client_set_verbosity_level(1)
    working_dir = a.out / "network"
    working_dir.mkdir()
    results = []
    started = time.time()
    async with Network(install, working_dir) as network:
        if network.config.auth_network_tag is None:
            network.config.auth_network_tag = hashlib.sha256(b"tos-local-pq-bench").digest()
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
        clients = []
        for node in nodes:
            for k in range(a.connections_per_node):
                c = ToslibClient(node.liteserver_config, install.toslibjson)
                await c.init()
                clients.append(chain.PacedClient(c, f"{node.name}/{k}"))
        scan = ToslibClient(nodes[-1].liteserver_config, install.toslibjson)
        await scan.init()
        pool = chain.ClientPool(clients)
        log.info("client pool: %d connections, %.0f queries/s", len(clients), pool.qps)
        bench = Bench(a, network, client, pool, code, net_id)
        bench.scan_client = chain.PacedClient(scan, "scanner")
        bench.signer = signer
        try:
            await run_bench(a, bench, net_id, results, started)
        finally:
            for c in [*clients, bench.scan_client]:
                await c.client.aclose()
    return 0


async def run_bench(a, bench, net_id, results, started) -> None:
    bench.check_reuse()
    chain_config = await chain.config_snapshot(bench.pool)
    await bench.deploy()
    for workload in a.workloads:
        for rate in a.rates:
            result = await bench.stage(workload, rate)
            results.append(result)
            if a.stop_on_saturation and result["saturated"]:
                log.info("%s saturated at %g/s; skipping higher rates", workload, rate)
                break
    report = {
        "scope": "LOCAL_ENGINEERING_EVIDENCE_ONLY: one host, co-located validators; not public capacity",
        "source_commit": source_commit(),
        "host": {"platform": platform.platform(), "cpus": os.cpu_count(),
                 "affinity": sorted(os.sched_getaffinity(0))},
        "validators": a.validators,
        "global_id": net_id,
        "block_limit_mul": a.block_limit_mul,
        "limits_profile": ("local test genesis: basechain block gas soft/hard 100M (deployment"
                           " profile is lower); see chain_config for the exact parameters"),
        "chain_config": chain_config,
        "wallets_per_workload": a.wallets,
        "relayers": len(bench.relayers),
        "relay_batch": a.relay_batch,
        "deployed_accounts": bench.deployed_accounts,
        "deploy_seconds": round(bench.deploy_seconds, 1),
        "wall_seconds": round(time.time() - started, 1),
        "read_retries": sum(c.retries for c in bench.pool.clients) + bench.scan_client.retries,
        "stages": results,
    }
    (a.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"stages": [{k: s[k] for k in ("workload", "offered_rate", "steady_transfer_tps",
                                                     "executed_fraction", "saturated")} for s in results]},
                     indent=2))
    if a.keep_running:
        log.info("bench done; net stays up (Ctrl-C to stop)")
        await asyncio.Event().wait()


if __name__ == "__main__":
    sys.exit(asyncio.run(main(parse_args())))
