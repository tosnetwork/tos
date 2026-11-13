"""T4 transfer ramp: the per-transfer ledger, the step pass rule, the bound, and a remote run.

Run: uv run python bench/tests/test_t4.py

The end-to-end test runs ``run_t4_ramp.py`` in a child process against a fake
JSON-RPC node served over loopback HTTP, with liteserver and local-net modules
made unimportable, a fake signer, and a key made of test material only.
"""

import argparse
import asyncio
import base64
import hashlib
import http.server
import json
import math
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections import Counter
from pathlib import Path
from typing import Any, cast
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from contract.pq_auth import transfer_message  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Cell,
)
from shard import journal as jr  # noqa: E402
from shard import remote, t2collect  # noqa: E402
from shard.rpc import PacedRpc, ReaderPool, RpcError  # noqa: E402
from shard.t2check import McRecord, Msg, Tx  # noqa: E402
from t4 import ramp  # noqa: E402
from t4.ledger import (  # noqa: E402
    ACCEPTED,
    COMPLETED,
    DELIVERED_FAILED,
    OUTCOMES,
    PENDING,
    REFUSED,
    SKIPPED,
    UNKNOWN,
    External,
    Ledger,
    StepRule,
    step_layout,
    step_metrics,
)
from tests import test_remote as tr  # noqa: E402

NANO = remote.NANO
SENDER = "0:" + "aa" * 32
PEERS = ["0:" + f"{b:02x}" * 32 for b in (0xB1, 0xB2, 0xB3)]
BENCH = Address("0:" + "cc" * 32)  # a bench wallet address for deriving load seeds


def h(*parts: object) -> str:
    return hashlib.sha256(repr(parts).encode()).hexdigest()


def ext_of(ledger: Ledger, seqno: int = 0, n: int = 3, step: int = 0) -> External:
    ext = External(
        wallet=0,
        seqno=seqno,
        nonce=seqno,
        step=step,
        intended=100.0,
        sender=SENDER,
        destinations=tuple(PEERS[i % len(PEERS)] for i in range(n)),
        values=tuple(1000 + i for i in range(n)),
    )
    ledger.add(ext)
    ledger.submitted(ext, h("ext", seqno), "url", 100.0)
    return ext


def out_msg(ext: External, i: int) -> Msg:
    return Msg(
        h("out", ext.msg_hash, i), "internal", SENDER, ext.destinations[i], False, ext.values[i]
    )


def wallet_tx(ext: External, emit: list[int], skipped: int = 0, success: bool = True) -> Tx:
    return Tx(
        hash=h("tx", ext.msg_hash),
        account=SENDER,
        lt=1,
        block=(0, 0, 1),
        in_msg=Msg(ext.msg_hash, "external"),
        out_msgs=tuple(out_msg(ext, i) for i in emit),
        action_success=success,
        skipped_actions=skipped,
        phase_failure=None,
    )


def delivery(
    message: Msg, account: str | None = None, lt: int = 2, failure: str | None = None
) -> Tx:
    return Tx(
        hash=h("rx", message.hash, lt),
        account=account or message.destination or "",
        lt=lt,
        block=(0, 0, 2),
        in_msg=message,
        aborted=failure == "transaction aborted",
        phase_failure=failure,
    )


def ledger() -> Ledger:
    return Ledger([SENDER, *PEERS])


# ─── the ledger ──────────────────────────────────────────────────────


class LedgerOutcomes(unittest.TestCase):
    def test_every_action_completes_when_delivered_and_finalized(self):
        lg = ledger()
        ext = ext_of(lg)
        lg.accept(ext)
        lg.observe([(wallet_tx(ext, [0, 1, 2]), 10, 1000)])
        lg.observe([(delivery(out_msg(ext, i)), 11, 1001) for i in range(3)])
        self.assertEqual([ext.outcome(i, 11)[0] for i in range(3)], [COMPLETED] * 3)
        self.assertEqual(lg.counts(11)[COMPLETED], 3)
        self.assertEqual(lg.anomalies, [])

    def test_a_skipped_action_is_not_counted_as_completed(self):
        lg = ledger()
        ext = ext_of(lg)
        lg.accept(ext)
        # Action 1 is skipped: the transaction emits actions 0 and 2 only.
        lg.observe([(wallet_tx(ext, [0, 2], skipped=1), 10, 1000)])
        lg.observe([(delivery(out_msg(ext, i)), 11, 1001) for i in (0, 2)])
        outcomes = [ext.outcome(i, 20)[0] for i in range(3)]
        self.assertEqual(outcomes, [COMPLETED, SKIPPED, COMPLETED])
        self.assertEqual(lg.counts(20), {**dict.fromkeys(OUTCOMES, 0), COMPLETED: 2, SKIPPED: 1})
        self.assertEqual(lg.anomalies, [])

    def test_a_failed_action_phase_fails_every_action(self):
        lg = ledger()
        ext = ext_of(lg)
        lg.accept(ext)
        lg.observe([(wallet_tx(ext, [], success=False), 10, 1000)])
        self.assertEqual({ext.outcome(i, 10) for i in range(3)}, {(SKIPPED, "action phase failed")})
        # Not yet final: an executed external above finality is still pending.
        self.assertEqual(ext.outcome(0, 9)[0], PENDING)

    def test_an_ambiguous_submission_stays_unknown(self):
        lg = ledger()
        ext = ext_of(lg)
        lg.ambiguous(ext, "no answer: TimeoutError")
        # Even when the chain later shows the external and every delivery.
        lg.observe([(wallet_tx(ext, [0, 1, 2]), 10, 1000)])
        lg.observe([(delivery(out_msg(ext, i)), 11, 1001) for i in range(3)])
        self.assertEqual(
            {ext.outcome(i, 99) for i in range(3)}, {(UNKNOWN, "no answer: TimeoutError")}
        )
        with self.assertRaises(ValueError):
            lg.submitted(ext, ext.msg_hash, "url", 101.0)

    def test_the_same_message_is_never_submitted_twice(self):
        lg = ledger()
        ext = ext_of(lg)
        other = External(0, 1, 1, 0, 1.0, SENDER, (PEERS[0],), (5,))
        lg.add(other)
        with self.assertRaises(ValueError):
            lg.submitted(other, ext.msg_hash, "url", 1.0)
        with self.assertRaises(ValueError):
            lg.add(External(0, 1, 1, 0, 1.0, SENDER, (PEERS[0],), (5,)))

    def test_a_completed_transfer_above_the_finalized_seqno_is_not_completed(self):
        lg = ledger()
        ext = ext_of(lg, n=1)
        lg.accept(ext)
        lg.observe([(wallet_tx(ext, [0]), 10, 1000)])
        lg.observe([(delivery(out_msg(ext, 0)), 12, 1002)])
        self.assertEqual(ext.outcome(0, 11)[0], PENDING)
        self.assertEqual(ext.outcome(0, None)[0], PENDING)
        self.assertEqual(ext.outcome(0, 12)[0], COMPLETED)

    def test_a_recipient_transaction_for_another_message_does_not_complete(self):
        lg = ledger()
        ext = ext_of(lg, n=1)
        lg.accept(ext)
        lg.observe([(wallet_tx(ext, [0]), 10, 1000)])
        real = out_msg(ext, 0)
        # Same source, destination and value, but another message.
        lookalike = Msg(h("other"), "internal", SENDER, real.destination, False, real.value)
        lg.observe([(delivery(lookalike), 11, 1001)])
        self.assertEqual(ext.outcome(0, 99)[0], PENDING)
        # The right message delivered to another account does not complete either.
        lg.observe([(delivery(real, account=PEERS[2]), 11, 1001)])
        self.assertEqual(ext.outcome(0, 99)[0], PENDING)
        self.assertTrue(any("does not match" in a["reason"] for a in lg.anomalies))
        lg.observe([(delivery(real), 12, 1002)])
        self.assertEqual(ext.outcome(0, 99)[0], COMPLETED)

    def test_a_failed_recipient_transaction_is_delivered_failed_never_completed(self):
        lg = ledger()
        ext = ext_of(lg)
        lg.accept(ext)
        lg.observe([(wallet_tx(ext, [0, 1, 2]), 10, 1000)])
        lg.observe(
            [
                (delivery(out_msg(ext, 0)), 11, 1001),
                (delivery(out_msg(ext, 1), failure="transaction aborted"), 11, 1001),
                (
                    delivery(out_msg(ext, 2), failure="compute phase failed (exit code 33)"),
                    11,
                    1001,
                ),
            ]
        )
        self.assertEqual(
            [ext.outcome(i, 11) for i in range(3)],
            [
                (COMPLETED, None),
                (DELIVERED_FAILED, "transaction aborted"),
                (DELIVERED_FAILED, "compute phase failed (exit code 33)"),
            ],
        )
        # Judged against finality like a completion, and counted on its own.
        self.assertEqual(ext.outcome(1, 10)[0], PENDING)
        self.assertEqual(
            lg.counts(11), {**dict.fromkeys(OUTCOMES, 0), COMPLETED: 1, DELIVERED_FAILED: 2}
        )
        self.assertTrue(ext.settled())
        [row] = list(lg.rows(11))
        self.assertEqual(
            [a["receipt_failure"] for a in row["actions"]],
            [None, "transaction aborted", "compute phase failed (exit code 33)"],
        )
        metrics = step_metrics([ext], 100, 2000, 11, StepRule())
        self.assertEqual((metrics["offered"], metrics["completed_in_window"]), (3, 1))
        self.assertEqual(metrics["latency_samples"], 1)

    def test_the_servers_rendering_decides_whether_a_receipt_executed(self):
        ok = {"skipped": False, "success": True, "exit_code": 0, "account_activated": False}
        cases: list[tuple[dict[str, Any], str | None]] = [
            ({"aborted": False, "compute": ok}, None),
            ({"aborted": False, "compute": {"skipped": True, "skip_reason": 0}}, None),
            ({"aborted": True, "compute": ok}, "transaction aborted"),
            ({"compute": ok}, "abort flag not shown"),
            (
                {"aborted": False, "compute": {**ok, "success": False, "exit_code": 33}},
                "compute phase failed (exit code 33)",
            ),
            (
                {"aborted": False, "compute": {"skipped": True, "skip_reason": 2}},
                "compute phase skipped (reason 2)",
            ),
            ({"aborted": False, "compute": None}, "compute phase not shown"),
            ({"aborted": False}, "compute phase not shown"),
        ]
        for rendered, failure in cases:
            value = {
                "account": "ab" * 32,
                "lt": "5",
                "hash": base64.b64encode(bytes(32)).decode(),
                "in_msg": None,
                "out_msgs": [],
                **rendered,
            }
            tx = t2collect.parse_transaction(value, (0, 0, 1))
            self.assertEqual(tx.phase_failure, failure, rendered)
        # An abort flag the node could not decode is refused, never read as "not shown".
        with self.assertRaises(ValueError):
            t2collect.parse_transaction(
                {
                    "account": "ab" * 32,
                    "lt": "5",
                    "hash": base64.b64encode(bytes(32)).decode(),
                    "in_msg": None,
                    "out_msgs": [],
                    "aborted": None,
                    "compute": ok,
                },
                (0, 0, 1),
            )

    def test_a_second_delivery_is_a_duplicate(self):
        lg = ledger()
        ext = ext_of(lg, n=1)
        lg.accept(ext)
        lg.observe([(wallet_tx(ext, [0]), 10, 1000)])
        lg.observe([(delivery(out_msg(ext, 0)), 11, 1001)])
        lg.observe([(delivery(out_msg(ext, 0), lt=9), 12, 1002)])
        self.assertEqual(lg.duplicates, 1)

    def test_a_delivery_seen_before_its_emitting_transaction_is_bound(self):
        lg = ledger()
        ext = ext_of(lg, n=1)
        lg.accept(ext)
        lg.observe([(delivery(out_msg(ext, 0)), 10, 1000)])
        lg.observe([(wallet_tx(ext, [0]), 10, 1000)])
        self.assertEqual(ext.outcome(0, 10)[0], COMPLETED)

    def test_external_validation(self):
        with self.assertRaises(ValueError):
            External(0, 0, 0, 0, 0.0, SENDER, (SENDER,), (1,))  # self-transfer
        with self.assertRaises(ValueError):
            External(0, 0, 0, 0, 0.0, SENDER, (PEERS[0], PEERS[0]), (1, 1))  # ambiguous binding
        with self.assertRaises(ValueError):
            External(0, 0, 0, 0, 0.0, SENDER, (PEERS[0],), (0,))  # zero amount
        with self.assertRaises(ValueError):
            External(0, 0, 0, 0, 0.0, SENDER, (), ())  # empty
        with self.assertRaises(ValueError):
            External(
                0, 0, 0, 0, 0.0, SENDER, tuple(PEERS[0] for _ in range(256)), tuple(range(1, 257))
            )


# ─── the step pass rule ──────────────────────────────────────────────


def timed(sent: float, latency: float | None, step: int = 0) -> External:
    """One accepted single-transfer external sent at ``sent``, completed ``latency`` later."""
    ext = External(0, int(sent * 10), 0, step, sent, SENDER, (PEERS[0],), (7,))
    ext.submission, ext.sent_at = ACCEPTED, sent
    ext.msg_hash = h("t", sent)
    ext.tx_hash, ext.tx_mc, ext.tx_utime = h("tx", sent), 1, int(sent)
    ext.emitted[0] = h("e", sent)
    if latency is not None:
        ext.recipient_tx[0], ext.recipient_mc[0] = h("r", sent), 1
        ext.recipient_utime[0] = int(sent + latency)
    return ext


def series(
    latency: Any, first: int = 60, last: int = 200, missing: frozenset[int] = frozenset()
) -> list[External]:
    """One transfer per second from ``first`` to ``last`` - 1."""
    return [timed(float(t), None if t in missing else latency(t)) for t in range(first, last)]


class PassRule(unittest.TestCase):
    rule = StepRule(tolerance=0.01, p95_limit=30.0, backlog_slack=0)

    def metrics(self, exts: list[External], rule: StepRule | None = None) -> dict[str, Any]:
        return step_metrics(exts, 100, 200, 10, rule or self.rule)

    def test_steady_load_passes(self):
        m = self.metrics(series(lambda t: 2))
        self.assertEqual((m["offered"], m["completed_in_window"]), (100, 100))
        self.assertEqual((m["backlog_at_start"], m["backlog_at_end"]), (2, 2))
        self.assertEqual(m["p95_s"], 2)
        self.assertTrue(m["passed"], m)

    def test_throughput_must_match_offered_within_one_percent(self):
        one = self.metrics(series(lambda t: 2, missing=frozenset({150})), StepRule(0.01, 30.0, 5))
        self.assertEqual(one["completed_in_window"], 99)
        self.assertTrue(one["checks"]["throughput_within_tolerance"], one)
        two = self.metrics(
            series(lambda t: 2, missing=frozenset({150, 151})), StepRule(0.01, 30.0, 5)
        )
        self.assertEqual(two["completed_in_window"], 98)
        self.assertFalse(two["checks"]["throughput_within_tolerance"], two)
        self.assertTrue(two["checks"]["backlog_not_growing"], two)
        self.assertTrue(two["checks"]["p95_within_limit"], two)
        self.assertFalse(two["passed"])

    def test_a_growing_backlog_fails(self):
        m = self.metrics(series(lambda t: 2 if t < 150 else 3))
        self.assertEqual((m["backlog_at_start"], m["backlog_at_end"]), (2, 3))
        self.assertTrue(m["checks"]["throughput_within_tolerance"], m)
        self.assertTrue(m["checks"]["p95_within_limit"], m)
        self.assertFalse(m["checks"]["backlog_not_growing"], m)
        self.assertFalse(m["passed"])

    def test_p95_over_thirty_seconds_fails(self):
        at = self.metrics(series(lambda t: 30))
        self.assertTrue(at["passed"], at)
        over = self.metrics(series(lambda t: 2 if t % 10 else 31))
        self.assertEqual(over["p50_s"], 2)
        self.assertGreater(over["p95_s"], 30)
        self.assertFalse(over["checks"]["p95_within_limit"], over)
        self.assertFalse(over["passed"])

    def test_unfinished_transfers_are_unbounded_latency(self):
        m = self.metrics(
            series(lambda t: 2, missing=frozenset(range(100, 110))), StepRule(0.5, 30.0, 50)
        )
        self.assertEqual(m["latency_unbounded"], 10)
        self.assertIsNone(m["p95_s"])
        self.assertFalse(m["checks"]["p95_within_limit"])

    def test_drain_completions_do_not_count(self):
        # Everything completes, but only after the window ends.
        m = self.metrics(series(lambda t: 250 - t, first=100))
        self.assertEqual(m["completed_in_window"], 0)
        self.assertFalse(m["passed"])

    def test_percentile_is_nearest_rank(self):
        from t4.ledger import percentile

        self.assertIsNone(percentile([], 0.95))
        self.assertEqual(percentile([float(x) for x in range(1, 101)], 0.95), 95.0)
        self.assertEqual(percentile([1.0, math.inf], 0.95), math.inf)


# ─── the bound ───────────────────────────────────────────────────────


def plan(**kw: Any) -> ramp.Plan:
    base: dict[str, Any] = dict(
        wallets=10,
        batch=100,
        start_rate=100.0,
        factor=2.0,
        steps=3,
        step_seconds=300,
        warmup=30,
        repeats=1,
        transfer_value=NANO // 1000,
        wallet_funding=50 * NANO,
        deploy_batch=35,
    )
    base.update(kw)
    return ramp.Plan(**base)


class Bound(unittest.TestCase):
    def test_bound_counts_every_step_and_repeat(self):
        b = ramp.work_bound(plan())
        per_step = [30_000, 60_000, 120_000]
        self.assertEqual(b.transfers, 2 * sum(per_step))
        self.assertEqual(b.load_externals, 2 * sum(t // 100 for t in per_step))
        self.assertEqual(ramp.planned_sizes(plan()), {100: 2 * 2100})
        self.assertEqual(b.deploy_externals, 1)
        self.assertEqual(b.funding, 500 * NANO)
        # Before the configuration is read there is no fee bound: the funding alone.
        self.assertEqual((b.cost, b.bench_fees, b.load_fees), (b.funding, 0, 0))
        # A remainder external is counted at its own size, once per run of its step.
        odd = plan(start_rate=7.0, step_seconds=10, warmup=1, steps=2, batch=4)
        self.assertEqual(ramp.planned_sizes(odd), {2: 2, 4: 2 * (17 + 35)})
        self.assertEqual(ramp.work_bound(odd).transfers, 2 * (70 + 140))

    def test_over_a_cap_is_refused(self):
        p = plan(wallet_funding=10_000 * NANO, wallets=3, steps=1, step_seconds=2, warmup=1)
        b = ramp.work_bound(p, derived_fees(p))
        self.assertGreater(b.bench_fees, 0)
        self.assertIsNone(ramp.refusal(b, b.cost, b.transfers))
        self.assertIn("cost bound", ramp.refusal(b, b.cost - 1, b.transfers) or "")
        self.assertIn("transfer bound", ramp.refusal(b, b.cost, b.transfers - 1) or "")
        starved_plan = plan(wallet_funding=NANO, wallets=3, steps=1, step_seconds=2, warmup=1)
        starved = ramp.work_bound(starved_plan, derived_fees(starved_plan))
        self.assertGreater(starved.load_fees, starved.funding)
        self.assertIn("load fee bound", ramp.refusal(starved, 1 << 100, 1 << 30) or "")

    def test_plans_outside_their_bounds_are_refused(self):
        for bad in (
            dict(wallets=1),
            dict(batch=0),
            dict(batch=256),
            dict(steps=0),
            dict(warmup=300),
            dict(start_rate=0.0),
            dict(start_rate=math.inf),
            dict(factor=0.5),
            dict(transfer_value=0),
            dict(wallet_funding=0),
            dict(deploy_batch=0),
        ):
            with self.assertRaises(ValueError, msg=bad):
                ramp.validate_plan(plan(**bad))

    def test_destinations_never_include_the_sender(self):
        for n in (2, 3, 7):
            for sender in range(n):
                for seqno in range(4):
                    peers = ramp.destinations(sender, seqno, 255, 255, n)
                    self.assertNotIn(sender, peers)
                    self.assertTrue(all(0 <= p < n for p in peers))

    def test_a_full_batch_fits_one_external(self):
        transfer, deploy_batch, deploy = ramp.size_plan(tr.WALLET_CODE, 255, NANO, NANO)
        self.assertLessEqual(transfer, ramp.EXT_MESSAGE_BUDGET)
        self.assertLessEqual(deploy, ramp.EXT_MESSAGE_BUDGET)
        self.assertGreaterEqual(deploy_batch, 1)


# ─── the fee bound from hand-built ConfigParams ───────────────────────


def test_loads(n: int) -> list[Any]:
    return [
        ramp.load_wallet(tr.WALLET_CODE, 3, tr.AUTH, i, bytes([i]) * 1312, bytes(32))
        for i in range(n)
    ]


def test_bench() -> remote.BenchWallet:
    key = remote.WalletKey(remote.Secret(tr.TEST_SEED), tr.TEST_RESCUE, 0)
    w = remote.bench_wallet(tr.WALLET_CODE, 3, tr.AUTH, key, tr.fake_public_key(tr.TEST_SEED))
    return remote.BenchWallet(w, cast(Any, None), cast(Any, None))


def derived_fees(p: ramp.Plan) -> ramp.RampFees:
    """The whole ramp's fee bound for ``p`` under the hand-built ConfigParams 18, 21 and 25."""
    loads = test_loads(p.wallets)
    bench = test_bench()
    actions = [w.deployment_message(bench.address, p.wallet_funding) for w in loads]
    return ramp.derive_fees(
        tr.fake_fee_config(),
        p,
        2_000_000,
        1_000_000,
        bench,
        False,
        (3, 900, 1_000_000, 17),
        actions,
        [p.wallet_funding] * p.wallets,
        loads,
        [None] * p.wallets,
    )


# ConfigParam 21 of test_remote: 40,000 nanotos for the first 100 gas, then 400 a gas
# (26,214,400 / 2^16), up to 1,000,000 gas. ConfigParam 25: lump 100,000, a bit
# 655,361 / 2^16, a cell 65,536,000 / 2^16 = 1,000.
GAS_AT_LIMIT = 40_000 + 400 * (1_000_000 - 100)
EMPTY_BODY_FORWARD = 100_000 + 1_000


class FeeBound(unittest.TestCase):
    def test_a_100_action_external_matches_a_hand_computation(self):
        p = plan(wallets=4, batch=100, steps=1, step_seconds=1, warmup=0, repeats=0)
        self.assertEqual(ramp.planned_sizes(p), {100: 1})
        loads = test_loads(4)
        fee = ramp.transfer_bounds(tr.fake_fee_config(), loads, p)[100]
        # The same external, built by hand: wallet 0 pays wallets 1, 2, 3, 1, ... in turn.
        sender = loads[0]
        actions = [
            transfer_message(sender.address, loads[1 + i % 3].address, NANO // 1000 + i)
            for i in range(100)
        ]
        request = sender.request(0, actions, 1, mode=3)
        root = sender.external(request, bytes(remote.SIGNATURE_BYTES)).serialize()
        cells = tr.all_cells([root])
        import_cells = len(cells) - 1
        import_bits = sum(len(c.bits) for c in cells.values())
        self.assertGreater(import_cells, 200)  # 100 action nodes and 100 messages at least
        import_fee = 100_000 + tr.ceil16(655_361 * import_bits + 65_536_000 * import_cells)
        self.assertEqual((fee.import_cells, fee.import_bits), (import_cells, import_bits))
        self.assertEqual(fee.import_fee, import_fee)
        self.assertEqual(GAS_AT_LIMIT, 400_000_000)
        self.assertEqual(fee.gas_fee, 400_000_000)
        self.assertEqual(fee.out_messages, [{"cells": 1, "bits": 0, "fee": 101_000}] * 100)
        self.assertEqual(fee.total, import_fee + 400_000_000 + 100 * EMPTY_BODY_FORWARD)

    def test_every_sender_and_seqno_has_the_same_bound(self):
        p = plan(wallets=5, batch=100, steps=1, step_seconds=1, warmup=0, repeats=0)
        config = tr.fake_fee_config()
        loads = test_loads(5)
        expected = ramp.transfer_bounds(config, loads, p)[100].total
        for sender in range(5):
            for seqno in range(3):
                peers = ramp.destinations(sender, seqno, 100, 100, 5)
                actions = ramp.transfer_actions(
                    loads[sender].address,
                    [loads[x].address for x in peers],
                    [p.transfer_value + i for i in range(100)],
                )
                external = ramp.unsigned_external(loads[sender], actions)
                got = remote.external_fee_bound(config, "x", external, actions).total
                self.assertEqual(got, expected, (sender, seqno))

    def test_the_computation_a_received_value_can_buy(self):
        gas = tr.fake_fee_config().gas
        # (1,000,000 - 40,000) * 2^16 / 26,214,400 = 2,400 gas past the flat 100.
        self.assertEqual(gas.bought_for(1_000_000), 2_500)
        self.assertEqual(gas.internal_fee(1_000_000), 40_000 + 400 * 2_400)
        self.assertEqual(gas.internal_fee(39_999), 40_000)  # buys nothing: the flat price
        self.assertEqual(gas.internal_fee(10 * NANO), 400_000_000)  # capped at gas_limit

    def test_the_whole_ramp_bound_sums_every_external_of_every_step_and_repeat(self):
        p = plan(start_rate=7.0, step_seconds=10, warmup=1, steps=2, batch=4, wallets=6)
        fees = derived_fees(p)
        sizes = {2: 2, 4: 104}
        self.assertEqual(fees.transfer_counts, sizes)
        self.assertEqual(
            fees.transfer_total, sum(fees.transfers[k].total * n for k, n in sizes.items())
        )
        for k in sizes:
            self.assertEqual(
                fees.transfers[k].total,
                fees.transfers[k].import_fee + 400_000_000 + k * EMPTY_BODY_FORWARD,
            )
        # 50 TOS of funding buys gas_limit; 0.001 TOS + i buys exactly 1,000,000 nanotos of gas.
        self.assertEqual(fees.receipts, 6 * 400_000_000)
        self.assertEqual(fees.recipients, 2 * (70 + 140) * 1_000_000)
        self.assertEqual(len(fees.load_storage), 6)
        self.assertEqual(
            fees.load_total,
            fees.transfer_total
            + fees.receipts
            + fees.recipients
            + sum(x.fee for x in fees.load_storage),
        )
        self.assertEqual(len(fees.funding), 1)
        self.assertEqual(fees.funding[0].gas_fee, 400_000_000)
        self.assertEqual(fees.bench_storage.due_payment, 17)
        self.assertEqual(fees.bench_total, fees.funding[0].total + fees.bench_storage.fee)
        b = ramp.work_bound(p, fees)
        self.assertEqual(b.cost, b.funding + fees.bench_total)
        self.assertEqual(b.fee_spend, fees.bench_total + fees.load_total)

    def test_a_fee_bound_not_covered_by_max_cost_is_refused(self):
        p = plan(wallets=3, steps=1, step_seconds=2, warmup=1)
        with_fees = ramp.work_bound(p, derived_fees(p))
        covered = with_fees.funding + with_fees.bench_fees
        self.assertIsNone(ramp.refusal(with_fees, covered, with_fees.transfers))
        self.assertIn("cost bound", ramp.refusal(with_fees, covered - 1, 1 << 30) or "")
        # The funding alone fits, so only the derived fee bound makes it refuse.
        self.assertIsNone(ramp.refusal(ramp.work_bound(p), covered - 1, 1 << 30))

    def test_the_horizon_covers_the_plan_and_fits_a_deadline(self):
        args = argparse.Namespace(
            deploy_wait=10.0, drain=2.0, finality_wait=3.0, lifetime=5, deadline_grace=1.0
        )
        p = plan(steps=2, step_seconds=10, warmup=1, repeats=1)
        horizon = ramp.fee_horizon(1_000, p, args, 2)
        self.assertEqual(horizon, 1_000 + 1_200 + 30 + 2 * 2 * 17 + 2 + 10 + 1 + 3)
        with self.assertRaises(ValueError):
            ramp.fee_horizon((1 << 32) - 10, p, args, 2)


# ─── submissions: refused, ambiguous, never resent ───────────────────


class FakeSigner:
    def __init__(self) -> None:
        self.calls = 0

    def sign(self, jobs: list[tuple[remote.Secret, bytes]]) -> list[bytes]:
        self.calls += 1
        return [bytes(remote.SIGNATURE_BYTES) for _ in jobs]


class Transport:
    """Answers queued per call: (status, document) or an exception to raise."""

    def __init__(self, answers: list[Any], nonce: int = 0, head_utime: int | None = 1_000):
        """``head_utime`` is the live head's time; None answers every head read with an error."""
        self.answers, self.nonce, self.head_utime = list(answers), nonce, head_utime
        self.sends: list[str] = []
        self.head_reads = 0

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        request = json.loads(body)
        if request["method"] in ("getMasterchainInfo", "getBlockHeader"):
            self.head_reads += 1
            if self.head_utime is None:
                return 200, json.dumps({"error": {"code": -32603, "message": "no head"}}).encode()
            result: dict[str, Any] = {"last": tr.block_id(-1, 7)}
            if request["method"] == "getBlockHeader":
                result = {"id": tr.block_id(-1, 7), "gen_utime": self.head_utime}
            return 200, json.dumps({"result": result}).encode()
        if request["method"] == "getAddressInformation":
            data = base64.b64encode(tr.wallet_data(self.nonce).to_boc()).decode()
            result = {"state": "active", "balance": "1", "data": data}
            return 200, json.dumps({"result": result}).encode()
        self.sends.append(request["params"]["boc"])
        answer = self.answers.pop(0) if self.answers else (200, {"result": {"status": 1}})
        if isinstance(answer, BaseException):
            raise answer
        status, document = answer
        return status, json.dumps(document).encode()


def rpc_error(code: int, message: str) -> tuple[int, dict[str, Any]]:
    return 200, {"error": {"code": code, "message": message}}


# Every test ramp journals into its own directory under this one.
JOURNALS = tempfile.TemporaryDirectory()


def new_journal() -> jr.Journal:
    return jr.Journal(Path(tempfile.mkdtemp(dir=JOURNALS.name)) / jr.NAME)


def make_ramp(
    transport: Any,
    wallets: int = 2,
    horizon: int = 1 << 31,
    fee_bound: int = NANO,
    storage: int = 0,
) -> ramp.Ramp:
    args = argparse.Namespace(lifetime=60, deadline_grace=5.0, stop_file=None, tick=0.0)
    p = plan(wallets=wallets, batch=3)
    reader = PacedRpc("http://fake", 1.0, transport=transport)
    sender = PacedRpc("http://fake", 1.0, attempts=1, budget=reader.budget, transport=transport)
    load = [
        ramp.LoadWallet(
            i,
            ramp.load_wallet(tr.WALLET_CODE, 3, tr.AUTH, i, bytes([i]) * 1312, bytes(32)),
            remote.Secret(bytes(32)),
        )
        for i in range(wallets)
    ]
    lg = Ledger(w.address for w in load)
    r = ramp.Ramp(
        args,
        p,
        StepRule(),
        [ramp.Endpoint("http://fake", reader, sender)],
        FakeSigner(),
        load,
        lg,
        horizon,
        {3: fee_bound},
        [storage] * wallets,
        new_journal(),
    )
    r.follower = ramp.Follower(reader, lg, r.included, McRecord(1, 1000, "00" * 32, ()), 0.0)
    return r


async def issue_and_wait(r: ramp.Ramp, count: int = 1) -> list[External]:
    before = len(r.ledger.externals)
    await r.issue(0, [(float(time.time()), 3)] * count)
    while r.tasks:
        await asyncio.gather(*list(r.tasks))
    return r.ledger.externals[before:]


class Submissions(unittest.TestCase):
    def test_a_refused_external_marks_every_action_refused_with_its_reason(self):
        cases = [
            (rpc_error(-32005, "rate limited"), "rate gate: -32005", False),
            ((429, {}), "rate gate: HTTP 429", False),
            (
                rpc_error(
                    -32603,
                    "sendBoc failed: cannot apply external message to current state : "
                    "inbound external message rejected by transaction AB:\nexitcode=1804, steps=9",
                ),
                "seqno conflict: the wallet's nonce moved",
                True,
            ),
            (
                rpc_error(
                    -32603,
                    "sendBoc failed: cannot apply external message to current state : exitcode=35, steps=3",
                ),
                "external rejected",
                False,
            ),
        ]
        for answer, reason, resync in cases:
            r = make_ramp(Transport([answer]))
            [ext] = asyncio.run(issue_and_wait(r))
            outcomes = {ext.outcome(i, 99) for i in range(ext.size)}
            self.assertEqual({o for o, _ in outcomes}, {REFUSED}, (reason, outcomes))
            self.assertTrue(all((why or "").startswith(reason) for _, why in outcomes), outcomes)
            w = r.wallets[ext.wallet]
            self.assertIsNone(w.busy)
            self.assertEqual(w.resync, resync, reason)

    def test_an_ambiguous_submission_stays_unknown_and_is_never_resent(self):
        transport = Transport([TimeoutError("timed out"), (502, {"error": "bad gateway"})])
        r = make_ramp(transport, wallets=3)

        async def scenario() -> tuple[External, External, External]:
            [first] = await issue_and_wait(r)
            [second] = await issue_and_wait(r)
            [third] = await issue_and_wait(r)
            return first, second, third

        first, second, third = asyncio.run(scenario())
        self.assertEqual(first.submission, "ambiguous")
        self.assertEqual(second.submission, "ambiguous")
        self.assertEqual(third.submission, ACCEPTED)
        # Both ambiguous wallets are held; nothing was sent twice.
        self.assertIs(r.wallets[first.wallet].busy, first)
        self.assertIs(r.wallets[second.wallet].busy, second)
        self.assertEqual(len(transport.sends), 3)
        self.assertEqual(len(set(transport.sends)), 3)
        [none_free] = asyncio.run(issue_and_wait(r))
        self.assertEqual(none_free.outcome(0, 99), (REFUSED, "local: no free wallet"))
        self.assertEqual(len(transport.sends), 3)
        for ext in (first, second):
            self.assertEqual({ext.outcome(i, 99)[0] for i in range(ext.size)}, {UNKNOWN})
        # Past the deadline the wallet's nonce is read again, and only new transfers follow.
        transport.nonce = first.nonce
        assert r.follower is not None
        r.follower.mcs.append(McRecord(2, first.deadline + 10, "11" * 32, ()))

        async def later() -> list[External]:
            r.housekeeping()
            while r.tasks:
                await asyncio.gather(*list(r.tasks))
            return await issue_and_wait(r)

        [fresh] = asyncio.run(later())
        self.assertEqual(fresh.submission, ACCEPTED)
        self.assertNotIn(fresh.msg_hash, {first.msg_hash, second.msg_hash})
        self.assertNotEqual(fresh.key, first.key)
        self.assertEqual({first.outcome(i, 99)[0] for i in range(first.size)}, {UNKNOWN})

    def test_request_deadlines_are_capped_at_the_fee_horizon(self):
        transport = Transport([])
        r = make_ramp(transport, wallets=3, horizon=1_030)
        [ext] = asyncio.run(issue_and_wait(r))
        self.assertEqual(ext.deadline, 1_030)  # now 1,000 + lifetime 60, capped
        self.assertEqual(ext.fee_bound, NANO)
        self.assertIsNone(r.stop_reason)
        assert r.follower is not None
        r.follower.mcs.append(McRecord(2, 1_030, "11" * 32, ()))
        [late] = asyncio.run(issue_and_wait(r))
        self.assertEqual(late.outcome(0, 99), (REFUSED, "local: past the fee horizon"))
        self.assertIn("fee horizon", r.stop_reason or "")
        self.assertEqual(len(transport.sends), 1)

    def test_a_fee_over_its_bound_stops_the_ramp(self):
        r = make_ramp(Transport([]), wallets=3, fee_bound=1_000, storage=5)
        first, second, third = (asyncio.run(issue_and_wait(r))[0] for _ in range(3))
        first.tx_fee = 1_005  # the bound plus all the storage the wallet may owe: inside
        r.included(first)
        self.assertIsNone(r.stop_reason)
        r.included(second)  # no fee reported: counted, never assumed inside
        self.assertEqual(r.fees_unreported, 1)
        self.assertIsNone(r.stop_reason)
        third.tx_fee = 1_006
        r.included(third)
        self.assertIn("over its derived bound 1005", r.stop_reason or "")
        self.assertEqual(
            r.fee_overruns, [{"external": third.msg_hash, "fee": 1_006, "bound": 1_005}]
        )

    def test_classify_send_error(self):
        from shard.rpc import RpcError

        definite, reason = ramp.classify_send_error(
            RpcError("sendBoc", 200, {"code": -32603, "message": "timeout"})
        )
        self.assertFalse(definite, reason)
        definite, _ = ramp.classify_send_error(RpcError("sendBoc", 502, b"bad gateway"))
        self.assertFalse(definite)
        definite, _ = ramp.classify_send_error(
            RpcError("sendBoc", 200, {"code": -32602, "message": "Invalid base64"})
        )
        self.assertTrue(definite)


# ─── the journal ─────────────────────────────────────────────────────


class JournalTransport(Transport):
    """On every sendBoc, checks that the external's attempt record is on disk and fsynced."""

    def __init__(self, answers: list[Any], path: Path, synced: dict[int, int]):
        super().__init__(answers)
        self.path, self.synced = path, synced
        self.checks: list[tuple[bool, bool]] = []

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        request = json.loads(body)
        if request["method"] == "sendBoc":
            boc = request["params"]["boc"]
            digest = Cell.one_from_boc(base64.b64decode(boc)).hash.hex()
            data = self.path.read_bytes()
            end = 0
            for line in data.split(b"\n"):
                end += len(line) + 1
                if b'"type":"attempt"' in line and digest.encode() in line:
                    break
            else:
                end = -1
            self.checks.append((end > 0, end > 0 and max(self.synced.values(), default=0) >= end))
        return await super().__call__(url, body, timeout)


class JournalBeforeSend(unittest.TestCase):
    def test_every_attempt_is_on_disk_and_fsynced_before_its_send(self):
        synced: dict[int, int] = {}
        real = os.fsync

        def fsync(fd: int) -> None:
            real(fd)
            synced[fd] = os.fstat(fd).st_size

        journal = new_journal()
        transport = JournalTransport([], journal.path, synced)
        r = make_ramp(transport, wallets=3)
        r.journal = journal
        with mock.patch.object(jr.os, "fsync", fsync):
            exts = asyncio.run(issue_and_wait(r, count=2))
        self.assertEqual(transport.checks, [(True, True), (True, True)])
        read = jr.read_journal(journal.path)
        self.assertEqual(
            [a["external"] for a in read.attempts.values()], [e.msg_hash for e in exts]
        )
        for ext in exts:
            key = ramp.attempt_of(ext)
            attempt = read.attempts[key]
            self.assertEqual((attempt["wallet"], attempt["nonce"]), (ext.wallet, ext.nonce))
            self.assertEqual(attempt["deadline"], ext.deadline)
            self.assertEqual(attempt["fee_bound"], NANO)
            self.assertEqual(
                [(a["destination"], a["value"]) for a in attempt["actions"]],
                list(zip(ext.destinations, ext.values)),
            )
            self.assertEqual((read.sent(key) or {}).get("state"), "accepted")

    def test_three_rate_gate_refusals_on_two_wallets_never_repeat_an_external(self):
        transport = Transport([(429, {}), rpc_error(-32005, "rate limited"), (429, {})])
        r = make_ramp(transport, wallets=2)
        exts = [asyncio.run(issue_and_wait(r))[0] for _ in range(3)]
        for ext in exts:
            self.assertEqual(ext.outcome(0, 99)[0], REFUSED)
            self.assertTrue((ext.reason or "").startswith("rate gate"), ext.reason)
        self.assertEqual(len(transport.sends), 3)
        self.assertEqual(len(set(transport.sends)), 3)
        self.assertEqual(len({e.msg_hash for e in exts}), 3)
        # The third reuses the first one's wallet and nonce before chain time moved.
        first, _, third = exts
        self.assertEqual((third.wallet, third.nonce), (first.wallet, first.nonce))
        self.assertGreater(third.deadline, first.deadline)
        self.assertEqual(r.ledger.anomalies, [])
        read = jr.read_journal(r.journal.path)
        self.assertEqual(read.attempts[ramp.attempt_of(third)]["prior"], ramp.attempt_of(first))
        for ext in exts:
            self.assertEqual((read.sent(ramp.attempt_of(ext)) or {}).get("state"), "refused")


def attempt_cell(n: int) -> Cell:
    from pytosiq_core import Builder

    return Builder().store_uint(n, 32).end_cell()


def write_journal(path: Path, attempts: int) -> None:
    journal = jr.Journal(path)
    journal.append({"type": "run", "version": jr.VERSION, "mc_start": 1})
    for n in range(attempts):
        journal.append(
            jr.attempt_record(
                role="transfer",
                sender=SENDER,
                wallet=0,
                seqno=n,
                nonce=n,
                deadline=1000 + n,
                cell=attempt_cell(n),
                actions=[(PEERS[0], 1000, 3)],
            )
        )
    journal.close()


class JournalReader(unittest.TestCase):
    def test_a_torn_last_line_is_dropped_and_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / jr.NAME
            write_journal(path, 2)
            with path.open("ab") as f:
                f.write(b'{"type":"sent","id":"transfer:0:1","sta')
            read = jr.read_journal(path)
            self.assertTrue(read.torn_tail)
            self.assertEqual(read.errors, [])
            self.assertEqual(list(read.attempts), ["transfer:0:0", "transfer:0:1"])
            self.assertIsNone(read.sent("transfer:0:1"))
            # Reopened for append, the torn line is closed off and the next record is whole.
            again = jr.Journal(path, create=False)
            again.event("sent", "transfer:0:1", state="refused", reason="rate gate: HTTP 429")
            again.close()
            reread = jr.read_journal(path)
            self.assertFalse(reread.torn_tail)
            self.assertEqual(len(reread.errors), 1)  # the closed-off fragment, now a line
            self.assertEqual((reread.sent("transfer:0:1") or {}).get("state"), "refused")

    def test_a_malformed_middle_line_or_a_wrong_hash_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / jr.NAME
            write_journal(path, 1)
            lines = path.read_bytes().split(b"\n")
            path.write_bytes(b"\n".join([lines[0], b"{not json", *lines[1:]]))
            self.assertEqual(jr.read_journal(path).errors, ["line 2: not JSON"])
            record = json.loads(lines[1])
            record["external"] = "00" * 32
            path.write_bytes(lines[0] + b"\n" + json.dumps(record).encode() + b"\n")
            read = jr.read_journal(path)
            self.assertEqual(read.attempts, {})
            self.assertIn("hashes to", read.errors[0])

    def test_a_new_journal_never_reuses_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / jr.NAME
            write_journal(path, 0)
            with self.assertRaises(FileExistsError):
                jr.Journal(path)


# ─── reconcile: what the sender's history proves ─────────────────────


class PagedHistory:
    """getTransactions over a test History, each answer passed through ``tamper``."""

    def __init__(self, history: Any, tamper: Any = None):
        self.history = history
        self.tamper = tamper or (lambda params, items: items)

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        request = json.loads(body)
        assert request["method"] == "getTransactions", request["method"]
        items = self.tamper(request["params"], self.history.answer(request["params"], 10**9))
        return 200, json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": items}).encode()


class ReconcileHistory(unittest.TestCase):
    """An attempt is not_executed only when the read provably reaches back far enough."""

    def verdict(self, tamper: Any = None, transactions: int = 3, limit: int = 100) -> jr.Verdict:
        history = tr.History()
        for n in range(transactions):
            external = {"hash": base64.b64encode(bytes.fromhex(h("other", n))).decode()}
            tx = tr.tx_json(SENDER, 10 + n, {**external, "kind": "external"}, [])
            history.add(SENDER, tx, 1 + n, 1000 + 10 * n)
        attempt = {"sender": SENDER, "external": h("never"), "deadline": 1100, "signed_at": 900}

        async def now() -> int:
            return 2000

        rpc = PacedRpc("http://fake", 1.0, transport=PagedHistory(history, tamper))
        with mock.patch.object(jr, "TX_PAGE", limit):
            return asyncio.run(jr.find_attempt(rpc, attempt, now, 5.0))

    def test_a_complete_history_proves_the_attempt_was_not_executed(self):
        self.assertEqual(self.verdict().state, "not_executed")
        self.assertEqual(self.verdict(limit=1).state, "not_executed")  # paged one by one
        # An account with no transaction at all: the server answers an empty first page.
        self.assertEqual(self.verdict(transactions=0).state, "not_executed")

    def test_a_non_object_entry_is_undetermined(self):
        for page in ([None], [None, "x"]):
            with self.subTest(page):
                v = self.verdict(lambda p, items, page=page: page)
                self.assertEqual(v.state, "undetermined", v.reason)
        v = self.verdict(lambda p, items: [None, *items])
        self.assertEqual(v.state, "undetermined", v.reason)

    def test_an_entry_missing_a_field_is_undetermined(self):
        for key in ("utime", "data", "transaction_id", "account"):
            with self.subTest(key):

                def drop(p: Any, items: list[Any], key: str = key) -> list[Any]:
                    return [{k: v for k, v in x.items() if k != key} for x in items]

                v = self.verdict(drop)
                self.assertEqual(v.state, "undetermined", v.reason)

    def test_a_truncated_history_is_undetermined(self):
        # The newest transaction names a predecessor, but the next page is empty.
        v = self.verdict(lambda p, items: items[:1] if "lt" not in p else [])
        self.assertEqual(v.state, "undetermined", v.reason)
        self.assertIn("stops at lt", v.reason or "")

    def test_a_page_that_skips_a_transaction_is_undetermined(self):
        v = self.verdict(lambda p, items: [items[0], *items[2:]])
        self.assertEqual(v.state, "undetermined", v.reason)
        self.assertIn("skips lt", v.reason or "")


# ─── the follower: incomplete reads ──────────────────────────────────


class ChainTransport:
    """A FakeChain answered in process, without HTTP."""

    def __init__(self, chain: "FakeChain"):
        self.chain = chain

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        request = json.loads(body)
        with self.chain.lock:
            status, reply = self.chain.answer(request["method"], request.get("params") or {})
        if isinstance(reply, dict):
            return status, json.dumps({"jsonrpc": "2.0", "id": request["id"], **reply}).encode()
        return status, reply


class IncompleteReads(unittest.TestCase):
    def follow(self, failure: tuple[str, int]) -> tuple[ramp.Ramp, External, int]:
        """Send one external, make ``failure[0]`` fail ``failure[1]`` times on the block that
        executes it, and follow the chain until it completes or the follower gives up."""
        chain = FakeChain("0:" + "ee" * 32, {})
        r = make_ramp(ChainTransport(chain), wallets=3)
        for w in r.wallets:
            chain.wallets[w.address] = 0

        async def scenario() -> tuple[External, int]:
            head = await r.head()
            [first] = await t2collect.read_masterchain(r.reader, head, head)
            r.follower = ramp.Follower(r.reader, r.ledger, r.included, first, 0.01)
            [ext] = await issue_and_wait(r)
            at = min(chain.txs)  # the shard block that executes the external
            chain.fail_reads[(failure[0], 0, at)] = failure[1]
            give_up = time.monotonic() + 20
            while time.monotonic() < give_up and r.follower.failed is None:
                await r.follower.round()
                if all(x is not None for x in ext.recipient_tx):
                    break
                await asyncio.sleep(0.05)
            return ext, at

        ext, at = asyncio.run(scenario())
        return r, ext, at

    def test_a_transaction_list_that_fails_once_is_read_again(self):
        r, ext, at = self.follow(("getBlockTransactionsExt", 1))
        assert r.follower is not None
        self.assertIsNone(r.follower.failed)
        self.assertEqual({ext.outcome(i, 10**9)[0] for i in range(ext.size)}, {COMPLETED})
        self.assertIn(at, [k[2] for k in r.follower.incomplete_blocks])

    def test_a_header_that_fails_once_is_read_again(self):
        r, ext, at = self.follow(("getBlockHeader", 1))
        assert r.follower is not None
        self.assertIsNone(r.follower.failed)
        self.assertEqual({ext.outcome(i, 10**9)[0] for i in range(ext.size)}, {COMPLETED})
        self.assertIn(at, [k[2] for k in r.follower.incomplete_blocks])

    def test_a_block_that_stays_unreadable_stops_the_ramp_inconclusive(self):
        for method in ("getBlockTransactionsExt", "getBlockHeader"):
            with self.subTest(method):
                r, ext, at = self.follow((method, 10**6))
                assert r.follower is not None
                self.assertIn("unreadable after 3 attempts", r.follower.failed or "")
                # The frontier never moved past the unread block, and nothing was bound.
                self.assertLess(r.follower.last.seqno, at)
                self.assertIsNone(ext.tx_hash)
                r.check_stop()
                self.assertIn("incomplete chain reads", r.stop_reason or "")
                self.assertEqual(ramp.exit_status(r.stop_reason, 0, 0), ramp.STOPPED)


# ─── a step's layout verdict and its stop conditions ─────────────────


def mc(seqno: int) -> McRecord:
    """A masterchain block whose basechain is one shard."""
    top = t2collect.parse_block_id(tr.block_id(0, seqno))
    return McRecord(seqno, 1000 + seqno, f"{seqno:064x}", (top,))


class StopFileSigner(FakeSigner):
    """Creates the stop file while it signs, as an operator stopping mid-batch would."""

    def __init__(self, stop_file: Path) -> None:
        super().__init__()
        self.stop_file = stop_file

    def sign(self, jobs: list[tuple[remote.Secret, bytes]]) -> list[bytes]:
        self.stop_file.touch()
        return super().sign(jobs)


class StepVerdicts(unittest.TestCase):
    def test_a_layout_needs_both_endpoints_and_every_block_between(self):
        blocks = [mc(s) for s in range(5, 10)]
        self.assertTrue(step_layout(blocks, 5, 9)["stable"])
        for lo, hi, missing in ((4, 9, [4]), (5, 10, [10]), (3, 11, [3, 4, 10, 11])):
            with self.subTest((lo, hi)):
                layout = step_layout(blocks, lo, hi)
                self.assertFalse(layout["stable"])
                self.assertEqual(layout["missing"], missing)
        self.assertFalse(step_layout([b for b in blocks if b.seqno != 7], 5, 9)["stable"])
        self.assertFalse(step_layout([], 5, 5)["stable"])
        with self.assertRaises(ValueError):
            step_layout(blocks, 9, 5)

    def step(
        self, transport: Any, reached: bool = True, signer: Any = None, stop_file: Any = None
    ) -> tuple[ramp.Ramp, dict[str, Any]]:
        """One one-second step of one 3-transfer external, over masterchain blocks 1..3."""
        r = make_ramp(transport, wallets=3)
        r.plan = plan(wallets=3, batch=3, start_rate=3.0, steps=1, step_seconds=1, warmup=0)
        r.a.drain = r.a.finality_wait = r.a.poll = 0.0
        r.a.stop_file = stop_file
        if signer is not None:
            r.signer = signer
        assert r.follower is not None
        r.follower.mcs = [mc(1), mc(2), mc(3)]
        heads = iter([1, 3])

        async def config() -> dict[str, Any]:
            return {}

        async def head() -> int:
            return next(heads)

        async def reach(seqno: int, timeout: float) -> bool:
            return reached

        async def finalized(*args: Any) -> int:
            return 10**9

        r.config = config  # pyright: ignore[reportAttributeAccessIssue]
        r.head = head  # pyright: ignore[reportAttributeAccessIssue]
        r.follower.reach = reach  # pyright: ignore[reportAttributeAccessIssue]

        async def scenario() -> dict[str, Any]:
            record = await r.step(0, 0, 3.0)
            while r.tasks:
                await asyncio.gather(*list(r.tasks))
            return record

        with mock.patch.object(ramp.t2collect, "wait_finalized", finalized):
            return r, asyncio.run(scenario())

    def test_a_step_the_follower_never_reached_the_end_of_does_not_count(self):
        _, record = self.step(Transport([]))
        self.assertTrue(record["counts"], record["layout"])
        self.assertTrue(record["layout"]["reached"])
        _, unreached = self.step(Transport([]), reached=False)
        self.assertFalse(unreached["layout"]["reached"])
        self.assertFalse(unreached["layout"]["stable"])
        self.assertFalse(unreached["counts"])
        self.assertFalse(unreached["passed"])

    def test_a_stop_file_present_before_a_batch_means_nothing_is_built_signed_or_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            stop = Path(tmp) / "stop"
            stop.touch()
            transport = Transport([])
            r, record = self.step(transport, stop_file=stop)
        self.assertEqual(transport.sends, [])
        self.assertEqual(cast(FakeSigner, r.signer).calls, 0)
        self.assertEqual(r.ledger.externals, [])
        self.assertIn("stop file", record["stopped"] or "")

    def test_a_stop_file_that_appears_while_signing_holds_back_every_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            stop = Path(tmp) / "stop"
            transport = Transport([])
            r, record = self.step(transport, signer=StopFileSigner(stop), stop_file=stop)
        self.assertEqual(transport.sends, [])
        self.assertEqual(cast(FakeSigner, r.signer).calls, 1)
        [ext] = r.ledger.externals
        self.assertEqual(ext.submission, "refused")
        self.assertTrue((ext.reason or "").startswith("local: stopped before sending"), ext.reason)
        self.assertIsNone(r.wallets[ext.wallet].busy)
        # Never journaled, since it was never sent.
        self.assertEqual(jr.read_journal(r.journal.path).attempts, {})
        self.assertIn("stop file", record["stopped"] or "")


# ─── exit statuses ───────────────────────────────────────────────────


class ExitStatus(unittest.TestCase):
    def test_the_mapping(self):
        self.assertEqual(ramp.exit_status(None, 0, 0), 0)
        self.assertEqual(ramp.exit_status("stop file present", 0, 0), 4)
        self.assertEqual(ramp.exit_status(None, 2, 0), 1)
        self.assertEqual(ramp.exit_status(None, 0, 1), 1)
        self.assertEqual(ramp.exit_status("the ledger saw a duplicate", 1, 1), 1)
        self.assertEqual((ramp.REFUSED, ramp.STOPPED), (remote.REFUSED, remote.INCONCLUSIVE))
        self.assertEqual((ramp.PASSED, ramp.FAILED), (0, 1))

    def run_steps(self, records: list[dict[str, Any]]) -> ramp.Ramp:
        r = make_ramp(Transport([]))
        r.plan = plan(steps=3, repeats=1)
        queue = list(records)

        async def step(index: int, attempt: int, rate: float) -> dict[str, Any]:
            return queue.pop(0)

        r.step = step  # pyright: ignore[reportAttributeAccessIssue]
        asyncio.run(r.ramp())
        return r

    def test_a_ramp_ending_at_its_first_counted_failing_step_ran_as_specified(self):
        r = self.run_steps([{"counts": True, "passed": True}, {"counts": True, "passed": False}])
        self.assertEqual(r.stated_rate, 100.0)
        self.assertEqual(ramp.exit_status(r.stop_reason, 0, 0), 0)
        every = self.run_steps([{"counts": True, "passed": True}] * 3)
        self.assertEqual(every.stated_rate, 400.0)
        self.assertEqual(ramp.exit_status(every.stop_reason, 0, 0), 0)

    def test_no_stable_layout_within_the_repeats_is_stopped(self):
        r = self.run_steps([{"counts": False, "passed": False}] * 2)
        self.assertIn("no stable layout", r.stop_reason or "")
        self.assertEqual(ramp.exit_status(r.stop_reason, 0, 0), 4)


# ─── a remote run against a fake node ────────────────────────────────

FAKE_BATCH_SIGNER = """#!/usr/bin/env python3
import hashlib, sys
args = sys.argv[1:]
for line in sys.stdin.read().splitlines():
    parts = line.split()
    seed = bytes.fromhex(parts[0])
    if args[0] == "public":
        print((hashlib.sha256(seed).digest() * 41)[:1312].hex())
    else:
        print((hashlib.sha256(seed + bytes.fromhex(parts[1])).digest() * 76)[:2420].hex())
"""

BLOCK_INTERVAL = 0.25


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


parse_external = tr.parse_external


# What the fake chain charges a load external, reported as the transaction's total_fees.
LOAD_FEE = NANO // 100


class FakeChain:
    """One basechain shard; a masterchain block every BLOCK_INTERVAL seconds commits shard
    block of the same seqno. An accepted external executes in the next block and its
    transfers are delivered in the one after. Finality lags the head by one block.

    It serves test_remote's hand-built ConfigParams 18, 21 and 25. A bench-wallet
    external costs the bench wallet NANO // 100 on top of the value it attaches; a load
    external is reported with total_fees LOAD_FEE, or ``overcharge`` for the load
    sends the scenario names there; ``bench_fee`` replaces the bench wallet's fee."""

    def __init__(self, bench: str, scenario: dict[str, Any]):
        self.lock = threading.Lock()
        self.t0, self.base = time.time(), 100
        self.bench, self.bench_balance, self.bench_nonce = bench, 10**6 * NANO, None
        self.wallets: dict[str, int] = {}  # load wallet -> nonce
        self.txs: dict[int, list[dict[str, Any]]] = {}
        self.scenario = scenario
        self.load_sends = 0
        self.charged: list[int] = []  # total_fees of every executed load external
        self.bodies: list[bytes] = []
        self.methods: list[str] = []
        self.bocs: list[str] = []
        self.lt = 0
        self.history = tr.History()
        self.executed: set[str] = set()  # message hashes of every executed external
        # Reads that fail with an RPC error: (method, workchain, seqno) -> failures left.
        self.fail_reads: dict[tuple[str, int, int], int] = {}
        self.hang_load: int | None = None  # the load send whose answer is held
        # From this load send on, the basechain blocks it executes in cannot be read.
        self.break_reads_at: int | None = None
        self.broken_from: int | None = None
        self.hang_now = False
        self.held, self.release = threading.Event(), threading.Event()

    def head(self) -> int:
        return self.base + int((time.time() - self.t0) / BLOCK_INTERVAL)

    def utime(self, seqno: int) -> int:
        return int(self.t0 + (seqno - self.base) * BLOCK_INTERVAL)

    def tx(
        self,
        account: str,
        in_msg: dict[str, Any],
        out: list[dict[str, Any]],
        skipped: int = 0,
        fee: int = 0,
        at: int | None = None,
        aborted: bool = False,
    ):
        self.lt += 1
        tx = {
            "account": account.split(":", 1)[1],
            "lt": str(self.lt),
            "hash": b64(hashlib.sha256(f"tx{self.lt}".encode()).digest()),
            "fee": str(fee),
            "in_msg": in_msg,
            "out_msgs": out,
            # An aborted transaction here ran its computation and failed its action phase.
            "aborted": aborted,
            "compute": {"skipped": False, "success": True, "account_activated": False},
            "action": {
                "success": not aborted,
                "skipped_actions": skipped,
                "messages_created": len(out),
            },
        }
        if at is not None:
            self.history.add(account, tx, at, self.utime(at))
        return tx

    def execute(
        self,
        digest: bytes,
        account: str,
        actions: list[tuple[str, int, bool, int]],
        skip: set[int],
        fee: int,
        failed_receipts: frozenset[int] = frozenset(),
    ):
        at = self.head() + 1
        out = []
        for i, (dest, value, _, _) in enumerate(actions):
            if i in skip:
                continue
            m = {
                "hash": b64(hashlib.sha256(digest + bytes([i])).digest()),
                "kind": "internal",
                "source": account,
                "destination": dest,
                "value": str(value),
                "bounced": False,
            }
            out.append(m)
            receipt = self.tx(dest, m, [], at=at + 1, aborted=i in failed_receipts)
            self.txs.setdefault(at + 1, []).append(receipt)
        external = {"hash": b64(digest), "kind": "external"}
        self.txs.setdefault(at, []).append(self.tx(account, external, out, len(skip), fee, at=at))
        self.executed.add(digest.hex())

    def send(self, boc: str) -> tuple[int, Any]:
        digest, account, nonce, actions = parse_external(boc)
        self.bocs.append(boc)
        if account == self.bench:
            self.bench_nonce = (self.bench_nonce or 0) + 1
            for dest, value, _, _ in actions:
                self.wallets.setdefault(dest, 0)
                self.bench_balance -= value
            fee = self.scenario.get("bench_fee", NANO // 100)
            self.bench_balance -= fee
            # Funding is confirmed by its transaction; it is served by getTransactions only.
            at = self.head() + 1
            out = [
                {
                    "hash": b64(hashlib.sha256(digest + bytes([i])).digest()),
                    "kind": "internal",
                    "source": account,
                    "destination": dest,
                    "value": str(value),
                    "bounced": False,
                }
                for i, (dest, value, _, _) in enumerate(actions)
            ]
            external = {"hash": b64(digest), "kind": "external"}
            self.tx(account, external, out, fee=fee, at=at)
            self.executed.add(digest.hex())
            return 200, {"result": {"status": 1}}
        k = self.load_sends
        self.load_sends += 1
        if k in self.scenario.get("rate_limited", set()):
            return 200, {"error": {"code": -32005, "message": "rate limited"}}
        if k in self.scenario.get("conflict", set()) or nonce != self.wallets.get(account):
            self.wallets[account] = self.wallets.get(account, 0) + 1
            return 200, {
                "error": {
                    "code": -32603,
                    "message": "sendBoc failed: cannot apply external message to current state"
                    " : inbound external message rejected by transaction:\\nexitcode=1804, steps=9",
                }
            }
        self.wallets[account] = nonce + 1
        skip = {i for (s, i) in self.scenario.get("skip", set()) if s == k}
        fee = self.scenario.get("overcharge", {}).get(k, LOAD_FEE)
        self.charged.append(fee)
        failed = frozenset(i for (s, i) in self.scenario.get("aborted_receipt", set()) if s == k)
        self.execute(digest, account, actions, skip, fee, failed)
        if k == self.hang_load:
            self.hang_now = True
        if k == self.break_reads_at:
            self.broken_from = self.head() + 1
        if k in self.scenario.get("ambiguous", set()):
            return 502, b"bad gateway"
        return 200, {"result": {"status": 1}}

    def failing(self, method: str, p: dict[str, Any]) -> bool:
        if (
            self.broken_from is not None
            and method == "getBlockTransactionsExt"
            and p.get("workchain") == 0
            and p.get("seqno", -1) >= self.broken_from
        ):
            return True
        key = (method, p.get("workchain", 0), p.get("seqno", -1))
        left = self.fail_reads.get(key, 0)
        if left <= 0:
            return False
        self.fail_reads[key] = left - 1
        return True

    def state(self, address: str) -> dict[str, Any]:
        if address == self.bench:
            active = self.bench_nonce is not None
            data = b64(tr.wallet_data(self.bench_nonce or 0).to_boc()) if active else ""
            return {
                "balance": str(self.bench_balance),
                "state": "active" if active else "uninitialized",
                "data": data,
                "storage_stat": {
                    "used_cells": "3",
                    "used_bits": "900",
                    "last_paid": int(self.t0) - 100,
                    "due_payment": "17",
                },
            }
        if address in self.wallets:
            data = b64(tr.wallet_data(self.wallets[address]).to_boc())
            stat = {"used_cells": "3", "used_bits": "900", "last_paid": int(self.t0)}
            return {
                "balance": str(10 * NANO),
                "state": "active",
                "data": data,
                "storage_stat": stat,
            }
        return {"balance": "0", "state": "uninitialized"}

    def answer(self, method: str, p: dict[str, Any]) -> tuple[int, Any]:
        head = self.head()
        if self.failing(method, p):
            return 200, {"error": {"code": -32603, "message": "block not ready"}}
        if method == "getTransactions":
            return 200, {"result": self.history.answer(p, head)}
        if method == "getMasterchainInfo":
            return 200, {"result": {"last": tr.block_id(-1, head)}}
        if method == "getBlockHeader":
            seqno, wc = p["seqno"], p["workchain"]
            out: dict[str, Any] = {"id": tr.block_id(wc, seqno), "gen_utime": self.utime(seqno)}
            if wc == -1:
                out["global_id"] = tr.GLOBAL_ID
            else:
                out |= {"after_merge": False, "after_split": False, "before_split": False}
                out["prev_blocks"] = [tr.block_id(0, seqno - 1)]
            return 200, {"result": out}
        if method == "getShards":
            return 200, {"result": {"shards": [tr.block_id(0, p["seqno"])]}}
        if method == "getConsensusBlock":
            return 200, {"result": {"consensus_block": head - 1}}
        if method == "getConfigParam":
            cell = tr.FAKE_CONFIG.get(p["param"])
            boc = b64(cell.to_boc()) if cell is not None else "AA=="
            return 200, {"result": {"config": {"bytes": boc}, "param": p["param"]}}
        if method == "getBlockTransactionsExt":
            txs = self.txs.get(p["seqno"], []) if p["workchain"] == 0 else []
            return 200, {
                "result": {
                    "id": tr.block_id(p["workchain"], p["seqno"]),
                    "incomplete": False,
                    "transactions": txs,
                }
            }
        if method == "getAddressInformation":
            return 200, {"result": self.state(p["address"])}
        if method == "sendBoc":
            return self.send(p["boc"])
        return 200, {"error": {"code": -32601}}

    def serve(self) -> tuple[http.server.ThreadingHTTPServer, str]:
        chain = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                request = json.loads(body)
                with chain.lock:
                    chain.bodies.append(body)
                    chain.methods.append(request["method"])
                    status, reply = chain.answer(request["method"], request.get("params") or {})
                    held, chain.hang_now = chain.hang_now, False
                if held:
                    tr.hold(chain.held, chain.release)
                if isinstance(reply, dict):
                    data = json.dumps({"jsonrpc": "2.0", "id": request["id"], **reply}).encode()
                else:
                    data = reply
                try:
                    self.send_response(status)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass  # the client was killed while its send was held

            def log_message(self, format: str, *args: Any) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}/jsonRPC"


METHODS = {
    "getTransactions",
    "getMasterchainInfo",
    "getBlockHeader",
    "getShards",
    "getConsensusBlock",
    "getConfigParam",
    "getBlockTransactionsExt",
    "getAddressInformation",
    "sendBoc",
}


class RemoteRun(unittest.TestCase):
    def driver(self, d: Path) -> Path:
        driver = d / "driver.py"
        driver.write_text(
            tr.DRIVER.format(blocked=tr.BLOCKED, script=str(ROOT / "bench/run_t4_ramp.py"))
        )
        return driver

    def argv(
        self, d: Path, url: str, extra: list[str] | None = None, out: str = "out"
    ) -> list[str]:
        signer = d / "signer.py"
        signer.write_text(FAKE_BATCH_SIGNER)
        signer.chmod(0o700)
        (d / "wallet.boc").write_bytes(tr.WALLET_CODE.to_boc())
        argv = [
            "--rpc", url,
            "--rpc-share", "1",
            "--out", str(d / out),
            "--key-file", str(tr.write_key(d)),
            "--signer", str(signer),
            "--auth-tag", tr.AUTH.hex(),
            "--wallet-code", str(d / "wallet.boc"),
            "--wallets", "6",
            "--batch", "4",
            "--start-rate", "8",
            "--factor", "2",
            "--steps", "2",
            "--step-seconds", "3",
            "--warmup", "1",
            "--layout-repeats", "0",
            "--tolerance", "0.9",
            "--backlog-slack", "1000",
            "--wallet-funding", "10",
            "--max-cost", "100",
            "--max-transfers", "1000",
            "--lifetime", "5",
            "--deadline-grace", "1",
            "--drain", "5",
            "--finality-wait", "5",
            "--poll", "0.05",
            "--tick", "0.02",
            *(extra or []),
        ]  # fmt: skip
        return [sys.executable, str(self.driver(d)), *argv]

    def run_ramp(
        self, d: Path, url: str, extra: list[str] | None = None, out: str = "out"
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.argv(d, url, extra, out),
            capture_output=True,
            text=True,
            timeout=300,
            env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"},
            cwd=d,
        )

    def reconcile(self, d: Path, url: str, out: str = "out") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.driver(d)), "reconcile", "--out", str(d / out), "--rpc", url],
            capture_output=True,
            text=True,
            timeout=300,
            env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"},
            cwd=d,
        )

    def bench_address(self) -> str:
        key = remote.WalletKey(remote.Secret(tr.TEST_SEED), tr.TEST_RESCUE, 0)
        w = remote.bench_wallet(
            tr.WALLET_CODE, tr.GLOBAL_ID, tr.AUTH, key, tr.fake_public_key(tr.TEST_SEED)
        )
        return remote.raw(w.address)

    def test_ramp_binds_every_transfer_over_json_rpc_and_never_leaks_a_key(self):
        scenario: dict[str, Any] = {
            # Step 0 carries sends 0..5 and stays clean, so the ramp goes on to step 1.
            "ambiguous": {7},
            "rate_limited": {9},
            "conflict": {11},
            "skip": {(6, 2)},
            "aborted_receipt": {(8, 1)},
        }
        chain = FakeChain(self.bench_address(), scenario)
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_ramp(d, url)
                self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                self.assertIn("LOADED-BLOCKED-MODULES []", result.stderr)
                record = json.loads((d / "out/results.json").read_text())
                rows = [json.loads(x) for x in (d / "out/ledger.jsonl").read_text().splitlines()]
                written = {p: p.read_bytes() for p in (d / "out").rglob("*") if p.is_file()}
                journal = jr.read_journal(d / "out" / jr.NAME)
        finally:
            server.shutdown()
            server.server_close()
        # The journal holds every external the node received, and ended cleanly.
        self.assertEqual(journal.errors, [])
        self.assertIsNotNone(journal.end)
        journaled = {a["external"] for a in journal.attempts.values()}
        received = {parse_external(b)[0].hex() for b in chain.bocs}
        self.assertEqual(received, journaled)
        roles = Counter(a["role"] for a in journal.attempts.values())
        self.assertEqual(roles, {"funding": 1, "transfer": sum(1 for r in rows if r["external"])})
        for key, attempt in journal.attempts.items():
            self.assertIsNotNone(journal.sent(key), key)
            self.assertTrue(journal.settled(key), (key, journal.events.get(key)))
        self.assertEqual(len(record["steps"]), 2, json.dumps(record["steps"], indent=1)[:3000])
        for step in record["steps"]:
            self.assertTrue(step["layout"]["stable"])
            self.assertIn("p95_s", step["metrics"])
            self.assertIn("22", step["config"])
            self.assertIn("23", step["config"])
        planned = sum(min(4, t - 4 * j) for t in (24, 48) for j in range(-(-t // 4)))
        self.assertEqual(sum(len(r["actions"]) for r in rows), planned)
        by_submission: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            by_submission.setdefault(r["submission"], []).append(r)
        [ambiguous] = by_submission["ambiguous"]
        # It executed on chain, and still stays unknown.
        self.assertIsNotNone(ambiguous["tx"])
        self.assertEqual({a["outcome"] for a in ambiguous["actions"]}, {UNKNOWN})
        refused = by_submission["refused"]
        reasons = {r["reason"] for r in refused}
        self.assertIn("rate gate: -32005", reasons)
        self.assertIn("seqno conflict: the wallet's nonce moved", reasons)
        self.assertFalse(any(x.startswith("local:") for x in reasons), reasons)
        for r in refused:
            self.assertEqual({a["outcome"] for a in r["actions"]}, {REFUSED})
        skipped = [a for r in rows for a in r["actions"] if a["outcome"] == SKIPPED]
        self.assertEqual(len(skipped), 1)
        # The recipient transaction of one transfer aborted: delivered, failed, never completed.
        [failed] = [a for r in rows for a in r["actions"] if a["outcome"] == DELIVERED_FAILED]
        self.assertEqual(failed["receipt_failure"], "transaction aborted")
        self.assertIsNotNone(failed["recipient_tx"])
        self.assertEqual(record["outcomes"][DELIVERED_FAILED], 1)
        delivered = [
            e for events in journal.events.values() for e in events if e["type"] == "delivered"
        ]
        self.assertEqual(
            [e["receipt_failure"] for e in delivered if e["receipt_failure"]],
            ["transaction aborted"],
        )
        others = [
            a
            for r in by_submission["accepted"]
            for a in r["actions"]
            if a["outcome"] not in (SKIPPED, DELIVERED_FAILED)
        ]
        self.assertEqual({a["outcome"] for a in others}, {COMPLETED})
        for a in others:
            self.assertIsNotNone(a["emitted"])
            self.assertLessEqual(a["recipient_mc"], record["finalized_mc"])
        self.assertEqual(sum(record["outcomes"].values()), planned)
        self.assertEqual(record["anomaly_count"], 0, record["anomalies"])
        self.assertEqual((record["stopped"], record["exit_status"]), (None, 0))
        # The fee bound, derived from the node's ConfigParams before any send, covers the
        # fee the node charged for every external: the funding external from the bench
        # wallet and every executed load external, each against its own bound.
        prep = record["preparation"]
        self.assertEqual(prep["funding_fees"], [NANO // 100])
        for paid, bound in zip(prep["funding_fees"], prep["funding_fee_bounds"], strict=True):
            self.assertGreaterEqual(bound, paid)
        executed = [r for r in rows if r["tx"] is not None]
        self.assertEqual(len(executed), len(chain.charged))
        self.assertEqual({r["tx_fee"] for r in executed}, {LOAD_FEE})
        for r in executed:
            self.assertGreaterEqual(r["fee_bound"], r["tx_fee"], r)
            self.assertEqual(
                r["fee_bound"],
                record["fee_bound"]["load"]["transfer_externals"][str(len(r["actions"]))]["total"],
            )
        self.assertEqual(record["fee_check"], {"overruns": [], "overrun_count": 0, "unreported": 0})
        bound = record["work_bound"]
        self.assertEqual(bound["cost"], bound["funding"] + record["fee_bound"]["bench"]["total"])
        self.assertEqual(
            record["fee_config"]["config_param_hashes"]["21"], tr.gas_cell().hash.hex()
        )
        self.assertLessEqual(record["wallet_balance"]["spent"], bound["cost"])
        # Every request expires by the horizon its storage bound covers.
        self.assertTrue(all(r["deadline"] <= record["fee_horizon"] for r in executed))
        # Never resent: every boc the node received is distinct, one per submitted external.
        self.assertEqual(len(chain.bocs), len(set(chain.bocs)))
        load_bocs = len(chain.bocs) - 1  # one funding external, and no sweep
        self.assertEqual(load_bocs, sum(1 for r in rows if r["external"]))
        self.assertNotIn("sweep", record)
        # Nothing is swept back: each load wallet's final balance is reported, and counted.
        left = record["left_in_load_wallets"]
        self.assertEqual(
            [(x["address"], x["balance"]) for x in left["wallets"]],
            [(a, 10 * NANO) for a in record["load_wallets"]],
        )
        self.assertEqual((left["total"], left["complete"]), (60 * NANO, True))
        balance = record["wallet_balance"]
        self.assertEqual(balance["left_in_load_wallets"], 60 * NANO)
        self.assertEqual(
            balance["consumed"],
            balance["spent"] - (60 * NANO - balance["load_wallets_before"]),
        )
        self.assertTrue(set(chain.methods) <= METHODS, set(chain.methods) - METHODS)
        # No key, and no load-wallet seed derived from it, appears anywhere.
        bench = Address(self.bench_address())
        secrets = [tr.TEST_SEED] + [
            ramp.load_seed(remote.Secret(tr.TEST_SEED), bench, i).reveal() for i in range(6)
        ]
        texts = [result.stdout, result.stderr] + [
            b.decode(errors="replace") for b in written.values()
        ]
        texts += [b.decode() for b in chain.bodies]
        for path, blob in written.items():
            if path.suffix == ".json":
                texts.append(json.dumps(json.loads(blob)))
        for seed in secrets:
            for form in tr.secret_forms(seed):
                for text in texts:
                    self.assertNotIn(form, text)
            for blob in list(written.values()) + chain.bodies:
                self.assertNotIn(seed, blob)

    def test_a_fee_bound_over_max_cost_is_refused_before_any_send(self):
        # 6 load wallets of 10 TOS: the funding alone (60 TOS) fits --max-cost 60.2,
        # and only the fee bound derived from the node's ConfigParams shows it cannot.
        chain = FakeChain(self.bench_address(), {})
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_ramp(d, url, ["--max-cost", "60.2"])
                self.assertFalse((d / "out").exists())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
        self.assertIn("cost bound", result.stderr)
        self.assertIn("fee_bound", result.stdout)
        self.assertIn("getConfigParam", chain.methods)
        self.assertNotIn("sendBoc", chain.methods)
        self.assertEqual(chain.bocs, [])

    def test_a_fee_over_its_bound_stops_the_ramp(self):
        # The third load external is charged 5 TOS, over its derived bound of about 0.4 TOS.
        chain = FakeChain(self.bench_address(), {"overcharge": {2: 5 * NANO}})
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_ramp(d, url)
                record = json.loads((d / "out/results.json").read_text())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, ramp.STOPPED, result.stderr[-4000:])
        self.assertIn("over its derived bound", record["stopped"])
        self.assertEqual(record["exit_status"], ramp.STOPPED)
        self.assertEqual(record["fee_check"]["overrun_count"], 1)
        self.assertEqual(record["fee_check"]["overruns"][0]["fee"], 5 * NANO)
        # It stopped in step 0: no further step was offered.
        self.assertEqual(len(record["steps"]), 1)
        self.assertLess(chain.load_sends, 6 + 12)

    def test_a_funding_fee_over_its_bound_stops_before_the_ramp(self):
        chain = FakeChain(self.bench_address(), {"bench_fee": 5 * NANO})
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_ramp(d, url)
                record = json.loads((d / "out/results.json").read_text())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, ramp.STOPPED, result.stderr[-4000:])
        self.assertIn("funding external 0 cost 5000000000 nanotos", record["stopped"])
        self.assertEqual(chain.load_sends, 0)
        self.assertEqual(len(chain.bocs), 1)

    def test_over_the_cap_is_refused_before_any_request(self):
        chain = FakeChain(self.bench_address(), {})
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                over_cost = self.run_ramp(d, url, ["--max-cost", "5"])
                over_transfers = self.run_ramp(d, url, ["--max-transfers", "10"])
                bad_batch = self.run_ramp(d, url, ["--batch", "256"])
                self.assertFalse((d / "out").exists())
        finally:
            server.shutdown()
            server.server_close()
        for result, reason in (
            (over_cost, "cost bound"),
            (over_transfers, "transfer bound"),
            (bad_batch, "batch must be"),
        ):
            self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
            self.assertIn(reason, result.stderr)
        self.assertIn("work_bound", over_cost.stdout)
        self.assertEqual(chain.methods, [])

    def test_a_kill_after_a_send_leaves_a_journal_reconcile_classifies(self):
        chain = FakeChain(self.bench_address(), {})
        chain.hang_load = 3  # the fourth transfer external executes; its answer never returns
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                child = subprocess.Popen(
                    self.argv(d, url),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=d,
                    env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"},
                )
                try:
                    self.assertTrue(chain.held.wait(120), "the fourth transfer was never sent")
                    child.kill()
                    self.assertEqual(child.wait(30), -9)
                finally:
                    chain.release.set()
                journal = jr.read_journal(d / "out" / jr.NAME)
                summaries = [(d / "out" / x).exists() for x in ("results.json", "ledger.jsonl")]
                latest = max(a["deadline"] for a in journal.attempts.values())
                give_up = time.monotonic() + 60
                while chain.utime(chain.head()) <= latest + 3 and time.monotonic() < give_up:
                    time.sleep(0.25)
                result = self.reconcile(d, url)
                bocs = len(chain.bocs)
                again = self.run_ramp(d, url, out="out2")
                bocs_after = len(chain.bocs)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(summaries, [False, False])
        self.assertEqual(journal.errors, [])
        # Journaled before it was sent: every external the node received is in the journal.
        received = {parse_external(b)[0].hex() for b in chain.bocs[:bocs]}
        self.assertLessEqual(received, {a["external"] for a in journal.attempts.values()})
        self.assertEqual(result.returncode, jr.RECONCILED, result.stderr[-3000:])
        report = json.loads(result.stdout)
        self.assertEqual(report["anomalies"], [])
        self.assertFalse(report["ended"])
        rows = {r["external"]: r for r in report["attempts"]}
        self.assertEqual(set(rows), {a["external"] for a in journal.attempts.values()})
        for digest, row in rows.items():
            expected = "executed" if digest in chain.executed else "not_executed"
            self.assertEqual(row["verdict"], expected, row)
        hung = parse_external(chain.bocs[1 + 3])[0].hex()  # after the one funding external
        self.assertIsNone(rows[hung]["journaled"])
        self.assertEqual(rows[hung]["verdict"], "executed")
        self.assertEqual(rows[hung]["problems"], [])
        self.assertEqual({x["delivery"] for x in rows[hung]["deliveries"]}, {"delivered"})
        self.assertEqual(len(rows[hung]["deliveries"]), 4)
        # A new run first reconciles, records it, and refuses to sign anything.
        self.assertEqual(again.returncode, remote.REFUSED, again.stderr[-3000:])
        self.assertIn("needed reconciling", again.stderr)
        self.assertEqual(bocs_after, bocs)

    def test_a_stop_file_present_at_the_start_sends_nothing(self):
        chain = FakeChain(self.bench_address(), {})
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                (d / "stop").touch()
                result = self.run_ramp(d, url, ["--stop-file", str(d / "stop")])
                out_exists = (d / "out").exists()
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
        self.assertIn("stop file", result.stderr)
        self.assertFalse(out_exists)
        self.assertNotIn("sendBoc", chain.methods)
        self.assertEqual(chain.bocs, [])

    def test_a_second_invocation_on_a_locked_wallet_is_refused(self):
        chain = FakeChain(self.bench_address(), {})
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                held = jr.WalletState(jr.default_state_dir(tr.write_key(d)), self.bench_address())
                try:
                    result = self.run_ramp(d, url)
                finally:
                    held.release()
                out_exists = (d / "out").exists()
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, remote.REFUSED, result.stderr[-2000:])
        self.assertIn("holds the lock", result.stderr)
        self.assertFalse(out_exists)
        self.assertEqual(chain.bocs, [])

    def test_shard_reads_that_never_complete_stop_the_ramp_inconclusive(self):
        chain = FakeChain(self.bench_address(), {})
        chain.break_reads_at = 0  # from the first transfer on, its blocks cannot be read
        server, url = chain.serve()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                result = self.run_ramp(d, url)
                record = json.loads((d / "out/results.json").read_text())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result.returncode, ramp.STOPPED, result.stderr[-3000:])
        self.assertIn("incomplete chain reads", record["stopped"])
        self.assertIn("unreadable after 3 attempts", record["follower"]["failed"])
        self.assertEqual(len(record["steps"]), 1)


class Signing(unittest.TestCase):
    def test_a_hung_batch_signer_is_killed_at_its_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            script = d / "signer.py"
            script.write_text(
                "#!/usr/bin/env python3\nimport os, time\n"
                f"open({str(d / 'pid')!r}, 'w').write(str(os.getpid()))\ntime.sleep(60)\n"
            )
            script.chmod(0o700)
            signer = ramp.BatchSigner(script, 1, timeout=1.0)
            seed = ramp.load_seed(remote.Secret(tr.TEST_SEED), BENCH, 0)
            started = time.monotonic()
            with self.assertRaises(remote.SignerTimeout) as caught:
                signer.sign([(seed, b"m" * 32)])
            self.assertLess(time.monotonic() - started, 30)
            self.assertNotIn(seed.reveal().hex(), str(caught.exception))
            with self.assertRaises(ProcessLookupError):
                os.kill(int((d / "pid").read_text()), 0)

    def test_load_seeds_are_distinct_and_hidden(self):
        bench = remote.Secret(tr.TEST_SEED)
        seeds = [ramp.load_seed(bench, BENCH, i) for i in range(64)]
        self.assertEqual(len({s.reveal() for s in seeds}), 64)
        self.assertNotIn(tr.TEST_SEED, {s.reveal() for s in seeds})
        for s in seeds[:3]:
            for form in tr.secret_forms(s.reveal()):
                self.assertNotIn(form, repr(s))

    def test_two_bench_wallets_with_one_seed_never_share_a_load_wallet(self):
        seed = remote.Secret(tr.TEST_SEED)

        def loads(wallet_id: int) -> tuple[str, set[str]]:
            key = remote.WalletKey(seed, tr.TEST_RESCUE, wallet_id)
            public = tr.fake_public_key(tr.TEST_SEED)
            bench = remote.bench_wallet(tr.WALLET_CODE, tr.GLOBAL_ID, tr.AUTH, key, public)
            out: set[str] = set()
            for i in range(8):
                derived = ramp.load_seed(key.seed, bench.address, i).reveal()
                pk = (hashlib.sha256(derived).digest() * 41)[:1312]
                w = ramp.load_wallet(tr.WALLET_CODE, tr.GLOBAL_ID, tr.AUTH, i, pk, tr.TEST_RESCUE)
                out.add(remote.raw(w.address))
            return remote.raw(bench.address), out

        first_bench, first = loads(0)
        second_bench, second = loads(1)
        self.assertNotEqual(first_bench, second_bench)
        self.assertEqual((len(first), len(second)), (8, 8))
        self.assertEqual(first & second, set())
        self.assertEqual(loads(0), (first_bench, first))  # deterministic for one identity

    def test_the_batch_signer_gets_seeds_on_stdin_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            argv_log = d / "argv.txt"
            script = d / "signer.py"
            script.write_text(
                FAKE_BATCH_SIGNER.replace(
                    "args = sys.argv[1:]",
                    f"args = sys.argv[1:]\nopen({str(argv_log)!r}, 'a').write(' '.join(args))",
                )
            )
            script.chmod(0o700)
            signer = ramp.BatchSigner(script, 2)
            seeds = [ramp.load_seed(remote.Secret(tr.TEST_SEED), BENCH, i) for i in range(3)]
            self.assertEqual(len(signer.public_keys(seeds)), 3)
            self.assertEqual(len(signer.sign([(s, b"m" * 32) for s in seeds])), 3)
            logged = argv_log.read_text()
            for s in seeds:
                self.assertNotIn(s.reveal().hex(), logged)

    def test_a_failing_signer_does_not_echo_its_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "signer.py"
            script.write_text(
                "#!/usr/bin/env python3\nimport sys\nsys.stderr.write(sys.stdin.read())\nsys.exit(2)\n"
            )
            script.chmod(0o700)
            signer = ramp.BatchSigner(script, 1)
            seed = ramp.load_seed(remote.Secret(tr.TEST_SEED), BENCH, 0)
            with self.assertRaises(RuntimeError) as caught:
                signer.sign([(seed, b"m")])
            self.assertNotIn(seed.reveal().hex(), str(caught.exception))


# ─── chain time for deadlines, and the follower's read rate ─────────


class LiveDeadlines(unittest.TestCase):
    """A request's deadline counts from the live head, whatever the follower trails by."""

    def test_a_deadline_counts_from_the_live_head_not_the_lagging_frontier(self):
        # The follower's frontier is at 1,000 (make_ramp); the head is 300 s ahead of it.
        r = make_ramp(Transport([], head_utime=1_300), wallets=3)
        [ext] = asyncio.run(issue_and_wait(r))
        self.assertEqual(ext.deadline, 1_360)  # head 1,300 + lifetime 60
        self.assertEqual(r.live_lag_max, 300)
        # Expiry still counts from the frontier: past 1,360 only once the walk is.
        r.housekeeping()
        self.assertFalse(ext.expired)

    def test_the_live_time_never_runs_below_the_frontier(self):
        r = make_ramp(Transport([], head_utime=900), wallets=3)  # a node behind the walk
        [ext] = asyncio.run(issue_and_wait(r))
        self.assertEqual(ext.deadline, 1_060)

    def test_the_head_is_read_at_most_once_a_refresh_period(self):
        transport = Transport([], head_utime=1_300)
        r = make_ramp(transport, wallets=3)
        for _ in range(3):
            asyncio.run(issue_and_wait(r))
        self.assertEqual(transport.head_reads, 2)  # getMasterchainInfo + getBlockHeader, once

    def test_without_a_live_reading_no_request_is_built(self):
        transport = Transport([], head_utime=None)
        r = make_ramp(transport, wallets=3)
        [ext] = asyncio.run(issue_and_wait(r))
        self.assertEqual(ext.outcome(0, 99), (REFUSED, "local: no live chain time"))
        self.assertEqual(transport.sends, [])

    def test_a_reading_older_than_its_maximum_age_is_not_used(self):
        transport = Transport([], head_utime=None)
        r = make_ramp(transport, wallets=3)
        r.live = (time.monotonic() - ramp.LIVE_MAX_AGE - 1, 5_000)
        [ext] = asyncio.run(issue_and_wait(r))
        self.assertEqual(ext.outcome(0, 99), (REFUSED, "local: no live chain time"))
        self.assertEqual(transport.sends, [])
        # A younger one serves while the head cannot be read.
        r.live = (time.monotonic() - ramp.LIVE_REFRESH - 0.5, 1_200)
        [late] = asyncio.run(issue_and_wait(r))
        self.assertEqual(late.deadline, 1_260)
        self.assertEqual(len(transport.sends), 1)


class CountingTransport:
    """Answers every call with ``result``, or an RPC error while ``broken``; counts calls."""

    def __init__(self, broken: bool = False):
        self.broken, self.calls = broken, 0

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        self.calls += 1
        request = json.loads(body)
        if self.broken:
            reply: dict[str, Any] = {"error": {"code": -32603, "message": "block not ready"}}
        else:
            reply = {"result": {"url": url}}
        return 200, json.dumps({"jsonrpc": "2.0", "id": request["id"], **reply}).encode()


class ReaderPoolTests(unittest.TestCase):
    def pool(self, *broken: bool) -> tuple[ReaderPool, list[CountingTransport]]:
        transports = [CountingTransport(b) for b in broken]
        clients = [PacedRpc(f"http://node-{i}", 1.0, transport=t) for i, t in enumerate(transports)]
        return ReaderPool(clients), transports

    def test_reads_are_spread_over_every_endpoint(self):
        pool, transports = self.pool(False, False, False, False)

        async def reads() -> list[Any]:
            return await asyncio.gather(*(pool.call("getShards") for _ in range(40)))

        answers = asyncio.run(reads())
        self.assertEqual([t.calls for t in transports], [10, 10, 10, 10])
        self.assertEqual(len({a["url"] for a in answers}), 4)
        self.assertEqual(pool.failovers, 0)

    def test_an_endpoint_that_errs_is_skipped_for_the_next(self):
        pool, transports = self.pool(True, False)
        answers = asyncio.run(self.many(pool, 4))
        self.assertEqual({a["url"] for a in answers}, {"http://node-1"})
        self.assertEqual(transports[0].calls, 2)  # tried first on every second call
        self.assertEqual(pool.failovers, 2)

    def test_every_endpoint_failing_raises_the_error(self):
        pool, transports = self.pool(True, True)
        with self.assertRaises(RpcError):
            asyncio.run(pool.call("getShards"))
        self.assertEqual([t.calls for t in transports], [1, 1])

    def test_an_endpoint_without_budget_room_goes_last(self):
        pool, transports = self.pool(False, False)
        while pool.clients[0].budget.room() > 0:  # endpoint 0's budget is used up
            pool.clients[0].budget.take()
        asyncio.run(self.many(pool, 2))
        self.assertEqual([t.calls for t in transports], [0, 2])

    @staticmethod
    async def many(pool: ReaderPool, n: int) -> list[Any]:
        return [await pool.call("getShards") for _ in range(n)]

    def test_an_empty_pool_is_refused(self):
        with self.assertRaises(ValueError):
            ReaderPool([])


class InFlight:
    """A FakeChain transport that holds every transaction read briefly and records the most
    reads in flight at once."""

    def __init__(self, chain: "FakeChain"):
        self.inner, self.now, self.most = ChainTransport(chain), 0, 0

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        if json.loads(body)["method"] != "getBlockTransactionsExt":
            return await self.inner(url, body, timeout)
        self.now += 1
        self.most = max(self.most, self.now)
        try:
            await asyncio.sleep(0.02)
            return await self.inner(url, body, timeout)
        finally:
            self.now -= 1


class FollowerReadRate(unittest.TestCase):
    def test_the_windows_of_one_round_are_read_together_and_applied_in_order(self):
        chain = FakeChain("0:" + "ee" * 32, {})
        transport = InFlight(chain)
        reader = PacedRpc("http://fake", 1.0, transport=transport)
        lg = Ledger([])

        async def scenario() -> ramp.Follower:
            [first] = await t2collect.read_masterchain(reader, chain.base, chain.base)
            while chain.head() < chain.base + 8:
                await asyncio.sleep(BLOCK_INTERVAL / 2)
            follower = ramp.Follower(reader, lg, lambda ext: None, first, 0.01)
            self.assertGreaterEqual(await follower.round(), 8)
            return follower

        follower = asyncio.run(scenario())
        seqnos = [m.seqno for m in follower.mcs]
        self.assertEqual(seqnos, list(range(chain.base, seqnos[-1] + 1)))
        self.assertGreater(transport.most, 1)  # one window at a time never overlaps reads
        self.assertIsNone(follower.failed)

    def test_a_window_that_fails_stops_the_frontier_before_it_and_applies_the_ones_before(self):
        chain = FakeChain("0:" + "ee" * 32, {})
        reader = PacedRpc("http://fake", 1.0, transport=ChainTransport(chain))
        lg = Ledger([])
        bad = chain.base + 5
        chain.fail_reads[("getBlockTransactionsExt", 0, bad)] = 10**6

        async def scenario() -> ramp.Follower:
            [first] = await t2collect.read_masterchain(reader, chain.base, chain.base)
            while chain.head() < chain.base + 8:
                await asyncio.sleep(BLOCK_INTERVAL / 2)
            follower = ramp.Follower(reader, lg, lambda ext: None, first, 0.01)
            await follower.round()
            return follower

        follower = asyncio.run(scenario())
        self.assertEqual(follower.last.seqno, bad - 1)
        self.assertIn(f"masterchain block {bad}", follower.failed or "")


if __name__ == "__main__":
    unittest.main()
