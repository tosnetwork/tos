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
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from contract.pq_auth import transfer_message  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Cell,
    ExternalMsgInfo,
    InternalMsgInfo,
    MessageAny,
)
from shard import remote  # noqa: E402
from shard.rpc import PacedRpc  # noqa: E402
from shard.t2check import McRecord, Msg, Tx  # noqa: E402
from t4 import ramp  # noqa: E402
from t4.ledger import (  # noqa: E402
    ACCEPTED,
    COMPLETED,
    OUTCOMES,
    PENDING,
    REFUSED,
    SKIPPED,
    UNKNOWN,
    External,
    Ledger,
    StepRule,
    step_metrics,
)
from tests import test_remote as tr  # noqa: E402

NANO = remote.NANO
SENDER = "0:" + "aa" * 32
PEERS = ["0:" + f"{b:02x}" * 32 for b in (0xB1, 0xB2, 0xB3)]


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
    )


def delivery(message: Msg, account: str | None = None, lt: int = 2) -> Tx:
    return Tx(
        hash=h("rx", message.hash, lt),
        account=account or message.destination or "",
        lt=lt,
        block=(0, 0, 2),
        in_msg=message,
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
        wallet_fee_cap=NANO,
        external_fee_cap=NANO // 10,
        transfer_fee_cap=NANO // 100,
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
        self.assertEqual(b.deploy_externals, 1)
        self.assertEqual(b.funding, 500 * NANO)
        self.assertEqual(b.cost, b.funding + NANO)
        self.assertEqual(
            b.load_fees, (b.load_externals + 10) * (NANO // 10) + b.transfers * (NANO // 100)
        )

    def test_over_a_cap_is_refused(self):
        b = ramp.work_bound(plan(wallet_funding=10_000 * NANO))
        self.assertIsNone(ramp.refusal(b, b.cost, b.transfers))
        self.assertIn("cost bound", ramp.refusal(b, b.cost - 1, b.transfers) or "")
        self.assertIn("transfer bound", ramp.refusal(b, b.cost, b.transfers - 1) or "")
        starved = ramp.work_bound(plan(wallet_funding=NANO))
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


# ─── submissions: refused, ambiguous, never resent ───────────────────


class FakeSigner:
    def __init__(self) -> None:
        self.calls = 0

    def sign(self, jobs: list[tuple[remote.Secret, bytes]]) -> list[bytes]:
        self.calls += 1
        return [bytes(remote.SIGNATURE_BYTES) for _ in jobs]


class Transport:
    """Answers queued per call: (status, document) or an exception to raise."""

    def __init__(self, answers: list[Any], nonce: int = 0):
        self.answers, self.nonce = list(answers), nonce
        self.sends: list[str] = []

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        request = json.loads(body)
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


def make_ramp(transport: Transport, wallets: int = 2) -> ramp.Ramp:
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
        args, p, StepRule(), [ramp.Endpoint("http://fake", reader, sender)], FakeSigner(), load, lg
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


def parse_external(boc: str) -> tuple[bytes, str, int, list[tuple[str, int, bool, int]]]:
    """(message hash, account, nonce, actions as (destination, value, has init, mode))."""
    cell = Cell.one_from_boc(base64.b64decode(boc))
    message = MessageAny.deserialize(cell.begin_parse())
    info = message.info
    assert isinstance(info, ExternalMsgInfo) and isinstance(info.dest, Address)
    account = remote.raw(info.dest)
    body = message.body
    assert isinstance(body, Cell)
    s = body.refs[0].begin_parse()
    s.skip_bits(32 + 32 + 256)
    s.load_address()
    s.skip_bits(256 + 8 + 64)
    nonce = s.load_uint(64)
    s.skip_bits(32 + 8)
    payload = s.load_ref().begin_parse()
    payload.skip_bits(32)
    cur = payload.load_ref()
    actions = []
    while cur.begin_parse().remaining_bits:
        a = cur.begin_parse()
        a.skip_bits(32)
        mode = a.load_uint(8)
        prev, msg = a.load_ref(), a.load_ref()
        m = MessageAny.deserialize(msg.begin_parse())
        assert isinstance(m.info, InternalMsgInfo) and isinstance(m.info.dest, Address)
        actions.append((remote.raw(m.info.dest), int(m.info.value.tomis), m.init is not None, mode))
        cur = prev
    actions.reverse()
    return cell.hash, account, nonce, actions


class FakeChain:
    """One basechain shard; a masterchain block every BLOCK_INTERVAL seconds commits shard
    block of the same seqno. An accepted external executes in the next block and its
    transfers are delivered in the one after. Finality lags the head by one block."""

    def __init__(self, bench: str, scenario: dict[str, set[Any]]):
        self.lock = threading.Lock()
        self.t0, self.base = time.time(), 100
        self.bench, self.bench_balance, self.bench_nonce = bench, 10**6 * NANO, None
        self.wallets: dict[str, int] = {}  # load wallet -> nonce
        self.txs: dict[int, list[dict[str, Any]]] = {}
        self.scenario = scenario
        self.load_sends = 0
        self.bodies: list[bytes] = []
        self.methods: list[str] = []
        self.bocs: list[str] = []
        self.lt = 0

    def head(self) -> int:
        return self.base + int((time.time() - self.t0) / BLOCK_INTERVAL)

    def utime(self, seqno: int) -> int:
        return int(self.t0 + (seqno - self.base) * BLOCK_INTERVAL)

    def tx(self, account: str, in_msg: dict[str, Any], out: list[dict[str, Any]], skipped: int = 0):
        self.lt += 1
        return {
            "account": account.split(":", 1)[1],
            "lt": str(self.lt),
            "hash": b64(hashlib.sha256(f"tx{self.lt}".encode()).digest()),
            "in_msg": in_msg,
            "out_msgs": out,
            "aborted": False,
            "compute": {"skipped": False, "success": True, "account_activated": False},
            "action": {"success": True, "skipped_actions": skipped, "messages_created": len(out)},
        }

    def execute(
        self, digest: bytes, account: str, actions: list[tuple[str, int, bool, int]], skip: set[int]
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
            self.txs.setdefault(at + 1, []).append(self.tx(dest, m, []))
        external = {"hash": b64(digest), "kind": "external"}
        self.txs.setdefault(at, []).append(self.tx(account, external, out, len(skip)))

    def send(self, boc: str) -> tuple[int, Any]:
        digest, account, nonce, actions = parse_external(boc)
        self.bocs.append(boc)
        if account == self.bench:
            self.bench_nonce = (self.bench_nonce or 0) + 1
            for dest, value, _, _ in actions:
                self.wallets.setdefault(dest, 0)
                self.bench_balance -= value
            self.bench_balance -= NANO // 100
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
        self.execute(digest, account, actions, skip)
        if k in self.scenario.get("ambiguous", set()):
            return 502, b"bad gateway"
        return 200, {"result": {"status": 1}}

    def state(self, address: str) -> dict[str, Any]:
        if address == self.bench:
            active = self.bench_nonce is not None
            data = b64(tr.wallet_data(self.bench_nonce or 0).to_boc()) if active else ""
            return {
                "balance": str(self.bench_balance),
                "state": "active" if active else "uninitialized",
                "data": data,
            }
        if address in self.wallets:
            data = b64(tr.wallet_data(self.wallets[address]).to_boc())
            return {"balance": str(10 * NANO), "state": "active", "data": data}
        return {"balance": "0", "state": "uninitialized"}

    def answer(self, method: str, p: dict[str, Any]) -> tuple[int, Any]:
        head = self.head()
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
            return 200, {"result": {"config": {"bytes": "AA=="}, "param": p["param"]}}
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
                if isinstance(reply, dict):
                    data = json.dumps({"jsonrpc": "2.0", "id": request["id"], **reply}).encode()
                else:
                    data = reply
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}/jsonRPC"


METHODS = {
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
    def run_ramp(self, d: Path, url: str, extra: list[str] | None = None):
        signer = d / "signer.py"
        signer.write_text(FAKE_BATCH_SIGNER)
        signer.chmod(0o700)
        (d / "wallet.boc").write_bytes(tr.WALLET_CODE.to_boc())
        driver = d / "driver.py"
        driver.write_text(
            tr.DRIVER.format(blocked=tr.BLOCKED, script=str(ROOT / "bench/run_t4_ramp.py"))
        )
        argv = [
            "--rpc", url,
            "--rpc-share", "1",
            "--out", str(d / "out"),
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
        return subprocess.run(
            [sys.executable, str(driver), *argv],
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
        scenario: dict[str, set[Any]] = {
            # Step 0 carries sends 0..5 and stays clean, so the ramp goes on to step 1.
            "ambiguous": {7},
            "rate_limited": {9},
            "conflict": {11},
            "skip": {(6, 2)},
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
        finally:
            server.shutdown()
            server.server_close()
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
        others = [
            a for r in by_submission["accepted"] for a in r["actions"] if a["outcome"] != SKIPPED
        ]
        self.assertEqual({a["outcome"] for a in others}, {COMPLETED})
        for a in others:
            self.assertIsNotNone(a["emitted"])
            self.assertLessEqual(a["recipient_mc"], record["finalized_mc"])
        self.assertEqual(sum(record["outcomes"].values()), planned)
        self.assertEqual(record["anomaly_count"], 0, record["anomalies"])
        # Never resent: every boc the node received is distinct, one per submitted external.
        self.assertEqual(len(chain.bocs), len(set(chain.bocs)))
        load_bocs = len(chain.bocs) - 1 - 6  # one funding external, six sweeps
        self.assertEqual(load_bocs, sum(1 for r in rows if r["external"]))
        self.assertEqual(record["sweep"]["accepted"], 6)
        self.assertTrue(set(chain.methods) <= METHODS, set(chain.methods) - METHODS)
        # No key, and no load-wallet seed derived from it, appears anywhere.
        secrets = [tr.TEST_SEED] + [
            ramp.load_seed(remote.Secret(tr.TEST_SEED), i).reveal() for i in range(6)
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


class Signing(unittest.TestCase):
    def test_load_seeds_are_distinct_and_hidden(self):
        bench = remote.Secret(tr.TEST_SEED)
        seeds = [ramp.load_seed(bench, i) for i in range(64)]
        self.assertEqual(len({s.reveal() for s in seeds}), 64)
        self.assertNotIn(tr.TEST_SEED, {s.reveal() for s in seeds})
        for s in seeds[:3]:
            for form in tr.secret_forms(s.reveal()):
                self.assertNotIn(form, repr(s))

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
            seeds = [ramp.load_seed(remote.Secret(tr.TEST_SEED), i) for i in range(3)]
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
            seed = ramp.load_seed(remote.Secret(tr.TEST_SEED), 0)
            with self.assertRaises(RuntimeError) as caught:
                signer.sign([(seed, b"m")])
            self.assertNotIn(seed.reveal().hex(), str(caught.exception))


class SweepFormat(unittest.TestCase):
    def test_sweep_request_carries_whole_balance_mode(self):
        w = ramp.load_wallet(tr.WALLET_CODE, 3, tr.AUTH, 0, bytes(1312), bytes(32))
        request = w.request(
            0, [transfer_message(w.address, Address(PEERS[0]), 0)], 10, mode=ramp.SWEEP_MODE
        )
        actions = request.refs[0].begin_parse()
        actions.skip_bits(32)
        head = actions.load_ref().begin_parse()
        head.skip_bits(32)
        self.assertEqual(head.load_uint(8), 130)


if __name__ == "__main__":
    unittest.main()
