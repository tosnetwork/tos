"""T2 evidence tooling: paced JSON-RPC reads, the layout recorder, continuity and conservation.

Run: uv run python bench/tests/test_t2.py

Every check runs on synthetic records, so no chain is needed. The red
controls (a duplicated import, a dropped message, a missed merge
predecessor, a truncated walk) each assert the verdict the checker must give.
"""

import asyncio
import base64
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from shard import rpc as rpcmod  # noqa: E402
from shard import t2check, t2collect  # noqa: E402
from shard.t2check import (  # noqa: E402
    FAIL,
    INCONCLUSIVE,
    PASS,
    BlockRecord,
    BlockRef,
    BlockTxs,
    McRecord,
    Msg,
    QueueBoundary,
    Tx,
)

ROOT_SHARD = -(1 << 63)
LEFT, RIGHT = t2check.shard_children(ROOT_SHARD)
LL, LR = t2check.shard_children(LEFT)
# The synthetic chains use masterchain seqnos 100..104; all are finalized.
FINAL = 104


def h(*parts: object) -> str:
    """A deterministic 32-byte hex hash for a synthetic object."""
    import hashlib

    return hashlib.sha256(repr(parts).encode()).hexdigest()


def ref(shard: int, seqno: int) -> BlockRef:
    return BlockRef(0, shard, seqno, h("block", shard, seqno))


class Chain:
    """A synthetic basechain: block records built forward, masterchain blocks referencing tops."""

    def __init__(self):
        self.blocks: dict[tuple[int, int, int], BlockRecord] = {}
        self.mcs: list[McRecord] = []

    def add(self, shard: int, seqno: int, prev: list[BlockRef], **flags: bool) -> BlockRef:
        r = ref(shard, seqno)
        self.blocks[r.key] = BlockRecord(r, tuple(prev), gen_utime=1000 + seqno, **flags)
        return r

    def run(self, shard: int, start: BlockRef, count: int) -> BlockRef:
        cur = start
        for _ in range(count):
            cur = self.add(shard, cur.seqno + 1, [cur])
        return cur

    def mc(self, *tops: BlockRef) -> McRecord:
        seqno = len(self.mcs) + 100
        m = McRecord(seqno, 2000 + seqno, h("mc", seqno), tuple(tops))
        self.mcs.append(m)
        return m


def split_then_merge() -> Chain:
    """1 shard -> split into 2 -> merge back to 1.

    The last block before the split and one sibling block before the merge
    are referenced by no masterchain block, so the walk reaches them only by
    crossing the split and by following the merge's second predecessor.
    """
    c = Chain()
    root = c.add(ROOT_SHARD, 10, [ref(ROOT_SHARD, 9)])
    c.mc(root)  # opening boundary
    r11 = c.run(ROOT_SHARD, root, 1)
    left = c.add(LEFT, 12, [r11], after_split=True)
    right = c.add(RIGHT, 12, [r11], after_split=True)
    c.mc(left, right)
    left = c.run(LEFT, left, 2)  # LEFT 14
    right13 = c.run(RIGHT, right, 1)
    c.mc(left, right)  # RIGHT 13 is not referenced by any masterchain block
    merged = c.add(ROOT_SHARD, 15, [left, right13], after_merge=True)
    c.mc(merged)
    tail = c.run(ROOT_SHARD, merged, 2)
    c.mc(tail)
    return c


def all_refs(c: Chain) -> list[BlockRef]:
    return [b.ref for b in c.blocks.values()]


# ─── paced client ────────────────────────────────────────────────────


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += max(0.0, seconds)
        await asyncio.sleep(0)


class FakeNode:
    """A node answering scripted replies, recording every request's start time."""

    def __init__(self, clock: FakeClock, script: list[tuple[int, Any]] | None = None):
        self.clock, self.script = clock, list(script or [])
        self.starts: list[float] = []

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        self.starts.append(self.clock.now)
        request = json.loads(body)
        if self.script:
            status, document = self.script.pop(0)
        else:
            status, document = 200, {"jsonrpc": "2.0", "id": request["id"], "result": {"ok": 1}}
        return status, json.dumps(document).encode()


def limited(code: int = rpcmod.RATE_LIMITED_CODE) -> tuple[int, Any]:
    return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "Rate limit"}}


def max_in_window(starts: list[float], window: float) -> int:
    best = 0
    for i, t in enumerate(starts):
        best = max(best, sum(1 for u in starts[i:] if u < t + window))
    return best


class Paced(unittest.TestCase):
    def client(self, node: FakeNode, clock: FakeClock, **kw: Any) -> rpcmod.PacedRpc:
        return rpcmod.PacedRpc(
            "http://node/jsonRPC", transport=node, clock=clock, sleep=clock.sleep, **kw
        )

    def test_retries_429_and_rate_limit_error(self):
        clock = FakeClock()
        node = FakeNode(clock, [(429, {}), limited(), (429, {})])
        rpc = self.client(node, clock)
        self.assertEqual(asyncio.run(rpc.call("getMasterchainInfo")), {"ok": 1})
        self.assertEqual((rpc.sent, rpc.throttled), (4, 3))
        # Backoff grows between refusals.
        gaps = [b - a for a, b in zip(node.starts, node.starts[1:])]
        self.assertTrue(all(g > 0 for g in gaps) and gaps == sorted(gaps), gaps)

    def test_gives_up_after_its_attempts(self):
        clock = FakeClock()
        node = FakeNode(clock, [(429, {})] * 3)
        rpc = self.client(node, clock, attempts=3)
        with self.assertRaises(rpcmod.RateLimited):
            asyncio.run(rpc.call("getShards"))
        self.assertEqual(rpc.sent, 3)

    def test_other_errors_are_not_retried(self):
        clock = FakeClock()
        node = FakeNode(clock, [limited(-32603)])
        rpc = self.client(node, clock)
        with self.assertRaises(rpcmod.RpcError):
            asyncio.run(rpc.call("getBlockHeader"))
        self.assertEqual(rpc.sent, 1)
        node = FakeNode(clock, [(500, {})])
        with self.assertRaises(rpcmod.RpcError):
            asyncio.run(self.client(node, clock).call("getBlockHeader"))

    def test_stays_inside_its_share_with_retries_and_concurrency(self):
        clock = FakeClock()
        # Every fifth reply is a refusal; refused attempts spend budget too.
        script = [limited() if i % 5 == 0 else (200, {"result": i}) for i in range(1000)]
        node = FakeNode(clock, script)
        rpc = self.client(node, clock, share=0.1)  # 60 requests per 10 s
        self.assertEqual(rpc.budget.requests, 60)

        async def burst():
            await asyncio.gather(*(rpc.call("getShards") for _ in range(400)))

        asyncio.run(burst())
        self.assertEqual(rpc.sent, len(node.starts))
        self.assertGreater(rpc.throttled, 0)
        self.assertLessEqual(max_in_window(node.starts, 10.0), 60)
        self.assertGreaterEqual(clock.now, (len(node.starts) / 60 - 1) * 10)

    def test_share_bounds(self):
        for bad in (0, 1.5, 0.001):
            with self.assertRaises(ValueError):
                rpcmod.PacedRpc("http://x", bad)


# ─── layout recorder ─────────────────────────────────────────────────


class Layout(unittest.TestCase):
    def test_split_then_merge_recorded_at_each_mc_block(self):
        c = split_then_merge()
        changes, verdict = t2check.layout_changes(c.mcs)
        self.assertEqual(verdict.status, PASS, verdict.failures)
        self.assertEqual([x.kind for x in changes], ["split", "merge"])
        self.assertEqual([x.mc_seqno for x in changes], [101, 103])
        self.assertEqual(changes[0].old, ("8000000000000000",))
        self.assertEqual(changes[0].new, ("4000000000000000", "c000000000000000"))
        self.assertEqual(changes[1].gen_utime, 2103)

    def test_one_block_split_is_not_missed(self):
        c = Chain()
        a = c.add(ROOT_SHARD, 1, [ref(ROOT_SHARD, 0)])
        c.mc(a)
        l, r = c.add(LEFT, 2, [a], after_split=True), c.add(RIGHT, 2, [a], after_split=True)
        c.mc(l, r)  # two shards for exactly one masterchain block
        c.mc(c.add(ROOT_SHARD, 3, [l, r], after_merge=True))
        changes, verdict = t2check.layout_changes(c.mcs)
        self.assertEqual(verdict.status, PASS)
        self.assertEqual([(x.mc_seqno, x.kind) for x in changes], [(101, "split"), (102, "merge")])

    def test_two_to_four_and_partial_merge(self):
        c = Chain()
        l, r = ref(LEFT, 5), ref(RIGHT, 5)
        c.mc(l, r)
        c.mc(ref(LL, 6), ref(LR, 6), r)
        c.mc(ref(LL, 7), ref(LR, 7), *(ref(s, 6) for s in t2check.shard_children(RIGHT)))
        c.mc(ref(LEFT, 8), *(ref(s, 7) for s in t2check.shard_children(RIGHT)))
        changes, verdict = t2check.layout_changes(c.mcs)
        self.assertEqual(verdict.status, PASS)
        self.assertEqual([x.kind for x in changes], ["split", "split", "merge"])
        self.assertEqual(verdict.stats["max_shards"], 4)

    def test_a_missing_mc_block_is_a_gap(self):
        c = split_then_merge()
        changes, verdict = t2check.layout_changes(c.mcs[:2] + c.mcs[3:])
        self.assertEqual(verdict.status, INCONCLUSIVE)
        self.assertEqual(verdict.gaps[0]["from"], 102)

    def test_impossible_layout_change_fails(self):
        c = Chain()
        c.mc(ref(ROOT_SHARD, 1))
        c.mc(ref(LL, 2), ref(LR, 2), ref(RIGHT, 2))  # skips a depth
        _, verdict = t2check.layout_changes(c.mcs)
        self.assertEqual(verdict.status, FAIL)

    def test_recorder_reads_every_mc_block(self):
        c = split_then_merge()
        node = RecordedNode(c)
        rpc = rpcmod.PacedRpc("http://n", 1.0, transport=node)
        mcs = asyncio.run(t2collect.read_masterchain(rpc, 100, 104))
        self.assertEqual([m.seqno for m in mcs], list(range(100, 105)))
        self.assertEqual(mcs, c.mcs)
        self.assertEqual(sorted(node.mc_reads), list(range(100, 105)))


# ─── block continuity ────────────────────────────────────────────────


class Continuity(unittest.TestCase):
    def test_split_and_merge_window_passes(self):
        c = split_then_merge()
        result = t2check.check_continuity(c.mcs, c.blocks, all_refs(c), finalized_mc=FINAL)
        self.assertEqual(result.verdict.status, PASS, result.verdict.failures)
        # Root 10 is the opening top; every later block is in the window.
        self.assertEqual(len(result.reached), len(c.blocks) - 1)
        self.assertEqual(result.verdict.stats["merge_blocks"], 1)
        self.assertEqual(result.verdict.stats["split_blocks"], 2)

    def test_missed_merge_predecessor_fails(self):
        c = split_then_merge()
        merged = next(b for b in c.blocks.values() if b.after_merge)
        # The merge block's record lists only one of its two parents.
        c.blocks[merged.ref.key] = BlockRecord(
            merged.ref, merged.prev[:1], after_merge=True, gen_utime=merged.gen_utime
        )
        result = t2check.check_continuity(c.mcs, c.blocks, all_refs(c), finalized_mc=FINAL)
        self.assertEqual(result.verdict.status, FAIL)
        reasons = {f["reason"] for f in result.verdict.failures}
        self.assertIn("a merge block lists 1 predecessors, not 2", reasons)
        self.assertIn("observed window blocks not reached by the walk", reasons)
        unreached = next(f for f in result.verdict.failures if "blocks" in f)["blocks"]
        self.assertEqual(unreached, [ref(RIGHT, 13).label()])

    def test_walk_follows_both_merge_parents_and_crosses_the_split(self):
        # Guards the walk itself: the right sibling is reachable only through
        # the merge block's second predecessor, and the last unsplit block
        # only through the split blocks' parent link.
        c = split_then_merge()
        result = t2check.check_continuity(c.mcs, c.blocks, all_refs(c), finalized_mc=FINAL)
        self.assertIn(ref(RIGHT, 13).key, result.reached)
        self.assertIn(ref(ROOT_SHARD, 11).key, result.reached)
        self.assertEqual(result.verdict.stats["observed_unreached"], 0)

    def test_truncated_walk_is_inconclusive_not_failed(self):
        c = split_then_merge()
        result = t2check.check_continuity(
            c.mcs, c.blocks, all_refs(c), max_blocks=3, finalized_mc=FINAL
        )
        self.assertEqual(result.verdict.status, INCONCLUSIVE)
        self.assertEqual(result.verdict.failures, [])
        self.assertTrue(result.verdict.stats["truncated"])
        # Conservation over that window is then inconclusive too, never "dropped".
        txs = {k: BlockTxs((), True) for k in result.reached}
        verdict = t2check.check_conservation(
            result, txs, {"0:aa"}, (), QueueBoundary(1, True), QueueBoundary(2, True)
        )
        self.assertEqual(verdict.status, INCONCLUSIVE)
        self.assertEqual(verdict.stats["dropped"], 0)

    def test_unread_block_is_a_gap(self):
        c = split_then_merge()
        del c.blocks[ref(LEFT, 13).key]
        result = t2check.check_continuity(c.mcs, c.blocks, all_refs(c), finalized_mc=FINAL)
        self.assertEqual(result.verdict.status, INCONCLUSIVE)
        self.assertEqual(result.verdict.failures, [])

    def test_observed_blocks_after_the_closing_tops_are_outside_the_window(self):
        c = split_then_merge()
        later = BlockRef(0, ROOT_SHARD, 30, h("later"))
        result = t2check.check_continuity(
            c.mcs, c.blocks, all_refs(c) + [later], finalized_mc=FINAL
        )
        self.assertEqual(result.verdict.status, PASS, result.verdict.failures)

    def test_fork_and_wrong_links_fail(self):
        c = split_then_merge()
        observed = all_refs(c) + [BlockRef(0, LEFT, 13, h("fork"))]
        result = t2check.check_continuity(c.mcs, c.blocks, observed, finalized_mc=FINAL)
        self.assertEqual(result.verdict.status, FAIL)
        c = split_then_merge()
        bad = ref(LEFT, 13)
        c.blocks[bad.key] = BlockRecord(bad, (ref(LEFT, 11),), gen_utime=1)
        self.assertEqual(
            t2check.check_continuity(c.mcs, c.blocks, finalized_mc=FINAL).verdict.status, FAIL
        )

    def test_split_block_must_name_its_parent_shard(self):
        c = split_then_merge()
        left = c.blocks[ref(LEFT, 12).key]
        c.blocks[left.ref.key] = BlockRecord(left.ref, left.prev, gen_utime=1)  # not after_split
        result = t2check.check_continuity(c.mcs, c.blocks, finalized_mc=FINAL)
        self.assertEqual(result.verdict.status, FAIL)

    def test_collector_walk_reads_both_parents_and_crosses_the_split(self):
        c = split_then_merge()
        rpc = rpcmod.PacedRpc("http://n", 1.0, transport=RecordedNode(c))
        blocks = asyncio.run(t2collect.walk_blocks(rpc, c.mcs))
        self.assertEqual(set(blocks), set(c.blocks) - {ref(ROOT_SHARD, 10).key})
        result = t2check.check_continuity(c.mcs, blocks, all_refs(c), finalized_mc=FINAL)
        self.assertEqual(result.verdict.status, PASS)


# ─── message conservation ────────────────────────────────────────────

RUN = [f"0:{i:064x}" for i in range(1, 5)]
FUNDER = f"0:{0xF0:064x}"


def msg(n: int, src: str, dst: str, bounced: bool = False) -> Msg:
    return Msg(h("msg", n), "internal", src, dst, bounced)


class Traffic:
    """Transactions placed into the window blocks of a synthetic chain."""

    def __init__(self, chain: Chain):
        self.chain = chain
        self.continuity = t2check.check_continuity(
            chain.mcs, chain.blocks, all_refs(chain), finalized_mc=FINAL
        )
        self.keys = sorted(self.continuity.reached, key=lambda k: (k[2], k[1] & t2check.U64))
        self.txs: dict[tuple[int, int, int], list[Tx]] = {k: [] for k in self.keys}
        self.n = 0

    def tx(self, block: int, account: str, in_msg: Msg | None, *out: Msg, **kw: Any) -> Tx:
        self.n += 1
        t = Tx(h("tx", self.n), account, self.n, self.keys[block], in_msg, tuple(out), **kw)
        self.txs[t.block].append(t)
        return t

    def check(self, opening: bool | None = True, closing: bool | None = True):
        blocks = {k: BlockTxs(tuple(v), True) for k, v in self.txs.items()}
        return t2check.check_conservation(
            self.continuity,
            blocks,
            RUN,
            [FUNDER],
            QueueBoundary(100, opening),
            QueueBoundary(104, closing),
        )


def hop_run() -> tuple[Traffic, dict[str, Msg]]:
    """Funder starts a chain, which forks once, ends after four hops, plus a bounce and a deploy."""
    t = Traffic(split_then_merge())
    m = {
        "start": msg(0, FUNDER, RUN[0]),
        "a": msg(1, RUN[0], RUN[1]),
        "b": msg(2, RUN[0], RUN[2]),
        "c": msg(3, RUN[1], RUN[3]),
        "d": msg(4, RUN[2], RUN[3]),
        "bounce": msg(5, RUN[3], RUN[2], bounced=True),
    }
    t.tx(0, FUNDER, Msg(h("ext"), "external"), m["start"])
    t.tx(1, RUN[0], m["start"], m["a"], m["b"])  # a fork
    t.tx(2, RUN[1], m["a"], m["c"])
    t.tx(3, RUN[2], m["b"], m["d"], skipped_actions=1)
    t.tx(4, RUN[3], m["c"], activated=True)  # the first message deploys the account
    t.tx(5, RUN[3], m["d"], m["bounce"])
    t.tx(6, RUN[2], m["bounce"])
    return t, m


class Conservation(unittest.TestCase):
    def test_happy_path_delivers_every_message_once(self):
        t, _ = hop_run()
        v = t.check()
        self.assertEqual(v.status, PASS, v.failures + v.gaps)
        self.assertEqual(v.stats["run_owned_emitted"], 6)
        self.assertEqual(v.stats["delivered"], {"entry": 1, "hop": 3, "deployment": 1, "bounce": 1})
        self.assertEqual(v.stats["skipped_actions"], 1)

    def test_duplicated_import_fails(self):
        t, m = hop_run()
        dup = t.tx(7, RUN[3], m["c"])
        v = t.check()
        self.assertEqual(v.status, FAIL)
        failure = next(
            f for f in v.failures if f["reason"] == "one message imported more than once"
        )
        self.assertEqual(failure["message"], m["c"].hash)
        self.assertIn(dup.hash, failure["txs"])

    def test_duplicate_fails_even_while_inconclusive(self):
        t, m = hop_run()
        t.tx(7, RUN[3], m["c"])
        self.assertEqual(t.check(opening=None, closing=None).status, FAIL)

    def test_dropped_message_fails(self):
        t, m = hop_run()
        for txs in t.txs.values():
            txs[:] = [x for x in txs if x.in_msg != m["d"]]
        # The bounce came from that import, so it goes too.
        for txs in t.txs.values():
            txs[:] = [x for x in txs if x.in_msg != m["bounce"]]
        v = t.check()
        self.assertEqual(v.status, FAIL)
        failure = next(f for f in v.failures if "never delivered" in f["reason"])
        self.assertEqual(failure["messages"], [m["d"].hash])

    def test_undelivered_before_drain_is_inconclusive_not_lost(self):
        t, m = hop_run()
        for txs in t.txs.values():
            txs[:] = [x for x in txs if x.in_msg not in (m["d"], m["bounce"])]
        v = t.check(closing=False)
        self.assertEqual(v.status, INCONCLUSIVE)
        self.assertEqual(v.stats["dropped"], 0)
        self.assertEqual(v.stats["pending"], 1)

    def test_import_by_wrong_account_fails(self):
        t, m = hop_run()
        for txs in t.txs.values():
            for i, x in enumerate(txs):
                if x.in_msg == m["c"]:
                    txs[i] = Tx(x.hash, RUN[1], x.lt, x.block, x.in_msg)
        self.assertEqual(t.check().status, FAIL)

    def test_import_without_emission_fails_when_opening_queue_empty(self):
        t, _ = hop_run()
        t.tx(7, RUN[1], msg(99, RUN[0], RUN[1]))
        self.assertEqual(t.check().status, FAIL)
        self.assertEqual(t.check(opening=None).status, INCONCLUSIVE)

    def test_incomplete_transaction_list_is_a_gap(self):
        t, _ = hop_run()
        blocks = {k: BlockTxs(tuple(v), True) for k, v in t.txs.items()}
        first = t.keys[0]
        blocks[first] = BlockTxs(blocks[first].txs, False)
        v = t2check.check_conservation(
            t.continuity, blocks, RUN, [FUNDER], QueueBoundary(1, True), QueueBoundary(2, True)
        )
        self.assertEqual(v.status, INCONCLUSIVE)

    def test_evaluate_combines_verdicts(self):
        t, _ = hop_run()
        blocks = {k: BlockTxs(tuple(v), True) for k, v in t.txs.items()}
        out = t2check.evaluate(
            t.chain.mcs,
            t.chain.blocks,
            blocks,
            RUN,
            [FUNDER],
            QueueBoundary(100, True),
            QueueBoundary(104, True),
            all_refs(t.chain),
            finalized_mc=FINAL,
        )
        self.assertEqual(out["status"], PASS)
        self.assertEqual([c["kind"] for c in out["layout_changes"]], ["split", "merge"])
        json.dumps(out)


# ─── collection layer: JSON parsing over the server's answer shapes ─


def b64(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode()


def id_json(r: BlockRef) -> dict[str, Any]:
    return {
        "@type": "tos.blockIdExt",
        "workchain": r.workchain,
        "shard": str(r.shard),
        "seqno": r.seqno,
        "root_hash": b64(r.root_hash),
        "file_hash": b64(h("file", r.key)),
    }


class RecordedNode:
    """Answers a synthetic chain's reads in the server's JSON shapes.

    ``finalized`` is the seqno getConsensusBlock reports; blocks carry no
    transactions.
    """

    def __init__(self, chain: Chain, finalized: int = FINAL):
        self.chain = chain
        self.finalized = finalized
        self.mc_reads: list[int] = []

    async def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        request = json.loads(body)
        p = request["params"]
        if request["method"] == "getConsensusBlock":
            result: Any = {"@type": "ext.blocks.consensusBlock", "consensus_block": self.finalized}
        elif request["method"] == "getBlockTransactionsExt":
            b = self.chain.blocks[(0, int(p["shard"]), p["seqno"])]
            result = {"id": id_json(b.ref), "incomplete": False, "transactions": []}
        elif request["method"] == "getShards":
            m = next(x for x in self.chain.mcs if x.seqno == p["seqno"])
            result = {"@type": "blocks.shards", "shards": [id_json(t) for t in m.tops]}
        elif p["workchain"] == -1:
            m = next(x for x in self.chain.mcs if x.seqno == p["seqno"])
            self.mc_reads.append(m.seqno)
            mc = BlockRef(-1, ROOT_SHARD, m.seqno, m.root_hash)
            result = {"@type": "blocks.header", "id": id_json(mc), "gen_utime": m.gen_utime}
        else:
            b = self.chain.blocks[(0, int(p["shard"]), p["seqno"])]
            result = {
                "@type": "blocks.header",
                "id": id_json(b.ref),
                "after_merge": b.after_merge,
                "after_split": b.after_split,
                "before_split": b.before_split,
                "gen_utime": b.gen_utime,
                "prev_blocks": [id_json(x) for x in b.prev],
            }
        return 200, json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()


class Finality(unittest.TestCase):
    def test_finalized_window_passes(self):
        c = split_then_merge()
        for finalized in (FINAL, FINAL + 50):
            result = t2check.check_continuity(c.mcs, c.blocks, all_refs(c), finalized_mc=finalized)
            self.assertEqual(result.verdict.status, PASS, result.verdict.gaps)

    def test_closing_above_finality_is_not_pass(self):
        c = split_then_merge()
        result = t2check.check_continuity(c.mcs, c.blocks, all_refs(c), finalized_mc=FINAL - 1)
        self.assertEqual(result.verdict.status, INCONCLUSIVE)
        self.assertEqual(result.verdict.failures, [])
        self.assertEqual(result.verdict.gaps[0]["mc_seqnos"], [FINAL])
        t, _ = hop_run()
        blocks = {k: BlockTxs(tuple(v), True) for k, v in t.txs.items()}
        out = t2check.evaluate(
            t.chain.mcs,
            t.chain.blocks,
            blocks,
            RUN,
            [FUNDER],
            QueueBoundary(100, True),
            QueueBoundary(104, True),
            all_refs(t.chain),
            finalized_mc=FINAL - 1,
        )
        self.assertEqual(out["status"], INCONCLUSIVE)
        self.assertEqual(out["conservation"]["status"], INCONCLUSIVE)

    def test_unknown_finality_is_not_pass(self):
        c = split_then_merge()
        result = t2check.check_continuity(c.mcs, c.blocks, all_refs(c), finalized_mc=None)
        self.assertEqual(result.verdict.status, INCONCLUSIVE)

    def test_read_finalized_takes_the_lowest_node_and_fails_closed(self):
        c = split_then_merge()
        nodes = [RecordedNode(c, 120), RecordedNode(c, 110), RecordedNode(c, 130)]
        rpcs = [rpcmod.PacedRpc("http://n", 1.0, transport=n) for n in nodes]
        self.assertEqual(asyncio.run(t2collect.read_finalized(rpcs)), 110)

        async def broken(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
            return 500, b"{}"

        rpcs.append(rpcmod.PacedRpc("http://n", 1.0, transport=broken))
        self.assertIsNone(asyncio.run(t2collect.read_finalized(rpcs)))
        self.assertIsNone(asyncio.run(t2collect.read_finalized([])))

    def test_wait_finalized_is_bounded(self):
        c = split_then_merge()
        node = RecordedNode(c, 100)
        rpc = rpcmod.PacedRpc("http://n", 1.0, transport=node)
        got = asyncio.run(t2collect.wait_finalized([rpc], 104, timeout=0.05, poll=0.01))
        self.assertEqual(got, 100)

        async def advancing():
            async def bump():
                await asyncio.sleep(0.02)
                node.finalized = 104

            task = asyncio.create_task(bump())
            got = await t2collect.wait_finalized([rpc], 104, timeout=5, poll=0.005)
            await task
            return got

        self.assertEqual(asyncio.run(advancing()), 104)

    def test_check_window_records_finality(self):
        import tempfile

        c = split_then_merge()
        for finalized, status in ((FINAL, PASS), (FINAL - 1, INCONCLUSIVE)):
            rpc = rpcmod.PacedRpc("http://n", 1.0, transport=RecordedNode(c, finalized))
            with tempfile.TemporaryDirectory() as d:
                result = asyncio.run(
                    t2collect.check_window(
                        rpc,
                        QueueBoundary(100, True),
                        QueueBoundary(FINAL, True),
                        set(RUN),
                        {FUNDER},
                        Path(d),
                        all_refs(c),
                        finality_wait=0,
                    )
                )
                records = json.loads((Path(d) / "t2-records.json").read_text())
            self.assertEqual(result["status"], status)
            self.assertEqual(records["finalized_mc"], finalized)
            self.assertEqual(records["diagnostics"]["run_owned_balance"]["emitted"], 0)


class Diagnostics(unittest.TestCase):
    def test_run_owned_balance_counts_outstanding_messages(self):
        t, m = hop_run()
        for txs in t.txs.values():
            txs[:] = [x for x in txs if x.in_msg not in (m["d"], m["bounce"])]
        # An import from outside the run is not a delivery of a run-owned message.
        t.tx(7, RUN[1], msg(77, f"0:{0xEE:064x}", RUN[1]))
        blocks = {k: BlockTxs(tuple(v), True) for k, v in t.txs.items()}
        got = t2check.run_owned_balance(t.continuity, blocks, RUN, [FUNDER])
        self.assertEqual(got, {"emitted": 5, "imported": 4, "emitted_minus_imported": 1})


class Parsing(unittest.TestCase):
    def test_transaction_summary(self):
        from pytosiq_core import Address

        src = Address((0, bytes.fromhex(RUN[0][2:]))).to_str()
        dst = Address((0, bytes.fromhex(RUN[1][2:]))).to_str()
        raw = {
            "@type": "raw.transaction",
            "account": RUN[1][2:],
            "lt": "77",
            "hash": b64(h("tx")),
            "in_msg": {
                "hash": b64(h("m1")),
                "kind": "internal",
                "source": src,
                "destination": dst,
                "value": "5",
                "bounced": False,
                "created_lt": "70",
                "created_at": 1,
            },
            "out_msgs": [{"hash": b64(h("m2")), "kind": "unknown"}],
            "transaction_type": "ordinary",
            "aborted": False,
            "compute": {"skipped": False, "success": True, "account_activated": True},
            "action": {"success": True, "skipped_actions": 2, "messages_created": 0},
        }
        tx = t2collect.parse_transaction(raw, (0, LEFT, 5))
        self.assertEqual(tx.account, RUN[1])
        self.assertEqual(tx.in_msg, Msg(h("m1"), "internal", RUN[0], RUN[1], False))
        self.assertEqual(tx.out_msgs[0].kind, "unknown")
        self.assertEqual((tx.activated, tx.skipped_actions, tx.action_success), (True, 2, True))

    def test_header_without_predecessors_is_refused(self):
        with self.assertRaises(ValueError):
            t2collect.parse_header({"id": id_json(ref(LEFT, 1)), "gen_utime": 1})

    def test_paginates_transaction_lists(self):
        block = ref(LEFT, 9)
        pages = [
            {"id": id_json(block), "incomplete": True, "transactions": [tx_json(1), tx_json(2)]},
            {"id": id_json(block), "incomplete": False, "transactions": [tx_json(3)]},
        ]
        seen: list[dict[str, Any]] = []

        async def node(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
            request = json.loads(body)
            seen.append(request["params"])
            return 200, json.dumps({"id": 1, "result": pages[len(seen) - 1]}).encode()

        rpc = rpcmod.PacedRpc("http://n", 1.0, transport=node)
        got = asyncio.run(t2collect.read_transactions(rpc, block))
        self.assertTrue(got.complete)
        self.assertEqual(len(got.txs), 3)
        self.assertEqual(seen[1]["after_lt"], "2")
        self.assertEqual(seen[1]["after_account"], f"{2:064x}")


def tx_json(n: int) -> dict[str, Any]:
    return {"account": f"{n:064x}", "lt": str(n), "hash": b64(h("t", n)), "in_msg": None}


if __name__ == "__main__":
    unittest.main()
