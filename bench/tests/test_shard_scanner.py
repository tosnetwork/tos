"""ShardScanner across a split and a merge: every block once, in its own shard, none missed."""

import asyncio
import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "run_shard_bench", ROOT / "bench/shard/run_shard_bench.py"
)
assert spec is not None and spec.loader is not None
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

ROOT_SHARD = -(1 << 63)  # 0x8000000000000000 as a signed int64
LEFT = 1 << 62  # 0x4000000000000000
RIGHT = -(1 << 62)  # 0xc000000000000000 as a signed int64


def ref(shard, seqno):
    return SimpleNamespace(
        workchain=0, shard=shard, seqno=seqno, root_hash=bytes([seqno % 256]) * 32
    )


class FakeChain:
    """A basechain whose block graph is given as {(shard, seqno): [prev refs]}."""

    def __init__(self, graph):
        self.graph = graph
        self.heads = []
        self.reads = []

    async def call(self, method, *args):
        if method == "get_masterchain_info":
            return SimpleNamespace(last=None)
        if method == "get_shards":
            return SimpleNamespace(shards=self.heads)
        if method == "get_block_header":
            block = args[0]
            self.reads.append((block.shard, block.seqno))
            return SimpleNamespace(
                gen_utime=1000 + block.seqno, prev_blocks=self.graph[(block.shard, block.seqno)]
            )
        raise AssertionError(method)


def chain_graph():
    g = {}
    for s in range(1, 13):  # the root shard 1..12
        g[(ROOT_SHARD, s)] = [ref(ROOT_SHARD, s - 1)] if s > 1 else []
    for child in (LEFT, RIGHT):  # split after root 12: children start at 13
        g[(child, 13)] = [ref(ROOT_SHARD, 12)]
        for s in range(14, 21):
            g[(child, s)] = [ref(child, s - 1)]
    g[(ROOT_SHARD, 21)] = [ref(LEFT, 20), ref(RIGHT, 20)]  # merge after both reach 20
    for s in range(22, 25):
        g[(ROOT_SHARD, s)] = [ref(ROOT_SHARD, s - 1)]
    return g


class ShardScannerSplitMergeTest(unittest.TestCase):
    def scan(self, polls):
        fake = FakeChain(chain_graph())
        scanner = bench.ShardScanner(fake)

        async def go():
            fake.heads = [ref(ROOT_SHARD, 10)]
            await scanner.start_position()
            for heads in polls:
                fake.heads = heads
                infos = await scanner.heads()
                for shard, head in infos.items():
                    await scanner._walk(shard, head)

        asyncio.run(go())
        return scanner, fake

    def test_a_split_records_the_parent_tail_and_every_child_block(self):
        scanner, fake = self.scan([[ref(LEFT, 16), ref(RIGHT, 15)]])
        got = sorted((b.shard, b.seqno) for b in scanner.blocks)
        want = sorted(
            [(ROOT_SHARD, 11), (ROOT_SHARD, 12)]
            + [(LEFT, s) for s in range(13, 17)]
            + [(RIGHT, s) for s in range(13, 16)]
        )
        self.assertEqual(got, want)
        self.assertEqual(len(fake.reads), len(set(fake.reads)), "a block was read twice")

    def test_a_merge_after_a_split_misses_nothing_and_counts_nothing_twice(self):
        scanner, _ = self.scan(
            [
                [ref(LEFT, 14), ref(RIGHT, 13)],
                [ref(LEFT, 18), ref(RIGHT, 19)],
                [ref(ROOT_SHARD, 23)],
            ]
        )
        got = [(b.shard, b.seqno) for b in scanner.blocks]
        self.assertEqual(len(got), len(set(got)), "a block was recorded twice")
        want = (
            [(ROOT_SHARD, s) for s in (11, 12)]
            + [(LEFT, s) for s in range(13, 21)]
            + [(RIGHT, s) for s in range(13, 21)]
            + [(ROOT_SHARD, s) for s in range(21, 24)]
        )
        self.assertEqual(sorted(got), sorted(want))


if __name__ == "__main__":
    unittest.main()
