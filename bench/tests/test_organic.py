"""Organic split runs of the shard bench: layout history, the merge wait and the CLI checks."""

import asyncio
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "bench/shard/run_shard_bench.py"
spec = importlib.util.spec_from_file_location("run_shard_bench", SCRIPT)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

ROOT_SHARD = 1 << 63  # 0x8000000000000000: the whole basechain
LEFT, RIGHT = 1 << 62, 3 << 62  # its two children


def signed(shard):
    return shard - (1 << 64) if shard >= 1 << 63 else shard


class FakeScanner:
    def __init__(self, layouts):
        self.layouts = list(layouts)
        self.shard_sets = [(0.0, ["8000"])]

    async def heads(self):
        layout = self.layouts.pop(0) if len(self.layouts) > 1 else self.layouts[0]
        labels = sorted(bench.hopbench.shard_label(s) for s in layout)
        if labels != self.shard_sets[-1][1]:
            self.shard_sets.append((0.0, labels))
        return {signed(s): None for s in layout}


async def no_sleep(_):
    return None


class OrganicSummaryTest(unittest.TestCase):
    def test_split_and_merge_times_are_relative_to_the_load(self):
        sets = [(100.0, ["8000"]), (130.5, ["4000", "c000"]), (400.0, ["8000"])]
        out = bench.organic_summary(sets, 0, 100.0, 300.0, 420.0, 600)
        self.assertEqual([h["t"] for h in out["history"]], [0.0, 30.5, 300.0])
        self.assertEqual(out["first_split_after_load_start_s"], 30.5)
        self.assertEqual(out["peak_shards"], 2)
        self.assertTrue(out["merged"])
        self.assertEqual(out["merge_after_load_end_s"], 120.0)

    def test_a_layout_that_never_split_has_no_split_time(self):
        out = bench.organic_summary([(10.0, ["8000"])], 0, 10.0, 50.0, None, 60)
        self.assertIsNone(out["first_split_after_load_start_s"])
        self.assertFalse(out["merged"])
        self.assertIsNone(out["merge_after_load_end_s"])


class WaitMergeTest(unittest.TestCase):
    def test_back_to_one_shard_after_a_split_is_a_merge(self):
        scanner = FakeScanner([[LEFT, RIGHT], [LEFT, RIGHT], [ROOT_SHARD]])
        with patch.object(bench.asyncio, "sleep", no_sleep):
            merged = asyncio.run(bench.wait_merge(scanner, 0, 5.0))
        self.assertIsNotNone(merged)

    def test_one_shard_that_never_split_is_not_a_merge(self):
        scanner = FakeScanner([[ROOT_SHARD]])
        with patch.object(bench.asyncio, "sleep", no_sleep):
            self.assertIsNone(asyncio.run(bench.wait_merge(scanner, 0, 0.05)))

    def test_a_split_layout_at_the_timeout_is_not_a_merge(self):
        scanner = FakeScanner([[LEFT, RIGHT]])
        with patch.object(bench.asyncio, "sleep", no_sleep):
            self.assertIsNone(asyncio.run(bench.wait_merge(scanner, 0, 0.05)))


class CliTest(unittest.TestCase):
    def refused(self, *args):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--out", "/nonexistent/never-created", *args],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(r.returncode, 2, r.stderr)
        return r.stderr

    def test_max_split_below_split_is_refused(self):
        self.assertIn("--max-split", self.refused("--split", "2", "--max-split", "1"))

    def test_merge_wait_needs_an_organic_run(self):
        self.assertIn("--merge-wait", self.refused("--merge-wait", "60"))

    def test_max_split_above_four_is_refused(self):
        self.assertIn("--max-split", self.refused("--max-split", "5"))


if __name__ == "__main__":
    unittest.main()
