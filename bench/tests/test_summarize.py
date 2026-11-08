"""Stage summary: exact accounting, saturation attribution and per-connection ingress counts.

Run: uv run python bench/tests/test_summarize.py
"""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

import run_local_bench as bench  # noqa: E402
from pqbench.chain import BlockRow, SendRecord  # noqa: E402

RATE_LIMIT = "LITE_SERVER_NOTREADY: external message source rate limit exceeded"
STALE = (
    "LITE_SERVER_UNKNOWN: inbound external message rejected by transaction AB: exitcode=1804, steps"
)
NETWORK = "LITE_SERVER_NETWORKconn not ready"


def make(out: Path, wallets: int = 4):
    a = SimpleNamespace(warmup=1, drain=1, out=out)
    self = SimpleNamespace(
        a=a,
        wallets=[
            SimpleNamespace(address=SimpleNamespace(hash_part=bytes([i]) * 32))
            for i in range(wallets)
        ],
    )
    return self


def blocks(t0: float, per_block: int, n: int = 20):
    return [
        BlockRow(
            i,
            int(t0 + i * 0.4),
            t0 + i * 0.4 + 0.1,
            2 * per_block,
            {bench.LOAD_CLASS: per_block, "sink": per_block},
        )
        for i in range(n)
    ]


def run(self, rate, count, records, rows, executed, t0, t_sent):
    scanner = SimpleNamespace(rows=rows, first_seen={})
    return bench.Bench.summarize(self, rate, count, records, scanner, executed, t0, t_sent, 0.1)


class SummarizeTests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def setUp(self):
        for child in self.out.iterdir():
            for f in child.iterdir():
                f.unlink()
            child.rmdir()

    def __del__(self):
        self.tmp.cleanup()

    def test_all_executed_is_not_saturated(self):
        t0 = 1000.0
        records = [
            SendRecord(i, t0 + i / 10, t0 + i / 10, True, None, f"c{i % 4}") for i in range(80)
        ]
        r = run(make(self.out), 10.0, 80, records, blocks(t0, 4), 80, t0, t0 + 8)
        self.assertEqual((r["transfers_executed"], r["transfers_unaccounted"]), (80, 0))
        self.assertFalse(r["below_offered_rate"])
        self.assertFalse(r["saturated"])
        self.assertEqual(r["ingress"]["connections"], 4)
        self.assertEqual(r["ingress"]["max_sends_per_connection_per_10s"], 20)

    def test_shortfall_with_only_backlog_refusals_is_saturation(self):
        t0 = 2000.0
        records = [
            SendRecord(i, t0 + i / 10, t0 + i / 10, i % 2 == 0, None if i % 2 == 0 else STALE, "c0")
            for i in range(80)
        ]
        r = run(make(self.out), 10.0, 80, records, blocks(t0, 2), 40, t0, t0 + 8)
        self.assertTrue(r["below_offered_rate"])
        self.assertEqual(r["admission_refusals"], 0)
        self.assertEqual(r["non_chain_bottlenecks"], [])
        self.assertTrue(r["saturated"])
        self.assertIn(
            "LITE_SERVER_UNKNOWN: inbound external message rejected (1804)", r["refusal_reasons"]
        )

    def test_ingress_and_client_network_failures_are_not_chain_saturation(self):
        t0 = 3000.0
        reasons = [None, RATE_LIMIT, NETWORK, None]
        records = [
            SendRecord(
                i, t0 + i / 10, t0 + i / 10, reasons[i % 4] is None, reasons[i % 4], f"c{i % 2}"
            )
            for i in range(80)
        ]
        r = run(make(self.out), 10.0, 80, records, blocks(t0, 2), 40, t0, t0 + 8)
        self.assertTrue(r["below_offered_rate"])
        self.assertFalse(r["saturated"])
        self.assertEqual(r["admission_refusals"], 20)
        self.assertEqual(r["client_network_failures"], 20)
        self.assertEqual(len(r["non_chain_bottlenecks"]), 2)
        self.assertEqual(r["ingress"]["connections_with_rate_limit_refusals"], 1)

    def test_late_observation_is_an_observer_bottleneck(self):
        t0 = 4000.0
        rows = blocks(t0, 4)
        rows[10].gen_utime = int(
            rows[10].observed - 7
        )  # observed inside the window, generated 7 s earlier
        records = [SendRecord(i, t0 + i / 10, t0 + i / 10, True, None, "c0") for i in range(80)]
        r = run(make(self.out), 10.0, 80, records, rows, 40, t0, t0 + 8)
        self.assertEqual(r["observer_late_blocks"], 1)
        self.assertIn("block scanner lagged the chain", r["non_chain_bottlenecks"])
        self.assertFalse(r["saturated"])


if __name__ == "__main__":
    unittest.main()
