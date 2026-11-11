"""Stage summary: exact accounting, saturation attribution and per-connection ingress counts.

Run: uv run python bench/tests/test_summarize.py
"""

import argparse
import asyncio
import csv
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

import run_local_bench as bench  # noqa: E402
from pqbench import chain  # noqa: E402
from pqbench.chain import BlockRow, SendRecord  # noqa: E402

RATE_LIMIT = "LITE_SERVER_NOTREADY: external message source rate limit exceeded"
STALE = (
    "LITE_SERVER_UNKNOWN: inbound external message rejected by transaction AB: exitcode=1804, steps"
)
NETWORK = "LITE_SERVER_NETWORKconn not ready"


def make(out: Path, wallets: int = 4):
    a = SimpleNamespace(warmup=1, drain=1, out=out)
    return SimpleNamespace(
        a=a, load_addresses=[SimpleNamespace(hash_part=bytes([i]) * 32) for i in range(wallets)]
    )


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


def run(self, rate, count, records, rows, executed, t0, t_sent, lag=None):
    scanner = SimpleNamespace(rows=rows, first_seen={}, lag=lag)
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

    def test_stale_refusals_beyond_the_ingress_cascade_are_chain_backlog(self):
        t0 = 5000.0
        # 4 wallets, 80 transfers: 20 per wallet, so one ingress refusal explains at most 19 stale ones.
        reasons = [RATE_LIMIT] + [STALE] * 30 + [None] * 49
        records = [
            SendRecord(i, t0 + i / 10, t0 + i / 10, reasons[i] is None, reasons[i], "c0")
            for i in range(80)
        ]
        r = run(make(self.out), 10.0, 80, records, blocks(t0, 2), 49, t0, t0 + 8)
        self.assertEqual(r["ingress_cascade_max"], 19)
        self.assertEqual(r["chain_backlog_refusals_min"], 11)
        self.assertIn("node admission refusals", r["non_chain_bottlenecks"])
        self.assertTrue(r["saturated"])

    def test_stale_refusals_within_the_ingress_cascade_are_not_saturation(self):
        t0 = 6000.0
        reasons = [RATE_LIMIT] + [STALE] * 19 + [None] * 60
        records = [
            SendRecord(i, t0 + i / 10, t0 + i / 10, reasons[i] is None, reasons[i], "c0")
            for i in range(80)
        ]
        r = run(make(self.out), 10.0, 80, records, blocks(t0, 2), 60, t0, t0 + 8)
        self.assertEqual(r["chain_backlog_refusals_min"], 0)
        self.assertFalse(r["saturated"])

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

    def test_only_retry_intervals_overlapping_the_steady_window_affect_saturation(self):
        t0 = 1000.0
        for name, start, end, refusal, observer, saturated in (
            ("straddles", 0.5, 8.5, None, True, False),
            ("warmup", 0.1, 0.5, None, False, True),
            ("drain", 8.1, 8.5, None, False, True),
            ("confirmed-backlog", 7.5, 8.5, STALE, True, True),
        ):
            with self.subTest(name=name):
                rows = blocks(t0, 1, n=1)
                rows[0].lag_started_at = t0 + start
                rows[0].observed = t0 + end
                records = [SendRecord(0, t0, t0, refusal is None, refusal, "c0")]
                r = run(
                    make(self.out / name), 1, 1, records, rows, int(refusal is None), t0, t0 + 8
                )
                self.assertTrue(r["below_offered_rate"])
                self.assertIsNone(r["scanner_lag"])
                self.assertEqual(r["observer_late_blocks"], 0)
                self.assertEqual(
                    "block scanner lagged the chain" in r["non_chain_bottlenecks"], observer
                )
                self.assertEqual(r["saturated"], saturated)

    def test_timeline_only_counts_observations_inside_the_send_and_drain_window(self):
        t0 = 1000.0
        rows = blocks(t0, 1, n=5)
        for row, offset in zip(rows, (-0.1, 0.1, 2.25, 2.26, 3600.0)):
            row.observed = t0 + offset
        records = [SendRecord(0, t0, t0, True, None, "c0")]
        for name, lag in (("complete", None), ("timeout", {"first_missing_seqno": 5})):
            with self.subTest(name=name):
                out = self.out / name
                run(make(out), 1, 1, records, rows, 1, t0, t0 + 1.25, lag=lag)
                stage = out / "stage-quantum-1"
                with (stage / "blocks.csv").open() as f:
                    self.assertEqual(len(list(csv.DictReader(f))), 5)
                with (stage / "timeline.csv").open() as f:
                    timeline = list(csv.DictReader(f))
                self.assertEqual([row["tx_observed"] for row in timeline], ["2", "0", "2", "0"])
                self.assertEqual([row["messages_sent"] for row in timeline], ["1", "0", "0", "0"])

    def test_incomplete_scan_keeps_observations_and_independent_accounting(self):
        t0 = 1000.0
        records = [SendRecord(i, t0 + i, t0 + i, True, None, "c0") for i in range(8)]
        rows = blocks(t0, 2, n=4)
        lag = {"first_missing_seqno": 4, "last_scanned_seqno": 3}
        r = run(make(self.out), 1.0, 8, records, rows, 8, t0, t0 + 8, lag=lag)
        self.assertEqual(r["scanner_lag"], lag)
        self.assertEqual(
            (r["messages_sent"], r["transfers_executed"], r["executed_fraction"]), (8, 8, 1)
        )
        self.assertEqual((r["blocks"], r["steady_blocks"]), (4, 1))
        self.assertIn("block scanner lagged the chain", r["non_chain_bottlenecks"])
        for key in (
            "steady_transfer_tps",
            "steady_total_tx_tps",
            "steady_blocks_per_second",
            "mean_block_interval_s",
            "max_tx_per_block",
            "inclusion_latency_s",
            "below_offered_rate",
            "saturated",
        ):
            self.assertIsNone(r[key], key)
        stage = self.out / "stage-quantum-1"
        with (stage / "blocks.csv").open() as f:
            self.assertEqual([int(row["seqno"]) for row in csv.DictReader(f)], [0, 1, 2, 3])
        with (stage / "timeline.csv").open() as f:
            timeline = list(csv.DictReader(f))
        self.assertEqual([row["tx_observed"] for row in timeline[:3]], ["12", "4", ""])
        self.assertEqual(timeline[2][f"{bench.LOAD_CLASS}_tx"], "")
        self.assertEqual(timeline[2]["messages_sent"], "1")

    def test_incomplete_scan_with_no_rows_preserves_proven_delivery_shortfall(self):
        t0 = 1000.0
        records = [SendRecord(0, t0, t0, True, None, "c0")]
        lag = {"first_missing_seqno": 12, "last_scanned_seqno": 11}
        r = run(make(self.out), 1.0, 1, records, [], 0, t0, t0 + 1, lag=lag)
        self.assertTrue(r["below_offered_rate"])
        self.assertIsNone(r["saturated"])
        with (self.out / "stage-quantum-1" / "timeline.csv").open() as f:
            self.assertEqual([row["tx_observed"] for row in csv.DictReader(f)], ["", "", ""])


class CollationStatsTests(unittest.TestCase):
    def test_reads_window_and_stop_reasons(self):
        import json

        from pqbench.chain import collation_stats

        def record(at, tx, size, est, gas, log, wc=0):
            return json.dumps(
                {
                    "@type": "validatorStats.collatedBlock",
                    "block_id": {"workchain": wc},
                    "collated_at": at,
                    "bytes": size,
                    "collated_data_bytes": 33,
                    "cpu_work_time": 0.1,
                    "block_stats": {"transactions": tx},
                    "block_limits": {"bytes": est, "gas": gas, "lt_delta": 5, "limits_log": log},
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            node = Path(tmp) / "node1"
            node.mkdir()
            (node / "session-logs").write_text(
                "\n".join(
                    [
                        record(
                            10,
                            560,
                            1_400_000,
                            1_600_000,
                            4_000_000,
                            "INBOUND_EXT_MESSAGES: block_full bytes 1574120\nNEW_MESSAGES: block_full bytes 1\n",
                        ),
                        record(11, 100, 200_000, 250_000, 800_000, ""),
                        record(
                            12, 50, 100_000, 120_000, 400_000, "INBOUND_EXT_MESSAGES: timeout\n"
                        ),
                        record(11, 9, 9, 9, 9, "", wc=-1),
                        record(99, 1, 1, 1, 1, ""),
                        "not json",
                    ]
                )
                + "\n"
            )
            s = collation_stats(Path(tmp), 5, 20)
        self.assertEqual(s["collations"], 3)
        self.assertEqual(
            s["external_stop_reasons"],
            {"block_full bytes": 1, "none (queue drained)": 1, "timeout": 1},
        )
        self.assertEqual(s["full_blocks"]["count"], 1)
        self.assertEqual(s["full_blocks"]["bytes_median"], 1_400_000)
        self.assertEqual(s["bytes"]["max"], 1_400_000)


class NodeMetricsTests(unittest.TestCase):
    def test_parse_keeps_ingress_and_stderr_loss_series(self):
        page = "\n".join(
            [
                "# HELP x",
                'tos_ext_message_admission_total{outcome="ok"} 7',
                "tos_overlay_broadcast_received_total 3",
                "tos_stderr_log_dropped_total 11",
                "process_resident_memory_bytes 1e9",
                "tos_mempool_size NaN-not-a-number",
            ]
        )
        self.assertEqual(
            bench.parse_metrics(page),
            {
                'tos_ext_message_admission_total{outcome="ok"}': 7.0,
                "tos_overlay_broadcast_received_total": 3.0,
                "tos_stderr_log_dropped_total": 11.0,
            },
        )

    def test_delta_reports_only_changed_series(self):
        before = {"node-1": {"a": 1.0, "b": 5.0}}
        after = {"node-1": {"a": 4.0, "b": 5.0, "c": 2.0}}
        self.assertEqual(bench.metrics_delta(before, after), {"node-1": {"a": 3.0, "c": 2.0}})

    def test_shard_progress_uses_each_nodes_absolute_gauges_from_one_scrape(self):
        before = {
            "validator-1": bench.parse_metrics(
                "tos_masterchain_seqno 140\ntos_shardclient_seqno 139\ntos_external_total 4"
            ),
            "ingress-1": bench.parse_metrics("tos_masterchain_seqno 0\ntos_shardclient_seqno 0"),
        }
        after = {
            "validator-1": bench.parse_metrics(
                "tos_masterchain_seqno 153\ntos_shardclient_seqno 150\ntos_external_total 9"
            ),
            "ingress-1": bench.parse_metrics(
                "tos_masterchain_seqno 153\ntos_shardclient_seqno 119"
            ),
        }
        self.assertEqual(
            bench.shard_progress(after)["validator-1"],
            {"status": "ok", "masterchain_seqno": 153, "shardclient_seqno": 150, "lag_blocks": 3},
        )
        self.assertEqual(bench.shard_progress(before)["validator-1"]["lag_blocks"], 1)
        self.assertEqual(bench.shard_progress(before)["ingress-1"]["lag_blocks"], 0)
        self.assertEqual(bench.shard_progress(after)["ingress-1"]["lag_blocks"], 34)
        self.assertEqual(
            bench.metrics_delta(before, after),
            {"validator-1": {"tos_external_total": 5.0}, "ingress-1": {}},
        )

    def test_unavailable_shard_gauge_and_failed_scrape_report_unknown_lag(self):
        for value in ("", "NaN", "+Inf", "-1", "0.5", "4294967296"):
            with self.subTest(value=value):
                snapshot = bench.parse_metrics(
                    f"tos_masterchain_seqno 153\ntos_shardclient_seqno {value}"
                )
                self.assertEqual(
                    bench.shard_progress({"validator-1": snapshot})["validator-1"],
                    {
                        "status": "missing_gauge",
                        "masterchain_seqno": 153,
                        "shardclient_seqno": None,
                        "lag_blocks": None,
                    },
                )
        self.assertEqual(
            bench.shard_progress({"node-2": None})["node-2"],
            {
                "status": "scrape_failed",
                "masterchain_seqno": None,
                "shardclient_seqno": None,
                "lag_blocks": None,
            },
        )

    def test_a_failed_scrape_is_reported_not_turned_into_counters(self):
        before = {"node-1": None, "node-2": {"a": 1.0}, "node-3": None}
        after = {"node-1": {"a": 9.0}, "node-2": None, "node-3": None}
        self.assertEqual(
            bench.metrics_delta(before, after),
            {
                "node-1": {"scrape_failed": ["before"]},
                "node-2": {"scrape_failed": ["after"]},
                "node-3": {"scrape_failed": ["before", "after"]},
            },
        )

    def test_node_args_append_every_node_arg_after_the_exporter(self):
        extra = ["--celldb-cell-cache-max-size=100000", "--celldb-cache-min-size=0"]
        bench.METRIC_PORTS.pop("node-test", None)
        off = argparse.Namespace(node_arg=extra, metrics_base_port=0)
        self.assertEqual(bench.node_args(off, "node-test"), extra)
        on = argparse.Namespace(node_arg=extra, metrics_base_port=39100)
        with patch.dict(bench.METRIC_PORTS, {"node-test": 39100}):
            args = bench.node_args(on, "node-test")
        self.assertEqual(args[0], "--exporter-address")
        self.assertEqual(args[1], "127.0.0.1:39100")
        self.assertEqual(args[2:], extra)
        bench.METRIC_PORTS.pop("node-test", None)
        none = argparse.Namespace(node_arg=[], metrics_base_port=0)
        self.assertEqual(bench.node_args(none, "node-test"), [])

    def test_a_node_missing_at_one_end_is_a_failure(self):
        self.assertEqual(
            bench.metrics_delta({}, {"node-1": {"a": 2.0}}),
            {"node-1": {"scrape_failed": ["before"]}},
        )


class ScrapeTests(unittest.TestCase):
    """A broken exporter fails only its own node, including a truncated chunked reply."""

    @staticmethod
    def serve(reply: bytes) -> int:
        import socket
        import threading

        listener = socket.create_server(("127.0.0.1", 0))

        def run():
            with listener:
                connection, _ = listener.accept()
                with connection:
                    _ = connection.recv(65536)
                    connection.sendall(reply)

        threading.Thread(target=run, daemon=True).start()
        return listener.getsockname()[1]

    def test_a_truncated_reply_fails_only_its_node(self):
        good = b"tos_ext_message_admission_total 3\n"
        ok_port = self.serve(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (len(good), good)
        )
        cut_port = self.serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"
        )
        saved = dict(bench.METRIC_PORTS)
        bench.METRIC_PORTS.clear()
        bench.METRIC_PORTS.update({"node-ok": ok_port, "node-cut": cut_port})
        try:
            out = bench.scrape_metrics()
        finally:
            bench.METRIC_PORTS.clear()
            bench.METRIC_PORTS.update(saved)
        self.assertEqual(out["node-ok"], {"tos_ext_message_admission_total": 3.0})
        self.assertIsNone(out["node-cut"])


class NodeArgTests(unittest.TestCase):
    def test_default_metrics_cover_all_nodes_and_allow_an_explicit_opt_out(self):
        for options, expected in (
            ([], None),
            (["--metrics-base-port", "40200"], 40200),
            (["--metrics-base-port", "0"], 0),
            (["--node-arg=--exporter-address=127.0.0.1:45678"], 0),
        ):
            with (
                self.subTest(options=options),
                patch.object(sys, "argv", ["bench", "--out", ".", *options]),
            ):
                self.assertEqual(bench.parse_args().metrics_base_port, expected)

    def test_metrics_ports_cover_each_node_and_refuse_an_occupied_address(self):
        nodes = []
        for name in ("validator", "ingress"):
            node = Mock(spec=bench.FullNode)
            node.name = name
            node.transport_ports = (2001, 2002, 2003)
            nodes.append(node)
        ports = bench.metrics_ports(nodes, None)
        self.assertEqual(set(ports), {"validator", "ingress"})
        self.assertEqual(len(set(ports.values())), 2)
        self.assertTrue(all(port > 0 for port in ports.values()))
        self.assertEqual(bench.metrics_ports(nodes, 0), {})
        with socket.create_server(("127.0.0.1", 0)) as other:
            with self.assertRaisesRegex(SystemExit, "cannot bind local metrics port"):
                bench.metrics_ports(nodes, other.getsockname()[1])

    def test_harness_options_cannot_be_forwarded(self):
        self.assertIsNone(bench.node_arg_conflict(["--celldb-cache-min-size=0"], 39100))
        self.assertIsNotNone(bench.node_arg_conflict(["--session-logs=x.log"], 0))
        self.assertIsNotNone(bench.node_arg_conflict(["--exporter-address=127.0.0.1:1"], 39100))
        # Without the harness exporter, forwarding one is the caller's choice.
        self.assertIsNone(bench.node_arg_conflict(["--exporter-address=127.0.0.1:1"], 0))


class ProgressSamplingTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_gap_during_the_stage_is_kept_after_the_node_catches_up(self):
        drained = asyncio.Event()
        loop = asyncio.get_running_loop()
        caught_up = {"node-1": {"tos_masterchain_seqno": 12.0, "tos_shardclient_seqno": 12.0}}

        def scrape():
            if drained.is_set():
                return caught_up
            loop.call_soon_threadsafe(drained.set)
            return {"node-1": {"tos_masterchain_seqno": 12.0, "tos_shardclient_seqno": 9.0}}

        with patch.object(bench, "scrape_metrics", side_effect=scrape):
            samples, final = await asyncio.wait_for(bench.sample_node_progress(drained, 0.001), 2)
        self.assertEqual(len(samples), 1)
        self.assertGreater(samples[0]["sampled_at"], 0)
        self.assertEqual(samples[0]["nodes"]["node-1"]["lag_blocks"], 3)
        self.assertEqual(bench.shard_progress(final)["node-1"]["lag_blocks"], 0)


class ChainNowTests(unittest.TestCase):
    """The masterchain time is read from one node, so a lagging node cannot fail it."""

    class Node:
        def __init__(self, applied: int, errors: list[str] | None = None):
            self.applied = applied
            self.errors = list(errors or [])
            self.calls: list[str] = []

        async def call(self, method: str, *args):
            self.calls.append(method)
            if self.errors:
                raise RuntimeError(self.errors.pop(0))
            if method == "get_masterchain_info":
                return SimpleNamespace(last=SimpleNamespace(seqno=self.applied))
            if args[0].seqno > self.applied:
                raise RuntimeError(f"LITE_SERVER_NOTREADY: block {args[0].seqno} is not in db")
            return SimpleNamespace(gen_utime=1000 + args[0].seqno)

    class Pool:
        def __init__(self, *nodes):
            self.nodes, self.i = nodes, 0

        def pick(self):
            node = self.nodes[self.i % len(self.nodes)]
            self.i += 1
            return node

    def now(self, pool, **kw) -> int:
        return asyncio.run(chain.chain_now(cast(chain.ClientPool, pool), pause=0, **kw))

    def test_both_reads_go_to_one_node(self):
        ahead, behind = self.Node(2258), self.Node(2257)
        self.assertEqual(self.now(self.Pool(ahead, behind)), 3258)
        self.assertEqual(behind.calls, [])

    def test_notready_is_retried_and_other_errors_are_raised(self):
        flaky = self.Node(5, ["LITE_SERVER_NOTREADY: not in db", "LITE_SERVER_NOTREADY: not in db"])
        self.assertEqual(self.now(self.Pool(flaky)), 1005)
        with self.assertRaises(RuntimeError):
            self.now(self.Pool(self.Node(5, ["LITE_SERVER_UNKNOWN: boom"])))
        with self.assertRaises(RuntimeError):
            self.now(self.Pool(self.Node(5, ["LITE_SERVER_NOTREADY: x"] * 3)), attempts=3)


if __name__ == "__main__":
    unittest.main()
