"""Startup readiness of the N6 cluster's lite polling.

A starting liteserver refuses every query with exactly `LITE_SERVER_NOTREADY: node not
synced` (code 500) until its validator manager has started. `_wait_all_heights` waits for
that refusal to clear within its own deadline; every other error keeps its behaviour, and
no node ever has two queries in flight. Set N6_CLUSTER_PATH to run the same checks against
another n6_cluster.py (the old-red control).
"""

import asyncio
import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = Path(os.environ.get("N6_CLUSTER_PATH", ROOT / "test/tostester/src/tostester/n6_cluster.py"))
spec = importlib.util.spec_from_file_location("n6_cluster_under_test", PATH)
n6 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = n6
spec.loader.exec_module(n6)

NOT_SYNCED = "LITE_SERVER_NOTREADY: node not synced"


class ToslibError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message

    def __str__(self):
        return self.message


ToslibError.__module__ = "toslib.toslibjson"
ToslibError.__qualname__ = "ToslibError"


class Info:
    def __init__(self, seqno):
        self.last = type("Last", (), {"seqno": seqno})()


class Client:
    """Answers from a script: an exception to raise, or a height to report."""

    def __init__(self, script, tail, delay=0.01):
        self.script, self.tail, self.calls, self.inflight, self.peak = list(script), tail, 0, 0, 0
        self.delay = delay

    async def get_masterchain_info(self):
        self.calls += 1
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        try:
            await asyncio.sleep(self.delay)
            step = self.script.pop(0) if self.script else self.tail
            if isinstance(step, BaseException):
                raise step
            return Info(step)
        finally:
            self.inflight -= 1


class Node:
    def __init__(self, name, script, tail=5, delay=0.01):
        self.name, self.client = name, Client(script, tail, delay)

    async def toslib_client(self):
        return self.client


def run(coro):
    return asyncio.run(coro)


def wait(nodes, timeout=3.0):
    return n6._wait_all_heights(nodes, 3, timeout, transport_retry_counts={n.name: {} for n in nodes},
                                transport_retry_budget_seconds=2.0, transport_retry_delay_seconds=0.01)


class StartupNotSynced(unittest.TestCase):
    def test_transient_not_synced_clears_then_heights_are_returned(self):
        nodes = [Node("a", [ToslibError(500, NOT_SYNCED)] * 3), Node("b", [])]
        self.assertEqual(run(wait(nodes)), [5, 5])

    def test_persistent_not_synced_fails_at_the_startup_deadline(self):
        nodes = [Node("a", [], tail=None), Node("b", [])]
        nodes[0].client.tail = ToslibError(500, NOT_SYNCED)
        with self.assertRaisesRegex(TimeoutError, "still refusing: LITE_SERVER_NOTREADY: node not synced"):
            run(wait(nodes, timeout=0.6))

    def test_other_code_500_error_is_raised_at_once(self):
        nodes = [Node("a", [ToslibError(500, "LITE_SERVER_UNKNOWN: boom")])]
        with self.assertRaisesRegex(ToslibError, "LITE_SERVER_UNKNOWN"):
            run(wait(nodes))
        self.assertEqual(nodes[0].client.calls, 1)

    def test_another_notready_reason_is_raised_at_once(self):
        nodes = [Node("a", [ToslibError(500, "LITE_SERVER_NOTREADY: block is not applied")])]
        with self.assertRaisesRegex(ToslibError, "block is not applied"):
            run(wait(nodes))

    def test_not_synced_with_another_code_is_raised_at_once(self):
        nodes = [Node("a", [ToslibError(651, NOT_SYNCED)])]
        with self.assertRaises(ToslibError):
            run(wait(nodes))

    def test_network_errors_keep_the_transport_retry_and_its_count(self):
        nodes = [Node("a", [ToslibError(500, "LITE_SERVER_NETWORKconn not ready")] * 2)]
        counts = {"a": {}}
        result = run(n6._wait_all_heights(nodes, 3, 3.0, transport_retry_counts=counts,
                                          transport_retry_budget_seconds=2.0, transport_retry_delay_seconds=0.01))
        self.assertEqual((result, counts["a"]["get_masterchain_info"]), ([5], 2))

    def test_sustained_polling_still_raises_not_synced(self):
        clients = {"a": Client([ToslibError(500, NOT_SYNCED)], 5)}
        with self.assertRaisesRegex(ToslibError, "node not synced"):
            run(n6._masterchain_heights(clients))

    def test_no_node_ever_has_two_queries_in_flight(self):
        # slower than the startup retry delay, so an orphaned query would still be in flight
        slow = Node("slow", [], tail=5, delay=0.4)
        nodes = [Node("a", [ToslibError(500, NOT_SYNCED)] * 4), slow]
        run(wait(nodes))
        self.assertEqual((nodes[0].client.peak, slow.client.peak), (1, 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
