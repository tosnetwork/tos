import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import x02_partial_adapter as adapter
import x02_partial_sequence as selection


class Ledger:
    def __init__(self):
        self.rows = []

    def append(self, row):
        self.rows.append(row)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.endpoints = {}
        for ordinal, direction in enumerate(selection.DIRECTIONS):
            self.endpoints[direction] = ("127.0.0.1", 32000 + ordinal,
                                         "127.0.0.2", 33000 + ordinal)
        self.raw = bytes.fromhex("4500001d00004000401100007f0000017f000002")
        self.raw += struct.pack("!HHHH", 32000, 33000, 9, 0) + b"x"
        self.ledger = Ledger()
        self.engine = adapter.DecisionAdapter(selection.candidate_policy("a" * 40),
                                              self.endpoints, self.ledger)
        self.direction = "node1>node2/adnl"

    def test_decisions_are_persisted_before_submission(self):
        seen = []
        def submit(dropped):
            self.assertEqual(self.ledger.rows[-1]["event"], "intent")
            seen.append(dropped)
        for index in range(4):
            self.engine.decide(self.direction, index, self.raw, submit)
        self.assertEqual(seen, [False, False, False, True])
        self.assertEqual(self.engine.counts[self.direction],
                         {"seen": 4, "submitted_drop": 1, "submitted_accept": 3})
        self.assertEqual([row["event"] for row in self.ledger.rows],
                         ["intent", "verdict_submitted"] * 4)

    def test_submission_failure_retains_pending_and_poisons_adapter(self):
        def fail(dropped):
            raise RuntimeError("backend failure")
        with self.assertRaisesRegex(RuntimeError, "backend failure"):
            self.engine.decide(self.direction, 7, self.raw, fail)
        self.assertIsNotNone(self.engine.pending)
        self.assertEqual(len(self.ledger.rows), 1)
        self.assertEqual(self.engine.counts[self.direction]["seen"], 0)
        with self.assertRaisesRegex(ValueError, "failed or busy"):
            self.engine.decide(self.direction, 8, self.raw, lambda dropped: None)

    def test_invalid_length_fragment_and_non_udp(self):
        variants = [self.raw[:-1], self.raw + b"x"]
        for offset, value in ((6, 0x20), (7, 1), (9, 6)):
            raw = bytearray(self.raw)
            raw[offset] = value
            variants.append(bytes(raw))
        for raw in variants:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                adapter.udp_datagram(raw)

    def test_wrong_endpoint_never_submits(self):
        submitted = []
        with self.assertRaisesRegex(ValueError, "frozen endpoints"):
            self.engine.decide("node1>node2/quic", 0, self.raw, submitted.append)
        self.assertEqual(submitted, [])
        self.assertEqual(self.ledger.rows, [])

    def test_ledger_failure_never_submits(self):
        def fail(row):
            raise OSError("disk full")
        self.ledger.append = fail
        submitted = []
        with self.assertRaisesRegex(OSError, "disk full"):
            self.engine.decide(self.direction, 0, self.raw, submitted.append)
        self.assertEqual(submitted, [])
        self.assertTrue(self.engine.failed)


if __name__ == "__main__":
    unittest.main()
