"""Selection controls; these synthetic rows do not demonstrate live loss."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import x02_partial_sequence as partial


class PartialSequenceTests(unittest.TestCase):
    def setUp(self):
        self.policy = partial.candidate_policy("535214d5836c5f09f45975689acb8daf8c37c7ae")
        # Independent literal vectors: seed=1, direction ordinal modulo four.
        self.rows = [{"direction": direction, "index": index,
                      "packet_sha256": "a" * 64,
                      "dropped": index % 4 == (3, 2, 1, 0)[ordinal % 4]}
                     for ordinal, direction in enumerate(partial.DIRECTIONS)
                     for index in range(8)]

    def test_literal_vectors_and_scope(self):
        result = partial.verify_selection_trace(self.policy, self.rows)
        self.assertEqual(len(result["counts"]), 24)
        self.assertTrue(all(row == {"seen": 8, "dropped": 2, "passed": 6}
                            for row in result["counts"].values()))
        self.assertIs(result["live_packet_hits_verified"], False)
        self.assertIs(result["chain_thresholds_verified"], False)

    def test_wrong_seed_rate_threshold_and_halt_claim(self):
        for field, value in (("seed_hex", "0" * 32),
                             ("rate", {"numerator": 1, "denominator": 2}),
                             ("halt_claim", True), ("chain_thresholds", {})):
            policy = copy.deepcopy(self.policy)
            policy[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "differs"):
                partial.validate_policy(policy)

    def test_missing_quic_or_empty_direction(self):
        rows = [row for row in self.rows if not row["direction"].endswith("/quic")]
        with self.assertRaisesRegex(ValueError, "insufficient per-direction"):
            partial.verify_selection_trace(self.policy, rows)

    def test_decision_tampering_and_total_drop(self):
        for index in (0, 3):
            rows = copy.deepcopy(self.rows)
            rows[index]["dropped"] = not rows[index]["dropped"]
            with self.assertRaisesRegex(ValueError, "decision differs"):
                partial.verify_selection_trace(self.policy, rows)
        rows = copy.deepcopy(self.rows)
        for row in rows:
            row["dropped"] = True
        with self.assertRaisesRegex(ValueError, "decision differs"):
            partial.verify_selection_trace(self.policy, rows)

    def test_index_reset_skip_and_boolean(self):
        for value in (0, 2, True):
            rows = copy.deepcopy(self.rows)
            rows[1]["index"] = value
            with self.assertRaisesRegex(ValueError, "sequence"):
                partial.verify_selection_trace(self.policy, rows)

    def test_missing_packet_digest(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["packet_sha256"] = ""
        with self.assertRaisesRegex(ValueError, "digest"):
            partial.verify_selection_trace(self.policy, rows)


if __name__ == "__main__":
    unittest.main()
