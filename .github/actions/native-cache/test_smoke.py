"""Regression controls for the real ccache machine-counter interface."""

import unittest
from unittest.mock import patch

import smoke

# Counter names and values observed in the hosted 4.9.1 warm-build failure.
WARM_OUTPUT = """cache_miss\t0
direct_cache_hit\t2
preprocessed_cache_hit\t0
local_storage_hit\t2
files_in_cache\t8
"""


class CacheCounterTests(unittest.TestCase):
    def test_observed_warm_output_passes(self):
        self.assertEqual(smoke.require_restored_hits(smoke.parse_stats(WARM_OUTPUT)), 2)

    def test_stats_reads_the_machine_interface(self):
        env = {"CCACHE_DIR": "/test-only/objects"}
        with patch.object(smoke, "run", return_value=WARM_OUTPUT) as command:
            self.assertEqual(smoke.stats(env)["direct_cache_hit"], 2)
        command.assert_called_once_with(["ccache", "--print-stats"], env)

    def test_preprocessed_hits_count_as_real_reuse(self):
        counters = smoke.parse_stats(WARM_OUTPUT)
        counters.update(direct_cache_hit=1, preprocessed_cache_hit=1)
        self.assertEqual(smoke.require_restored_hits(counters), 2)

    def test_missing_counters_are_not_silently_zero(self):
        for key in sorted(smoke.REQUIRED_COUNTERS):
            with self.subTest(key=key):
                output = "\n".join(
                    line for line in WARM_OUTPUT.splitlines() if not line.startswith(key + "\t")
                )
                with self.assertRaisesRegex(RuntimeError, "Missing required ccache counters"):
                    smoke.parse_stats(output)
                counters = smoke.parse_stats(WARM_OUTPUT)
                del counters[key]
                with self.assertRaisesRegex(RuntimeError, "Missing required ccache counters"):
                    smoke.require_restored_hits(counters)

    def test_incorrect_old_counter_names_are_refused(self):
        output = WARM_OUTPUT.replace("direct_cache_hit", "cache_hit_direct").replace(
            "preprocessed_cache_hit", "cache_hit_preprocessed"
        )
        with self.assertRaisesRegex(RuntimeError, "Missing required ccache counters"):
            smoke.parse_stats(output)

    def test_zero_or_one_hit_still_fails(self):
        for hits in (0, 1):
            with self.subTest(hits=hits):
                counters = smoke.parse_stats(WARM_OUTPUT)
                counters["direct_cache_hit"] = hits
                with self.assertRaisesRegex(RuntimeError, "did not reuse both compilations"):
                    smoke.require_restored_hits(counters)

    def test_a_warm_miss_still_fails(self):
        counters = smoke.parse_stats(WARM_OUTPUT)
        counters["cache_miss"] = 1
        with self.assertRaisesRegex(RuntimeError, "did not reuse both compilations"):
            smoke.require_restored_hits(counters)

    def test_duplicate_counters_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, "Duplicate ccache counter"):
            smoke.parse_stats(WARM_OUTPUT + "cache_miss\t0\n")

    def test_malformed_and_negative_values_are_refused(self):
        for suffix in ("broken", "broken 1 2", "broken NaN", "broken -1"):
            with self.subTest(suffix=suffix), self.assertRaises(RuntimeError):
                smoke.parse_stats(WARM_OUTPUT + suffix + "\n")

    def test_empty_output_is_not_evidence(self):
        with self.assertRaisesRegex(RuntimeError, "Missing required ccache counters"):
            smoke.parse_stats("")

    def test_additional_counters_remain_forward_compatible(self):
        counters = smoke.parse_stats(WARM_OUTPUT + "future_counter\t9\n")
        self.assertEqual(counters["future_counter"], 9)
        self.assertEqual(smoke.require_restored_hits(counters), 2)


if __name__ == "__main__":
    unittest.main()
