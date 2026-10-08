"""Sensitivity controls for matching structural-parser verdicts and message roots."""

import inspect
import unittest

import ingress_fixture_probe as probe


class IngressFixtureControls(unittest.TestCase):
    def test_message_root_substitution_is_not_a_parse_success(self):
        expected = [{"name": "fixture", "status": "ok", "reason": "", "root": "ab" * 32}]
        row = "fixture\tok\t-\t" + "ab" * 32 + "\t100,200"
        self.assertEqual(probe.check(row, expected, 2)[0]["median_ns"], 150)
        changed = row.replace("ab" * 32, "cd" * 32)
        with self.assertRaisesRegex(ValueError, "different message root"):
            probe.check(changed, expected, 2)
        source = inspect.getsource(probe.check)
        guard = 'if root != case["root"]:'
        self.assertEqual(source.count(guard), 1)
        namespace = dict(probe.__dict__)
        exec(source.replace(guard, "if False:"), namespace)
        namespace["check"](changed, expected, 2)

    def test_boundary_verdict_and_samples_are_required(self):
        reason = "external message is too deep"
        expected = [{"name": "deep", "status": "reject", "reason": reason, "root": "-"}]
        row = f"deep\treject\t{reason.encode().hex()}\t-\t100"
        probe.check(row, expected, 1)
        with self.assertRaisesRegex(ValueError, "parser boundary mismatch"):
            probe.check("deep\tok\t-\t-\t100", expected, 1)
        with self.assertRaisesRegex(ValueError, "missing parser timings"):
            probe.check(row, expected, 2)
        with self.assertRaisesRegex(ValueError, "missing parser results"):
            probe.check("", expected, 1)


if __name__ == "__main__":
    unittest.main()
