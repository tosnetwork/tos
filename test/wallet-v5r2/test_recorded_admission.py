"""Configuration-preservation controls for exact recorded admission replay."""

import unittest
from pathlib import Path
from unittest.mock import patch

import recorded_admission as admission
from cells import Cell, make_dict, read_dict


def prices(credit, constructor=0xDE, flat=True):
    result = Cell()
    if flat:
        result.uint(0xD1, 8).uint(100, 64).uint(667, 64)
    result.uint(constructor, 8).uint(436907, 64).uint(30000000, 64)
    if constructor == 0xDE:
        result.uint(30000000, 64)
    return result.uint(credit, 64).uint(60000000, 64).uint(100000000, 64).uint(1000000000, 64)


def config(version=18, credit=20000, constructor=0xDE, flat=True):
    entries = {
        8: Cell().ref(Cell().uint(0xC4, 8).uint(version, 32).uint(0x1EE, 64)),
        19: Cell().ref(Cell().sint(-239, 32)),
        20: Cell().ref(prices(10000)),
        21: Cell().ref(prices(credit, constructor, flat)),
        48: Cell().ref(Cell().uint(0xA1, 8).uint(123, 256)),
    }
    return Cell().uint(42, 256).ref(make_dict(entries, 32))


class RecordedAdmissionControls(unittest.TestCase):
    def test_credit_probe_preserves_every_other_field_and_parameter(self):
        for constructor in (0xDD, 0xDE):
            for flat in (False, True):
                root = config(constructor=constructor, flat=flat)
                before = read_dict(root.refs[0], 32)
                for amount in (0, 10000, 15499, 15500, 20000):
                    changed = admission.configuration(root, amount)
                    after = read_dict(changed.refs[0], 32)
                    actual, offset = admission.gas_credit(after[21].refs[0])
                    self.assertEqual(actual, amount)
                    self.assertEqual(root.bits, changed.bits)
                    self.assertEqual(set(before), set(after))
                    for key in before:
                        if key != 21:
                            self.assertEqual(before[key].hash, after[key].hash)
                    original = before[21].refs[0].bits
                    replacement = after[21].refs[0].bits
                    self.assertEqual(original[:offset], replacement[:offset])
                    self.assertEqual(original[offset + 64 :], replacement[offset + 64 :])
                self.assertIs(admission.configuration(root, 20000), root)

    def test_probe_uses_supplied_credit_as_upper_bound(self):
        root = config(credit=24000)
        self.assertIs(admission.configuration(root, 24000), root)
        self.assertEqual(
            admission.config_profile(admission.configuration(root, 22000))["basechain_credit"],
            22000,
        )
        with self.assertRaisesRegex(AssertionError, "probe cannot increase configured credit"):
            admission.configuration(config(credit=16000), 20000)

    def test_profile_reads_configuration_version(self):
        for version in (17, 18, 19):
            self.assertEqual(
                admission.config_profile(config(version=version)),
                {
                    "global_version": version,
                    "basechain_credit": 20000,
                    "masterchain_credit": 10000,
                },
            )

    def test_release_config_requires_exact_original_bytes(self):
        root = config()
        profile = admission.config_profile(root)
        admission.require_release_config(root.boc(), root.boc(), profile)
        with self.assertRaisesRegex(AssertionError, "differs from frozen release input"):
            admission.require_release_config(root.boc(), config(version=17).boc(), profile)

    def test_release_profile_refuses_legacy_or_relaxed_values(self):
        for version, credit in ((17, 20000), (18, 10000), (18, 24000)):
            root = config(version=version, credit=credit)
            with self.assertRaisesRegex(AssertionError, "unexpected release admission profile"):
                admission.require_release_config(
                    root.boc(), root.boc(), admission.config_profile(root)
                )

    def test_price_parser_rejects_trailing_or_unknown_fields(self):
        valid = prices(20000)
        for invalid in (
            Cell(bits=valid.bits + "0"),
            Cell(bits=valid.bits, refs=[Cell()]),
            Cell(bits=format(0xDF, "08b") + prices(20000, flat=False).bits[8:]),
        ):
            with self.assertRaises(AssertionError):
                admission.gas_credit(invalid)

    def test_guard_deletions_fail_their_required_assertions(self):
        source = Path(admission.__file__).read_text()
        controls = [
            (
                'assert raw == release_raw, "recorded configuration differs from frozen release input"',
                "pass",
                "require_release_config",
                "test_release_config_requires_exact_original_bytes",
            ),
            (
                'assert 0 <= amount <= original_credit, "probe cannot increase configured credit"',
                "pass",
                "configuration",
                "test_probe_uses_supplied_credit_as_upper_bound",
            ),
            (
                "global_version = version.uint(32)",
                "version.uint(32)\n    global_version = 17",
                "config_profile",
                "test_profile_reads_configuration_version",
            ),
        ]
        for anchor, replacement, function, test in controls:
            self.assertEqual(source.count(anchor), 1)
            namespace = {"__name__": "recorded_admission_mutant"}
            exec(
                compile(source.replace(anchor, replacement), admission.__file__, "exec"), namespace
            )
            with patch.object(admission, function, namespace[function]):
                result = unittest.TestResult()
                RecordedAdmissionControls(test).run(result)
            self.assertEqual(len(result.failures), 1, (function, result.errors))
            self.assertFalse(result.errors, "control must fail semantically, not during setup")


if __name__ == "__main__":
    unittest.main()
