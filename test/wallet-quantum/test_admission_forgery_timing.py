"""Controls for invalid-signature admission measurement and result validation."""

import inspect
import unittest

import admission_forgery_timing as probe


class ForgeryControls(unittest.TestCase):
    def test_forgery_preserves_envelope_intent_and_signature_profile(self):
        original = bytes((i % 256 for i in range(2832)))
        intent = probe.Cell().uint(123, 32)
        body = probe.Cell().ref(intent).ref(probe.chain(original))
        message = probe.Cell().uint(8, 4).ref(body)
        hashes = set()
        for mode, start in [("randomizer", 12), ("last_path_node", 2800)]:
            for index in range(16):
                changed = probe.forge(message, index, mode)
                self.assertEqual(changed.bits, message.bits)
                self.assertEqual(changed.refs[0].refs[0].hash, intent.hash)
                signature = probe.signature_bytes(changed.refs[0].refs[1])
                self.assertEqual(signature[:start], original[:start])
                self.assertEqual(signature[start + 32 :], original[start + 32 :])
                self.assertNotEqual(signature[start : start + 32], original[start : start + 32])
                hashes.add(changed.hash)
        self.assertEqual(len(hashes), 32)
        with self.assertRaisesRegex(ValueError, "fixed H20"):
            probe.signature_bytes(probe.chain(original[:-1]))

    def test_changed_rejection_is_detected_and_guard_deletion_admits_it(self):
        name = "class-1-randomizer-000"
        correct = f"{name}\t2007\t0\t-\t-"
        probe.validate_rows(correct, [name], 20000)
        changed = correct.replace("2007", "2012")
        with self.assertRaisesRegex(ValueError, "unexpected admission outcome"):
            probe.validate_rows(changed, [name], 20000)
        source = inspect.getsource(probe.validate_rows)
        guard = "if fields[1] != expected:"
        self.assertEqual(source.count(guard), 1)
        namespace = {}
        exec(source.replace(guard, "if False:"), namespace)
        namespace["validate_rows"](changed, [name], 20000)
        probe.validate_rows(correct.replace("2007", "-14"), [name], 10000)
        with self.assertRaisesRegex(ValueError, "missing replay"):
            probe.validate_rows("", [name], 20000)


if __name__ == "__main__":
    unittest.main()
