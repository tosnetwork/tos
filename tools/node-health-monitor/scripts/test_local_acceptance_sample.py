"""Sensitivity checks for the local acceptance instrument's trust boundary."""

import base64
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "local_acceptance_sample", Path(__file__).with_name("local-acceptance-sample.py")
)
sample = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sample)


def valid_block():
    digest = base64.b64encode(bytes(32)).decode()
    return {
        "workchain": -1,
        "shard": "-9223372036854775808",
        "seqno": 2,
        "root_hash": digest,
        "file_hash": digest,
    }


class InstrumentTrustBoundary(unittest.TestCase):
    def test_complete_id_normalizes_only_masterchain(self):
        block = valid_block()
        self.assertEqual(sample.block_id(block)["shard"], "9223372036854775808")
        block["shard"] = "1"
        with self.assertRaisesRegex(ValueError, "masterchain shard"):
            sample.block_id(block)

    def test_boolean_and_overflow_are_not_block_heights(self):
        for value in (True, -1, 2**32):
            block = valid_block()
            block["seqno"] = value
            with self.assertRaisesRegex(ValueError, "block seqno"):
                sample.block_id(block)

    def test_short_digest_is_not_complete_identity(self):
        block = valid_block()
        block["root_hash"] = base64.b64encode(bytes(31)).decode()
        with self.assertRaisesRegex(ValueError, "block digest length"):
            sample.block_id(block)

    def test_capture_boundary_rejects_one_extra_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "field"
            path.write_bytes(b"a" * 16)
            self.assertEqual(sample.bounded_text(path, 16), "a" * 16)
            path.write_bytes(b"a" * 17)
            with self.assertRaisesRegex(ValueError, "instrument file overflow"):
                sample.bounded_text(path, 16)


if __name__ == "__main__":
    unittest.main()
