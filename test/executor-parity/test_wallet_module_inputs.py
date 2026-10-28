"""Constructor context, bounded public input parsing and scoped replay controls."""

import base64
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import wallet_module_roots as roots
from cells import Cell, make_dict, read_dict
from test_auth_policy import policy


class WalletModuleInputTests(unittest.TestCase):
    def test_bounded_file_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            with path.open("wb") as stream:
                stream.truncate(roots.MAX_BYTES + 1)
            with self.assertRaisesRegex(AssertionError, "file size limit"):
                roots.read(path)
            path.unlink()
            path.symlink_to(roots.DATA / "wallet-module-inputs.json")
            with self.assertRaisesRegex(AssertionError, "invalid wallet-module file"):
                roots.read(path)

    def test_fixture_hash_not_just_schema(self):
        original = roots.read

        def changed(path):
            return original(path) + b" "

        with (
            patch.object(roots, "read", changed),
            self.assertRaisesRegex(AssertionError, "fixture identity"),
        ):
            roots.fixtures()

    def test_json_depth_and_duplicate_keys(self):
        for value in (b"[" * 2000 + b"]" * 2000, b'{"x":1,"x":2}'):
            with self.assertRaises(AssertionError):
                roots.json_value(value)

    def test_bit_width_padding_and_index_types(self):
        self.assertEqual(roots.decode_bits(dict(width=3, hex="5")), "101")
        for value in (
            dict(width=True, hex="1"),
            dict(width=1024, hex="0" * 256),
            dict(width=1, hex="f"),
            dict(width=1, hex="01"),
            dict(width=0, hex="0"),
        ):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                roots.decode_bits(value)

    def test_signature_limits_before_chain_allocation(self):
        for value, key, encoded in (
            ("00", "primary", False),
            ("?" * 3228, "primary", True),
            ("00" * 2420, "rescue", False),
            ("00" * 2420, "unknown", False),
        ):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                roots.signature(value, key, encoded=encoded)

    def test_line_endings_are_not_normalized(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rows"
            for raw in (b"row", b"row\r\n"):
                path.write_bytes(raw)
                with self.assertRaisesRegex(AssertionError, "line endings"):
                    roots.lines(path)
            path.write_bytes(b"row\n")
            self.assertEqual(roots.lines(path), ["row"])

    def diagnostic_config(self):
        entries = read_dict(roots.native.config(16), 32)
        entries[48] = Cell().ref(policy(network=123))
        result = make_dict(entries, 32)
        self.assertEqual(
            result.hash.hex(), roots.fixtures()[0]["modes"]["diagnostic"]["groups"][0]["dictionary"]
        )
        return result

    def test_dynamic_constructor_and_factory_before_native_allocation(self):
        configuration = self.diagnostic_config()
        allocated, timed = [], []

        def initialize(emulator, actual, verbosity):
            allocated.append((actual.boc(), verbosity))
            emulator.ptr = None
            emulator.lib = Mock()

        def time(emulator, now):
            timed.append(now)
            emulator.now = now

        recording = roots.recording_emulator("diagnostic")
        with (
            patch.object(roots.CaptureEmulator, "_initialize", initialize),
            patch.object(roots.CaptureEmulator, "set_time", time),
            patch.object(roots.native, "NOW", 1780000000),
        ):
            with patch.object(roots.native, "config", return_value=configuration) as provider:
                first = recording(16, None, 7)
                provider.assert_called_once_with(16, None)
            with patch.object(
                roots.native, "config", side_effect=AssertionError("factory synthesized config")
            ):
                second = recording.from_config(configuration, 3)
        self.assertEqual(allocated, [(configuration.boc(), 7), (configuration.boc(), 3)])
        self.assertEqual(timed, [1780000000, 1780000000])
        self.assertEqual((first.now, second.now), (1780000000, 1780000000))
        self.assertIsNot(first.configuration, configuration)

    def test_wrong_time_and_config_never_allocate_native(self):
        configuration = self.diagnostic_config()
        recording = roots.recording_emulator("diagnostic")
        with patch.object(roots.CaptureEmulator, "_initialize") as allocate:
            with (
                patch.object(roots.native, "NOW", 1),
                self.assertRaisesRegex(AssertionError, "dynamic time"),
            ):
                recording.from_config(configuration)
            with self.assertRaisesRegex(AssertionError, "capture configuration"):
                recording.from_config(Cell())
            allocate.assert_not_called()

    def test_replay_consumption_and_restoration(self):
        import native_signer_fixture

        original = native_signer_fixture.NativeSignerFixture.invoke
        signer = native_signer_fixture.NativeSignerFixture(Path("unused"))
        profile = roots.fixtures()[0]
        with roots.SignatureReplay("diagnostic"):
            for row in profile["modes"]["diagnostic"]["calls"]:
                result = signer.invoke(
                    row["key"],
                    row["purpose"],
                    bytes.fromhex(row["digest"]),
                    base64.b64decode(profile["public_keys"][row["key"]]),
                )
                self.assertEqual(len(result), 2420 if row["key"] == "primary" else 7856)
            with self.assertRaisesRegex(AssertionError, "replay exhausted"):
                signer.invoke("primary", "auth", b"", b"")
        self.assertIs(native_signer_fixture.NativeSignerFixture.invoke, original)
        roots.calls(signer.calls, "diagnostic", recorded=True)

    def test_replay_unknown_request_and_exceptions_restore_provider(self):
        import native_signer_fixture

        original = native_signer_fixture.NativeSignerFixture.invoke
        signer = native_signer_fixture.NativeSignerFixture(Path("unused"))
        for key, purpose, digest, public, diagnostic in (
            ("unknown", "auth", b"", b"", "request drift"),
            ("primary", "unknown", b"", b"", "request drift"),
        ):
            with self.assertRaisesRegex(AssertionError, diagnostic):
                with roots.SignatureReplay("diagnostic"):
                    signer.invoke(key, purpose, digest, public)
            self.assertIs(native_signer_fixture.NativeSignerFixture.invoke, original)
        with self.assertRaisesRegex(RuntimeError, "original failure"):
            with roots.SignatureReplay("diagnostic"):
                raise RuntimeError("original failure")
        self.assertIs(native_signer_fixture.NativeSignerFixture.invoke, original)
        with self.assertRaisesRegex(AssertionError, "unused calls"):
            with roots.SignatureReplay("diagnostic"):
                pass
        self.assertIs(native_signer_fixture.NativeSignerFixture.invoke, original)

    def test_replay_wrong_public_key(self):
        import native_signer_fixture

        row = roots.fixtures()[0]["modes"]["diagnostic"]["calls"][0]
        signer = native_signer_fixture.NativeSignerFixture(Path("unused"))
        with self.assertRaisesRegex(AssertionError, "replay public key"):
            with roots.SignatureReplay("diagnostic"):
                signer.invoke(
                    row["key"], row["purpose"], bytes.fromhex(row["digest"]), b"incorrect"
                )

    def test_relay_requires_earlier_unique_matching_output(self):
        rule = dict(kind="relay", bits=dict(width=0, hex=""), refs=0, prior=0)
        message = Cell()
        roots.bind_message(message, rule, [], [[Cell()]])
        for prior, validated, diagnostic in (
            (0, [], "relay order"),
            (True, [[Cell()]], "relay order"),
            (0, [[]], "relay message"),
            (0, [[Cell(), Cell()]], "relay message"),
            (0, [[Cell().uint(1, 1)]], "relay message"),
        ):
            with self.subTest(prior=prior), self.assertRaisesRegex(AssertionError, diagnostic):
                roots.bind_message(message, dict(rule, prior=prior), [], validated)

    def test_direct_unsigned_request_is_checked(self):
        # A structurally valid message with real fixed signature material, but
        # its claimed unsigned request belongs to another message.
        profile, replay = roots.fixtures()
        rule = copy.deepcopy(profile["modes"]["diagnostic"]["groups"][0]["rows"][0]["message"])
        signatures = [
            roots.signature(row["signature"], row["key"], encoded=True)
            for row in replay["modes"]["diagnostic"]
        ]
        body = Cell(
            bits=roots.decode_bits(rule["body_bits"]), refs=[Cell(), roots.chain(signatures[0])]
        )
        message = Cell(bits=roots.decode_bits(rule["bits"]), refs=[body])
        with self.assertRaisesRegex(AssertionError, "unsigned request"):
            roots.bind_message(message, rule, signatures, [])


if __name__ == "__main__":
    unittest.main()
