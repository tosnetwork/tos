"""Actual native configuration snapshots and pre-allocation version admission."""

# ruff: noqa: E402
import argparse
import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "test/falcon-auth"))
from account_limit_context import configuration as account_configuration
from linked_roots import Capture, CaptureEmulator, configuration
from native import from_boc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    args = parser.parse_args()
    os.environ["EMULATOR_PATH"] = str(args.emulator.resolve())
    fields = (
        (args.artifacts / "account-limit-v16-roots.tsv").read_text().splitlines()[1].split("\t")
    )
    supplied = account_configuration(16)
    expected = supplied.hash.hex()
    supplied.__dict__.update(hash=b"untrusted cache", depth=700)
    emulator = CaptureEmulator.from_config(supplied)
    try:
        assert emulator.version == 16 and emulator._configuration_hash == expected
        default = configuration().refs[0]
        supplied.bits, supplied.refs = default.bits, list(default.refs)
        emulator.configuration.bits, emulator.configuration.refs = default.bits, list(default.refs)
        emulator.lt = int(fields[2]) - 1_000_000
        original, message = from_boc(bytes.fromhex(fields[3])), from_boc(bytes.fromhex(fields[4]))
        result = emulator.send(original, message)
        assert result["success"] and result["details"]["action"]["code"] == 50
        assert emulator.last_capture[4] == expected
        try:
            Capture.from_send(fields[0], original, message, emulator, result, "")
        except AssertionError as error:
            assert "unexpected linked configuration" in str(error)
        else:
            raise AssertionError("custom config admitted as default family")
        Capture.from_send(
            fields[0], original, message, emulator, result, "", family="account-limit-v16"
        )
    finally:
        emulator.close()
    historical = CaptureEmulator.from_config(account_configuration(12))
    try:
        assert historical.version == 12
    finally:
        historical.close()
    with (
        patch("linked_roots.config", return_value=account_configuration(12)),
        patch.object(CaptureEmulator, "_initialize") as allocate,
    ):
        try:
            CaptureEmulator(16)
        except AssertionError as error:
            assert "capture configuration version mismatch" in str(error)
        else:
            raise AssertionError("declared version overrode actual CP8")
        allocate.assert_not_called()
    print(
        "PASS: actual custom config survives caller/cache mutation; defaults refuse it; CP8 version checked before native allocation"
    )


if __name__ == "__main__":
    main()
