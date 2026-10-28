"""Original auth and ML-DSA factories with full v16 input/root observation.

The factories and their assertions run unchanged. Historical versions stay in the
native call ledger; only v16 is replayed in the Rust driver. Current source uses
native helper defaults for seed/libraries/previous blocks/signature policy. An
unexpected later setter is refused rather than silently dropping its context.
"""

# ruff: noqa: E402
import argparse
import hashlib
import inspect
import json
import runpy
import sys
import unittest
import weakref
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / p)
    for p in (
        "test/auth-extensions",
        "test/falcon-auth",
        "test/mldsa-auth",
        "test/rel02",
    )
]
import native
from cells import Cell, from_boc, read_dict
from linked_roots import Capture
from transaction_roots import compare, expected_row

MAX_CALLS = 10_000
MAX_BYTES = 64 * 1024 * 1024
SOURCES = {
    "auth": "test/auth-extensions/test_auth.py",
    "mldsa": "test/mldsa-auth/e2e.py",
}

PROFILE = ROOT / "test/executor-parity/data/auth-factory-inputs.json"
PROFILE_SHA256 = "836d582900ce9e3c94570c50c15429a9a33da18bf23f7cb5a48dbfcdf546de30"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def producer_sources(family):
    names = {SOURCES[family], "test/auth-extensions/native.py", "test/auth-extensions/cells.py"}
    if family == "mldsa":
        names.update(
            {
                "test/auth-extensions/test_auth.py",
                "test/mldsa-auth/protocol.py",
                "test/mldsa-auth/build_contracts.py",
            }
        )
    return {name: digest((ROOT / name).read_bytes()) for name in sorted(names)}


def validate_profile(family, profile, raw=None):
    assert family in SOURCES, "unknown auth factory"
    if raw is None:
        with PROFILE.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
    assert len(raw) <= 1024 * 1024, "auth frozen profile byte limit"
    assert digest(raw) == PROFILE_SHA256, "auth frozen profile source digest"
    frozen = json.loads(raw)
    assert set(frozen) == set(SOURCES), "auth frozen family population"
    assert profile == frozen[family], "auth original case/input/context/outcome population changed"


class ObservedTimeSetter:
    """Delegate the exact function and ctypes metadata; observe successful calls."""

    def __init__(self, function, owner):
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "owner", weakref.ref(owner))

    def __getattr__(self, name):
        return getattr(self.function, name)

    def __setattr__(self, name, value):
        setattr(self.function, name, value)

    def __call__(self, pointer, timestamp):
        owner = self.owner()
        assert owner is not None, "time observer outlived its emulator"
        assert pointer == owner.ptr, "time setter used another emulator pointer"
        result = self.function(pointer, timestamp)
        if result:
            owner.capture_now = int(timestamp)
        return result


class ObservedLibrary:
    def __init__(self, library, owner):
        self.library = library
        self.time = ObservedTimeSetter(library.transaction_emulator_set_unixtime, owner)

    def __getattr__(self, name):
        if name == "transaction_emulator_set_unixtime":
            return self.time
        if name.startswith("transaction_emulator_set_") and name != "transaction_emulator_set_lt":
            raise AssertionError(f"unobserved context setter after initialization: {name}")
        return getattr(self.library, name)


def run(family, driver, output, build=None, signer=None, record_profile=None):
    assert not output.exists(), "auth output must be fresh"
    output.mkdir(parents=True)
    original = native.Emulator
    groups, ledger, retained = {}, [], 0
    input_sizes = []

    class Recording(original):
        # Observation belongs inside _initialize, preserving the original test
        # that intentionally mocks this method without allocating a native handle.
        def _initialize(self, configuration, vm_log_verbosity):
            snapshot = from_boc(configuration.boc())
            version = read_dict(snapshot, 32)[8].refs[0].slice()
            assert version.uint(8) == 0xC4, "auth capture configuration tag"
            self.capture_version = version.uint(32)
            self.capture_config = snapshot
            self.capture_now = native.NOW
            super()._initialize(configuration, vm_log_verbosity)
            self.lib = ObservedLibrary(self.lib, self)

        def send(self, shard, message):
            nonlocal retained
            assert len(ledger) < MAX_CALLS, "auth native call limit"
            original_shard, inbound = shard.boc().hex(), message.boc().hex()
            result = super().send(shard, message)
            frame = inspect.currentframe()
            try:
                while frame and not frame.f_code.co_name.startswith("test_"):
                    frame = frame.f_back
                case = frame.f_code.co_name if frame else "setup"
            finally:
                del frame
            name = f"{family}-{len(ledger):04d}:{case}"
            oracle = {
                k: result[k]
                for k in (
                    "success",
                    "transaction",
                    "shard_account",
                    "external_not_accepted",
                    "vm_exit_code",
                    "error",
                )
                if k in result
            }
            record = Capture(name, original_shard, inbound, self.lt, self.capture_now, oracle, "")
            line = record.root_input()
            input_sizes.append(
                dict(name=name, version=self.capture_version, bytes=len(line.encode()))
            )
            expected = expected_row(name, oracle, allow_library=True)
            cfg = self.capture_config.hash.hex()
            retained += len(line.encode()) + len(json.dumps(oracle).encode())
            assert retained <= MAX_BYTES, "auth capture byte limit"
            ledger.append(
                dict(
                    name=name,
                    version=self.capture_version,
                    configuration=cfg,
                    input_sha256=digest(line.encode()),
                    expected=expected[1:],
                )
            )
            if self.capture_version == 16:
                if cfg not in groups:
                    fixture = from_boc(
                        (ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes()
                    )
                    groups[cfg] = (Cell(bits=fixture.bits).ref(self.capture_config), [])
                groups[cfg][1].append(record)
            return result

    source = ROOT / SOURCES[family]
    if family == "mldsa":
        # Falcon has same-named protocol/build modules. Use the original
        # factory's module search path, and refuse an existing ambiguous import.
        assert "protocol" not in sys.modules and "build_contracts" not in sys.modules
        sys.path.insert(0, str(ROOT / "test/mldsa-auth"))
    with patch.object(native, "Emulator", Recording):
        namespace = runpy.run_path(str(source), run_name="auth_factory_capture")
        if family == "auth":
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(
                namespace["AuthenticationTests"]
            )
            cases = [t.id().rsplit(".", 1)[-1] for t in suite]
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            assert result.wasSuccessful(), "original authentication assertions failed"
            assert result.testsRun == len(cases), "auth test population changed during execution"
        else:
            assert build and signer, "ML-DSA factory needs native build tools and signer"
            cases = unittest.defaultTestLoader.getTestCaseNames(namespace["MldsaAuthTests"])
            args = [
                str(source),
                "--build",
                str(build),
                "--signer",
                str(signer),
                "--out",
                str(output / "native"),
            ]
            with patch.object(sys, "argv", args):
                assert namespace["main"]() == 0, "original ML-DSA assertions failed"
    assert ledger, "empty auth native call population"
    (output / "input-sizes.json").write_text(json.dumps(input_sizes, indent=2) + "\n")
    profile = dict(
        family=family, producer_sources=producer_sources(family), cases=cases, calls=ledger
    )
    (output / "profile.json").write_text(json.dumps(profile, indent=2) + "\n")
    if record_profile is None:
        validate_profile(family, profile)
    else:
        record_profile.write_text(json.dumps(profile, indent=2) + "\n")
    signatures = []
    for index, (key, (configuration, records)) in enumerate(groups.items()):
        folder = output / f"config-{index:02d}"
        folder.mkdir()
        cfg = folder / "config.boc"
        cfg.write_bytes(configuration.boc())
        compare(
            driver,
            cfg,
            [(r.root_input(), r.native) for r in records],
            folder,
            "auth-factory",
            expected_result=lambda name, result: expected_row(name, result, allow_library=True),
        )
        signatures.append(dict(dictionary=key, calls=len(records)))
    expected_calls = sum(row["version"] == 16 for row in ledger)
    assert expected_calls > 0 and sum(v["calls"] for v in signatures) == expected_calls, (
        "unobserved v16 auth call"
    )
    summary = dict(
        family=family,
        native_tests=len(cases),
        native_calls=len(ledger),
        v16_calls=expected_calls,
        historical_calls=len(ledger) - expected_calls,
        configurations=signatures,
        profile_sha256=digest((output / "profile.json").read_bytes()),
        passed=True,
        frozen_profile=record_profile is None,
        scope="local original-input profile; artifact/hosted gates pending",
    )
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=SOURCES, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--signer", type=Path)
    parser.add_argument(
        "--record-profile", type=Path, help="Author-only candidate profile generation"
    )
    args = parser.parse_args()
    run(
        args.family,
        args.driver.resolve(),
        args.output.resolve(),
        args.build,
        args.signer,
        args.record_profile,
    )


if __name__ == "__main__":
    main()
