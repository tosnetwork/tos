"""Original preparation/self-pay/recovery factories, without dropping native calls."""

# ruff: noqa: E402
import argparse
import hashlib
import inspect
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / name)
    for name in (
        "test/auth-extensions",
        "test/falcon-auth",
        "test/wallet-quantum",
        "test/rescue-fee-gate",
    )
]
import native
from cells import Cell
from linked_roots import ATTEMPTS, Capture, CaptureEmulator
from root_cells import from_boc
from transaction_roots import MAX_INPUT_BYTES, compare, expected_row
from wallet_module_roots import json_value

PROFILE = Path(__file__).with_name("data") / "wallet-variant-inputs.json"
PROFILE_SHA256 = "9881e67f9202e851696dd1ca42123aa032f7dafb2c861d8f1b71a3d18c951122"
MAX_FILE = 2 * 1024 * 1024
FAMILIES = {
    "preparation": (24, 24, 2),
    "self_pay": (108, 244, 54),
    "self_pay_recovery": (36, 36, 1),
}
IMPORT_REFUSAL = re.compile(
    r"Emulate transaction failed: \[Error : -701 : cannot run message on account "
    r"inbound external message rejected by account [0-9A-F]{64} "
    r"before smart-contract execution\]"
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    assert path.is_file() and not path.is_symlink(), "invalid wallet-variant artifact"
    assert path.stat().st_size <= MAX_FILE, "wallet-variant artifact size limit"
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    assert len(raw) <= MAX_FILE, "wallet-variant artifact size limit"
    return raw


def wallet_expected(name, result):
    assert type(result.get("success")) is bool, "missing native wallet success classification"
    if not result["success"] and result.get("external_not_accepted") is False:
        # Only the original, independently asserted balance sweep uses this
        # native diagnostic. Other unknown native failures remain fatal.
        assert name.startswith("self_pay-") and ":balance-" in name, (
            "unexpected wallet import refusal",
            name,
        )
        assert "transaction" not in result and "shard_account" not in result
        assert "vm_exit_code" not in result, "import refusal must precede VM execution"
        assert IMPORT_REFUSAL.fullmatch(result.get("error", "")), "unknown import refusal"
        return [name, "refused", "import-no-funds", "-", "-"]
    return expected_row(name, result, allow_library=True)


def producer_name(source):
    frame = inspect.currentframe()
    try:
        while frame is not None:
            if frame.f_code.co_filename == str(source) and frame.f_code.co_name in {
                "send",
                "transact",
                "run",
            }:
                for field in ("name", "label"):
                    if field in frame.f_locals:
                        value = frame.f_locals[field]
                        if value is None:
                            return "admission-search"
                        if isinstance(value, str) and value:
                            assert len(value) <= 128 and not any(c in value for c in "\t\r\n")
                            return value
            frame = frame.f_back
        return "deployment"
    finally:
        del frame


def native_cases(output, family):
    if family == "preparation":
        return list(json.loads(read(output / "results.json")))
    return [entry["name"] for entry in json.loads(read(output / "report.json"))["cases"]]


def profiles():
    raw = read(PROFILE)
    assert digest(raw) == PROFILE_SHA256, "wallet input profile source digest changed"
    result = json_value(raw)
    assert set(result) == set(FAMILIES), "wallet profile family population changed"
    return result


def run_files(family):
    count = FAMILIES[family][2]
    result = {"wallet-variant-receipt.json"}
    result.add("native/results.json" if family == "preparation" else "native/report.json")
    for index in range(count):
        result.update(
            f"configuration-{index}/" + name
            for name in (
                "config.boc",
                "wallet-variant-roots.tsv",
                "wallet-variant-root-native.json",
                "wallet-variant-root-expected.tsv",
                "wallet-variant-root-driver.stdout",
            )
        )
    return result


def validate_run(directory, family, source, *, allow_dirty=False):
    profile = profiles()[family]
    receipt = json_value(read(directory / "wallet-variant-receipt.json"))
    assert set(receipt) == {
        "family",
        "source",
        "source_diff_sha256",
        "harness_sha256",
        "original_producer_sha256",
        "profile_sha256",
        "cases",
        "calls",
        "configurations",
        "recorded_profile",
        "executables",
        "passed",
    }, "wallet receipt fields"
    assert receipt["family"] == family and receipt["source"] == source, "wallet receipt source"
    assert receipt["recorded_profile"] is False and receipt["passed"] is True, (
        "wallet producer did not pass the frozen profile"
    )
    if not allow_dirty:
        assert receipt["source_diff_sha256"] == digest(b""), "wallet source had tracked changes"
    assert receipt["harness_sha256"] == digest(Path(__file__).read_bytes()), "wallet harness source"
    producer = ROOT / f"test/wallet-quantum/test_{family}.py"
    assert receipt["original_producer_sha256"] == digest(producer.read_bytes()), (
        "wallet producer source"
    )
    assert receipt["profile_sha256"] == digest(json.dumps(profile, sort_keys=True).encode()), (
        "wallet input profile receipt"
    )
    assert (receipt["cases"], receipt["calls"], len(receipt["configurations"])) == FAMILIES[family]
    assert native_cases(directory / "native", family) == profile["cases"], "wallet native cases"
    if family != "preparation":
        report = json_value(read(directory / "native/report.json"))
        assert report["rust_parity"] == "passed", "original wallet comparison did not pass"
        if family == "self_pay":
            assert report["mutations"] == {"signature": "caught", "commit": "caught"}
    signatures, counts = [], {"accepted": 0, "rejected": 0, "refused": 0}
    expected_groups = []
    for index, cfg in enumerate(profile["configurations"]):
        folder = directory / f"configuration-{index}"
        raw_config = read(folder / "config.boc")
        root = from_boc(raw_config)
        assert len(root.bits) == 256 and len(root.refs) == 1, "wallet ConfigParams shape"
        assert digest(raw_config) == cfg["wire_sha256"], "wallet configuration wire changed"
        assert root.refs[0].hash.hex() == cfg["dictionary"], "wallet configuration root changed"
        raw_inputs = read(folder / "wallet-variant-roots.tsv")
        assert raw_inputs.endswith(b"\n") and b"\r" not in raw_inputs, "wallet root input framing"
        lines = raw_inputs.decode().splitlines()
        assert lines[0] == "#pq-tx-roots-v1", "wallet root input schema"
        selected = [row for row in profile["rows"] if row["dictionary"] == cfg["dictionary"]]
        assert len(lines) == len(selected) + 1, "wallet linked record count changed"
        oracles = json_value(read(folder / "wallet-variant-root-native.json"))
        assert isinstance(oracles, list) and len(oracles) == len(selected), (
            "wallet oracle population"
        )
        expected = []
        for line, want, oracle in zip(lines[1:], selected, oracles, strict=True):
            fields = line.split("\t")
            assert len(fields) == 9 and fields[0] == want["name"], "wallet call order changed"
            assert digest(line.encode()) == want["input_sha256"], "wallet original input changed"
            row = wallet_expected(fields[0], oracle)
            assert row[1:] == want["expected"], "wallet native baseline outcome or roots changed"
            counts[row[1]] += 1
            expected.append("\t".join(row))
        for filename in ("wallet-variant-root-expected.tsv", "wallet-variant-root-driver.stdout"):
            raw = read(folder / filename)
            assert raw == ("\n".join(expected) + "\n").encode(), "wallet root output changed"
        signatures.append((raw_config, raw_inputs, tuple(expected)))
        expected_groups.append(dict(dictionary=cfg["dictionary"], calls=len(selected)))
    assert receipt["configurations"] == expected_groups, "wallet receipt group population changed"
    assert sum(counts.values()) == FAMILIES[family][1], "wallet total call population changed"
    return signatures, counts


def run(family, driver, output, record_profile=None):
    source = ROOT / f"test/wallet-quantum/test_{family}.py"
    groups, ordered, row_profile = {}, [], []
    retained_bytes = 0
    assert not ATTEMPTS, "wallet-variant capture must start empty"

    class Recording(CaptureEmulator):
        def send(self, shard, message):
            nonlocal retained_bytes
            ordinal = len(ordered)
            assert ordinal < FAMILIES[family][1], "unexpected extra native wallet call"
            name = f"{family}-{ordinal:03d}:{producer_name(source)}"
            result = super().send(shard, message)
            original, inbound, lt, now, cfg, oracle, event = self.last_capture
            assert self.version == 16, "wallet-variant capture requires v16"
            assert not event["captured"]
            event.update(captured=True, name=name, reason="captured")
            record = Capture(name, original, inbound, lt, now, oracle, "")
            line = record.root_input()
            classification = wallet_expected(name, oracle)
            retained_bytes += len(line.encode()) + len(json.dumps(oracle).encode())
            assert retained_bytes <= MAX_INPUT_BYTES, "wallet-variant capture size limit"
            if cfg not in groups:
                fixture = from_boc(
                    (ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes()
                )
                groups[cfg] = (Cell(bits=fixture.bits).ref(self.configuration), [])
            groups[cfg][1].append(record)
            ordered.append((cfg, record))
            row_profile.append(
                dict(
                    name=name,
                    dictionary=cfg,
                    input_sha256=digest(line.encode()),
                    expected=classification[1:],
                )
            )
            return result

    output.mkdir(parents=True, exist_ok=False)
    original_output = output / "native"
    # The original 255/256-action fixtures recurse through cached_property on
    # Python3.10. The bounded BOC decoder still enforces its own depth/work caps.
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old_limit, 8192))
    try:
        argv = [str(source), "--output", str(original_output), "--rust-driver", str(driver)]
        with patch.object(native, "Emulator", Recording), patch.object(sys, "argv", argv):
            runpy.run_path(str(source), run_name="__main__")
    finally:
        sys.setrecursionlimit(old_limit)
    cases = native_cases(original_output, family)
    assert len(cases) == FAMILIES[family][0], "original native case population changed"
    assert len(ordered) == len(ATTEMPTS) == FAMILIES[family][1], "wallet call population changed"
    assert all(event["captured"] for event in ATTEMPTS), "unaccounted native wallet call"
    assert len(groups) == FAMILIES[family][2], "wallet configuration population changed"
    profile = dict(
        cases=cases,
        configurations=[
            dict(dictionary=key, wire_sha256=digest(value[0].boc()))
            for key, value in groups.items()
        ],
        rows=row_profile,
    )
    if record_profile is None:
        assert profile == profiles()[family], "wallet original-input profile changed"
    results = []
    for index, (cfg, (configuration, records)) in enumerate(groups.items()):
        folder = output / f"configuration-{index}"
        folder.mkdir()
        config_path = folder / "config.boc"
        config_path.write_bytes(configuration.boc())
        count = compare(
            driver,
            config_path,
            [(record.root_input(), record.native) for record in records],
            folder,
            "wallet-variant",
            expected_result=wallet_expected,
        )
        results.append(dict(dictionary=cfg, calls=count))
    if record_profile is not None:
        record_profile.write_text(json.dumps({family: profile}, indent=2) + "\n")
    receipt = dict(
        family=family,
        source=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        source_diff_sha256=digest(subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)),
        harness_sha256=digest(Path(__file__).read_bytes()),
        original_producer_sha256=digest(source.read_bytes()),
        profile_sha256=digest(json.dumps(profile, sort_keys=True).encode()),
        cases=len(cases),
        calls=len(ordered),
        configurations=results,
        recorded_profile=record_profile is not None,
        executables={
            name: dict(path=str(path), sha256=digest(path.read_bytes()))
            for name, path in {
                **{
                    name: Path(os.environ[name]).resolve()
                    for name in (
                        "FUNC_PATH",
                        "FIFT_PATH",
                        "EMULATOR_PATH",
                        "MLDSA_TOOL",
                        "SLH_TOOL",
                    )
                },
                "rust_driver": driver,
            }.items()
        },
        passed=True,
    )
    (output / "wallet-variant-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"PASS: {family} {len(ordered)} original calls in {len(groups)} configurations")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", required=True, choices=FAMILIES)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--record-profile", type=Path, help="Author-only candidate profile output")
    args = parser.parse_args()
    run(args.family, args.driver.resolve(), args.output.resolve(), args.record_profile)


if __name__ == "__main__":
    main()
