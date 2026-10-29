"""Bounded block transport and independent validation of original auth roots.

Large rows stay intact logically. Transport blocks remain at most1MiB; the new
artifact kind has its own64MiB aggregate budget, without changing older gates.
"""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from auth_factory_roots import PROFILE, ROOT, SOURCES, digest, producer_sources, validate_profile
from generated_bundle import MAX_BUNDLES, RUNNERS, children, metadata, preflight, receipt_guard
from root_cells import from_boc
from transaction_roots import MAX_INPUT_BYTES, MAX_ROW_BYTES, expected_row

PREFIX = "auth-factory-roots-"
BLOCK = 1024 * 1024
MAX_TOTAL = 64 * BLOCK
MAX_MANIFEST = BLOCK
MAX_FILES = 256


def json_value(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, "duplicate auth JSON key"
            value[key] = item
        return value

    return json.loads(raw, object_pairs_hook=unique)


def bounded(path, maximum):
    assert path.is_file() and not path.is_symlink(), "auth artifact must be a regular file"
    assert path.stat().st_size <= maximum, "auth artifact file limit"
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    assert len(raw) <= maximum, "auth artifact file limit"
    return raw


def frozen():
    raw = bounded(PROFILE, BLOCK)
    value = json_value(raw)
    for family in SOURCES:
        validate_profile(family, value[family], raw)
        assert value[family]["producer_sources"] == producer_sources(family), (
            "auth producer source changed"
        )
    return value


def configurations(profile):
    return list(
        dict.fromkeys(row["configuration"] for row in profile["calls"] if row["version"] == 16)
    )


def payload_names(profiles):
    names = set()
    for family, profile in profiles.items():
        names.update(
            f"{family}/{name}" for name in ("profile.json", "summary.json", "receipt.json")
        )
        for index, _ in enumerate(configurations(profile)):
            names.update(
                f"{family}/config-{index:02d}/{name}"
                for name in (
                    "config.boc",
                    "auth-factory-roots.tsv",
                    "auth-factory-root-native.json",
                    "auth-factory-root-expected.tsv",
                    "auth-factory-root-driver.stdout",
                )
            )
    return names


def validate_receipt(raw, family, source, profile):
    value = json_value(raw)
    assert set(value) == {
        "family",
        "source",
        "tree",
        "dirty",
        "harness_sha256",
        "profile_sha256",
        "executables",
    }, "auth receipt fields"
    assert value["family"] == family and value["source"] == source, "auth receipt source/family"
    assert value["dirty"] is False, "auth receipt from dirty source"
    assert (
        value["tree"]
        == subprocess.check_output(
            ["git", "rev-parse", source + "^{tree}"], cwd=ROOT, text=True
        ).strip()
    ), "auth receipt tree"
    assert value["harness_sha256"] == digest(
        subprocess.check_output(
            ["git", "show", source + ":test/executor-parity/auth_factory_roots.py"], cwd=ROOT
        )
    ), "auth receipt harness"
    assert value["profile_sha256"] == digest(profile), "auth receipt profile digest"
    required = {"driver", "emulator", "func", "fift", "tol"} | (
        {"signer"} if family == "mldsa" else set()
    )
    assert set(value["executables"]) == required, "auth executable population"
    for executable in value["executables"].values():
        assert (
            set(executable) == {"path", "sha256"}
            and isinstance(executable["path"], str)
            and executable["path"]
        ), "auth executable identity"
        assert re.fullmatch(r"[a-f0-9]{64}", executable["sha256"]), "auth executable digest"


def validate_payloads(payloads, source):
    profiles = frozen()
    assert set(payloads) == payload_names(profiles), "auth payload population"
    assert sum(len(raw) for raw in payloads.values()) <= MAX_TOTAL, "auth payload total limit"
    signatures = []
    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    for family, reference in profiles.items():
        raw_profile = payloads[f"{family}/profile.json"]
        profile = json_value(raw_profile)
        validate_profile(family, profile)
        validate_receipt(payloads[f"{family}/receipt.json"], family, source, raw_profile)
        summary = json_value(payloads[f"{family}/summary.json"])
        groups = configurations(reference)
        calls = [row for row in reference["calls"] if row["version"] == 16]
        counts = [
            {"dictionary": key, "calls": sum(row["configuration"] == key for row in calls)}
            for key in groups
        ]
        assert summary == dict(
            family=family,
            native_tests=len(reference["cases"]),
            native_calls=len(reference["calls"]),
            v16_calls=len(calls),
            historical_calls=len(reference["calls"]) - len(calls),
            configurations=counts,
            profile_sha256=digest(raw_profile),
            passed=True,
            frozen_profile=True,
            scope="local original-input profile; artifact/hosted gates pending",
        ), "auth summary/population/frozen status"
        for index, key in enumerate(groups):
            prefix = f"{family}/config-{index:02d}/"
            cfg = payloads[prefix + "config.boc"]
            root = from_boc(cfg)
            assert (
                root.bits == fixture.bits and len(root.refs) == 1 and root.refs[0].hash.hex() == key
            ), "auth configuration identity"
            inputs = payloads[prefix + "auth-factory-roots.tsv"]
            assert (
                inputs.endswith(b"\n") and b"\r" not in inputs and len(inputs) <= MAX_INPUT_BYTES
            ), "auth input framing/limit"
            lines = inputs.decode().splitlines()
            assert lines.pop(0) == "#pq-tx-roots-v1", "auth input schema"
            selected = [row for row in calls if row["configuration"] == key]
            assert len(lines) == len(selected), "auth input population"
            native = json_value(payloads[prefix + "auth-factory-root-native.json"])
            assert isinstance(native, list) and len(native) == len(selected), (
                "auth native population"
            )
            expected = []
            for line, reference_row, oracle in zip(lines, selected, native, strict=True):
                assert len(line.encode()) <= MAX_ROW_BYTES and len(line.split("\t")) == 9, (
                    "auth input row bound/schema"
                )
                assert (
                    line.split("\t")[0] == reference_row["name"]
                    and digest(line.encode()) == reference_row["input_sha256"]
                ), "auth original input/context changed"
                keys = (
                    {"success", "transaction", "shard_account"}
                    if oracle.get("success") is True
                    else {"success", "error", "external_not_accepted", "vm_exit_code"}
                )
                assert set(oracle) == keys, "auth native result fields"
                result = expected_row(reference_row["name"], oracle, allow_library=True)
                assert result[1:] == reference_row["expected"], "auth native root/refusal changed"
                expected.append("\t".join(result) + "\n")
            encoded = "".join(expected).encode()
            assert payloads[prefix + "auth-factory-root-expected.tsv"] == encoded, (
                "auth expected rows changed"
            )
            assert payloads[prefix + "auth-factory-root-driver.stdout"] == encoded, (
                "auth Rust result mismatch"
            )
            signatures.append((family, key, digest(cfg), digest(inputs), digest(encoded)))
    return tuple(signatures)


def collect(directory):
    profiles = frozen()
    payloads = {}
    total = 0
    for name in sorted(payload_names(profiles)):
        raw = bounded(directory / name, MAX_TOTAL - total)
        total += len(raw)
        assert total <= MAX_TOTAL, "auth payload total limit"
        payloads[name] = raw
    return payloads


def pack(output, artifacts, controls, source, runner):
    assert not output.exists(), "auth bundle destination must be fresh"
    payloads = collect(artifacts)
    validate_payloads(payloads, source)
    controls_raw = bounded(controls, BLOCK)
    check_controls(controls_raw, source)
    payloads["controls.json"] = controls_raw
    value = metadata(source, runner)
    value.update(kind="auth-factories", payloads={})
    blocks = {}
    for ordinal, (name, raw) in enumerate(sorted(payloads.items())):
        assert 0 < len(raw) <= MAX_TOTAL, "auth payload byte length"
        names = []
        for index, start in enumerate(range(0, len(raw), BLOCK)):
            path = f"block-{ordinal:03d}-{index:03d}.bin"
            names.append(path)
            blocks[path] = raw[start : start + BLOCK]
        value["payloads"][name] = dict(bytes=len(raw), sha256=digest(raw), blocks=names)
    encoded = (json.dumps(value, indent=2) + "\n").encode()
    assert len(blocks) <= MAX_FILES and len(encoded) <= MAX_MANIFEST, "auth block/manifest limit"
    assert sum(len(raw) for raw in blocks.values()) + len(encoded) <= MAX_TOTAL, (
        "auth bundle total limit"
    )
    output.mkdir(parents=True)
    for name, raw in blocks.items():
        (output / name).write_bytes(raw)
    (output / "bundle.json").write_bytes(encoded)
    validate_bundle(output, source, value["event"], value["run_id"], value["run_attempt"])


CONTROL_NAMES = (
    "missing",
    "extra",
    "reordered",
    "context",
    "config",
    "native",
    "coherent-native-rust",
    "rust",
    "source",
    "dirty",
    "candidate-profile",
    "summary",
)


def check_controls(raw, source):
    value = json_value(raw)
    assert value == dict(
        source=source, passed=True, families={family: list(CONTROL_NAMES) for family in SOURCES}
    ), "auth corruption controls incomplete"


def validate_bundle(directory, source, event, run_id, attempt):
    assert directory.is_dir() and not directory.is_symlink(), "auth bundle directory"
    value = json_value(bounded(directory / "bundle.json", MAX_MANIFEST))
    assert set(value) == {
        "source",
        "event",
        "run_id",
        "run_attempt",
        "suite",
        "runner",
        "kind",
        "payloads",
    }, "auth bundle fields"
    assert (value["source"], value["event"], value["run_id"], value["suite"], value["kind"]) == (
        source,
        event,
        run_id,
        "release-wallet",
        "auth-factories",
    ), "auth bundle source/run/event/suite"
    assert value["runner"] in RUNNERS, "auth bundle runner"
    assert isinstance(value["run_attempt"], str) and re.fullmatch(
        r"[1-9][0-9]*", value["run_attempt"]
    ), "auth bundle attempt"
    assert 0 < int(value["run_attempt"]) <= int(attempt), "auth bundle future attempt"
    expected = payload_names(frozen()) | {"controls.json"}
    assert set(value["payloads"]) == expected, "auth bundle payload population"
    total = len(bounded(directory / "bundle.json", MAX_MANIFEST))
    names, payloads = {"bundle.json"}, {}
    for ordinal, name in enumerate(sorted(expected)):
        spec = value["payloads"][name]
        assert set(spec) == {"bytes", "sha256", "blocks"}, "auth payload declaration"
        size = spec["bytes"]
        assert type(size) is int and 0 < size <= MAX_TOTAL, "auth payload declared size"
        total += size
        assert total <= MAX_TOTAL, "auth bundle total limit"
        paths = [f"block-{ordinal:03d}-{i:03d}.bin" for i in range((size + BLOCK - 1) // BLOCK)]
        assert spec["blocks"] == paths, "auth block order/population"
        names.update(paths)
        assert len(names) <= MAX_FILES + 1, "auth block population limit"
        pieces = []
        for index, path in enumerate(paths):
            raw = bounded(directory / path, BLOCK)
            assert len(raw) == min(BLOCK, size - index * BLOCK), "auth block size"
            pieces.append(raw)
        raw = b"".join(pieces)
        assert digest(raw) == spec["sha256"], "auth payload digest"
        payloads[name] = raw
    assert {p.name for p in children(directory, MAX_FILES + 1)} == names, (
        "auth bundle extra/missing paths"
    )
    check_controls(payloads.pop("controls.json"), source)
    return value, validate_payloads(payloads, source)


def compare_bundles(directory, receipts, source, event, run_id, attempt):
    guard = receipt_guard()
    coverage = guard.validate(
        guard.WORKFLOW.read_text(),
        json.loads(guard.CONTRACT.read_text()),
        (ROOT / ".github/workflows/source-guards.yml").read_text(),
    )
    selected = guard.verify_receipts(receipts, source, run_id, attempt, coverage, event)
    candidates = {}
    paths = children(directory, MAX_BUNDLES)
    assert paths, "missing auth bundles"
    for path in paths:
        value, signature = validate_bundle(path, source, event, run_id, attempt)
        key = value["runner"], int(value["run_attempt"])
        assert key not in candidates, "duplicate auth bundle attempt"
        candidates[key] = signature
    chosen = []
    for runner in RUNNERS:
        key = runner, selected[("release-wallet", runner)]
        assert key in candidates, "missing auth successful-attempt artifact"
        chosen.append(candidates[key])
    assert chosen[0] == chosen[1], "auth architecture mismatch"
    print("PASS:1115 original v16 auth calls; fixed native roots/refusals and both architectures")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--bundle", type=Path)
    action.add_argument("--compare", type=Path)
    action.add_argument("--check-download", action="store_true")
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--controls", type=Path)
    parser.add_argument("--receipts", type=Path)
    parser.add_argument("--runner", choices=RUNNERS)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if args.check_download:
        preflight(PREFIX, max_total=MAX_TOTAL)
    elif args.bundle:
        pack(args.bundle, args.artifacts, args.controls, source, args.runner)
    else:
        assert os.environ["SOURCE_SHA"] == source, "auth expected checkout"
        compare_bundles(
            args.compare,
            args.receipts,
            source,
            os.environ["GITHUB_EVENT_NAME"],
            os.environ["GITHUB_RUN_ID"],
            os.environ["GITHUB_RUN_ATTEMPT"],
        )


if __name__ == "__main__":
    main()
