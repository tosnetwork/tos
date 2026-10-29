"""Compare ordered v16 fixture outputs without normalizing native state.

Callers supply explicit nine-field original-input rows and separate native
results. Reuse the bounded replay supervisor for driver execution and cleanup.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/rel02"), str(ROOT / "test/auth-extensions")]
import run_rust  # noqa: E402
from cells import read_dict  # noqa: E402
from root_cells import from_boc  # noqa: E402

if not __debug__:
    raise RuntimeError("root comparison requires enabled Python assertions")

MAX_ROWS = 10_000
# Original basechain wallet state-bound fixtures reach 2,881,435 bytes/row.
MAX_ROW_BYTES = 4 * 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
PRECOMPILED_NAMES = (
    "ext-accept",
    "ext-no-accept",
    "ext-over-gas-max",
    "ext-burn-under-credit",
    "ext-burn-over-credit",
    "int-accept",
    "ext-no-accept-credit-4294967295",
    "ext-accept-credit-4294967295",
    "ext-no-accept-credit-4294967296",
    "ext-accept-credit-4294967296",
    "ext-no-accept-credit-4294967297",
    "ext-accept-credit-4294967297",
)
FINE_NAMES = ("depth0", "depth1", "depth4", "depth8")
ACCEPTED_PRECOMPILED = {
    "ext-accept",
    "ext-burn-under-credit",
    "int-accept",
    "ext-accept-credit-4294967295",
    "ext-accept-credit-4294967296",
    "ext-accept-credit-4294967297",
}


def expected_row(name, result, *, allow_library=False):
    """Keep accepted failures, external refusals and compute errors distinct."""
    assert type(result.get("success")) is bool, "missing native success classification"
    if result["success"]:
        assert result.get("external_not_accepted", False) is False and "vm_exit_code" not in result
        transaction = from_boc(result["transaction"], allow_library=allow_library)
        shard = from_boc(result["shard_account"], allow_library=allow_library)
        assert len(shard.refs) == 1, "invalid native ShardAccount"
        return [
            name,
            "accepted",
            transaction.hash.hex(),
            shard.refs[0].hash.hex(),
            shard.hash.hex(),
        ]
    assert "transaction" not in result and "shard_account" not in result
    if result.get("external_not_accepted") is True:
        assert type(result.get("vm_exit_code")) is int
        return [name, "rejected", str(result["vm_exit_code"]), "-", "-"]
    assert result.get("external_not_accepted") is False and "vm_exit_code" not in result
    assert "cannot create compute phase of a new transaction" in result.get("error", ""), (
        "unsupported native refusal",
        result,
    )
    return [name, "refused", "precompiled-compute-failed", "-", "-"]


def compare(driver, configuration, records, output, label, *, expected_result=None):
    """records are ordered (explicit original input line, native result) pairs."""
    assert 0 < len(records) <= MAX_ROWS, "root scenario count limit"
    assert (
        label
        and len(label) <= 256
        and all(c.isascii() and (c.isalnum() or c in "-_") for c in label)
    )
    lines, expected, oracles = [], [], []
    size = len("#pq-tx-roots-v1\n")
    oracle_bytes = 2
    for line, result in records:
        assert "\n" not in line and "\r" not in line
        assert len(line.encode()) <= MAX_ROW_BYTES, "root scenario byte limit"
        fields = line.split("\t")
        assert len(fields) == 9, "root input requires all nine original-context fields"
        size += len(line.encode()) + 1
        assert size <= MAX_INPUT_BYTES, "root input byte limit"
        lines.append(line)
        classify = expected_row if expected_result is None else expected_result
        expected.append(classify(fields[0], result))
        raw = {
            key: result[key]
            for key in (
                "success",
                "transaction",
                "shard_account",
                "external_not_accepted",
                "vm_exit_code",
                "error",
            )
            if key in result
        }
        encoded = json.dumps(raw, separators=(",", ":"))
        oracle_bytes += len(encoded.encode()) + 1
        assert oracle_bytes <= MAX_INPUT_BYTES, "native root oracle byte limit"
        oracles.append(encoded)
    output.mkdir(parents=True, exist_ok=True)
    inputs = output / f"{label}-roots.tsv"
    inputs.write_text("#pq-tx-roots-v1\n" + "\n".join(lines) + "\n")
    (output / f"{label}-root-native.json").write_text("[" + ",".join(oracles) + "]\n")
    (output / f"{label}-root-expected.tsv").write_text(
        "".join("\t".join(row) + "\n" for row in expected)
    )
    stdout, _ = run_rust.execute(
        [
            str(driver.resolve()),
            str(configuration.resolve()),
            str(inputs.resolve()),
            "16",
            "--roots",
        ],
        output,
        label + "-root-driver",
    )
    text = stdout.decode()
    assert text.endswith("\n") and "\r" not in text, "incomplete root output records"
    actual = [line.split("\t") for line in text.splitlines()]
    assert len(actual) == len(expected), "root output row count mismatch"
    for index, (got, want) in enumerate(zip(actual, expected, strict=True)):
        assert len(got) == 5 and got == want, (label, index, got, want)
    return len(actual)


def validate_artifacts(directory):
    """Recompute every claimed record from its retained original native BOCs."""
    signatures = []
    counts = {"accepted": 0, "rejected": 0, "refused": 0}
    for family, labels in (("precompiled", PRECOMPILED_NAMES), ("fine", ("v16",))):
        folder = directory / family
        report = json.loads(run_rust.bounded_read(folder / "result.json", 8 * 1024 * 1024))
        assert report.get("passed") is True, (family, "producer did not pass")
        if family == "precompiled":
            assert tuple(report["rows"]) == labels, "precompiled scenario set/order changed"
        for label in labels:
            metadata = report["rows"][label if family == "precompiled" else "16"]
            assert metadata["root_rows"] == 4, "producer root row count changed"
            configuration = run_rust.bounded_read(folder / f"{label}-config.boc", 8 * 1024 * 1024)
            wrapper = from_boc(configuration)
            assert len(wrapper.bits) == 256 and len(wrapper.refs) == 1
            version = read_dict(wrapper.refs[0], 32)[8].refs[0].slice()
            assert version.uint(8) == 0xC4 and version.uint(32) == 16, "artifact config is not v16"
            raw_input = run_rust.bounded_read(folder / f"{label}-roots.tsv", MAX_INPUT_BYTES)
            text = raw_input.decode()
            assert text.endswith("\n") and "\r" not in text
            lines = text.splitlines()
            assert lines[0] == "#pq-tx-roots-v1" and len(lines) == 5
            fields = [line.split("\t") for line in lines[1:]]
            assert all(len(row) == 9 for row in fields)
            names = (label,) * 4 if family == "precompiled" else FINE_NAMES
            assert tuple(row[0] for row in fields) == names
            native = json.loads(
                run_rust.bounded_read(folder / f"{label}-root-native.json", MAX_INPUT_BYTES)
            )
            assert isinstance(native, list) and len(native) == 4, "native oracle row count changed"
            expected = [
                expected_row(name, result) for name, result in zip(names, native, strict=True)
            ]
            classification = (
                "accepted"
                if family == "fine" or label in ACCEPTED_PRECOMPILED
                else "refused"
                if label == "ext-burn-over-credit"
                else "rejected"
            )
            assert all(row[1] == classification for row in expected), (
                family,
                label,
                "wrong native class",
            )
            if classification == "rejected":
                assert all(row[2] == "0" for row in expected), (label, "wrong native refusal code")
            claimed = run_rust.bounded_read(folder / f"{label}-root-expected.tsv", 8 * 1024 * 1024)
            actual = run_rust.bounded_read(folder / f"{label}-root-driver.stdout", 8 * 1024 * 1024)
            canonical = "".join("\t".join(row) + "\n" for row in expected).encode()
            assert claimed == canonical and actual == canonical, (
                family,
                label,
                "native root mismatch",
            )
            for row in expected:
                counts[row[1]] += 1
            signatures.append((family, label, configuration, raw_input, canonical))
    assert counts == {"accepted": 28, "rejected": 20, "refused": 4}
    return signatures, counts


def compare_artifacts(left, right):
    a, counts = validate_artifacts(left)
    b, other_counts = validate_artifacts(right)
    assert a == b and counts == other_counts, "fixture input/config/output architecture mismatch"
    return counts


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", nargs=2, type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(dict(rows=52, outcomes=compare_artifacts(*arguments.compare))))
