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
from cells import from_boc  # noqa: E402

if not __debug__:
    raise RuntimeError("root comparison requires enabled Python assertions")

MAX_ROWS = 10_000
MAX_ROW_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024


def expected_row(name, result):
    """Keep accepted failures, external refusals and compute errors distinct."""
    assert type(result.get("success")) is bool, "missing native success classification"
    if result["success"]:
        transaction = from_boc(result["transaction"])
        shard = from_boc(result["shard_account"])
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


def compare(driver, configuration, records, output, label):
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
        expected.append(expected_row(fields[0], result))
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
