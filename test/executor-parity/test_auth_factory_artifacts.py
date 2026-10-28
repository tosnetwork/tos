"""Corrupt actual factory payloads; every refusal must name its intended guard.

This runner needs completed captures including their execution receipts. It does
not manufacture execution receipts or claim hosted architecture execution.
"""

import argparse
import json
import subprocess
from pathlib import Path

from auth_factory_artifacts import (
    CONTROL_NAMES,
    ROOT,
    SOURCES,
    collect,
    configurations,
    frozen,
    json_value,
    validate_payloads,
)
from transaction_roots import expected_row


def encoded(value):
    return (json.dumps(value) + "\n").encode()


def mutations(original, family, profiles):
    prefix = family + "/"
    group = prefix + "config-00/"
    inputs = group + "auth-factory-roots.tsv"
    native = group + "auth-factory-root-native.json"
    expected = group + "auth-factory-root-expected.tsv"
    driver = group + "auth-factory-root-driver.stdout"
    receipt = prefix + "receipt.json"
    summary = prefix + "summary.json"

    def altered(path, raw):
        return {**original, path: raw}

    yield "missing", {k: v for k, v in original.items() if k != inputs}, "auth payload population"
    yield "extra", {**original, prefix + "extra": b"x"}, "auth payload population"
    lines = original[inputs].decode().splitlines()
    swapped = lines.copy()
    swapped[1], swapped[2] = swapped[2], swapped[1]
    yield (
        "reordered",
        altered(inputs, ("\n".join(swapped) + "\n").encode()),
        "auth original input/context changed",
    )
    changed = lines.copy()
    fields = changed[1].split("\t")
    fields[-1] = str(int(fields[-1]) + 1)
    changed[1] = "\t".join(fields)
    yield (
        "context",
        altered(inputs, ("\n".join(changed) + "\n").encode()),
        "auth original input/context changed",
    )
    assert len(configurations(profiles[family])) > 1, "control needs two actual configurations"
    yield (
        "config",
        altered(group + "config.boc", original[prefix + "config-01/config.boc"]),
        "auth configuration identity",
    )
    oracles = json_value(original[native])
    candidates = [i for i, oracle in enumerate(oracles) if oracle["success"]]
    first = candidates[0]
    second = next(
        i for i in candidates[1:] if oracles[i]["transaction"] != oracles[first]["transaction"]
    )
    wrong = oracles.copy()
    wrong[first] = oracles[second]
    changed_native = altered(native, encoded(wrong))
    yield "native", changed_native, "auth native root/refusal changed"
    outputs = original[expected].decode().splitlines()
    outputs[first] = "\t".join(
        expected_row(lines[first + 1].split("\t")[0], wrong[first], allow_library=True)
    )
    coherent = ("\n".join(outputs) + "\n").encode()
    yield (
        "coherent-native-rust",
        {**changed_native, expected: coherent, driver: coherent},
        "auth native root/refusal changed",
    )
    yield "rust", altered(driver, original[driver] + b"extra\n"), "auth Rust result mismatch"
    value = json_value(original[receipt])
    yield (
        "source",
        altered(receipt, encoded({**value, "source": "0" * 40})),
        "auth receipt source/family",
    )
    yield (
        "dirty",
        altered(receipt, encoded({**value, "dirty": True})),
        "auth receipt from dirty source",
    )
    value = json_value(original[summary])
    yield (
        "candidate-profile",
        altered(summary, encoded({**value, "frozen_profile": False})),
        "auth summary/population/frozen status",
    )
    yield (
        "summary",
        altered(summary, encoded({**value, "v16_calls": value["v16_calls"] - 1})),
        "auth summary/population/frozen status",
    )


def controls(artifacts, source):
    original = collect(artifacts)
    baseline = validate_payloads(original, source)
    result = dict(source=source, passed=True, families={})
    for family in SOURCES:
        labels = []
        for label, payloads, witness in mutations(original, family, frozen()):
            try:
                validate_payloads(payloads, source)
            except AssertionError as error:
                assert witness in str(error), (family, label, "wrong refusal", str(error))
            else:
                raise AssertionError((family, label, "corruption survived"))
            labels.append(label)
            print("PASS:", family, label, witness)
        assert tuple(labels) == CONTROL_NAMES, "auth control population/order"
        result["families"][family] = labels
    assert validate_payloads(original, source) == baseline, "auth restored baseline changed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), "auth controls output must be fresh"
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    result = controls(args.artifacts, source)
    args.output.write_bytes(encoded(result))


if __name__ == "__main__":
    main()
