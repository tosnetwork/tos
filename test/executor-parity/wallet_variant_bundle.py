"""Bounded, source/run/attempt-bound wallet artifacts for both architectures."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from generated_bundle import (
    MAX_BUNDLES,
    MAX_TOTAL,
    RUNNERS,
    children,
    metadata,
    preflight,
    receipt_guard,
)
from test_wallet_variant_roots import CONTROLS
from wallet_variant_roots import FAMILIES, ROOT, json_value, read, run_files, validate_run

PREFIX = "wallet-variant-roots-"


def filenames():
    return {f"{family}/{name}" for family in FAMILIES for name in run_files(family)} | {
        "controls.json"
    }


def check_controls(raw, source):
    value = json_value(raw)
    assert set(value) == {"source", "passed", "mutations"}
    assert value["source"] == source and value["passed"] is True, "wallet controls source/result"
    assert set(value["mutations"]) == set(FAMILIES), "wallet controls families"
    assert len(CONTROLS) == 26, "wallet required corruption population changed"
    for family in FAMILIES:
        rows = value["mutations"][family]
        assert [row["mutation"] for row in rows] == list(CONTROLS), "wallet controls population"
        assert all(row["rejected"] is True for row in rows), "wallet corruption survived"


def bundle(output, artifacts, controls, source, runner):
    assert not output.exists(), "wallet bundle destination exists"
    for family in FAMILIES:
        validate_run(artifacts / family, family, source)
    payloads, total = {}, 0
    manifest = metadata(source, runner)
    manifest.update(kind="wallet-variants", files={})
    for name in sorted(filenames()):
        path = controls if name == "controls.json" else artifacts / name
        raw = read(path)
        total += len(raw)
        assert total <= MAX_TOTAL, "wallet bundle total size limit"
        payloads[name] = raw
        manifest["files"][name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    check_controls(payloads["controls.json"], source)
    encoded = (json.dumps(manifest, indent=2) + "\n").encode()
    assert total + len(encoded) <= MAX_TOTAL, "wallet bundle total size limit"
    output.mkdir(parents=True)
    for name, raw in payloads.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (output / "bundle.json").write_bytes(encoded)
    validate_bundle(output, source, manifest["event"], manifest["run_id"], manifest["run_attempt"])


def validate_bundle(directory, source, event, run_id, attempt):
    assert directory.is_dir() and not directory.is_symlink(), "invalid wallet bundle directory"
    expected = filenames()
    tree = {}
    for name in expected | {"bundle.json"}:
        path = Path(name)
        for parent in (path.parent, *path.parent.parents):
            tree.setdefault(parent, set())
        tree[path.parent].add(path.name)
        for parent in path.parent.parents:
            tree[parent].add(path.parent.relative_to(parent).parts[0])
    for folder, names in tree.items():
        path = directory / folder
        assert path.is_dir() and not path.is_symlink(), "invalid wallet bundle directory"
        assert {p.name for p in children(path, len(names))} == names, "wallet bundle paths"
    raw_manifest = read(directory / "bundle.json")
    value = json_value(raw_manifest)
    assert set(value) == {
        "source",
        "event",
        "run_id",
        "run_attempt",
        "suite",
        "runner",
        "files",
        "kind",
    }, "wallet bundle fields"
    assert (value["source"], value["event"], value["run_id"], value["suite"], value["kind"]) == (
        source,
        event,
        run_id,
        "release-wallet",
        "wallet-variants",
    ), "wallet bundle source/run/event/suite mismatch"
    assert value["runner"] in RUNNERS, "wallet bundle runner mismatch"
    assert isinstance(value["run_attempt"], str) and re.fullmatch(
        r"[1-9][0-9]*", value["run_attempt"]
    ), "wallet bundle attempt"
    assert 0 < int(value["run_attempt"]) <= int(attempt), "wallet bundle future attempt"
    assert set(value["files"]) == expected, "wallet bundle manifest paths"
    total = len(raw_manifest)
    for name in sorted(expected):
        raw = read(directory / name)
        total += len(raw)
        assert total <= MAX_TOTAL, "wallet bundle total size limit"
        assert value["files"][name] == dict(
            bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()
        ), "wallet bundle file digest mismatch"
    check_controls(read(directory / "controls.json"), source)
    signatures = tuple(validate_run(directory / family, family, source) for family in FAMILIES)
    return value, signatures


def compare_bundles(directory, receipts, source, event, run_id, attempt):
    assert re.fullmatch(r"[1-9][0-9]*", attempt), "wallet current attempt"
    guard = receipt_guard()
    coverage = guard.validate(
        guard.WORKFLOW.read_text(),
        json.loads(guard.CONTRACT.read_text()),
        (ROOT / ".github/workflows/source-guards.yml").read_text(),
    )
    selected = guard.verify_receipts(receipts, source, run_id, attempt, coverage, event)
    candidates = {}
    paths = children(directory, MAX_BUNDLES)
    assert paths, "missing wallet bundles"
    for path in paths:
        value, signature = validate_bundle(path, source, event, run_id, attempt)
        key = value["runner"], int(value["run_attempt"])
        assert key not in candidates, "duplicate wallet bundle attempt"
        candidates[key] = signature
    chosen = []
    for runner in RUNNERS:
        key = runner, selected[("release-wallet", runner)]
        assert key in candidates, "missing wallet bundle for successful suite attempt"
        chosen.append(candidates[key])
    assert chosen[0] == chosen[1], "wallet architecture mismatch"
    print("PASS: 304 original wallet calls; native expected roots/refusals and both architectures")


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
    if args.bundle:
        bundle(args.bundle, args.artifacts, args.controls, source, args.runner)
    elif args.compare:
        assert os.environ["SOURCE_SHA"] == source, "wallet expected checkout mismatch"
        compare_bundles(
            args.compare,
            args.receipts,
            source,
            os.environ["GITHUB_EVENT_NAME"],
            os.environ["GITHUB_RUN_ID"],
            os.environ["GITHUB_RUN_ATTEMPT"],
        )
    else:
        preflight(PREFIX)


if __name__ == "__main__":
    main()
