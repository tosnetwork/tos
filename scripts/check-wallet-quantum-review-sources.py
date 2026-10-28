#!/usr/bin/env python3
"""Reject stale candidate-bundle source identities without compiling contracts."""

import argparse
import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build-wallet-quantum-bundle.py"
MANIFEST = ROOT / "test/wallet-quantum/review-candidate-manifest.json"
SPEC = importlib.util.spec_from_file_location("wallet_bundle_sources", BUILDER)
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


def source_inputs():
    paths = [*bundle.source_files(), *bundle.public_files(), BUILDER]
    return {"repository/" + path.relative_to(ROOT).as_posix(): path.read_bytes() for path in paths}


def verify(manifest, inputs):
    recorded = {
        name: metadata
        for name, metadata in manifest["files"].items()
        if name.startswith("repository/")
    }
    if set(recorded) != set(inputs):
        raise ValueError("candidate bundle source set differs; regenerate the review manifest")
    for name, raw in inputs.items():
        if recorded[name] != bundle.digest(raw):
            raise ValueError("candidate bundle source digest differs: " + name)


def self_test(manifest, inputs):
    target = "repository/tosctl/src/node-control/contracts/src/wallet_quantum_fee_decode_tests.rs"
    assert target in inputs and target in manifest["files"]
    controls = []

    def refused(label, changed_manifest, changed_inputs, witness):
        try:
            verify(changed_manifest, changed_inputs)
        except ValueError as error:
            assert witness in str(error), (label, str(error))
        else:
            raise AssertionError("source identity mutation survived: " + label)
        controls.append(label)

    changed = dict(inputs)
    changed[target] += b"\n// changed test comment\n"
    refused("changed-source-comment", manifest, changed, target)
    for field, value in (("bytes", manifest["files"][target]["bytes"] + 1), ("sha256", "0" * 64)):
        changed = copy.deepcopy(manifest)
        changed["files"][target][field] = value
        refused("wrong-" + field, changed, inputs, target)
    changed = copy.deepcopy(manifest)
    changed["files"]["repository/unexpected-input.rs"] = bundle.digest(b"extra")
    refused("unexpected-declared-source", changed, inputs, "source set differs")
    changed = copy.deepcopy(manifest)
    del changed["files"][target]
    refused("missing-declared-source", changed, inputs, "source set differs")
    changed = dict(inputs)
    changed["repository/new-builder-input.rs"] = b"new input"
    refused("new-unrecorded-input", manifest, changed, "source set differs")
    verify(manifest, inputs)
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    inputs = source_inputs()
    verify(manifest, inputs)
    controls = self_test(manifest, inputs) if args.self_test else []
    print(json.dumps(dict(passed=True, sources=len(inputs), controls=controls)))


if __name__ == "__main__":
    main()
