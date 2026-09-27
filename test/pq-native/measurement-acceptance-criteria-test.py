#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    print(f"N6_ACCEPTANCE_CRITERIA_FAILURE: {message}", file=sys.stderr)
    raise SystemExit(1)


repo_root = Path(__file__).resolve().parents[2]
module_path = repo_root / "scripts" / "pq_measurement_manifest.py"
spec = importlib.util.spec_from_file_location("pq_measurement_manifest", module_path)
if spec is None or spec.loader is None:
    fail("could not load manifest module")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

criteria_path = repo_root / "doc" / "pq-native" / "N6-ACCEPTANCE-CRITERIA.json"
criteria = module.load_acceptance_criteria(criteria_path, release=False)

try:
    module.load_acceptance_criteria(criteria_path, release=True)
    fail("placeholder criteria were accepted for a release-grade run")
except module.ManifestError as exc:
    if "unreviewed hardware profile" not in str(exc):
        fail(f"placeholder criteria reported the wrong release refusal: {exc}")

with tempfile.TemporaryDirectory(prefix="n6-criteria-hash-") as raw:
    root = Path(raw)
    copied_criteria = root / "criteria.json"
    reviewed_zero_criteria = root / "reviewed-zero-criteria.json"
    matrix = root / "matrix.json"
    reviewed_zero = dict(criteria)
    reviewed_zero["release_hardware_profile"] = "reviewed-test-hardware"
    reviewed_zero_criteria.write_text(json.dumps(reviewed_zero) + "\n", encoding="utf-8")
    try:
        module.load_acceptance_criteria(reviewed_zero_criteria, release=True)
        fail("zero thresholds were interpreted as unlimited for a release-grade run")
    except module.ManifestError as exc:
        if "zero threshold" not in str(exc):
            fail(f"zero threshold reported the wrong release refusal: {exc}")

    copied_criteria.write_text(json.dumps(criteria, sort_keys=True) + "\n", encoding="utf-8")
    matrix.write_text('{"schema_version":1}\n', encoding="utf-8")
    manifest = {
        "acceptance_criteria_sha256": module.sha256_file(copied_criteria),
        "test_matrix_sha256": module.sha256_file(matrix),
    }
    module.validate_manifest_inputs(manifest, copied_criteria, matrix)

    copied_criteria.write_text(
        json.dumps(criteria, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    try:
        module.validate_manifest_inputs(manifest, copied_criteria, matrix)
        fail("changed criteria matched a manifest that was not regenerated")
    except module.ManifestError as exc:
        if "acceptance_criteria_sha256" not in str(exc):
            fail(f"changed criteria reported the wrong hash refusal: {exc}")

print("N6_ACCEPTANCE_CRITERIA_OK: schema complete, release placeholders refused, hash binding live")
