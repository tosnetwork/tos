"""Actual auth payload transport with modeled CI run identity, not hosted proof."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from auth_factory_artifacts import (
    BLOCK,
    MAX_TOTAL,
    PREFIX,
    ROOT,
    RUNNERS,
    pack,
    validate_bundle,
)
from generated_bundle import MAX_TOTAL as OLD_MAX_TOTAL
from generated_bundle import artifact_selection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), "auth bundle control output must be fresh"
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    passed = []

    def refuses(label, operation, witness):
        try:
            operation()
        except AssertionError as error:
            assert witness in str(error), (label, "wrong refusal", str(error))
        else:
            raise AssertionError((label, "corruption survived"))
        passed.append(label)

    with tempfile.TemporaryDirectory() as temporary:
        bundle = Path(temporary) / "bundle"
        with patch.dict(
            os.environ,
            {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ID": "71", "GITHUB_RUN_ATTEMPT": "1"},
        ):
            pack(bundle, args.artifacts, args.controls, source, RUNNERS[0])

        def validate():
            return validate_bundle(bundle, source, "pull_request", "71", "2")

        validate()
        manifest = bundle / "bundle.json"
        saved = manifest.read_bytes()
        baseline = json.loads(saved)
        for key, value, witness in (
            ("source", "0" * 40, "auth bundle source/run/event/suite"),
            ("event", "push", "auth bundle source/run/event/suite"),
            ("run_id", "72", "auth bundle source/run/event/suite"),
            ("suite", "other", "auth bundle source/run/event/suite"),
            ("kind", "other", "auth bundle source/run/event/suite"),
            ("runner", "other", "auth bundle runner"),
            ("run_attempt", "3", "auth bundle future attempt"),
            ("run_attempt", "01", "auth bundle attempt"),
        ):
            manifest.write_text(json.dumps({**baseline, key: value}))
            refuses(key + "=" + value, validate, witness)
            manifest.write_bytes(saved)
        name = next(n for n, p in baseline["payloads"].items() if len(p["blocks"]) > 1)
        value = json.loads(saved)
        value["payloads"][name]["blocks"].reverse()
        manifest.write_text(json.dumps(value))
        refuses("block-order", validate, "auth block order/population")
        manifest.write_bytes(saved)
        block = bundle / baseline["payloads"][name]["blocks"][0]
        raw = block.read_bytes()
        assert len(raw) == BLOCK, "control must exercise a full block"
        block.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        refuses("block-digest", validate, "auth payload digest")
        block.write_bytes(raw + b"x")
        refuses("block-limit", validate, "auth artifact file limit")
        block.write_bytes(raw)
        value = json.loads(saved)
        value["payloads"][name]["bytes"] = MAX_TOTAL + 1
        manifest.write_text(json.dumps(value))
        refuses("declared-budget", validate, "auth payload declared size")
        manifest.write_bytes(saved)
        validate()

    artifact = dict(name=PREFIX + RUNNERS[0] + "-attempt-1", expired=False, size_in_bytes=MAX_TOTAL)
    assert artifact_selection([artifact], "2", PREFIX, max_total=MAX_TOTAL) == 1
    refuses(
        "old-download-bound-retained",
        lambda: artifact_selection([artifact], "2", PREFIX),
        "generated download size limit",
    )
    assert OLD_MAX_TOTAL == 16 * BLOCK, "old bundle budget changed"
    artifact["size_in_bytes"] += 1
    refuses(
        "auth-download-budget",
        lambda: artifact_selection([artifact], "2", PREFIX, max_total=MAX_TOTAL),
        "generated download size limit",
    )
    args.output.write_text(
        json.dumps(dict(modeled_ci=True, controls=passed, passed=True), indent=2) + "\n"
    )
    print("PASS:", len(passed), "auth bundle controls; CI identity modeled")


if __name__ == "__main__":
    main()
