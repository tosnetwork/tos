"""Actual wallet payloads with modeled CI identities and adverse attempt selection."""

import argparse
import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from generated_bundle import MAX_TOTAL, RUNNERS, artifact_selection, receipt_guard
from wallet_variant_bundle import PREFIX, bundle, compare_bundles, validate_bundle
from wallet_variant_roots import ROOT, digest, json_value, read, wallet_expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    results = []

    def refused(name, operation, witness):
        try:
            operation()
        except (AssertionError, ValueError) as error:
            assert witness in str(error), (name, witness, str(error))
            results.append(dict(control=name, rejected=True, witness=witness))
        else:
            raise AssertionError("wallet bundle mutation survived: " + name)

    event, run_id, attempt = "workflow_dispatch", "73", "2"
    guard = receipt_guard()
    coverage = guard.validate(
        guard.WORKFLOW.read_text(),
        json.loads(guard.CONTRACT.read_text()),
        (ROOT / ".github/workflows/source-guards.yml").read_text(),
    )
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        roots, receipts = base / "roots", base / "receipts"
        roots.mkdir()
        receipts.mkdir()
        for (suite, runner), checks in coverage.items():
            value = dict(
                source=source,
                event=event,
                run_id=run_id,
                run_attempt="1",
                suite=suite,
                runner=runner,
                checks=checks,
                contract_sha256=digest(guard.CONTRACT.read_bytes()),
            )
            folder = receipts / (suite + runner)
            folder.mkdir()
            (folder / "suite-success.json").write_text(json.dumps(value) + "\n")
        with patch.dict(
            os.environ,
            {
                "GITHUB_EVENT_NAME": event,
                "GITHUB_RUN_ID": run_id,
                "GITHUB_RUN_ATTEMPT": "1",
            },
        ):
            for runner in RUNNERS:
                bundle(roots / runner, args.artifacts, args.controls, source, runner)

        def compare():
            compare_bundles(roots, receipts, source, event, run_id, attempt)

        compare()
        selected = roots / RUNNERS[0]
        saved = {}

        def write(path, raw):
            saved.setdefault(path, path.read_bytes())
            path.write_bytes(raw)

        def write_json(path, value):
            write(path, (json.dumps(value) + "\n").encode())

        def restore():
            for path, raw in saved.items():
                path.write_bytes(raw)
            saved.clear()

        def validate():
            return validate_bundle(selected, source, event, run_id, attempt)

        def refresh(path, relative):
            manifest_path = path / "bundle.json"
            manifest = json_value(read(manifest_path))
            for name in relative:
                raw = read(path / name)
                manifest["files"][name] = dict(bytes=len(raw), sha256=digest(raw))
            write_json(manifest_path, manifest)

        for label, key, changed, witness in (
            ("source", "source", "0" * 40, "wallet bundle source/run/event/suite mismatch"),
            ("run", "run_id", "74", "wallet bundle source/run/event/suite mismatch"),
            ("event", "event", "pull_request", "wallet bundle source/run/event/suite mismatch"),
            ("suite", "suite", "other", "wallet bundle source/run/event/suite mismatch"),
            ("kind", "kind", "other", "wallet bundle source/run/event/suite mismatch"),
            ("runner", "runner", "other", "wallet bundle runner mismatch"),
            ("future", "run_attempt", "3", "wallet bundle future attempt"),
        ):
            value = json_value(read(selected / "bundle.json"))
            value[key] = changed
            write_json(selected / "bundle.json", value)
            refused(label, validate, witness)
            restore()
        path = selected / "preparation/native/results.json"
        write(path, read(path) + b"\n")
        refused("digest-only", validate, "wallet bundle file digest mismatch")
        restore()
        extra = selected / "unexpected.json"
        extra.write_text("{}")
        refused("extra-path", validate, "generated directory population limit")
        extra.unlink()
        raw = read(path)
        path.unlink()
        refused("missing-path", validate, "wallet bundle paths")
        path.write_bytes(raw)
        path.unlink()
        path.symlink_to(args.artifacts.resolve() / "preparation/native/results.json")
        refused("symlink", validate, "invalid wallet-variant artifact")
        path.unlink()
        path.write_bytes(raw)
        control_path = selected / "controls.json"
        value = json_value(read(control_path))
        value["mutations"]["self_pay"].pop()
        write_json(control_path, value)
        refresh(selected, ["controls.json"])
        refused("coherent-missing-control", validate, "wallet controls population")
        restore()

        # Both architecture artifacts can agree with each other and still be
        # wrong. Refresh every changed manifest entry before checking the oracle.
        for runner in RUNNERS:
            directory = roots / runner
            prefix = "preparation/configuration-0/"
            native_name = prefix + "wallet-variant-root-native.json"
            oracles = json_value(read(directory / native_name))
            first = next(i for i, row in enumerate(oracles) if row["success"])
            other = next(
                row
                for row in oracles
                if row["success"] and row["transaction"] != oracles[first]["transaction"]
            )
            oracles[first] = copy.deepcopy(other)
            write_json(directory / native_name, oracles)
            lines = (
                read(directory / (prefix + "wallet-variant-roots.tsv")).decode().splitlines()[1:]
            )
            expected = "".join(
                "\t".join(wallet_expected(line.split("\t")[0], oracle)) + "\n"
                for line, oracle in zip(lines, oracles, strict=True)
            ).encode()
            changed_names = [native_name]
            for filename in (
                "wallet-variant-root-driver.stdout",
                "wallet-variant-root-expected.tsv",
            ):
                name = prefix + filename
                write(directory / name, expected)
                changed_names.append(name)
            refresh(directory, changed_names)
        refused(
            "both-architectures-coherent-wrong", compare, "wallet native baseline outcome or roots"
        )
        restore()
        duplicate = roots / "duplicate"
        shutil.copytree(selected, duplicate)
        refused("duplicate-attempt", compare, "duplicate wallet bundle attempt")
        shutil.rmtree(duplicate)
        arm = roots / RUNNERS[1]
        hidden = base / "hidden"
        arm.rename(hidden)
        refused(
            "missing-architecture", compare, "missing wallet bundle for successful suite attempt"
        )
        hidden.rename(arm)
        receipt_path = receipts / ("release-wallet" + RUNNERS[0]) / "suite-success.json"
        receipt = json_value(read(receipt_path))
        receipt["run_attempt"] = "2"
        write_json(receipt_path, receipt)
        refused(
            "stale-success-artifact", compare, "missing wallet bundle for successful suite attempt"
        )
        restore()
        shutil.copytree(selected, duplicate)
        value = json_value(read(duplicate / "bundle.json"))
        value.update(run_attempt="2", source="0" * 40)
        (duplicate / "bundle.json").write_text(json.dumps(value) + "\n")
        refused(
            "invalid-newer-cannot-hide", compare, "wallet bundle source/run/event/suite mismatch"
        )
        shutil.rmtree(duplicate)
        compare()

    metadata = [
        dict(name=PREFIX + runner + "-attempt-1", expired=False, size_in_bytes=100)
        for runner in RUNNERS
    ]
    assert artifact_selection(metadata, attempt, PREFIX) == 2
    for label, mutate, witness in (
        (
            "download-future",
            lambda x: x[0].update(name=PREFIX + RUNNERS[0] + "-attempt-3"),
            "download identity",
        ),
        (
            "download-duplicate",
            lambda x: x.append(x[0].copy()),
            "duplicate generated download identity",
        ),
        (
            "download-expired",
            lambda x: x[0].update(expired=True),
            "expired or invalid generated download metadata",
        ),
        (
            "download-oversize",
            lambda x: x[0].update(size_in_bytes=MAX_TOTAL + 1),
            "download size limit",
        ),
        (
            "download-runner",
            lambda x: x[0].update(name=PREFIX + "other-attempt-1"),
            "download identity",
        ),
    ):
        changed = copy.deepcopy(metadata)
        mutate(changed)
        refused(label, lambda: artifact_selection(changed, attempt, PREFIX), witness)
    assert (
        artifact_selection(
            metadata + [dict(name="rescue-roots-" + RUNNERS[0] + "-attempt-1")], attempt, PREFIX
        )
        == 2
    )
    assert (
        artifact_selection(
            [
                dict(name="rescue-roots-" + runner + "-attempt-1", expired=False, size_in_bytes=100)
                for runner in RUNNERS
            ],
            attempt,
        )
        == 2
    )
    args.output.write_text(
        json.dumps(
            dict(
                source=source,
                passed=True,
                controls=results,
                scope="Actual frozen wallet payloads; modeled run/attempt/receipt identities, not hosted CI acceptance.",
            ),
            indent=2,
        )
        + "\n"
    )
    print("PASS:", len(results), "wallet bundle/attempt/download controls")


if __name__ == "__main__":
    main()
