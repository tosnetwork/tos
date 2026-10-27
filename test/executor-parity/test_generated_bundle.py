"""Exercise actual small bundles, mixed-attempt reruns and fail-closed admission."""

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import generated_bundle as gate
from generated_roots import ROOT

OPTIONS = None


class GeneratedBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="generated-bundle-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.template = Path(cls.temporary.name)
        cls.source = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        cls.environment = dict(
            GITHUB_EVENT_NAME="pull_request", GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2"
        )
        guard = gate.receipt_guard()
        coverage = guard.validate(
            guard.WORKFLOW.read_text(),
            json.loads(guard.CONTRACT.read_text()),
            (ROOT / ".github/workflows/source-guards.yml").read_text(),
        )
        for pair in sorted(coverage):
            suite, runner = pair
            attempt = "2" if pair == ("release-wallet", gate.RUNNERS[1]) else "1"
            with patch.dict(os.environ, cls.environment | {"GITHUB_RUN_ATTEMPT": attempt}):
                receipt = guard.receipt(suite, runner, coverage)
            path = cls.template / "receipts" / (suite + "-" + runner) / "suite-success.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(receipt))
        for index, runner in enumerate(gate.RUNNERS):
            with patch.dict(os.environ, cls.environment | {"GITHUB_RUN_ATTEMPT": str(index + 1)}):
                gate.bundle(
                    cls.template / "roots" / runner,
                    OPTIONS.release,
                    OPTIONS.post,
                    OPTIONS.controls,
                    cls.source,
                    runner,
                )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="generated-bundle-case-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "case"
        shutil.copytree(self.template, self.root)

    def verify(self, root=None):
        root = root or self.root
        return gate.compare_bundles(
            root / "roots", root / "receipts", self.source, "pull_request", "123", "2"
        )

    def bundle(self, runner=None):
        return self.root / "roots" / (runner or gate.RUNNERS[1])

    def metadata(self, change, directory=None):
        path = (directory or self.bundle()) / "bundle.json"
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def refresh(self, name, directory=None):
        directory = directory or self.bundle()
        data = (directory / name).read_bytes()
        self.metadata(
            lambda m: m["files"].__setitem__(
                name, dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            ),
            directory,
        )

    def test_actual_bundles_and_valid_mixed_attempts(self):
        self.verify()
        older = self.root / "roots" / "older-arm"
        shutil.copytree(self.bundle(), older)
        self.metadata(lambda m: m.update(run_attempt="1"), older)
        self.verify()

    def test_latest_bad_bundle_never_falls_back(self):
        older = self.root / "roots" / "older-arm"
        shutil.copytree(self.bundle(), older)
        self.metadata(lambda m: m.update(run_attempt="1"), older)
        path = self.root / "receipts" / ("release-wallet-" + gate.RUNNERS[1]) / "suite-success.json"
        receipt = json.loads(path.read_text())
        receipt["run_attempt"] = "1"
        path.write_text(json.dumps(receipt))
        path = self.bundle() / "controls.json"
        value = json.loads(path.read_text())
        value["passed"] = False
        path.write_text(json.dumps(value))
        self.refresh("controls.json")
        with self.assertRaisesRegex(AssertionError, "generated controls incomplete"):
            self.verify()

    def test_bundle_attempt_must_match_success_receipt(self):
        self.metadata(lambda m: m.update(run_attempt="1"))
        with self.assertRaisesRegex(
            AssertionError, "missing generated bundle for successful suite attempt"
        ):
            self.verify()

    def test_all_candidate_identities_checked(self):
        for key, value in [
            ("source", "0" * 40),
            ("event", "workflow_dispatch"),
            ("run_id", "124"),
            ("suite", "mutations"),
            ("runner", "unrecognized"),
            ("run_attempt", "3"),
        ]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "case"
                shutil.copytree(self.template, root)
                path = root / "roots" / gate.RUNNERS[1] / "bundle.json"
                metadata = json.loads(path.read_text())
                metadata[key] = value
                path.write_text(json.dumps(metadata))
                with self.assertRaisesRegex(
                    AssertionError,
                    "generated bundle (source/run/event/suite mismatch|runner mismatch|future attempt)",
                ):
                    self.verify(root)

    def test_duplicate_bundle_identity_rejected(self):
        shutil.copytree(self.bundle(), self.root / "roots" / "duplicate")
        with self.assertRaisesRegex(AssertionError, "duplicate generated bundle attempt"):
            self.verify()

    def test_missing_architecture_rejected(self):
        shutil.rmtree(self.bundle())
        with self.assertRaisesRegex(
            AssertionError, "missing generated bundle for successful suite attempt"
        ):
            self.verify()

    def test_unknown_paths_and_manifest_paths_rejected(self):
        self.metadata(
            lambda m: m["files"].__setitem__("../../outside", dict(bytes=0, sha256="0" * 64))
        )
        with self.assertRaisesRegex(AssertionError, "generated bundle manifest paths mismatch"):
            self.verify()
        self.metadata(lambda m: m["files"].pop("../../outside"))
        (self.bundle() / "extra").write_text("unexpected")
        with self.assertRaisesRegex(AssertionError, "generated directory population limit"):
            self.verify()

    def test_symlink_rejected_before_file_read(self):
        path = self.bundle() / "release/config.boc"
        path.unlink()
        path.symlink_to(OPTIONS.release / "config.boc")
        with self.assertRaisesRegex(AssertionError, "invalid generated bundle file"):
            self.verify()

    def test_file_size_bound_before_read(self):
        path = self.bundle() / "release/config.boc"
        with path.open("wb") as stream:
            stream.truncate(gate.MAX_FILE + 1)
        with self.assertRaisesRegex(AssertionError, "generated bundle file size limit"):
            self.verify()

    def test_exact_total_byte_budget(self):
        size = sum(
            (self.bundle() / name).stat().st_size for name in gate.filenames() | {"bundle.json"}
        )
        with patch.object(gate, "MAX_TOTAL", size):
            gate.validate_bundle(self.bundle(), self.source, "pull_request", "123", "2")
        with (
            patch.object(gate, "MAX_TOTAL", size - 1),
            self.assertRaisesRegex(AssertionError, "generated bundle total size limit"),
        ):
            gate.validate_bundle(self.bundle(), self.source, "pull_request", "123", "2")

    def test_actual_contents_bound_by_digest(self):
        (self.bundle() / "release/native.tsv").write_text("changed\n")
        with self.assertRaisesRegex(AssertionError, "generated bundle file digest mismatch"):
            self.verify()

    def test_root_validation_cannot_be_replaced_by_manifest_hashes(self):
        name = "release/generated-release-config-root-driver.stdout"
        path = self.bundle() / name
        lines = path.read_text().splitlines()
        fields = lines[0].split("\t")
        fields[2] = "0" * 64
        lines[0] = "\t".join(fields)
        path.write_text("\n".join(lines) + "\n")
        self.refresh(name)
        with self.assertRaisesRegex(AssertionError, "generated root mismatch"):
            self.verify()

    def test_download_selection_bounds_and_identities(self):
        original = [
            dict(name=f"rescue-roots-{runner}-attempt-1", expired=False, size_in_bytes=100)
            for runner in gate.RUNNERS
        ]
        self.assertEqual(gate.artifact_selection(original, "2"), 2)
        for key, value in [
            ("name", "rescue-roots-other"),
            ("name", "rescue-roots-ubuntu-24.04-attempt-3"),
            ("expired", True),
            ("size_in_bytes", gate.MAX_TOTAL + 1),
        ]:
            with self.subTest(key=key, value=value):
                damaged = copy.deepcopy(original)
                damaged[0][key] = value
                with self.assertRaises(AssertionError):
                    gate.artifact_selection(damaged, "2")
        with self.assertRaisesRegex(AssertionError, "duplicate generated download identity"):
            gate.artifact_selection(original + original[:1], "2")
        at_limit = [
            dict(name=f"rescue-roots-ubuntu-24.04-attempt-{i}", expired=False, size_in_bytes=100)
            for i in range(1, gate.MAX_BUNDLES + 1)
        ]
        self.assertEqual(gate.artifact_selection(at_limit, str(gate.MAX_BUNDLES)), gate.MAX_BUNDLES)
        with self.assertRaisesRegex(AssertionError, "generated download population limit"):
            gate.artifact_selection(at_limit + at_limit[:1], str(gate.MAX_BUNDLES))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--post", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    OPTIONS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining])
