"""Snapshot reuse must never hide a changed or unproven validation context."""

import copy
import importlib.util
import io
import json
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "ci_snapshot", Path(__file__).with_name("ci-snapshot.py")
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def zipped(receipt, name="ci-snapshot-native.json"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, json.dumps(receipt))
    return buffer.getvalue()


class FakeApi:
    def __init__(self, identity):
        self.run = {
            "id": 10,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "head_sha": identity["head"],
            "event": "pull_request",
            "path": identity["workflow"],
        }
        self.artifact = {
            "id": 20,
            "name": mod.artifact_name(identity["job"]) + "-attempt-1",
            "expired": False,
            "size_in_bytes": 1000,
        }
        self.receipt = {
            "identity": copy.deepcopy(identity),
            "run_id": 10,
            "run_attempt": 1,
            "executed": True,
        }
        self.downloads = 0

    def json(self, path):
        if "/workflows/" in path:
            return {"workflow_runs": [self.run]}
        return {"artifacts": [self.artifact]}

    def read(self, path, limit):
        self.downloads += 1
        return zipped(self.receipt)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "schema": 1,
            "repository": "owner/repo",
            "pr": 1,
            "head": "a" * 40,
            "base": "b" * 40,
            "tree": "c" * 40,
            "workflow": ".github/workflows/check.yml",
            "workflow_blob": "d" * 40,
            "job": "native",
        }
        self.api = FakeApi(self.identity)
        self.env = {"GH_TOKEN": "test-token", "GITHUB_RUN_ID": "11", "GITHUB_RUN_ATTEMPT": "1"}

    def decide(self, action="ready_for_review"):
        return mod.decide(self.identity, {"action": action}, self.env, self.api)

    def test_only_ready_can_reuse_a_fully_successful_prior_run(self):
        self.assertEqual(self.decide(), 10)
        for action in ["opened", "synchronize", "reopened", None]:
            self.assertIsNone(self.decide(action))
        self.assertIsNone(mod.decide(None, {"action": "ready_for_review"}, self.env, self.api))
        for field, value in [
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("event", "push"),
            ("head_sha", "wrong"),
            ("path", "wrong"),
            ("id", 11),
        ]:
            with self.subTest(field=field):
                original = self.api.run.copy()
                self.api.run[field] = value
                self.assertIsNone(self.decide())
                self.api.run = original

    def test_every_snapshot_dimension_and_provenance_must_match(self):
        for field in self.identity:
            with self.subTest(field=field):
                self.api.receipt["identity"][field] = "changed"
                self.assertIsNone(self.decide())
                self.api.receipt["identity"] = self.identity.copy()
        for field, value in [
            ("run_id", 9),
            ("run_attempt", 2),
            ("executed", False),
            ("executed", 1),
        ]:
            with self.subTest(field=field, value=value):
                original = self.api.receipt.copy()
                self.api.receipt[field] = value
                self.assertIsNone(self.decide())
                self.api.receipt = original

    def test_missing_or_bad_evidence_runs_all_tests(self):
        for field, value in [
            ("expired", True),
            ("name", "other-job"),
            ("size_in_bytes", mod.MAX_ARCHIVE + 1),
            ("size_in_bytes", 0),
        ]:
            with self.subTest(field=field):
                original = self.api.artifact.copy()
                self.api.artifact[field] = value
                self.assertIsNone(self.decide())
                self.api.artifact = original
        with patch.object(self.api, "json", side_effect=OSError("unavailable")):
            self.assertIsNone(self.decide())
        with patch.object(self.api, "read", return_value=b"not a zip"):
            self.assertIsNone(self.decide())
        with patch.object(self.api, "json", return_value={"workflow_runs": []}):
            self.assertIsNone(self.decide())
        self.assertIsNone(mod.decide(self.identity, {"action": "ready_for_review"}, {}, self.api))

    def test_partial_retry_accepts_earlier_executed_attempt_but_rejects_future_evidence(self):
        self.api.run["run_attempt"] = 2
        self.assertEqual(self.decide(), 10)
        self.api.artifact["name"] = mod.artifact_name("native") + "-attempt-3"
        self.assertIsNone(self.decide())

    def test_cli_output_never_skips_a_changed_snapshot(self):
        import os
        import sys

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            env = dict(
                self.env,
                GITHUB_OUTPUT=str(output),
                GITHUB_STEP_SUMMARY=str(Path(directory) / "summary"),
                GITHUB_REPOSITORY="owner/repo",
            )
            for changed in (False, True):
                output.write_text("")
                self.api.receipt["identity"] = self.identity.copy()
                if changed:
                    self.api.receipt["identity"]["base"] = "new-base"
                with (
                    patch.dict(os.environ, env),
                    patch.object(sys, "argv", ["snapshot", "--job", "native"]),
                    patch.object(
                        mod, "context", return_value=(self.identity, {"action": "ready_for_review"})
                    ),
                    patch.object(mod, "Api", return_value=self.api),
                ):
                    mod.main()
                self.assertEqual(
                    output.read_text(), "run-tests=" + ("true" if changed else "false") + "\n"
                )

    def test_zip_is_bounded_and_never_extracted(self):
        self.assertEqual(mod.archive_receipt(zipped(self.api.receipt)), self.api.receipt)
        for name in [
            "../ci-snapshot-native.json",
            "/ci-snapshot-native.json",
            "nested/receipt.json",
        ]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                mod.archive_receipt(zipped(self.api.receipt, name))
        with self.assertRaises(ValueError):
            mod.archive_receipt(b"x" * (mod.MAX_ARCHIVE + 1))
        with self.assertRaises(ValueError):
            mod.archive_receipt(zipped({"oversized": "x" * (mod.MAX_RECEIPT + 1)}))

    def test_redirect_does_not_forward_api_credentials(self):
        request = urllib.request.Request(
            "https://api.github.com/artifact", headers={"Authorization": "Bearer secret"}
        )
        handler = mod.StripRedirectCredentials()
        redirected = handler.redirect_request(
            request, None, 302, "Found", {}, "https://storage.example/file"
        )
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://storage.example/file")

    def test_record_rejects_dirty_source_and_binds_current_run(self):
        import subprocess

        with tempfile.TemporaryDirectory() as directory:
            env = dict(self.env, RUNNER_TEMP=directory)
            with patch.object(
                mod.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git diff")
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    mod.record(self.identity, "native", env)
                self.assertFalse(list(Path(directory).iterdir()))
            with patch.object(mod.subprocess, "run"):
                mod.record(self.identity, "native", env)
            receipt = json.loads(mod.receipt_path("native", env).read_text())
            self.assertEqual(
                receipt,
                {"identity": self.identity, "run_id": 11, "run_attempt": 1, "executed": True},
            )
            with self.assertRaises(ValueError):
                mod.receipt_path("../escape", env)

    def test_context_captures_actual_checkout_and_event_base(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "action": "ready_for_review",
                        "pull_request": {
                            "number": 1,
                            "head": {"sha": "a" * 40},
                            "base": {"sha": "b" * 40},
                        },
                    }
                )
            )
            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/check.yml@refs/pull/1/merge",
            }
            with patch.object(mod, "git", side_effect=["c" * 40, "d" * 40]):
                identity, _ = mod.context("native", env)
            self.assertEqual(identity, self.identity)
            env["GITHUB_EVENT_NAME"] = "push"
            self.assertIsNone(mod.context("native", env)[0])


if __name__ == "__main__":
    unittest.main()
