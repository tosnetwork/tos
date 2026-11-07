#!/usr/bin/env python3
"""Controls for the Service Actor release check that need no compiler.

The provenance check must distinguish exactly: a matching commit (checked), a
commit absent from a shallow history (explicit note), and three refusals -- a
differing source or include, an object that is not a commit, and a Git failure.
The include closure must follow nested includes. The SDK and artifact decoders
must refuse a different BOC even when the root cell is the same.

Runs with the standard library only: python3 scripts/test_tos_service_actor_release.py
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "tos_service_actor_release", ROOT / "scripts/tos_service_actor_release.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def git(directory: Path, *args: str) -> str:
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="test",
        GIT_AUTHOR_EMAIL="test@invalid",
        GIT_COMMITTER_NAME="test",
        GIT_COMMITTER_EMAIL="test@invalid",
    )
    return subprocess.run(
        ["git", *args], cwd=directory, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


class Provenance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q")
        (self.repo / "a.fc").write_text('#include "b.fc";\n')
        (self.repo / "b.fc").write_text('#include "c.fc";\n')
        (self.repo / "c.fc").write_text("() c() {}\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "release")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        self.paths = release.include_closure(self.repo / "a.fc", self.repo)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_include_closure_follows_nested_includes(self):
        self.assertEqual(self.paths, ["a.fc", "b.fc", "c.fc"])

    def test_a_matching_commit_is_checked(self):
        self.assertEqual(release.check_provenance(self.commit, self.paths, self.repo), "checked")

    def test_a_changed_nested_include_is_refused(self):
        (self.repo / "c.fc").write_text("() c() { changed(); }\n")
        with self.assertRaisesRegex(release.ReleaseError, "differs from tos_commit"):
            release.check_provenance(self.commit, self.paths, self.repo)

    def test_an_absent_commit_is_reported_unavailable(self):
        absent = "1" * 40
        self.assertEqual(release.check_provenance(absent, self.paths, self.repo), "unavailable")

    def test_an_object_that_is_not_a_commit_is_refused(self):
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        with self.assertRaisesRegex(release.ReleaseError, "not a commit"):
            release.check_provenance(tree, self.paths, self.repo)

    def test_a_git_failure_is_refused(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        with self.assertRaisesRegex(release.ReleaseError, "git cat-file failed"):
            release.check_provenance(self.commit, self.paths, Path(outside.name))

    def test_a_malformed_commit_is_refused(self):
        for value in (self.commit[:12], self.commit.upper(), "z" * 40):
            with self.subTest(value=value), self.assertRaises(release.ReleaseError):
                release.check_provenance(value, self.paths, self.repo)


class FrozenBytes(unittest.TestCase):
    def test_the_frozen_artifact_and_sdk_constant_are_the_same_bytes(self):
        manifest_artifact = ROOT / release.EXPECTED_FIELDS["artifact_base64"]
        self.assertEqual(release.decode_base64_file(manifest_artifact), release.sdk_code())

    def test_build_output_must_report_every_pinned_field(self):
        complete = "code_hash=a\nboc_sha256=b\nboc_bytes=1\ncompiler_arguments=-W x\n"
        self.assertEqual(release.parse_build_output(complete)["boc_bytes"], "1")
        for missing in ("code_hash", "boc_sha256", "boc_bytes", "compiler_arguments"):
            text = "".join(
                line + "\n" for line in complete.splitlines() if not line.startswith(missing)
            )
            with self.subTest(missing=missing), self.assertRaises(release.ReleaseError):
                release.parse_build_output(text)
        with self.assertRaises(release.ReleaseError):
            release.parse_build_output(complete + "boc_bytes=2\n")


if __name__ == "__main__":
    unittest.main()
