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
import json
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
profiles = release.profiles


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
        for name, selected in profiles.PROFILES.items():
            with self.subTest(profile=name):
                artifact = release.decode_base64_file(ROOT / selected["artifact_base64"])
                sdk = release.sdk_code(ROOT / selected["sdk"], selected["sdk_constant"])
                self.assertEqual(artifact, sdk)

    def test_each_test_artifact_differs_from_its_release_artifact(self):
        self.assertEqual(
            profiles.TEST_PAIRS,
            ((profiles.RELEASE, profiles.TEST), (profiles.TOKEN, profiles.TOKEN_TEST)),
        )
        for released, tested in profiles.TEST_PAIRS:
            release_boc, test_boc = (
                release.decode_base64_file(ROOT / profiles.PROFILES[name]["artifact_base64"])
                for name in (released, tested)
            )
            with self.subTest(pair=(released, tested)):
                self.assertNotEqual(release_boc, test_boc)

    def test_each_profile_names_its_rails_contract_and_source(self):
        for name, selected in profiles.PROFILES.items():
            with self.subTest(profile=name):
                fields = release.expected_fields(name)
                self.assertEqual(fields["source"], selected["source"])
                self.assertEqual(fields["contract"], selected["contract"])
        self.assertEqual(profiles.PROFILES[profiles.TOKEN]["source"], profiles.TOKEN_SOURCE)

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


class TestProfile(unittest.TestCase):
    """The test-only build may change exactly the listed lower bounds."""

    SOURCE = (
        "const int MIN_RESPONSE_SLA = 3600; ;; 1 hour\n"
        "const int MAX_RESPONSE_SLA = 2592000;\n"
        "const int MIN_REFUND_CLAIM_WINDOW = 3600; ;; 1 hour\n"
    )

    def test_the_overrides_are_exactly_the_two_lower_bounds(self):
        self.assertEqual(
            profiles.TEST_OVERRIDES, {"MIN_RESPONSE_SLA": 600, "MIN_REFUND_CLAIM_WINDOW": 600}
        )
        self.assertEqual(profiles.PROFILES[profiles.RELEASE]["overrides"], {})
        self.assertEqual(profiles.PROFILES[profiles.TOKEN]["overrides"], {})
        self.assertEqual(
            profiles.PROFILES[profiles.TOKEN_TEST]["overrides"], profiles.TEST_OVERRIDES
        )

    def test_the_token_test_source_differs_from_its_source_in_two_lines(self):
        with tempfile.TemporaryDirectory() as work:
            derived = profiles.source_for(profiles.TOKEN_TEST, Path(work)).read_text().splitlines()
            original = (ROOT / profiles.TOKEN_SOURCE).read_text().splitlines()
            changed = [(a, b) for a, b in zip(original, derived) if a != b]
            self.assertEqual(len(original), len(derived))
            self.assertEqual(
                [a.split(" = ")[0] for a, _ in changed],
                ["const int MIN_RESPONSE_SLA", "const int MIN_REFUND_CLAIM_WINDOW"],
            )

    def test_only_the_named_values_change(self):
        derived = profiles.apply_overrides(self.SOURCE, profiles.TEST_OVERRIDES)
        self.assertEqual(
            derived,
            "const int MIN_RESPONSE_SLA = 600; ;; 1 hour\n"
            "const int MAX_RESPONSE_SLA = 2592000;\n"
            "const int MIN_REFUND_CLAIM_WINDOW = 600; ;; 1 hour\n",
        )

    def test_a_missing_or_repeated_declaration_is_refused(self):
        for text in (
            "const int MIN_RESPONSE_SLA = 3600;\n",
            self.SOURCE + "const int MIN_RESPONSE_SLA = 3600;\n",
            self.SOURCE.replace("const int MIN_RESPONSE_SLA", ";; const int MIN_RESPONSE_SLA"),
        ):
            with self.subTest(text=text), self.assertRaises(profiles.ProfileError):
                profiles.apply_overrides(text, profiles.TEST_OVERRIDES)

    def test_an_override_that_does_not_lower_the_bound_is_refused(self):
        for value in (3600, 7200, 0, -1, True):
            with self.subTest(value=value), self.assertRaises(profiles.ProfileError):
                profiles.apply_overrides(self.SOURCE, {"MIN_RESPONSE_SLA": value})

    def test_an_unknown_profile_is_refused(self):
        with self.assertRaises(profiles.ProfileError):
            profiles.profile("production")

    def test_the_derived_source_differs_from_the_checkout_in_two_lines(self):
        with tempfile.TemporaryDirectory() as work:
            derived = profiles.source_for(profiles.TEST, Path(work)).read_text().splitlines()
            original = (ROOT / profiles.SOURCE).read_text().splitlines()
            self.assertEqual(len(original), len(derived))
            changed = [(a, b) for a, b in zip(original, derived) if a != b]
            self.assertEqual(
                changed,
                [
                    (
                        "const int MIN_RESPONSE_SLA = 3600; ;; 1 hour",
                        "const int MIN_RESPONSE_SLA = 600; ;; 1 hour",
                    ),
                    (
                        "const int MIN_REFUND_CLAIM_WINDOW = 3600; ;; 1 hour",
                        "const int MIN_REFUND_CLAIM_WINDOW = 600; ;; 1 hour",
                    ),
                ],
            )
        self.assertEqual(
            profiles.source_for(profiles.RELEASE, Path("/nonexistent")),
            (ROOT / profiles.SOURCE).resolve(),
        )


class ProfileManifests(unittest.TestCase):
    def manifest(self, name):
        return json.loads((ROOT / profiles.PROFILES[name]["manifest"]).read_text())

    def test_the_checked_in_manifests_pass(self):
        for name in profiles.PROFILES:
            with self.subTest(profile=name):
                release.check_profile_fields(self.manifest(name), name, ROOT)

    def test_the_release_manifest_refuses_profile_fields(self):
        for key in release.PROFILE_FIELDS:
            manifest = dict(self.manifest(profiles.RELEASE), **{key: True})
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(release.ReleaseError, "must not carry profile fields"),
            ):
                release.check_profile_fields(manifest, profiles.RELEASE, ROOT)

    def test_the_test_manifest_refusals(self):
        released = self.manifest(profiles.RELEASE)
        cases = {
            "test_only false": ({"test_only": False}, "test_only"),
            "test_only missing": ({"test_only": None}, "test_only"),
            "notice": ({"notice": "test build"}, "notice"),
            "overrides": ({"constant_overrides": {"MIN_RESPONSE_SLA": 600}}, "constant_overrides"),
            "release code hash": ({"code_hash": released["code_hash"]}, "equals the release code"),
            "release BOC": ({"boc_sha256": released["boc_sha256"]}, "equals the release BOC"),
            "profile": ({"profile": "release"}, "profile"),
        }
        for label, (change, message) in cases.items():
            manifest = dict(self.manifest(profiles.TEST), **change)
            with self.subTest(case=label), self.assertRaisesRegex(release.ReleaseError, message):
                release.check_profile_fields(manifest, profiles.TEST, ROOT)

    def test_a_changed_release_artifact_fails_the_test_profile_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for selected in profiles.PROFILES.values():
                for key in ("manifest", "artifact_base64"):
                    target = root / selected[key]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((ROOT / selected[key]).read_bytes())
            artifact = root / profiles.PROFILES[profiles.RELEASE]["artifact_base64"]
            lines = artifact.read_text().splitlines(keepends=True)
            line = lines[3]
            lines[3] = line[:5] + ("A" if line[5] != "A" else "B") + line[6:]
            artifact.write_text("".join(lines))
            with self.assertRaisesRegex(release.ReleaseError, "release artifact differs"):
                release.check_profile_fields(self.manifest(profiles.TEST), profiles.TEST, root)


if __name__ == "__main__":
    unittest.main()
