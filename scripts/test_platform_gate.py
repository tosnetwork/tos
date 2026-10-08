#!/usr/bin/env python3
"""Tests for scripts/platform_gate.py: relevance fails safe, the gate refuses gaps."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import platform_gate as gate

CONFIG = gate.load_config()
DOCS = CONFIG["documentation_only"]
MEMBERS = CONFIG["members"]
PLATFORM = {n for n, m in MEMBERS.items() if m["tier"] == "platform"}
NIGHTLY = {n for n, m in MEMBERS.items() if m["tier"] == "nightly"}


def needs(relevant: str | None = "true", changes: str = "success", **results: str) -> dict:
    out: dict = {
        "changes": {
            "result": changes,
            "outputs": {} if relevant is None else {"relevant": relevant},
        }
    }
    for name in MEMBERS:
        out[name] = {"result": results.get(name.replace("-", "_"), "skipped")}
    return out


def all_of(names: set[str], result: str = "success") -> dict[str, str]:
    return {n.replace("-", "_"): result for n in names}


class RelevanceTest(unittest.TestCase):
    def test_documentation_paths(self) -> None:
        for path in (
            "README.md",
            "doc/x/y.txt",
            "crypto/notes.md",
            "LICENSE",
            "LICENSE.LGPL",
            ".gitignore",
        ):
            self.assertTrue(gate.is_documentation(path, DOCS), path)

    def test_build_inputs_are_not_documentation(self) -> None:
        for path in (
            "CMakeLists.txt",
            ".github/workflows/platform-matrix.yml",
            "scripts/platform-matrix.json",
            "third-party/LICENSE",
            "docs/conf.py",
            "doc.cpp",
        ):
            self.assertFalse(gate.is_documentation(path, DOCS), path)

    def test_documentation_only_is_not_relevant(self) -> None:
        self.assertEqual(gate.decide(["README.md", "doc/a.md"], DOCS)[0], False)

    def test_one_build_input_makes_it_relevant(self) -> None:
        self.assertEqual(
            gate.decide(["README.md", "tdutils/td/utils/port/path.cpp"], DOCS)[0], True
        )

    def test_unknown_or_empty_lists_are_relevant(self) -> None:
        self.assertTrue(gate.decide(None, DOCS)[0])
        self.assertTrue(gate.decide([], DOCS)[0])

    def test_full_events_are_relevant_without_a_diff(self) -> None:
        for event in ("schedule", "workflow_dispatch"):
            self.assertTrue(gate.run_changes(event, {}, CONFIG)[0], event)

    def test_unknown_event_is_relevant(self) -> None:
        self.assertTrue(gate.run_changes("merge_group", {}, CONFIG)[0])


class GitRelevanceTest(unittest.TestCase):
    """changed_files against a real repository."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.dir.name)
        self.vcs("init", "-q", "-b", "main")
        self.vcs("config", "user.email", "ci@example.invalid")
        self.vcs("config", "user.name", "ci")
        self.base = self.commit("CMakeLists.txt", "base")
        self.vcs("update-ref", "refs/remotes/origin/main", self.base)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def vcs(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True
        ).stdout

    def commit(self, path: str, text: str) -> str:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        self.vcs("add", path)
        self.vcs("commit", "-q", "-m", path)
        return self.vcs("rev-parse", "HEAD").strip()

    def changes(self, event: str, env: dict[str, str]) -> bool:
        old = Path.cwd()
        try:
            os.chdir(self.repo)
            return gate.run_changes(event, env, CONFIG)[0]
        finally:
            os.chdir(old)

    def test_pull_request_documentation_only(self) -> None:
        head = self.commit("doc/guide.md", "words")
        self.assertFalse(self.changes("pull_request", {"BASE_REF": "main", "HEAD_SHA": head}))

    def test_pull_request_with_code(self) -> None:
        self.commit("doc/guide.md", "words")
        head = self.commit("crypto/vm/x.cpp", "int x;")
        self.assertTrue(self.changes("pull_request", {"BASE_REF": "main", "HEAD_SHA": head}))

    def test_pull_request_against_a_missing_base_is_relevant(self) -> None:
        head = self.commit("doc/guide.md", "words")
        self.assertTrue(self.changes("pull_request", {"BASE_REF": "absent", "HEAD_SHA": head}))

    def test_push_documentation_only(self) -> None:
        after = self.commit("README.md", "words")
        self.assertFalse(self.changes("push", {"BEFORE": self.base, "AFTER": after}))

    def test_push_of_a_new_branch_is_relevant(self) -> None:
        after = self.commit("README.md", "words")
        self.assertTrue(self.changes("push", {"BEFORE": gate.ZERO_SHA, "AFTER": after}))

    def test_push_after_a_force_push_is_relevant(self) -> None:
        after = self.commit("README.md", "words")
        self.assertTrue(self.changes("push", {"BEFORE": "1" * 40, "AFTER": after}))


class GateTest(unittest.TestCase):
    def verdict(self, event: str, context: dict) -> bool:
        return gate.evaluate(event, context, CONFIG)[0]

    def test_all_platform_members_succeed(self) -> None:
        self.assertTrue(self.verdict("pull_request", needs(**all_of(PLATFORM))))

    def test_expected_member_skipped_fails(self) -> None:
        results = all_of(PLATFORM)
        results["wasm"] = "skipped"
        self.assertFalse(self.verdict("pull_request", needs(**results)))

    def test_expected_member_cancelled_fails(self) -> None:
        results = all_of(PLATFORM)
        results["windows_msvc"] = "cancelled"
        self.assertFalse(self.verdict("push", needs(**results)))

    def test_unexpected_member_that_failed_fails(self) -> None:
        results = all_of(PLATFORM)
        results["cppcheck"] = "failure"
        self.assertFalse(self.verdict("pull_request", needs(**results)))

    def test_nightly_members_are_expected_on_schedule(self) -> None:
        self.assertFalse(self.verdict("schedule", needs(**all_of(PLATFORM))))
        self.assertTrue(self.verdict("schedule", needs(**all_of(PLATFORM | NIGHTLY))))
        self.assertTrue(self.verdict("workflow_dispatch", needs(**all_of(PLATFORM | NIGHTLY))))

    def test_documentation_only_change_is_not_applicable(self) -> None:
        passed, lines = gate.evaluate("pull_request", needs(relevant="false"), CONFIG)
        self.assertTrue(passed)
        self.assertIn("not applicable", lines[0])

    def test_relevance_job_failed_fails(self) -> None:
        self.assertFalse(self.verdict("pull_request", needs(changes="failure", **all_of(PLATFORM))))

    def test_relevance_output_missing_fails(self) -> None:
        self.assertFalse(self.verdict("pull_request", needs(relevant=None, **all_of(PLATFORM))))

    def test_relevance_output_invalid_fails(self) -> None:
        self.assertFalse(self.verdict("pull_request", needs(relevant="yes", **all_of(PLATFORM))))

    def test_member_missing_from_needs_fails(self) -> None:
        context = needs(**all_of(PLATFORM))
        del context["wasm"]
        self.assertFalse(self.verdict("pull_request", context))

    def test_unknown_job_in_needs_fails(self) -> None:
        context = needs(**all_of(PLATFORM))
        context["surprise"] = {"result": "success"}
        self.assertFalse(self.verdict("pull_request", context))


if __name__ == "__main__":
    unittest.main()
