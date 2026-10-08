#!/usr/bin/env python3
"""Tests for scripts/nightly_report.py's issue decisions."""

from __future__ import annotations

import unittest

import nightly_report as report

URL = "https://example.invalid/run/1"


def job(name: str, conclusion: str) -> dict:
    return {"name": name, "conclusion": conclusion}


class NightlyReportTest(unittest.TestCase):
    def test_failing_members_group_by_caller_job(self) -> None:
        jobs = [
            job("matrix / changes", "success"),
            job("matrix / wasm / build", "failure"),
            job("matrix / windows-msvc / build", "cancelled"),
            job("matrix / cppcheck / build", "skipped"),
            job("matrix / platform-gate", "failure"),
            job("nightly-report", None),
        ]
        self.assertEqual(report.failing_members(jobs), ["platform-gate", "wasm", "windows-msvc"])

    def test_first_failure_opens_the_issue(self) -> None:
        actions = report.plan("failure", [job("wasm / build", "failure")], None, URL)
        self.assertEqual([a for a, _ in actions], ["create"])
        self.assertIn("- wasm", actions[0][1])

    def test_later_failure_comments_on_the_open_issue(self) -> None:
        actions = report.plan("failure", [job("wasm / build", "failure")], 7, URL)
        self.assertEqual([a for a, _ in actions], ["comment"])

    def test_green_night_closes_the_issue(self) -> None:
        actions = report.plan("success", [job("wasm / build", "success")], 7, URL)
        self.assertEqual([a for a, _ in actions], ["comment", "close"])

    def test_green_night_without_an_issue_does_nothing(self) -> None:
        self.assertEqual(report.plan("success", [job("wasm / build", "success")], None, URL), [])

    def test_a_failed_run_without_a_failed_job_still_reports(self) -> None:
        actions = report.plan("cancelled", [job("wasm / build", "success")], None, URL)
        self.assertEqual([a for a, _ in actions], ["create"])
        self.assertIn("cancelled", actions[0][1])


if __name__ == "__main__":
    unittest.main()
