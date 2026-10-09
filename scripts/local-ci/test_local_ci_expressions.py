#!/usr/bin/env python3
"""The local replay evaluates expressions as GitHub does, short-circuits included."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("local_ci", HERE / "local_ci.py")
local_ci = importlib.util.module_from_spec(SPEC)
sys.modules["local_ci"] = local_ci
SPEC.loader.exec_module(local_ci)

WORKFLOW = HERE.parents[1] / ".github" / "workflows" / "connect-trust.yml"
ROUTED = ["self-hosted", "linux", "x64", "tos-vm"]


def evaluator(variables: dict | None = None, login: str = "trusted") -> local_ci.Evaluator:
    github = {
        "event_name": "pull_request",
        "ref": "refs/pull/1/merge",
        "repository": "tosnetwork/tos",
        "triggering_actor": login,
        "event": {
            "pull_request": {
                "head": {"repo": {"full_name": "tosnetwork/tos"}},
                "user": {"login": login},
            }
        },
    }
    contexts = {"github": github, "matrix": {}}
    if variables is not None:
        contexts["vars"] = variables
    return local_ci.Evaluator(contexts, {"failed": False}, lambda patterns: "")


class ExpressionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runs_on = yaml.safe_load(WORKFLOW.read_text())["jobs"]["connect-trust"]["runs-on"]

    def test_the_routing_expression_without_variables_is_hosted(self) -> None:
        self.assertEqual(local_ci.interpolate(self.runs_on, evaluator()), "ubuntu-24.04")

    def test_the_routing_expression_for_a_trusted_pull_request_is_routed(self) -> None:
        variables = {"SELF_HOSTED_LINUX": "true", "CI_TRUSTED_LOGINS": '["trusted"]'}
        self.assertEqual(local_ci.interpolate(self.runs_on, evaluator(variables)), ROUTED)
        self.assertEqual(
            local_ci.interpolate(self.runs_on, evaluator(variables, login="other")), "ubuntu-24.04"
        )

    def test_and_does_not_evaluate_its_right_side_after_false(self) -> None:
        self.assertEqual(evaluator().evaluate("false && fromJSON('')"), False)

    def test_or_does_not_evaluate_its_right_side_after_true(self) -> None:
        self.assertEqual(evaluator().evaluate("'x' || fromJSON('')"), "x")

    def test_the_deciding_side_is_still_evaluated(self) -> None:
        self.assertEqual(evaluator().evaluate("true && fromJSON('[1]')"), [1])
        self.assertEqual(evaluator().evaluate("false || fromJSON('[2]')"), [2])
        with self.assertRaises(ValueError):
            evaluator().evaluate("true && fromJSON('')")


if __name__ == "__main__":
    unittest.main()
