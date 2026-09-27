"""Offline completion control for the retained full PQ launch gate."""

import ast
import os
from pathlib import Path
from types import SimpleNamespace
import unittest


SOURCE = Path(os.environ.get("E11_ROUTE_SOURCE", Path(__file__).with_name("validator-election-stage-a.py")))


def report_status(stage):
    tree = ast.parse(SOURCE.read_text())
    method = next(
        method
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ValidatorElectionRehearsal"
        for method in node.body
        if isinstance(method, ast.FunctionDef) and method.name == "report_status"
    )
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(SOURCE), "exec"), namespace)
    return namespace["report_status"](stage)


class TestFullPqCompletion(unittest.TestCase):
    def stage(self, events, *, full=True, failures=(), experiment=None, final=None):
        return SimpleNamespace(
            pq_full=full, events=[{"event": event} for event in events],
            failures=list(failures), experiment=experiment,
            experiment_final_status=final,
        )

    def test_missing_terminal_event_fails(self):
        self.assertEqual(report_status(self.stage([])), "fail")
        self.assertEqual(report_status(self.stage(["pq_first_election_activated"])), "fail")

    def test_complete_full_route_passes(self):
        self.assertEqual(report_status(self.stage(["pq_full_launch_gate_passed"])), "pass")

    def test_other_modes_and_existing_failure_gate(self):
        self.assertEqual(report_status(self.stage([], full=False)), "pass")
        self.assertEqual(report_status(self.stage(["pq_full_launch_gate_passed"], failures=["bad"])), "fail")
        self.assertEqual(report_status(self.stage([], full=False, experiment=object(), final="partial-settlement")), "fail")


if __name__ == "__main__":
    unittest.main()
