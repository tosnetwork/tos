#!/usr/bin/env python3
"""Scenario selection, budgets and the D (100% directed) phase of the four-node coordinator.

No network, tc or StageA: the D phase runs with its policy builder, runner, clock and
StageA handle replaced, so each refusal is shown to stop before the fault is started or
to turn the run red after it. P is checked to keep its reviewed preset and budget.
"""

import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import x02_directed_run as runner  # noqa: E402
import x02_four_node_binding as closure  # noqa: E402


def load(name, raw):
    module = types.ModuleType(name)
    module.__file__ = str(REPO / "scripts/x02_four_node.py")
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


four_node = load(
    "x02_four_node_directed_under_test", (REPO / "scripts/x02_four_node.py").read_bytes()
)
# Frozen by x02_fault_evidence.validate_policy for every directed policy.
THRESHOLDS = {
    "three_max_seconds": 120,
    "two_drain_seconds": 30,
    "recovery_max_seconds": 180,
    "three_min_delta": 2,
    "recovery_min_delta": 2,
}
# The argv every P binding carried before scenarios existed (cfb80f19).
OLD_P_ARGV_TAIL = [
    "--base-port",
    "32600",
    "--rpc-base-port",
    "34600",
    "--duration-seconds",
    "420",
    "--settlement-tail-seconds",
    "600",
    "--sample-interval",
    "5",
]


def binding(scenario, **extra):
    return {
        "scenario": scenario,
        "partial_engine": "nft-ordinal-v1" if scenario == "P" else None,
        "build_root": "/b",
        "stage_output": "/o/stage-a",
        "bwrap_path": "/usr/bin/bwrap",
        **extra,
    }


class ScenarioBindingTests(unittest.TestCase):
    def test_p_keeps_its_reviewed_420_600_preset(self):
        argv = closure.expected_stage_argv(binding("P"))
        self.assertEqual(argv[6:16], OLD_P_ARGV_TAIL)
        self.assertEqual(
            closure.expected_host_files(binding("P")), {"/usr/bin/bwrap", "/usr/sbin/nft"}
        )

    def test_d_gets_900_s_primary_the_same_tail_and_a_pinned_tc(self):
        argv = closure.expected_stage_argv(binding("D"))
        self.assertEqual(argv[argv.index("--duration-seconds") + 1], "900")
        self.assertEqual(argv[argv.index("--settlement-tail-seconds") + 1], "600")
        self.assertEqual(
            closure.expected_host_files(binding("D")), {"/usr/bin/bwrap", "/usr/sbin/tc"}
        )

    def test_missing_or_unknown_scenario_is_refused(self):
        for value in (None, "", "p", "PD", "partial"):
            with self.assertRaisesRegex(ValueError, "no known fault scenario"):
                closure.expected_stage_argv(binding(value))
        with self.assertRaisesRegex(ValueError, "no known fault scenario"):
            closure.verify_binding({"schema": "tos.x02.four-node-binding.v2", "build_root": "/b"})

    def test_a_v1_binding_without_a_scenario_is_refused_by_schema(self):
        with self.assertRaisesRegex(ValueError, "binding schema differs"):
            closure.verify_binding({"schema": "tos.x02.four-node-binding.v1"})

    def test_a_d_argv_in_a_p_binding_or_the_reverse_is_refused(self):
        for scenario, other in (("P", "D"), ("D", "P")):
            record = binding(
                scenario,
                schema="tos.x02.four-node-binding.v2",
                native_source_sha="f" * 40,
                stage_argv=closure.expected_stage_argv(binding(other)),
            )
            with self.assertRaisesRegex(ValueError, "argv differs from fixed preset"):
                closure.verify_binding(record)

    def test_host_files_must_match_the_scenario_exactly(self):
        for scenario, files in (
            ("P", {"/usr/bin/bwrap": {}, "/usr/sbin/tc": {}}),
            ("D", {"/usr/bin/bwrap": {}}),
        ):
            record = binding(
                scenario,
                schema="tos.x02.four-node-binding.v2",
                native_source_sha="f" * 40,
                host_files=files,
            )
            record["stage_argv"] = closure.expected_stage_argv(record)
            with self.assertRaisesRegex(ValueError, "pinned host executables differ"):
                closure.verify_binding(record)


class BudgetTests(unittest.TestCase):
    def test_p_service_budget_is_unchanged(self):
        self.assertEqual(four_node.service_seconds(closure.SCENARIO_WINDOWS["P"]), 2400)

    def test_d_budget_adds_exactly_the_longer_primary_window(self):
        p, d = (four_node.service_seconds(closure.SCENARIO_WINDOWS[s]) for s in "PD")
        self.assertEqual(d - p, 900 - 420)
        self.assertEqual(d, 2880)

    def test_unit_runtime_leaves_the_cleanup_reserve_and_the_executor_waits_longer(self):
        for scenario, service in (("P", 2400), ("D", 2880)):
            bounds = four_node.unit_bounds(closure.SCENARIO_WINDOWS[scenario])
            self.assertEqual(bounds["service_seconds"], service)
            self.assertEqual(
                bounds["unit_runtime_max_seconds"], service + four_node.CLEANUP_SECONDS
            )
            self.assertGreater(bounds["executor_wait_seconds"], bounds["unit_runtime_max_seconds"])

    def test_the_directed_fault_fits_d_and_not_p(self):
        bound = four_node.directed_fault_seconds(THRESHOLDS)
        self.assertEqual(bound, 425)
        self.assertLess(bound, closure.SCENARIO_WINDOWS["D"]["duration"])
        self.assertGreater(bound + 60, closure.SCENARIO_WINDOWS["P"]["duration"])

    def test_collects_worst_timeouts_stay_within_the_bound(self):
        """Drive the real collect() to both timeouts with a fake clock; its sleeps fit the bound."""
        edges = [("three_of_four", f"r{i}") for i in range(1, 13)]
        edges += [("two_of_four", f"r{i}") for i in range(13, 21)]
        policy = {
            "source_commit": "a" * 40,
            "thresholds": {"two_drain_seconds": 30, "recovery_min_delta": 2},
            "clsact": {
                "interface": "lo",
                "cleanup_argv": ["tc", "qdisc", "del", "dev", "lo", "clsact"],
            },
            "rules": [
                {"id": name, "phase": phase, "remove_argv": ["tc", "filter", "del", name]}
                for phase, name in edges
            ],
        }
        # First: 3/4 never grows. Second, the longest path: 3/4 grows at its very last poll,
        # the full drain and halt samples, then recovery never grows.
        for heights, phase in (
            ([100] + [100] * 40, "three_of_four"),
            ([100, 100] + [100] * 11 + [102] + [102] * 4 + [102] * 40, "recovery"),
        ):
            clock, index = [0.0], [0]

            def sample(_p, _s, phase_name, _a, _prev, heights=heights):
                index[0] += 1
                return {"phase": phase_name, "common_seqno": heights[index[0] - 1]}

            with (
                tempfile.TemporaryDirectory(prefix="x02-bound-") as directory,
                patch.object(runner.x02, "require_source_commit"),
                patch.object(runner, "private_net_admin", return_value={}),
                patch.object(
                    runner.x02, "capture_tc", return_value={"lo": {"filters": {}, "qdiscs": {}}}
                ),
                patch.object(
                    runner.x02,
                    "command_json",
                    side_effect=lambda _r, argv: (
                        [{"kind": "noqueue", "root": True}] if "qdisc" in argv else []
                    ),
                ),
                patch.object(runner.x02, "has_clsact", return_value=False),
                patch.object(
                    runner.x02, "fault_event", side_effect=lambda *_a: {"command": {"exit": 0}}
                ),
                patch.object(runner.x02, "capture", side_effect=sample),
                patch.object(runner.x02, "run_raw", return_value={"exit": 0}),
                patch.object(
                    runner.time, "sleep", side_effect=lambda s: clock.__setitem__(0, clock[0] + s)
                ),
                patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]),
            ):
                result = runner.collect(policy, "b" * 64, Path(directory) / "run", "net:[1]")
            self.assertEqual(result["status"], "failed", phase)
            self.assertLessEqual(clock[0], four_node.directed_fault_seconds(THRESHOLDS), phase)


class VerifierBudgetTests(unittest.TestCase):
    def test_a_verifier_that_cannot_finish_before_the_deadline_is_not_started(self):
        launched = []
        check = four_node.config34_proof_check(
            {},
            {"source_sha": "a" * 40},
            Path("/nonexistent"),
            [],
            launcher=lambda *a: launched.append(a),
            deadline=1000.0,
            clock=lambda: 1000.0 - 179.0,
        )
        with self.assertRaisesRegex(ValueError, "no service budget left"):
            check({"election_id": 1}, Path("/nonexistent"), [])
        self.assertEqual(launched, [])

    def test_with_budget_the_guard_lets_the_verifier_path_proceed(self):
        check = four_node.config34_proof_check(
            {},
            {"source_sha": "a" * 40},
            Path("/nonexistent"),
            [],
            deadline=1000.0,
            clock=lambda: 1000.0 - 181.0,
        )
        # Past the guard, the next step reads the fixed verifier source and git: not a budget refusal.
        with self.assertRaises(Exception) as caught:
            check({"election_id": 1}, Path("/nonexistent"), [])
        self.assertNotIn("no service budget left", str(caught.exception))


class Stage:
    def __init__(self, polls):
        self.polls = list(polls)

    def poll(self):
        return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]


class DirectedPhaseTests(unittest.TestCase):
    START = 1_790_000_000.0

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="x02-directed-phase-")
        self.root = Path(os.path.realpath(self.directory.name))
        self.output = self.root / "run"
        self.output.mkdir()
        self.tc = self.root / "tc"
        self.tc.write_bytes(b"tc-bytes")
        self.binding = {
            "host_files": {str(self.tc): {"sha256": hashlib.sha256(b"tc-bytes").hexdigest()}}
        }
        self.collected = []
        self.ledger = []
        self.frozen = []

    def tearDown(self):
        self.directory.cleanup()

    def manifest(self, primary_left):
        deadline = datetime.datetime.fromtimestamp(
            self.START + primary_left, datetime.UTC
        ).isoformat()
        return {"window": {"deadline_at": deadline}}

    def prepare(self, head="c" * 40):
        policy = {
            "thresholds": dict(THRESHOLDS),
            "rules": [{"id": "r1"}],
            "clsact": {"interface": "lo"},
            "nodes": ["node1", "node2", "node3", "node4"],
        }
        return types.SimpleNamespace(
            fixed_source=lambda: (head, {"scripts/x.py": "d" * 64}),
            build_policy=lambda raw, h, files, nodes: dict(policy, readiness=raw.hex()),
        )

    def evidence(self):
        def read_policy(path, sha):
            raw = path.read_bytes()
            assert hashlib.sha256(raw).hexdigest() == sha
            return json.loads(raw)

        return types.SimpleNamespace(read_policy=read_policy)

    def directed(self, status="passed", verdict=True, elapsed=300.0, clock=None):
        def collect(policy, sha, root, host_netns):
            self.collected.append((sha, root, host_netns))
            root.mkdir()
            (root / "verdict.json").write_text(json.dumps({"passed": verdict}))
            if clock is not None:
                clock[0] += elapsed
            return {
                "status": status,
                "policy_sha256": sha,
                "error": None if status == "passed" else "injected",
            }

        return types.SimpleNamespace(collect=collect)

    def run_phase(
        self,
        *,
        primary_left=900.0,
        which=None,
        head="c" * 40,
        status="passed",
        verdict=True,
        elapsed=300.0,
        polls=(None,),
        tc_sha=None,
    ):
        clock = [self.START]
        if tc_sha is not None:
            self.binding["host_files"][str(self.tc)]["sha256"] = tc_sha
        with patch.object(four_node, "TC_PATH", str(self.tc)):
            four_node.directed_phase(
                self.output,
                self.binding,
                {"source_sha": "c" * 40, "host_netns": "net:[1]"},
                self.evidence(),
                self.prepare(head),
                self.directed(status, verdict, elapsed, clock),
                b"readiness",
                self.manifest(primary_left),
                ["n"] * 4,
                Stage(polls),
                self.ledger,
                self.frozen,
                now=lambda: clock[0],
                which=lambda name: str(self.tc) if which is None else which,
            )

    def events(self):
        return [row["event"] for row in self.ledger]

    def test_positive_freezes_this_runs_policy_then_runs_it_once_into_its_own_directory(self):
        self.run_phase()
        self.assertEqual(
            self.events(),
            [
                "directed_tc_pin",
                "directed_policy_frozen",
                "directed_result",
                "directed_and_recovery_verified",
            ],
        )
        ((sha, root, host),) = self.collected
        self.assertEqual((root, host), (self.output / "directed", "net:[1]"))
        raw = (self.output / "directed-policy.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), sha)
        self.assertEqual(json.loads(raw)["readiness"], b"readiness".hex())
        self.assertEqual(len(self.frozen), 1)

    def test_tc_elsewhere_on_path_is_refused_before_any_policy(self):
        with self.assertRaisesRegex(ValueError, "tc on the worker PATH differs"):
            self.run_phase(which="/usr/local/bin/tc")
        self.assertEqual((self.collected, self.frozen), ([], []))
        self.assertEqual(self.ledger[0]["which"], "/usr/local/bin/tc")

    def test_tc_bytes_differing_from_the_pin_are_refused_and_the_raw_digest_kept(self):
        with self.assertRaisesRegex(ValueError, "tc on the worker PATH differs"):
            self.run_phase(tc_sha="0" * 64)
        self.assertEqual(self.collected, [])
        self.assertEqual(self.ledger[0]["sha256"], hashlib.sha256(b"tc-bytes").hexdigest())
        self.assertFalse((self.output / "directed-policy.json").exists())

    def test_a_policy_from_another_source_commit_is_refused(self):
        with self.assertRaisesRegex(ValueError, "source commit differs"):
            self.run_phase(head="e" * 40)
        self.assertEqual(self.collected, [])

    def test_a_fault_that_cannot_finish_in_the_primary_window_never_starts(self):
        with self.assertRaisesRegex(ValueError, "cannot finish inside the StageA primary window"):
            self.run_phase(primary_left=424.0)
        self.assertEqual(self.collected, [])
        self.assertEqual(len(self.frozen), 1)

    def test_stage_a_gone_before_the_fault_is_refused(self):
        with self.assertRaisesRegex(ValueError, "exited before the directed fault"):
            self.run_phase(polls=(1,))
        self.assertEqual(self.collected, [])

    def test_a_failed_or_unconfirmed_fault_is_red(self):
        with self.assertRaisesRegex(ValueError, "did not pass: injected"):
            self.run_phase(status="failed")
        self.setUp()
        with self.assertRaisesRegex(ValueError, "not an explicit pass"):
            self.run_phase(verdict="yes")

    def test_an_overrun_of_the_primary_window_is_red(self):
        with self.assertRaisesRegex(ValueError, "overran the StageA primary window"):
            self.run_phase(primary_left=500.0, elapsed=501.0)

    def test_stage_a_exiting_during_the_fault_is_red(self):
        with self.assertRaisesRegex(ValueError, "exited during the directed fault"):
            self.run_phase(polls=(None, 0))

    def test_an_existing_policy_file_is_never_overwritten(self):
        (self.output / "directed-policy.json").write_text("{}")
        with self.assertRaises(FileExistsError):
            self.run_phase()
        self.assertEqual(self.collected, [])

    def test_primary_deadline_must_be_utc(self):
        with self.assertRaisesRegex(ValueError, "not UTC"):
            four_node.primary_deadline_epoch({"window": {"deadline_at": "2026-09-27T10:00:00"}})
        self.assertEqual(four_node.primary_deadline_epoch(self.manifest(10.0)), self.START + 10.0)


class DirectedCleanupTests(unittest.TestCase):
    POLICY = {
        "clsact": {
            "interface": "lo",
            "cleanup_argv": ["tc", "qdisc", "del", "dev", "lo", "clsact"],
        },
        "rules": [
            {"remove_argv": ["tc", "filter", "del", "r1"]},
            {"remove_argv": ["tc", "filter", "del", "r2"]},
        ],
    }

    def evidence(self, states):
        states = list(states)
        commands = []
        return commands, types.SimpleNamespace(
            capture_tc=lambda _policy: {"lo": {"filters": states.pop(0), "qdiscs": None}},
            command_json=lambda row, argv: row["rules"],
            has_clsact=lambda snapshot, iface: snapshot["tc"][iface]["filters"]["clsact"],
            run_raw=lambda argv: commands.append(argv) or {"argv": argv, "exit": 0},
        )

    def test_clean_state_runs_no_command(self):
        ledger = []
        commands, evidence = self.evidence([{"rules": [], "clsact": False}])
        four_node.directed_tc_cleanup(evidence, self.POLICY, ledger)
        self.assertEqual((commands, [row["event"] for row in ledger]), ([], ["directed_tc_clean"]))

    def test_leftover_rules_are_removed_in_reverse_with_raw_commands_kept(self):
        ledger = []
        commands, evidence = self.evidence(
            [{"rules": [{"pref": 101}], "clsact": True}, {"rules": [], "clsact": False}]
        )
        four_node.directed_tc_cleanup(evidence, self.POLICY, ledger)
        self.assertEqual(
            commands,
            [
                ["tc", "filter", "del", "r2"],
                ["tc", "filter", "del", "r1"],
                ["tc", "qdisc", "del", "dev", "lo", "clsact"],
            ],
        )
        self.assertEqual(ledger[0]["event"], "directed_tc_fallback_cleanup")

    def test_state_that_survives_fallback_is_a_cleanup_failure(self):
        for leftover in (
            {"rules": [{"pref": 101}], "clsact": False},
            {"rules": [], "clsact": True},
        ):
            commands, evidence = self.evidence([leftover, leftover])
            with self.assertRaisesRegex(ValueError, "remains after fallback cleanup"):
                four_node.directed_tc_cleanup(evidence, self.POLICY, [])


class PortableGitBindingTest(unittest.TestCase):
    def test_linked_worktree_binds_actual_common_root_and_ignores_git_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, worktree = root / "repo", root / "worktree"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Tests", "-c",
                 "user.email=tests@localhost", "commit", "-q", "--allow-empty", "-m", "Fixture"],
                check=True,
            )
            subprocess.run(["git", "-C", str(repo), "worktree", "add", "-q", "--detach", str(worktree)], check=True)
            with patch.object(closure, "__file__", str(worktree / "scripts/binding.py")), patch.dict(
                os.environ, {"GIT_DIR": str(root / "untrusted")}
            ):
                self.assertEqual(str((repo / ".git").resolve()), closure.repository_git_common_root())

    def test_missing_repository_metadata_is_refused(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            closure, "__file__", str(Path(directory) / "scripts/binding.py")
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                closure.repository_git_common_root()


if __name__ == "__main__":
    unittest.main()
