"""Trace population and strict replay regression controls."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location(
    "replay", Path(__file__).with_name("replay-token-bridge-trace.py")
)
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)

CODE, DATA = "c0" * 32, "da" * 32


def shape():
    """A deployment refused in compute: the Rust and native views of it."""
    expect = {
        "aborted": True,
        "exit_code": 709,
        "compute_skipped": False,
        "action": None,
        "bounce": "ok",
        "balance": "0",
        "code": CODE,
        "data": DATA,
    }
    got = dict(expect, balance=None, code=None, data=None)
    before = {"state": "none", "balance": None, "code": None, "data": None}
    return expect, got, before, (CODE, DATA)


class FailedDeploymentDiagnostic(unittest.TestCase):
    def test_the_exact_shape_is_recognised(self):
        self.assertTrue(replay.failed_deployment_kept_by_rust(*shape()))

    def test_an_uninit_account_is_still_a_deployment(self):
        expect, got, before, init = shape()
        before["state"] = "uninit"
        self.assertTrue(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_an_existing_account_that_disappears_is_not_tolerated(self):
        expect, got, before, init = shape()
        before.update(state="active", balance="0", code=CODE, data=DATA)
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_a_message_without_a_state_init_is_not_tolerated(self):
        expect, got, before, _ = shape()
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, None))

    def test_kept_data_other_than_the_state_inits_is_not_tolerated(self):
        expect, got, before, init = shape()
        expect["data"] = "ee" * 32
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_kept_code_other_than_the_state_inits_is_not_tolerated(self):
        expect, got, before, init = shape()
        expect["code"] = "ee" * 32
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_an_action_phase_failure_is_not_tolerated(self):
        expect, got, before, init = shape()
        expect["action"] = got["action"] = {"success": False, "result_code": 37, "skipped": 0}
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_a_skipped_compute_phase_is_not_tolerated(self):
        expect, got, before, init = shape()
        expect["compute_skipped"] = got["compute_skipped"] = True
        expect["exit_code"] = got["exit_code"] = None
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_a_successful_compute_is_not_tolerated(self):
        expect, got, before, init = shape()
        expect["exit_code"] = got["exit_code"] = 0
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_a_non_zero_kept_balance_is_not_tolerated(self):
        expect, got, before, init = shape()
        expect["balance"] = "1"
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_a_native_account_left_behind_is_not_tolerated(self):
        expect, got, before, init = shape()
        got["balance"] = "0"
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))

    def test_no_bounce_is_not_tolerated(self):
        expect, got, before, init = shape()
        expect["bounce"] = got["bounce"] = "none"
        self.assertFalse(replay.failed_deployment_kept_by_rust(expect, got, before, init))


class TracePopulation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write(1)
        self.write(2)

    def write(self, index, name=None):
        path = self.root / (name or f"{index:04}.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"trace_index": index}))
        return path

    def test_complete_population(self):
        self.assertEqual(len(replay.trace_population(self.root, 2)), 2)

    def test_missing(self):
        (self.root / "0002.json").unlink()
        with self.assertRaisesRegex(ValueError, "population mismatch"):
            replay.trace_population(self.root, 2)

    def test_extra(self):
        self.write(3)
        with self.assertRaisesRegex(ValueError, "population mismatch"):
            replay.trace_population(self.root, 2)

    def test_duplicate(self):
        (self.root / "0002.json").unlink()
        self.write(1, "other/0001.json")
        with self.assertRaisesRegex(ValueError, "duplicate trace index"):
            replay.trace_population(self.root, 2)

    def test_invalid_index(self):
        for index in (0, 3, True, "2", None):
            with self.subTest(index=index):
                self.write(index, "0002.json")
                with self.assertRaisesRegex(ValueError, "invalid trace index"):
                    replay.trace_population(self.root, 2)

    def test_filename(self):
        (self.root / "0002.json").rename(self.root / "wrong.json")
        with self.assertRaisesRegex(ValueError, "filename/index mismatch"):
            replay.trace_population(self.root, 2)

    def test_symlink(self):
        (self.root / "0002.json").unlink()
        (self.root / "0002.json").symlink_to(self.root / "0001.json")
        with self.assertRaisesRegex(ValueError, "regular files"):
            replay.trace_population(self.root, 2)

    def test_record_limit(self):
        with patch.object(replay, "MAX_TRACE_RECORDS", 1):
            with self.assertRaisesRegex(ValueError, "record limit exceeded"):
                replay.trace_population(self.root)

    def test_file_limit(self):
        with patch.object(replay, "MAX_TRACE_FILE", 1):
            with self.assertRaisesRegex(ValueError, "byte limit exceeded"):
                replay.trace_population(self.root)

    def test_total_limit(self):
        size = (self.root / "0001.json").stat().st_size
        with patch.object(replay, "MAX_TRACE_BYTES", size):
            with self.assertRaisesRegex(ValueError, "byte limit exceeded"):
                replay.trace_population(self.root)

    def test_expected_limit(self):
        for count in (0, -1, replay.MAX_TRACE_RECORDS + 1):
            with self.subTest(count=count):
                with self.assertRaisesRegex(ValueError, "outside the record limit"):
                    replay.trace_population(self.root, count)

    def test_population_checked_before_engine(self):
        with patch.object(
            replay.sys, "argv", ["replay", str(self.root), "--expected-records", "3"]
        ):
            with patch.object(replay, "Engine") as engine:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        replay.main()
                self.assertEqual(error.exception.code, 2)
                engine.assert_not_called()


class StrictReplay(unittest.TestCase):
    def test_previously_waived_deployment_fails_without_mutating_native(self):
        expect, got, before, init = shape()
        expect["out"] = got["out"] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "0001.json"
            path.write_text(
                json.dumps(dict(config="", unixtime=1, shard_account="", message="", expect=expect))
            )
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(replay.sys, "argv", ["replay", directory]))
                stack.enter_context(
                    patch.object(replay, "Engine")
                ).return_value.run.return_value = {
                    "success": True,
                    "transaction": "",
                    "shard_account": "",
                }
                stack.enter_context(patch.object(replay, "from_boc"))
                stack.enter_context(patch.object(replay, "description", return_value=got))
                stack.enter_context(patch.object(replay, "outgoing", return_value=[]))
                stack.enter_context(patch.object(replay, "read_account", side_effect=[got, before]))
                stack.enter_context(patch.object(replay, "message_init", return_value=init))
                output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertEqual(replay.main(), 1)
                for key in ("balance", "data", "code"):
                    self.assertIsNone(got[key])
                    self.assertIn(f": {key}: Rust", output.getvalue())


class BridgeCI(unittest.TestCase):
    def test_complete_fresh_population_is_mandatory(self):
        workflow = (replay.ROOT / ".github/workflows/contract-sandboxes.yml").read_text()
        step = workflow.split(
            "- name: Token-bridge transactions agree with the native engine\n", 1
        )[1]
        step = step.split("\n      - name:", 1)[0]
        fresh = 'test ! -e "$TOKEN_BRIDGE_TRACE_DIR"'
        producer = "cargo test --manifest-path tosctl/src/Cargo.toml -p contracts --locked --test token_bridge_sandbox"
        consumer = 'python3 scripts/replay-token-bridge-trace.py "$TOKEN_BRIDGE_TRACE_DIR" --expected-records 5097'
        for command in (fresh, producer, consumer):
            self.assertIn(command + "\n", step)
        self.assertLess(step.index(fresh), step.index(producer))
        self.assertLess(step.index(producer), step.index(consumer))
        self.assertIn("python3 scripts/test_replay_token_bridge_trace.py\n", step)


if __name__ == "__main__":
    unittest.main()
