"""The replay's one tolerated difference must not tolerate anything else."""

import importlib.util
import unittest
from pathlib import Path

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


class FailedDeploymentException(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
