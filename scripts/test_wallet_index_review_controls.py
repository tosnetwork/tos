#!/usr/bin/env python3
"""Check that review controls cannot report an unrun test or lose source edits."""

import importlib.util
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "wallet_index_review_controls", Path(__file__).with_name("test-wallet-index-review-controls.py")
)
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


class ReviewControlTests(unittest.TestCase):
    def test_a_build_of_another_checkout_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            cache = build / "CMakeCache.txt"
            for value in ("", "CMAKE_HOME_DIRECTORY:INTERNAL=/another-checkout\n"):
                cache.write_text(value)
                with self.assertRaisesRegex(RuntimeError, "invoked checkout"):
                    CONTROL.checked_source(build, CONTROL.ROOT)
            configured = f"CMAKE_HOME_DIRECTORY:INTERNAL={CONTROL.ROOT}\n"
            cache.write_text(configured * 2)
            with self.assertRaisesRegex(RuntimeError, "one configured source"):
                CONTROL.checked_source(build, CONTROL.ROOT)
            cache.write_text(configured)
            CONTROL.checked_source(build, CONTROL.ROOT)

    def test_every_mutation_still_targets_exactly_the_repaired_rule(self):
        paths = {path for _, edits, _ in CONTROL.MUTATIONS for path, _, _ in edits}
        originals = {path: path.read_bytes() for path in paths}
        for name, edits, tests in CONTROL.MUTATIONS:
            with self.subTest(name=name):
                changed = CONTROL.mutation_text(originals, edits)
                self.assertTrue(tests)
                self.assertTrue(all(data != originals[path] for path, data in changed.items()))
                first_path, anchor, _ = edits[0]
                for data in (originals[first_path].replace(anchor.encode(), b""), originals[first_path] + anchor.encode()):
                    with self.assertRaisesRegex(RuntimeError, "anchor must occur once"):
                        CONTROL.mutation_text(originals | {first_path: data}, edits)

    def test_restoration_is_byte_exact_even_when_a_test_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.cpp"
            original = b"public test source\r\n\x00"
            source.write_bytes(original)
            edits = CONTROL.SourceEdits((source,))
            try:
                edits.replace({source: b"mutated source\n"})
                self.assertNotEqual(source.read_bytes(), original)
                raise RuntimeError("intentional test failure")
            except RuntimeError:
                pass
            finally:
                edits.restore()
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(CONTROL.sha256(source.read_bytes()), CONTROL.sha256(original))

    def test_a_concurrent_edit_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.cpp"
            source.write_bytes(b"original")
            edits = CONTROL.SourceEdits((source,))
            source.write_bytes(b"concurrent edit")
            with self.assertRaisesRegex(RuntimeError, "source changed outside"):
                edits.replace({source: b"mutant"})
            with self.assertRaisesRegex(RuntimeError, "concurrent source edit"):
                edits.restore()
            self.assertEqual(source.read_bytes(), b"concurrent edit")

    def test_a_conflict_does_not_leave_other_sources_mutated(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as directory:
                owned = Path(directory) / "owned.cpp"
                external = Path(directory) / "external.cpp"
                owned.write_bytes(b"owned original")
                external.write_bytes(b"external original")
                paths = (external, owned) if reverse else (owned, external)
                edits = CONTROL.SourceEdits(paths)
                edits.replace({owned: b"owned mutation"})
                external.write_bytes(b"concurrent edit")
                with self.assertRaisesRegex(RuntimeError, "concurrent source edit"):
                    edits.restore()
                self.assertEqual(owned.read_bytes(), b"owned original")
                self.assertEqual(external.read_bytes(), b"concurrent edit")

    def test_output_is_bounded_but_an_early_execution_marker_is_remembered(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "test.log"
            status, executed = CONTROL.run_logged(
                [sys.executable, "-c", "import sys; print('RUN_NAMED_TEST', flush=True); sys.stdout.write('x' * 1000000); sys.exit(3)"],
                log, 10, b"RUN_NAMED_TEST",
            )
            self.assertEqual(status, 3)
            self.assertTrue(executed)
            self.assertEqual(log.stat().st_size, CONTROL.LOG_BYTES)

    def test_a_failure_before_the_named_test_starts_is_distinguishable(self):
        with tempfile.TemporaryDirectory() as directory:
            status, executed = CONTROL.run_logged(
                [sys.executable, "-c", "raise SystemExit(3)"],
                Path(directory) / "test.log", 10, b"RUN_NAMED_TEST",
            )
            self.assertEqual(status, 3)
            self.assertFalse(executed)

    def test_the_execution_marker_matches_the_native_test_registration_prefix(self):
        name = "WalletIndexVerify_the_ownership_drain_rejects_malformed_getters"
        # TEST_NAME in tdutils/tests.h registers Test_<suite>_<case>; --filter
        # is only a substring, while the observed runner line has that prefix.
        line = f"Running test Test_{name}..."
        with tempfile.TemporaryDirectory() as directory:
            status, executed = CONTROL.run_logged(
                [sys.executable, "-c", f"print({line!r})"],
                Path(directory) / "test.log", 10, CONTROL.native_test_marker(name),
            )
            self.assertEqual(status, 0)
            self.assertTrue(executed, "the real native test started but the marker did not match")

    def test_a_started_test_needs_its_specific_failure_and_abort(self):
        name = "WalletIndexVerify_the_ownership_drain_rejects_malformed_getters"
        failure = "Expectation failed: db.token_backlog_stats().move_as_ok().parked is not equal to 0u"
        expected = f"Running test {name}...\n{failure}\n"
        CONTROL.require_test_result(name, -signal.SIGABRT, True, expected, True)
        CONTROL.require_test_result(name, 1, True, expected + "Signal: 6\n", True)
        for status, diagnostic, executed in (
            (-signal.SIGABRT, "Expectation failed: fixture_setup!", True),
            (1, "Expectation failed: fixture_setup!\nSignal: 6\n", True),
            (-signal.SIGKILL, expected, True),
            (-signal.SIGSEGV, expected, True),
            (1, expected, True),
            (-signal.SIGABRT, expected, False),
        ):
            with self.subTest(status=status, diagnostic=diagnostic, executed=executed):
                with self.assertRaises(RuntimeError):
                    CONTROL.require_test_result(name, status, executed, diagnostic, True)

    def test_each_named_red_control_has_a_specific_diagnostic(self):
        tests = {name for _, _, names in CONTROL.MUTATIONS for name in names}
        self.assertEqual(tests, set(CONTROL.EXPECTED_RED))

    def test_a_timeout_cannot_be_a_red_result(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "not a sensitivity result"):
                CONTROL.run_logged(
                    [sys.executable, "-c", "import time; print('RUN_NAMED_TEST', flush=True); time.sleep(60)"],
                    Path(directory) / "test.log", 0.2, b"RUN_NAMED_TEST",
                )

    def test_timeout_ends_a_stdout_child_after_its_parent_has_exited(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "test.log"
            with self.assertRaisesRegex(RuntimeError, "not a sensitivity result"):
                CONTROL.run_logged(
                    [sys.executable, "-c", "import subprocess, sys; child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); print(child.pid, flush=True)"],
                    log, 0.4,
                )
            child = int(log.read_text().strip())

            def running():
                try:
                    return Path(f"/proc/{child}/stat").read_text().split()[2] != "Z"
                except FileNotFoundError:
                    return False

            try:
                deadline = time.monotonic() + 1
                while running() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(running(), "the command's child survived its timeout")
            finally:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
