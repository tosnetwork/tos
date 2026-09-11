#!/usr/bin/env python3
"""Runner-only controls: simulated CTest output is NEVER host acceptance evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

path = Path(__file__).with_name('workchain-bucket-sweep-handoff.py')
spec = importlib.util.spec_from_file_location('handoff', path)
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


class Readiness(unittest.TestCase):
    def run_case(self, change=None, output=None, error=None):
        entries = [{'name': name, 'properties': []} for name in handoff.TESTS]
        if change:
            change(entries)

        def invoke(args, **kwargs):
            if '--show-only=json-v1' in args:
                return subprocess.CompletedProcess(args, 0, json.dumps({'tests': entries}), '')
            if error:
                raise error
            name = args[-1][1:-1]
            text = handoff.MARKER + name if output is None else output(name)
            return subprocess.CompletedProcess(args, 0, text, '')

        with patch.object(handoff.subprocess, 'run', side_effect=invoke), \
                patch.object(handoff.sys, 'argv', ['runner', '--build', 'SIMULATED']), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return handoff.main()

    def test_all_executed_protocol_only(self):
        self.assertEqual(self.run_case(), 0)

    def test_missing(self):
        self.assertEqual(self.run_case(lambda entries: entries.pop()), 1)

    def test_each_bucket_obligation_is_independently_required(self):
        expected = ('return-once', 'terminal', 'close', 'transfer', 'fee-routing',
                    'sequence', 'atomicity', 'oracle-control')
        for suffix in expected:
            name = 'test-workchain-bucket-sweep-' + suffix
            with self.subTest(name=name):
                self.assertIn(name, handoff.TESTS)
                entries = [{'name': item, 'properties': []} for item in handoff.TESTS if item != name]
                output = io.StringIO()
                with patch.object(handoff.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        ['ctest'], 0, json.dumps({'tests': entries}), '')), contextlib.redirect_stdout(output):
                    self.assertEqual(handoff.check('SIMULATED'), 1)
                self.assertIn('HANDOFF_NOT_READY', output.getvalue())
                self.assertIn(name, output.getvalue())

    def test_disabled(self):
        self.assertEqual(self.run_case(lambda entries: entries[0]['properties'].append(
            {'name': 'DISABLED', 'value': True})), 1)

    def test_duplicate(self):
        self.assertEqual(self.run_case(lambda entries: entries.append(entries[0])), 1)

    def test_marker_absent(self):
        self.assertEqual(self.run_case(output=lambda name: '0 tests passed'), 1)

    def test_skipped_even_with_marker(self):
        self.assertEqual(self.run_case(output=lambda name: handoff.MARKER + name + '\nSkipped'), 1)

    def test_not_run_even_with_marker(self):
        self.assertEqual(self.run_case(output=lambda name: handoff.MARKER + name + '\nNot Run'), 1)

    def test_test_failure(self):
        self.assertEqual(self.run_case(error=subprocess.CalledProcessError(8, ['ctest'])), 1)

    def test_tool_missing(self):
        self.assertEqual(self.run_case(error=FileNotFoundError('ctest')), 1)

    def test_timeout(self):
        self.assertEqual(self.run_case(error=subprocess.TimeoutExpired(['ctest'], 1800)), 1)


if __name__ == '__main__':
    unittest.main()
