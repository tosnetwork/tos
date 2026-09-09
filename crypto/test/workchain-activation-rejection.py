"""Shared, deliberately partial classifier for observed activation rejections.

Call only with an observed error Status, never infer is_error() from its code:
the raw registry's Error(message) has code zero. This is a test instrument,
not a production error classifier. Unknown observations must fail the test.
Run this file directly for the colocated calibration checks.
"""

from pathlib import Path
import hashlib
import unittest
from unittest.mock import patch


ACTIVATION_MESSAGE = "block transition is not activated by global version and capability"
EARLIER_MESSAGE = "descriptor has no registered block engine"
EARLIER_ACCOUNT_MESSAGE = "missing workchain engine Basic:1129206833 for workchain 2"
COLLATOR_PREFIX = "cannot create block for configured workchain: "


class UnclassifiableActivationStatus(ValueError):
    pass


def is_activation_rejection(code, message, *, boundary="scoped"):
    """True for the known activation site, False for the known earlier site.

scoped: resolve_scoped_workchain error; raw-registry: resolve_block error;
collator: observed error with the exact production collation prefix.
No arbitrary prefix stripping, substring search, or generic local-error fallback.
Success is outside this instrument's domain and must be handled by the caller.
"""
    forms = {
        "scoped": (-7201, ""),
        "raw-registry": (0, ""),
        "collator": (-7201, COLLATOR_PREFIX),
    }
    form = forms.get(boundary)
    if form is not None and type(code) is int and isinstance(message, str):
        expected_code, prefix = form
        if code == expected_code:
            if message == prefix + ACTIVATION_MESSAGE:
                return True
            if message in (prefix + EARLIER_MESSAGE, prefix + EARLIER_ACCOUNT_MESSAGE):
                return False
    raise UnclassifiableActivationStatus(
        f"unclassifiable activation status: boundary={boundary!r}, code={code!r}, message={message!r}"
    )


def _check_source_message(repo, message, function):
    repo = Path(repo)
    expected = repo / "crypto/block/workchain-execution-dispatch.cpp"
    hits = []
    for directory in ("crypto/block", "validator", "validator-engine"):
        for path in (repo / directory).rglob("*"):
            if path.suffix in (".cpp", ".h", ".hpp", ".cc"):
                hits.extend([path] * path.read_text().count(message))
    if hits != [expected]:
        raise AssertionError(f"message producer is not unique: {message!r}: {hits!r}")
    text = expected.read_text()
    start = text.index(function)
    end = text.index("\n}\n", start)
    if f'return td::Status::Error("{message}");' not in text[start:end]:
        raise AssertionError(f"message {message!r} is not produced by {function}")


def check_activation_source(repo):
    """Check production crypto/block, validator and validator-engine C++ sources.

    This is not a whole-repository scanner. The exact account-compute failure
    is specific to the calibrated workchain-2 test selector, not a wildcard.
    Both exact activation and block-lookup messages must have unique producers.
    """
    repo = Path(repo)
    _check_source_message(repo, ACTIVATION_MESSAGE, "td::Status validate_workchain_block_activation(")
    _check_source_message(repo, EARLIER_MESSAGE, "WorkchainExecutionRegistry::resolve_block(")
    prefix_site = f'execution_res.move_as_error_prefix("{COLLATOR_PREFIX}")'
    if (repo / 'validator/impl/collator.cpp').read_text().count(prefix_site) != 1:
        raise AssertionError("collator prefix differs from the calibrated producer")


def check_scoped_probe_output(stdout):
    """Calibrate the real four-row resolver probe; consumers keep no answer table."""
    rows = [line.split('\t') for line in stdout.splitlines()]
    if len(rows) != 4 or any(len(row) != 5 for row in rows):
        raise AssertionError(f"invalid scoped calibration rows: {rows!r}")
    for row, flags, expected in zip(rows[:3], (['0', '0'], ['0', '1'], ['1', '0']), (False, False, True)):
        if row[:2] != flags or is_activation_rejection(int(row[2]), row[3]) is not expected:
            raise AssertionError(f"incorrect scoped calibration result: {row!r}, expected={expected!r}")
    if rows[3][:4] != ['1', '1', '0', '']:
        raise AssertionError(f"missing real success observation: {rows[3]!r}")
    for code, message in ((int(rows[3][2]), rows[3][3]), (-7201, 'unrecognized calibration status')):
        try:
            answer = is_activation_rejection(code, message)
        except UnclassifiableActivationStatus:
            continue
        raise AssertionError(f"success/unknown received Boolean answer: code={code!r}, message={message!r}, answer={answer!r}")


class ActivationCalibration(unittest.TestCase):
    def test_real_scoped_resolver_observations(self):
        path = Path(__file__).resolve().parents[2] / 'doc/measurements/uno-v2-activation-helper-provenance/probe.stdout.log'
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         '733efbdfc547676767c5c7b3b64884a4d24c2383b27b48e1517afdcb8d7c151b')
        check_scoped_probe_output(data.decode())

    def test_activation_and_earlier_failure_same_code(self):
        for boundary, code, prefix in (
            ("scoped", -7201, ""),
            ("raw-registry", 0, ""),
            ("collator", -7201, COLLATOR_PREFIX),
        ):
            with self.subTest(boundary=boundary):
                self.assertIs(is_activation_rejection(code, prefix + ACTIVATION_MESSAGE, boundary=boundary), True)
                self.assertIs(is_activation_rejection(code, prefix + EARLIER_MESSAGE, boundary=boundary), False)

    def test_unknown_is_not_a_boolean_answer(self):
        for code, message, boundary in (
            (-7201, "unrecognized local failure", "scoped"),
            (-7202, ACTIVATION_MESSAGE, "scoped"),
            (0, ACTIVATION_MESSAGE, "scoped"),
            (-7201, "new prefix: " + ACTIVATION_MESSAGE, "scoped"),
            (-7201, ACTIVATION_MESSAGE, "unknown-boundary"),
            (0, "", "raw-registry"),
            (False, EARLIER_MESSAGE, "raw-registry"),
            (-7201.0, ACTIVATION_MESSAGE, "scoped"),
            (-7201, None, "scoped"),
        ):
            with self.subTest(code=code, message=message, boundary=boundary):
                with self.assertRaises(UnclassifiableActivationStatus) as caught:
                    is_activation_rejection(code, message, boundary=boundary)
                self.assertIn(repr(code), str(caught.exception))
                self.assertIn(repr(message), str(caught.exception))

    def test_unique_production_origin(self):
        check_activation_source(Path(__file__).resolve().parents[2])

    def test_duplicate_producer(self):
        repo = Path(__file__).resolve().parents[2]
        original = Path.read_text
        def duplicated(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path == repo / 'crypto/block/workchain-execution-dispatch.cpp':
                text += '\n// ' + ACTIVATION_MESSAGE + '\n'
            return text
        with patch.object(Path, 'read_text', duplicated):
            with self.assertRaisesRegex(AssertionError, 'producer is not unique'):
                check_activation_source(repo)

    def test_duplicate_block_lookup_producer(self):
        repo = Path(__file__).resolve().parents[2]
        original = Path.read_text
        def duplicated(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path == repo / 'crypto/block/workchain-execution-dispatch.cpp':
                text += '\n// ' + EARLIER_MESSAGE + '\n'
            return text
        with patch.object(Path, 'read_text', duplicated):
            with self.assertRaisesRegex(AssertionError, 'producer is not unique'):
                check_activation_source(repo)

    def test_malformed_calibration_table(self):
        path = Path(__file__).resolve().parents[2] / 'doc/measurements/uno-v2-activation-helper-provenance/probe.stdout.log'
        rows = path.read_text().splitlines()
        extra_column = rows.copy()
        extra_column[0] += '\textra'
        wrong_flags = rows.copy()
        wrong_flags[0] = '1\t0\t' + rows[0].split('\t', 2)[2]
        wrong_success = rows.copy()
        wrong_success[3] = '0\t0\t' + rows[3].split('\t', 2)[2]
        for malformed in (rows + [rows[3]], extra_column, wrong_flags, wrong_success):
            with self.subTest(rows=malformed):
                with self.assertRaises(AssertionError):
                    check_scoped_probe_output('\n'.join(malformed))

    def test_message_moved_outside_activation_function(self):
        repo = Path(__file__).resolve().parents[2]
        source = repo / 'crypto/block/workchain-execution-dispatch.cpp'
        original = Path.read_text
        statement = f'return td::Status::Error("{ACTIVATION_MESSAGE}");'
        def moved(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path == source:
                # Keep one literal in the same file, outside the checked function.
                text = text.replace(statement, 'return td::Status::Error("other error");')
                text += '\n// ' + ACTIVATION_MESSAGE + '\n'
            return text
        with patch.object(Path, 'read_text', moved):
            with self.assertRaisesRegex(AssertionError, 'not produced by'):
                check_activation_source(repo)


if __name__ == "__main__":
    unittest.main()
