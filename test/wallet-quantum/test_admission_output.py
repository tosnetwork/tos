"""Admission experiment output paths must preserve retained evidence."""

import inspect
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probe_admission_helpers import prepare_output


class AdmissionOutputTests(unittest.TestCase):
    def test_nonempty_directory_is_refused_without_touching_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            artifact = output / "candidate.fc"
            artifact.write_bytes(b"retained original evidence\n")
            with self.assertRaisesRegex(FileExistsError, "new or empty output"):
                prepare_output(output)
            self.assertEqual(artifact.read_bytes(), b"retained original evidence\n")
            self.assertEqual(list(output.iterdir()), [artifact])

    def test_guard_deletion_is_detected_by_the_preservation_test(self):
        source = inspect.getsource(prepare_output)
        start = source.index("    if output.exists()")
        end = source.index("    output.mkdir", start)
        namespace = {}
        exec(compile(source[:start] + source[end:], "<guard-deleted>", "exec"), namespace)
        suite = unittest.TestSuite(
            [AdmissionOutputTests("test_nonempty_directory_is_refused_without_touching_evidence")]
        )
        log = io.StringIO()
        with patch(__name__ + ".prepare_output", namespace["prepare_output"]):
            result = unittest.TextTestRunner(stream=log).run(suite)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(result.errors, [])
        self.assertIn("FileExistsError not raised", log.getvalue())

    def test_file_is_refused_and_new_or_empty_directory_works(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "file"
            file.write_bytes(b"retained")
            with self.assertRaisesRegex(FileExistsError, "new or empty output"):
                prepare_output(file)
            self.assertEqual(file.read_bytes(), b"retained")
            output = root / "new" / "output"
            prepare_output(output)
            self.assertTrue(output.is_dir())
            prepare_output(output)
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
