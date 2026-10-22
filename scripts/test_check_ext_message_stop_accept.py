"""The stop-on-accept control forwards only an explicit build-job limit into its container."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "stop_accept", Path(__file__).resolve().parent / "check-ext-message-stop-accept.py"
)
stop_accept = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stop_accept)

BUILD = ["cmake", "--build", "build", "--target", "test-ext-message-pool"]


class ContainerExecTests(unittest.TestCase):
    def test_without_a_limit_the_container_sizes_the_build(self):
        self.assertEqual(
            stop_accept.container_exec("builder", BUILD, {"PATH": "/usr/bin"}),
            ["docker", "exec", "builder", *BUILD],
        )

    def test_explicit_limits_reach_the_container(self):
        environ = {"CMAKE_BUILD_PARALLEL_LEVEL": "3", "CARGO_BUILD_JOBS": "2", "HOME": "/root"}
        self.assertEqual(
            stop_accept.container_exec("builder", BUILD, environ),
            [
                "docker",
                "exec",
                "-e",
                "CMAKE_BUILD_PARALLEL_LEVEL=3",
                "-e",
                "CARGO_BUILD_JOBS=2",
                "builder",
                *BUILD,
            ],
        )

    def test_an_empty_limit_is_not_forwarded(self):
        self.assertEqual(
            stop_accept.container_exec("builder", BUILD, {"CMAKE_BUILD_PARALLEL_LEVEL": ""}),
            ["docker", "exec", "builder", *BUILD],
        )

    def test_the_build_command_passes_no_job_count(self):
        text = (Path(__file__).resolve().parent / "check-ext-message-stop-accept.py").read_text()
        self.assertIn('"--target", "test-ext-message-pool"]', text)
        self.assertNotRegex(text, r'"-j\d*"')


if __name__ == "__main__":
    unittest.main()
