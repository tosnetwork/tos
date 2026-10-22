"""Local replay keeps build parallelism under --jobs, including helper-started builds."""

import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_ci  # noqa: E402


def rewrite(line, jobs):
    runner = types.SimpleNamespace(args=types.SimpleNamespace(jobs=jobs))
    return local_ci.Run.rewrite_parallelism(runner, line)


class RewriteTests(unittest.TestCase):
    def test_every_build_parallelism_form_is_rewritten(self):
        cases = {
            'cmake --build build --target fift -j"$(nproc)"': "cmake --build build --target fift -j3",
            "cmake --build build --target fift -j2": "cmake --build build --target fift -j3",
            'cmake --build b -- -j"$(nproc)"': "cmake --build b -- -j3",
            'cmake --build b --parallel "$(nproc)"': "cmake --build b --parallel 3",
            "cmake --build b --parallel 4": "cmake --build b --parallel 3",
            'cmake --build b --parallel "$(getconf _NPROCESSORS_ONLN)"': "cmake --build b --parallel 3",
            'cmake --build "$RUNNER_TEMP/q" --parallel "$(nproc 2>/dev/null || sysctl -n hw.ncpu)"': (
                'cmake --build "$RUNNER_TEMP/q" --parallel 3'
            ),
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                script, changes = rewrite(line + "\n", 3)
                self.assertEqual(script, expected + "\n")
                self.assertEqual(changes, [f"{line}  =>  {expected}"])

    def test_non_build_lines_and_no_jobs_are_untouched(self):
        for line, jobs in [
            ("ctest -j2 --output-on-failure\n", 3),
            ('cmake --build b -j"$(nproc)"\n', 0),
        ]:
            with self.subTest(line=line, jobs=jobs):
                self.assertEqual(rewrite(line, jobs), (line, []))


class EnvironmentTests(unittest.TestCase):
    def test_jobs_bound_builds_started_by_helpers(self):
        self.assertEqual(
            local_ci.parallelism_env(3),
            {"CMAKE_BUILD_PARALLEL_LEVEL": "3", "CARGO_BUILD_JOBS": "3"},
        )
        self.assertEqual(local_ci.parallelism_env(0), {})

    def test_memory_limits(self):
        self.assertEqual(local_ci.memory_args("", ""), [])
        self.assertEqual(local_ci.memory_args("16g", ""), ["--memory", "16g"])
        self.assertEqual(
            local_ci.memory_args("16g", "20g"), ["--memory", "16g", "--memory-swap", "20g"]
        )
        with self.assertRaises(SystemExit):
            local_ci.memory_args("", "20g")


if __name__ == "__main__":
    unittest.main()
