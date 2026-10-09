#!/usr/bin/env python3
"""Exit-status handling of scripts/check-use-after-move.py, against a stand-in tool.

The real guard runs clang-tidy; these tests replace it with a small script that
prints diagnostics in clang-tidy's format and exits with a chosen status, inside a
throwaway source tree with one listed unit. A production run is clean only with exit
0, whatever it printed; a control passes only with its expected diagnostics and
exactly the expected exit status. Without these, a run that printed an unrelated
warning and then failed was accepted as a clean unit.

Standard library only. UAM_GUARD may name another guard script to test (used to show
this test going red against an older guard).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

GUARD = Path(
    os.environ.get("UAM_GUARD", Path(__file__).resolve().parent / "check-use-after-move.py")
)

STAND_IN = textwrap.dedent(
    """\
    import os, sys
    args = sys.argv[1:]
    check = next(a for a in args if a.startswith("--checks=")).split(",", 1)[1]
    target = next(a for a in args if not a.startswith("-") and a.endswith(".cpp"))
    tag = f"[{check},-warnings-as-errors]"
    if "--" in args:
        directory = os.path.dirname(target)
        if check == "bugprone-use-after-move":
            names = ["use-after-move-control.cpp", "use-after-move-control.h"]
        else:
            names = ["analyzer-move-control.cpp"]
        for name in names:
            print(f"{directory}/{name}:3:5: error: 's' used after it was moved {tag}")
        sys.exit(int(os.environ.get("STAND_IN_CONTROL_EXIT", "1")))
    output = os.environ.get("STAND_IN_UNIT_OUTPUT", "")
    if output:
        print(output.replace("UNIT", target))
    sys.exit(int(os.environ.get("STAND_IN_UNIT_EXIT", "0")))
    """
)


class StandInToolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.source = root / "src"
        self.build = root / "build"
        (self.source / "scripts").mkdir(parents=True)
        (self.source / "unit").mkdir()
        (self.source / "test" / "static-analysis").mkdir(parents=True)
        self.build.mkdir()
        (self.source / "unit" / "unit.cpp").write_text("int main() { return 0; }\n")
        for name in ("use-after-move-guard-files.txt", "analyzer-move-guard-files.txt"):
            (self.source / "scripts" / name).write_text("unit/unit.cpp\n")
        entry = {"directory": str(self.build), "file": str(self.source / "unit" / "unit.cpp")}
        (self.build / "compile_commands.json").write_text(json.dumps([entry]))
        self.tool = root / "stand-in-clang-tidy"
        self.tool.write_text(f"#!{sys.executable}\n" + STAND_IN)
        self.tool.chmod(0o755)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_guard(self, **env: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(env)
        return subprocess.run(
            [
                sys.executable,
                str(GUARD),
                "--source-dir",
                str(self.source),
                "--build-dir",
                str(self.build),
                "--clang-tidy",
                str(self.tool),
                "--jobs",
                "1",
                "--timeout",
                "60",
            ],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def test_clean_units_and_reporting_controls_pass(self) -> None:
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("USE_AFTER_MOVE_GUARD_OK", result.stdout)

    def test_unit_with_unrelated_warning_and_failing_exit_fails(self) -> None:
        warning = "UNIT:1:1: warning: unused variable 'x' [clang-diagnostic-unused-variable]"
        result = self.run_guard(STAND_IN_UNIT_OUTPUT=warning, STAND_IN_UNIT_EXIT="3")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unit/unit.cpp: clang-tidy exited 3", result.stderr)

    def test_unit_with_silent_failing_exit_fails(self) -> None:
        result = self.run_guard(STAND_IN_UNIT_EXIT="2")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unit/unit.cpp: clang-tidy exited 2", result.stderr)

    def test_control_with_unexpected_failing_exit_fails(self) -> None:
        result = self.run_guard(STAND_IN_CONTROL_EXIT="2")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("diagnostics and exit 1, got", result.stderr)
        self.assertIn("(exit 2)", result.stderr)

    def test_control_with_zero_exit_fails(self) -> None:
        result = self.run_guard(STAND_IN_CONTROL_EXIT="0")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("(exit 0)", result.stderr)


if __name__ == "__main__":
    unittest.main()
