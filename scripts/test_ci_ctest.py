"""Require complete CTest execution, bounded overlap and real failure propagation."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("ci_ctest", Path(__file__).with_name("ci-ctest.py"))
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class CtestTests(unittest.TestCase):
    def test_plan_is_complete_and_unknown_tests_remain_serial(self):
        names = list(mod.PARALLEL_UNITS) + ["source-mutator", "future-unreviewed-test"]
        parallel, serial = mod.plan([{"name": n} for n in names])
        self.assertEqual(parallel, list(mod.PARALLEL_UNITS))
        self.assertEqual(serial, names[-2:])
        for tests in [[], [{"name": "a"}, {"name": "a"}], [{"name": n} for n in names[1:]]]:
            with self.assertRaises(ValueError):
                mod.plan(tests)
        for prop in ["DEPENDS", "FIXTURES_REQUIRED", "FIXTURES_SETUP", "FIXTURES_CLEANUP"]:
            tests = [{"name": n} for n in names]
            tests[0]["properties"] = [{"name": prop, "value": ["shared"]}]
            with self.assertRaisesRegex(ValueError, "unaudited"):
                mod.plan(tests)

    def fixture(self, fail):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        fixture = root / "fixture.py"
        fixture.write_text("""import os,sys,time,json
from pathlib import Path
root=Path(sys.argv[1]); name=sys.argv[2]
def log(kind):
 with (root/"trace.jsonl").open("a") as stream:
  stream.write(json.dumps({"name":name,"kind":kind,"at":time.monotonic()})+"\\n")
log("start"); time.sleep(0.15); log("end")
sys.exit(3 if name==sys.argv[3] else 0)
""")
        names = list(mod.PARALLEL_UNITS) + ["source-mutator", "future-unreviewed-test"]
        cmake = "cmake_minimum_required(VERSION 3.17)\nproject(phase NONE)\nenable_testing()\n"
        for name in names:
            cmake += f'add_test(NAME {name} COMMAND "{sys.executable}" "{fixture}" "{root}" {name} "{fail}")\n'
        (root / "CMakeLists.txt").write_text(cmake)
        subprocess.run(
            ["cmake", "-S", str(root), "-B", str(root / "build")], check=True, capture_output=True
        )
        return root, names

    def test_actual_ctest_overlap_and_all_tests_run_once(self):
        root, names = self.fixture("")
        result = subprocess.run(
            [sys.executable, str(Path(mod.__file__)), "--build-dir", str(root / "build")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = [json.loads(line) for line in (root / "trace.jsonl").read_text().splitlines()]
        self.assertEqual(sorted(e["name"] for e in events if e["kind"] == "start"), sorted(names))
        active = set()
        peak = 0
        for event in sorted(events, key=lambda e: e["at"]):
            if event["kind"] == "start":
                if event["name"] not in mod.PARALLEL_UNITS:
                    self.assertFalse(active)
                else:
                    self.assertTrue(active <= set(mod.PARALLEL_UNITS))
                active.add(event["name"])
                peak = max(peak, len(active))
                self.assertLessEqual(len(active), 2)
            else:
                active.remove(event["name"])
        self.assertEqual(peak, 2)
        self.assertFalse(active)

    def test_actual_test_failure_is_not_hidden_and_serial_phase_still_runs(self):
        root, names = self.fixture("test-db")
        result = subprocess.run(
            [sys.executable, str(Path(mod.__file__)), "--build-dir", str(root / "build")],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test-db (Failed)", result.stdout + result.stderr)
        events = [json.loads(line) for line in (root / "trace.jsonl").read_text().splitlines()]
        self.assertEqual(sorted(e["name"] for e in events if e["kind"] == "start"), sorted(names))


if __name__ == "__main__":
    unittest.main()
