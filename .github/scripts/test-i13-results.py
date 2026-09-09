#!/usr/bin/env python3
"""Exercise the CI observer, not the private acceptance harnesses themselves."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

GATE = Path(__file__).with_name("check-i13-results.py")
NAMES = ["test-workchain-construction-isolation-gates",
         "test-workchain-i13-acceptance-gates",
         "test-workchain-i13-usage-acceptance-gates",
         "test-workchain-execution-ledger-gates",
         "test-workchain-batch-scan-gates"]


def run(mode, path, success):
    result = subprocess.run([sys.executable, str(GATE), mode, str(path), str(path.parent)],
                            capture_output=True, text=True)
    print(f"{path.name}: exit={result.returncode}\n{result.stdout}{result.stderr}")
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected observer result: {path.name}")


with tempfile.TemporaryDirectory(prefix="i13-ci-observer-") as temporary:
    directory = Path(temporary)
    # Use actual CTest JSON and JUnit schemas, not hand-invented success reports.
    source = 'cmake_minimum_required(VERSION 3.22)\nproject(Observer NONE)\nenable_testing()\n'
    drivers = directory / "crypto" / "test"
    drivers.mkdir(parents=True)
    for name in NAMES:
        driver = drivers / (name.removeprefix("test-").removesuffix("-gates") + ".py")
        driver.write_text("# Trivial observer fixture, not an acceptance harness.\n")
        source += f'add_test(NAME {name} COMMAND "{sys.executable}" "{driver}")\n'
        source += f'set_tests_properties({name} PROPERTIES LABELS "private;workchain;i13")\n'
    (directory / "CMakeLists.txt").write_text(source)
    build = directory / "out"
    subprocess.run(["cmake", "-S", str(directory), "-B", str(build)], check=True)
    registry = json.loads(subprocess.check_output(
        ["ctest", "--test-dir", str(build), "-L", "i13", "--show-only=json-v1"]))
    for label, tests, success in [
        ("five", registry["tests"], True), ("zero", [], False),
        ("missing", registry["tests"][:-1], False),
        ("duplicate", [registry["tests"][0]] * 5, False),
    ]:
        path = directory / (label + ".json")
        path.write_text(json.dumps({"tests": tests}))
        run("registered", path, success)
    substituted = json.loads(json.dumps(registry))
    substituted["tests"][0]["command"] = ["cmake", "-E", "true"]
    path = directory / "wrong-driver.json"
    path.write_text(json.dumps(substituted))
    run("registered", path, False)
    report = directory / "actual.xml"
    subprocess.run(["ctest", "--test-dir", str(build), "-L", "i13",
                    "--no-tests=error", "--output-junit", str(report)], check=True)
    run("executed", report, True)
    successful_tests = list(ET.parse(report).iter('testcase'))
    if len(successful_tests) != 5 or any(t.get('status') != 'run' for t in successful_tests):
        raise AssertionError('positive observer must see five actual run statuses')
    # Keep all five actual names so failure cannot be rejected merely by count.
    failing_driver = drivers / (NAMES[-1].removeprefix('test-').removesuffix('-gates') + '.py')
    original_driver = failing_driver.read_bytes()
    try:
        failing_driver.write_text('raise SystemExit(1)\n')
        failure_report = directory / 'actual-failure.xml'
        failed = subprocess.run(['ctest', '--test-dir', str(build), '-L', 'i13',
                                 '--no-tests=error', '--output-junit', str(failure_report)])
        if failed.returncode != 8:
            raise AssertionError(f'forced driver failure: expected CTest exit 8, got {failed.returncode}')
        failed_tests = list(ET.parse(failure_report).iter('testcase'))
        if len(failed_tests) != 5 or {t.get('name') for t in failed_tests} != set(NAMES):
            raise AssertionError('forced failure must retain all five registered names')
        actual_failures = [t for t in failed_tests if t.find('failure') is not None]
        if len(actual_failures) != 1 or actual_failures[0].get('status') != 'fail':
            raise AssertionError('forced failure must produce exactly one real CTest fail status')
        run('executed', failure_report, False)
    finally:
        failing_driver.write_bytes(original_driver)
    for label in ("zero", "missing", "skipped", "failure", "notrun"):
        root = ET.parse(report).getroot()
        tests = root.findall("testcase")
        if label in ("zero", "missing"):
            for test in (tests if label == "zero" else tests[:1]):
                root.remove(test)
        elif label == "notrun":
            tests[0].set("status", "notrun")
        else:
            ET.SubElement(tests[0], label)
        path = directory / (label + ".xml")
        ET.ElementTree(root).write(path)
        run("executed", path, False)
