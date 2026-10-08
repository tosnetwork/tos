"""Regression controls for native coverage, platform routing and artifact failure."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("native_tests", ROOT / "ci/native_tests.py")
assert SPEC is not None and SPEC.loader is not None
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)

# Independently recorded from the native registration and platform workflows.
CORE = {
    "test-ed25519", "test-bigint", "test-vm", "test-fift", "test-cells",
    "test-smartcont", "test-net", "test-tdactor", "test-tdutils", "test-toslib-offline",
    "test-func", "test-func-legacy", "test-tol",
}
PLATFORMS = {
    "build-tos-linux-arm64-shared.yml": "os: [ubuntu-22.04-arm, ubuntu-24.04-arm]",
    "build-tos-linux-arm64-appimage.yml": "runs-on: ubuntu-22.04-arm",
    "build-tos-linux-x86-64-appimage.yml": "runs-on: ubuntu-22.04",
    "build-tos-macos-14-arm64-portable.yml": "runs-on: macos-14",
    "build-tos-macos-15-arm64-shared.yml": "runs-on: macos-15",
    "build-tos-macos-15-x86-64-portable.yml": "runs-on: macos-15-intel",
    "build-tos-macos-15-x86-64-shared.yml": "runs-on: macos-15-intel",
    "build-tos-macos-arm64-shared.yml": "runs-on: macos-14",
    "build-tos-wasm-emscripten.yml": "runs-on: ubuntu-22.04",
    "tos-x86-64-windows.yml": "runs-on: windows-2022",
}
PACKAGING = {
    name for name in PLATFORMS if any(x in name for x in ("appimage", "portable", "wasm"))
} | {"tos-x86-64-windows.yml"}


def event_body(text: str, event: str) -> str:
    # These maintained adapters deliberately use simple, explicit event maps.
    # This is a source contract, not a general YAML/event-expression evaluator.
    match = re.search(rf"(?m)^  {event}:\n((?:    [^\n]*\n|\n)*)", text)
    if match is None:
        raise ValueError(f"Explicit {event} mapping missing")
    return match[1]


def require_main(text: str) -> None:
    for event in ("pull_request", "push"):
        body = event_body(text, event)
        branch = re.search(r"(?m)^    branches: \[([^\]]+)\]$", body)
        if branch is None or "main" not in {x.strip() for x in branch[1].split(",")}:
            raise ValueError(f"{event} does not cover main")
        if "paths:" in body or "paths-ignore:" in body or "branches-ignore:" in body:
            raise ValueError("Unreviewed platform trigger filter")
    if re.search(r"(?m)^    (if|continue-on-error):", text):
        raise ValueError("A required native job can be skipped or its failure ignored")


class NativeReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="native-ci-")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.xml = self.directory / "results.xml"

    def registry(self, names=CORE) -> dict:
        return {"tests": [{"name": n, "command": ["/bin/true"]} for n in sorted(names)]}

    def results(self, names=CORE) -> Path:
        suite = ET.Element("testsuite")
        for name in sorted(names):
            ET.SubElement(suite, "testcase", name=name, status="run")
        ET.ElementTree(suite).write(self.xml)
        return self.xml

    def test_floor_and_all_additional_tests_are_retained(self) -> None:
        names = CORE | {"new-security-boundary"}
        self.assertEqual(native.registered_names(self.registry(names)), names)
        self.assertEqual(native.verify_results(self.results(names), names), len(names))

    def test_each_missing_core_test_is_rejected(self) -> None:
        for name in CORE:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "missing"):
                native.registered_names(self.registry(CORE - {name}))

    def test_empty_registry_is_not_success(self) -> None:
        with self.assertRaisesRegex(ValueError, "Empty"):
            native.registered_names(self.registry(set()))

    def test_duplicate_registry_is_rejected(self) -> None:
        payload = self.registry()
        payload["tests"].append(copy.deepcopy(payload["tests"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            native.registered_names(payload)

    def test_unbuilt_executable_is_rejected(self) -> None:
        payload = self.registry()
        del payload["tests"][0]["command"]
        with self.assertRaisesRegex(ValueError, "not built"):
            native.registered_names(payload)

    def test_disabled_test_is_not_counted_as_pass(self) -> None:
        for value in (True, "ON", 1, "TRUE"):
            payload = self.registry()
            payload["tests"][0]["properties"] = [{"name": "DISABLED", "value": value}]
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Disabled"):
                native.registered_names(payload)

    def test_explicitly_enabled_test_remains_valid(self) -> None:
        payload = self.registry()
        payload["tests"][0]["properties"] = [{"name": "DISABLED", "value": False}]
        self.assertEqual(native.registered_names(payload), CORE)

    def test_each_omitted_execution_is_rejected(self) -> None:
        for name in CORE:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "differs"):
                native.verify_results(self.results(CORE - {name}), CORE)

    def test_unexpected_execution_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "differs"):
            native.verify_results(self.results(CORE | {"unexpected"}), CORE)

    def test_failure_error_and_skip_are_rejected(self) -> None:
        for tag in ("failure", "error", "skipped"):
            self.results()
            tree = ET.parse(self.xml)
            ET.SubElement(tree.getroot()[0], tag)
            tree.write(self.xml)
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "failed|skipped"):
                native.verify_results(self.xml, CORE)

    def test_nonrun_and_missing_status_are_rejected(self) -> None:
        for status in (None, "notrun", "disabled"):
            self.results()
            tree = ET.parse(self.xml)
            case = tree.getroot()[0]
            if status is None:
                del case.attrib["status"]
            else:
                case.set("status", status)
            tree.write(self.xml)
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "did not run"):
                native.verify_results(self.xml, CORE)

    def test_duplicate_result_is_rejected(self) -> None:
        self.results()
        tree = ET.parse(self.xml)
        tree.getroot().append(copy.deepcopy(tree.getroot()[0]))
        tree.write(self.xml)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            native.verify_results(self.xml, CORE)

    def fixture(self, definitions: str) -> Path:
        for tool in ("cmake", "ctest"):
            self.assertIsNotNone(shutil.which(tool), f"Required test tool missing: {tool}")
        source = self.directory / "CMakeLists.txt"
        source.write_text(
            "cmake_minimum_required(VERSION 3.21)\nproject(NativeCIFixture NONE)\n"
            "enable_testing()\n" + definitions
        )
        build = self.directory / "build"
        subprocess.run(
            ["cmake", "-S", str(self.directory), "-B", str(build)],
            capture_output=True, text=True, check=True,
        )
        return build

    def test_real_ctest_executes_entire_registry(self) -> None:
        build = self.fixture(
            'add_test(NAME core COMMAND "${CMAKE_COMMAND}" -E true)\n'
            'add_test(NAME additional COMMAND "${CMAKE_COMMAND}" -E true)\n'
        )
        self.assertEqual(native.run_suite(build, frozenset({"core"})), 0)
        record = json.loads((build / "ci-native-results/summary.json").read_text())
        self.assertEqual(record, {"registered": 2, "executed": 2, "passed": True})

    def test_real_ctest_failure_propagates_and_removes_old_green(self) -> None:
        build = self.fixture('add_test(NAME core COMMAND "${CMAKE_COMMAND}" -E false)\n')
        evidence = build / "ci-native-results"
        evidence.mkdir()
        (evidence / "summary.json").write_text('{"passed": true}')
        (evidence / "results.xml").write_text("stale result")
        self.assertNotEqual(native.run_suite(build, frozenset({"core"})), 0)
        self.assertFalse((evidence / "summary.json").exists())
        self.assertNotEqual((evidence / "results.xml").read_text(), "stale result")

    def test_real_ctest_skip_is_not_a_success(self) -> None:
        build = self.fixture(
            'add_test(NAME core COMMAND "${CMAKE_COMMAND}" -E false)\n'
            'set_tests_properties(core PROPERTIES SKIP_RETURN_CODE 1)\n'
        )
        with self.assertRaisesRegex(ValueError, "did not run|skipped"):
            native.run_suite(build, frozenset({"core"}))
        self.assertFalse((build / "ci-native-results/summary.json").exists())

    def test_real_ctest_empty_inventory_refused(self) -> None:
        build = self.fixture("")
        with self.assertRaisesRegex(ValueError, "Empty"):
            native.run_suite(build, frozenset({"core"}))


class WorkflowCoverageTests(unittest.TestCase):
    def text(self, name: str) -> str:
        return (ROOT / ".github/workflows" / name).read_text()

    def test_all_platforms_cover_main_with_original_runner_identities(self) -> None:
        for name, runner in PLATFORMS.items():
            with self.subTest(workflow=name):
                text = self.text(name)
                require_main(text)
                self.assertIn(runner + "\n", text)
                self.assertIn("  workflow_call:", text)
                self.assertIn("  workflow_dispatch:", text)

    def test_deleted_main_and_added_skip_fail_the_routing_guard(self) -> None:
        text = self.text("build-tos-linux-arm64-shared.yml")
        require_main(text)
        for mutant in (
            text.replace("[main, master, testnet]", "[master, testnet]"),
            text.replace("  build:\n", "  build:\n    if: false\n"),
        ):
            with self.assertRaises(ValueError):
                require_main(mutant)

    def test_packaging_fails_when_artifacts_are_missing(self) -> None:
        self.assertEqual(len(PACKAGING), 6)
        for name in PACKAGING:
            with self.subTest(workflow=name):
                text = self.text(name)
                self.assertIn("if-no-files-found: error", text)
                self.assertIn("tags: ['v*']", text)

    def test_complete_ctest_and_installed_consumer_routing(self) -> None:
        names = [n for n in PLATFORMS if "shared" in n or "portable" in n]
        names += ["build-tos-linux-x86-64-shared.yml"]
        for name in names:
            with self.subTest(workflow=name):
                text = self.text(name)
                self.assertIn("run: ci/run native-tests\n", text)
                if "shared" in name:
                    self.assertIn("run: ci/run installed-consumer\n", text)

    def test_full_linux_lane_is_premerge_and_two_userspaces(self) -> None:
        text = self.text("build-tos-linux-x86-64-shared.yml")
        require_main(text)
        self.assertIn("os: [ubuntu-22.04, ubuntu-24.04]", text)
        for task in ("native-build", "native-python-env", "native-python", "native-integrations"):
            self.assertIn(f"run: ci/run {task}\n", text)

    def test_windows_batch_failure_cannot_be_hidden_by_cache_statistics(self) -> None:
        text = self.text("tos-x86-64-windows.yml")
        self.assertIn(
            "call build-windows-github-2022.bat Enterprise\n"
            "          if errorlevel 1 exit /b %errorlevel%", text,
        )

    def test_python_only_hygiene_does_not_install_cpp_toolchain(self) -> None:
        text = self.text("build-tos-linux-x86-64-werror.yml")
        self.assertIn("grep -cE '\\.(h|hpp|cpp)$' changed-files.txt", text)
        for name in ("Install Clang 21 formatting tools", "Check C++ formatting of changed lines"):
            self.assertIn(f"- name: {name}\n      if: steps.changed.outputs.cpp_count != '0'", text)


if __name__ == "__main__":
    unittest.main()
