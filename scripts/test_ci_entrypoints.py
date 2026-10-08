"""Check shared command contracts and fail-closed execution, not TOS correctness."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Independent command oracles from the pre-extraction workflow run blocks.
STRICT = [
    ["cmake", "-S", ".", "-B", "build", "-G", "Ninja",
     "-DCMAKE_C_COMPILER=clang-21", "-DCMAKE_CXX_COMPILER=clang++-21",
     "-DCMAKE_BUILD_TYPE=Release", "-DTOS_USE_JEMALLOC=ON", "-DTOS_USE_LLD=On",
     "-DTOS_WERROR_BUILD=On", "-DTOS_ARCH=x86-64-v2", "-DPORTABLE=x86-64-v2",
     "-DCMAKE_C_COMPILER_LAUNCHER=ccache", "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache"],
    ["ccache", "--zero-stats"],
    ["ninja", "-C", "build"],
]
SOURCE = [
    ["cmake", "-S", ".", "-B", "build-source-guards", "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release"],
    ["python3", "scripts/check-source-guard-inventory.py", "--build-dir", "build-source-guards"],
    ["ctest", "-L", "source-guard", "--no-tests=error", "--output-on-failure"],
]
REGISTRY = [
    ["cmake", "-S", ".", "-B", "build", "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release"],
    ["cmake", "--build", "build", "--target", "func", "fift", "-j2"],
    ["test-tos-service-native-registry-v1.sh"],
    ["check-nominator-pool-code-lock.sh"],
    ["check-single-nominator-code-lock.sh"],
    ["check-root-authority-off-the-node.sh"],
    ["cmake", "--build", "build", "--target", "gen_fif", "-j2"],
    ["git", "diff", "--exit-code"],
]
NATIVE_BUILD = [
    ["install-rust-toolchain.sh"],
    ["build-ubuntu-shared.sh", "-t", "-c"],
    ["ccache", "-sp"],
    ["git", "diff", "--exit-code"],
]
NATIVE_PYTHON = [
    ["uv", "run", "--frozen", "python", "-m", "pytest",
     "test/pq-native/test_n6_startup_not_synced.py",
     "test/pq-native/test_z01_final_capture.py",
     "test/pq-native/test_z01_proof_controls.py"],
    ["uv", "run", "--frozen", "pytest"],
]
PREFLIGHT = [
    ["python3", "scripts/ci_workflow_inventory.py", "--verify-baseline", "doc/ci-local-first-baseline.json"],
    ["python3", "scripts/test_ci_workflow_inventory.py", "-v"],
    ["python3", "scripts/test_ci_entrypoints.py", "-v"],
    ["python3", "scripts/test_ci_native.py", "-v"],
    ["python3", "scripts/test_ci_docker.py", "-v"],
]
STUB = r'''#!/usr/bin/env bash
set -eu
count=0
if [ -f "$CI_TEST_LOG.count" ]; then read -r count < "$CI_TEST_LOG.count"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$CI_TEST_LOG.count"
{ printf '%s\0' "$PWD" "${0##*/}" "$@"; printf '\n'; } >> "$CI_TEST_LOG"
if [ "$count" = "${CI_TEST_FAIL_AT:-0}" ]; then
  echo INTENDED_COMMAND_FAILURE >&2
  exit 17
fi
if [ "${0##*/}" = cmake ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -B ]; then mkdir -p "$2"; break; fi
    shift
  done
fi
'''


class EntryPointTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ci entrypoint ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "ci").mkdir()
        self.entrypoint = self.root / "ci/run"
        shutil.copy2(ROOT / "ci/run", self.entrypoint)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "scripts").mkdir()
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ)
        for name in ("BUILD_ARCH", "CI_BUILD_JOBS", "BASH_ENV", "ENV", "SHELLOPTS", "CI_TEST_FAIL_AT"):
            self.env.pop(name, None)
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"], CI_TEST_LOG=str(self.log), LC_ALL="C")
        for name in ("cmake", "ninja", "ccache", "python3", "ctest", "make", "git", "uv"):
            self.write_stub(self.bin / name)
        (self.root / "assembly/native").mkdir(parents=True)
        self.write_stub(self.root / "assembly/native/build-ubuntu-shared.sh")
        self.write_stub(self.root / "scripts/install-rust-toolchain.sh")
        self.env["HOME"] = str(self.root / "home")
        (self.root / "home").mkdir()
        for command in REGISTRY:
            if command[0].endswith(".sh"):
                self.write_stub(self.root / "scripts" / command[0])

    def write_stub(self, path: Path) -> None:
        path.write_text(STUB)
        path.chmod(0o755)

    def invoke(self, *args: str, via_sh: bool = False, **env: str) -> subprocess.CompletedProcess:
        (self.root / "build/.tos-ci-profile").unlink(missing_ok=True)
        self.log.unlink(missing_ok=True)
        Path(str(self.log) + ".count").unlink(missing_ok=True)
        command = [str(self.entrypoint), *args]
        if via_sh:
            command = ["sh", "-c", shlex.join(command)]
        return subprocess.run(command, cwd=self.bin, env={**self.env, **env},
                              text=True, capture_output=True, check=False, timeout=30)

    def records(self) -> list[dict]:
        if not self.log.exists():
            return []
        records = []
        for line in self.log.read_text().splitlines():
            cwd, *argv, sentinel = line.split("\0")
            self.assertEqual(sentinel, "")
            records.append({"cwd": cwd, "argv": argv})
        return records

    def commands(self) -> list[list[str]]:
        return [record["argv"] for record in self.records()]

    def test_native_build_and_python_command_contracts(self) -> None:
        for task, expected in (("native-build", NATIVE_BUILD), ("native-python", NATIVE_PYTHON)):
            with self.subTest(task=task):
                result = self.invoke(task)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.commands(), expected)
                for index in range(1, len(expected) + 1):
                    result = self.invoke(task, CI_TEST_FAIL_AT=str(index))
                    self.assertEqual(result.returncode, 17, result.stderr)
                    self.assertEqual(self.commands(), expected[:index])

    def test_incompatible_profiles_are_rejected_without_running_commands(self) -> None:
        result = self.invoke("strict-build")
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.commands()
        result = subprocess.run(
            [str(self.entrypoint), "native-build"],
            cwd=self.root, env=self.env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Incompatible CI build profile", result.stderr)
        self.assertEqual(self.commands(), before)

    def test_unowned_cmake_directory_is_rejected_without_running_commands(self) -> None:
        (self.root / "build").mkdir()
        (self.root / "build/CMakeCache.txt").write_text("unowned cache")
        result = self.invoke("native-build")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Existing unowned build directory", result.stderr)
        self.assertEqual(self.commands(), [])

    def test_native_test_command_has_no_selector(self) -> None:
        result = self.invoke("native-tests")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.commands(), [["python3", "ci/native_tests.py", "--build-dir", "build"]]
        )

    def test_all_extracted_command_sequences(self) -> None:
        for task, expected in (("strict-build", STRICT), ("source-guards", SOURCE),
                               ("native-registry", REGISTRY), ("rust-format", [["make", "-C", "tosctl/src", "fmt-check"]]),
                               ("preflight", PREFLIGHT)):
            with self.subTest(task=task):
                result = self.invoke(task)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.commands(), expected)
                for record in self.records():
                    cwd = self.root / "build-source-guards" if record["argv"][0] == "ctest" else self.root
                    self.assertEqual(Path(record["cwd"]), cwd)

    def test_every_external_failure_stops_the_task(self) -> None:
        for task, expected in (("strict-build", STRICT), ("source-guards", SOURCE),
                               ("native-registry", REGISTRY), ("preflight", PREFLIGHT)):
            for index in range(1, len(expected) + 1):
                with self.subTest(task=task, command=index):
                    result = self.invoke(task, CI_TEST_FAIL_AT=str(index))
                    self.assertEqual(result.returncode, 17, result.stderr)
                    self.assertIn("INTENDED_COMMAND_FAILURE", result.stderr)
                    self.assertEqual(self.commands(), expected[:index])

    def test_sh_caller_preserves_bash_failure_semantics(self) -> None:
        result = self.invoke("native-registry", via_sh=True, CI_TEST_FAIL_AT="3")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(self.commands(), REGISTRY[:3])

    def test_no_task_and_extra_arguments_are_errors(self) -> None:
        for args in ((), ("strict-build", "ignored")):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args).returncode, 2)
                self.assertEqual(self.commands(), [])

    def test_unknown_and_unimplemented_aggregates_are_errors(self) -> None:
        for task in ("full", "fast", "all", "quantum", "missing", "../../bin/sh", "list; touch marker"):
            with self.subTest(task=task):
                result = self.invoke(task)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Unsupported CI task", result.stderr)
                self.assertEqual(self.commands(), [])

    def test_list_does_not_run_any_check(self) -> None:
        result = self.invoke("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No full/fast aggregate is implemented", result.stdout)
        self.assertEqual(self.commands(), [])

    def test_explicit_worker_limit_does_not_change_build_flags(self) -> None:
        result = self.invoke("strict-build", CI_BUILD_JOBS="8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commands(), STRICT[:-1] + [["ninja", "-C", "build", "-j8"]])

    def test_invalid_worker_limits_never_start_a_build(self) -> None:
        for value in ("0", "-1", "1.5", "01", "10000", "2; touch marker"):
            with self.subTest(value=value):
                result = self.invoke("strict-build", CI_BUILD_JOBS=value)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.commands(), [])

    def test_strict_architecture_cannot_drift(self) -> None:
        result = self.invoke("strict-build", BUILD_ARCH="native")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.commands(), [])

    def test_explicit_original_architecture_retains_contract(self) -> None:
        result = self.invoke("strict-build", BUILD_ARCH="x86-64-v2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commands(), STRICT)

    def test_generated_source_pollution_is_not_hidden(self) -> None:
        (self.root / "crypto/smartcont/auto").mkdir(parents=True)
        result = self.invoke("native-registry")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.commands(), REGISTRY[:-1])

    def real_ctest_fixture(self, outcome: str | None) -> subprocess.CompletedProcess:
        for name in ("cmake", "ctest", "ninja"):
            if shutil.which(name) is None:
                self.fail(f"Missing required fixture tool: {name}")
            (self.bin / name).unlink()
        cmake = "cmake_minimum_required(VERSION 3.16)\nproject(CIGuardFixture NONE)\nenable_testing()\n"
        if outcome:
            cmake += (f'add_test(NAME actual-guard COMMAND "${{CMAKE_COMMAND}}" -E {outcome})\n'
                      'set_tests_properties(actual-guard PROPERTIES LABELS source-guard)\n')
        (self.root / "CMakeLists.txt").write_text(cmake)
        result = self.invoke("source-guards")
        result.stdout = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
        result.stderr = re.sub(r"\x1b\[[0-9;]*m", "", result.stderr)
        return result

    def test_real_ctest_empty_selection_fails(self) -> None:
        result = self.real_ctest_fixture(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No tests were found", result.stdout + result.stderr)

    def test_real_ctest_registered_failure_propagates(self) -> None:
        result = self.real_ctest_fixture("false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0% tests passed", result.stdout + result.stderr)

    def test_real_ctest_registered_guard_passes(self) -> None:
        result = self.real_ctest_fixture("true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("100% tests passed, 0 tests failed out of 1", result.stdout)


class NativeBuilderTests(unittest.TestCase):
    setUp = EntryPointTests.setUp
    write_stub = EntryPointTests.write_stub
    records = EntryPointTests.records
    commands = EntryPointTests.commands

    # Use a separate instance of the real native shell script with tool stubs.
    # No TOS compilation is claimed by these argv/failure controls.
    def builder(self, *args: str, **env: str) -> subprocess.CompletedProcess:
        shutil.copy2(
            ROOT / "assembly/native/build-ubuntu-shared.sh",
            self.root / "build-ubuntu-shared.sh",
        )
        for name in (
            "storage/storage-daemon/storage-daemon",
            "validator-engine/validator-engine",
            "lite-client/lite-client",
            "crypto/fift",
        ):
            target = self.root / "build" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            self.write_stub(target)
        self.write_stub(self.bin / "ldd")
        self.log.unlink(missing_ok=True)
        Path(str(self.log) + ".count").unlink(missing_ok=True)
        return subprocess.run(
            ["bash", str(self.root / "build-ubuntu-shared.sh"), *args],
            cwd=self.root, env={**self.env, **env}, capture_output=True,
            text=True, check=False, timeout=30,
        )

    def test_native_workers_cover_main_and_separate_signer_builds(self) -> None:
        for args in (("-t", "-c"), ("-c",)):
            with self.subTest(args=args):
                result = self.builder(*args, CI_BUILD_JOBS="7")
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [argv for argv in self.commands() if argv[0] == "ninja"]
                self.assertEqual(len(calls), 2)
                self.assertTrue(all(argv[1:3] == ["-j", "7"] for argv in calls))
                if "-t" in args:
                    self.assertIn("all-tests", calls[0])
                    self.assertIn("install", calls[0])
                self.assertEqual(calls[-1][-3:], ["-C", "pq-key", "tos-pq-key"])

    def test_native_invalid_workers_reject_before_configuration(self) -> None:
        result = self.builder("-t", "-c", CI_BUILD_JOBS="0")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.commands(), [])

    def test_native_cache_directory_and_limit_are_respected(self) -> None:
        directory = self.root / "dedicated-cache"
        result = self.builder(
            "-t", "-c", CCACHE_DIR=str(directory), CCACHE_MAXSIZE="1G"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(directory.is_dir())
        self.assertEqual(self.commands()[0], ["ccache", "-M", "1G"])

    def test_native_main_compile_failure_prevents_signer_and_smoke_tests(self) -> None:
        result = self.builder("-t", "-c", CI_TEST_FAIL_AT="3")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Can't compile tos", result.stdout)
        self.assertEqual([x[0] for x in self.commands()], ["ccache", "cmake", "ninja"])


class WorkflowRoutingTests(unittest.TestCase):
    def workflow(self, name: str) -> str:
        return (ROOT / ".github/workflows" / name).read_text()

    def test_migrated_jobs_call_shared_commands(self) -> None:
        for name, commands in {
            "build-tos-linux-x86-64-werror.yml": ("strict-build", "preflight"),
            "source-guards.yml": ("source-guards",),
            "source-hygiene.yml": ("native-registry", "rust-format", "preflight"),
            "ci-cache-validation.yml": ("preflight",),
        }.items():
            for command in commands:
                with self.subTest(workflow=name, task=command):
                    self.assertIn(f"run: ci/run {command}\n", self.workflow(name))

    def test_fast_preflight_precedes_expensive_strict_installation(self) -> None:
        text = self.workflow("build-tos-linux-x86-64-werror.yml")
        self.assertLess(text.index("run: ci/run preflight"), text.index("name: Install Clang 21"))

    def test_falcon_caches_are_compatible_and_never_skip_checks(self) -> None:
        text = self.workflow("wallet-falcon.yml")
        self.assertIn("- '.github/actions/native-cache/**'", text)
        self.assertLess(text.index("scripts/install-rust-toolchain.sh"), text.index("uses: Swatinem/rust-cache@"))
        self.assertLess(text.index("uses: ./.github/actions/native-cache"), text.index("name: Build both VMs"))
        self.assertIn("steps.native-cache.outputs.host-key", text)
        self.assertIn("matrix.arch", text)
        self.assertIn("workspaces: tosctl/src -> target", text)
        self.assertIn("cache-bin: false", text)
        self.assertNotIn("cache-workspace-crates: true", text)
        self.assertNotIn("cache-all-crates: true", text)
        self.assertNotIn("cache-hit", text)
        self.assertIn("arch: x86_64", text)
        self.assertIn("arch: aarch64", text)

    def test_registry_cache_runs_before_shared_native_build(self) -> None:
        text = self.workflow("source-hygiene.yml")
        self.assertIn("profile: native-registry-release", text)
        self.assertLess(text.index("uses: ./.github/actions/native-cache"), text.index("run: ci/run native-registry"))
        self.assertIn("if: always()\n        run: ccache --show-stats", text)

    def test_entrypoint_changes_trigger_cache_contract_validation(self) -> None:
        text = self.workflow("ci-cache-validation.yml")
        self.assertEqual(text.count("- 'ci/**'"), 2)
        self.assertEqual(text.count("- 'scripts/test_ci_entrypoints.py'"), 2)


if __name__ == "__main__":
    unittest.main()
