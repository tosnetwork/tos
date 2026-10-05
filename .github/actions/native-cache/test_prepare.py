"""Offline checks for cache identity and early CMake launcher initialization."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from prepare import cache_settings, cpu_signature, digest, file_digest


class CacheIdentityTests(unittest.TestCase):
    def test_ignores_clock_core_number_and_feature_order(self):
        first = "processor: 0\nmodel name: example\ncpu MHz: 3000\nflags: sse avx sse\n"
        second = "processor: 9\nmodel name: example\ncpu MHz: 1000\nflags: avx sse\n"
        self.assertEqual(cpu_signature(first), cpu_signature(second))

    def test_different_instruction_sets_are_isolated(self):
        self.assertNotEqual(
            digest(cpu_signature("flags: sse avx\n")), digest(cpu_signature("flags: sse\n"))
        )

    def test_different_cpu_models_are_isolated(self):
        self.assertNotEqual(
            cpu_signature("model: 1\nflags: sse\n"), cpu_signature("model: 2\nflags: sse\n")
        )

    def test_arm_capabilities_are_identified(self):
        self.assertNotEqual(
            cpu_signature("CPU part: 0xd0c\nFeatures: fp asimd\n"),
            cpu_signature("CPU part: 0xd0c\nFeatures: fp asimd sve\n"),
        )

    def test_missing_cpu_identity_is_refused(self):
        for value in ("", "processor: 0\n", "flags:\n"):
            with self.assertRaises(ValueError):
                cpu_signature(value)

    def test_binary_identity_uses_contents_not_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compiler"
            path.write_bytes(b"version1")
            before = file_digest(path)
            stamp = path.stat().st_mtime
            path.write_bytes(b"version2")
            os.utime(path, (stamp, stamp))
            self.assertNotEqual(before, file_digest(path))

    def test_profile_and_host_are_in_both_archive_and_object_namespace(self):
        for profile in ("release", "debug", "asan-ubsan"):
            settings, prefix = cache_settings(Path("/src"), Path("/tmp"), "a" * 64, profile, "2G")
            self.assertEqual(settings["CCACHE_NAMESPACE"], prefix)
            self.assertIn(profile, prefix)
            self.assertIn("a" * 64, prefix)

    def test_does_not_change_compiler_or_runtime_flags(self):
        settings, _ = cache_settings(Path("/src"), Path("/tmp"), "a" * 64, "release", "2G")
        self.assertEqual(settings["CCACHE_COMPILERCHECK"], "content")
        self.assertEqual(settings["CCACHE_SLOPPINESS"], "")
        for language in ("C", "CXX"):
            self.assertEqual(settings[f"CMAKE_{language}_COMPILER_LAUNCHER"], "ccache")
        self.assertFalse(
            {"CC", "CXX", "CFLAGS", "CXXFLAGS", "RUSTFLAGS", "TOS_ARCH"} & settings.keys()
        )
        self.assertFalse(Path(settings["CCACHE_CONFIGPATH"]).is_relative_to(settings["CCACHE_DIR"]))

    def test_rejects_invalid_inputs_and_environment_injection(self):
        for profile, size in (("../release", "2G"), ("release\nKEY=bad", "2G"), ("release", "0")):
            with self.assertRaises(ValueError):
                cache_settings(Path("/src"), Path("/tmp"), "a" * 64, profile, size)
        with self.assertRaises(ValueError):
            cache_settings(Path("/src\nBAD=yes"), Path("/tmp"), "a" * 64, "release", "2G")

    def test_cmake_launcher_reaches_c_cpp_and_early_subdirectories(self):
        for tool in ("cmake", "ninja", "cc", "c++"):
            self.assertIsNotNone(shutil.which(tool), f"Required fixture tool missing: {tool}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "early").mkdir()
            trace = root / "launcher.log"
            # A spy, not a fake cache-hit claim. The hosted integration check
            # separately requires actual cold misses and restored-cache hits.
            launcher = root / "bin" / "ccache"
            launcher.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$LAUNCHER_TRACE"\nexec "$@"\n')
            launcher.chmod(0o755)
            (root / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.17)\nproject(probe C CXX)\n"
                "add_subdirectory(early)\nadd_executable(probe main.cpp)\n"
                "target_link_libraries(probe early)\n"
            )
            (root / "early/CMakeLists.txt").write_text("add_library(early STATIC early.c)\n")
            (root / "early/early.c").write_text("int answer(void) { return 42; }\n")
            (root / "main.cpp").write_text(
                'extern "C" int answer(void);\nint main() { return answer() != 42; }\n'
            )
            settings, _ = cache_settings(root, root, "a" * 64, "release", "2G")
            env = dict(
                os.environ,
                **settings,
                PATH=f"{root / 'bin'}:{os.environ['PATH']}",
                LAUNCHER_TRACE=str(trace),
            )
            for command in (
                ["cmake", "-S", str(root), "-B", str(root / "build"), "-G", "Ninja"],
                ["cmake", "--build", str(root / "build")],
                [str(root / "build/probe")],
            ):
                result = subprocess.run(command, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            log = trace.read_text()
            self.assertIn("main.cpp", log)
            self.assertIn("early.c", log)


if __name__ == "__main__":
    unittest.main()
