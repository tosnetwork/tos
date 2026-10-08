#!/usr/bin/env python3
"""Check CMake/CompilerAutodetect.cmake's selection rules.

A minimal project that includes the module is configured with stand-in
clang/clang++ executables on PATH. The test reads back what the module chose:
it may only choose clang when the caller chose nothing, and it sets both
compilers or neither.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "CMake/CompilerAutodetect.cmake"
CMAKE = shutil.which("cmake")

PROJECT = f"""cmake_minimum_required(VERSION 3.16)
include("{MODULE.as_posix()}")
project(autodetect_probe NONE)
message(STATUS "probe C=[${{CMAKE_C_COMPILER}}] CXX=[${{CMAKE_CXX_COMPILER}}]")
"""


class CompilerAutodetectTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="tos-autodetect-"))
        self.bin = self.work / "bin"
        self.bin.mkdir()
        (self.work / "src").mkdir()
        (self.work / "src/CMakeLists.txt").write_text(PROJECT)
        self.toolchain = self.work / "toolchain.cmake"
        self.toolchain.write_text("# selects nothing\n")
        # The generator needs a build program; the probe project builds nothing.
        self.fake("make")

    def tearDown(self):
        shutil.rmtree(self.work)

    def fake(self, *names):
        for name in names:
            tool = self.bin / name
            tool.write_text("#!/bin/sh\nexit 0\n")
            tool.chmod(0o755)

    def configure(self, *args, env=None):
        environment = {"PATH": str(self.bin), "HOME": str(self.work)}
        environment.update(env or {})
        build = Path(tempfile.mkdtemp(dir=self.work))
        result = subprocess.run(
            [CMAKE, "-S", str(self.work / "src"), "-B", str(build), *args],
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        line = next(x for x in result.stdout.splitlines() if "probe C=" in x)
        c = line.split("C=[", 1)[1].split("]", 1)[0]
        cxx = line.split("CXX=[", 1)[1].split("]", 1)[0]
        return c, cxx

    def test_nothing_selected_picks_both_clang_drivers(self):
        self.fake("clang", "clang++")
        self.assertEqual(self.configure(), (str(self.bin / "clang"), str(self.bin / "clang++")))

    def test_environment_compilers_win(self):
        self.fake("clang", "clang++")
        self.assertEqual(self.configure(env={"CC": "/opt/cc", "CXX": "/opt/cxx"}), ("", ""))

    def test_command_line_compiler_wins(self):
        self.fake("clang", "clang++")
        self.assertEqual(self.configure("-DCMAKE_CXX_COMPILER=/opt/cxx"), ("", "/opt/cxx"))

    def test_toolchain_file_is_left_alone(self):
        self.fake("clang", "clang++")
        self.assertEqual(self.configure(f"-DCMAKE_TOOLCHAIN_FILE={self.toolchain}"), ("", ""))
        self.assertEqual(
            self.configure(env={"CMAKE_TOOLCHAIN_FILE": str(self.toolchain)}), ("", "")
        )

    def test_one_environment_compiler_prevents_a_partial_override(self):
        self.fake("clang", "clang++")
        self.assertEqual(self.configure(env={"CC": "/opt/cc"}), ("", ""))

    def test_windows_host_is_left_alone(self):
        self.fake("clang", "clang++")
        self.assertEqual(self.configure("-DTOS_AUTODETECT_ASSUME_WIN32=ON"), ("", ""))

    def test_one_clang_driver_selects_nothing(self):
        self.fake("clang")
        self.assertEqual(self.configure(), ("", ""))


if __name__ == "__main__":
    if CMAKE is None:
        sys.exit("cmake not found")
    unittest.main()
