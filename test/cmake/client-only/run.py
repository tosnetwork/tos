#!/usr/bin/env python3
"""Check CMake/ClientOnly.cmake's rules.

A minimal project that includes the module is configured and reports what the
module decided. Windows (simulated with TOS_CLIENT_ONLY_ASSUME_WIN32) is
client-only by default and refuses an explicit OFF; elsewhere the option is
off unless asked for, and asking for it selects the toslib-only graph.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "CMake/ClientOnly.cmake"
CMAKE = shutil.which("cmake")
REFUSAL = "Windows supports the client toolchain only (TOS_CLIENT_ONLY=ON)"

PROJECT = f"""cmake_minimum_required(VERSION 3.16)
project(client_only_probe NONE)
include("{MODULE.as_posix()}")
message(STATUS "probe CLIENT_ONLY=[${{TOS_CLIENT_ONLY}}] ONLY_TOSLIB=[${{TOS_ONLY_TOSLIB}}]")
"""


class ClientOnlyTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="tos-client-only-"))
        (self.work / "src").mkdir()
        (self.work / "src/CMakeLists.txt").write_text(PROJECT)

    def tearDown(self):
        shutil.rmtree(self.work)

    def run_cmake(self, *args):
        build = Path(tempfile.mkdtemp(dir=self.work))
        return subprocess.run(
            [CMAKE, "-S", str(self.work / "src"), "-B", str(build), *args],
            capture_output=True,
            text=True,
        )

    def configure(self, *args):
        result = self.run_cmake(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        line = next(x for x in result.stdout.splitlines() if "probe CLIENT_ONLY=" in x)
        client_only = line.split("CLIENT_ONLY=[", 1)[1].split("]", 1)[0]
        only_toslib = line.split("ONLY_TOSLIB=[", 1)[1].split("]", 1)[0]
        return client_only, only_toslib

    def test_default_elsewhere_builds_the_node(self):
        self.assertEqual(self.configure(), ("OFF", ""))

    def test_requested_elsewhere_selects_the_client_graph(self):
        self.assertEqual(self.configure("-DTOS_CLIENT_ONLY=ON"), ("ON", "true"))

    def test_windows_defaults_to_client_only(self):
        self.assertEqual(self.configure("-DTOS_CLIENT_ONLY_ASSUME_WIN32=ON"), ("ON", "true"))

    def test_windows_accepts_an_explicit_on(self):
        self.assertEqual(
            self.configure("-DTOS_CLIENT_ONLY_ASSUME_WIN32=ON", "-DTOS_CLIENT_ONLY=ON"),
            ("ON", "true"),
        )

    def test_windows_refuses_an_explicit_off(self):
        result = self.run_cmake("-DTOS_CLIENT_ONLY_ASSUME_WIN32=ON", "-DTOS_CLIENT_ONLY=OFF")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(REFUSAL, " ".join((result.stdout + result.stderr).split()))


if __name__ == "__main__":
    if CMAKE is None:
        sys.exit("cmake not found")
    unittest.main()
