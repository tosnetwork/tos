#!/usr/bin/env python3
"""The replay benchmark refuses a live or writable source database."""

from __future__ import annotations

import fcntl
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "wallet-index-replay-bench.py"
spec = importlib.util.spec_from_file_location("wallet_index_replay_bench", SCRIPT)
assert spec is not None and spec.loader is not None
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def make_source(root: Path) -> Path:
    source = root / "db"
    (source / "celldb").mkdir(parents=True)
    (source / "celldb" / "LOCK").write_bytes(b"")
    (source / "celldb" / "000001.sst").write_bytes(b"x" * 10)
    return source


def freeze(source: Path) -> None:
    for directory, _, names in os.walk(source):
        for name in names:
            os.chmod(Path(directory) / name, 0o444)


class SourceChecks(unittest.TestCase):
    def test_frozen_source_is_accepted_and_fingerprinted(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            source = make_source(Path(root))
            freeze(source)
            first = bench.check_source(source, allow_writable=False)
            self.assertIn("2 files", first)
            self.assertEqual(first, bench.check_source(source, allow_writable=False))

    def test_writable_source_is_refused_unless_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            source = make_source(Path(root))
            with self.assertRaises(SystemExit) as refused:
                bench.check_source(source, allow_writable=False)
            self.assertIn("writable", str(refused.exception))
            bench.check_source(source, allow_writable=True)

    def test_locked_source_is_refused_without_taking_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            source = make_source(Path(root))
            lock = source / "celldb" / "LOCK"
            holder = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import fcntl, sys, time\n"
                    "f = open(sys.argv[1], 'r+')\n"
                    "fcntl.lockf(f, fcntl.LOCK_EX)\n"
                    "print('locked', flush=True)\n"
                    "time.sleep(60)\n",
                    str(lock),
                ],
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                assert holder.stdout is not None
                self.assertEqual(holder.stdout.readline().strip(), "locked")
                self.assertEqual(bench.lock_holder(lock), holder.pid)
                with self.assertRaises(SystemExit) as refused:
                    bench.check_source(source, allow_writable=True)
                self.assertIn("live database", str(refused.exception))
            finally:
                holder.kill()
                holder.wait()
            # Released, and the query took no lock of its own.
            deadline = time.monotonic() + 5
            while bench.lock_holder(lock) is not None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIsNone(bench.lock_holder(lock))
            with lock.open("r+") as handle:
                fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_not_a_node_database_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(SystemExit):
                bench.check_source(Path(root), allow_writable=True)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class PassThrough(unittest.TestCase):
    def test_tuning_options_are_passed_through(self) -> None:
        self.assertEqual(
            bench.tuning_arguments(["--archive-keep-recent", "0", "--archive-open-files=1024"]),
            ["--archive-keep-recent", "0", "--archive-open-files", "1024"],
        )
        self.assertEqual(bench.tuning_arguments([]), [])

    def test_paths_listeners_and_unknown_options_are_refused(self) -> None:
        for arguments in (
            ["--source-db", "/live/db"],
            ["--source-db=/live/db"],
            ["--data-dir", "/elsewhere"],
            ["--data-dir=/elsewhere"],
            ["--listen", "0.0.0.0:80"],
            ["--listen=0.0.0.0:80"],
            ["--archive-keep-recent", "0", "--source-db", "/live/db"],
            ["--unknown"],
            ["--archive-keep-recent"],
            ["--archive-keep-recent", "-1"],
            ["--archive-open-files=lots"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                bench.tuning_arguments(arguments)

    def run_main(self, root: Path, passed: list[str]) -> Path:
        """Run the benchmark with a stand-in index that records its launch."""
        marker = root / "launched"
        fake = root / "fake-index"
        fake.write_text(f'#!/bin/sh\necho "$@" > {marker}\n')
        fake.chmod(0o755)
        source = make_source(root)
        freeze(source)
        bench.main(
            [
                "--binary",
                str(fake),
                "--source",
                str(source),
                "--work-dir",
                str(root / "runs"),
                "--label",
                "t",
                "--port",
                str(free_port()),
                "--duration",
                "1",
                "--interval",
                "0.1",
                "--warmup",
                "0",
                "--repeat",
                "1",
                "--",
                *passed,
            ]
        )
        return marker

    def test_refusal_happens_before_the_index_is_launched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(SystemExit) as refused:
                self.run_main(root, ["--source-db=/live/db"])
            self.assertIn("refusing index argument", str(refused.exception))
            self.assertFalse((root / "launched").exists())
            self.assertFalse((root / "runs").exists())

    def test_accepted_run_launches_with_the_checked_paths_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = self.run_main(root, ["--archive-keep-recent", "0"])
            launched = marker.read_text().split()
            self.assertEqual(launched.count("--source-db"), 1)
            self.assertEqual(
                launched[launched.index("--source-db") + 1], str((root / "db").resolve())
            )
            self.assertEqual(launched.count("--data-dir"), 1)
            self.assertEqual(launched[-2:], ["--archive-keep-recent", "0"])


if __name__ == "__main__":
    unittest.main()
