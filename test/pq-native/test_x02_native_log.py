"""Live local-process controls for X02's validator stderr-file cursor."""

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "scripts/x02_fault_evidence.py"
spec = importlib.util.spec_from_file_location("x02_fault_evidence", SOURCE)
x02 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(x02)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def start_ticks(pid):
    return x02._proc_start_ticks(Path(f"/proc/{pid}/stat").read_bytes())


class NativeLogCursorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="x02-native-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.log = self.directory / "log"
        self.writer = self.log.open("wb")
        self.addCleanup(self.writer.close)
        self.child = subprocess.Popen(
            [sys.executable, "-u", "-c", "import time; time.sleep(20)"],
            cwd=self.directory, stderr=subprocess.PIPE,
        )
        self.addCleanup(self._stop_child)
        identity = self.directory.stat()
        log_identity = self.log.stat()
        self.node = {"pid": self.child.pid,
                     "pid_start_ticks": start_ticks(self.child.pid),
                     "harness_pid": os.getpid(),
                     "harness_start_ticks": start_ticks(os.getpid()),
                     "data_dir": str(self.directory),
                     "db_dev": identity.st_dev, "db_ino": identity.st_ino,
                     "log_path": str(self.log),
                     "log_dev": log_identity.st_dev, "log_ino": log_identity.st_ino,
                     "exe_sha256": sha(f"/proc/{self.child.pid}/exe"),
                     "harness_exe_sha256": sha("/proc/self/exe")}

    def _stop_child(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.wait(timeout=5)
        assert self.child.stderr is not None
        self.child.stderr.close()

    def append(self, value):
        self.writer.write(value)
        self.writer.flush()

    def marker(self, height=11):
        now = time.time_ns()
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now // 1_000_000_000))
        return (f"[ 3][t 2][{stamp}.{now % 1_000_000_000:09d}]"
                "[BusRuntime.h:238] Published event "
                "BlockFinalizedInMasterchain@0x1"
                f"{{block=(-1,8000000000000000,{height}):"
                f"{'1' * 64}:{'2' * 64}}}\n").encode()

    def test_exact_pipe_db_log_and_incremental_prefix(self):
        self.append(b"first complete line\npartial")
        first = x02.capture_native_log(self.node)
        self.assertEqual(first["start_offset"], 0)
        self.assertEqual(first["end_offset"], len(b"first complete line\n"))
        self.assertEqual(first["partial_tail_bytes"], len(b"partial"))
        self.assertEqual(first["origin"]["stderr_link"],
                         f"pipe:[{first['origin']['stderr_pipe_inode']}]")
        self.append(b" rest\nsecond\n")
        second = x02.capture_native_log(self.node, first)
        self.assertEqual(second["start_offset"], first["end_offset"])
        self.assertEqual(second["end_offset"], self.log.stat().st_size)
        self.assertEqual(second["prior_prefix_sha256"], first["end_prefix_sha256"])

    def test_same_inode_truncate_and_replay_is_rejected(self):
        self.append(b"native marker H11 original bytes\n")
        first = x02.capture_native_log(self.node)
        identity = self.log.stat()
        self.writer.seek(0)
        self.writer.truncate(0)
        self.append(b"native marker H11 altered bytes!\n")
        self.assertEqual((self.log.stat().st_dev, self.log.stat().st_ino),
                         (identity.st_dev, identity.st_ino))
        with self.assertRaisesRegex(ValueError, "prefix changed"):
            x02.capture_native_log(self.node, first)

    def test_wrong_db_or_pipe_origin_is_rejected(self):
        self.append(b"line\n")
        bad = dict(self.node, db_ino=self.node["db_ino"] + 1)
        with self.assertRaisesRegex(ValueError, "DB directory"):
            x02.capture_native_log(bad)
        bad = dict(self.node, harness_pid=1)
        with self.assertRaisesRegex(ValueError, "parent"):
            x02.capture_native_log(bad)

    def test_cross_node_log_alias_is_rejected_before_capture(self):
        self.append(b"line\n")
        first = x02.capture_native_log(self.node)
        alias = dict(self.node, log_path=str(self.directory / "other"))
        with self.assertRaisesRegex(ValueError, "node DB log"):
            x02.capture_native_log(alias, first)

    def test_real_raw_marker_has_file_cursor_and_bounded_event_time(self):
        line = self.marker()
        self.append(line)
        first = x02.capture_native_log(self.node)
        ids = x02.native_log_ids(first, self.node)
        self.assertEqual(ids[11][:2], ("1" * 64, "2" * 64))
        self.assertLess(ids[11][2], first["read_completed_ns"])
        self.assertTrue(ids[11][3].endswith(f":{len(line)}"))
        self.assertEqual(x02.native_log_ids(x02.capture_native_log(self.node, first),
                                             self.node, first), {})

    def test_replayed_cursor_and_late_event_are_rejected(self):
        self.append(self.marker())
        first = x02.capture_native_log(self.node)
        later = x02.capture_native_log(self.node, first)
        bad = dict(later, start_offset=0)
        with self.assertRaisesRegex(ValueError, "cursor gap"):
            x02.native_log_ids(bad, self.node, first)
        bad = dict(first, realtime_completed_ns=first["realtime_completed_ns"] -
                   1_000_000_000)
        with self.assertRaisesRegex(ValueError, "paired clock|calibration jumped|after read"):
            x02.native_log_ids(bad, self.node)

    def test_pre_cut_marker_read_after_cut_keeps_original_event_time(self):
        self.append(self.marker(12))
        time.sleep(0.02)
        cut_finished_ns = time.monotonic_ns()
        row = x02.capture_native_log(self.node)
        marker = x02.native_log_ids(row, self.node)[12]
        self.assertLess(marker[2], cut_finished_ns)
        self.assertGreater(row["read_started_ns"], cut_finished_ns)


if __name__ == "__main__":
    unittest.main()
