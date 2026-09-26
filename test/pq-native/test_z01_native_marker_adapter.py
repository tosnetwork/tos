import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.z01_native_marker_adapter import MarkerError, adapt, read_log_prefix, read_log_tail


def marker(height: int, root: str = "11" * 32) -> bytes:
    return (f"[2026-09-25 20:00:00.000000] BlockFinalizedInMasterchain "
            f"{{block=(-1,8000000000000000,{height}):{root}:{'22' * 32}}}\n").encode()


class NativeMarkerControls(unittest.TestCase):
    def test_raw_prefix_and_process_bound_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory)
            raw = b"noise\n" + b"".join(marker(h) for h in (10, 11, 12, 13))
            (db / "log").write_bytes(raw)
            original, source = read_log_prefix(db / "log", db)
            receipt = adapt(original, source, node="node1", pid=111, start_ticks=222,
                            db_root=db, first=10, last=13)
            self.assertEqual(receipt["ids"]["11"], [-1, -(1 << 63), 11, "11" * 32, "22" * 32])
            self.assertEqual(receipt["source"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual((receipt["pid"], receipt["start_ticks"]), (111, 222))
            with (db / "log").open("ab") as log:
                log.write(marker(14))
            self.assertEqual(read_log_tail(db / "log", source, len(raw)), marker(14))
            self.assertEqual(read_log_tail(db / "log", source, len(raw) + len(marker(14))), b"")
            (db / "log").write_bytes(b"short")
            with self.assertRaisesRegex(MarkerError, "changed inode or was truncated"):
                read_log_tail(db / "log", source, len(raw))
            with self.assertRaisesRegex(MarkerError, "source or SHA differs"):
                adapt(original + b"x", source, node="node1", pid=111, start_ticks=222,
                      db_root=db, first=10, last=13)
            with self.assertRaisesRegex(MarkerError, "not the node DB log"):
                read_log_prefix(db / "another.log", db)

    def test_missing_conflict_and_zero_digest_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory)
            for raw, message in (
                (b"".join(marker(h) for h in (10, 12, 13)), "lacks a governance-window height"),
                (b"".join(marker(h) for h in (10, 11, 12, 13)) + marker(11, "33" * 32),
                 "conflicting full ID"),
                (b"".join(marker(h, "00" * 32 if h == 11 else "11" * 32)
                          for h in (10, 11, 12, 13)), "zero root/file hash"),
            ):
                (db / "log").write_bytes(raw)
                original, source = read_log_prefix(db / "log", db)
                with self.subTest(message=message), self.assertRaisesRegex(MarkerError, message):
                    adapt(original, source, node="node1", pid=111, start_ticks=222,
                          db_root=db, first=10, last=13)


if __name__ == "__main__":
    unittest.main()
