"""Failure controls for the authenticated-export orchestrator; no fake passing replay."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import run_rust as gate


class BoundsAndProcesses(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_read_exact_bound_and_one_over(self):
        path = self.root / "input"
        path.write_bytes(b"1234")
        self.assertEqual(gate.bounded_read(path, 4), b"1234")
        with self.assertRaisesRegex(ValueError, "byte limit"):
            gate.bounded_read(path, 3)

    def test_fifo_is_rejected_without_waiting(self):
        path = self.root / "fifo"
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "regular file"):
            gate.bounded_read(path, 4)

    def test_symlink_is_rejected(self):
        path = self.root / "input"
        path.write_bytes(b"1234")
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            gate.bounded_read(link, 4)

    def test_process_success_and_nonzero(self):
        output, _ = gate.execute([sys.executable, "-c", "print('control')"], self.root, "ok")
        self.assertEqual(output, b"control\n")
        with self.assertRaisesRegex(ValueError, "exit 7"):
            gate.execute(
                [sys.executable, "-c", "print('control'); raise SystemExit(7)"], self.root, "bad"
            )

    def test_child_output_cannot_grow_past_file_cap(self):
        with mock.patch.object(gate, "MAX_OUTPUT", 128):
            with self.assertRaisesRegex(ValueError, "failed"):
                gate.execute(
                    [sys.executable, "-c", "import os; os.write(1,b'x'*128); os.write(1,b'y')"],
                    self.root,
                    "large",
                )
        self.assertLessEqual((self.root / "large.stdout").stat().st_size, 128)

    def test_parent_rejects_overlong_diagnostics(self):
        with mock.patch.object(gate, "MAX_DIAGNOSTICS", 3):
            with self.assertRaisesRegex(ValueError, "byte limit"):
                gate.execute([sys.executable, "-c", "print('1234')"], self.root, "diagnostics")

    def test_timeout_kills_descendant_group(self):
        program = "import os,time\npid=os.fork()\nif pid: print(pid,flush=True)\ntime.sleep(20)\n"
        with mock.patch.object(gate, "TIMEOUT", 1):
            with self.assertRaisesRegex(ValueError, "timed out; process group killed"):
                gate.execute([sys.executable, "-c", program], self.root, "timeout")
        pid = int((self.root / "timeout.stdout").read_text())
        for _ in range(40):
            status = Path(f"/proc/{pid}/stat")
            if not status.exists() or status.read_text().split()[2] == "Z":
                break
            time.sleep(0.05)
        else:
            self.fail("descendant remains live after timeout")

    def test_snapshot_rejects_budget_before_reading_payload(self):
        source = self.root / "manifest.json"
        source.write_text(json.dumps({"files": [{"path": "absent", "size": gate.MAX_CORPUS + 1}]}))
        with self.assertRaisesRegex(ValueError, "budget"):
            gate.snapshot(source, self.root / "snapshot")

    def test_failed_native_with_complete_stdout_never_invokes_rust(self):
        native_binary = self.root / "native"
        native_binary.write_text(
            '#!/usr/bin/env python3\nprint(\'{"kind": "control"}\')\nraise SystemExit(7)\n'
        )
        native_binary.chmod(0o700)
        rust_binary = self.root / "rust"
        marker = self.root / "rust-started"
        rust_binary.write_text(
            f"#!/usr/bin/env python3\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n"
        )
        rust_binary.chmod(0o700)
        topology = self.root / "topology.json"
        topology.write_text(json.dumps({"rows": 576, "carried_edges": 474, "segments": 102}))
        receipt = self.root / "result.json"
        manifest = {"blocks": [], "supplements": [], "expected": [{"kind": "control"}]}
        argv = [
            "run_rust",
            "--native",
            str(native_binary),
            "--rust",
            str(rust_binary),
            "--topology",
            str(topology),
            "--output",
            str(receipt),
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(
                gate, "snapshot", return_value=(manifest, {}, self.root / "manifest.json", "unused")
            ),
            mock.patch.object(gate.native, "check_records") as check_records,
        ):
            with self.assertRaisesRegex(ValueError, r"native failed \(exit 7"):
                gate.main()
        check_records.assert_not_called()
        self.assertFalse(marker.exists())
        self.assertFalse(receipt.exists())

    def test_existing_receipt_is_not_reused(self):
        receipt = self.root / "receipt.json"
        receipt.write_text("old receipt")
        result = subprocess.run(
            [
                sys.executable,
                str(Path(gate.__file__)),
                "--native",
                "/absent",
                "--rust",
                "/absent",
                "--output",
                str(receipt),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output receipt already exists", result.stderr)
        self.assertEqual(receipt.read_text(), "old receipt")


class RootArtifacts(unittest.TestCase):
    def setUp(self):
        # Unit-level shape control only; no synthetic on-chain replay is accepted.
        self.expected = [
            {
                "kind": "transaction",
                "description": "ordinary",
                "lt": "42",
                "result_hash": "a" * 64,
                "account_hash": "b" * 64,
            }
        ]
        self.row = ["0", "1", "42", "EQUAL", "account=", "-", "a" * 64, "b" * 64, "c" * 64]

    def encoded(self, rows):
        return ("\n".join("\t".join(row) for row in rows) + "\n").encode()

    def test_actual_roots_are_required_even_with_equal_labels(self):
        gate.check_rust_roots(self.encoded([self.row]), self.expected)
        for index in (6, 7):
            changed = self.row.copy()
            changed[index] = "d" * 64
            with self.assertRaisesRegex(ValueError, "differs from complete parity"):
                gate.check_rust_roots(self.encoded([changed]), self.expected)

    def test_old_output_and_invalid_shard_root_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "differs from complete parity"):
            gate.check_rust_roots(self.encoded([self.row[:6]]), self.expected)
        changed = self.row.copy()
        changed[8] = "-"
        with self.assertRaisesRegex(ValueError, "invalid ShardAccount root"):
            gate.check_rust_roots(self.encoded([changed]), self.expected)

    def test_missing_and_duplicate_output_are_rejected(self):
        for data in (b"", self.encoded([self.row, self.row])):
            with self.assertRaisesRegex(ValueError, "missing/extra"):
                gate.check_rust_roots(data, self.expected)


if __name__ == "__main__":
    unittest.main()
