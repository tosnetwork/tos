"""Controls for strict output comparison; no generated positive chain fixtures."""

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("rel02", Path(__file__).with_name("run.py"))
resolve = load("rel02_resolve", Path(__file__).with_name("capture") / "resolve.py")

# A stand-in for the diagnostic replay: MODE --run BLOCKS SUPPLEMENTS. It replays the listed
# blocks the way the real child reports them, or misbehaves in one named way.
DIAGNOSTIC_STUB = """
import json, os, signal, sys, time
from pathlib import Path
mode, _, blocks, _ = sys.argv[1:]
paths = Path(blocks).read_text().split()
if mode == "killed":
    os.kill(os.getpid(), signal.SIGKILL)
if mode == "hang":
    time.sleep(30)
if mode in ("partial", "unannounced"):
    paths = paths[: len(paths) // 2]
for i, path in enumerate(paths):
    if mode != "unannounced":
        print("replay " + path, file=sys.stderr, flush=True)
    wc, seq = Path(path).stem.rsplit("-", 1)
    if mode == "missing-cell" and i == 0:
        print("pruned cell " + "AB" * 32 + " while reading master context 7", file=sys.stderr)
        print("DIAGFAIL " + path + " prunned branch", file=sys.stderr)
        continue
    if mode == "silent-block" and i == 1:
        continue
    print(json.dumps({"kind": "block", "workchain": int(wc), "seqno": int(seq)}))
    print(json.dumps({"kind": "transaction", "lt": str(i)}))
"""


class ComparisonControls(unittest.TestCase):
    def test_names_the_first_changed_consensus_field(self):
        expected = [{"gas_used": "4057", "result_hash": "abc"}]
        with self.assertRaisesRegex(ValueError, r"\$\[0\].gas_used"):
            runner.check_records(expected, [{"gas_used": "4058", "result_hash": "abc"}], "control")

    def test_missing_records_refuse(self):
        with self.assertRaisesRegex(ValueError, "length"):
            runner.check_records([{"kind": "block"}], [], "control")

    def test_missing_field_refuses(self):
        with self.assertRaisesRegex(ValueError, "result_hash"):
            runner.check_records([{"result_hash": "abc"}], [{}], "control")

    def test_changed_prefix_is_reported_before_a_missing_tail(self):
        with self.assertRaisesRegex(ValueError, r"\$\[0\].gas_used"):
            runner.check_records(
                [{"gas_used": "1"}, {"gas_used": "2"}], [{"gas_used": "9"}], "control"
            )

    def test_nonzero_native_exit_cannot_report_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                executable=Path("/unused"),
                timeout=1,
                output=Path(directory) / "out.jsonl",
                metrics=None,
            )
            with mock.patch.object(
                runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "")
            ):
                with self.assertRaisesRegex(ValueError, "native replay exited 1"):
                    runner.run(args, {"blocks": [], "supplements": [], "expected": []}, {})

    def test_does_not_equate_boolean_and_number(self):
        self.assertIsNotNone(runner.difference({"aborted": False}, {"aborted": 0}))


class DiagnosticReplayControls(unittest.TestCase):
    """The capture resolver must not read silence from a failed or partial child as success."""

    def run_child(self, command, timeout=20):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blocks = [
                str(root / name) for name in ("-1-100.boc", "-1-101.boc", "0-7.boc", "0-8.boc")
            ]
            (root / "blocks").write_text("".join(b + "\n" for b in blocks))
            (root / "supplements").write_text("")
            return resolve.run_replay(
                command, root / "blocks", root / "supplements", blocks, timeout
            )

    def run_stub(self, mode, timeout=20):
        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / "stub.py"
            stub.write_text(DIAGNOSTIC_STUB)
            return self.run_child([sys.executable, str(stub), mode], timeout)

    def test_failed_child_refuses(self):
        with self.assertRaisesRegex(SystemExit, "exited 1"):
            self.run_child(["/bin/false"])

    def test_child_that_did_no_work_refuses(self):
        with self.assertRaisesRegex(SystemExit, "announced 0 of 4"):
            self.run_child(["/bin/true"])

    def test_child_that_replayed_part_of_the_selection_refuses(self):
        with self.assertRaisesRegex(SystemExit, "announced 2 of 4"):
            self.run_stub("partial")

    def test_records_without_announced_blocks_refuse(self):
        with self.assertRaisesRegex(SystemExit, "announced 0 of 4"):
            self.run_stub("unannounced")

    def test_block_with_neither_record_nor_failure_refuses(self):
        with self.assertRaisesRegex(SystemExit, "no record and no failure for 1 blocks"):
            self.run_stub("silent-block")

    def test_killed_child_refuses(self):
        with self.assertRaisesRegex(SystemExit, "exited -9"):
            self.run_stub("killed")

    def test_timed_out_child_refuses(self):
        with self.assertRaisesRegex(SystemExit, "timed out after 1s"):
            self.run_stub("hang", timeout=1)

    def test_complete_run_passes(self):
        misses, fails, records = self.run_stub("full")
        self.assertEqual((misses, fails, len(records)), ([], 0, 8))

    def test_complete_run_reports_missing_cells(self):
        misses, fails, records = self.run_stub("missing-cell")
        self.assertEqual((fails, len(records)), (1, 6))
        self.assertEqual(len(misses), 1)
        self.assertTrue(misses[0][2].endswith("-1-100.boc"))


class CorpusControls(unittest.TestCase):
    def assert_missing_provenance_refuses(self, bank):
        original = Path(__file__).with_name("corpus")
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "corpus"
            shutil.copytree(original, copied)
            manifest = copied / "manifest.json"
            data = json.loads(manifest.read_text())
            entry = data["files"][-1] if bank else data["files"][0]
            entry.pop("source_block", None)
            entry.pop("source_blocks", None)
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "missing chain provenance"):
                runner.read_manifest(manifest)

    def test_block_without_chain_provenance_refuses(self):
        self.assert_missing_provenance_refuses(False)

    def test_packed_cells_without_chain_provenance_refuse(self):
        self.assert_missing_provenance_refuses(True)


if __name__ == "__main__":
    unittest.main()
