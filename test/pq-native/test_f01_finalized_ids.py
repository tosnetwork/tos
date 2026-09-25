"""Synthetic controls for the read-only F01 finalization evidence checker."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(os.environ.get(
    "F01_CHECKER_SOURCE",
    Path(__file__).resolve().parents[2] / "scripts/f01_finalized_ids.py",
))
SPEC = importlib.util.spec_from_file_location("f01_finalized_ids", SOURCE)
f01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f01)
BEFORE, AFTER = "a" * 64, "b" * 64


def fixture():
    nodes = {}
    for index in range(4):
        nodes[f"node{index}"] = [
            {"height": height,
             "id": (-1, "8000000000000000", height, f"{height:064x}", f"{height + 10:064x}"),
             "at": f"2026-09-25 10:00:{height:02d}.{index + 1:09d}", "line": height}
            for height in (1, 2, 3)
        ]
    return nodes


class FinalizedIdTests(unittest.TestCase):
    def test_full_ids_agree_across_transition_and_lag_catches_up(self):
        report = f01.evaluate(fixture(), 2, BEFORE, AFTER)
        self.assertEqual(report["checked_heights"], [1, 2, 3])
        self.assertTrue(report["lag_events"])
        self.assertTrue(all(row["caught_up"] for row in report["lag_events"]))

    def test_conflicting_full_id_fails_even_when_heights_match(self):
        nodes = fixture()
        nodes["node3"][1]["id"] = (-1, "8000000000000000", 2, "f" * 64, "c" * 64)
        with self.assertRaisesRegex(ValueError, "conflicting finalized full BlockIdExt"):
            f01.evaluate(nodes, 2, BEFORE, AFTER)

    def test_missing_common_pretransition_height_and_uncaught_lag_fail(self):
        nodes = fixture()
        nodes["node3"] = nodes["node3"][1:]
        with self.assertRaisesRegex(ValueError, "absent all-node common-height"):
            f01.evaluate(nodes, 2, BEFORE, AFTER)
        nodes = fixture()
        for index in range(3):
            nodes[f"node{index}"].append({
                "height": 4,
                "id": (-1, "8000000000000000", 4, f"{4:064x}", f"{14:064x}"),
                "at": f"2026-09-25 10:00:04.{index + 1:09d}", "line": 4,
            })
        with self.assertRaisesRegex(ValueError, "never caught up"):
            f01.evaluate(nodes, 2, BEFORE, AFTER)

    def test_extractor_requires_raw_full_id_and_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.log"
            path.write_text("[2026-09-25 10:00:01.000000001] BlockFinalizedInMasterchain {block=(-1,8000000000000000,2):" + "a" * 64 + ":" + "b" * 64 + "}\n")
            events, digest = f01.extract(path)
            self.assertEqual(events[0]["id"], (-1, "8000000000000000", 2, "a" * 64, "b" * 64))
            self.assertEqual(len(digest), 64)
            path.write_text("[2026-09-25 10:00:01.000000001] finalized height 2 only\n")
            with self.assertRaisesRegex(ValueError, "no BlockFinalizedInMasterchain"):
                f01.extract(path)

    def test_zero_root_or_file_hash_is_rejected_from_raw_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.log"
            for root, file_hash in (("0" * 64, "b" * 64), ("a" * 64, "0" * 64)):
                with self.subTest(root=root, file_hash=file_hash):
                    path.write_text(
                        "[2026-09-25 10:00:01.000000001] "
                        "BlockFinalizedInMasterchain {block=(-1,8000000000000000,2):"
                        f"{root}:{file_hash}}}\n"
                    )
                    with self.assertRaisesRegex(ValueError, "zero root/file hash"):
                        f01.extract(path)

    def test_zero_root_or_file_hash_is_rejected_from_synthetic_events(self):
        for position in (3, 4):
            with self.subTest(position=position):
                nodes = fixture()
                for events in nodes.values():
                    block_id = list(events[1]["id"])
                    block_id[position] = "0" * 64
                    events[1]["id"] = tuple(block_id)
                with self.assertRaisesRegex(ValueError, "zero root/file hash"):
                    f01.evaluate(nodes, 2, BEFORE, AFTER)

    def test_consistent_but_wrong_block_identity_is_rejected(self):
        for position, value in ((0, 0), (1, "7000000000000000"), (2, 3)):
            with self.subTest(position=position):
                nodes = fixture()
                for events in nodes.values():
                    block_id = list(events[1]["id"])
                    block_id[position] = value
                    events[1]["id"] = tuple(block_id)
                with self.assertRaisesRegex(ValueError, "BlockIdExt is malformed"):
                    f01.evaluate(nodes, 2, BEFORE, AFTER)

    def test_zero_config34_cell_digest_is_rejected(self):
        for before, after in (("0" * 64, AFTER), (BEFORE, "0" * 64)):
            with self.subTest(before=before, after=after):
                with self.assertRaisesRegex(ValueError, "ConfigParam 34 set digests"):
                    f01.evaluate(fixture(), 2, before, after)

    def test_cli_rejects_same_file_alias_and_byte_copy_as_four_nodes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "node1.log"

            def write_log(path, node_index):
                path.write_text("".join(
                    f"[2026-09-25 10:00:{height:02d}.{node_index:09d}] "
                    "BlockFinalizedInMasterchain "
                    f"{{block=(-1,8000000000000000,{height}):"
                    f"{height:064x}:{height + 10:064x}}}\n"
                    for height in (1, 2, 3)
                ))

            write_log(original, 1)
            distinct = [original]
            for index in range(2, 5):
                path = root / f"node{index}.log"
                write_log(path, index)
                distinct.append(path)
            output = root / "report.json"

            def run(paths):
                argv = ["f01_finalized_ids.py", "--transition-height", "2",
                        "--before-set", BEFORE, "--after-set", AFTER,
                        "--out", str(output)]
                for index, path in enumerate(paths, 1):
                    argv += ["--node-log", f"node{index}={path}"]
                with patch.object(sys, "argv", argv):
                    return f01.main()

            with self.assertRaisesRegex(ValueError, "alias one raw file"):
                run([original] * 4)
            copied = root / "copy.log"
            copied.write_bytes(original.read_bytes())
            with self.assertRaisesRegex(ValueError, "duplicate raw SHA-256"):
                run([original, copied, distinct[2], distinct[3]])
            symlink = root / "symlink.log"
            symlink.symlink_to(original)
            with self.assertRaisesRegex(ValueError, "alias one raw file"):
                run([original, symlink, original, original])
            self.assertEqual(run(distinct), 0)
            self.assertTrue(json.loads(output.read_text())["passed"])


if __name__ == "__main__":
    unittest.main()
