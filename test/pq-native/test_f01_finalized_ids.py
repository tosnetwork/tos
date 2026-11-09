"""Synthetic controls for the read-only F01 finalization evidence checker."""

import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pytosiq_core import Builder

SOURCE = Path(
    os.environ.get(
        "F01_CHECKER_SOURCE",
        Path(__file__).resolve().parents[2] / "scripts/f01_finalized_ids.py",
    )
)
SPEC = importlib.util.spec_from_file_location("f01_finalized_ids", SOURCE)
f01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f01)
BEFORE, AFTER = "a" * 64, "b" * 64


def fixture():
    nodes = {}
    for index in range(4):
        nodes[f"node{index}"] = [
            {
                "height": height,
                "id": (-1, "8000000000000000", height, f"{height:064x}", f"{height + 10:064x}"),
                "at": f"2026-09-25 10:00:{height:02d}.{index + 1:09d}",
                "line": height,
            }
            for height in (1, 2, 3)
        ]
    return nodes


def capture_fixture(root, nodes, log_paths, before_cell, after_cell):
    transcript = root / "config34-rpc.jsonl"
    observations = []
    rows = []
    for name, events in nodes.items():
        for event in events:
            height = event["height"]
            _, _, _, root_hash, file_hash = event["id"]
            block_id = {
                "workchain": -1,
                "shard": -(1 << 63),
                "seqno": height,
                "root_hash": base64.b64encode(bytes.fromhex(root_hash)).decode(),
                "file_hash": base64.b64encode(bytes.fromhex(file_hash)).decode(),
            }
            cell = before_cell if height < 2 else after_cell
            observations.append(
                {
                    "node_name": name,
                    "height": height,
                    "block_id": block_id,
                    "config34_cell_hash": cell.hash.hex(),
                }
            )
            for method, result in (
                ("getBlockHeader", {"id": block_id}),
                ("getConfigParam", {"config": {"bytes": base64.b64encode(cell.to_boc()).decode()}}),
            ):
                rows.append(
                    {
                        "node_name": name,
                        "address": f"127.0.0.1:{25000 + int(name[4:])}",
                        "http_status": 200,
                        "request": {
                            "method": method,
                            "params": {
                                "seqno": height,
                                **(
                                    {"param": 34}
                                    if method == "getConfigParam"
                                    else {"workchain": -1, "shard": "-9223372036854775808"}
                                ),
                            },
                        },
                        "response_base64": base64.b64encode(
                            json.dumps(
                                {
                                    "ok": True,
                                    "result": result,
                                }
                            ).encode()
                        ).decode(),
                    }
                )
    transcript.write_text("".join(json.dumps(row) + "\n" for row in rows))
    manifest = root / "capture-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "tos.f01.stage-a-capture.v1",
                "source": {
                    "config34_raw_rpc_transcript": {
                        "path": str(transcript),
                        "sha256": hashlib.sha256(transcript.read_bytes()).hexdigest(),
                    }
                },
                "validators": [
                    {
                        "node_name": name,
                        "rpc_address": f"127.0.0.1:{25000 + int(name[4:])}",
                        "combined_log": {
                            "path": str(log_paths[name]),
                            "sha256": hashlib.sha256(log_paths[name].read_bytes()).hexdigest(),
                        },
                    }
                    for name in nodes
                ],
                "transitions": [
                    {
                        "height": 2,
                        "before_config34_cell_hash": before_cell.hash.hex(),
                        "after_config34_cell_hash": after_cell.hash.hex(),
                        "observations": observations,
                    }
                ],
            }
        )
    )
    return manifest, transcript


class FinalizedIdTests(unittest.TestCase):
    def test_raw_headers_and_config34_bind_each_node_at_h_minus_one_h_h_plus_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nodes = fixture()
            paths = {}
            for name in nodes:
                paths[name] = root / f"{name}.log"
                paths[name].write_text(f"independent {name} native log\n")
            before = Builder().store_uint(1, 8).end_cell()
            after = Builder().store_uint(2, 8).end_cell()
            manifest, transcript = capture_fixture(root, nodes, paths, before, after)
            sources = {
                name: (path, hashlib.sha256(path.read_bytes()).hexdigest())
                for name, path in paths.items()
            }
            verdict = f01.verify_capture(
                manifest, nodes, sources, 2, before.hash.hex(), after.hash.hex()
            )
            self.assertEqual(verdict["raw_header_heights"], [1, 2, 3])

            original_rows = [json.loads(line) for line in transcript.read_text().splitlines()]

            def seal(rows):
                transcript.write_text("".join(json.dumps(row) + "\n" for row in rows))
                document = json.loads(manifest.read_text())
                document["source"]["config34_raw_rpc_transcript"]["sha256"] = hashlib.sha256(
                    transcript.read_bytes()
                ).hexdigest()
                manifest.write_text(json.dumps(document))

            for method, changed, expected_error in (
                ("getBlockHeader", ("address", "127.0.0.1:9999"), "endpoint differs"),
                ("getBlockHeader", ("shard", "7000000000000000"), "masterchain header"),
                ("getConfigParam", ("param", 47), "Config34/masterchain"),
            ):
                rows = json.loads(json.dumps(original_rows))
                target = next(
                    row
                    for row in rows
                    if row["node_name"] == "node3"
                    and row["request"]["method"] == method
                    and row["request"]["params"]["seqno"] == 3
                )
                field, value = changed
                if field == "address":
                    target[field] = value
                else:
                    target["request"]["params"][field] = value
                seal(rows)
                with self.assertRaisesRegex(ValueError, expected_error):
                    f01.verify_capture(
                        manifest, nodes, sources, 2, before.hash.hex(), after.hash.hex()
                    )

            rows = json.loads(json.dumps(original_rows))
            target = next(
                row
                for row in rows
                if row["node_name"] == "node3"
                and row["request"]["method"] == "getBlockHeader"
                and row["request"]["params"]["seqno"] == 3
            )
            response = json.loads(base64.b64decode(target["response_base64"]))
            response["result"]["id"]["root_hash"] = base64.b64encode(b"z" * 32).decode()
            target["response_base64"] = base64.b64encode(json.dumps(response).encode()).decode()
            seal(rows)
            with self.assertRaisesRegex(ValueError, "raw header differs"):
                f01.verify_capture(manifest, nodes, sources, 2, before.hash.hex(), after.hash.hex())

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
            nodes[f"node{index}"].append(
                {
                    "height": 4,
                    "id": (-1, "8000000000000000", 4, f"{4:064x}", f"{14:064x}"),
                    "at": f"2026-09-25 10:00:04.{index + 1:09d}",
                    "line": 4,
                }
            )
        with self.assertRaisesRegex(ValueError, "never caught up"):
            f01.evaluate(nodes, 2, BEFORE, AFTER)

    def test_extractor_requires_raw_full_id_and_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.log"
            path.write_text(
                "[2026-09-25 10:00:01.000000001] BlockFinalizedInMasterchain {block=(-1,8000000000000000,2):"
                + "a" * 64
                + ":"
                + "b" * 64
                + "}\n"
            )
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
                path.write_text(
                    "".join(
                        f"[2026-09-25 10:00:{height:02d}.{node_index:09d}] "
                        "BlockFinalizedInMasterchain "
                        f"{{block=(-1,8000000000000000,{height}):"
                        f"{height:064x}:{height + 10:064x}}}\n"
                        for height in (1, 2, 3)
                    )
                )

            write_log(original, 1)
            distinct = [original]
            for index in range(2, 5):
                path = root / f"node{index}.log"
                write_log(path, index)
                distinct.append(path)
            output = root / "report.json"
            native_nodes = {
                f"node{index}": f01.extract(path)[0] for index, path in enumerate(distinct, 1)
            }
            before = Builder().store_uint(1, 8).end_cell()
            after = Builder().store_uint(2, 8).end_cell()
            manifest, _ = capture_fixture(
                root,
                native_nodes,
                {name: path for name, path in zip(native_nodes, distinct)},
                before,
                after,
            )

            def run(paths):
                argv = [
                    "f01_finalized_ids.py",
                    "--transition-height",
                    "2",
                    "--before-set",
                    before.hash.hex(),
                    "--after-set",
                    after.hash.hex(),
                    "--capture-manifest",
                    str(manifest),
                    "--out",
                    str(output),
                ]
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


class KeyBlockTransitionTests(unittest.TestCase):
    """H is a key block whose own finalization marker no node logs.

    Real rehearsals show it: every node lacks BlockFinalizedInMasterchain at
    exactly the key blocks, because the key block's notice reaches no consensus
    bus. H must then be proven by its successor's predecessor link.
    """

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.nodes = fixture()
        self.paths = {}
        for name in self.nodes:
            self.paths[name] = self.root / f"{name}.log"
            self.paths[name].write_text(f"independent {name} native log\n")
        self.before = Builder().store_uint(1, 8).end_cell()
        self.after = Builder().store_uint(2, 8).end_cell()
        self.manifest, self.transcript = capture_fixture(
            self.root, self.nodes, self.paths, self.before, self.after
        )
        self.sources = {
            name: (path, hashlib.sha256(path.read_bytes()).hexdigest())
            for name, path in self.paths.items()
        }
        self.rows = [json.loads(line) for line in self.transcript.read_text().splitlines()]
        # Mark H (2) a key block, give every header its preceding key block (0),
        # and link each H+1 (3) header to H's exact ID.
        for row in self.rows:
            if row["request"]["method"] != "getBlockHeader":
                continue
            height = row["request"]["params"]["seqno"]
            self.edit(
                row,
                lambda result, h=height: result.update(
                    is_key_block=h == 2, prev_key_block_seqno=2 if h == 3 else 0
                ),
            )
            if height == 3:
                self.edit(
                    row,
                    lambda result, name=row["node_name"]: result.update(
                        prev_blocks=[self.header(name, 2)["id"]]
                    ),
                )
        self.seal()
        for name in self.nodes:  # no node logs H itself
            self.nodes[name] = [event for event in self.nodes[name] if event["height"] != 2]

    @staticmethod
    def edit(row, change):
        response = json.loads(base64.b64decode(row["response_base64"]))
        change(response["result"])
        row["response_base64"] = base64.b64encode(json.dumps(response).encode()).decode()

    def header(self, name, height):
        row = next(
            row
            for row in self.rows
            if row["node_name"] == name
            and row["request"]["method"] == "getBlockHeader"
            and row["request"]["params"]["seqno"] == height
        )
        return json.loads(base64.b64decode(row["response_base64"]))["result"]

    def header_row(self, name, height):
        return next(
            row
            for row in self.rows
            if row["node_name"] == name
            and row["request"]["method"] == "getBlockHeader"
            and row["request"]["params"]["seqno"] == height
        )

    def seal(self):
        self.transcript.write_text("".join(json.dumps(row) + "\n" for row in self.rows))
        document = json.loads(self.manifest.read_text())
        document["source"]["config34_raw_rpc_transcript"]["sha256"] = hashlib.sha256(
            self.transcript.read_bytes()
        ).hexdigest()
        self.manifest.write_text(json.dumps(document))

    def verify(self):
        return f01.verify_capture(
            self.manifest,
            self.nodes,
            self.sources,
            2,
            self.before.hash.hex(),
            self.after.hash.hex(),
        )

    def test_key_block_h_without_markers_is_proven_by_its_successor(self):
        verdict = self.verify()
        self.assertEqual(set(verdict["h_proven_by"].values()), {"successor_prev"})
        self.assertEqual(verdict["raw_key_block_heights"], [2])
        self.assertEqual(verdict["raw_named_key_heights"], [0])
        exempt = frozenset(verdict["raw_key_block_heights"]) | frozenset(
            verdict["raw_named_key_heights"]
        )
        report = f01.evaluate(self.nodes, 2, BEFORE, AFTER, exempt_heights=exempt)
        self.assertEqual(report["checked_heights"], [1, 3])
        self.assertEqual(report["coverage_exempt_key_heights"], [2])

    def test_a_present_h_marker_must_still_match(self):
        self.nodes["node1"].append(
            {
                "height": 2,
                "id": (-1, "8000000000000000", 2, "f" * 64, "c" * 64),
                "at": "2026-09-25 10:00:02.000000009",
                "line": 2,
            }
        )
        with self.assertRaisesRegex(ValueError, "native marker differs"):
            self.verify()

    def test_successor_must_name_h_exactly(self):
        for field in ("root_hash", "file_hash"):
            row = self.header_row("node2", 3)
            saved = row["response_base64"]

            def flip(result, field=field):
                raw = bytearray(base64.b64decode(result["prev_blocks"][0][field]))
                raw[0] ^= 1
                result["prev_blocks"][0][field] = base64.b64encode(bytes(raw)).decode()

            self.edit(row, flip)
            self.seal()
            with self.assertRaisesRegex(ValueError, "does not name H's exact ID"):
                self.verify()
            row["response_base64"] = saved
        row = self.header_row("node2", 3)
        self.edit(row, lambda result: result.update(prev_blocks=result["prev_blocks"] * 2))
        self.seal()
        with self.assertRaisesRegex(ValueError, "does not name H's exact ID"):
            self.verify()

    def test_h_must_be_a_raw_key_block(self):
        for name in self.nodes:
            self.edit(self.header_row(name, 2), lambda result: result.update(is_key_block=False))
            # H+1 no longer names H as its key block either, so only H's own flag decides.
            self.edit(
                self.header_row(name, 3), lambda result: result.update(prev_key_block_seqno=0)
            )
        self.seal()
        with self.assertRaisesRegex(ValueError, "not a raw key block"):
            self.verify()
        for name in self.nodes:
            self.edit(self.header_row(name, 2), lambda result: result.pop("is_key_block"))
        self.seal()
        with self.assertRaisesRegex(ValueError, "not a raw key block"):
            self.verify()

    def test_h_plus_one_marker_is_still_required(self):
        self.nodes["node3"] = [event for event in self.nodes["node3"] if event["height"] != 3]
        with self.assertRaisesRegex(ValueError, "native marker differs"):
            self.verify()

    def test_raw_header_facts_are_validated(self):
        cases = (
            (lambda result: result.update(is_key_block=1), "not a boolean"),
            (
                lambda result: result.update(prev_key_block_seqno=3),
                "prev_key_block_seqno is invalid",
            ),
            (
                lambda result: result.update(prev_key_block_seqno="0"),
                "prev_key_block_seqno is invalid",
            ),
            (lambda result: result["id"].update(seqno=9), "not the requested height"),
        )
        for change, message in cases:
            row = self.header_row("node1", 3)
            saved = row["response_base64"]
            self.edit(row, change)
            self.seal()
            with self.assertRaisesRegex(ValueError, message):
                self.verify()
            row["response_base64"] = saved
        self.edit(self.header_row("node2", 2), lambda result: result.update(is_key_block=False))
        self.seal()
        with self.assertRaisesRegex(ValueError, "disagree on is_key_block"):
            self.verify()

    def test_a_named_key_height_cannot_be_a_raw_non_key_block(self):
        for name in self.nodes:
            self.edit(
                self.header_row(name, 1), lambda result: result.update(prev_key_block_seqno=0)
            )
            self.edit(
                self.header_row(name, 3), lambda result: result.update(prev_key_block_seqno=1)
            )
        self.seal()
        with self.assertRaisesRegex(ValueError, "names a non-key block"):
            self.verify()


class KeyBlockCoverageTests(unittest.TestCase):
    def test_gap_outside_key_heights_still_fails(self):
        nodes = fixture()
        for name in nodes:
            nodes[name] = [event for event in nodes[name] if event["height"] != 2]
        with self.assertRaisesRegex(ValueError, "absent all-node common-height"):
            f01.evaluate(nodes, 2, BEFORE, AFTER)
        with self.assertRaisesRegex(ValueError, "absent all-node common-height"):
            f01.evaluate(nodes, 2, BEFORE, AFTER, exempt_heights=frozenset({7}))
        report = f01.evaluate(nodes, 2, BEFORE, AFTER, exempt_heights=frozenset({2}))
        self.assertEqual(report["coverage_exempt_key_heights"], [2])

    def test_gap_at_a_non_key_height_inside_the_range_fails(self):
        nodes = fixture()
        for name in nodes:
            nodes[name] = nodes[name] + [
                {
                    "height": h,
                    "id": (-1, "8000000000000000", h, f"{h:064x}", f"{h + 10:064x}"),
                    "at": f"2026-09-25 10:00:{h:02d}.{int(name[4:]) + 1:09d}",
                    "line": h,
                }
                for h in (4, 5, 6)
            ]
        for name in nodes:
            nodes[name] = [event for event in nodes[name] if event["height"] != 5]
        with self.assertRaisesRegex(ValueError, "has a gap"):
            f01.evaluate(nodes, 2, BEFORE, AFTER, exempt_heights=frozenset({4}))
        self.assertEqual(
            f01.evaluate(nodes, 2, BEFORE, AFTER, exempt_heights=frozenset({5}))[
                "coverage_exempt_key_heights"
            ],
            [5],
        )

    def test_conflict_at_an_exempt_height_is_still_caught(self):
        nodes = fixture()
        for name in ("node0", "node1"):
            nodes[name] = [event for event in nodes[name] if event["height"] != 2]
        nodes["node3"] = [
            {**event, "id": (-1, "8000000000000000", 2, "e" * 64, "d" * 64)}
            if event["height"] == 2
            else event
            for event in nodes["node3"]
        ]
        with self.assertRaisesRegex(
            ValueError, "conflicting finalized full BlockIdExt at height 2"
        ):
            f01.evaluate(nodes, 2, BEFORE, AFTER, exempt_heights=frozenset({2}))


if __name__ == "__main__":
    unittest.main()
