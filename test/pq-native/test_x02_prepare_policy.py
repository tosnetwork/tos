"""Offline policy-freeze controls; no validator network or tc commands."""

import asyncio
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import x02_fault_evidence as x02  # noqa: E402
import x02_prepare_policy as prepare  # noqa: E402
from test_x02_fault_evidence import policy as legacy_policy  # noqa: E402
sys.path.insert(0, str(REPO / "test/tostester/src"))
from tostester.log_streamer import LogStreamer  # noqa: E402


def native_fixture():
    fixture = legacy_policy()
    manifest = json.loads(base64.b64decode(fixture["readiness_manifest_b64"]))
    for index, (node, item) in enumerate(zip(fixture["nodes"], manifest["validators"]), 1):
        node.update(log_path=f"/tmp/x02-node{index}/log", log_dev=1,
                    log_ino=1000 + index, db_dev=1, db_ino=2000 + index,
                    harness_pid=5000, harness_start_ticks=6000,
                    harness_exe_sha256="b" * 64,
                    input_fd=10 + index, input_link=f"pipe:[{3000 + index}]",
                    output_fd=20 + index)
        item["raw_log_stream"] = {
            "harness_pid": node["harness_pid"],
            "harness_start_ticks": node["harness_start_ticks"],
            "input_fd": node["input_fd"], "input_link": node["input_link"],
            "output_fd": node["output_fd"],
            "output_dev": node["log_dev"], "output_ino": node["log_ino"]}
    return fixture, manifest


class PolicyFreezeTests(unittest.TestCase):
    def test_live_log_streamer_exposes_the_matching_pipe_and_writer_fds(self):
        async def exercise():
            with tempfile.TemporaryDirectory(prefix="x02-fd-binding-") as directory:
                path = Path(directory) / "log"
                output = path.open("wb")
                child = await asyncio.create_subprocess_exec(
                    sys.executable, "-c", "import sys; sys.stderr.write('x02\\n')",
                    stderr=asyncio.subprocess.PIPE)
                try:
                    streamer = LogStreamer(output, "x02-policy-test", child.stderr)
                    binding = streamer.fd_binding()
                    self.assertEqual(os.readlink(f"/proc/{child.pid}/fd/2"),
                                     os.readlink(f"/proc/self/fd/{binding['input_fd']}"))
                    self.assertEqual(os.fstat(binding["output_fd"]).st_ino,
                                     path.stat().st_ino)
                    self.assertEqual(await child.wait(), 0)
                    await streamer.aclose()
                finally:
                    if child.returncode is None:
                        child.kill()
                        await child.wait()
                    output.close()
        asyncio.run(exercise())

    def test_four_node_native_policy_has_ten_exact_bidirectional_edges(self):
        fixture, manifest = native_fixture()
        raw = json.dumps(manifest, sort_keys=True).encode()
        policy = prepare.build_policy(raw, fixture["source_commit"],
                                      fixture["source_files"], fixture["nodes"])
        self.assertEqual(policy["log_source"], "native-file")
        self.assertEqual(len(policy["rules"]), 10)
        self.assertEqual(len([r for r in policy["rules"]
                              if r["phase"] == "three_of_four"]), 6)
        self.assertEqual(len([r for r in policy["rules"]
                              if r["phase"] == "two_of_four"]), 4)

    def test_swapped_stream_mapping_is_rejected_before_policy_freeze(self):
        fixture, manifest = native_fixture()
        swapped = copy.deepcopy(manifest)
        first = swapped["validators"][0]["raw_log_stream"]
        second = swapped["validators"][1]["raw_log_stream"]
        first["input_fd"], second["input_fd"] = second["input_fd"], first["input_fd"]
        raw = json.dumps(swapped, sort_keys=True).encode()
        with self.assertRaisesRegex(ValueError, "stderr pipe.*log writer FD"):
            prepare.build_policy(raw, fixture["source_commit"],
                                 fixture["source_files"], fixture["nodes"])

    def test_duplicate_validator_db_inode_is_rejected(self):
        fixture, manifest = native_fixture()
        fixture["nodes"][1]["db_ino"] = fixture["nodes"][0]["db_ino"]
        raw = json.dumps(manifest, sort_keys=True).encode()
        with self.assertRaisesRegex(ValueError, "share a DB directory"):
            prepare.build_policy(raw, fixture["source_commit"],
                                 fixture["source_files"], fixture["nodes"])

    def test_duplicate_raw_stderr_pipe_is_rejected(self):
        fixture, manifest = native_fixture()
        fixture["nodes"][1]["input_link"] = fixture["nodes"][0]["input_link"]
        manifest["validators"][1]["raw_log_stream"]["input_link"] = (
            manifest["validators"][0]["raw_log_stream"]["input_link"])
        raw = json.dumps(manifest, sort_keys=True).encode()
        with self.assertRaisesRegex(ValueError, "alias the same stderr input pipe"):
            prepare.build_policy(raw, fixture["source_commit"],
                                 fixture["source_files"], fixture["nodes"])

    def test_wrong_stage_a_name_or_index_is_rejected(self):
        fixture, manifest = native_fixture()
        for wrong in ("node1", "node-2", "node-5"):
            mutated = copy.deepcopy(manifest)
            mutated["validators"][0]["node_name"] = wrong
            raw = json.dumps(mutated, sort_keys=True).encode()
            with self.assertRaisesRegex(ValueError, "name/index|duplicate Stage A"):
                prepare.build_policy(raw, fixture["source_commit"],
                                     fixture["source_files"], fixture["nodes"])


if __name__ == "__main__":
    unittest.main()
