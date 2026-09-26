"""Offline controls for the Z01 live runner. No test starts a validator or DHT.

Set Z01_BUILD_DIR to a build with create-state, tos-pq-consensus-key and
libtoslibjson to also exercise genesis generation and the exact validator argv
through a recording process backend that spawns only ``sleep``.
"""

import asyncio
import hashlib
import importlib.util
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test/tostester/src"))
SPEC = importlib.util.spec_from_file_location("z01_live_run", ROOT / "scripts/z01_live_run.py")
assert SPEC and SPEC.loader
live = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live)


class RunnerGuards(unittest.TestCase):
    def test_harness_environment_knobs_refused(self):
        live.refuse_local_knobs({"PATH": "/bin", "HOME": "/tmp"})
        with self.assertRaisesRegex(live.RunError, "TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS"):
            live.refuse_local_knobs({"TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS": "2"})

    def test_harness_refuses_22_before_fift(self):
        refusals = live.harness_refusals()
        self.assertEqual(set(refusals), {"22_total_validators", "22_minimum"})
        self.assertTrue(all("launch" in message for message in refusals.values()))

    def test_occupied_port_refused(self):
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        try:
            with self.assertRaisesRegex(live.RunError, f"port {port} is not free"):
                live.ports_free(port - 1, 1)
        finally:
            holder.close()

    def test_overlapping_port_ranges_refused(self):
        with self.assertRaisesRegex(live.RunError, "overlap"):
            live.ports_free(30600, 30601)

    def test_precommit_digest_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "precommit.json"
            path.write_text(json.dumps({"schema": live.SCHEMA}))
            with self.assertRaisesRegex(live.RunError, "differs from its recorded SHA-256"):
                live.load_precommit(path, "00" * 32, Path(temp), True)

    def test_native_tail_reads_only_appended_complete_lines(self):
        marker = ("[2026-09-26 00:00:00.000000] BlockFinalizedInMasterchain "
                  "{block=(-1,8000000000000000,%d):" + "11" * 32 + ":" + "22" * 32 + "}\n")
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "log"
            log.write_bytes((marker % 4).encode())
            tail = live.NativeTail(log)
            self.assertEqual(tail.tip(), 4)
            line = (marker % 5).encode()
            with log.open("ab") as handle:
                handle.write(line[:30])
            self.assertEqual(tail.tip(), 4)
            with log.open("ab") as handle:
                handle.write(line[30:])
            self.assertEqual(tail.tip(), 5)

    def test_expected_param_cells_are_the_reviewed_launch_cells(self):
        self.assertEqual(live.EXPECTED_PARAM_CELLS["28"],
                         "f0a98e1c3fa538583cc06d470a29dfb1a6d9407323fe8d64a8f870c838a19fea")
        self.assertEqual(set(live.BINARIES), {"validator_engine", "dht_server", "lite_client",
                                              "create_state", "pq_consensus_key", "toslibjson",
                                              "proof_checker", "chain_checker", "launch_cap_test"})
        self.assertEqual(live.BINARIES["chain_checker"], "z01-chain-proof-check")


class RecordingBackend:
    """Record the exact argv a node would receive; run only sleep."""

    def __init__(self):
        self.spawned: list[tuple[str, list[str], str]] = []

    def manifest(self):
        return {"kind": "recording"}

    async def spawn(self, name, executable, args, cwd, env, capture_stdout=False):
        self.spawned.append((str(executable), [str(arg) for arg in args], str(cwd)))
        return await asyncio.create_subprocess_exec(
            "sleep", "30", cwd=cwd, stdout=None, stderr=asyncio.subprocess.PIPE)


@unittest.skipUnless(os.environ.get("Z01_BUILD_DIR"), "needs Z01_BUILD_DIR with genesis tools")
class GenesisAndArgv(unittest.TestCase):
    def test_genesis_cells_and_exact_validator_argv(self):
        from tostester.install import Install
        from tostester.network import StartOptions

        build = Path(os.environ["Z01_BUILD_DIR"])
        install = Install(build, ROOT)

        async def run(directory: Path):
            network, dht, nodes = live.build_network(install, directory / "network", 30600)
            backend = RecordingBackend()
            network._process_backend = backend
            genesis = live.check_genesis(network, directory, live.EXPECTED_PARAM_CELLS)
            node = nodes[0]
            await node.run(StartOptions(threads=2, verbosity=3,
                                        args=("--json-rpc-address", "127.0.0.1:31600")))
            try:
                executable, args, cwd = backend.spawned[0]
                self.assertEqual([executable, *args],
                                 live.expected_cmdline(install, node, "127.0.0.1:31600"))
                self.assertEqual(cwd, str(node.directory))
            finally:
                await node.stop()
            return genesis

        with tempfile.TemporaryDirectory() as temp:
            genesis = asyncio.run(run(Path(temp)))
        self.assertEqual(genesis["param_cells"], live.EXPECTED_PARAM_CELLS)


if __name__ == "__main__":
    unittest.main()
