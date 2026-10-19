#!/usr/bin/env python3
"""X02 live PID-to-identity binding against real /proc, with the refusals that matter.

Four stand-in processes each run in their own data directory holding a public
config.json and listen on their console port; capture uses the real /proc and kernel
socket tables. Public keys and key_ids come from a real retained Config34 cell. No seed,
keyring or environment file exists here or is read.
"""

import base64
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import x02_config34_proof as proof
import x02_live_identity as live
from pytosiq_core.boc.cell import Cell

FIXTURES = Path(__file__).resolve().parent / "x02-config34-fixtures"
# The stand-ins run this interpreter; it plays the frozen validator executable.
EXE_BYTES = Path(os.path.realpath(sys.executable)).stat().st_size
EXE_SHA256 = (
    __import__("hashlib").sha256(Path(os.path.realpath(sys.executable)).read_bytes()).hexdigest()
)
LISTENER = (
    "import os, socket, sys, time\n"
    "ports = []\n"
    "for _ in range(2):  # console, then RPC\n"
    "    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "    s.bind(('127.0.0.1', 0)); s.listen(1); ports.append(s)\n"
    "sys.stdout.write(' '.join(str(s.getsockname()[1]) for s in ports) + '\\n'); sys.stdout.flush()\n"
    "time.sleep(120)\n"
)


def real_validators():
    cell = Cell.one_from_boc(sorted(FIXTURES.glob("config34-since-*.boc"))[0].read_bytes())
    decoded = proof.decode_validator_set(cell)
    public_keys = []
    entries = cell.begin_parse()
    entries.load_uint(8 + 32 + 32 + 16 + 16 + 64)
    for _, entry in sorted(entries.load_dict(16).items()):
        entry.load_uint(8 + 256 + 16 + 256 + 64 + 256)
        public_keys.append(proof.unpack_pq_bytes(entry.load_ref()))
    return decoded["validators"], public_keys


class Nodes:
    """Four stand-in node processes, each in its own data directory."""

    def __init__(self, base: Path, rows, shared_dir_for=None):
        self.base, self.rows, self.processes, self.dirs, self.ports = base, rows, [], [], []
        self.rpc_ports = []
        for index, row in enumerate(rows):
            directory = base / f"node{index + 1}"
            if shared_dir_for is not None and index == shared_dir_for:
                directory = self.dirs[0]
            directory.mkdir(exist_ok=True)
            child = subprocess.Popen(
                [sys.executable, "-c", LISTENER], cwd=directory, stdout=subprocess.PIPE, text=True
            )
            port, rpc = map(int, child.stdout.readline().split())
            self.write_config(directory, row, port)
            self.processes.append(child)
            self.dirs.append(directory)
            self.ports.append(port)
            self.rpc_ports.append(rpc)

    @staticmethod
    def write_config(directory, row, port, extra_adnl=None):
        adnl = [row["adnl_id_hex"]] + ([extra_adnl] if extra_adnl else [])
        (directory / "config.json").write_text(
            __import__("json").dumps(
                {
                    "extraconfig": {
                        "pq_consensus": {
                            "validator_id": base64.b64encode(
                                bytes.fromhex(row["controller_id_hex"])
                            ).decode(),
                            "consensus_key_file": "/nonexistent",
                        }
                    },
                    "adnl": [
                        {"id": base64.b64encode(bytes.fromhex(a)).decode(), "category": 0}
                        for a in adnl
                    ],
                    "control": [{"id": "", "port": port, "allowed": []}],
                }
            )
        )

    def capture(self, **overrides):
        return [
            live.capture_node(
                child.pid,
                directory,
                overrides.get("exe_sha256", EXE_SHA256),
                overrides.get("exe_bytes", EXE_BYTES),
                rpc,
            )
            for child, directory, rpc in zip(self.processes, self.dirs, self.rpc_ports)
        ]

    def close(self):
        for child in self.processes:
            child.kill()
            child.wait()


class LiveIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validators, cls.public_keys = real_validators()

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.nodes = Nodes(self.base, self.validators)

    def tearDown(self):
        self.nodes.close()
        shutil.rmtree(self.base)

    def authorizations(self, captures):
        return [
            {
                "validator_id_hex": row["controller_id_hex"],
                "key_id_hex": row["consensus_key_id_hex"],
                "algorithm_id": 1,
                "public_key_hex": key.hex(),
                "control_port": cap["control_port"],
                "node_pid": cap["pid"],
                "node_start_ticks": cap["start_ticks"],
            }
            for row, key, cap in zip(self.validators, self.public_keys, captures)
        ]

    def frozen(self):
        return [
            {
                "validator_index": i + 1,
                **{f: row[f] for f in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")},
            }
            for i, row in enumerate(self.validators)
        ]

    def test_real_proc_capture_binds_four_pids_to_their_public_identity(self):
        before = self.nodes.capture()
        self.assertTrue(all(c["owns_control_listener"] for c in before))
        after = self.nodes.capture()
        bound = live.verify_live_identity(before, after, self.authorizations(before), self.frozen())
        self.assertEqual([b["pid"] for b in bound], [p.pid for p in self.nodes.processes])

    def test_four_row_swap_is_refused(self):
        before = self.nodes.capture()
        frozen = self.frozen()
        frozen[0], frozen[1] = frozen[1], frozen[0]
        with self.assertRaisesRegex(live.IdentityRefused, "differs from frozen row"):
            live.verify_live_identity(before, before, self.authorizations(before), frozen)

    def test_a_frozen_controller_that_differs_alone_is_refused(self):
        before = self.nodes.capture()
        frozen = self.frozen()
        frozen[1] = dict(frozen[1], controller_id_hex="ab" * 32)
        with self.assertRaisesRegex(live.IdentityRefused, "differs from frozen row"):
            live.verify_live_identity(before, before, self.authorizations(before), frozen)

    def test_same_key_under_two_pids_is_refused(self):
        before = self.nodes.capture()
        auth = self.authorizations(before)
        # node3 keeps its own validator_id but answers with node2's consensus key.
        auth[2] = dict(
            auth[2], key_id_hex=auth[1]["key_id_hex"], public_key_hex=auth[1]["public_key_hex"]
        )
        with self.assertRaisesRegex(
            live.IdentityRefused, "two PIDs report the same consensus_key_id_hex"
        ):
            live.verify_live_identity(before, before, auth, self.frozen())

    def test_pid_generation_change_is_refused(self):
        before = self.nodes.capture()
        old = self.nodes.processes[3]
        old.kill()
        old.wait()
        child = subprocess.Popen(
            [sys.executable, "-c", LISTENER],
            cwd=self.nodes.dirs[3],
            stdout=subprocess.PIPE,
            text=True,
        )
        port, rpc = map(int, child.stdout.readline().split())
        self.nodes.processes[3] = child
        self.nodes.rpc_ports[3] = rpc
        Nodes.write_config(self.nodes.dirs[3], self.validators[3], port)
        after = self.nodes.capture()
        with self.assertRaisesRegex(live.IdentityRefused, "replaced|changed"):
            live.verify_live_identity(before, after, self.authorizations(before), self.frozen())

    def test_db_alias_is_refused(self):
        self.nodes.close()
        shutil.rmtree(self.base)
        self.base = Path(tempfile.mkdtemp())
        self.nodes = Nodes(self.base, self.validators, shared_dir_for=3)
        # node4 runs in node1's directory; its config overwrote node1's, so rebuild both views
        before = self.nodes.capture()
        # A real shared directory also shares one config.json, so whichever check sees it
        # first refuses (in practice the console-port owner); the DB check alone is below.
        with self.assertRaises(live.IdentityRefused):
            live.verify_live_identity(before, before, self.authorizations(before), self.frozen())

    def test_pid_reuse_with_a_new_start_tick_is_refused(self):
        before = self.nodes.capture()
        after = [dict(c) for c in before]
        after[2]["start_ticks"] += 1  # same PID number, another process generation
        with self.assertRaisesRegex(live.IdentityRefused, "was replaced"):
            live.verify_live_identity(before, after, self.authorizations(before), self.frozen())

    def test_db_alias_alone_is_refused(self):
        before = self.nodes.capture()
        before[3] = dict(before[3], db_dev=before[0]["db_dev"], db_ino=before[0]["db_ino"])
        with self.assertRaisesRegex(live.IdentityRefused, "two validators share one DB directory"):
            live.verify_live_identity(before, before, self.authorizations(before), self.frozen())

    def test_missing_config_source_is_refused(self):
        (self.nodes.dirs[2] / "config.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.nodes.capture()

    def test_console_port_owned_by_another_process_is_refused(self):
        Nodes.write_config(self.nodes.dirs[0], self.validators[0], self.nodes.ports[1])
        before = self.nodes.capture()
        self.assertFalse(before[0]["owns_control_listener"])
        with self.assertRaisesRegex(live.IdentityRefused, "does not own the console port"):
            live.verify_live_identity(before, before, self.authorizations(before), self.frozen())

    def test_authorization_public_key_tamper_is_refused(self):
        before = self.nodes.capture()
        auth = self.authorizations(before)
        key = bytearray(bytes.fromhex(auth[1]["public_key_hex"]))
        key[5] ^= 1
        auth[1]["public_key_hex"] = bytes(key).hex()
        with self.assertRaisesRegex(live.IdentityRefused, "does not derive"):
            live.verify_live_identity(before, before, auth, self.frozen())

    def test_an_executable_other_than_the_frozen_validator_is_refused(self):
        with self.assertRaisesRegex(live.IdentityRefused, "not the frozen validator size"):
            self.nodes.capture(exe_bytes=EXE_BYTES + 1)
        with self.assertRaisesRegex(live.IdentityRefused, "not the frozen validator"):
            self.nodes.capture(exe_sha256="0" * 64)

    def test_descriptor_scan_is_bounded_in_count_and_time(self):
        pid = self.nodes.processes[0].pid
        self.assertTrue(live.socket_inodes(pid))
        with self.assertRaisesRegex(live.IdentityRefused, "more than 1 descriptors"):
            live.socket_inodes(pid, limit=1)
        with self.assertRaisesRegex(live.IdentityRefused, "scan exceeded"):
            live.socket_inodes(pid, seconds=0)

    def test_rpc_endpoint_owned_by_another_process_is_refused(self):
        self.nodes.rpc_ports[0], self.nodes.rpc_ports[1] = (
            self.nodes.rpc_ports[1],
            self.nodes.rpc_ports[0],
        )
        before = self.nodes.capture()
        self.assertFalse(before[0]["owns_rpc_listener"])
        with self.assertRaisesRegex(live.IdentityRefused, "does not own its frozen RPC endpoint"):
            live.verify_live_identity(before, before, self.authorizations(before), self.frozen())

    def test_retained_raw_sources_recompute_every_ownership_claim(self):
        for capture, directory in zip(self.nodes.capture(), self.nodes.dirs):
            config_raw = base64.b64decode(capture["config_raw_b64"])
            self.assertEqual(config_raw, (directory / "config.json").read_bytes())
            self.assertEqual(
                __import__("hashlib").sha256(config_raw).hexdigest(), capture["config_sha256"]
            )
            listening = {}
            for table in capture["socket_tables"].values():
                raw = base64.b64decode(table["raw_b64"])
                self.assertEqual(__import__("hashlib").sha256(raw).hexdigest(), table["sha256"])
                for line in raw.decode().splitlines()[1:]:
                    fields = line.split()
                    if fields[3] == "0A":
                        listening.setdefault(int(fields[1].rsplit(":", 1)[1], 16), set()).add(
                            int(fields[9])
                        )
            owned = set(capture["socket_inodes"])
            self.assertTrue(listening[capture["control_port"]] <= owned)
            self.assertTrue(listening[capture["rpc_port"]] <= owned)

    def test_capture_opens_only_the_named_public_file(self):
        self.assertEqual(live.PUBLIC_NODE_FILES, ("config.json",))
        source = Path(live.__file__).read_text()
        for secret in ("pq-consensus.seed", "keyring", "environ"):
            self.assertNotIn(f'"{secret}', source)


if __name__ == "__main__":
    unittest.main()
