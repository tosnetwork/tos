#!/usr/bin/env python3
"""Stage A's X02 capture seams, offline: authorization retention and the Config34 proof bundle.

No node runs here. The two ValidatorElectionRehearsal methods are bound to a minimal
stand-in; JSON-RPC answers are built from retained Z01 lite bytes, which prove Config30
only, so the bundle must be refused as Config34 after being retained exactly.
"""

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "stage_a", REPO / "scripts/validator-election-stage-a.py"
)
stage_a = importlib.util.module_from_spec(spec)
sys.modules["stage_a"] = stage_a
spec.loader.exec_module(stage_a)
Rehearsal = stage_a.ValidatorElectionRehearsal
from x02_config34_proof import ProofRefused  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "x02-config34-fixtures"
SEQ11_ROOT = bytes.fromhex("944F0E7095C7BACB5D4CBED23785BAF9C4B30A606ED36E7B916F6865BAFF7C0C")
SEQ11_FILE = bytes.fromhex("78099EA7E95C42FE8BEDC2CDA8F67FB0D162A67ED0F13644E6DE3D177FF839EC")


def stand_in(artifacts: Path):
    node = SimpleNamespace(
        process_id=os.getpid(),
        transport_ports=(1, 2, 30604),
        validator_key=SimpleNamespace(id=bytes(range(32))),
    )
    controller = SimpleNamespace(
        address=SimpleNamespace(hash_part=b"\x11" * 32),
        consensus=SimpleNamespace(key_id=b"\x22" * 32),
    )
    fake = SimpleNamespace(
        nodes=[node] * 4,
        controllers=[controller] * 4,
        artifacts_dir=artifacts,
        pq_authorization_records={},
        file_provenance=Rehearsal.file_provenance,
        experiment=SimpleNamespace(rpc_addresses=[f"127.0.0.1:{n}" for n in range(1, 5)]),
        experiment_current_config34_hash=0,
    )

    async def masterchain_seqno():
        return 11

    fake.masterchain_seqno = masterchain_seqno
    return fake


def rpc(block_id_override=None):
    q = {
        k: (FIXTURES / f"z01-seq11-{k}.boc").read_bytes()
        for k in ("param30", "state-proof", "config-proof")
    }
    full = {
        "@type": "tos.blockIdExt",
        "workchain": -1,
        "shard": str(-(1 << 63)),
        "seqno": 11,
        "root_hash": base64.b64encode(SEQ11_ROOT).decode(),
        "file_hash": base64.b64encode(SEQ11_FILE).decode(),
    }

    def call(address, method, params=None):
        if method == "getBlockHeader":
            return {"result": {"id": full}}
        assert method == "getConfigParam" and params == {
            "param": 34,
            "seqno": 11,
            "with_proof": True,
        }
        return {
            "result": {
                "@type": "configInfo",
                "block_id": block_id_override or full,
                "config": {"@type": "tvm.cell", "bytes": base64.b64encode(q["param30"]).decode()},
                "state_proof": base64.b64encode(q["state-proof"]).decode(),
                "config_proof": base64.b64encode(q["config-proof"]).decode(),
            }
        }

    return call


class AuthorizationRetention(unittest.TestCase):
    def test_record_names_the_answering_process_and_its_public_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(directory))
            auth = SimpleNamespace(
                validator_id=b"\x11" * 32,
                key_id=b"\x22" * 32,
                algorithm_id=1,
                public_key=b"\x33" * 1312,
            )
            provenance = Rehearsal.record_pq_authorization(fake, 1, 1790000000, 7, auth)
            record = json.loads(Path(provenance["path"]).read_text())
            stat_raw = Path(f"/proc/{os.getpid()}/stat").read_bytes()
            self.assertEqual(record["node_pid"], os.getpid())
            self.assertEqual(
                record["node_start_ticks"], int(stat_raw.rsplit(b") ", 1)[1].split()[19])
            )
            self.assertEqual(
                (record["control_port"], record["validator_index"], record["key_id_hex"]),
                (30604, 2, "22" * 32),
            )
            self.assertEqual(fake.pq_authorization_records[1790000000]["2"], [provenance])
            with self.assertRaises(FileExistsError):
                Rehearsal.record_pq_authorization(fake, 1, 1790000000, 7, auth)


class Config34ProofCapture(unittest.TestCase):
    def capture(self, fake):
        return asyncio.run(Rehearsal.capture_config34_same_block_proof(fake, 1790358449))

    def test_bundle_is_retained_exactly_and_a_config30_only_proof_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(directory))
            original = stage_a.json_rpc_call
            stage_a.json_rpc_call = rpc()
            try:
                with self.assertRaisesRegex(ProofRefused, "ConfigParam34 is not proven"):
                    self.capture(fake)
            finally:
                stage_a.json_rpc_call = original
            retained = Path(directory) / "election-1790358449-config34-proof"
            self.assertEqual(
                sorted(p.name for p in retained.iterdir()),
                [
                    "config_proof.boc",
                    "header-node1.json",
                    "header-node2.json",
                    "header-node3.json",
                    "header-node4.json",
                    "param.boc",
                    "state_proof.boc",
                ],
            )
            self.assertEqual(
                hashlib.sha256((retained / "state_proof.boc").read_bytes()).hexdigest(),
                hashlib.sha256((FIXTURES / "z01-seq11-state-proof.boc").read_bytes()).hexdigest(),
            )

    def test_four_nodes_disagreeing_on_the_full_id_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(directory))
            honest = rpc()

            def split(address, method, params=None):
                reply = honest(address, method, params)
                if method == "getBlockHeader" and address.endswith(":3"):
                    reply = {
                        "result": {
                            "id": dict(
                                reply["result"]["id"],
                                file_hash=base64.b64encode(b"\x09" * 32).decode(),
                            )
                        }
                    }
                return reply

            original = stage_a.json_rpc_call
            stage_a.json_rpc_call = split
            try:
                with self.assertRaisesRegex(AssertionError, "disagree on the full block ID"):
                    self.capture(fake)
            finally:
                stage_a.json_rpc_call = original
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_a_reply_for_another_block_is_refused_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(directory))
            other = {
                "@type": "tos.blockIdExt",
                "workchain": -1,
                "shard": str(-(1 << 63)),
                "seqno": 12,
                "root_hash": base64.b64encode(b"\x01" * 32).decode(),
                "file_hash": base64.b64encode(b"\x02" * 32).decode(),
            }
            original = stage_a.json_rpc_call
            stage_a.json_rpc_call = rpc(block_id_override=other)
            try:
                with self.assertRaisesRegex(AssertionError, "another full block ID"):
                    self.capture(fake)
            finally:
                stage_a.json_rpc_call = original
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
