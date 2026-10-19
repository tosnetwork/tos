#!/usr/bin/env python3
"""Stage A's X02 capture seams, offline: authorization retention and the Config34 proof bundle.

No node runs here. The ValidatorElectionRehearsal methods are bound to a minimal
stand-in. The lite-server answers are real retained ones from a local PQ network
(data/proof-verify-real), and the compiled anchored verifier authenticates them in
process, so the built verifier is required (TOS_PROOF_VERIFY or the default build).
"""

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
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

REAL = REPO / "test/pq-native/data/proof-verify-real"
VERIFIER = Path(
    os.environ.get("TOS_PROOF_VERIFY", REPO / "build/lite-client/proof-verify/tos-proof-verify")
).resolve()
ANCHOR = json.loads((REAL / "anchor.json").read_text())
TARGET = json.loads((REAL / "historical-request.json").read_text())["target"]
ROOT = bytes.fromhex(TARGET["root_hash"])
FILE = bytes.fromhex(TARGET["file_hash"])
ELECTION = 1790945281


def proven_param() -> bytes:
    with tempfile.TemporaryDirectory() as work:
        material = Path(work) / "material"
        material.mkdir()
        for name in ("chain-0000.tl", "config.tl"):
            (material / name).write_bytes((REAL / "historical" / name).read_bytes())
        request = Path(work) / "request.json"
        request.write_text(
            json.dumps({"mode": "historical", "target": TARGET, "config_params": [34]})
        )
        result = subprocess.run(
            [
                str(VERIFIER),
                "verify",
                "--anchor",
                str(REAL / "anchor.json"),
                "--request",
                str(request),
                "--material",
                str(material),
            ],
            capture_output=True,
            check=True,
        )
    return base64.b64decode(json.loads(result.stdout)["config_params"][0]["boc"])


def stand_in(artifacts: Path, rows=None):
    node = SimpleNamespace(
        process_id=os.getpid(),
        transport_ports=(1, 2, 30604),
        validator_key=SimpleNamespace(id=bytes(range(32))),
    )
    controller = SimpleNamespace(
        address=SimpleNamespace(hash_part=b"\x11" * 32),
        consensus=SimpleNamespace(key_id=b"\x22" * 32),
    )
    nodes, controllers = [node] * 4, [controller] * 4
    if rows is not None:
        nodes = [
            SimpleNamespace(validator_key=SimpleNamespace(id=bytes.fromhex(r["adnl_id_hex"])))
            for r in rows
        ]
        controllers = [
            SimpleNamespace(
                address=SimpleNamespace(hash_part=bytes.fromhex(r["controller_id_hex"])),
                consensus=SimpleNamespace(key_id=bytes.fromhex(r["consensus_key_id_hex"])),
            )
            for r in rows
        ]
    fetched = []

    def fetch(verifier, anchor, block_id, material):
        # The lite-server's answers, exactly as the verifier saves them.
        fetched.append((anchor, block_id))
        material.mkdir()
        for name in ("chain-0000.tl", "config.tl"):
            (material / name).write_bytes((REAL / "historical" / name).read_bytes())

    fake = SimpleNamespace(
        nodes=nodes,
        controllers=controllers,
        artifacts_dir=artifacts,
        pq_authorization_records={},
        file_provenance=Rehearsal.file_provenance,
        experiment=SimpleNamespace(rpc_addresses=[f"127.0.0.1:{n}" for n in range(1, 5)]),
        experiment_current_config34_hash=0,
        network=SimpleNamespace(),
        install=SimpleNamespace(build_dir=VERIFIER.parents[2]),
        zerostate_anchor=lambda verifier: dict(ANCHOR),
        fetch_config34_material=fetch,
        fetched=fetched,
    )

    async def masterchain_seqno():
        return TARGET["seqno"]

    fake.masterchain_seqno = masterchain_seqno
    return fake


def rpc(param: bytes, block_id_override=None):
    full = {
        "@type": "tos.blockIdExt",
        "workchain": -1,
        "shard": str(-(1 << 63)),
        "seqno": TARGET["seqno"],
        "root_hash": base64.b64encode(ROOT).decode(),
        "file_hash": base64.b64encode(FILE).decode(),
    }

    def call(address, method, params=None):
        if method == "getBlockHeader":
            return {"result": {"id": full}}
        assert method == "getConfigParam" and params == {
            "param": 34,
            "seqno": TARGET["seqno"],
            "with_proof": True,
        }
        return {
            "result": {
                "@type": "configInfo",
                "block_id": block_id_override or full,
                "config": {"@type": "tvm.cell", "bytes": base64.b64encode(param).decode()},
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
    @classmethod
    def setUpClass(cls):
        if not VERIFIER.is_file():
            raise AssertionError(f"tos-proof-verify is not built at {VERIFIER}")
        from pytosiq_core.boc.cell import Cell
        from x02_config34_proof import decode_validator_set

        cls.param = proven_param()
        decoded = decode_validator_set(Cell.one_from_boc(cls.param))
        cls.rows = decoded["validators"]
        cls.cell_hash = int(decoded["cell_hash"], 16)

    def capture(self, fake, election=ELECTION):
        return asyncio.run(Rehearsal.capture_config34_same_block_proof(fake, election))

    def run_with(self, call, fake, election=ELECTION):
        original = stage_a.json_rpc_call
        stage_a.json_rpc_call = call
        try:
            return self.capture(fake, election)
        finally:
            stage_a.json_rpc_call = original

    def test_the_bundle_is_retained_exactly_and_authenticated_from_the_zerostate(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(os.path.realpath(directory)), self.rows)
            fake.experiment_current_config34_hash = self.cell_hash
            bundle = self.run_with(rpc(self.param), fake)
            self.assertEqual(bundle["stage_a_verdict"], "X02_CONFIG34_SAME_BLOCK_PROOF_OK")
            self.assertEqual(fake.fetched[0][0], ANCHOR)
            self.assertEqual(fake.fetched[0][1]["seqno"], TARGET["seqno"])
            retained = Path(directory) / f"election-{ELECTION}-config34-proof"
            self.assertEqual(
                sorted(str(p.relative_to(retained)) for p in retained.rglob("*") if p.is_file()),
                ["material/chain-0000.tl", "material/config.tl", "param.boc"],
            )
            for name in ("chain-0000.tl", "config.tl"):
                self.assertEqual(
                    bundle["material"][name]["sha256"],
                    hashlib.sha256((REAL / "historical" / name).read_bytes()).hexdigest(),
                )

    def test_a_retained_parameter_that_is_not_the_proven_cell_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(os.path.realpath(directory)), self.rows)
            other = next((REPO / "test/pq-native/x02-config34-fixtures").glob("config34-*.boc"))
            with self.assertRaisesRegex(ProofRefused, "differs from the proven parameter cell"):
                self.run_with(rpc(other.read_bytes()), fake)

    def test_four_nodes_disagreeing_on_the_full_id_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(directory), self.rows)
            honest = rpc(self.param)

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

            with self.assertRaisesRegex(AssertionError, "disagree on the full block ID"):
                self.run_with(split, fake)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_a_reply_for_another_block_is_refused_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = stand_in(Path(directory), self.rows)
            other = {
                "@type": "tos.blockIdExt",
                "workchain": -1,
                "shard": str(-(1 << 63)),
                "seqno": 12,
                "root_hash": base64.b64encode(b"\x01" * 32).decode(),
                "file_hash": base64.b64encode(b"\x02" * 32).decode(),
            }
            with self.assertRaisesRegex(AssertionError, "another full block ID"):
                self.run_with(rpc(self.param, block_id_override=other), fake)
            self.assertEqual(list(Path(directory).iterdir()), [])


class ZerostateAnchor(unittest.TestCase):
    def test_the_anchor_is_computed_from_the_local_zerostate_file(self):
        genesis = REPO / "test/pq-native/data/c04-pq-genesis.boc"
        result = subprocess.run(
            [str(VERIFIER), "anchor", "--zerostate", str(genesis)], capture_output=True, check=True
        )
        expected = json.loads(result.stdout)
        zero = SimpleNamespace(
            file=genesis,
            root_hash=bytes.fromhex(expected["root_hash"]),
            file_hash=bytes.fromhex(expected["file_hash"]),
        )
        fake = SimpleNamespace(network=SimpleNamespace(zerostate=SimpleNamespace(masterchain=zero)))
        self.assertEqual(Rehearsal.zerostate_anchor(fake, VERIFIER), expected)
        zero.file_hash = b"\x01" * 32
        with self.assertRaisesRegex(AssertionError, "does not give the network's anchor"):
            Rehearsal.zerostate_anchor(fake, VERIFIER)


if __name__ == "__main__":
    unittest.main()
