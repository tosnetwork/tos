#!/usr/bin/env python3
"""The coordinator's elected-identity gate: decoded TEXT alone no longer accepts.

The fixture election is built from a real retained Config34 cell: its text rows are
what the old gate accepted. Old red/new green: the 55d3c8f5 gate accepts it without a
same-block proof; this gate refuses it. The real proof check runs the verifier in a
separate process on a retained Config30-only bundle, which must not pass as Config34.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

import x02_config34_proof as proof
from pytosiq_core.boc.cell import Cell

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "x02-config34-fixtures"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_x02_config34_proof as proof_fixture  # noqa: E402
import test_x02_live_identity as live_fixture  # noqa: E402


def load(name, raw):
    module = types.ModuleType(name)
    module.__file__ = str(REPO / "scripts/x02_four_node.py")
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


four_node = load("x02_four_node_under_test", (REPO / "scripts/x02_four_node.py").read_bytes())
OLD_SOURCE = "55d3c8f511b98d499643723b21bbbbd47a2e7f88"


def old_four_node():
    raw = subprocess.check_output(
        ["git", "-C", str(REPO), "show", f"{OLD_SOURCE}:scripts/x02_four_node.py"]
    )
    return load("x02_four_node_old", raw)


class Ledger(list):
    def append(self, item):
        super().append(item)


def fixture(base: Path):
    since = min(int(p.stem.rsplit("-", 1)[1]) for p in FIXTURES.glob("config34-since-*.boc"))
    cell = Cell.one_from_boc((FIXTURES / f"config34-since-{since}.boc").read_bytes())
    decoded = proof.decode_validator_set(cell)
    rows = [
        {
            "validator_index": i + 1,
            "node_name": f"node{i + 1}",
            **{f: row[f] for f in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")},
        }
        for i, row in enumerate(decoded["validators"])
    ]
    text = " ".join(
        f"validator_pq validator_id:x{r['controller_id_hex'].upper()} algorithm_id:1 "
        f"key_id:x{r['consensus_key_id_hex'].upper()} weight:1 adnl_addr:x{r['adnl_id_hex'].upper()}"
        for r in rows
    ).encode()
    (base / "artifacts").mkdir()
    artifact = base / "artifacts" / f"election-{since}-config34.txt"
    artifact.write_bytes(text)
    digest = hashlib.sha256(text).hexdigest()
    election = {
        "election_id": since,
        "config34_cell_hash": int(decoded["cell_hash"], 16),
        "config34_artifact": {"path": str(artifact), "size": len(text), "sha256": digest},
        "config34": {"raw_sha256": digest, "utime_since": since, "total": 4, "main": 4},
        "validators": {
            str(i + 1): {
                "validator_index": i + 1,
                "selection_status": "selected",
                **{f: r[f] for f in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")},
            }
            for i, r in enumerate(rows)
        },
    }
    allocation = {
        "schema": "tos.validator-reward-election-allocation-evidence.v4",
        "status": "complete",
        "mode": "experiment",
        "provenance": {"source_commit": "c"},
        "elections": [election],
    }
    path = base / "reward-election-allocation-evidence-v4.json"
    path.write_text(json.dumps(allocation))
    report = {"experiment": {"allocation_evidence": str(path)}, "source_commit": "c"}
    return report, rows, election, decoded


class ElectedIdentityGate(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.path.realpath(tempfile.mkdtemp()))
        self.report, self.rows, self.election, self.decoded = fixture(self.base)

    def tearDown(self):
        shutil.rmtree(self.base)

    def test_old_gate_accepted_decoded_text_alone_and_this_gate_refuses_it(self):
        old_four_node().verify_elected_identity(self.report, self.base, self.rows, Ledger())
        with self.assertRaisesRegex(ValueError, "no same-block Config34 proof"):
            four_node.verify_elected_identity(
                self.report,
                self.base,
                self.rows,
                Ledger(),
                lambda *args: {"verdict": "X02_CONFIG34_SAME_BLOCK_PROOF_OK"},
            )

    def with_bundle(self):
        allocation = json.loads(
            (self.base / "reward-election-allocation-evidence-v4.json").read_text()
        )
        allocation["elections"][0]["config34_proof"] = {"block_id": {}}
        (self.base / "reward-election-allocation-evidence-v4.json").write_text(
            json.dumps(allocation)
        )

    def test_an_accepting_proof_with_the_recorded_cell_hash_passes(self):
        self.with_bundle()
        ledger = Ledger()
        four_node.verify_elected_identity(
            self.report,
            self.base,
            self.rows,
            ledger,
            lambda *args: {
                "verdict": "X02_CONFIG34_SAME_BLOCK_PROOF_OK",
                "election_id": self.election["election_id"],
                "config34_cell_hash": self.decoded["cell_hash"],
            },
        )
        self.assertIn("elected_config34_same_block_proof_verified", [e["event"] for e in ledger])

    def test_a_proof_for_another_cell_or_election_or_a_refusal_is_refused(self):
        self.with_bundle()
        good = {
            "verdict": "X02_CONFIG34_SAME_BLOCK_PROOF_OK",
            "election_id": self.election["election_id"],
            "config34_cell_hash": self.decoded["cell_hash"],
        }
        for verdict in (
            dict(good, config34_cell_hash="00" * 32),
            dict(good, election_id=1),
            {"verdict": "REFUSED", "reason": "x"},
        ):
            with (
                self.subTest(verdict=verdict.get("verdict")),
                self.assertRaisesRegex(ValueError, "does not accept this election"),
            ):
                four_node.verify_elected_identity(
                    self.report, self.base, self.rows, Ledger(), lambda *a, v=verdict: v
                )

    def test_real_proof_check_process_refuses_a_config30_only_bundle(self):
        # Logic only: a direct launcher stands in for the U24 sandbox, which needs host bwrap
        # and is exercised in test_x02_verifier_sandbox.py without running the verifier.
        allocation = json.loads(
            (self.base / "reward-election-allocation-evidence-v4.json").read_text()
        )
        artifacts = Path(os.path.realpath(self.base / "artifacts"))
        allocation["elections"][0]["config34_proof"] = proof_fixture.make_bundle(artifacts)
        (self.base / "reward-election-allocation-evidence-v4.json").write_text(
            json.dumps(allocation)
        )
        head = subprocess.check_output(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
        ).strip()
        output = self.base / "out"
        output.mkdir()
        check = four_node.config34_proof_check(
            {"interpreter": sys.executable, "dependency_roots": []},
            {"source_sha": head},
            output,
            proof_fixture.RPCS,
            launcher=lambda binding, out, command: command,
        )
        with self.assertRaisesRegex(ValueError, "verifier refused.*ConfigParam34 is not proven"):
            four_node.verify_elected_identity(self.report, self.base, self.rows, Ledger(), check)
        terminal = json.loads(
            (output / f"config34-proof-{proof_fixture.ELECTION}.terminal.json").read_text()
        )
        self.assertEqual(
            (terminal["natural_exit"], terminal["timed_out"], terminal["sandbox_setup_failed"]),
            (1, False, False),
        )


class LivePidIdentityGate(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.path.realpath(tempfile.mkdtemp()))
        (self.base / "artifacts").mkdir()
        self.validators, self.keys = live_fixture.real_validators()
        (self.base / "nodes").mkdir()
        self.nodes = live_fixture.Nodes(self.base / "nodes", self.validators)
        self.live = importlib.import_module("x02_live_identity")
        self.before = self.nodes.capture()
        self.election_id = 1790358449
        records = {}
        for index, (row, key, cap) in enumerate(zip(self.validators, self.keys, self.before), 1):
            record = {
                "schema": "tos.x02.pq-authorization.v1",
                "validator_index": index,
                "election_id": self.election_id,
                "query_id": index,
                "validator_id_hex": row["controller_id_hex"],
                "key_id_hex": row["consensus_key_id_hex"],
                "algorithm_id": 1,
                "public_key_hex": key.hex(),
                "control_port": cap["control_port"],
                "node_pid": cap["pid"],
                "node_start_ticks": cap["start_ticks"],
            }
            path = (
                self.base
                / "artifacts"
                / (f"pq-authorization-{self.election_id}-validator-{index}-query-{index}.json")
            )
            raw = json.dumps(record).encode()
            path.write_bytes(raw)
            records[str(index)] = [{"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}]
        self.allocation = {
            "elections": [
                {
                    "election_id": self.election_id,
                    "selection_status": "selected",
                    "pq_authorizations": records,
                }
            ]
        }
        self.write()
        self.declared = [
            {
                "validator_index": i + 1,
                **{f: r[f] for f in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")},
            }
            for i, r in enumerate(self.validators)
        ]

    def write(self):
        (self.base / "reward-election-allocation-evidence-v4.json").write_text(
            json.dumps(self.allocation)
        )

    def tearDown(self):
        self.nodes.close()
        shutil.rmtree(self.base)

    def verify(self):
        return four_node.verify_live_pid_identity(
            self.live, self.before, self.nodes.capture(), self.base, self.declared
        )

    def test_retained_authorizations_bind_the_four_live_pids(self):
        self.assertEqual([b["pid"] for b in self.verify()], [p.pid for p in self.nodes.processes])

    def test_a_changed_record_is_refused(self):
        path = Path(self.allocation["elections"][0]["pq_authorizations"]["2"][0]["path"])
        path.write_bytes(path.read_bytes().replace(b'"query_id": 2', b'"query_id": 9'))
        with self.assertRaisesRegex(ValueError, "digest differs"):
            self.verify()

    def test_a_missing_validator_record_is_refused(self):
        self.allocation["elections"][0]["pq_authorizations"]["3"] = []
        self.write()
        with self.assertRaisesRegex(ValueError, "validator 3 has no retained node authorization"):
            self.verify()

    def test_a_record_from_another_election_is_refused(self):
        entry = self.allocation["elections"][0]["pq_authorizations"]["4"][0]
        record = json.loads(Path(entry["path"]).read_text())
        record["election_id"] = 1
        raw = json.dumps(record).encode()
        Path(entry["path"]).write_bytes(raw)
        entry["sha256"] = hashlib.sha256(raw).hexdigest()
        self.write()
        with self.assertRaisesRegex(ValueError, "belongs elsewhere"):
            self.verify()

    def test_a_record_outside_this_elections_artifact_names_is_refused(self):
        entry = self.allocation["elections"][0]["pq_authorizations"]["1"][0]
        original = Path(entry["path"])
        cases = {
            "outside": self.base / original.name,
            "other-election": original.with_name(original.name.replace(str(self.election_id), "1")),
            "nested": self.base / "artifacts" / "sub" / original.name,
        }
        for label, target in cases.items():
            target.parent.mkdir(exist_ok=True)
            shutil.copy(original, target)
            entry["path"] = str(target)
            self.write()
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(ValueError, "not this election's artifact"),
            ):
                self.verify()
        entry["path"] = str(original)

    def test_a_symlinked_record_is_refused(self):
        entry = self.allocation["elections"][0]["pq_authorizations"]["2"][0]
        original = Path(entry["path"])
        moved = self.base / "elsewhere.json"
        original.rename(moved)
        os.symlink(moved, original)
        with self.assertRaises(OSError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
