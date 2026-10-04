#!/usr/bin/env python3
"""X02 same-block Config34 proof on retained real bytes, with the controls that matter.

Positive proof-chain bytes are Z01's retained lite quartets (a ConfigParam30 proof per
block, each accepted by the native checker); positive Config34 bytes are four real
Config34 cells returned by JSON-RPC in X01. No retained lite reply proves Config34
itself, so a real same-block Config34 bundle is exercised only by a live capture.
"""

import base64
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import x02_config34_proof as proof
from pytosiq_core.boc.cell import Cell

FIXTURES = Path(__file__).resolve().parent / "x02-config34-fixtures"
SEQ = {
    11: {
        "workchain": -1,
        "shard": str(-(1 << 63)),
        "seqno": 11,
        "root_hash": "944F0E7095C7BACB5D4CBED23785BAF9C4B30A606ED36E7B916F6865BAFF7C0C",
        "file_hash": "78099EA7E95C42FE8BEDC2CDA8F67FB0D162A67ED0F13644E6DE3D177FF839EC",
    },
    12: {
        "workchain": -1,
        "shard": str(-(1 << 63)),
        "seqno": 12,
        "root_hash": "4A77BA6D3D146F6DEBE31C3E9600E44D3609991857D8155B2711DFC3E9554F87",
        "file_hash": "C4B33E125A555681BE0D93C0C0D473D9D05C32D905C4B9EC197AF7DF52F6EE11",
    },
}
NATIVE_PARAM30 = "A922FC0CB6BACFEE2D49645DA25394F069447D8C250E4A0FB5ED75BA23CDD9E5"


def quartet(seqno):
    return {
        kind: (FIXTURES / f"z01-seq{seqno}-{kind}.boc").read_bytes()
        for kind in ("block", "state-proof", "config-proof", "param30")
    }


def config34_cells():
    return {
        int(path.stem.rsplit("-", 1)[1]): Cell.one_from_boc(path.read_bytes())
        for path in sorted(FIXTURES.glob("config34-since-*.boc"))
    }


ELECTION = 1790358449
RPCS = [f"127.0.0.1:{34600 + index}" for index in range(4)]


def make_bundle(base, block=True, param=None, forged_header=None, seqno=11):
    """A bundle laid out exactly as Stage A writes it, from retained Z01 bytes."""
    q = quartet(seqno)
    paths = proof.bundle_paths(ELECTION)
    directory = base / f"election-{ELECTION}-config34-proof"
    directory.mkdir(parents=True)
    bundle = {"block_id": SEQ[seqno], "source_rpc": RPCS[0], "headers": []}
    kinds = {
        "state_proof": q["state-proof"],
        "config_proof": q["config-proof"],
        "param": q["param30"] if param is None else param,
    }
    if block:
        kinds["block"] = q["block"]
    for key, raw in kinds.items():
        (base / paths[key]).write_bytes(raw)
        bundle[key] = {"path": paths[key], "sha256": hashlib.sha256(raw).hexdigest()}
    for index, rpc in enumerate(RPCS, 1):
        full = {
            "workchain": -1,
            "shard": SEQ[seqno]["shard"],
            "seqno": seqno,
            "root_hash": base64.b64encode(bytes.fromhex(SEQ[seqno]["root_hash"])).decode(),
            "file_hash": base64.b64encode(bytes.fromhex(SEQ[seqno]["file_hash"])).decode(),
        }
        if forged_header == index:
            full["file_hash"] = base64.b64encode(b"\x07" * 32).decode()
        raw = json.dumps({"result": {"id": full}}).encode()
        (base / paths["headers"][index - 1]).write_bytes(raw)
        bundle["headers"].append(
            {
                "rpc": rpc,
                "path": paths["headers"][index - 1],
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return bundle


class FixtureIdentity(unittest.TestCase):
    def test_fixture_bytes_match_their_recorded_provenance(self):
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        for key in ("z01_seq11_quartet", "z01_seq12_quartet"):
            for name, digest in manifest[key]["files"].items():
                self.assertEqual(hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest(), digest)
        for since, row in manifest["config34_cells"]["by_utime_since"].items():
            raw = (FIXTURES / f"config34-since-{since}.boc").read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"])


class SameBlockProofChain(unittest.TestCase):
    def prove(self, block_seq, proof_seq=None, index=30, block_id=None):
        block, proofs = quartet(block_seq), quartet(proof_seq or block_seq)
        return proof.proven_config_param(
            block_id or SEQ[block_seq],
            block["block"],
            proofs["state-proof"],
            proofs["config-proof"],
            index,
        )

    def test_both_retained_blocks_prove_the_native_checkers_param30(self):
        for seqno in (11, 12):
            cell = self.prove(seqno)
            self.assertEqual(cell.hash.hex().upper(), NATIVE_PARAM30)
            self.assertEqual(cell.hash, Cell.one_from_boc(quartet(seqno)["param30"]).hash)

    def test_state_proof_alone_binds_the_block_root(self):
        q = quartet(11)
        cell = proof.proven_config_param(SEQ[11], None, q["state-proof"], q["config-proof"], 30)
        self.assertEqual(cell.hash.hex().upper(), NATIVE_PARAM30)
        with self.assertRaisesRegex(proof.ProofRefused, "does not match the full block ID"):
            proof.proven_config_param(SEQ[12], None, q["state-proof"], q["config-proof"], 30)

    def test_wrong_parameter_is_not_proven(self):
        with self.assertRaisesRegex(proof.ProofRefused, "ConfigParam34 is not proven"):
            self.prove(11, index=34)

    def test_proofs_from_another_block_are_refused(self):
        with self.assertRaisesRegex(proof.ProofRefused, "does not match the full block ID"):
            self.prove(11, proof_seq=12)

    def test_block_bytes_and_full_id_must_agree(self):
        wrong_root = dict(SEQ[11], root_hash=SEQ[12]["root_hash"])
        with self.assertRaisesRegex(proof.ProofRefused, "file hash|root hash"):
            self.prove(11, block_id=wrong_root)
        wrong_file = dict(SEQ[11], file_hash=SEQ[12]["file_hash"])
        with self.assertRaisesRegex(proof.ProofRefused, "file hash"):
            self.prove(11, block_id=wrong_file)
        with self.assertRaisesRegex(proof.ProofRefused, "masterchain"):
            self.prove(11, block_id=dict(SEQ[11], workchain=0))

    def test_a_config_proof_from_another_block_is_refused(self):
        block, other = quartet(11), quartet(12)
        with self.assertRaisesRegex(proof.ProofRefused, "does not match the full block ID"):
            proof.proven_config_param(
                SEQ[11], block["block"], block["state-proof"], other["config-proof"], 30
            )

    def test_the_retained_parameter_must_be_the_proven_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(os.path.realpath(directory))
            wrong = sorted(FIXTURES.glob("config34-since-*.boc"))[0].read_bytes()
            bundle = make_bundle(base, param=wrong)
            with self.assertRaisesRegex(
                proof.ProofRefused, "differs from the proven parameter cell"
            ):
                proof.verify_bundle(bundle, base, [], ELECTION, RPCS, index=30)
            bundle = make_bundle(base / "again", param=quartet(11)["param30"])
            with self.assertRaisesRegex(proof.ProofRefused, "not a validator set"):
                proof.verify_bundle(bundle, base / "again", [], ELECTION, RPCS, index=30)

    def test_a_flipped_state_proof_byte_is_refused(self):
        q = quartet(11)
        tampered = bytearray(q["state-proof"])
        tampered[len(tampered) // 2] ^= 1
        with self.assertRaises((proof.ProofRefused, ValueError, Exception)):
            proof.proven_config_param(SEQ[11], q["block"], bytes(tampered), q["config-proof"], 30)


class Config34Decoding(unittest.TestCase):
    def test_four_real_config34_cells_decode_and_every_key_id_derives(self):
        cells = config34_cells()
        self.assertEqual(len(cells), 4)
        for since, cell in cells.items():
            decoded = proof.decode_validator_set(cell)
            self.assertEqual(
                (decoded["tag"], decoded["utime_since"], decoded["total"]), (0x12, since, 4)
            )

    def test_a_single_public_key_byte_change_breaks_the_key_id(self):
        cell = next(iter(config34_cells().values()))
        original = proof.unpack_pq_bytes

        def flipped(root):
            raw = bytearray(original(root))
            raw[0] ^= 1
            return bytes(raw)

        proof.unpack_pq_bytes = flipped
        try:
            with self.assertRaisesRegex(proof.ProofRefused, "key_id does not derive"):
                proof.decode_validator_set(cell)
        finally:
            proof.unpack_pq_bytes = original

    def test_key_id_derivation_matches_the_source_formula(self):
        public = bytes(range(256)) * 5 + bytes(32)
        self.assertEqual(
            proof.derive_key_id(1, public),
            hashlib.sha256(b"TOS-PQ-CONSENSUS-KEY-v1" + b"\x01\x00" + public).digest(),
        )
        with self.assertRaises(proof.ProofRefused):
            proof.derive_key_id(1, public[:-1])


class FrozenRowComparison(unittest.TestCase):
    def setUp(self):
        self.cells = config34_cells()
        self.since = min(self.cells)
        self.decoded = proof.decode_validator_set(self.cells[self.since])
        self.rows = [
            {f: row[f] for f in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")}
            for row in self.decoded["validators"]
        ]

    def test_matching_rows_and_election_pass(self):
        proof.compare_frozen_rows(self.decoded, self.rows, self.since)

    def test_cross_election_splice_is_refused(self):
        # The retained elections re-elect the same four validators with the same keys and
        # ADNL, so rows alone cannot tell them apart; only the election binding can.
        other = max(self.cells)
        decoded_other = proof.decode_validator_set(self.cells[other])
        self.assertEqual(
            {r["consensus_key_id_hex"] for r in decoded_other["validators"]},
            {r["consensus_key_id_hex"] for r in self.decoded["validators"]},
        )
        with self.assertRaisesRegex(proof.ProofRefused, "another election"):
            proof.compare_frozen_rows(self.decoded, self.rows, other)
        with self.assertRaisesRegex(proof.ProofRefused, "another election"):
            proof.compare_frozen_rows(decoded_other, self.rows, self.since)

    def test_single_byte_key_or_adnl_mutation_is_refused(self):
        for field in ("consensus_key_id_hex", "adnl_id_hex", "controller_id_hex"):
            rows = [dict(row) for row in self.rows]
            value = rows[2][field]
            rows[2][field] = ("0" if value[0] != "0" else "1") + value[1:]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(proof.ProofRefused, "differ from the frozen rows"),
            ):
                proof.compare_frozen_rows(self.decoded, rows, self.since)

    def test_swapped_keys_between_two_rows_are_refused(self):
        rows = [dict(row) for row in self.rows]
        rows[0]["consensus_key_id_hex"], rows[1]["consensus_key_id_hex"] = (
            rows[1]["consensus_key_id_hex"],
            rows[0]["consensus_key_id_hex"],
        )
        with self.assertRaisesRegex(proof.ProofRefused, "differ from the frozen rows"):
            proof.compare_frozen_rows(self.decoded, rows, self.since)

    def test_three_rows_are_not_four(self):
        with self.assertRaisesRegex(proof.ProofRefused, "four elected rows"):
            proof.compare_frozen_rows(self.decoded, self.rows[:3], self.since)


class BoundedInputs(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(os.path.realpath(self.directory.name))

    def tearDown(self):
        self.directory.cleanup()

    def test_contained_reads_refuse_escapes_links_and_bad_sizes(self):
        (self.base / "d").mkdir()
        (self.base / "d" / "real.boc").write_bytes(b"x" * 10)
        outside = Path(tempfile.mkdtemp())
        (outside / "secret.boc").write_bytes(b"y" * 10)
        os.symlink(outside, self.base / "linkdir")
        os.symlink(self.base / "d" / "real.boc", self.base / "d" / "link.boc")
        self.assertEqual(proof.open_contained(self.base, "d/real.boc", 100), b"x" * 10)
        for relative, reason in (
            (str(outside / "secret.boc"), "plain relative"),
            ("../" + outside.name + "/secret.boc", "plain relative"),
            ("d/../d/real.boc", "plain relative"),
            ("d//real.boc", "plain relative"),
        ):
            with (
                self.subTest(relative=relative),
                self.assertRaisesRegex(proof.ProofRefused, reason),
            ):
                proof.open_contained(self.base, relative, 100)
        with self.assertRaises(OSError):
            proof.open_contained(self.base, "linkdir/secret.boc", 100)  # symlink ancestor
        with self.assertRaises(OSError):
            proof.open_contained(self.base, "d/link.boc", 100)  # symlink final
        with self.assertRaisesRegex(proof.ProofRefused, "bounded regular file"):
            proof.open_contained(self.base, "d/real.boc", 9)
        with self.assertRaisesRegex(proof.ProofRefused, "digest differs"):
            proof.open_contained(self.base, "d/real.boc", 100, "0" * 64)
        with self.assertRaisesRegex(proof.ProofRefused, "canonical real directory"):
            proof.open_contained(self.base / "linkdir", "secret.boc", 100)
        shutil.rmtree(outside)

    def test_bundle_files_must_be_this_elections_fixed_names(self):
        bundle = make_bundle(self.base)
        for name, path in (
            ("state_proof", f"election-{ELECTION + 1}-config34-proof/state_proof.boc"),
            ("config_proof", "/etc/passwd"),
            ("param", f"election-{ELECTION}-config34-proof/../x/param.boc"),
        ):
            changed = json.loads(json.dumps(bundle))
            changed[name]["path"] = path
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(proof.ProofRefused, "not this election's"),
            ):
                proof.verify_bundle(changed, self.base, [], ELECTION, RPCS)

    def test_digest_mismatch_refuses_before_parsing(self):
        bundle = make_bundle(self.base)
        bundle["config_proof"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(proof.ProofRefused, "digest differs"):
            proof.verify_bundle(bundle, self.base, [], ELECTION, RPCS)

    def test_headers_bind_the_file_hash_only_from_the_four_frozen_endpoints(self):
        bundle = make_bundle(self.base, block=False)
        # Correct headers reach the proof, which (Config30 only) is then refused as Config34.
        with self.assertRaisesRegex(proof.ProofRefused, "ConfigParam34 is not proven"):
            proof.verify_bundle(bundle, self.base, [], ELECTION, RPCS)
        cases = {
            "swapped": RPCS[1::-1] + RPCS[2:],
            "foreign": RPCS[:3] + ["127.0.0.1:9999"],
            "three": RPCS[:3],
        }
        for label, expected in cases.items():
            with self.subTest(case=label), self.assertRaisesRegex(proof.ProofRefused, "frozen"):
                proof.verify_bundle(bundle, self.base, [], ELECTION, expected)
        changed = json.loads(json.dumps(bundle))
        changed["source_rpc"] = RPCS[2]
        with self.assertRaisesRegex(proof.ProofRefused, "not exactly the four frozen"):
            proof.verify_bundle(changed, self.base, [], ELECTION, RPCS)
        changed = json.loads(json.dumps(bundle))
        changed["headers"][1], changed["headers"][2] = changed["headers"][2], changed["headers"][1]
        with self.assertRaisesRegex(proof.ProofRefused, "not exactly the four frozen"):
            proof.verify_bundle(changed, self.base, [], ELECTION, RPCS)

    def test_a_header_disagreeing_on_the_file_hash_is_refused(self):
        bundle = make_bundle(self.base, block=False, forged_header=3)
        with self.assertRaisesRegex(proof.ProofRefused, "differs from the proven full block ID"):
            proof.verify_bundle(bundle, self.base, [], ELECTION, RPCS)

    def test_the_verdict_names_its_unauthenticated_trust_root(self):
        # Only the verdict mapping is under test: the retained fixtures prove Config30,
        # not Config34, so the proof and decoding steps are stood in for.
        stand_ins = {
            "proven_config_param": lambda *args: SimpleNamespace(hash=None),
            "decode_validator_set": lambda cell: {"cell_hash": "00", "validators": []},
            "compare_frozen_rows": lambda *args: None,
        }

        class Cell:
            hash = None

            @staticmethod
            def one_from_boc(raw):
                return Cell

        saved = {name: getattr(proof, name) for name in [*stand_ins, "_pytosiq"]}
        try:
            for name, value in stand_ins.items():
                setattr(proof, name, value)
            proof._pytosiq = lambda: (Cell, None, None, None)
            for block, bound_by in [(True, "block BOC"), (False, "four nodes' headers")]:
                base = self.base / bound_by.replace(" ", "-").replace("'", "")
                result = proof.verify_bundle(
                    make_bundle(base, block=block), base, [], ELECTION, RPCS
                )
                self.assertEqual(result["file_hash_bound_by"], bound_by)
                self.assertIn("no validator signature", result["block_id_trust_root"])
                self.assertEqual(result["block_id_trust_root"], proof.TRUST_ROOT[bound_by])
        finally:
            for name, value in saved.items():
                setattr(proof, name, value)

    def test_a_config30_only_bundle_is_not_config34(self):
        with self.assertRaisesRegex(proof.ProofRefused, "ConfigParam34 is not proven"):
            proof.verify_bundle(make_bundle(self.base), self.base, [], ELECTION, RPCS)


if __name__ == "__main__":
    unittest.main()
