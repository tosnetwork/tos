#!/usr/bin/env python3
"""X02 Config34: decoding, frozen-row binding and bundle-shape refusals, without the verifier.

Authentication itself is the compiled anchored verifier's; its production-path tests,
including a self-consistent bundle that is not authenticated from the anchor, are in
test_x02_config34_verifier.py. The checks here refuse before the verifier runs, so they
need no native build. Positive Config34 bytes are four real Config34 cells returned by
JSON-RPC in X01.
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import x02_config34_proof as proof
from pytosiq_core.boc.cell import Cell

FIXTURES = Path(__file__).resolve().parent / "x02-config34-fixtures"


def config34_cells():
    return {
        int(path.stem.rsplit("-", 1)[1]): Cell.one_from_boc(path.read_bytes())
        for path in sorted(FIXTURES.glob("config34-since-*.boc"))
    }


ELECTION = 1790358449
ANCHOR = {
    "kind": "zerostate",
    "workchain": -1,
    "shard": "8000000000000000",
    "seqno": 0,
    "root_hash": "1b" * 32,
    "file_hash": "c9" * 32,
}
TARGET = {
    "workchain": -1,
    "shard": "8000000000000000",
    "seqno": 11,
    "root_hash": "944F0E7095C7BACB5D4CBED23785BAF9C4B30A606ED36E7B916F6865BAFF7C0C",
    "file_hash": "78099EA7E95C42FE8BEDC2CDA8F67FB0D162A67ED0F13644E6DE3D177FF839EC",
}


def make_bundle(base, chain=b"chain", config=b"config", param=b"param"):
    """A bundle in Stage A's layout; its bytes are placeholders that never reach a proof."""
    paths = proof.bundle_paths(ELECTION)
    (base / paths["material"]).mkdir(parents=True)
    bundle = {"block_id": dict(TARGET), "material": {}}
    for name, raw in (("chain-0000.tl", chain), ("config.tl", config)):
        (base / paths["material"] / name).write_bytes(raw)
        bundle["material"][name] = {
            "path": paths["material"] + name,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    (base / paths["param"]).write_bytes(param)
    bundle["param"] = {"path": paths["param"], "sha256": hashlib.sha256(param).hexdigest()}
    return bundle


class FixtureIdentity(unittest.TestCase):
    def test_fixture_bytes_match_their_recorded_provenance(self):
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        for since, row in manifest["config34_cells"]["by_utime_since"].items():
            raw = (FIXTURES / f"config34-since-{since}.boc").read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"])


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
        # An executable that fails if run: every refusal below precedes it.
        self.stub = self.base / "stub-verifier"
        self.stub.write_text("#!/bin/sh\nexit 9\n")
        self.stub.chmod(0o755)

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

    def refuse(self, bundle, reason, anchor=ANCHOR, verifier=None):
        """Every refusal here must happen before any verifier could run."""
        with self.assertRaisesRegex(proof.ProofRefused, reason):
            proof.verify_bundle(bundle, self.base, [], ELECTION, anchor, verifier or self.stub)

    def test_bundle_files_must_be_this_elections_fixed_names(self):
        bundle = make_bundle(self.base)
        for name, path in (
            ("chain-0000.tl", f"election-{ELECTION + 1}-config34-proof/material/chain-0000.tl"),
            ("config.tl", "/etc/passwd"),
        ):
            changed = json.loads(json.dumps(bundle))
            changed["material"][name]["path"] = path
            with self.subTest(name=name):
                self.refuse(changed, "not this election's", verifier=self.stub)
        changed = json.loads(json.dumps(bundle))
        changed["param"]["path"] = f"election-{ELECTION}-config34-proof/../x/param.boc"
        self.refuse(changed, "not this election's", verifier=self.stub)

    def test_material_must_be_a_contiguous_chain_and_one_configuration_proof(self):
        bundle = make_bundle(self.base)
        for label, mutate in (
            ("no chain", lambda m: m.pop("chain-0000.tl")),
            ("no config", lambda m: m.pop("config.tl")),
            ("gap", lambda m: m.__setitem__("chain-0002.tl", m["chain-0000.tl"])),
            ("extra", lambda m: m.__setitem__("account.tl", m["config.tl"])),
        ):
            changed = json.loads(json.dumps(bundle))
            mutate(changed["material"])
            with self.subTest(case=label):
                self.refuse(
                    changed,
                    "contiguous chain plus one configuration proof",
                    verifier=self.stub,
                )

    def test_digest_mismatch_and_missing_digest_refuse_before_any_proof(self):
        bundle = make_bundle(self.base)
        bundle["material"]["config.tl"]["sha256"] = "0" * 64
        self.refuse(bundle, "digest differs", verifier=self.stub)
        bundle = make_bundle(self.base / "again")
        del bundle["param"]["sha256"]
        with self.assertRaisesRegex(proof.ProofRefused, "no retained digest"):
            proof.verify_bundle(bundle, self.base / "again", [], ELECTION, ANCHOR, self.stub)

    def test_only_a_full_zerostate_identity_is_an_anchor(self):
        bundle = make_bundle(self.base)
        for label, anchor in (
            ("key block kind", dict(ANCHOR, kind="key_block")),
            ("seqno", dict(ANCHOR, seqno=1)),
            ("short root", dict(ANCHOR, root_hash="1b" * 31)),
            ("no file hash", {k: v for k, v in ANCHOR.items() if k != "file_hash"}),
            ("global id only", {"global_id": 3}),
            ("extra field", dict(ANCHOR, trusted=True)),
        ):
            with self.subTest(case=label):
                self.refuse(bundle, "not a full masterchain zerostate identity", anchor=anchor)

    def test_the_target_must_be_a_full_masterchain_id(self):
        for label, target, reason in (
            ("basechain", dict(TARGET, workchain=0), "masterchain block only"),
            ("zero seqno", dict(TARGET, seqno=0), "seqno is invalid"),
            ("short hash", dict(TARGET, file_hash="00"), "not 256-bit"),
            ("shard", dict(TARGET, shard="4000000000000000"), "masterchain shard"),
        ):
            base = self.base / label.replace(" ", "-")
            bundle = make_bundle(base)
            bundle["block_id"] = target
            with self.subTest(case=label), self.assertRaisesRegex(proof.ProofRefused, reason):
                proof.verify_bundle(bundle, base, [], ELECTION, ANCHOR, self.stub)

    def test_the_verifier_must_be_an_absolute_executable_named_by_the_caller(self):
        bundle = make_bundle(self.base)
        with self.assertRaisesRegex(proof.ProofRefused, "not absolute"):
            proof.verify_bundle(bundle, self.base, [], ELECTION, ANCHOR, "tos-proof-verify")
        data = self.base / "data.bin"
        data.write_bytes(b"x")
        with self.assertRaisesRegex(proof.ProofRefused, "executable regular file"):
            proof.verify_bundle(bundle, self.base, [], ELECTION, ANCHOR, data)

    def test_the_unauthenticated_header_path_is_gone(self):
        for name in ("proven_config_param", "require_four_node_headers", "TRUST_ROOT"):
            self.assertFalse(hasattr(proof, name), name)


if __name__ == "__main__":
    unittest.main()
