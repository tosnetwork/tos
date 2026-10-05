#!/usr/bin/env python3
"""C09: an X02 Config34 bundle is accepted only through the compiled anchored verifier.

Production path: scripts/x02_config34_proof.py drives tos-proof-verify on retained real
lite-server answers from a local PQ network (zerostate anchor, a chain through four key
blocks, the target's Config34 proof), and the X02 coordinator's process check runs that
script as a separate process. A bundle that is internally consistent -- block id, state
proof, configuration proof and parameter BOC all agree -- is still refused unless its
block is authenticated from the caller's anchor.

Needs the built verifier: TOS_PROOF_VERIFY, or build/lite-client/proof-verify/tos-proof-verify.
Its absence fails these tests; it never skips them.
"""

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

import x02_config34_proof as proof
from pytosiq_core.boc.cell import Cell

REPO = Path(__file__).resolve().parents[2]
REAL = REPO / "test/pq-native/data/proof-verify-real"
GENESIS = REPO / "test/pq-native/data/c04-pq-genesis.boc"
FIXTURES = REPO / "test/pq-native/x02-config34-fixtures"
VERIFIER = Path(
    os.environ.get("TOS_PROOF_VERIFY", REPO / "build/lite-client/proof-verify/tos-proof-verify")
).resolve()
OLD_SOURCE = "07cccbb0d"


def verifier() -> Path:
    if not (VERIFIER.is_file() and os.access(VERIFIER, os.X_OK)):
        raise AssertionError(f"tos-proof-verify is not built at {VERIFIER}; build it, do not skip")
    return VERIFIER


def anchor_of(zerostate: Path) -> dict:
    result = subprocess.run(
        [str(verifier()), "anchor", "--zerostate", str(zerostate)],
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def real_anchor() -> dict:
    return json.loads((REAL / "anchor.json").read_text())


def real_target() -> dict:
    target = json.loads((REAL / "historical-request.json").read_text())["target"]
    return {
        **target,
        "root_hash": target["root_hash"].lower(),
        "file_hash": target["file_hash"].lower(),
    }


def proven_config34() -> bytes:
    """Config34 of the real target as the verifier proves it (the retained parameter)."""
    request = {"mode": "historical", "target": real_target(), "config_params": [34]}
    with tempfile.TemporaryDirectory() as work:
        path = Path(work) / "request.json"
        path.write_text(json.dumps(request))
        material = Path(work) / "material"
        material.mkdir()
        for name in ("chain-0000.tl", "config.tl"):
            shutil.copyfile(REAL / "historical" / name, material / name)
        result = subprocess.run(
            [
                str(verifier()),
                "verify",
                "--anchor",
                str(REAL / "anchor.json"),
                "--request",
                str(path),
                "--material",
                str(material),
            ],
            capture_output=True,
        )
    output = json.loads(result.stdout)
    assert result.returncode == 0 and output["status"] == "verified", output
    return base64.b64decode(output["config_params"][0]["boc"])


PARAM = None
DECODED = None


def setUpModule():
    global PARAM, DECODED
    PARAM = proven_config34()
    DECODED = proof.decode_validator_set(Cell.one_from_boc(PARAM))


def frozen_rows():
    return [
        {f: row[f] for f in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")}
        for row in DECODED["validators"]
    ]


def election():
    return DECODED["utime_since"]


def write_bundle(
    base: Path, chain=None, config=None, param=None, target=None, election_id=None
) -> dict:
    """A bundle laid out exactly as Stage A retains it."""
    paths = proof.bundle_paths(election() if election_id is None else election_id)
    material_dir = base / paths["material"]
    material_dir.mkdir(parents=True)
    files = {
        "chain-0000.tl": (REAL / "historical/chain-0000.tl").read_bytes()
        if chain is None
        else chain,
        "config.tl": (REAL / "historical/config.tl").read_bytes() if config is None else config,
    }
    bundle = {"block_id": target or real_target(), "material": {}}
    for name, raw in files.items():
        (material_dir / name).write_bytes(raw)
        bundle["material"][name] = {
            "path": paths["material"] + name,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    raw = PARAM if param is None else param
    (base / paths["param"]).write_bytes(raw)
    bundle["param"] = {"path": paths["param"], "sha256": hashlib.sha256(raw).hexdigest()}
    return bundle


def tl_bytes(data: bytes, offset: int) -> tuple[bytes, int]:
    if data[offset] < 254:
        length, start = data[offset], offset + 1
    else:
        length, start = int.from_bytes(data[offset + 1 : offset + 4], "little"), offset + 4
    end = start + length
    return data[start:end], end + (-(end - offset) % 4)


def split_config_info(raw: bytes) -> tuple[bytes, bytes]:
    """liteServer.configInfo: constructor, mode, blockIdExt (80 bytes), state_proof, config_proof."""
    offset = 4 + 4 + 80
    state_proof, offset = tl_bytes(raw, offset)
    config_proof, _ = tl_bytes(raw, offset)
    return state_proof, config_proof


class Base(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(os.path.realpath(self.directory.name))

    def tearDown(self):
        self.directory.cleanup()

    def verify(self, bundle, anchor=None, rows=None, election_id=None, verifier_path=None):
        return proof.verify_bundle(
            bundle,
            self.base,
            frozen_rows() if rows is None else rows,
            election() if election_id is None else election_id,
            real_anchor() if anchor is None else anchor,
            verifier() if verifier_path is None else verifier_path,
        )


class AuthenticatedConfig34(Base):
    def test_a_bundle_authenticated_from_the_zerostate_is_accepted(self):
        verdict = self.verify(write_bundle(self.base))
        self.assertEqual(verdict["verdict"], proof.VERDICT)
        self.assertEqual(verdict["block_id"], real_target())
        self.assertEqual(verdict["anchor"]["root_hash"], real_anchor()["root_hash"].lower())
        self.assertEqual(
            (verdict["chain_links"], verdict["chain_key_blocks"]), (5, [1334, 1485, 5091, 5243])
        )
        self.assertEqual(verdict["config34_cell_hash"], DECODED["cell_hash"])
        self.assertEqual(len(verdict["validators"]), 4)


class FabricatedBundles(Base):
    """Self-consistent bundles whose block is not authenticated from the configured anchor."""

    def test_another_networks_anchor_does_not_authenticate_a_consistent_bundle(self):
        foreign = anchor_of(GENESIS)
        self.assertNotEqual(foreign["root_hash"], real_anchor()["root_hash"].lower())
        with self.assertRaisesRegex(
            proof.ProofRefused, "does not start at the authenticated block"
        ):
            self.verify(write_bundle(self.base), anchor=foreign)

    def test_a_chain_that_does_not_start_at_the_zerostate_is_refused(self):
        # A genuine chain of this network, but from an intermediate key block: nothing
        # links it to the zerostate the caller configured.
        bundle = write_bundle(self.base, chain=(REAL / "live/chain-0000.tl").read_bytes())
        with self.assertRaisesRegex(
            proof.ProofRefused, "does not start at the authenticated block"
        ):
            self.verify(bundle)

    def test_the_old_verifier_accepted_this_unauthenticated_bundle_and_this_one_refuses_it(self):
        # Old green: the pre-fix script accepted state proof + config proof + parameter
        # bound only by four agreeing headers, with no chain from the zerostate at all.
        raw = subprocess.check_output(
            ["git", "-C", str(REPO), "show", f"{OLD_SOURCE}:scripts/x02_config34_proof.py"]
        )
        old = types.ModuleType("x02_config34_proof_old")
        exec(compile(raw, "x02_config34_proof_old.py", "exec"), old.__dict__)
        state_proof, config_proof = split_config_info((REAL / "historical/config.tl").read_bytes())
        target = dict(real_target(), shard=str(-(1 << 63)))
        paths = old.bundle_paths(election())
        (self.base / paths["param"]).parent.mkdir(parents=True)
        rpcs = [f"127.0.0.1:{34600 + index}" for index in range(4)]
        bundle = {"block_id": target, "source_rpc": rpcs[0], "headers": []}
        for name, data in (
            ("state_proof", state_proof),
            ("config_proof", config_proof),
            ("param", PARAM),
        ):
            (self.base / paths[name]).write_bytes(data)
            bundle[name] = {"path": paths[name], "sha256": hashlib.sha256(data).hexdigest()}
        for index, rpc in enumerate(rpcs):
            full = {
                "workchain": -1,
                "shard": str(-(1 << 63)),
                "seqno": target["seqno"],
                "root_hash": base64.b64encode(bytes.fromhex(target["root_hash"])).decode(),
                "file_hash": base64.b64encode(bytes.fromhex(target["file_hash"])).decode(),
            }
            header = json.dumps({"result": {"id": full}}).encode()
            (self.base / paths["headers"][index]).write_bytes(header)
            bundle["headers"].append(
                {
                    "rpc": rpc,
                    "path": paths["headers"][index],
                    "sha256": hashlib.sha256(header).hexdigest(),
                }
            )
        accepted = old.verify_bundle(bundle, self.base, frozen_rows(), election(), rpcs)
        self.assertEqual(accepted["verdict"], proof.VERDICT)
        with self.assertRaisesRegex(proof.ProofRefused, "bundle is incomplete"):
            self.verify(bundle)

    def test_a_target_the_chain_does_not_reach_is_refused(self):
        target = dict(real_target(), root_hash="00" * 31 + "01")
        with self.assertRaisesRegex(proof.ProofRefused, "does not end at the exact target block"):
            self.verify(write_bundle(self.base, target=target))

    def test_a_configuration_proof_of_another_block_is_refused(self):
        bundle = write_bundle(self.base, config=(REAL / "other-block-config.tl").read_bytes())
        with self.assertRaisesRegex(proof.ProofRefused, "answers for another block"):
            self.verify(bundle)

    def test_a_forged_chain_signature_is_refused(self):
        chain = bytearray((REAL / "historical/chain-0000.tl").read_bytes())
        chain[len(chain) // 2] ^= 1
        with self.assertRaisesRegex(proof.ProofRefused, "anchored verifier refused"):
            self.verify(write_bundle(self.base, chain=bytes(chain)))


class ConsistencyAfterAuthentication(Base):
    def test_the_retained_parameter_must_be_the_proven_cell(self):
        other = sorted(FIXTURES.glob("config34-since-*.boc"))[0].read_bytes()
        with self.assertRaisesRegex(proof.ProofRefused, "differs from the proven parameter cell"):
            self.verify(write_bundle(self.base, param=other))

    def test_frozen_rows_and_election_still_bind(self):
        rows = frozen_rows()
        rows[1] = dict(rows[1], adnl_id_hex="00" * 32)
        with self.assertRaisesRegex(proof.ProofRefused, "differ from the frozen rows"):
            self.verify(write_bundle(self.base), rows=rows)
        with self.assertRaisesRegex(proof.ProofRefused, "another election"):
            self.verify(
                write_bundle(self.base, election_id=election() + 1), election_id=election() + 1
            )


class VerifierBoundary(Base):
    """Helper failure, malformed output or a result for something else never passes."""

    def fake(self, body: str) -> Path:
        path = self.base / "fake-verifier"
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_a_failing_helper_is_a_refusal(self):
        with self.assertRaisesRegex(proof.ProofRefused, "not one JSON object"):
            self.verify(write_bundle(self.base), verifier_path=self.fake("exit 3"))

    def test_malformed_output_is_a_refusal(self):
        fake = self.fake('echo \'{"status":"verified",\'; exit 0')
        with self.assertRaisesRegex(proof.ProofRefused, "not one JSON object"):
            self.verify(write_bundle(self.base), verifier_path=fake)

    def test_a_verified_result_for_another_request_is_a_refusal(self):
        fake = self.fake(
            "echo '"
            + json.dumps(
                {
                    "status": "verified",
                    "interface": proof.VERIFIER_INTERFACE,
                    "mode": "historical",
                    "anchor": real_anchor(),
                    "target": real_target(),
                    "request_sha256": "00" * 32,
                    "config_params": [{"index": 34, "cell_hash": DECODED["cell_hash"], "boc": ""}],
                }
            )
            + "'"
        )
        with self.assertRaisesRegex(
            proof.ProofRefused, "not bound to this anchor, target and request"
        ):
            self.verify(write_bundle(self.base), verifier_path=fake)

    def test_a_refusal_with_exit_zero_is_still_a_refusal(self):
        fake = self.fake('echo \'{"status":"refused","reason":"x"}\'')
        with self.assertRaisesRegex(proof.ProofRefused, "anchored verifier refused"):
            self.verify(write_bundle(self.base), verifier_path=fake)

    def test_omitted_material_never_reaches_a_verdict(self):
        bundle = write_bundle(self.base)
        del bundle["material"]["config.tl"]
        with self.assertRaisesRegex(proof.ProofRefused, "contiguous chain plus one configuration"):
            self.verify(bundle)


class CoordinatorProcessCheck(Base):
    """The X02 coordinator's own separate-process check, with a direct launcher."""

    def coordinator(self):
        module = types.ModuleType("x02_four_node_c09")
        module.__file__ = str(REPO / "scripts/x02_four_node.py")
        exec(
            compile((REPO / "scripts/x02_four_node.py").read_bytes(), module.__file__, "exec"),
            module.__dict__,
        )
        return module

    def run_check(self, bundle, anchor):
        four_node = self.coordinator()
        head = subprocess.check_output(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
        ).strip()
        output = self.base / "out"
        output.mkdir(exist_ok=True)
        build_root = self.base / "build"
        installed = build_root / proof.VERIFIER_RELATIVE
        installed.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(verifier(), installed)
        installed.chmod(0o755)
        binding = {
            "interpreter": sys.executable,
            "dependency_roots": [],
            "build_root": str(build_root),
            "files": {
                str(installed): {
                    "sha256": hashlib.sha256(installed.read_bytes()).hexdigest(),
                    "bytes": installed.stat().st_size,
                }
            },
        }
        check = four_node.config34_proof_check(
            binding,
            {"source_sha": head},
            output,
            anchor,
            launcher=lambda binding, out, command, binds: command,
        )
        allocation_entry = {"election_id": election(), "config34_proof": bundle}
        return check(allocation_entry, self.base, frozen_rows())

    def test_the_coordinator_accepts_an_authenticated_bundle(self):
        artifacts = self.base / "artifacts"
        bundle = write_bundle(artifacts)
        verdict = self.run_check(bundle, real_anchor())
        self.assertEqual((verdict["verdict"], verdict["election_id"]), (proof.VERDICT, election()))

    def test_the_coordinator_refuses_a_bundle_not_authenticated_from_its_anchor(self):
        artifacts = self.base / "artifacts"
        bundle = write_bundle(artifacts)
        with self.assertRaisesRegex(
            ValueError, "verifier refused.*does not start at the authenticated block"
        ):
            self.run_check(bundle, anchor_of(GENESIS))


if __name__ == "__main__":
    unittest.main()
