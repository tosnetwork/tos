#!/usr/bin/env python3
"""The local-network registry scripts' ML-DSA-44 encoders against the contract's vectors.

The protocol vectors (tosctl/src/node-control/contracts/tests/fixtures/native_registry/
protocol-vectors.json) are produced by executing the release code on the Rust sandbox: the
registrations they describe were accepted by the contract. Reproducing them byte for byte
here shows that the Python key derivation, policy, action, signature-set and submission
encoders, and the test-only signer, build exactly what the contract accepts.

Requires PQ_TEST_SIGNER (the signer built from test/pq-contracts). It fails, rather than
skips, without one: a check that cannot run must not pass.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "test/tostester/src"))

import tos_service_native_registry_pq as registry_pq  # noqa: E402
from pytosiq_core import Builder, Cell  # noqa: E402

VECTORS = json.loads(
    (
        ROOT
        / "tosctl/src/node-control/contracts/tests/fixtures/native_registry/protocol-vectors.json"
    ).read_text()
)
GENESIS_ROOT = bytes([0x11]) * 32
GENESIS_FILE = bytes([0x22]) * 32
NETWORK = "tos-testnet"


def load_gate():
    """Gate C itself, so that its own builders are what is checked."""
    spec = importlib.util.spec_from_file_location(
        "gate_c", ROOT / "scripts/tos-service-native-registry-local-gate-c.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load_gate()


def hex_of(tagged: str) -> str:
    return tagged.split(":", 1)[1]


def frozen_action(entry: str) -> Cell:
    return Cell.one_from_boc(base64.b64decode(VECTORS[entry]["action_boc_base64"]))


def signed_domain() -> Cell:
    code_hash = bytes.fromhex(hex_of(VECTORS["contract_code_hash"]))
    return gate.domain_cell(GENESIS_ROOT, GENESIS_FILE, NETWORK, code_hash)


class VectorController(unittest.TestCase):
    """The vector controller is the ML-DSA-44 key of the fixed seed 0102..20. Every cell
    below is rebuilt with Gate C's own builders and compared with the frozen vector."""

    @classmethod
    def setUpClass(cls):
        cls.controller = registry_pq.Controller(bytes(range(1, 33)))
        cls.policy = registry_pq.single_controller_policy(cls.controller, timelock=86_400)
        cls.agent_id = gate.agent_identity(
            GENESIS_ROOT, GENESIS_FILE, NETWORK, bytes([0x6F]) * 32, cls.policy
        )

    def submission(self, opcode: int, act: Cell) -> Cell:
        authority = registry_pq.signed_by([self.controller], act)
        return gate.body(opcode, 1, act, authority, registry_pq.signature_set([]))

    def test_key_generation_and_key_id_match_the_contract_vectors(self):
        controller = VECTORS["controller"]
        self.assertEqual(controller["key_seed_hex"], bytes(range(1, 33)).hex())
        self.assertEqual(
            hashlib.sha256(self.controller.public_key).hexdigest(),
            hex_of(controller["public_key_sha256"]),
        )
        self.assertEqual(self.controller.key_id.hex(), controller["key_id"])
        self.assertEqual(controller["signature_context"], registry_pq.SIGNATURE_CONTEXT.decode())

    def test_the_policy_reproduces_the_agent_identity(self):
        self.assertEqual("agent_" + self.agent_id.hex(), VECTORS["agent_registration"]["object_id"])

    def test_agent_registration_action_signature_and_body_are_byte_exact(self):
        payload = Builder().store_bytes(bytes([0x6F]) * 32).store_ref(self.policy).end_cell()
        built = gate.action(
            gate.REGISTER_AGENT, 1, 1, 1, self.agent_id, bytes(32), 0x61, signed_domain(), payload
        )
        self.assertEqual(built.hash, frozen_action("agent_registration").hash)
        self.assertEqual(built.hash.hex(), hex_of(VECTORS["agent_registration"]["action_hash"]))
        self.assertEqual(
            hashlib.sha256(self.controller.sign(built)).hexdigest(),
            hex_of(VECTORS["agent_registration"]["signature_sha256"]),
        )
        self.assertEqual(
            self.submission(gate.OP_SUBMIT, built).hash.hex(),
            hex_of(VECTORS["agent_registration"]["submission_body_hash"]),
        )

    def test_capability_registration_identity_action_and_body_are_byte_exact(self):
        nonce, version, manifest = bytes([0x63]) * 32, b"1.0.0", bytes([0x55]) * 32
        capability_id = gate.capability_identity(
            GENESIS_ROOT, GENESIS_FILE, NETWORK, nonce, self.agent_id, version, manifest
        )
        self.assertEqual(
            "cap_" + capability_id.hex(), VECTORS["capability_registration"]["object_id"]
        )
        payload = gate.capability_registration_payload(nonce, self.agent_id, version, manifest)
        built = gate.action(
            gate.REGISTER_CAPABILITY,
            2,
            1,
            1,
            capability_id,
            bytes(32),
            0x62,
            signed_domain(),
            payload,
        )
        self.assertEqual(built.hash, frozen_action("capability_registration").hash)
        self.assertEqual(
            hashlib.sha256(self.controller.sign(built)).hexdigest(),
            hex_of(VECTORS["capability_registration"]["signature_sha256"]),
        )
        self.assertEqual(
            self.submission(gate.OP_AUTHORIZE_CAPABILITY, built).hash.hex(),
            hex_of(VECTORS["capability_registration"]["submission_body_hash"]),
        )

    def test_gate_policy_and_signature_set_use_the_identity_controller(self):
        identity_seed = bytes([0x2A]) * 32
        controller = registry_pq.controller_for(identity_seed)
        self.assertEqual(
            gate.policy(identity_seed).hash, registry_pq.single_controller_policy(controller).hash
        )
        act = frozen_action("agent_registration")
        self.assertEqual(
            gate.signature_set(identity_seed, act).hash,
            registry_pq.signed_by([controller], act).hash,
        )
        self.assertEqual(gate.signature_set(None, act).hash, registry_pq.signature_set([]).hash)


class Encoders(unittest.TestCase):
    def test_stored_material_is_the_canonical_chain(self):
        data = bytes(range(256)) * 5 + bytes(32)  # 1,312 bytes
        cell = registry_pq.stored(data)
        wrapper = cell.begin_parse()
        self.assertEqual(wrapper.load_uint(32), 1312)
        chain, collected, cells = wrapper.load_ref(), b"", 0
        while True:
            part = chain.begin_parse()
            chunk = part.load_bytes(len(part.bits) // 8)
            collected += chunk
            cells += 1
            if part.refs:
                self.assertEqual(len(chunk), registry_pq.CHUNK_BYTES)
                chain = part.load_ref()
            else:
                self.assertTrue(0 < len(chunk) <= registry_pq.CHUNK_BYTES)
                break
        self.assertEqual(collected, data)
        self.assertEqual(cells, 11)

    def test_controllers_and_entries_are_ordered_by_key_id(self):
        a, b = registry_pq.Controller(bytes([3]) * 32), registry_pq.Controller(bytes([4]) * 32)
        low, high = sorted((a, b), key=lambda c: c.key_id)
        cell = registry_pq.policy([(high, 1, 15), (low, 2, 15)], 2, 2, 10)
        first = cell.begin_parse().load_ref().begin_parse()
        self.assertEqual(first.load_bytes(32), low.key_id)
        self.assertEqual(first.load_uint(32), 2)
        signatures = registry_pq.signature_set([(high, bytes(2420)), (low, bytes(2420))])
        entry = signatures.begin_parse()
        self.assertEqual(entry.load_uint(8), 2)
        self.assertEqual(entry.load_ref().begin_parse().load_bytes(32), low.key_id)
        self.assertEqual(registry_pq.signature_set([]).begin_parse().load_uint(8), 0)

    def test_malformed_inputs_are_refused(self):
        controller = registry_pq.Controller(bytes([5]) * 32)
        for seed in (bytes(32), bytes(31), bytes(33)):
            with self.assertRaises(ValueError):
                registry_pq.Controller(seed)
        with self.assertRaises(ValueError):
            registry_pq.key_id(bytes(32))
        with self.assertRaises(ValueError):
            registry_pq.policy([], 1, 1, 10)
        with self.assertRaises(ValueError):
            registry_pq.policy([(controller, 1, 15), (controller, 1, 15)], 1, 1, 10)
        many = [registry_pq.Controller(bytes([0x40 + i]) * 32) for i in range(9)]
        with self.assertRaises(ValueError):
            registry_pq.policy([(c, 1, 15) for c in many], 1, 1, 10)
        with self.assertRaises(ValueError):
            registry_pq.signature_set([(controller, bytes(64))])

    def test_identity_controllers_are_domain_separated_and_stable(self):
        identity_seed = bytes([7]) * 32
        derived = registry_pq.controller_for(identity_seed)
        self.assertIs(registry_pq.controller_for(identity_seed), derived)
        self.assertNotEqual(derived.key_id, registry_pq.Controller(identity_seed).key_id)
        expected = hashlib.sha256(registry_pq.LOCAL_CONTROLLER_DOMAIN + identity_seed).digest()
        self.assertEqual(derived.key_id, registry_pq.Controller(expected).key_id)


if __name__ == "__main__":
    registry_pq.signer_path()
    unittest.main()
