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
MAGIC_ACTION = 0x4E564131
MAGIC_IDENTITY = 0x4E564931
OP_SUBMIT = 0x4E560001
OP_AUTHORIZE_CAPABILITY = 0x4E560002
GENESIS_ROOT = bytes([0x11]) * 32
GENESIS_FILE = bytes([0x22]) * 32
NETWORK = "tos-testnet"


def hex_of(tagged: str) -> str:
    return tagged.split(":", 1)[1]


def code_hash() -> bytes:
    return bytes.fromhex(hex_of(VECTORS["contract_code_hash"]))


def identity_domain() -> Cell:
    return (
        Builder()
        .store_bytes(GENESIS_ROOT)
        .store_bytes(GENESIS_FILE)
        .store_bytes(hashlib.sha256(NETWORK.encode()).digest())
        .end_cell()
    )


def signed_domain() -> Cell:
    return (
        Builder()
        .store_bytes(GENESIS_ROOT)
        .store_bytes(GENESIS_FILE)
        .store_bytes(hashlib.sha256(NETWORK.encode()).digest())
        .store_ref(Builder().store_bytes(code_hash()).end_cell())
        .end_cell()
    )


def action(kind: int, target_kind: int, object_id: bytes, nonce: int, payload: Cell) -> Cell:
    return (
        Builder()
        .store_uint(MAGIC_ACTION, 32)
        .store_uint(1, 16)
        .store_uint(kind, 8)
        .store_uint(target_kind, 8)
        .store_uint(1, 64)
        .store_uint(1, 64)
        .store_bytes(object_id)
        .store_bytes(bytes(32))
        .store_bytes(bytes([nonce]) * 32)
        .store_ref(signed_domain())
        .store_ref(payload)
        .end_cell()
    )


def body(opcode: int, action_cell: Cell, authority: Cell) -> Cell:
    return (
        Builder()
        .store_uint(opcode, 32)
        .store_uint(1, 64)
        .store_ref(action_cell)
        .store_ref(authority)
        .store_ref(registry_pq.signature_set([]))
        .end_cell()
    )


def frozen_action(entry: str) -> Cell:
    return Cell.one_from_boc(base64.b64decode(VECTORS[entry]["action_boc_base64"]))


class VectorController(unittest.TestCase):
    """The vector controller is the ML-DSA-44 key of the fixed seed 0102..20."""

    @classmethod
    def setUpClass(cls):
        cls.controller = registry_pq.Controller(bytes(range(1, 33)))
        cls.policy = registry_pq.single_controller_policy(cls.controller, timelock=86_400)
        cls.agent_id = (
            Builder()
            .store_uint(MAGIC_IDENTITY, 32)
            .store_uint(1, 8)
            .store_bytes(bytes([0x6F]) * 32)
            .store_bytes(cls.policy.hash)
            .store_ref(identity_domain())
            .end_cell()
            .hash
        )

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
        built = action(1, 1, self.agent_id, 0x61, payload)
        frozen = frozen_action("agent_registration")
        self.assertEqual(built.hash, frozen.hash)
        self.assertEqual(built.hash.hex(), hex_of(VECTORS["agent_registration"]["action_hash"]))
        signature = self.controller.sign(built)
        self.assertEqual(
            hashlib.sha256(signature).hexdigest(),
            hex_of(VECTORS["agent_registration"]["signature_sha256"]),
        )
        submission = body(OP_SUBMIT, built, registry_pq.signed_by([self.controller], built))
        self.assertEqual(
            submission.hash.hex(),
            hex_of(VECTORS["agent_registration"]["submission_body_hash"]),
        )

    def test_capability_registration_body_is_byte_exact(self):
        frozen = frozen_action("capability_registration")
        self.assertEqual(
            frozen.hash.hex(), hex_of(VECTORS["capability_registration"]["action_hash"])
        )
        submission = body(
            OP_AUTHORIZE_CAPABILITY, frozen, registry_pq.signed_by([self.controller], frozen)
        )
        self.assertEqual(
            submission.hash.hex(),
            hex_of(VECTORS["capability_registration"]["submission_body_hash"]),
        )


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
