#!/usr/bin/env python3
"""ML-DSA-44 controllers and cell encoders for the local-network Native Registry scripts.

TEST ONLY. The Gate C rehearsal and the deploy/fixture scripts that import it register
Agents with controllers derived from tosctl's test-only identity fixture. Each identity's
32-byte seed is turned into an ML-DSA-44 key-generation seed under a domain of its own,
so the registry key never reuses the identity's Ed25519 key material, and signatures are
made by `test-pq-contracts-sign` (test/pq-contracts), named by `PQ_TEST_SIGNER`, with the
FIPS 204 deterministic variant. Production signing is `tosctl agent native-registry`
with controllers held in the vault.

Layouts (crypto/smartcont/native-registry-code.fc):
  policy     = magic:uint32 schema:uint16 threshold:uint32 recovery_threshold:uint32
               timelock:uint64 count:uint8 ^controller
  controller = key_id:uint256 weight:uint32 purposes:uint16 recovery:Bool ^stored_key [^next]
  signatures = count:uint8 [^entry];  entry = key_id:uint256 ^stored_signature [^next]
  stored     = len:uint32 ^chain (127-byte cells, a non-empty last cell)
"""

from __future__ import annotations

import functools
import hashlib
import os
import subprocess
from pathlib import Path

from pytosiq_core import Builder, Cell

SIGNATURE_CONTEXT = b"TOS-NATIVE-REGISTRY"
KEY_ID_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
LOCAL_CONTROLLER_DOMAIN = b"TOS-NATIVE-REGISTRY-LOCAL-TEST-CONTROLLER-v1"
PUBLIC_KEY_BYTES = 1312
SIGNATURE_BYTES = 2420
SEED_BYTES = 32
CHUNK_BYTES = 127
MAGIC_POLICY = 0x4E565031
POLICY_SCHEMA = 1
ALL_PURPOSES = 0x0F
PURPOSE_RECOVERY = 0x04
MAX_CONTROLLERS = 8


def byte_chain(data: bytes) -> Cell:
    """The canonical chain of `data`: full 127-byte cells, each linking the next."""
    if not data:
        raise ValueError("stored material must not be empty")
    tail = None
    for start in reversed(range(0, len(data), CHUNK_BYTES)):
        builder = Builder().store_bytes(data[start : start + CHUNK_BYTES])
        if tail is not None:
            builder = builder.store_ref(tail)
        tail = builder.end_cell()
    return tail


def stored(data: bytes) -> Cell:
    """`len:uint32 ^chain`, the wrapper a stored key or signature travels in."""
    return Builder().store_uint(len(data), 32).store_ref(byte_chain(data)).end_cell()


def key_id(public_key: bytes) -> bytes:
    """SHA-256 over the key-id domain, the suite number 1 as the bytes 01 00, and the key."""
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError(
            f"an ML-DSA-44 public key is {PUBLIC_KEY_BYTES} bytes, not {len(public_key)}"
        )
    return hashlib.sha256(KEY_ID_DOMAIN + bytes([1, 0]) + public_key).digest()


def signer_path() -> Path:
    value = os.environ.get("PQ_TEST_SIGNER")
    if not value:
        raise RuntimeError(
            "PQ_TEST_SIGNER must name the test-only ML-DSA-44 signer built from test/pq-contracts"
        )
    path = Path(value)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"PQ_TEST_SIGNER is not an executable file: {path}")
    return path


def _sign_with_seed(seed: bytes, message: bytes, context: bytes) -> tuple[bytes, bytes]:
    line = f"seed:{seed.hex()} {message.hex() or '-'} {context.hex() or '-'}\n"
    result = subprocess.run(
        [str(signer_path())], input=line, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"the test-only ML-DSA-44 signer refused: {result.stderr.strip()}")
    fields = result.stdout.split()
    if len(fields) != 2:
        raise RuntimeError("the test-only ML-DSA-44 signer returned a malformed line")
    public_key, signature = bytes.fromhex(fields[0]), bytes.fromhex(fields[1])
    if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        raise RuntimeError("the test-only ML-DSA-44 signer returned wrong lengths")
    return public_key, signature


class Controller:
    """A test-only ML-DSA-44 registry controller, held as its key-generation seed."""

    def __init__(self, seed: bytes):
        if len(seed) != SEED_BYTES or not any(seed):
            raise ValueError("a controller seed is 32 bytes and not all zero")
        self._seed = bytes(seed)
        self.public_key, _ = _sign_with_seed(self._seed, b"", b"")
        self.key_id = key_id(self.public_key)

    def signature(self, message: bytes, context: bytes = SIGNATURE_CONTEXT) -> bytes:
        public_key, signature = _sign_with_seed(self._seed, message, context)
        if public_key != self.public_key:
            raise RuntimeError("the signer used a different key")
        return signature

    def sign(self, action: Cell) -> bytes:
        """Pure ML-DSA-44 over the 32 bytes of the action hash under the registry context."""
        return self.signature(action.hash)

    def __repr__(self) -> str:
        return f"Controller(key_id={self.key_id.hex()})"


@functools.lru_cache(maxsize=None)
def _controller_for_seed(identity_seed: bytes) -> Controller:
    return Controller(hashlib.sha256(LOCAL_CONTROLLER_DOMAIN + identity_seed).digest())


def controller_for(identity) -> Controller:
    """The registry controller of a tosctl test identity (a PyNaCl signing key or its seed)."""
    if isinstance(identity, Controller):
        return identity
    seed = bytes(identity)
    if len(seed) != SEED_BYTES:
        raise ValueError("a test identity seed is 32 bytes")
    return _controller_for_seed(seed)


def policy(
    controllers: list[tuple[Controller, int, int]],
    threshold: int,
    recovery_threshold: int,
    timelock: int,
) -> Cell:
    """A policy over `(controller, weight, purposes)` entries, ordered by key id."""
    if not 1 <= len(controllers) <= MAX_CONTROLLERS:
        raise ValueError(f"a policy has 1..={MAX_CONTROLLERS} controllers")
    entries = sorted(controllers, key=lambda entry: entry[0].key_id)
    if len({entry[0].key_id for entry in entries}) != len(entries):
        raise ValueError("duplicate policy controller")
    tail = None
    for controller, weight, purposes in reversed(entries):
        builder = (
            Builder()
            .store_bytes(controller.key_id)
            .store_uint(weight, 32)
            .store_uint(purposes, 16)
            .store_bit(1 if purposes & PURPOSE_RECOVERY else 0)
            .store_ref(stored(controller.public_key))
        )
        if tail is not None:
            builder = builder.store_ref(tail)
        tail = builder.end_cell()
    return (
        Builder()
        .store_uint(MAGIC_POLICY, 32)
        .store_uint(POLICY_SCHEMA, 16)
        .store_uint(threshold, 32)
        .store_uint(recovery_threshold, 32)
        .store_uint(timelock, 64)
        .store_uint(len(entries), 8)
        .store_ref(tail)
        .end_cell()
    )


def single_controller_policy(controller: Controller, timelock: int = 10) -> Cell:
    """One controller with every purpose and the recovery designation, thresholds 1."""
    return policy([(controller, 1, ALL_PURPOSES)], 1, 1, timelock)


def signature_set(signatures: list[tuple[Controller, bytes]]) -> Cell:
    """A signature set from `(controller, signature)` pairs, ordered by key id."""
    if len(signatures) > MAX_CONTROLLERS:
        raise ValueError(f"a signature set has at most {MAX_CONTROLLERS} entries")
    entries = sorted(signatures, key=lambda entry: entry[0].key_id)
    if len({entry[0].key_id for entry in entries}) != len(entries):
        raise ValueError("duplicate signer")
    tail = None
    for controller, signature in reversed(entries):
        if len(signature) != SIGNATURE_BYTES:
            raise ValueError(f"an ML-DSA-44 signature is {SIGNATURE_BYTES} bytes")
        builder = Builder().store_bytes(controller.key_id).store_ref(stored(signature))
        if tail is not None:
            builder = builder.store_ref(tail)
        tail = builder.end_cell()
    root = Builder().store_uint(len(entries), 8)
    if tail is not None:
        root = root.store_ref(tail)
    return root.end_cell()


def signed_by(controllers: list[Controller], action: Cell) -> Cell:
    """The signature set of `controllers` over `action`."""
    return signature_set([(controller, controller.sign(action)) for controller in controllers])
