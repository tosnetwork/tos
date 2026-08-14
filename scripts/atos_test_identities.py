#!/usr/bin/env python3
"""Load and authenticate test-only identities emitted by tosctl."""

import json
from pathlib import Path

import nacl.exceptions
import nacl.signing


def load_test_identity(path: Path, role: str) -> nacl.signing.SigningKey:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "atos-test-identities-v1" or document.get("test_only") is not True:
        raise RuntimeError(f"invalid tosctl test identity fixture: {path}")
    matches = [entry for entry in document.get("identities", []) if entry.get("role") == role]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one '{role}' identity in {path}")
    entry = matches[0]
    try:
        seed = bytes.fromhex(entry["private_seed_hex"])
        public_key = bytes.fromhex(entry["public_key_hex"])
        proof_message = bytes.fromhex(entry["proof_message_hex"])
        proof_signature = bytes.fromhex(entry["proof_signature_hex"])
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"malformed '{role}' identity in {path}") from error
    if len(seed) != 32 or len(public_key) != 32 or len(proof_signature) != 64:
        raise RuntimeError(f"invalid Ed25519 field length for '{role}' in {path}")
    expected_message = f"ATOS_TEST_IDENTITY_V1:{role}".encode()
    if proof_message != expected_message:
        raise RuntimeError(f"identity proof domain mismatch for '{role}' in {path}")
    key = nacl.signing.SigningKey(seed)
    if bytes(key.verify_key) != public_key:
        raise RuntimeError(f"private/public key mismatch for '{role}' in {path}")
    try:
        key.verify_key.verify(proof_message, proof_signature)
    except nacl.exceptions.BadSignatureError as error:
        raise RuntimeError(f"invalid identity proof for '{role}' in {path}") from error
    return key
