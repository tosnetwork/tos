"""Real ML-DSA-44 candidate tests for the TOS-AUTH request commitment.

SCOPE: OFF-CHAIN cryptography and ordinary-cell serialization ONLY.
This is NOT a TVM verifier and must not be cited as on-chain ML-DSA support.
No synthetic module sender, Ed25519 relay, pre-verified boolean, or disabled
signature check is used to stand in for PQ verification.

Run with Python 3.10+ and OpenSSL 3.5+ (ML-DSA default provider):
    python3 test/auth-extensions/test_ml_dsa_candidate.py
Optional OPENSSL_PATH selects the executable; PQ_FIXTURE_OUTPUT exports a
public-only interoperability fixture. Missing ML-DSA is an ERROR, not a skip.

Algorithm: FIPS 204 Pure ML-DSA-44 over the 32-byte auth_request_hash, with
context TOS-AUTH-ML-DSA-44-v1. This is not HashML-DSA, legacy Dilithium2,
ML-DSA-ETH, or Ethereum consensus leanXMSS. The context is a TEST profile,
not an assigned production algorithm identifier. Fixed seeds are TEST ONLY.

References:
https://csrc.nist.gov/pubs/fips/204/final
https://eips.ethereum.org/EIPS/eip-8051 (draft, not an adopted Ethereum choice)
https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cells import Cell, from_boc

ALGORITHM = 'ML-DSA-44'
CONTEXT = 'TOS-AUTH-ML-DSA-44-v1'
PUBLIC_KEY_BYTES = 1312
SIGNATURE_BYTES = 2420
# DER SubjectPublicKeyInfo: id-ml-dsa-44, absent parameters, 1312-byte key.
SPKI_PREFIX = bytes.fromhex('30820532300b06096086480165030403110382052100')
AUTH_DOMAIN = 0x544F532D41555448


def snake(data: bytes) -> Cell:
    """Test-only canonical 127-byte-per-cell encoding, not a module wire ABI."""
    if not data:
        return Cell()
    tail = None
    for offset in reversed(range(0, len(data), 127)):
        cell = Cell().raw(data[offset:offset + 127])
        if tail is not None:
            cell.ref(tail)
        tail = cell
    return tail


def unsnake(root: Cell, expected_size: int) -> bytes:
    result = bytearray()
    cell = root
    seen = set()
    while True:
        if id(cell) in seen:
            raise ValueError('cyclic byte chain')
        seen.add(id(cell))
        nbits = len(cell.bits)
        if nbits % 8 or len(cell.refs) > 1:
            raise ValueError('non-byte-aligned or branching byte chain')
        size = nbits // 8
        if cell.refs and size != 127:
            raise ValueError('non-canonical non-terminal cell')
        if size > 127 or (size == 0 and (cell.refs or result)):
            raise ValueError('non-canonical byte chain')
        result.extend(int(cell.bits or '0', 2).to_bytes(size, 'big'))
        if len(result) > expected_size:
            raise ValueError('oversized byte chain')
        if not cell.refs:
            break
        cell = cell.refs[0]
    if len(result) != expected_size:
        raise ValueError('incorrect byte chain size')
    return bytes(result)


def request(**changes) -> Cell:
    """Use fresh immutable cells; the harness memoizes cell hashes."""
    fields = dict(global_id=42, account=(0, 0x1234), epoch=1, nonce=0,
                  valid_until=1_780_000_600, kind=0,
                  payload=Cell().uint(0x41475005, 32).sint(42, 32)
                  .uint(0, 64).uint(0, 32).uint(1_780_000_600, 32))
    fields.update(changes)
    return (Cell().sint(fields['global_id'], 32).addr(fields['account'])
            .uint(fields['epoch'], 64).uint(fields['nonce'], 64)
            .uint(fields['valid_until'], 32).uint(fields['kind'], 8)
            .ref(fields['payload']))


def commitment(req: Cell) -> bytes:
    # Exactly auth_request_hash()/authRequestHash() in PR #93.
    return Cell().uint(AUTH_DOMAIN, 64).ref(req).hash


class MlDsaCandidateTests(unittest.TestCase):
    @classmethod
    def run_ssl(cls, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run([cls.openssl, *map(str, args)],
                                capture_output=True, timeout=30)
        if check and result.returncode:
            raise RuntimeError('OpenSSL operation failed: ' +
                               result.stderr.decode(errors='replace'))
        return result

    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which(os.environ.get('OPENSSL_PATH', 'openssl'))
        if cls.openssl is None:
            raise RuntimeError('OpenSSL 3.5+ with ML-DSA is required; not skipping')
        cls.version = cls.run_ssl('version').stdout.decode().strip()
        cls.tmp = tempfile.TemporaryDirectory(prefix='tos-ml-dsa-test-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.directory = Path(cls.tmp.name)
        cls.keys = []
        cls.public_keys = []
        for index, seed_byte in enumerate((0x42, 0x43)):
            key = cls.directory / f'test-only-{index}.pem'
            # Deterministic TEST keys; never export or reuse in production.
            cls.run_ssl('genpkey', '-algorithm', ALGORITHM, '-pkeyopt',
                        'hexseed:' + bytes([seed_byte] * 32).hex(), '-out', key)
            der = cls.run_ssl('pkey', '-in', key, '-pubout', '-outform', 'DER').stdout
            if len(der) != len(SPKI_PREFIX) + PUBLIC_KEY_BYTES or not der.startswith(SPKI_PREFIX):
                raise RuntimeError('unexpected ML-DSA-44 public-key encoding')
            cls.keys.append(key)
            cls.public_keys.append(der[len(SPKI_PREFIX):])
        cls.req = request()
        cls.digest = commitment(cls.req)
        cls.signature = cls.sign(cls.digest)
        if len(cls.signature) != SIGNATURE_BYTES:
            raise RuntimeError('unexpected ML-DSA-44 signature length')
        # A failed provider/setup must never make all negative controls "pass".
        if not cls.verify(cls.digest, cls.signature, cls.public_keys[0]):
            raise RuntimeError('positive ML-DSA verification control failed')

    @classmethod
    def sign(cls, message: bytes) -> bytes:
        msg = cls.directory / 'message.bin'
        sig = cls.directory / 'signature.bin'
        msg.write_bytes(message)
        cls.run_ssl('pkeyutl', '-sign', '-rawin', '-inkey', cls.keys[0],
                    '-in', msg, '-out', sig, '-pkeyopt', 'context-string:' + CONTEXT,
                    '-pkeyopt', 'deterministic:1')
        return sig.read_bytes()

    @classmethod
    def verify(cls, message: bytes, signature: bytes, public_key: bytes,
               context: str = CONTEXT) -> bool:
        # Exact-size parsing is a host-fixture check, not an on-chain guarantee.
        if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
            return False
        msg = cls.directory / 'verify-message.bin'
        sig = cls.directory / 'verify-signature.bin'
        key = cls.directory / 'verify-public.der'
        msg.write_bytes(message)
        sig.write_bytes(signature)
        key.write_bytes(SPKI_PREFIX + public_key)
        result = cls.run_ssl('pkeyutl', '-verify', '-rawin', '-pubin',
                             '-inkey', key, '-keyform', 'DER', '-in', msg,
                             '-sigfile', sig, '-pkeyopt', 'context-string:' + context,
                             check=False)
        # Distinguish genuine verification rejection from provider/CLI errors.
        if result.returncode == 0:
            return True
        if result.returncode == 1 and b'Signature Verification Failure' in result.stdout:
            return False
        raise RuntimeError('verification infrastructure failed: ' +
                           (result.stdout + result.stderr).decode(errors='replace'))

    def test_real_signature_and_deterministic_test_profile(self):
        self.assertTrue(self.verify(self.digest, self.signature, self.public_keys[0]))
        self.assertEqual(self.signature, self.sign(self.digest))
        self.assertEqual(len(self.public_keys[0]), PUBLIC_KEY_BYTES)
        self.assertEqual(len(self.signature), SIGNATURE_BYTES)

    def test_all_auth_request_fields_are_cryptographically_bound(self):
        variants = [('global_id', 43), ('account', (0, 0x1235)),
                    ('account', (-1, 0x1234)), ('epoch', 2), ('nonce', 1),
                    ('valid_until', 1_780_000_601), ('kind', 1),
                    ('payload', Cell().uint(99, 32))]
        for field, value in variants:
            with self.subTest(field=field, value=value):
                self.assertFalse(self.verify(commitment(request(**{field: value})),
                                             self.signature, self.public_keys[0]))

    def test_domain_and_algorithm_context_are_bound(self):
        self.assertFalse(self.verify(self.req.hash, self.signature, self.public_keys[0]))
        self.assertFalse(self.verify(self.digest, self.signature, self.public_keys[0],
                                     context='TOS-AUTH-other-profile'))
        self.assertFalse(self.verify(self.digest, self.signature, self.public_keys[0], context=''))

    def test_wrong_key_and_corrupted_signatures_are_rejected(self):
        self.assertFalse(self.verify(self.digest, self.signature, self.public_keys[1]))
        for offset in (0, SIGNATURE_BYTES // 2, SIGNATURE_BYTES - 1):
            with self.subTest(offset=offset):
                bad = bytearray(self.signature)
                bad[offset] ^= 1
                self.assertFalse(self.verify(self.digest, bytes(bad), self.public_keys[0]))
        self.assertFalse(self.verify(self.digest, bytes(SIGNATURE_BYTES), self.public_keys[0]))

    def test_host_fixture_length_checks_fail_closed(self):
        for sig in (b'', self.signature[:-1], self.signature + b'\0'):
            self.assertFalse(self.verify(self.digest, sig, self.public_keys[0]))
        for key in (b'', self.public_keys[0][:-1], self.public_keys[0] + b'\0'):
            self.assertFalse(self.verify(self.digest, self.signature, key))

    def test_large_public_key_and_signature_survive_boc_roundtrip(self):
        key = snake(self.public_keys[0])
        sig = snake(self.signature)
        # This is a test container, not an AUTH message or a deployed verifier.
        container = Cell().ref(self.req).ref(key).ref(sig)
        decoded = from_boc(container.boc())
        pk = unsnake(decoded.refs[1], PUBLIC_KEY_BYTES)
        proof = unsnake(decoded.refs[2], SIGNATURE_BYTES)
        self.assertEqual(pk, self.public_keys[0])
        self.assertEqual(proof, self.signature)
        self.assertEqual(key.depth + 1, 11)
        self.assertEqual(sig.depth + 1, 20)
        self.assertTrue(self.verify(commitment(decoded.refs[0]), proof, pk))
        for malformed, size in ((Cell().raw(b'x').ref(Cell().raw(b'y')), 2),
                                (Cell().uint(1, 1), 1),
                                (Cell().raw(b'x').ref(Cell()).ref(Cell()), 1),
                                (sig, SIGNATURE_BYTES - 1)):
            with self.assertRaises(ValueError):
                unsnake(malformed, size)

    def test_referenced_payload_tail_is_bound(self):
        payload = snake(bytes(range(256)) * 4)
        req = request(payload=payload)
        sig = self.sign(commitment(req))
        self.assertTrue(self.verify(commitment(req), sig, self.public_keys[0]))
        changed = snake(bytes(range(256)) * 3 + bytes(range(255)) + b'\0')
        self.assertFalse(self.verify(commitment(request(payload=changed)), sig, self.public_keys[0]))


def public_fixture() -> dict:
    cls = MlDsaCandidateTests
    return dict(scope='OFFCHAIN_ONLY_NOT_TVM_SUPPORT', algorithm=ALGORITHM,
                standard='FIPS 204 Pure ML-DSA', context=CONTEXT,
                openssl=cls.version, signing_profile='deterministic TEST ONLY',
                request_boc_base64=cls.req.b64().decode(),
                auth_request_hash_hex=cls.digest.hex(),
                public_key_hex=cls.public_keys[0].hex(), signature_hex=cls.signature.hex(),
                public_key_bytes=PUBLIC_KEY_BYTES, signature_bytes=SIGNATURE_BYTES,
                onchain_verifier_implemented=False, onchain_gas_measured=False)


if __name__ == '__main__':
    result = unittest.main(verbosity=2, exit=False)
    success = result.result.wasSuccessful()
    if success:
        print(MlDsaCandidateTests.version)
        print('ML-DSA-44: 1312-byte public key; 2420-byte signature; real sign/verify passed.')
        print('Scope: OFF-CHAIN request binding and BOC fixtures ONLY; on-chain support NOT PROVEN.')
        if output := os.environ.get('PQ_FIXTURE_OUTPUT'):
            Path(output).write_text(json.dumps(public_fixture(), indent=2) + '\n', encoding='utf-8')
    sys.exit(0 if success else 1)
