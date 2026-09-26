"""Genuine Ed25519 byte/phase controls with explicitly synthetic test custody."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import z01_development_signature as signature


class ExactDevelopmentSignature(unittest.TestCase):
    def prepare(self, directory):
        seed = bytes([99]) * 32  # synthetic test seed, never production custody
        seed_path = directory / 'test.seed'
        seed_path.write_bytes(seed)
        seed_path.chmod(0o600)
        signer = SigningKey(seed)
        public_path = directory / 'anchor.public'
        public_path.write_bytes(signer.verify_key.encode())
        payload = {'schema': signature.COMMITMENT_SCHEMA, 'phase': 'custody-commitments',
                   'scope': 'development-final-candidate', 'owner_mainnet_release_identity': False,
                   'private_manifest_sha256': '11' * 32}
        raw = (json.dumps(payload, indent=2) + '\n').encode()
        input_path = directory / 'commitments.json'
        input_path.write_bytes(raw)
        signature_path = directory / 'signature.raw'
        signature_path.write_bytes(signer.sign(signature.DOMAIN + raw).signature)
        anchor = {'schema': 'tos.z01.r2-development-anchor.v1', 'scope': 'development-final-candidate',
                  'owner_mainnet_release_identity': False, 'algorithm': 'Ed25519',
                  'public_key_file': str(public_path), 'public_key_hex': signer.verify_key.encode().hex(),
                  'public_key_sha256': hashlib.sha256(public_path.read_bytes()).hexdigest(),
                  'private_seed_commitment': hashlib.sha256(seed).hexdigest(),
                  'payload_path': str(input_path), 'payload_sha256': hashlib.sha256(raw).hexdigest(),
                  'signature_path': str(signature_path),
                  'signature_sha256': hashlib.sha256(signature_path.read_bytes()).hexdigest()}
        anchor_path = directory / 'anchor.json'
        anchor_path.write_text(json.dumps(anchor))
        return anchor_path, hashlib.sha256(anchor_path.read_bytes()).hexdigest(), seed_path

    def test_exact_raw_signature_and_pre_frozen_anchor_positive(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, seed = self.prepare(Path(temp))
            anchor, key = signature.anchor(path, digest)
            result = signature.verify_commitments(anchor, key, '11' * 32)
            self.assertEqual(result['phase'], 'custody-commitments')
            raw = json.dumps({'schema': signature.DESCRIPTOR_SCHEMA, 'phase': 'public-pq-descriptors',
                              'scope': 'development-fixed', 'candidate_scope': 'development-final-candidate',
                              'owner_mainnet_release_identity': False}).encode()
            detached = signature.sign_public(raw, anchor, key, seed)
            self.assertEqual(len(detached), 64)
            key.verify(signature.DOMAIN + raw, detached)

    def test_signed_parameter_type_confusion_refused(self):
        import copy
        public = {'wallet_commitment': '11' * 32, 'validators': []}
        payload = {'profile': 'z01-validator-economics-v1', 'original_vset_valid_for': 131072,
                   **copy.deepcopy(signature.EXPECTED_PARAMETERS)}
        payload['param30']['use_quic'] = 1
        with self.assertRaisesRegex(ValueError, 'actual generator profile'):
            signature.verify_profile(payload, {'private_seed_commitment': '22' * 32}, public)

    def test_development_signer_cannot_reuse_wallet_custody(self):
        payload = {'profile': 'z01-validator-economics-v1', 'original_vset_valid_for': 131072,
                   **signature.EXPECTED_PARAMETERS}
        with self.assertRaisesRegex(ValueError, 'separate from wallet'):
            signature.verify_profile(payload, {'private_seed_commitment': '11' * 32},
                                     {'wallet_commitment': '11' * 32, 'validators': []})

    def test_different_external_anchor_digest_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path, _, _ = self.prepare(Path(temp))
            with self.assertRaisesRegex(ValueError, 'differs from external freeze'):
                signature.anchor(path, '00' * 32)

    def test_reserialized_payload_does_not_verify_old_signature(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, _ = self.prepare(Path(temp))
            anchor, key = signature.anchor(path, digest)
            payload_path = Path(anchor['payload_path'])
            raw = json.dumps(json.loads(payload_path.read_bytes()), separators=(',', ':')).encode()
            payload_path.write_bytes(raw)
            anchor['payload_sha256'] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(BadSignatureError):
                signature.verify_commitments(anchor, key, '11' * 32)

    def test_signed_commitment_phase_cannot_be_descriptor_phase(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, seed = self.prepare(Path(temp))
            anchor, key = signature.anchor(path, digest)
            raw = Path(anchor['payload_path']).read_bytes()
            with self.assertRaisesRegex(ValueError, 'descriptor payload has wrong schema/phase'):
                signature.sign_public(raw, anchor, key, seed)

    def test_consumed_private_manifest_digest_is_signed(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, _ = self.prepare(Path(temp))
            anchor, key = signature.anchor(path, digest)
            with self.assertRaisesRegex(ValueError, 'do not bind consumed private manifest'):
                signature.verify_commitments(anchor, key, '22' * 32)


if __name__ == '__main__':
    unittest.main()
