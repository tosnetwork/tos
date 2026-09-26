"""Real signature boundary tests; all keys here are public test recipes."""
import hashlib
import copy
import importlib.util
from pathlib import Path
import unittest

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

source = Path(__file__).resolve().parents[2] / 'scripts/z02_pq_regenerate.py'
spec = importlib.util.spec_from_file_location('z02_signature_candidate', source)
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)

DOMAIN = b'TOS-R2-DEVELOPMENT-INPUTS-V1\x00'


class DevelopmentSignatureTests(unittest.TestCase):
    def setUp(self):
        # Public deterministic recipes are fixtures, never private custody.
        self.key = SigningKey(bytes(range(32)))
        self.anchor = self.key.verify_key.encode()
        self.anchor_sha = hashlib.sha256(self.anchor).hexdigest()
        self.raw = b'{"scope":"development-fixed", "epoch":1790395200}\n'
        self.signature = self.key.sign(DOMAIN + self.raw).signature

    def check(self, raw=None, anchor=None, signature=None, expected=None):
        return candidate.authenticate_input(
            self.raw if raw is None else raw,
            self.anchor if anchor is None else anchor,
            self.signature if signature is None else signature,
            self.anchor_sha if expected is None else expected)

    def test_exact_original_bytes_and_external_anchor_pass(self):
        self.assertEqual(self.check(), DOMAIN + self.raw)

    def test_input_one_byte_mutation_is_rejected(self):
        changed = self.raw.replace(b'1790395200', b'1790395201')
        with self.assertRaises(BadSignatureError):
            self.check(raw=changed)

    def test_signature_one_byte_mutation_is_rejected(self):
        changed = bytes([self.signature[0] ^ 1]) + self.signature[1:]
        with self.assertRaises(BadSignatureError):
            self.check(signature=changed)

    def test_replacement_anchor_is_rejected_before_verify(self):
        other = SigningKey(bytes(range(1, 33))).verify_key.encode()
        with self.assertRaisesRegex(ValueError, 'trust anchor mismatch'):
            self.check(anchor=other)

    def test_fresh_signature_cannot_replace_prefrozen_anchor(self):
        other = SigningKey(bytes(range(1, 33)))
        with self.assertRaisesRegex(ValueError, 'trust anchor mismatch'):
            self.check(anchor=other.verify_key.encode(), signature=other.sign(DOMAIN + self.raw).signature)

    def test_wrong_domain_signature_is_rejected(self):
        signature = self.key.sign(b'TOS-R2-DEV-INPUTS-v1\x00' + self.raw).signature
        with self.assertRaises(BadSignatureError):
            self.check(signature=signature)

    def test_reserialized_equivalent_json_is_rejected(self):
        changed = b'{"epoch":1790395200,"scope":"development-fixed"}'
        with self.assertRaises(BadSignatureError):
            self.check(raw=changed)

    def test_missing_signature_is_rejected_as_length_error(self):
        with self.assertRaisesRegex(ValueError, 'raw64bytes'):
            self.check(signature=b'')

    def test_nonraw_anchor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'trust anchor mismatch'):
            self.check(anchor=self.anchor.hex().encode())


class PublicSchemaTests(unittest.TestCase):
    def setUp(self):
        self.source = 'a' * 40
        self.manifest = {'schema': 'tos.z02.pq-regeneration-input.v1', 'scope': 'development-fixed',
                         'phase': 'public-pq-descriptors', 'candidate_scope': 'development-final-candidate',
                         'owner_mainnet_release_identity': False, 'final_signed_genesis': False,
                         'source_commit': self.source, 'genesis_time': 1790395200,
                         'profile': 'z01-validator-economics-v1', 'wallet_seed': {'sha256': 'b' * 64},
                         'original_vset_valid_for': 131072, 'trust_anchor_sha256': 'c' * 64,
                         'input_commitments_sha256': 'd' * 64,
                         'expected_parameters': {'param16': [21, 21, 4], 'param28': [250, 250, 1000, 21, True],
                                                 'param30': {'tag': '22', 'flags': 0, 'protocol_version': 2,
                                                             'use_quic': True, 'slots_per_leader_window': 4,
                                                             'noncritical_params': {'0': 400, '1': 1000, '10': 250}}},
                         'validators': []}

    def test_public_contract_fields_pass_schema_boundary(self):
        candidate.validate_public_input(self.manifest, self.source)

    def test_signed_commitment_schema_is_not_descriptor_schema(self):
        changed = copy.deepcopy(self.manifest)
        changed['schema'] = 'tos.z01.input-commitments.v1'
        with self.assertRaisesRegex(ValueError, 'unsupported input schema'):
            candidate.validate_public_input(changed, self.source)

    def test_nested_private_manifest_path_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed['custody_public_receipt'] = {'manifest_path': '/private/custody'}
        with self.assertRaisesRegex(ValueError, 'nested custody'):
            candidate.validate_public_input(changed, self.source)

    def test_unknown_unsigned_semantic_fields_are_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed['ignored_generator_override'] = 1
        with self.assertRaisesRegex(ValueError, 'unexpected public input fields'):
            candidate.validate_public_input(changed, self.source)

    def test_wrong_epoch_does_not_pass_frozen_contract(self):
        changed = copy.deepcopy(self.manifest)
        changed['genesis_time'] = 1789434000
        with self.assertRaisesRegex(ValueError, 'epoch1790395200'):
            candidate.validate_public_input(changed, self.source)

    def test_final_release_authority_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed['final_signed_genesis'] = True
        with self.assertRaisesRegex(ValueError, 'phase/authority'):
            candidate.validate_public_input(changed, self.source)

    def test_phase1_cannot_be_used_as_phase2(self):
        changed = copy.deepcopy(self.manifest)
        changed['phase'] = 'custody-commitments'
        with self.assertRaisesRegex(ValueError, 'phase/authority'):
            candidate.validate_public_input(changed, self.source)

    def test_signed_parameter_change_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed['expected_parameters']['param30']['use_quic'] = 1
        with self.assertRaisesRegex(ValueError, 'expected parameters'):
            candidate.validate_public_input(changed, self.source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
