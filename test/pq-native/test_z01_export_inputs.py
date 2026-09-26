"""Fake PQ export boundary controls; no native tool or Genesis is generated."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'test/tostester/src'))
SPEC = importlib.util.spec_from_file_location('public_export', ROOT / 'scripts/z01_export_inputs.py')
export = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export)


class PublicExportBoundary(unittest.TestCase):
    def exercise(self, directory, *, change_manifest=False, import_exit=0, source_mismatch=False):
        wallet = directory / 'wallet.seed'
        wallet.write_bytes(bytes([1]) * 32)
        wallet.chmod(0o600)
        source_manifest = {'wallet_seed': {'path': wallet.name, 'sha256': hashlib.sha256(wallet.read_bytes()).hexdigest()}}
        path = directory / 'custody.json'
        path.write_text(json.dumps(source_manifest))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        public = {'wallet_commitment': source_manifest['wallet_seed']['sha256'],
                  'validators': [{'validator_id': bytes([index + 2]).hex() * 32,
                                  'adnl_seed_commitment': hashlib.sha256(bytes([index + 20]) * 32).hexdigest(),
                                  'pq_seed_commitment': hashlib.sha256(bytes([index + 10]) * 32).hexdigest()}
                                 for index in range(4)]}
        private = {'genesis_time': 1790395200,
                   'validators': [{'validator_id': bytes([index + 2]) * 32,
                                   'pq_seed': bytes([index + 10]) * 32,
                                   'adnl_seed': bytes([index + 20]) * 32} for index in range(4)]}
        build = {'fixed_inputs': public, 'source': {'commit': '44' * 20},
                 'binaries': {'pq_consensus_key': {'path': '/fake/tool', 'sha256': '33' * 32}},
                 'z01_eligible': False, 'os_release': {'id': 'ubuntu', 'version_id': '22.04'},
                 'image_id': 'rehearsal-only'}
        args = argparse.Namespace(precommit=directory / 'precommit.json', precommit_sha256='55' * 32,
                                  build_dir=directory / 'build', custody_input=path,
                                  custody_input_sha256=digest, out=directory / 'export', rehearsal=True,
                                  trust_anchor=directory / 'anchor.json', trust_anchor_sha256='66' * 32,
                                  signer_seed_file=directory / 'signer.seed')
        authority = {'private_seed_commitment': '77' * 32, 'payload_sha256': '88' * 32,
                     'public_key_sha256': '99' * 32}
        commitments = {'source_commit': build['source']['commit'],
                       'generator_source_commit': build['source']['commit'], 'genesis_time': private['genesis_time'], 'wallet_seed_commitment': public['wallet_commitment'],
                       'validators': public['validators'], 'profile': 'z01-validator-economics-v1',
                       'original_vset_valid_for': 131072, 'param16': [21, 21, 4],
                       'param28': [250, 250, 1000, 21, True],
                       'param30': {'tag': '22', 'flags': 0, 'protocol_version': 2, 'use_quic': True,
                                   'slots_per_leader_window': 4,
                                   'noncritical_params': {'0': 400, '1': 1000, '10': 250}}}
        if source_mismatch:
            commitments["generator_source_commit"] = "aa" * 20
        counter = 0

        def fake_import(argv, **kwargs):
            nonlocal counter
            index = counter
            counter += 1
            local_key = Path(argv[-1])
            local_key.write_bytes(b'fake-native-custody')
            local_key.chmod(0o600)
            if change_manifest:
                path.write_text('{"changed":true}')
            stdout = f'algorithm mldsa44\nkey_id    {index + 1:064x}\npublic    {bytes([index + 1]).hex() * 1312}\n'.encode()
            return subprocess.CompletedProcess(argv, import_exit, stdout, b'fake-tool-refusal' if import_exit else b'')

        with patch.object(export.argparse.ArgumentParser, 'parse_args', return_value=args), \
             patch.object(export.live, 'load_precommit', return_value=build), \
             patch.object(export, 'load', return_value=(public, private)), \
             patch.object(export.signatures, 'anchor', return_value=(authority, None)), \
             patch.object(export.signatures, 'verify_commitments', return_value=commitments), \
             patch.object(export.signatures, 'sign_public', return_value=b'fake-signature-' + bytes(49)), \
             patch.object(export.subprocess, 'run', fake_import):
            export.main()
        return json.loads((args.out / 'public-inputs.json').read_bytes())

    def test_rehearsal_scope_and_public_identity_export_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.exercise(Path(temp))
            self.assertEqual(result['scope'], 'development-fixed')
            self.assertFalse(result['final_signed_genesis'])
            self.assertFalse(result['provenance']['z01_eligible'])
            self.assertTrue(result['provenance']['rehearsal'])
            self.assertEqual(len(result['validators']), 4)
            self.assertTrue(all(len(item['public_key']) == 2624 for item in result['validators']))
            self.assertNotIn('pq_seed', result['validators'][0])
            self.assertNotIn('path', result['wallet_seed'])
            self.assertNotIn('path', result['pq_tool'])

    def test_signed_generator_source_mismatch_refused_before_export(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with self.assertRaisesRegex(export.live.RunError, 'actual common source/generator'):
                self.exercise(directory, source_mismatch=True)
            self.assertFalse((directory / 'export').exists())

    def test_changed_custody_manifest_refused_before_public_freeze(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with self.assertRaisesRegex(export.live.RunError, 'custody manifest changed during export'):
                self.exercise(directory, change_manifest=True)
            self.assertFalse((directory / 'export/public-inputs.json').exists())

    def test_native_import_refusal_preserves_original_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with self.assertRaisesRegex(export.live.RunError, 'export did not exit naturally0'):
                self.exercise(directory, import_exit=1)
            self.assertEqual((directory / 'export/pq-0.exit.raw').read_text(), '1\n')
            self.assertEqual((directory / 'export/pq-0.stderr.raw').read_bytes(), b'fake-tool-refusal')


if __name__ == '__main__':
    unittest.main()
