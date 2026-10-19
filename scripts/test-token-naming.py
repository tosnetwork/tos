#!/usr/bin/env python3
"""Positive and negative controls for the source naming migration."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("migrate-token-naming.py")
SPEC = importlib.util.spec_from_file_location("token_naming_migration", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MIGRATION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MIGRATION
SPEC.loader.exec_module(MIGRATION)


class TextMigration(unittest.TestCase):
    def test_identifier_cases_and_getter(self):
        text = 'JettonWallet JETTON_OP_MINT jetton_wallet get_jetton_data jettons'
        self.assertEqual(MIGRATION.transform("active.cpp", text), 'TokenWallet TOKEN_OP_MINT token_wallet get_token_data tokens')

    def test_master_public_names_and_filename(self):
        self.assertEqual(MIGRATION.transform("x.ts", "JettonMinter JETTON_MINTER_CODE_HEX"), "TokenMaster TOKEN_MASTER_CODE_HEX")
        self.assertEqual(MIGRATION.rename("sdk/jetton/JettonMinter.test.ts"), "sdk/token/TokenMaster.test.ts")

    def test_generic_token_data_does_not_collide(self):
        self.assertEqual(MIGRATION.transform("types.ts", 'TokenData JettonData JettonMasterData'), 'TokenData FungibleTokenData TokenMasterData')

    def test_scoped_kind_keeps_discriminants(self):
        before = 'enum class TokenKind { Jetton = 0, Nft = 1 }; TokenKind::Jetton;'
        self.assertEqual(MIGRATION.transform("index.h", before), 'enum class TokenKind { Fungible = 0, Nft = 1 }; TokenKind::Fungible;')

    def test_protocol_numbers_unchanged_except_named_getter(self):
        before = 'get_jetton_data() method_id(106029) { return 106029; } JETTON_OP_TRANSFER = 0x0f8a7ea5;'
        after = MIGRATION.transform("jetton.fc", before)
        self.assertIn('get_token_data() method_id(84418)', after)
        self.assertIn('return 106029;', after)
        self.assertIn('TOKEN_OP_TRANSFER = 0x0f8a7ea5;', after)
        self.assertEqual(MIGRATION.OLD_GETTER_ID, 106029)
        self.assertEqual(MIGRATION.NEW_GETTER_ID, 84418)

    def test_upstream_and_commit_links_are_not_rewritten(self):
        urls = ['https://example.com/jetton', 'https://github.com/tosnetwork/tos/blob/abcdef/jetton.tol']
        for url in urls:
            self.assertEqual(MIGRATION.transform("doc.md", url), url)
        live = 'https://github.com/tosnetwork/tos/blob/main/crypto/smartcont/jetton-wallet.tol'
        self.assertEqual(MIGRATION.transform("doc.md", live), live.replace('jetton', 'token'))

    def test_evidence_and_license_contents_unchanged(self):
        for path in ['tools/evidence/raw/jetton.log', 'third-party/jetton/NOTICE', 'contracts/jetton/LICENSE', 'scripts/x02_four_node_inputs.json']:
            self.assertEqual(MIGRATION.transform(path, 'Jetton proof 106029'), 'Jetton proof 106029')
        self.assertEqual(MIGRATION.rename('contracts/jetton/LICENSE'), 'contracts/token/LICENSE')
        self.assertEqual(MIGRATION.rename('tools/evidence/jetton.json'), 'tools/evidence/jetton.json')

    def test_legal_header_preserved_but_code_renamed(self):
        self.assertEqual(MIGRATION.transform('x.ts', '// Copyright 2020 Jetton authors\nclass JettonWallet {}'), '// Copyright 2020 Jetton authors\nclass TokenWallet {}')

    def test_retained_path_reference_not_broken(self):
        path = 'tools/evidence/jetton.json'
        self.assertEqual(MIGRATION.transform('doc.md', f'See {path}; Jetton wallet', (path,)), f'See {path}; Token wallet')

    def test_compatibility_claim_removed(self):
        self.assertEqual(MIGRATION.transform('doc.md', 'TEP-74 Jetton interface'), 'TOS Token V1 Token interface')

    def test_transform_idempotent(self):
        before = 'JettonData JETTON_OP_MINT get_jetton_data https://example.com/jetton'
        once = MIGRATION.transform('test.ts', before)
        self.assertEqual(MIGRATION.transform('test.ts', once), once)


class RepositoryMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Migration Test')
        self.git('config', 'user.email', 'migration-test@example.invalid')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.STDOUT, text=True)

    def put(self, name, text, executable=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if executable:
            path.chmod(0o755)
        self.git('add', '--', name)

    def test_apply_preserves_modes_license_and_reaches_fixed_point(self):
        self.put('src/jetton/run.sh', '#!/bin/sh\necho JETTON\n', True)
        self.put('src/jetton/LICENSE', 'Original Jetton license\n')
        self.put('types.ts', 'TokenData JettonData\n')
        self.put('evidence/jetton.json', '{"proof":"Jetton"}\n')
        self.git('commit', '-qm', 'fixture')
        edits = MIGRATION.plan(self.root)
        self.assertEqual(len(edits), 3)
        MIGRATION.apply(self.root, edits)
        self.assertEqual((self.root/'src/token/run.sh').read_text(), '#!/bin/sh\necho TOKEN\n')
        self.assertTrue(os.access(self.root/'src/token/run.sh', os.X_OK))
        self.assertEqual((self.root/'src/token/LICENSE').read_text(), 'Original Jetton license\n')
        self.assertEqual((self.root/'evidence/jetton.json').read_text(), '{"proof":"Jetton"}\n')
        self.assertEqual(MIGRATION.plan(self.root), [])

    def test_path_collision_fails_before_any_write(self):
        self.put('jetton.ts', 'JettonWallet')
        self.put('token.ts', 'DO NOT OVERWRITE')
        with self.assertRaisesRegex(RuntimeError, 'overwrite|collision'):
            MIGRATION.plan(self.root)
        self.assertEqual((self.root/'token.ts').read_text(), 'DO NOT OVERWRITE')
        self.assertEqual((self.root/'jetton.ts').read_text(), 'JettonWallet')

    def test_untracked_destination_collision_is_rejected(self):
        self.put('jetton.ts', 'JettonWallet')
        (self.root/'token.ts').write_text('untracked')
        with self.assertRaisesRegex(RuntimeError, 'overwrite'):
            MIGRATION.plan(self.root)

    def test_binary_bytes_are_not_text_patched(self):
        path = self.root/'jetton.boc'
        payload = b'\0Jetton\xff\x00'
        path.write_bytes(payload)
        self.git('add', '--', path.name)
        edits = MIGRATION.plan(self.root)
        MIGRATION.apply(self.root, edits)
        self.assertEqual((self.root/'token.boc').read_bytes(), payload)

    def test_symlink_remains_a_symlink(self):
        self.put('jetton.ts', 'JettonWallet')
        (self.root/'current.ts').symlink_to('jetton.ts')
        self.git('add', '--', 'current.ts')
        MIGRATION.apply(self.root, MIGRATION.plan(self.root))
        self.assertTrue((self.root/'current.ts').is_symlink())
        self.assertEqual(os.readlink(self.root/'current.ts'), 'token.ts')
        self.assertEqual((self.root/'current.ts').read_text(), 'TokenWallet')

    def test_guard_can_fail_on_a_real_remaining_identifier(self):
        self.put('active.ts', 'export class JettonWallet {}')
        result = subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root), '--check'], capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        MIGRATION.apply(self.root, MIGRATION.plan(self.root))
        result = subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root), '--check'], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_removed_transform_is_detected_by_control(self):
        with mock.patch.object(MIGRATION, 'replace_terms', side_effect=lambda text: text):
            self.assertNotEqual(MIGRATION.transform('active.ts', 'JettonWallet'), 'TokenWallet')


if __name__ == '__main__':
    unittest.main(verbosity=2)
