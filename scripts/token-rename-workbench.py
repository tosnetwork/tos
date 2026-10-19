#!/usr/bin/env python3
"""Temporary independent baseline check before freezing renamed contract code."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = '8430f633a5b694b3ee0b31934d92941898474d83'
BUILD = ROOT / 'build'
SPEC = importlib.util.spec_from_file_location('token_code', ROOT / 'scripts/update-token-code.py')
assert SPEC is not None and SPEC.loader is not None
CODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CODE)


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


with tempfile.TemporaryDirectory(prefix='token-baseline-') as raw:
    scratch = Path(raw)
    base_tree = scratch / 'base'
    base_tree.mkdir()
    # Both archives are our pinned repository source; never extract runtime data.
    archive = subprocess.Popen(['git', 'archive', BASE, 'crypto/func/auto-tests/legacy_tests', 'crypto/func/auto-tests/legacy_tests.json', 'sdk/js/packages/contracts/src/jetton/codes.ts'], cwd=ROOT, stdout=subprocess.PIPE)
    extracted = subprocess.run(['tar', '-x', '-C', str(base_tree)], stdin=archive.stdout, check=False)
    assert archive.stdout is not None
    archive.stdout.close()
    if archive.wait() != 0 or extracted.returncode != 0:
        raise RuntimeError('could not extract the pinned baseline')
    before_manifest = dict(json.loads((base_tree / CODE.GOLDEN_JSON).read_text()))
    control_root = scratch / 'reverted-getter'
    shutil.copytree(ROOT / 'crypto/func/auto-tests/legacy_tests', control_root)
    for path in control_root.rglob('*.fc'):
        text = path.read_text()
        text = text.replace('get_token_data', 'get_jetton_data')
        text = text.replace('method_id(84418)', 'method_id(106029)')
        path.write_text(text)
    receipts = []
    for index, new_name in enumerate(CODE.FIXTURES):
        old_name = new_name.replace('token', 'jetton').replace('Token', 'Jetton')
        old = base_tree / 'crypto/func/auto-tests/legacy_tests' / old_name
        old_boc = CODE.compile_boc(old, scratch / f'old-{index}', BUILD)
        old_hash = CODE.root_hash(old_boc, scratch / f'old-{index}', BUILD)
        if old_hash != before_manifest[old_name]:
            raise RuntimeError(f'baseline golden mismatch: {old_name} expected {before_manifest[old_name]} actual {old_hash}')
        control_boc = CODE.compile_boc(control_root / new_name, scratch / f'control-{index}', BUILD)
        control_hash = CODE.root_hash(control_boc, scratch / f'control-{index}', BUILD)
        if control_hash != old_hash:
            raise RuntimeError(f'non-getter bytecode change: {new_name} baseline {old_hash} reverted-getter {control_hash}')
        candidate_boc = CODE.compile_boc(ROOT / 'crypto/func/auto-tests/legacy_tests' / new_name, scratch / f'candidate-{index}', BUILD)
        candidate_hash = CODE.root_hash(candidate_boc, scratch / f'candidate-{index}', BUILD)
        receipts.append({'source': new_name, 'baseline_cell_hash': old_hash, 'candidate_cell_hash': candidate_hash, 'getter_reversion_restores_baseline': True})
    # Record whether the former SDK embedding was actually the golden source.
    old_sdk = (base_tree / 'sdk/js/packages/contracts/src/jetton/codes.ts').read_text()
    for index, const in enumerate(['JETTON_MINTER_CODE_HEX', 'JETTON_WALLET_CODE_HEX']):
        match = re.search(rf'export const {const}\s*=\s*(.*?);', old_sdk, re.S)
        if match is None:
            raise RuntimeError(f'missing baseline SDK constant: {const}')
        encoded = ''.join(re.findall(r'"([0-9a-fA-F]+)"', match.group(1)))
        old_sdk_hash = CODE.root_hash(bytes.fromhex(encoded), scratch / f'old-{index}', BUILD)
        receipts[index]['former_sdk_cell_hash'] = old_sdk_hash
        receipts[index]['former_sdk_matches_reference'] = old_sdk_hash == receipts[index]['baseline_cell_hash']
    print('BASELINE_AND_MUTATION_EVIDENCE', json.dumps(receipts), flush=True)
run(sys.executable, 'scripts/update-token-code.py', '--update-goldens')
run(sys.executable, 'scripts/update-token-code.py', '--check')
run('git', 'add', '--', str(CODE.SDK), str(CODE.GOLDEN_JSON), str(CODE.GOLDEN_PY))
if subprocess.run(['git', 'diff', '--cached', '--quiet'], cwd=ROOT).returncode == 1:
    run('git', '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit', '-m', 'build: regenerate Token SDK code and verify compiler fixture hashes')
print('ARTIFACT_COMMIT', subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), flush=True)
