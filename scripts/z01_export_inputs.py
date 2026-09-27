#!/usr/bin/env python3
"""Ticketed public PQ descriptor export from already committed local custody.

This emits development-fixed inputs for independent generation. It neither
creates owner signing identities nor claims final signed Genesis authority.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'test/tostester/src'))

from scripts import z01_live_run as live
from scripts.z01_fixed_inputs import load
from scripts import z01_development_signature as signatures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--precommit', type=Path, required=True)
    parser.add_argument('--precommit-sha256', required=True)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--custody-input', type=Path, required=True)
    parser.add_argument('--custody-input-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--trust-anchor', type=Path, required=True)
    parser.add_argument('--trust-anchor-sha256', required=True)
    parser.add_argument('--signer-seed-file', type=Path, required=True)
    parser.add_argument('--rehearsal', action='store_true')
    args = parser.parse_args()
    build = live.load_precommit(args.precommit, args.precommit_sha256, args.build_dir, args.rehearsal)
    public, private = load(args.custody_input, args.custody_input_sha256)
    authority, key = signatures.anchor(args.trust_anchor, args.trust_anchor_sha256)
    commitments = signatures.verify_commitments(authority, key, args.custody_input_sha256)
    live.require(commitments.get('source_commit') == build['source']['commit']
                 and commitments.get('generator_source_commit') == build['source']['commit'],
                 'signed commitments differ from actual common source/generator')
    live.require(commitments['genesis_time'] == private['genesis_time']
                 and commitments['wallet_seed_commitment'] == public['wallet_commitment']
                 and commitments['validators'] == public['validators'],
                 'signed commitment fields differ from consumed custody')
    signatures.verify_profile(commitments, authority, public)
    expected_parameters = signatures.EXPECTED_PARAMETERS
    live.require(build.get('fixed_inputs') == public, 'custody freeze differs from precommit')
    live.require(private['genesis_time'] == 1790395200, 'development network epoch differs from freeze')
    args.out.mkdir(exist_ok=False)
    args.out.chmod(0o700)
    from nacl.signing import SigningKey
    from tostester.key import Key
    entries = []
    receipts = []
    tool = build['binaries']['pq_consensus_key']
    for index, custody in enumerate(private['validators']):
        directory = args.out / f'custody-{index}'
        directory.mkdir(mode=0o700)
        local_key = directory / 'pq-consensus.seed'
        argv = [tool['path'], 'import', str(local_key.resolve())]
        command_path = args.out / f'pq-{index}.command.private.json'
        live.write_json(command_path, {
            'argv': argv, 'cwd': str(ROOT), 'source_commit': build['source']['commit'],
            'binary_sha256': tool['sha256'], 'seed_commitment': public['validators'][index]['pq_seed_commitment'],
            'started_wall_ns': time.time_ns(),
        })
        command_path.chmod(0o600)
        try:
            result = subprocess.run(argv, input=custody['pq_seed'].hex().encode() + b'\n',
                                    cwd=ROOT, capture_output=True, timeout=30)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr = None, error.stdout or b'', error.stderr or b''
        for suffix, data in [('stdout.raw', stdout), ('stderr.raw', stderr), ('exit.raw', f'{code}\n'.encode())]:
            live.write_once(args.out / f'pq-{index}.{suffix}', data)
        live.require(code == 0, 'PQ public export did not exit naturally0')
        live.require(local_key.is_file() and not local_key.is_symlink()
                     and local_key.stat().st_uid == os.geteuid()
                     and local_key.stat().st_mode & 0o777 == 0o600
                     and 0 < local_key.stat().st_size <= 4096,
                     'PQ export has no owner-only custody artifact')
        exported = re.fullmatch(rb'algorithm mldsa44\nkey_id +([0-9a-f]{64})\npublic +([0-9a-f]{2624})\n', stdout)
        live.require(exported is not None, 'PQ public export response is malformed')
        adnl = Key(SigningKey(custody['adnl_seed']))
        entries.append({'validator_id': custody['validator_id'].hex(),
                        'key_id': exported[1].decode(), 'public_key': exported[2].decode(),
                        'adnl_id': adnl.id.hex(), 'adnl_public_key': adnl.public_key.key.hex(), 'weight': 17})
        receipts.append({'index': index, 'private_command_sha256': hashlib.sha256(command_path.read_bytes()).hexdigest(),
                         'original_receipts': {suffix: {'ref': f'pq-{index}.{suffix}',
                             'sha256': hashlib.sha256((args.out / f'pq-{index}.{suffix}').read_bytes()).hexdigest()}
                             for suffix in ('stdout.raw', 'stderr.raw', 'exit.raw')},
                         'custody_artifact_sha256': hashlib.sha256(local_key.read_bytes()).hexdigest()})
    for field in ('validator_id', 'key_id', 'public_key', 'adnl_id'):
        live.require(len({entry[field] for entry in entries}) == 4,
                     f'PQ export duplicates {field}')
    custody_raw = args.custody_input.read_bytes()
    live.require(hashlib.sha256(custody_raw).hexdigest() == args.custody_input_sha256,
                 'custody manifest changed during export')
    manifest = {'schema': 'tos.z02.pq-regeneration-input.v1', 'scope': 'development-fixed',
                'phase': 'public-pq-descriptors', 'candidate_scope': 'development-final-candidate',
                'owner_mainnet_release_identity': False,
                'source_commit': build['source']['commit'], 'genesis_time': private['genesis_time'],
                'profile': 'z01-validator-economics-v1',
                'original_vset_valid_for': 131072, 'expected_parameters': expected_parameters,
                'wallet_seed': {'sha256': public['wallet_commitment']},
                'validators': entries, 'custody_public_receipt': {k: v for k, v in public.items() if k != 'manifest_path'},
                'pq_tool': {'ref': 'shared-build/pq_consensus_key', 'sha256': tool['sha256']}, 'pq_tool_receipts': receipts,
                'provenance': {'z01_eligible': build['z01_eligible'], 'os_release': build['os_release'],
                               'image_id': build['image_id'], 'rehearsal': args.rehearsal},
                'precommit_sha256': args.precommit_sha256, 'final_signed_genesis': False,
                'trust_anchor_sha256': args.trust_anchor_sha256,
                'input_commitments_sha256': authority['payload_sha256']}
    from scripts.z02_pq_regenerate import validate_public_input
    validate_public_input(manifest, build['source']['commit'])
    digest = live.write_json(args.out / 'public-inputs.json', manifest)
    signature = signatures.sign_public((args.out / 'public-inputs.json').read_bytes(),
                                       authority, key, args.signer_seed_file)
    live.write_once(args.out / 'public-inputs.ed25519.signature', signature)
    live.write_json(args.out / 'signature-receipt.json', {
        'scope': 'development-final-candidate', 'payload_sha256': digest,
        'signature_sha256': hashlib.sha256(signature).hexdigest(),
        'raw_public_anchor_sha256': authority['public_key_sha256'],
        'trust_anchor_sha256': args.trust_anchor_sha256,
        'covering_bytes': 'TOS-R2-DEVELOPMENT-INPUTS-V1 ASCII +NUL+exact raw public-inputs.json',
        'owner_mainnet_release_identity': False, 'genesis_generation_started': False,
    })
    print(json.dumps({'public_input': str(args.out / 'public-inputs.json'), 'sha256': digest,
                      'scope': 'development-fixed', 'final_signed_genesis': False}))


if __name__ == '__main__':
    main()
