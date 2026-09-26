#!/usr/bin/env python3
"""Ticketed independent regeneration from public PQ descriptors and fixed wallet.

This entry authenticates development inputs against a separately frozen public
anchor. It does not grant mainnet authority or start nodes. Runs need a ticket.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_hex(value: object, length: int, label: str) -> bytes:
    require(isinstance(value, str) and len(value) == length * 2
            and all(c in '0123456789abcdef' for c in value), f'invalid {label}')
    return bytes.fromhex(value)


def authenticate_input(raw: bytes, anchor: bytes, signature: bytes, expected_anchor_sha256: str) -> bytes:
    require(len(anchor) == 32 and hashlib.sha256(anchor).hexdigest() == expected_anchor_sha256,
            'pre-frozen external development trust anchor mismatch')
    require(len(signature) == 64, 'development signature must be raw64bytes')
    from nacl.signing import VerifyKey
    covering_bytes = b'TOS-R2-DEVELOPMENT-INPUTS-V1\x00' + raw
    VerifyKey(anchor).verify(covering_bytes, signature)
    return covering_bytes


def validate_public_input(manifest: dict, expected_source: str) -> None:
    required = {'schema', 'scope', 'phase', 'candidate_scope', 'owner_mainnet_release_identity',
                'source_commit', 'genesis_time', 'profile', 'original_vset_valid_for',
                'expected_parameters', 'wallet_seed', 'validators', 'trust_anchor_sha256',
                'input_commitments_sha256', 'final_signed_genesis'}
    optional = {'custody_public_receipt', 'pq_tool', 'pq_tool_receipts', 'precommit_sha256',
                'final_signed_genesis', 'provenance', 'custody_commitments'}
    require(isinstance(manifest, dict) and required <= set(manifest)
            and set(manifest) <= required | optional, 'unexpected public input fields')
    def no_private_paths(value):
        if isinstance(value, dict):
            require(not any(str(key).lower().endswith('path') or str(key).lower().endswith('paths')
                            for key in value), 'public input must not contain nested custody/filesystem paths')
            for child in value.values():
                no_private_paths(child)
        elif isinstance(value, list):
            for child in value:
                no_private_paths(child)
    no_private_paths(manifest)
    require(manifest.get('schema') == 'tos.z02.pq-regeneration-input.v1', 'unsupported input schema')
    require(manifest.get('scope') == 'development-fixed', 'final signed inputs need authenticated contract')
    require(manifest['phase'] == 'public-pq-descriptors'
            and manifest['candidate_scope'] == 'development-final-candidate'
            and manifest['owner_mainnet_release_identity'] is False
            and manifest['final_signed_genesis'] is False, 'invalid development descriptor phase/authority')
    require(manifest.get('source_commit') == expected_source, 'manifest source mismatch')
    require(type(manifest.get('genesis_time')) is int and manifest['genesis_time'] == 1790395200,
            'development freeze requires epoch1790395200')
    require(manifest.get('profile') == 'z01-validator-economics-v1', 'unsupported config profile')
    require(type(manifest['original_vset_valid_for']) is int and manifest['original_vset_valid_for'] == 131072,
            'original validator lifetime differs from freeze')
    expected = {'param16': [21, 21, 4], 'param28': [250, 250, 1000, 21, True],
                'param30': {'tag': '22', 'flags': 0, 'protocol_version': 2, 'use_quic': True,
                            'slots_per_leader_window': 4,
                            'noncritical_params': {'0': 400, '1': 1000, '10': 250}}}
    require(json.dumps(manifest['expected_parameters'], sort_keys=True) == json.dumps(expected, sort_keys=True),
            'signed expected parameters differ from consumed profile')
    exact_hex(manifest['trust_anchor_sha256'], 32, 'external anchor contract hash')
    exact_hex(manifest['input_commitments_sha256'], 32, 'phase1 commitment payload hash')
    require(isinstance(manifest['wallet_seed'], dict) and set(manifest['wallet_seed']) == {'sha256'},
            'wallet public entry must be commitment only')
    exact_hex(manifest['wallet_seed']['sha256'], 32, 'wallet commitment')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--anchor', type=Path, required=True)
    parser.add_argument('--anchor-sha256', required=True)
    parser.add_argument('--signature', type=Path, required=True)
    parser.add_argument('--anchor-contract-sha256', required=True,
                        help='independently pre-frozen JSON authority hash, distinct from raw key hash')
    parser.add_argument('--wallet-seed-file', type=Path, required=True,
                        help='local private custody mapping; never put path in signed public inputs')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    exact_hex(args.source_commit, 20, 'source commit')
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    require(head == args.source_commit, 'source commit mismatch')
    dirty = subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=all'])
    require(not dirty, 'generation source is dirty')
    raw = args.input.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.input_sha256, 'input receipt mismatch')
    anchor = args.anchor.read_bytes()
    signature = args.signature.read_bytes()
    # Freeze exactly these bytes with Z01/Z03; JSON reserialization is forbidden.
    covering_bytes = authenticate_input(raw, anchor, signature, args.anchor_sha256)
    manifest = json.loads(raw)
    validate_public_input(manifest, head)
    require(manifest['trust_anchor_sha256'] == args.anchor_contract_sha256,
            'signed descriptor authority does not match external pre-freeze contract')
    epoch = manifest.get('genesis_time')
    wallet_entry = manifest['wallet_seed']
    require(isinstance(wallet_entry, dict) and 'path' not in wallet_entry,
            'public wallet entry must contain commitment only, no private path')
    wallet_path = args.wallet_seed_file
    fd = os.open(wallet_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as wallet_file:
        metadata = os.fstat(wallet_file.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o600, 'wallet custody must be owned regular0600')
        wallet = wallet_file.read(33)
    require(len(wallet) == 32 and hashlib.sha256(wallet).hexdigest() == wallet_entry['sha256'],
            'wallet input commitment mismatch')
    entries = manifest.get('validators')
    require(isinstance(entries, list) and len(entries) == 4, 'need four complete PQ descriptors')
    descriptors = []
    seen = [set(), set(), set(), set()]
    for entry in entries:
        values = [exact_hex(entry[k], n, k) for k, n in
                  [('validator_id', 32), ('key_id', 32), ('public_key', 1312), ('adnl_id', 32)]]
        adnl_public = exact_hex(entry['adnl_public_key'], 32, 'adnl_public_key')
        require(hashlib.sha256(bytes.fromhex('c6b41348') + adnl_public).digest() == values[3],
                'ADNL public key does not bind descriptor ID')
        require(entry.get('weight') == 17 and type(entry.get('weight')) is int,
                'generator profile requires exact weight17')
        for index, value in enumerate(values):
            require(value not in seen[index], 'duplicate PQ descriptor identity')
            seen[index].add(value)
        descriptors.append(values)
    # Import the explicitly bound clone, rather than a retained editable package.
    sys.path.insert(0, str(source / 'test/tostester/src'))
    from tostester.install import Install
    from tostester.zerostate import NetworkConfig, PqInitialValidator, create_zerostate
    import tostester.zerostate as generator
    require(Path(generator.__file__).resolve().is_relative_to(source), 'generator imported from another source')
    import tostester.install as installation
    require(Path(installation.__file__).resolve().is_relative_to(source), 'install imported from another source')
    config = NetworkConfig(genesis_time=epoch, genesis_wallet_seed=wallet)
    config.validator_economics_profile = True
    config.shard_validators = 4
    public_config = asdict(config)
    del public_config['genesis_wallet_seed']
    pq = [PqInitialValidator(*values) for values in descriptors]
    args.out.mkdir(exist_ok=False)
    os.chmod(args.out, 0o700)
    create_zerostate(Install(args.build.resolve(), source), args.out, config, [], pq)
    require((args.out / 'generation.exit.raw').read_text().strip() == '0', 'generation natural exit missing')
    outputs = {}
    for filename in ('zerostate.boc', 'zerostate.rhash', 'zerostate.fhash',
                     'basestate0.boc', 'basestate0.rhash', 'basestate0.fhash'):
        data = (args.out / filename).read_bytes()
        require(data and (not filename.endswith(('rhash', 'fhash')) or len(data) == 32),
                'invalid output length')
        outputs[filename] = hashlib.sha256(data).hexdigest()
    public_argv = list(sys.argv)
    for index, argument in enumerate(public_argv):
        if argument == '--wallet-seed-file' and index + 1 < len(public_argv):
            public_argv[index + 1] = '<private-custody-path>'
        elif argument.startswith('--wallet-seed-file='):
            public_argv[index] = '--wallet-seed-file=<private-custody-path>'
    receipt = {'scope': 'development-fixed', 'final_signed_genesis': False,
               'source_commit': head, 'input_sha256': args.input_sha256,
               'input_path': str(args.input.resolve()),
               'development_signature': {'algorithm': 'Ed25519', 'anchor_path': str(args.anchor.resolve()),
                                         'anchor_sha256': args.anchor_sha256,
                                         'anchor_contract_sha256': args.anchor_contract_sha256,
                                         'signature_path': str(args.signature.resolve()),
                                         'signature_sha256': hashlib.sha256(signature).hexdigest(),
                                         'covering_bytes_sha256': hashlib.sha256(covering_bytes).hexdigest(),
                                         'covering_contract': 'TOS-R2-DEVELOPMENT-INPUTS-V1 NUL followed by exact input bytes',
                                         'verified': True, 'mainnet_authority': False,
                                         'pre_generation_anchor_freeze': 'requires independent dispatcher receipt'},
               'public_argv': public_argv, 'cwd': str(Path.cwd()),
               'exact_argv_receipt': 'retain separately in restricted custody job; not public evidence',
               'build_path': str(args.build.resolve()),
               'config_consumed': public_config,
               'public_descriptors': entries,
               'wallet_seed_commitment': wallet_entry['sha256'],
               'generator_origins': {'zerostate': str(Path(generator.__file__).resolve()),
                                     'install': str(Path(installation.__file__).resolve())},
               'pythonpath': os.environ.get('PYTHONPATH'),
               'generation_command_receipt': str((args.out / 'generation.command.json').resolve()),
               'generation_exit_receipt': str((args.out / 'generation.exit.raw').resolve()),
               'outer_natural_exit': 'requires ticket runner original; this JSON is not outer exit evidence',
               'genesis_time': epoch, 'outputs_sha256': outputs,
               'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'unverified': ['PQ key_id derivation and custody binding', 'public descriptor export provenance',
                              'formal mainnet release authentication (outside development scope)',
                              'independent pre-generation anchor/custody freeze receipt', 'build/environment/binary provenance',
                              'independent BOC roots/config decode', 'live proof trust chain']}
    (args.out / 'regeneration-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    # Private wallet remains local0600, excluded from the public receipt inventory.


if __name__ == '__main__':
    main()
