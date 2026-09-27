"""Explicit pre-frozen development anchor; exact raw Ed25519 covering bytes."""

import hashlib
import json
import os
from pathlib import Path
import stat

from nacl.signing import SigningKey, VerifyKey

DOMAIN = b'TOS-R2-DEVELOPMENT-INPUTS-V1\x00'
COMMITMENT_SCHEMA = 'tos.z01.r2-development-commitments.v1'
DESCRIPTOR_SCHEMA = 'tos.z02.pq-regeneration-input.v1'
EXPECTED_PARAMETERS = {'param16': [21, 21, 4], 'param28': [250, 250, 1000, 21, True],
                       'param30': {'tag': '22', 'flags': 0, 'protocol_version': 2, 'use_quic': True,
                                   'slots_per_leader_window': 4,
                                   'noncritical_params': {'0': 400, '1': 1000, '10': 250}}}


def verify_profile(payload, authority, public):
    require(payload.get('profile') == 'z01-validator-economics-v1'
            and type(payload.get('original_vset_valid_for')) is int
            and payload['original_vset_valid_for'] == 131072
            and json.dumps({name: payload.get(name) for name in EXPECTED_PARAMETERS}, sort_keys=True)
                == json.dumps(EXPECTED_PARAMETERS, sort_keys=True),
            'signed development parameters differ from actual generator profile')
    commitments = {public['wallet_commitment']}
    for entry in public['validators']:
        commitments.update((entry['adnl_seed_commitment'], entry['pq_seed_commitment']))
    require(authority['private_seed_commitment'] not in commitments,
            'development signer must be separate from wallet/ADNL/PQ custody')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded(path, limit):
    with path.open('rb') as file:
        raw = file.read(limit + 1)
    require(0 < len(raw) <= limit, 'signature input size is invalid')
    return raw


def anchor(path: Path, expected_sha256: str):
    raw = bounded(path, 64 * 1024)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'development anchor differs from external freeze')
    value = json.loads(raw)
    require(value.get('schema') == 'tos.z01.r2-development-anchor.v1'
            and value.get('scope') == 'development-final-candidate'
            and value.get('owner_mainnet_release_identity') is False
            and value.get('algorithm') == 'Ed25519', 'invalid development anchor authority/scope')
    public = bounded(Path(value['public_key_file']), 32)
    require(len(public) == 32 and public.hex() == value['public_key_hex']
            and hashlib.sha256(public).hexdigest() == value['public_key_sha256'],
            'raw development public anchor differs from freeze')
    return value, VerifyKey(public)


def verify_commitments(anchor_value, key, expected_private_manifest_sha256: str):
    raw = bounded(Path(anchor_value['payload_path']), 2 * 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == anchor_value['payload_sha256'], 'commitment payload hash differs')
    signature = bounded(Path(anchor_value['signature_path']), 64)
    require(len(signature) == 64 and hashlib.sha256(signature).hexdigest() == anchor_value['signature_sha256'],
            'commitment detached signature differs')
    key.verify(DOMAIN + raw, signature)
    payload = json.loads(raw)
    require(payload.get('schema') == COMMITMENT_SCHEMA and payload.get('phase') == 'custody-commitments'
            and payload.get('scope') == 'development-final-candidate'
            and payload.get('owner_mainnet_release_identity') is False,
            'commitment payload has wrong schema/phase/scope')
    require(payload.get('private_manifest_sha256') == expected_private_manifest_sha256,
            'signed public commitments do not bind consumed private manifest')
    return payload


def sign_public(raw: bytes, anchor_value, key, signer_path: Path):
    payload = json.loads(raw)
    require(payload.get('schema') == DESCRIPTOR_SCHEMA and payload.get('phase') == 'public-pq-descriptors',
            'descriptor payload has wrong schema/phase')
    require(payload.get('scope') == 'development-fixed'
            and payload.get('candidate_scope') == 'development-final-candidate'
            and payload.get('owner_mainnet_release_identity') is False, 'descriptor authority scope is invalid')
    fd = os.open(signer_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        metadata = os.fstat(file.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o600, 'signer custody must be owned regular0600')
        seed = file.read(33)
    require(len(seed) == 32 and hashlib.sha256(seed).hexdigest() == anchor_value['private_seed_commitment'],
            'signer custody differs from frozen commitment')
    signer = SigningKey(seed)
    require(signer.verify_key.encode() == key.encode(), 'signer differs from pre-frozen public anchor')
    signature = signer.sign(DOMAIN + raw).signature
    key.verify(DOMAIN + raw, signature)
    return signature
