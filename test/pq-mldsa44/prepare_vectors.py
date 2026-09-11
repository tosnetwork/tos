#!/usr/bin/env python3
"""Prepare pinned public vectors; downloading never substitutes for executing them."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent
ACVP = '975de31eb83d87039ec88934fdc47d8c312b892d'
WYCHEPROOF = '3fa63dd0344abb611f1fb1d77e119938603ea230'
SOURCES = {
    'acvp-prompt.json': ('usnistgov/ACVP-Server', ACVP,
        'gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json',
        '22b0803253f7aa24644229acd04c387d260e874a'),
    'acvp-expected.json': ('usnistgov/ACVP-Server', ACVP,
        'gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json',
        'dba8bcfe5f090503c9390701c11677389752cecd'),
    'wycheproof.json': ('C2SP/wycheproof', WYCHEPROOF,
        'testvectors_v1/mldsa_44_verify_test.json',
        'b2fb655fc645dab4a8af226bbefe5a8f23a687a7'),
}


def load_source(name: str, cache: Path, offline: bool):
    repo, commit, path, blob = SOURCES[name]
    dest = cache / name
    if dest.exists():
        raw = dest.read_bytes()
    else:
        if offline:
            raise RuntimeError(f'missing pinned vector file: {dest}')
        url = f'https://raw.githubusercontent.com/{repo}/{commit}/{path}'
        with urllib.request.urlopen(url, timeout=60) as response:
            raw = response.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise RuntimeError('vector download exceeds size bound')
    actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if actual != blob:
        raise RuntimeError(f'{name}: pinned Git blob mismatch ({actual})')
    dest.write_bytes(raw)
    data = json.loads(raw)
    if isinstance(data, list):
        data, = [x for x in data if 'testGroups' in x]
    return data


def fixture_bytes(item, field: str) -> bytes:
    if field + 'Hex' in item:
        return bytes.fromhex(item[field + 'Hex'])
    spec = item[field + 'Repeat']
    if not (0 <= spec['byte'] <= 255 and 0 <= spec['count'] <= 8192):
        raise ValueError('invalid fixture byte pattern')
    return bytes([spec['byte']]) * spec['count']


def prepare(output: Path, cache: Path, offline: bool = False, fixtures_only: bool = False):
    output.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    rows, counts, ids = [], Counter(), set()

    def add(id, valid, m, ctx, sig, pk, source):
        if id in ids or any(c in id for c in '\t\r\n'):
            raise ValueError('invalid/duplicate vector id')
        ids.add(id)
        malformed = len(m) > 8192 or len(ctx) > 255 or len(sig) != 2420 or len(pk) != 1312
        if valid and malformed:
            # Algorithm-valid messages outside this bounded VM profile are NOT
            # counted as a passed conformance vector.
            counts[source + '.valid_outside_vm_profile'] += 1
            return
        if max(map(len, (m, ctx, sig, pk))) > 65536:
            raise ValueError('unexpectedly large test case; review explicitly')
        expected = 'M' if malformed else ('V' if valid else 'I')
        rows.append((id, expected, m.hex(), ctx.hex(), sig.hex(), pk.hex()))
        counts[source + '.' + expected] += 1

    fixture = json.loads((ROOT / 'fixtures.json').read_text())
    pk = bytes.fromhex(fixture['publicKeyHex'])
    for item in fixture['cases']:
        add(item['id'], True, fixture_bytes(item, 'message'), fixture_bytes(item, 'context'),
            bytes.fromhex(item['signatureHex']), pk, 'openssl')
    if not fixtures_only:
        prompt = load_source('acvp-prompt.json', cache, offline)
        answers = load_source('acvp-expected.json', cache, offline)
        expected = {(g['tgId'], t['tcId']): t['testPassed']
                    for g in answers['testGroups'] for t in g['tests']}
        for group in prompt['testGroups']:
            if (group['parameterSet'] != 'ML-DSA-44' or
                    group['signatureInterface'] != 'external' or
                    group.get('preHash') == 'preHash' or group.get('externalMu') is True):
                counts['acvp.other_profile'] += len(group['tests'])
                continue
            for t in group['tests']:
                add(f"acvp-{group['tgId']}-{t['tcId']}", expected[group['tgId'], t['tcId']],
                    bytes.fromhex(t['message']), bytes.fromhex(t['context']),
                    bytes.fromhex(t['signature']), bytes.fromhex(t['pk']), 'acvp')
        w = load_source('wycheproof.json', cache, offline)
        if w['algorithm'] != 'ML-DSA-44':
            raise ValueError('unexpected vector algorithm')
        for group in w['testGroups']:
            for t in group['tests']:
                if t['result'] not in ('valid', 'invalid'):
                    raise ValueError('unclassified vector result')
                add(f"wycheproof-{t['tcId']}", t['result'] == 'valid',
                    bytes.fromhex(t['msg']), bytes.fromhex(t.get('ctx', '')),
                    bytes.fromhex(t['sig']), bytes.fromhex(group['publicKey']), 'wycheproof')
        for source in ('acvp', 'wycheproof'):
            if counts[source + '.V'] == 0 or counts[source + '.I'] == 0:
                raise RuntimeError(f'{source}: both positive and negative controls are required')
    if len(rows) < 3:
        raise RuntimeError('missing independent positive fixtures')
    text = ''.join('\t'.join(r) + '\n' for r in rows)
    (output / 'vectors.tsv').write_text(text, encoding='ascii')
    manifest = {'rows': len(rows), 'counts': dict(sorted(counts.items())),
                'vectors_sha256': hashlib.sha256(text.encode()).hexdigest(),
                'sources': SOURCES if not fixtures_only else {}}
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    print(json.dumps(manifest, sort_keys=True, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--cache', type=Path)
    p.add_argument('--offline', action='store_true')
    p.add_argument('--fixtures-only', action='store_true', help='local smoke test, not the ACVP CI gate')
    args = p.parse_args()
    prepare(args.out, args.cache or args.out / 'cache', args.offline, args.fixtures_only)
