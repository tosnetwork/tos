"""Public C0 statements and adversarial signatures for the native VM boundary."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'test/validator-auth-p0'))
import reference as r
from ed25519_oracle import Verifier, L, P


def main(out):
    out.mkdir()
    oracle = Verifier()
    cases = []

    def add(key, message, signature):
        index = len(cases)
        for suffix, data in [('key', key), ('message', message), ('signature', signature)]:
            (out / f'{index}.{suffix}').write_bytes(data)
        expected_exit = 0 if len(signature) == 64 else 9
        expected_value = (-1 if oracle.verify(key, message, signature) else 0) if expected_exit == 0 else 99
        cases.append(f'{expected_exit} {expected_value}')

    frozen = json.loads(gzip.decompress((ROOT / 'test/validator-auth-p0/golden.json.gz').read_bytes()))
    committee = r.decode('committee', bytes.fromhex(frozen['committee']))
    for case in frozen['cases']:
        certificate = r.decode('certificate', bytes.fromhex(case['certificate']))
        for row, member in zip(certificate['records'], committee['members']):
            public = member['keys'][case['role'] - 1]['public_key']
            message = r.statement(certificate['duty'], row)
            signature = row['components'][0]['signature']
            add(public, message, signature)
            add(public, message + b'\0', signature)
            add(public, message, signature[:32] + L.to_bytes(32, 'little'))
            add(public, message, signature[:-1])
            add(public, message, signature + b'\0')
            add(public, hashlib.sha256(message).digest(), signature)
    base = bytes.fromhex('58' + '66' * 31)
    identity = (1).to_bytes(32, 'little')
    message = b'public edge fixture'
    scalar = int.from_bytes(hashlib.sha512(identity + base + message).digest(), 'little') % L
    signature = identity + scalar.to_bytes(32, 'little')
    add(base, message, signature)
    for key in (bytes(32), identity, (P + 1).to_bytes(32, 'little'), (1 + (1 << 255)).to_bytes(32, 'little')):
        add(key, message, signature)
    for first in (bytes(32), (P + 1).to_bytes(32, 'little'), (1 + (1 << 255)).to_bytes(32, 'little')):
        add(base, message, first + scalar.to_bytes(32, 'little'))
    (out / 'cases').write_text('\n'.join(cases) + '\n')
    print(f'PASS: {len(cases)} public C0 VM inputs from frozen statements and independent oracle')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    main(parser.parse_args().out)
