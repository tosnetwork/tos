#!/usr/bin/env python3
"""Regenerate the independent OpenSSL interoperability fixture.

Run by hand with OpenSSL 3.5 or newer; the committed JSON is what the test
suite consumes, so no runner needs an ML-DSA-capable OpenSSL. The point is that
a second, unrelated implementation signs the same commitment bytes this
repository computes. Seeds are PUBLIC TEST DATA and never protect real funds.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from protocol import Cell, CONTEXT, commitment

# SubjectPublicKeyInfo wrapper OpenSSL puts in front of the 1312 raw key bytes.
SPKI_PREFIX = bytes.fromhex('30820532300b06096086480165030403110382052100')
FIELDS = dict(network=42, account=(0, 0x1234), epoch=1, nonce=0,
              valid_until=1_780_000_600, kind=0, payload=7)


def request(network, account, epoch, nonce, valid_until, kind, payload):
    return (Cell().sint(network, 32).addr(account).uint(epoch, 64).uint(nonce, 64)
            .uint(valid_until, 32).uint(kind, 8).ref(Cell().uint(payload, 32)))


def openssl(binary, *args, stdin_ok=True):
    return subprocess.run([binary, *map(str, args)], check=True, capture_output=True)


def generate(binary, out):
    with tempfile.TemporaryDirectory(prefix='mldsa-interop-') as tmp:
        d = Path(tmp)
        keys = []
        for index in range(2):
            secret, public = d / f'k{index}.pem', d / f'k{index}.der'
            openssl(binary, 'genpkey', '-algorithm', 'ML-DSA-44',
                    '-pkeyopt', 'hexseed:' + bytes([0x61 + index] * 32).hex(), '-out', secret)
            openssl(binary, 'pkey', '-in', secret, '-pubout', '-outform', 'DER', '-out', public)
            der = public.read_bytes()
            if not der.startswith(SPKI_PREFIX) or len(der) != len(SPKI_PREFIX) + 1312:
                raise SystemExit('unexpected ML-DSA-44 SubjectPublicKeyInfo encoding')
            keys.append(der[len(SPKI_PREFIX):])
        req = request(**FIELDS)
        digest = commitment(req)
        (d / 'digest').write_bytes(digest)
        openssl(binary, 'pkeyutl', '-sign', '-rawin', '-inkey', d / 'k0.pem', '-in', d / 'digest',
                '-out', d / 'sig', '-pkeyopt', 'context-string:' + CONTEXT.decode(),
                '-pkeyopt', 'deterministic:1')
        signature = (d / 'sig').read_bytes()
        if len(signature) != 2420:
            raise SystemExit('unexpected ML-DSA-44 signature length')
        # The independent implementation must accept what it just produced.
        (d / 'spki').write_bytes(SPKI_PREFIX + keys[0])
        openssl(binary, 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', d / 'spki',
                '-keyform', 'DER', '-in', d / 'digest', '-sigfile', d / 'sig',
                '-pkeyopt', 'context-string:' + CONTEXT.decode())
        version = openssl(binary, 'version').stdout.decode().strip()
    fixture = {
        'scope': 'independent OpenSSL signature over this repository\'s commitment bytes',
        'generator': version,
        'public_seeds_hex': [bytes([0x61 + i] * 32).hex() for i in range(2)],
        'fields': {k: list(v) if isinstance(v, tuple) else v for k, v in FIELDS.items()},
        'request_boc_hex': req.boc().hex(),
        'commitment_hex': digest.hex(),
        'context_hex': CONTEXT.hex(),
        'signing_key_hex': keys[0].hex(),
        'other_key_hex': keys[1].hex(),
        'signature_hex': signature.hex(),
    }
    out.write_text(json.dumps(fixture, indent=2, sort_keys=True) + '\n')
    print(f'wrote {out} using {version}')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--openssl', default='openssl')
    p.add_argument('--out', type=Path,
                   default=Path(__file__).resolve().parent / 'openssl-interop.json')
    a = p.parse_args()
    generate(a.openssl, a.out)
