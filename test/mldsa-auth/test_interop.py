#!/usr/bin/env python3
"""Execute an independently produced ML-DSA-44 signature through the real module.

The signature in `openssl-interop.json` was produced by OpenSSL, not by this
repository's signer or verifier. Accepting it proves two separate
implementations agree on the exact commitment bytes, the context string and the
canonical wire encoding; the negative cases prove the module still binds every
signed field. Fixture keys are PUBLIC TEST DATA.
"""
import argparse
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test/auth-extensions'))
from build_contracts import build_contracts
from protocol import (AUTH, Cell, CONTEXT, chain, commitment, from_boc, module_data,
                      parse_message, submission)
from native import (GLOBAL_ID, Emulator, account_data, active_account, internal,
                    outgoing, state_init)

FIXTURE = json.loads((Path(__file__).resolve().parent / 'openssl-interop.json').read_text())
WORKCHAIN = 0
BALANCE = 100_000_000_000
FUNDING = 10_000_000_000
BAD_SIGNATURE = 1808
WRONG_NETWORK = 1801
CODES = {}


def request(network, account, epoch, nonce, valid_until, kind, payload):
    return (Cell().sint(network, 32).addr(tuple(account)).uint(epoch, 64).uint(nonce, 64)
            .uint(valid_until, 32).uint(kind, 8).ref(Cell().uint(payload, 32)))


class InteropTests(unittest.TestCase):
    def setUp(self):
        # Without this an empty code table would make every loop below vacuous.
        self.assertEqual(set(CODES), {'func', 'tol'}, 'both module languages must be loaded')
        self.signature = bytes.fromhex(FIXTURE['signature_hex'])
        self.key = bytes.fromhex(FIXTURE['signing_key_hex'])
        self.other = bytes.fromhex(FIXTURE['other_key_hex'])
        self.request = from_boc(bytes.fromhex(FIXTURE['request_boc_hex']))

    def submit(self, language, request, signature, key, expected):
        """Send one funded submission into a freshly deployed immutable module."""
        data = module_data(key, GLOBAL_ID)
        address = (WORKCHAIN, int.from_bytes(state_init(CODES[language], data).hash, 'big'))
        shard = active_account(address, CODES[language], data, BALANCE)
        envelope = Cell().uint(AUTH, 32).ref(request).maybe(None)
        body = submission(envelope, signature)
        emulator = Emulator(16)
        try:
            result = emulator.send(shard, internal((WORKCHAIN, 17), address, body, FUNDING, False))
            self.assertTrue(result['success'], f'{language}: emulator error, not a transaction')
            details = result.get('details', result)
            self.assertEqual(details.get('exit'), expected, f'{language}: {details}')
            after = from_boc(result['shard_account'])
            self.assertEqual(account_data(after)[0].hash, data.hash,
                             f'{language}: module must stay immutable')
            messages = outgoing(from_boc(result['transaction']))
            if expected != 0:
                self.assertEqual(messages, [], f'{language}: rejection must not emit AUTH')
                return None
            self.assertEqual(len(messages), 1, f'{language}: exactly one relay expected')
            return parse_message(messages[0]), envelope
        finally:
            emulator.close()

    def test_commitment_matches_the_independent_signer(self):
        self.assertEqual(commitment(self.request).hex(), FIXTURE['commitment_hex'],
                         'an unrelated implementation signed different commitment bytes')
        self.assertEqual(CONTEXT.hex(), FIXTURE['context_hex'])
        self.assertEqual(len(self.key), 1312)
        self.assertEqual(len(self.signature), 2420)

    def test_module_accepts_the_independent_signature(self):
        for language in CODES:
            wire, envelope = self.submit(language, self.request, self.signature, self.key, 0)
            self.assertEqual(wire['destination'], tuple(FIXTURE['fields']['account']),
                             f'{language}: relay must go to the signed account')
            self.assertEqual(wire['body'].hash, envelope.hash,
                             f'{language}: relay must preserve the exact AUTH body')
            self.assertFalse(wire['bounced'])

    def test_wrong_key_and_tampered_proof_are_rejected(self):
        for language in CODES:
            self.submit(language, self.request, self.signature, self.other, BAD_SIGNATURE)
            for offset in (0, 1210, 2419):
                tampered = bytearray(self.signature)
                tampered[offset] ^= 1
                self.submit(language, self.request, bytes(tampered), self.key, BAD_SIGNATURE)

    def test_every_signed_field_is_bound(self):
        base = dict(FIXTURE['fields'])
        # Each alteration stays structurally valid, so only the proof can reject it.
        for field, value in [('account', [0, 0x1235]), ('epoch', 2), ('nonce', 1),
                             ('valid_until', base['valid_until'] + 1), ('kind', 1),
                             ('payload', base['payload'] + 1)]:
            altered = request(**dict(base, **{field: value}))
            self.assertNotEqual(commitment(altered).hex(), FIXTURE['commitment_hex'], field)
            for language in CODES:
                self.submit(language, altered, self.signature, self.key, BAD_SIGNATURE)
        # A different network is refused before the proof is even considered.
        for language in CODES:
            self.submit(language, request(**dict(base, network=base['network'] + 1)),
                        self.signature, self.key, WRONG_NETWORK)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    import os
    os.environ.update(FUNC_PATH=str(build / 'crypto/func'), FIFT_PATH=str(build / 'crypto/fift'),
                      TOL_PATH=str(build / 'tol/tol'),
                      EMULATOR_PATH=os.environ.get('EMULATOR_PATH',
                                                   str(build / 'emulator/libemulator.so')))
    build_contracts(build, out)
    for language in ('func', 'tol'):
        CODES[language] = from_boc((out / f'module-{language}.boc').read_bytes())
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(InteropTests))
    (out / 'interop.json').write_text(json.dumps(
        {'success': result.wasSuccessful(), 'generator': FIXTURE['generator'],
         'commitment': FIXTURE['commitment_hex']}, indent=2, sort_keys=True) + '\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
