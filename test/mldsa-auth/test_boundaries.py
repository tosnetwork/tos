#!/usr/bin/env python3
"""Module-side boundaries the two-hop suite does not pin down.

These execute the real compiled modules in the emulator. The funding cases
classify the two distinct failures around the point where a submission stops
being relayable, and record the measured values rather than asserting a constant
that only holds at one gas price. Fixture keys are PUBLIC TEST DATA.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test/auth-extensions'))
from build_contracts import build_contracts
from protocol import (AUTH, Cell, CONTEXT, commitment, emulator_library, from_boc,
                      module_data, submission, Signer)
from native import (NOW, GLOBAL_ID, Emulator, account_data, active_account, internal,
                    outgoing, state_init)

BALANCE = 100_000_000_000
FUNDING = 10_000_000_000
BAD_SIGNATURE, BAD_MODULE, EXPIRED, BAD_OPERATION, CELL_UNDERFLOW = 1808, 1809, 1805, 1811, 9
CODES = {}
SIGNER = None
MEASURED = {}


def request(account=None, network=GLOBAL_ID, epoch=1, nonce=0, valid_until=NOW + 600,
            kind=0, payload=7, extra_ref=False, trailing_bits=0, raw_account=None):
    cell = Cell().sint(network, 32)
    if raw_account is None:
        cell.addr(account if account is not None else (0, 0x1234))
    else:
        raw_account(cell)
    cell.uint(epoch, 64).uint(nonce, 64).uint(valid_until, 32).uint(kind, 8)
    if trailing_bits:
        cell.uint(0, trailing_bits)
    cell.ref(Cell().uint(payload, 32))
    if extra_ref:
        cell.ref(Cell().uint(1, 8))
    return cell


class Boundaries(unittest.TestCase):
    def setUp(self):
        # Without this an empty code table would make every loop below vacuous.
        self.assertEqual(set(CODES), {'func', 'tol'}, 'both module languages must be loaded')
        self.data = module_data(SIGNER.public_key(0), GLOBAL_ID)

    def address(self, language, workchain=0):
        return (workchain, int.from_bytes(state_init(CODES[language], self.data).hash, 'big'))

    def submit(self, language, req, workchain=0, value=FUNDING, envelope_bits=0):
        address = self.address(language, workchain)
        shard = active_account(address, CODES[language], self.data, BALANCE)
        envelope = Cell().uint(AUTH, 32)
        if envelope_bits:
            envelope.uint(0, envelope_bits)
        envelope = envelope.ref(req).maybe(None)
        _, signature = SIGNER.sign(commitment(req), CONTEXT, 0)
        emulator = Emulator(16)
        try:
            result = emulator.send(shard, internal((workchain, 17), address,
                                                   submission(envelope, signature), value, False))
            self.assertTrue(result['success'], f'{language}: emulator error, not a transaction')
            details = result.get('details', result)
            after = from_boc(result['shard_account'])
            self.assertEqual(account_data(after)[0].hash, self.data.hash,
                             f'{language}: module must stay immutable')
            action = details.get('action') or {}
            messages = outgoing(from_boc(result['transaction']))
            return details.get('exit'), action.get('success'), len(messages)
        finally:
            emulator.close()

    def expect(self, req, exit_code, note, **kwargs):
        for language in CODES:
            got, _, emitted = self.submit(language, req, **kwargs)
            self.assertEqual(got, exit_code, f'{language}: {note}')
            self.assertEqual(emitted, 0 if exit_code else 1, f'{language}: {note}: emitted {emitted}')

    def test_expiry_window_boundaries(self):
        self.expect(request(valid_until=NOW), EXPIRED, 'an expiry of now must be refused')
        self.expect(request(valid_until=NOW + 1), 0, 'one second ahead is inside the window')
        self.expect(request(valid_until=NOW + 3600), 0, 'the last second is inside the window')
        self.expect(request(valid_until=NOW + 3601), EXPIRED, 'one second past the window')

    def test_request_kind_bound(self):
        self.expect(request(kind=2), 0, 'the highest existing kind is relayable')
        self.expect(request(kind=3), BAD_OPERATION, 'an unknown kind must be refused')

    def test_request_and_envelope_are_parsed_exactly(self):
        self.expect(request(extra_ref=True), CELL_UNDERFLOW, 'a second reference is not signed')
        self.expect(request(trailing_bits=8), CELL_UNDERFLOW, 'trailing request bits are not signed')
        self.expect(request(), CELL_UNDERFLOW, 'extra envelope bits', envelope_bits=8)

    def test_destination_encodings(self):
        self.expect(request(account=(-1, 0x1234)), BAD_MODULE, 'another workchain')
        self.expect(request(raw_account=lambda c: c.uint(0, 2)), BAD_MODULE, 'addr_none')
        # addr_std carrying an anycast prefix is longer than the canonical 267 bits.
        self.expect(request(raw_account=lambda c: c.uint(0b100, 3).uint(1, 1).uint(1, 5)
                            .uint(0, 1).sint(0, 8).uint(0x1234, 256)), BAD_MODULE, 'anycast')
        # Sized to exactly 267 bits so the length check passes and only the
        # address-tag comparison can reject it.
        self.expect(request(raw_account=lambda c: c.uint(0b01, 2).uint(256, 9).uint(0x1234, 256)),
                    BAD_MODULE, 'addr_extern at the canonical length')

    def test_the_module_refuses_to_relay_to_itself(self):
        for language in CODES:
            me = self.address(language)
            got, _, emitted = self.submit(language, request(account=me))
            self.assertEqual(got, BAD_MODULE, f'{language}: a self-send must be refused')
            self.assertEqual(emitted, 0, f'{language}: a refused self-send must emit nothing')

    def test_funding_separates_compute_from_forwarding(self):
        """Below the relayable point the proof still verifies; the action fails."""
        for workchain in (0, -1):
            # The signed destination must share the module's workchain.
            target = request(account=(workchain, 0x1234))
            for language in CODES:
                low, high = 1_000_000, 4_000_000_000
                while low < high:
                    middle = (low + high) // 2
                    exit_code, action, emitted = self.submit(language, target, workchain, middle)
                    if exit_code == 0 and emitted == 1:
                        high = middle
                    else:
                        low = middle + 1
                MEASURED.setdefault(language, {})[str(workchain)] = low
                exit_code, action, emitted = self.submit(language, target, workchain, low)
                self.assertEqual((exit_code, action, emitted), (0, True, 1),
                                 f'{language}/wc{workchain}: the measured point must relay')
                exit_code, action, emitted = self.submit(language, target, workchain, low - 1)
                self.assertEqual(exit_code, 0,
                                 f'{language}/wc{workchain}: verification still completes below it')
                self.assertFalse(action, f'{language}/wc{workchain}: the action phase must fail')
                self.assertEqual(emitted, 0, f'{language}/wc{workchain}: nothing may be relayed')


def main():
    global SIGNER
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--signer', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    os.environ.update(FUNC_PATH=str(build / 'crypto/func'), FIFT_PATH=str(build / 'crypto/fift'),
                      TOL_PATH=str(build / 'tol/tol'),
                      EMULATOR_PATH=str(emulator_library(build)))
    build_contracts(build, out)
    SIGNER = Signer(args.signer)
    for language in ('func', 'tol'):
        CODES[language] = from_boc((out / f'module-{language}.boc').read_bytes())
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Boundaries))
    (out / 'boundaries.json').write_text(json.dumps(
        {'success': result.wasSuccessful(),
         'units': 'nanotomis; the smallest inbound value that still relays',
         'relayable_from': MEASURED}, indent=2, sort_keys=True) + '\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
