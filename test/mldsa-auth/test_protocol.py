#!/usr/bin/env python3
"""Wire-codec tests only. These are not substitutes for native transaction E2E."""
import re
import unittest
from protocol import (ROOT, Cell, from_boc, chain, module_data, submission,
                      commitment, parse_message, CONTEXT, SUBMIT)


def raw_bytes(cell):
    result = b''
    while True:
        assert len(cell.bits) % 8 == 0
        size = len(cell.bits) // 8
        assert size <= 127 and len(cell.refs) <= 1
        assert not cell.refs or size == 127
        result += int(cell.bits or '0', 2).to_bytes(size, 'big')
        if not cell.refs:
            return result
        cell = cell.refs[0]


class WireTests(unittest.TestCase):
    def test_canonical_bytes_and_boc_roundtrip(self):
        for size in (0, 1, 126, 127, 128, 1312, 2420):
            with self.subTest(size=size):
                original = bytes(i % 256 for i in range(size))
                value = chain(original)
                decoded = from_boc(value.boc())
                self.assertEqual(raw_bytes(decoded), original)
                self.assertEqual(decoded.hash, value.hash)

    def test_both_contracts_use_exact_pure_context_bytes(self):
        self.assertEqual(len(CONTEXT), 21)
        for language in ('fc', 'tol'):
            source = (ROOT / 'crypto/smartcont' / ('mldsa44-auth-module.' + language)).read_text()
            match = re.search(r'store_[uU]int\((0x[0-9a-f]+), 168\)', source) if language == 'fc' else re.search(r'storeUint\((0x[0-9a-f]+), 168\)', source)
            self.assertIsNotNone(match)
            self.assertEqual(int(match[1], 16).to_bytes(21, 'big'), CONTEXT)

    def test_stored_key_is_explicit_network_bound_and_exact_length(self):
        key = bytes(i % 251 for i in range(1312))
        state = module_data(key, -42).slice()
        self.assertEqual(state.sint(32), -42)
        self.assertEqual(raw_bytes(state.ref()), key)
        state.end()
        for size in (0, 1311, 1313):
            with self.assertRaises(ValueError):
                module_data(bytes(size), 42)

    def test_commitment_covers_request_fields_and_referenced_payload(self):
        def request(network=42, account=(0, 99), epoch=1, nonce=0, expiry=1000, kind=0, payload=7):
            return (Cell().sint(network, 32).addr(account).uint(epoch, 64).uint(nonce, 64)
                    .uint(expiry, 32).uint(kind, 8).ref(Cell().uint(payload, 8)))
        base = request()
        digest = commitment(base)
        self.assertEqual(len(digest), 32)
        self.assertNotEqual(digest, base.hash)
        self.assertEqual(digest, commitment(from_boc(base.boc())))
        for field, value in [('network', 43), ('account', (0, 100)), ('epoch', 2), ('nonce', 1),
                             ('expiry', 1001), ('kind', 1), ('payload', 8)]:
            self.assertNotEqual(digest, commitment(request(**{field: value})))

    def test_submission_and_actual_internal_message_decoder(self):
        envelope = Cell().uint(0x41555448, 32).ref(Cell().uint(1, 8)).maybe(None)
        sig = bytes(i % 251 for i in range(2420))
        body = submission(envelope, sig, query_id=17)
        cursor = from_boc(body.boc()).slice()
        self.assertEqual(cursor.uint(32), SUBMIT)
        self.assertEqual(cursor.uint(64), 17)
        self.assertEqual(cursor.ref().hash, envelope.hash)
        self.assertEqual(raw_bytes(cursor.ref()), sig)
        cursor.end()
        msg = (Cell().uint(6, 4).addr((0, 1)).addr((0, 2)).coins(100)
               .uint(0, 1).coins(0).coins(7).uint(0, 64).uint(1000, 32)
               .uint(0, 1).uint(1, 1).ref(envelope))
        parsed = parse_message(from_boc(msg.boc()))
        self.assertEqual(parsed['sender'], (0, 1))
        self.assertEqual(parsed['destination'], (0, 2))
        self.assertEqual(parsed['value'], 100)
        self.assertEqual(parsed['forward_fee'], 7)
        self.assertEqual(parsed['created_lt'], 0)
        self.assertEqual(parsed['created_at'], 1000)
        self.assertEqual(parsed['bounce'], 1)
        self.assertEqual(parsed['bounced'], 0)
        self.assertEqual(parsed['body'].hash, envelope.hash)
        for size in (0, 2419, 2421):
            with self.assertRaises(ValueError):
                submission(envelope, bytes(size))


if __name__ == '__main__':
    unittest.main(verbosity=2)
