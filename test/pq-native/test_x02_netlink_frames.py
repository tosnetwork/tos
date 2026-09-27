#!/usr/bin/env python3
"""Offline exact framing controls, never a kernel/network compatibility verdict."""
import hashlib
import struct
import unittest

from x02_nfqueue_backend import attributes, frame_end, netlink_messages

# Actual dd3 positive/kernel.jsonl final98-byte kernel_netlink record, retained.
CAPTURED = bytes.fromhex(
    '6200000000030000000000000000000002007f580b0001000000000208000300'
    '08000600000000013a000a00450000360002400040113cb27f0000017f000002'
    '7d0080e8002262365830322f323032363039323630303030303030312f30302f3031')


# Both unaligned kernel datagrams retained in dd3 positive/kernel.jsonl (sha256
# bcb655a7...), file lines 110 and 116 counted from 1, keyed by the sha256 of their exact bytes. The
# dd3 parser rejected both in its message iterator and, once a datagram is padded,
# in its attribute iterator; each ends its last record at the declared length.
DD3_DATAGRAMS = {
    '416b4a9191a27a347c5ad1e919d7dd2e714641ceefb1c4fa4f81fc8b6fd4b0e2': bytes.fromhex(
        '6200000000030000000000000000000002007f580b0001000000000108000300'
        '08000600000000013a000a00450000360001400040113cb37f0000017f000002'
        '7d0080e8002262375830322f323032363039323630303030303030312f30302f3030'),
    '359da453805293e81ecb4bc7871fcfe59c63530914b8a1fe67ff33b9320cde33': CAPTURED,
}


class Dd3RetainedDatagramControls(unittest.TestCase):
    def test_retained_bytes_are_the_recorded_datagrams(self):
        for digest, raw in DD3_DATAGRAMS.items():
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            self.assertEqual((len(raw), struct.unpack_from('=I', raw)[0]), (98, 98))

    def accepted(self, parse, raw):
        # A refusal of a valid retained frame is this test's failure, not a setup error.
        try:
            return parse(raw)
        except ValueError as error:
            self.fail(f'retained frame refused: {error}')

    def test_both_iterators_accept_a_terminal_record_at_its_declared_length(self):
        # No subTest: one refusal must be exactly one failure for the mutant guard.
        for raw in DD3_DATAGRAMS.values():
            (kind, seq, body), = self.accepted(netlink_messages, raw)
            self.assertEqual((kind, seq), (0x300, 0))
            attrs = self.accepted(attributes, body[4:])
            self.assertEqual(set(attrs), {1, 6, 10})
            # The payload attribute is the one whose end is not 4-byte aligned.
            self.assertEqual(len(attrs[10]) % 4, 2)
            padded = self.accepted(netlink_messages, raw + b'\0\0')
            self.assertEqual(padded, netlink_messages(raw))
            self.assertEqual(self.accepted(attributes, padded[0][2][4:]), attrs)

    def test_overrun_truncation_and_nonzero_padding_still_reject(self):
        for digest, raw in DD3_DATAGRAMS.items():
            body = netlink_messages(raw)[0][2][4:]
            last = len(body) - 58
            with self.subTest(datagram=digest[:16]):
                with self.assertRaisesRegex(ValueError, '^invalid netlink length$'):
                    netlink_messages(struct.pack('=I', 99) + raw[4:])
                with self.assertRaisesRegex(ValueError, '^invalid or duplicate netlink attribute$'):
                    attributes(body[:last] + struct.pack('=H', 59) + body[last + 2:])
                with self.assertRaisesRegex(ValueError, '^invalid or duplicate netlink attribute$'):
                    attributes(body[:-1])
                with self.assertRaisesRegex(ValueError, '^short netlink attribute$'):
                    attributes(body[:last + 3])
                with self.assertRaisesRegex(ValueError, '^incomplete or nonzero netlink padding$'):
                    attributes(body + b'\1\0' + struct.pack('=HHI', 8, 7, 1))
                with self.assertRaisesRegex(ValueError, '^incomplete or nonzero netlink padding$'):
                    netlink_messages(raw + b'\0\1' + raw)


class NetlinkFrameControls(unittest.TestCase):
    def test_actual_complete_unpadded_message_and_attribute(self):
        self.assertEqual(len(CAPTURED), 98)
        messages = netlink_messages(CAPTURED)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][:2], (0x300, 0))
        attrs = attributes(messages[0][2][4:])
        self.assertEqual(set(attrs), {1, 6, 10})
        self.assertEqual(len(attrs[10]), 54)
        self.assertEqual(attrs[10][:4], bytes.fromhex('45000036'))

    def test_terminal_remainders_and_full_padding(self):
        for remainder in (1, 2, 3):
            with self.subTest(remainder=remainder):
                length = 16 + remainder
                raw = struct.pack('=IHHII', length, 0x300, 0, 0, 0) + bytes(remainder)
                self.assertEqual(netlink_messages(raw), [(0x300, 0, bytes(remainder))])
                padded = raw + bytes((-length) % 4)
                self.assertEqual(netlink_messages(padded), netlink_messages(raw))
                attr = struct.pack('=HH', 4 + remainder, 10) + bytes(remainder)
                self.assertEqual(attributes(attr), {10: bytes(remainder)})
                self.assertEqual(attributes(attr + bytes((-len(attr)) % 4)), attributes(attr))

    def test_two_records_require_complete_intermediate_alignment(self):
        padded = CAPTURED + b'\0\0'
        self.assertEqual(netlink_messages(padded + CAPTURED), netlink_messages(CAPTURED) * 2)
        with self.assertRaisesRegex(ValueError, '^incomplete or nonzero netlink padding$'):
            netlink_messages(CAPTURED + CAPTURED)

    def test_nonzero_intermediate_padding_rejects(self):
        with self.assertRaisesRegex(ValueError, '^incomplete or nonzero netlink padding$'):
            netlink_messages(CAPTURED + b'\1\0' + CAPTURED)

    def test_truncated_logical_body_and_dangling_bytes_reject(self):
        with self.assertRaisesRegex(ValueError, '^invalid netlink length$'):
            netlink_messages(CAPTURED[:-1])
        with self.assertRaisesRegex(ValueError, '^incomplete or nonzero netlink padding$'):
            netlink_messages(CAPTURED + b'\0')
        with self.assertRaisesRegex(ValueError, '^short netlink header$'):
            netlink_messages(CAPTURED + b'\0\0\0')
        with self.assertRaisesRegex(ValueError, '^short netlink datagram$'):
            netlink_messages(b'')

    def test_duplicate_and_truncated_attributes_reject(self):
        body = netlink_messages(CAPTURED)[0][2][4:]
        with self.assertRaisesRegex(ValueError, '^invalid or duplicate netlink attribute$'):
            attributes(body + b'\0\0' + struct.pack('=HHI', 8, 6, 1))
        with self.assertRaisesRegex(ValueError, '^invalid or duplicate netlink attribute$'):
            attributes(body[:-1])
        with self.assertRaisesRegex(ValueError, '^short netlink attribute$'):
            attributes(body + b'\0\0\0')


if __name__ == '__main__':
    unittest.main()
