#!/usr/bin/env python3
"""Offline exact framing controls, never a kernel/network compatibility verdict."""
import struct
import unittest

from x02_nfqueue_backend import attributes, frame_end, netlink_messages

# Actual dd3 positive/kernel.jsonl final98-byte kernel_netlink record, retained.
CAPTURED = bytes.fromhex(
    '6200000000030000000000000000000002007f580b0001000000000208000300'
    '08000600000000013a000a00450000360002400040113cb27f0000017f000002'
    '7d0080e8002262365830322f323032363039323630303030303030312f30302f3031')


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
        with self.assertRaisesRegex(ValueError, '^invalid netlink length$'):
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
