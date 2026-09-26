#!/usr/bin/env python3
"""Offline checksum-unit controls; partial metadata here is constructed data."""
import unittest

from test_x02_netlink_frames import CAPTURED
from x02_packet_identity import ingress_identity, nfqueue_identity

PACKET = CAPTURED[44:]
PARTIAL = PACKET[:26] + bytes.fromhex('fe36') + PACKET[28:]


class PacketIdentityControls(unittest.TestCase):
    def test_exact_captured_completed_udp_checksum(self):
        row = nfqueue_identity(PACKET, 0)
        self.assertEqual(row['checksum_field'], 0x6236)
        self.assertEqual(row['pseudo_header_seed'], 0xfe36)
        self.assertEqual(row['checksum_mode'], 'completed-checksum')

    def test_constructed_partial_to_partial_or_completed_identity(self):
        partial = nfqueue_identity(PARTIAL, 1)
        complete = ingress_identity(PACKET, 129, 54, 54)
        seeded = ingress_identity(PARTIAL, 9, 54, 54)
        self.assertEqual(partial['identity_sha256'], complete['identity_sha256'])
        self.assertEqual(partial['identity_sha256'], seeded['identity_sha256'])
        self.assertNotEqual(partial['raw_sha256'], complete['raw_sha256'])

    def test_wrong_partial_seed_rejects(self):
        bad = PARTIAL[:26] + b'\x12\x34' + PARTIAL[28:]
        with self.assertRaisesRegex(ValueError, '^partial UDP checksum is not exact pseudo-header seed$'):
            nfqueue_identity(bad, 1)

    def test_changed_packet_checksum_rejects(self):
        with self.assertRaisesRegex(ValueError, '^completed UDP checksum differs$'):
            nfqueue_identity(PACKET[:-1] + bytes([PACKET[-1] ^ 1]), 0)
        with self.assertRaisesRegex(ValueError, '^IPv4 header checksum differs$'):
            nfqueue_identity(PACKET[:10] + b'\0\0' + PACKET[12:], 0)

    def test_gso_unknown_truncated_and_conflicting_metadata_reject(self):
        for info, reason in ((2, 'GSO packet is outside fixed unit'),
                             (8, 'unknown NFQUEUE skb checksum metadata')):
            with self.subTest(info=info), self.assertRaisesRegex(ValueError, '^' + reason + '$'):
                nfqueue_identity(PACKET, info)
        with self.assertRaisesRegex(ValueError, '^ingress packet unit is truncated or padded$'):
            ingress_identity(PACKET, 129, 55, 54)
        with self.assertRaisesRegex(ValueError, '^unknown or conflicting packet checksum metadata$'):
            ingress_identity(PACKET, 137, 54, 54)
