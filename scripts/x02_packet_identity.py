#!/usr/bin/env python3
"""Exact IPv4 UDP identity across declared checksum completion, no mutation.

NFQUEUE and AF_PACKET originals retain every byte. Only the UDP checksum field
is zeroed in the comparison key, after validating the actual checksum mode.
GSO, fragments, padding, unsupported metadata and unknown checksum units reject.
"""
import hashlib
import socket
import struct

from x02_partial_adapter import udp_datagram
from x02_partial_sequence import require


def checksum(raw):
    raw += bytes(len(raw) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(raw) // 2), raw))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet_identity(raw, partial_checksum):
    endpoint = udp_datagram(raw)
    require(type(partial_checksum) is bool, 'checksum mode is not explicit boolean')
    ihl = (raw[0] & 15) * 4
    require(checksum(raw[:ihl]) == 0, 'IPv4 header checksum differs')
    udp = raw[ihl:]
    pseudo = raw[12:20] + struct.pack('!BBH', 0, socket.IPPROTO_UDP, len(udp))
    actual = struct.unpack_from('!H', udp, 6)[0]
    seed = (~checksum(pseudo)) & 65535
    if partial_checksum:
        require(actual == seed, 'partial UDP checksum is not exact pseudo-header seed')
        mode = 'pseudo-header-seed'
    else:
        require(actual == 0 or checksum(pseudo + udp) == 0, 'completed UDP checksum differs')
        mode = 'disabled-ipv4-checksum' if actual == 0 else 'completed-checksum'
    canonical = raw[:ihl + 6] + b'\0\0' + raw[ihl + 8:]
    return {'endpoint': endpoint, 'raw_sha256': hashlib.sha256(raw).hexdigest(),
            'identity_sha256': hashlib.sha256(canonical).hexdigest(),
            'checksum_mode': mode, 'checksum_field': actual, 'pseudo_header_seed': seed,
            'canonical_rule': 'udp-checksum-field-only-after-mode-validation.v1'}


def nfqueue_identity(raw, skb_info):
    require(type(skb_info) is int and 0 <= skb_info <= 7, 'unknown NFQUEUE skb checksum metadata')
    require(not skb_info & 2, 'GSO packet is outside fixed unit')
    return {**packet_identity(raw, bool(skb_info & 1)), 'nfqa_skb_info': skb_info}


def ingress_identity(raw, status, wire_len, captured_len):
    require(type(status) is int and status & ~(1 | 8 | 128) == 0
            and not (status & 8 and status & 128), 'unknown or conflicting packet checksum metadata')
    require(wire_len == captured_len == len(raw), 'ingress packet unit is truncated or padded')
    return {**packet_identity(raw, bool(status & 8)), 'tp_status': status,
            'wire_len': wire_len, 'captured_len': captured_len}
