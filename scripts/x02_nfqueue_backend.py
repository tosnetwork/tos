#!/usr/bin/env python3
"""Raw NFQUEUE backend using installed Linux ABI; never starts on import.

Lifecycle/capability/identity gates and live orchestration remain external.
Kernel ACK proves verdict handling, not socket delivery. GSO is rejected.
"""

from __future__ import annotations

from collections import deque
import socket
import struct
import time
from pathlib import Path

from x02_partial_sequence import DIRECTIONS, require


def attribute(kind: int, value: bytes) -> bytes:
    length = 4 + len(value)
    return struct.pack("=HH", length, kind) + value + bytes((-length) % 4)


def frame_end(raw: bytes, offset: int, length: int) -> int:
    """A terminal record may end at nlmsg_len/nla_len, without transport pad.

    Linux NLMSG_OK tests the unaligned declared length against remaining bytes;
    alignment determines the NEXT record, not extra bytes required after LAST.
    Captured NFQUEUE packet has nlmsg_len98 and datagram length98. Its final
    payload attribute has nla_len58 and ends exactly at byte98 as well.
    Interior records still need their entire zero padding before a next header.
    """
    end = offset + length
    require(end <= len(raw), "declared frame exceeds datagram")
    if end == len(raw):
        return end
    aligned = offset + ((length + 3) & ~3)
    require(aligned <= len(raw) and raw[end:aligned] == bytes(aligned - end),
            "incomplete or nonzero netlink padding")
    return aligned


def netlink_messages(raw: bytes) -> list[tuple[int, int, bytes]]:
    require(isinstance(raw, bytes) and len(raw) >= 16, "short netlink datagram")
    offset, messages = 0, []
    while offset < len(raw):
        require(len(raw) - offset >= 16, "short netlink header")
        length, kind, flags, seq, pid = struct.unpack_from("=IHHII", raw, offset)
        require(16 <= length <= len(raw) - offset, "invalid netlink length")
        require(kind in (2, 0x300), "unexpected netlink control or overflow")
        messages.append((kind, seq, raw[offset + 16:offset + length]))
        offset = frame_end(raw, offset, length)
    require(offset == len(raw), "netlink alignment differs")
    return messages


def attributes(raw: bytes) -> dict[int, bytes]:
    result = {}
    offset = 0
    while offset < len(raw):
        require(len(raw) - offset >= 4, "short netlink attribute")
        length, kind = struct.unpack_from("=HH", raw, offset)
        kind &= 0x3FFF
        require(4 <= length <= len(raw) - offset and kind not in result,
                "invalid or duplicate netlink attribute")
        result[kind] = raw[offset + 4:offset + length]
        offset = frame_end(raw, offset, length)
    require(offset == len(raw), "attribute alignment differs")
    return result


class QueueBackend:
    def __init__(self, ledger, stats_reader, first_queue: int = 32600):
        require(type(first_queue) is int and 0 <= first_queue <= 65512, "invalid queue base")
        self.ledger = ledger
        self.stats_reader = stats_reader
        require(stats_reader.read() == b"", "initial private queue stats not empty")
        self.ledger.append({"event": "queue_stats_initial_empty", "receipt": stats_reader.receipt})
        self.queues = {first_queue + ordinal: direction
                       for ordinal, direction in enumerate(DIRECTIONS)}
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
        self.sock.settimeout(2)
        self.sock.bind((0, 0))
        self.portid = self.sock.getsockname()[0]
        self.seq = 0
        self.buffer = deque()
        self.bound = set()
        self.last_id = {}

    def receive(self) -> list[tuple[int, int, bytes]]:
        raw, ancillary, flags, peer = self.sock.recvmsg(131072)
        require(peer[0] == 0 and not ancillary and not flags & socket.MSG_TRUNC,
                "untrusted or truncated netlink datagram")
        self.ledger.append({"event": "kernel_netlink", "monotonic_ns": time.monotonic_ns(),
                            "peer": list(peer), "raw_hex": raw.hex()})
        return netlink_messages(raw)

    def request(self, operation: int, queue: int, attrs: bytes) -> None:
        self.seq += 1
        require(self.seq < 2**32, "request sequence wrapped")
        payload = struct.pack("!BBH", socket.AF_INET, 0, queue) + attrs
        raw = struct.pack("=IHHII", 16 + len(payload), 0x300 | operation,
                          5, self.seq, self.portid) + payload
        self.ledger.append({"event": "netlink_request", "monotonic_ns": time.monotonic_ns(),
                            "seq": self.seq, "raw_hex": raw.hex()})
        require(self.sock.sendto(raw, (0, 0)) == len(raw), "short netlink send")
        deadline, acknowledged = time.monotonic() + 2, False
        while not acknowledged:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "kernel ACK deadline exceeded")
            self.sock.settimeout(remaining)
            messages = self.receive()
            require(time.monotonic() < deadline, "late kernel ACK or packet batch")
            for kind, seq, body in messages:
                if kind == 0x300:
                    require(len(self.buffer) < 256, "userspace queue backlog exceeded")
                    self.buffer.append(body)
                else:
                    require(seq == self.seq and not acknowledged and len(body) >= 20,
                            "unexpected or malformed kernel ACK")
                    error = struct.unpack_from("=i", body)[0]
                    require(error == 0, f"kernel rejected request: {error}")
                    # ACK includes the original message header, even with capped body.
                    _, original_kind, _, original_seq, original_pid = struct.unpack_from("=IHHII", body, 4)
                    require(original_kind == 0x300 | operation and original_seq == self.seq
                            and original_pid == self.portid, "ACK request identity differs")
                    acknowledged = True
        self.sock.settimeout(2)

    def bind(self) -> None:
        try:
            for queue in self.queues:
                self.request(2, queue, attribute(1, struct.pack("!BBH", 1, 0, socket.AF_INET)))
                self.bound.add(queue)
                # Preserve GSO metadata and fail on GSO rather than silently segmenting it.
                attrs = attribute(2, struct.pack("!IB", 65531, 2))
                attrs += attribute(3, struct.pack("!I", 256))
                attrs += attribute(4, struct.pack("!I", 5))
                attrs += attribute(5, struct.pack("!I", 4))
                self.request(2, queue, attrs)
            require(not self.buffer, "packets arrived before rules were authorized")
        except Exception:
            self.sock.close()
            raise

    def process_one(self, adapter) -> None:
        while not self.buffer:
            for kind, seq, body in self.receive():
                require(kind == 0x300, "unsolicited kernel ACK")
                require(len(self.buffer) < 256, "userspace queue backlog exceeded")
                self.buffer.append(body)
        body = self.buffer.popleft()
        require(len(body) >= 4, "short queue message")
        family, version, queue = struct.unpack_from("!BBH", body)
        require(family == socket.AF_INET and version == 0 and queue in self.bound,
                "queue family, version or identity differs")
        attrs = attributes(body[4:])
        require(1 in attrs and len(attrs[1]) == 7 and 10 in attrs, "missing packet header/payload")
        packet_id, protocol, hook = struct.unpack("!IHB", attrs[1])
        require(protocol == 0x0800 and hook == 3, "not IPv4 LOCAL_OUT")
        if queue in self.last_id:
            require(self.last_id[queue] < 2**32 - 1
                    and packet_id == self.last_id[queue] + 1, "queue packet ID gap or wrap")
        if 13 in attrs:
            require(len(attrs[13]) == 4 and struct.unpack("!I", attrs[13])[0] == len(attrs[10]),
                    "packet capture truncated")
        if 14 in attrs:
            require(len(attrs[14]) == 4 and struct.unpack("!I", attrs[14])[0] & 2 == 0,
                    "GSO packet is outside fixed unit")
        self.last_id[queue] = packet_id
        def submit(dropped):
            self.request(1, queue, attribute(2, struct.pack("!II", 0 if dropped else 1, packet_id)))
        adapter.decide(self.queues[queue], packet_id, attrs[10], submit)

    def health(self, require_empty: bool = False) -> dict:
        raw = self.stats_reader.read()
        self.ledger.append({"event": "kernel_queue_stats", "monotonic_ns": time.monotonic_ns(),
                            "raw_hex": raw.hex(), "portid": self.portid})
        rows = {}
        for line in raw.decode("ascii").splitlines():
            values = [int(value) for value in line.split()]
            require(len(values) == 9, "unknown kernel queue stats format")
            if values[0] in self.bound:
                require(values[0] not in rows and values[1] == self.portid
                        and values[3:5] == [2, 65531] and values[5:7] == [0, 0],
                        "queue identity/config/overflow differs")
                rows[values[0]] = values
        require(set(rows) == self.bound, "bound queue disappeared")
        if require_empty:
            require(not self.buffer and all(row[2] == 0 for row in rows.values()),
                    "queue is not drained")
        return rows

    def close_drained(self) -> None:
        self.health(require_empty=True)
        for queue in sorted(self.bound):
            self.request(2, queue, attribute(1, struct.pack("!BBH", 2, 0, socket.AF_INET)))
        self.bound.clear()
        require(self.stats_reader.read() == b"", "final private queue stats not empty")
        self.ledger.append({"event": "queue_stats_final_empty"})
        self.sock.close()
