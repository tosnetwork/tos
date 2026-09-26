#!/usr/bin/env python3
"""Partial-loss callback core; no queue binding, rule installation or live claim.

An external backend must authenticate packet metadata, serialize callbacks and
prove offload/queue health. Successful verdict submission alone is not delivery.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from pathlib import Path

import x02_partial_sequence as sequence


def udp_datagram(raw: bytes) -> tuple[str, int, str, int]:
    """Accept one complete, unfragmented IPv4 UDP datagram without padding."""
    sequence.require(isinstance(raw, bytes) and len(raw) >= 28, "short IPv4 UDP packet")
    version, ihl = raw[0] >> 4, (raw[0] & 15) * 4
    sequence.require(version == 4 and 20 <= ihl <= 60 and len(raw) >= ihl + 8,
                     "invalid IPv4 header")
    total, fragment = struct.unpack_from("!H", raw, 2)[0], struct.unpack_from("!H", raw, 6)[0]
    sequence.require(total == len(raw), "truncated, padded or aggregated packet")
    sequence.require(fragment & 0xBFFF == 0, "fragment or reserved IPv4 flag")
    sequence.require(raw[9] == 17, "not UDP")
    src_port, dst_port, udp_length = struct.unpack_from("!HHH", raw, ihl)
    sequence.require(udp_length >= 8 and udp_length == total - ihl,
                     "UDP length differs from complete datagram")
    src = ".".join(str(value) for value in raw[12:16])
    dst = ".".join(str(value) for value in raw[16:20])
    return src, src_port, dst, dst_port


class DurableLedger:
    """Exclusive new file; persist intent before attempting a kernel verdict."""

    def __init__(self, path: Path):
        self.stream = path.open("xb", buffering=0)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            self.stream.close()
            raise

    def append(self, row: dict) -> None:
        payload = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        view = memoryview(payload)
        while view:
            written = self.stream.write(view)
            sequence.require(written is not None and written > 0, "ledger write stalled")
            view = view[written:]
        os.fsync(self.stream.fileno())

    def close(self) -> None:
        self.stream.close()


class DecisionAdapter:
    """One serialized owner for callbacks; lifecycle/identity gates are external.

    `submit` receives a boolean dropped verdict; it must raise on submission
    failure. Its return is recorded as submission only, never proof of delivery.
    Any error poisons the whole adapter; caller must remove rules and retain raw.
    """

    def __init__(self, policy: dict, endpoints: dict, ledger: DurableLedger):
        sequence.validate_policy(policy)
        sequence.require(isinstance(endpoints, dict)
                         and set(endpoints) == set(sequence.DIRECTIONS), "missing endpoints")
        normalized = {}
        for direction, value in endpoints.items():
            sequence.require(isinstance(value, tuple) and len(value) == 4,
                             "endpoint must be an IPv4 UDP four-tuple")
            for ip in (value[0], value[2]):
                sequence.require(isinstance(ip, str), "endpoint IP is not text")
                parts = ip.split(".")
                sequence.require(len(parts) == 4 and all(part.isascii() and part.isdigit()
                                 and str(int(part)) == part and 0 <= int(part) <= 255
                                 for part in parts), "noncanonical IPv4 endpoint")
            sequence.require(all(type(port) is int and 0 < port < 65536
                                 for port in (value[1], value[3])), "invalid UDP endpoint port")
            normalized[direction] = value
        sequence.require(len(set(normalized.values())) == 24, "aliased endpoint directions")
        self.policy, self.endpoints, self.ledger = policy, normalized, ledger
        self.counts = {direction: {"seen": 0, "submitted_drop": 0, "submitted_accept": 0}
                       for direction in sequence.DIRECTIONS}
        self.failed = False
        self.pending = None

    def decide(self, direction: str, queue_packet_id: int, raw: bytes, submit) -> None:
        if self.failed or self.pending is not None:
            self.failed = True
            raise ValueError("adapter is failed or busy")
        try:
            sequence.require(isinstance(direction, str) and direction in self.endpoints,
                             "unknown queue direction")
            sequence.require(type(queue_packet_id) is int and 0 <= queue_packet_id < 2**32,
                             "invalid queue packet ID")
            sequence.require(udp_datagram(raw) == self.endpoints[direction],
                             "queued packet differs from frozen endpoints")
            count = self.counts[direction]
            index = count["seen"]
            dropped = sequence.selected_drop(self.policy, direction, index)
            intent = {"event": "intent", "phase": "partial_four_live", "direction": direction,
                      "index": index, "queue_packet_id": queue_packet_id,
                      "monotonic_ns": time.monotonic_ns(), "packet_hex": raw.hex(),
                      "packet_sha256": hashlib.sha256(raw).hexdigest(), "dropped": dropped}
            self.pending = intent
            self.ledger.append(intent)
            submit(dropped)
            sequence.require(not self.failed, "adapter poisoned during submission")
            self.ledger.append({"event": "verdict_submitted", "direction": direction,
                                "index": index, "queue_packet_id": queue_packet_id,
                                "monotonic_ns": time.monotonic_ns(), "dropped": dropped})
            count["seen"] += 1
            count["submitted_drop" if dropped else "submitted_accept"] += 1
            self.pending = None
        except Exception:
            self.failed = True
            raise
