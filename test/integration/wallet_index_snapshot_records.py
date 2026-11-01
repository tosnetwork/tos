"""Read, edit and write wallet-index snapshot files for the native red controls.

The format is `TOSIDX01`, a four-byte big-endian schema version, then strictly
increasing unique records, each a big-endian four-byte key length and value
length followed by the bytes, and an all-zero length pair. This module reads
it as strictly as the index tool does, so an edited file differs from an
honest one only in the edit the scenario names.
"""

import struct
from dataclasses import dataclass, field

MAGIC = b"TOSIDX01"
EVENT_TAG = 0x12
CHECKPOINT_KEY = b"\0\x20"
# A block identity as the index stores it: tag(1) workchain(4) shard(8)
# seqno(4) root hash(32) file hash(32).
BLOCK_KEY_BYTES = 1 + 4 + 8 + 4 + 32 + 32


@dataclass
class Snapshot:
    schema: int
    records: list[tuple[bytes, bytes]] = field(default_factory=list)

    def get(self, key: bytes) -> bytes | None:
        for existing, value in self.records:
            if existing == key:
                return value
        return None

    def put(self, key: bytes, value: bytes) -> None:
        """Insert or replace a record, keeping the records in key order."""
        self.records = [(k, v) for k, v in self.records if k != key]
        self.records.append((key, value))
        self.records.sort(key=lambda record: record[0])

    def delete(self, key: bytes) -> None:
        before = len(self.records)
        self.records = [(k, v) for k, v in self.records if k != key]
        if len(self.records) == before:
            raise KeyError(key.hex())

    def events(self, account: bytes | None = None) -> list[tuple[bytes, int, bytes]]:
        """History rows (account, lt, value), newest first within an account."""
        rows = []
        for key, value in self.records:
            if len(key) == 41 and key[0] == EVENT_TAG:
                owner, lt = parse_event_key(key)
                if account is None or owner == account:
                    rows.append((owner, lt, value))
        return rows


def parse(data: bytes) -> Snapshot:
    if len(data) < 12 or data[:8] != MAGIC:
        raise ValueError("not a wallet-index snapshot")
    (schema,) = struct.unpack(">I", data[8:12])
    snapshot = Snapshot(schema)
    offset = 12
    previous: bytes | None = None
    while True:
        if offset + 8 > len(data):
            raise ValueError("truncated snapshot")
        key_size, value_size = struct.unpack(">II", data[offset : offset + 8])
        offset += 8
        if key_size == 0 and value_size == 0:
            break
        if key_size == 0 or offset + key_size + value_size > len(data):
            raise ValueError("malformed or truncated record")
        key = data[offset : offset + key_size]
        value = data[offset + key_size : offset + key_size + value_size]
        offset += key_size + value_size
        if previous is not None and key <= previous:
            raise ValueError("snapshot keys are not strictly ordered")
        snapshot.records.append((key, value))
        previous = key
    if offset != len(data):
        raise ValueError("trailing data in snapshot")
    return snapshot


def encode(snapshot: Snapshot) -> bytes:
    keys = [key for key, _ in snapshot.records]
    if keys != sorted(set(keys)):
        raise ValueError("records are not strictly ordered")
    parts = [MAGIC, struct.pack(">I", snapshot.schema)]
    for key, value in snapshot.records:
        parts.append(struct.pack(">II", len(key), len(value)))
        parts.append(key)
        parts.append(value)
    parts.append(bytes(8))
    return b"".join(parts)


def event_key(account: bytes, lt: int) -> bytes:
    if len(account) != 32:
        raise ValueError("an account is 32 bytes")
    return bytes([EVENT_TAG]) + account + struct.pack(">Q", ~lt & (1 << 64) - 1)


def parse_event_key(key: bytes) -> tuple[bytes, int]:
    if len(key) != 41 or key[0] != EVENT_TAG:
        raise ValueError("not an event key")
    (stored,) = struct.unpack(">Q", key[33:])
    return key[1:33], ~stored & (1 << 64) - 1


@dataclass
class Checkpoint:
    anchor: bytes
    committed: bytes

    def seqno(self) -> int:
        return struct.unpack(">I", self.committed[13:17])[0]


def checkpoint(snapshot: Snapshot) -> Checkpoint:
    value = snapshot.get(CHECKPOINT_KEY)
    if value is None or len(value) != 2 * BLOCK_KEY_BYTES:
        raise ValueError("snapshot has no replay checkpoint")
    return Checkpoint(value[:BLOCK_KEY_BYTES], value[BLOCK_KEY_BYTES:])


def set_checkpoint(snapshot: Snapshot, point: Checkpoint) -> None:
    snapshot.put(CHECKPOINT_KEY, point.anchor + point.committed)


def flip_root_hash(block_key: bytes) -> bytes:
    """The same block position with a different root hash: a sibling identity."""
    edited = bytearray(block_key)
    edited[17] ^= 1
    return bytes(edited)


def tamper_value(value: bytes) -> bytes:
    """Flip one bit in the last byte of a serialized transaction cell."""
    if not value:
        raise ValueError("empty value")
    return value[:-1] + bytes([value[-1] ^ 1])
