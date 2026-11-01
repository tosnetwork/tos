"""The native red controls edit snapshots exactly as named and nothing else."""

import importlib.util
import struct
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[3] / "integration/wallet_index_snapshot_records.py"
SPEC = importlib.util.spec_from_file_location("wallet_index_snapshot_records", SOURCE)
assert SPEC is not None and SPEC.loader is not None
RECORDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECORDS)


def block(seqno: int) -> bytes:
    return (
        struct.pack(">BiQI", 0, -1, 1 << 63, seqno) + bytes([seqno]) * 32 + bytes([seqno + 1]) * 32
    )


def honest() -> bytes:
    account = bytes([7]) * 32
    snapshot = RECORDS.Snapshot(4)
    snapshot.put(b"\0\1", struct.pack(">I", 4))
    snapshot.put(RECORDS.CHECKPOINT_KEY, block(1) + block(5))
    for lt in (100, 200, 300):
        snapshot.put(RECORDS.event_key(account, lt), bytes([lt % 256]) * 8)
    return RECORDS.encode(snapshot)


def test_round_trip_is_byte_exact():
    data = honest()
    assert RECORDS.encode(RECORDS.parse(data)) == data


def test_events_are_newest_first_and_keys_round_trip():
    snapshot = RECORDS.parse(honest())
    rows = snapshot.events()
    assert [lt for _, lt, _ in rows] == [300, 200, 100]
    account, lt = RECORDS.parse_event_key(RECORDS.event_key(bytes(32), 12345))
    assert account == bytes(32) and lt == 12345


@pytest.mark.parametrize(
    "edit",
    [
        lambda data: data + b"x",
        lambda data: data[:-1],
        lambda data: data[:-8],
        lambda data: b"TOSIDX02" + data[8:],
    ],
)
def test_malformed_files_are_refused(edit):
    with pytest.raises(ValueError):
        RECORDS.parse(edit(honest()))


def test_edits_change_only_what_they_name():
    snapshot = RECORDS.parse(honest())
    account = bytes([7]) * 32
    key = RECORDS.event_key(account, 200)
    before = dict(snapshot.records)
    snapshot.put(key, RECORDS.tamper_value(snapshot.get(key)))
    after = dict(snapshot.records)
    assert {k for k in before if before[k] != after[k]} == {key}
    snapshot.delete(RECORDS.event_key(account, 100))
    assert [lt for _, lt, _ in snapshot.events(account)] == [300, 200]
    with pytest.raises(KeyError):
        snapshot.delete(RECORDS.event_key(account, 100))
    point = RECORDS.checkpoint(snapshot)
    assert point.seqno() == 5
    sibling = RECORDS.flip_root_hash(point.committed)
    assert sibling != point.committed and sibling[:17] == point.committed[:17]
    RECORDS.set_checkpoint(snapshot, RECORDS.Checkpoint(point.anchor, sibling))
    assert RECORDS.checkpoint(RECORDS.parse(RECORDS.encode(snapshot))).committed == sibling
