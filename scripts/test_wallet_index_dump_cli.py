#!/usr/bin/env python3
"""The canonical wallet-index dump is bound to the index's window.

Each index is installed with the real snapshot tool (a trusted restore of a
snapshot written here), holding only the records the dump's bindings read:
the schema, the checkpoint, the window base, the base block's record and, for
one, a verification record. The dump must refuse another head, a nonzero base
without its record, and a --window-base-from index at another checkpoint or
with a wider window; it may narrow the window to another index's base; and
the anchor's verification status is printed outside the digest.
"""

import argparse
import hashlib
import re
import struct
import subprocess
import tempfile
from pathlib import Path

SCHEMA = 4


def block(seqno: int, salt: int = 0) -> bytes:
    """A masterchain block key (tag 0, workchain -1, shard all)."""
    return (
        struct.pack(">BiQI", 0, -1, 1 << 63, seqno)
        + bytes([(seqno + salt) % 256 or 1]) * 32
        + bytes([seqno + 1]) * 32
    )


def base_record(seqno: int, end_lt: int) -> bytes:
    """The window base's record: its block and one shard covering the basechain."""
    return (
        bytes([1])
        + struct.pack(">I", SCHEMA)
        + block(seqno)
        + struct.pack(">I", 1)
        + struct.pack(">QQ", 1 << 63, end_lt)
    )


def verification(anchor_verified: bool) -> bytes:
    return (
        bytes([1])
        + struct.pack(">I", SCHEMA)
        + block(5)
        + struct.pack(">IIIQ", 3, 3, 0, 0)
        + bytes([1 if anchor_verified else 0, 1])
        + block(5)
    )


def snapshot(
    base: int | None, record: bytes | None, head_salt: int = 0, verified: bool | None = None
) -> bytes:
    records = [(b"\0\1", struct.pack(">I", SCHEMA))]
    if base is not None:
        records.append((b"\0\x02", struct.pack(">I", base)))
    records.append((b"\0\x20", block(1) + block(5, head_salt)))
    if verified is not None:
        records.append((b"\0\x31", verification(verified)))
    if record is not None:
        records.append((b"\0\x36", record))
    return (
        b"TOSIDX01"
        + struct.pack(">I", SCHEMA)
        + b"".join(struct.pack(">II", len(k), len(v)) + k + v for k, v in records)
        + bytes(8)
    )


def install(tool: Path, root: Path, name: str, content: bytes) -> Path:
    file = root / f"{name}.snapshot"
    file.write_bytes(content)
    index = root / name / "index"
    index.parent.mkdir()
    digest = hashlib.sha256(content).hexdigest()
    subprocess.run(
        [str(tool), "--action", "restore", "--sha256", digest, "--snapshot", str(file)]
        + ["--index-dir", str(index)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return index


def dump(binary: Path, index: Path, *extra: str) -> tuple[int, dict[str, str], str]:
    result = subprocess.run(
        [str(binary), "--index-dir", str(index), *extra],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
    )
    fields = dict(re.findall(r"(?m)^(\w+)=(.*)$", result.stdout))
    return result.returncode, fields, result.stdout + result.stderr


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump-binary", type=Path, required=True)
    parser.add_argument("--snapshot-binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.dump_binary.resolve(strict=True)
    tool = args.snapshot_binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="wallet-index-dump-") as raw:
        root = Path(raw)
        own = install(tool, root, "own", snapshot(3, base_record(3, 3000)))
        verified = install(tool, root, "verified", snapshot(3, base_record(3, 3000), verified=True))
        narrower = install(tool, root, "narrower", snapshot(4, base_record(4, 4000)))
        wider = install(tool, root, "wider", snapshot(2, base_record(2, 2000)))
        other_head = install(
            tool, root, "other-head", snapshot(4, base_record(4, 4000), head_salt=9)
        )
        unrecorded = install(tool, root, "unrecorded", snapshot(3, None))

        code, fields, text = dump(binary, own, "--canonical", "--head", "5")
        assert code == 0, text
        assert fields["head"] == "5" and fields["window_base"] == "3", text
        assert re.fullmatch("[0-9a-f]{64}", fields["sha256"]), text
        assert fields["anchor_verified"] == "unrecorded", text
        digest = fields["sha256"]

        # The anchor's status is outside the digest.
        code, fields, text = dump(binary, verified, "--canonical", "--head", "5")
        assert code == 0 and fields["anchor_verified"] == "yes", text
        assert fields["sha256"] == digest, text

        # Another head is refused.
        code, _, text = dump(binary, own, "--canonical", "--head", "6")
        assert code == 2 and "not 6" in text, text

        # A nonzero base without its block's record is refused, never broadened.
        code, fields, text = dump(binary, unrecorded, "--canonical", "--head", "5")
        assert code == 2 and "sha256" not in fields, text

        # Narrowing to another index's base at the same checkpoint.
        code, fields, text = dump(
            binary, own, "--canonical", "--head", "5", "--window-base-from", str(narrower)
        )
        assert code == 0 and fields["window_base"] == "4", text
        assert fields["sha256"] != digest, text

        # Never wider than this index's own window.
        code, _, text = dump(
            binary, own, "--canonical", "--head", "5", "--window-base-from", str(wider)
        )
        assert code == 2 and "may only narrow" in text, text

        # Never from an index at another checkpoint.
        code, _, text = dump(
            binary, own, "--canonical", "--head", "5", "--window-base-from", str(other_head)
        )
        assert code == 2 and "not at this index's checkpoint" in text, text

        # The raw mode is unchanged, and takes no canonical options.
        code, fields, text = dump(binary, own)
        assert code == 0 and "keys" in text and "sha256=" in text, text
        code, _, text = dump(binary, own, "--head", "5")
        assert code == 2, text
    print("WALLET_INDEX_DUMP_CLI_OK: the canonical dump is bound to the index's head and window")


if __name__ == "__main__":
    main()
