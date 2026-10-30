#!/usr/bin/env python3
"""The wallet-index service refuses to serve an index that is not verified.

An index imported from an untrusted snapshot is Quarantined until it has been
checked against the local node's own head; a Partial, Refused or malformed
state must not be served either. Each state is installed with the real
snapshot tool, and the real service must exit before it listens. A Full
index is the control: the service gets past the gate and stops later, at the
deliberately incomplete source database, without the refusal.
"""

import argparse
import hashlib
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

# The wallet-index schema version the binaries under test write.
SCHEMA = 4
REFUSAL = "imported from an untrusted snapshot"


def block(seqno: int) -> bytes:
    return (
        struct.pack(">BiQI", 0, -1, 1 << 63, seqno) + bytes([seqno]) * 32 + bytes([seqno + 1]) * 32
    )


def snapshot(state: bytes | None) -> bytes:
    records = [(b"\0\1", struct.pack(">I", SCHEMA)), (b"\0\x20", block(1) + block(5))]
    if state is not None:
        records.append((b"\0\x30", state))
    return (
        b"TOSIDX01"
        + struct.pack(">I", SCHEMA)
        + b"".join(struct.pack(">II", len(k), len(v)) + k + v for k, v in records)
        + bytes(8)
    )


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-binary", type=Path, required=True)
    parser.add_argument("--snapshot-binary", type=Path, required=True)
    args = parser.parse_args()
    service = args.index_binary.resolve(strict=True)
    tool = args.snapshot_binary.resolve(strict=True)
    cases = [
        ("untrusted-import", None, True),
        ("partial", b"\x02", True),
        ("refused", b"\x03", True),
        ("malformed-value", b"\x09", True),
        ("malformed-length", b"\x01\x01", True),
        ("full-control", b"\x00", False),
    ]
    with tempfile.TemporaryDirectory(prefix="wallet-index-gate-") as raw:
        root = Path(raw)
        source = root / "source"
        (source / "celldb").mkdir(parents=True)
        for name, state, refused in cases:
            data = root / name
            data.mkdir()
            file = root / f"{name}.snapshot"
            file.write_bytes(snapshot(state))
            if state is None:
                action = ["--action", "import-untrusted"]
            else:
                digest = hashlib.sha256(file.read_bytes()).hexdigest()
                action = ["--action", "restore", "--sha256", digest]
            subprocess.run(
                [str(tool), *action, "--snapshot", str(file), "--index-dir", str(data / "index")],
                check=True,
                capture_output=True,
                timeout=30,
            )
            port = free_port()
            process = subprocess.Popen(
                [
                    str(service),
                    "--source-db",
                    str(source),
                    "--data-dir",
                    str(data),
                    "--listen",
                    f"127.0.0.1:{port}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                # The service's output may hold bytes that are not UTF-8.
                errors="replace",
            )
            try:
                output, _ = process.communicate(timeout=20)
                code = process.returncode
            except subprocess.TimeoutExpired:
                # Still running: it got past the gate (only the Full control may).
                process.kill()
                output, _ = process.communicate()
                code = None
            if refused:
                assert code == 2, (name, code, output)
                expected = (
                    REFUSAL
                    if name in ("untrusted-import", "partial", "refused")
                    else "verification state"
                )
                assert expected in output, (name, output)
            else:
                assert REFUSAL not in output and "verification state" not in output, (name, output)
    print(
        "WALLET_INDEX_VERIFICATION_GATE_OK: unverified and malformed states refused before listening"
    )


if __name__ == "__main__":
    main()
