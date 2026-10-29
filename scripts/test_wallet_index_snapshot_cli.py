#!/usr/bin/env python3
"""Exercise the real offline index snapshot CLI, including failure exit codes."""

from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess
import tempfile
from pathlib import Path


# The wallet-index schema version the binaries under test write.
SCHEMA = 4


def block(seqno: int) -> bytes:
    return (
        struct.pack(">BiQI", 0, -1, 1 << 63, seqno) + bytes([seqno]) * 32 + bytes([seqno + 1]) * 32
    )


def fixture() -> bytes:
    records = [(b"\0\1", struct.pack(">I", SCHEMA)), (b"\0\x20", block(1) + block(5))]
    return (
        b"TOSIDX01"
        + struct.pack(">I", SCHEMA)
        + b"".join(struct.pack(">II", len(k), len(v)) + k + v for k, v in records)
        + bytes(8)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    binary = parser.parse_args().binary.resolve(strict=True)

    def run(*args: str | Path, code: int = 0, contains: str = "") -> str:
        result = subprocess.run(
            [str(binary), *(str(arg) for arg in args)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        output = result.stdout + result.stderr
        assert result.returncode == code, (result.returncode, code, output)
        assert contains in output, (contains, output)
        return output

    with tempfile.TemporaryDirectory(prefix="wallet-snapshot-cli-") as raw:
        root = Path(raw)
        snapshot = root / "input.snapshot"
        snapshot.write_bytes(fixture())
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        run("--help", contains="--sha256")
        run("--action", "verify", "--snapshot", snapshot, code=2)
        run("--action", "verify", "--snapshot", snapshot, "--sha256", "z" * 64, code=2)
        run(
            "--action",
            "verify",
            "--snapshot",
            snapshot,
            "--sha256",
            "0" * 64,
            code=1,
            contains="trusted digest",
        )
        run(
            "--action", "verify", "--snapshot", snapshot, "--sha256", digest, contains="checkpoint="
        )
        restored = root / "index"
        run(
            "--action",
            "restore",
            "--snapshot",
            snapshot,
            "--sha256",
            digest,
            "--index-dir",
            restored,
        )
        exported = root / "output.snapshot"
        run(
            "--action",
            "create",
            "--snapshot",
            exported,
            "--index-dir",
            restored,
            contains=f"sha256={digest}",
        )
        assert exported.read_bytes() == snapshot.read_bytes()
        run(
            "--action",
            "restore",
            "--snapshot",
            snapshot,
            "--sha256",
            digest,
            "--index-dir",
            restored,
            code=1,
            contains="already exists",
        )
        print(
            "WALLET_INDEX_SNAPSHOT_CLI_OK: verify/restore/export round trip and refusal exit codes"
        )


if __name__ == "__main__":
    main()
