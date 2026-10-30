#!/usr/bin/env python3
"""The wallet-index service never serves an index that is not verified.

An index imported from an untrusted snapshot is Quarantined until it has been
checked against the local node's own head: the service starts, verifies it,
and meanwhile answers no index query and reports itself not ready. A Partial
index keeps running its verification: without --allow-partial-verification
it answers no query, with it every history answer is flagged, and in both
cases it is never ready while replay is held for that verification. A Refused
or malformed state is never served, and the service exits before it listens.
A fresh index is not served either until the source has shown whether it
holds masterchain block 1 (a replay from it) or not (a build from the
window's blocks).
Each state is installed with the real snapshot tool, over a fixture node
database that holds no chain, so every verification attempt fails with a
retryable error that /readyz must show. A Full index is the control: the
service gets past the gate.
"""

import argparse
import hashlib
import http.client
import json
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

# The wallet-index schema version the binaries under test write.
SCHEMA = 4
REFUSAL = "imported from an untrusted snapshot"
# A case whose index directory the service creates itself.
FRESH = b"fresh"
NOT_VERIFIED = "not verified against this node's chain"


def block(seqno: int) -> bytes:
    return (
        struct.pack(">BiQI", 0, -1, 1 << 63, seqno) + bytes([seqno]) * 32 + bytes([seqno + 1]) * 32
    )


def verified_at_head() -> bytes:
    """A verification record (meta 0x00 0x31) of an index checked at block 5."""
    return (
        bytes([1])
        + struct.pack(">I", SCHEMA)
        + block(5)
        + struct.pack(">IIIQ", 0, 0, 0, 0)
        + bytes([0, 1])
        + block(5)
    )


def snapshot(state: bytes | None, record: bytes | None = None) -> bytes:
    records = [(b"\0\1", struct.pack(">I", SCHEMA)), (b"\0\x20", block(1) + block(5))]
    if state is not None:
        records.append((b"\0\x30", state))
    if record is not None:
        records.append((b"\0\x31", record))
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


def request(port: int, method: str, path: str, body: bytes | None = None) -> tuple[int, str]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read().decode(errors="replace")
    finally:
        connection.close()


def check_running(
    process: subprocess.Popen[str], port: int, verification: str, answers: bool
) -> None:
    """The service listens while it verifies, never ready, and shows the retries.

    `answers`: whether index queries are answered (flagged) or refused. The
    query is checked as soon as the service listens, before anything else.
    """
    deadline = time.monotonic() + 30
    queried = False
    while True:
        if process.poll() is not None:
            output, _ = process.communicate()
            raise AssertionError((verification, "service exited", process.returncode, output))
        try:
            status, body = request(port, "GET", "/readyz")
        except OSError:
            status, body = None, ""
        if status is not None and not queried:
            check_query(port, answers)
            queried = True
        if status is not None:
            assert status == 503, (status, body)
            readyz = json.loads(body)
            assert readyz["verification"] == verification, body
            if verification == "partial":
                assert readyz["verification_phase"], body
            retry = readyz["verification_retry"]
            if retry is not None:
                assert retry["attempts"] >= 1 and retry["last_error"], body
                assert retry["since"] > 0, body
                break
        if time.monotonic() > deadline:
            raise AssertionError((verification, "never reported a retried failure", body))
        time.sleep(0.2)


def check_query(port: int, answers: bool) -> None:
    """An index query is answered flagged, or refused with no history."""
    query = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountEvents",
            "params": {"address": "0:" + "11" * 32},
        }
    ).encode()
    status, body = request(port, "POST", "/jsonRPC", query)
    if answers:
        assert NOT_VERIFIED not in body, ("query refused", status, body)
        assert '"history_verified":false' in body, ("query answered unflagged", status, body)
    else:
        assert NOT_VERIFIED in body, ("query answered", status, body)
        assert '"events"' not in body, ("query answered", body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-binary", type=Path, required=True)
    parser.add_argument("--snapshot-binary", type=Path, required=True)
    parser.add_argument("--source-fixture-binary", type=Path, required=True)
    args = parser.parse_args()
    service = args.index_binary.resolve(strict=True)
    tool = args.snapshot_binary.resolve(strict=True)
    record = verified_at_head()
    # (name, state record, verification record, extra service flags, expected outcome)
    cases = [
        ("untrusted-import", None, None, [], "quarantined"),
        ("fresh-unbuilt", FRESH, None, [], "quarantined"),
        ("partial", b"\x02", record, [], "partial"),
        ("partial-allowed", b"\x02", record, ["--allow-partial-verification"], "partial-answers"),
        ("refused", b"\x03", None, [], "refused"),
        ("refused-allowed", b"\x03", None, ["--allow-partial-verification"], "refused"),
        ("malformed-value", b"\x09", None, [], "refused"),
        ("malformed-length", b"\x01\x01", None, [], "refused"),
        ("full-control", b"\x00", None, [], "runs"),
    ]
    with tempfile.TemporaryDirectory(prefix="wallet-index-gate-") as raw:
        root = Path(raw)
        source = root / "source"
        subprocess.run(
            [str(args.source_fixture_binary.resolve(strict=True)), "--db", str(source)],
            check=True,
            capture_output=True,
            timeout=60,
        )
        for name, state, verification, flags, expected in cases:
            data = root / name
            data.mkdir()
            if state != FRESH:
                file = root / f"{name}.snapshot"
                file.write_bytes(snapshot(state, verification))
                if state is None:
                    action = ["--action", "import-untrusted"]
                else:
                    digest = hashlib.sha256(file.read_bytes()).hexdigest()
                    action = ["--action", "restore", "--sha256", digest]
                subprocess.run(
                    [
                        str(tool),
                        *action,
                        "--snapshot",
                        str(file),
                        "--index-dir",
                        str(data / "index"),
                    ],
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
                    *flags,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                # The service's output may hold bytes that are not UTF-8.
                errors="replace",
            )
            if expected in ("quarantined", "partial", "partial-answers"):
                try:
                    check_running(
                        process,
                        port,
                        "quarantined" if expected == "quarantined" else "partial",
                        expected == "partial-answers",
                    )
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                continue
            try:
                output, _ = process.communicate(timeout=20)
                code = process.returncode
            except subprocess.TimeoutExpired:
                # Still running: it got past the gate.
                process.kill()
                output, _ = process.communicate()
                code = None
            if expected == "refused":
                assert code == 2, (name, code, output)
                reason = REFUSAL if name.startswith("refused") else "verification state"
                assert reason in output, (name, output)
            else:
                assert REFUSAL not in output and "verification state" not in output, (name, output)
    print(
        "WALLET_INDEX_VERIFICATION_GATE_OK: unverified and undecided fresh indexes are never served "
        "unflagged, never ready, and malformed or refused states are refused before listening"
    )


if __name__ == "__main__":
    main()
