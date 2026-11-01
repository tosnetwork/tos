#!/usr/bin/env python3
"""Compare full replay and snapshot resume using two stopped native node stores.

The optional node_sync_init_block.py fixture creates a suitable pair: node1 has
Genesis history and node5 joined at a persistent state. This runner accepts any
such stopped pair, and has no build or CI dependency on that fixture. Select a
checkpoint after the joined node's init block and a target both sources retain.
All generated indexes, exports and receipts go below a new, separate --root.
"""

import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import TypedDict


class ReplayStats(TypedDict):
    mc_blocks: int


class Readiness(TypedDict):
    masterchain_seqno: int | None
    source_seqno: int | None
    caught_up: bool
    replay_ceiling: int | None
    settled: bool
    initialized: bool
    replay_stats: ReplayStats


class IndexResult(TypedDict):
    seconds: float
    readyz: Readiness
    first_readyz: Readiness
    command: list[str]


class SourceInventory(TypedDict):
    files: int
    directories: int
    metadata_sha256: str


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def source_inventory(path: Path) -> SourceInventory:
    digest = hashlib.sha256()
    count = 0
    directory_count = 0

    def record(item: Path) -> None:
        stat = item.lstat()
        metadata = (str(item.relative_to(path)), stat.st_mode, stat.st_size, stat.st_mtime_ns)
        digest.update(json.dumps(metadata, separators=(",", ":")).encode())
        digest.update(b"\n")

    for root, dirs, files in os.walk(path):
        dirs.sort()
        record(Path(root))
        directory_count += 1
        for name in dirs:
            item = Path(root) / name
            if item.is_symlink():
                record(item)
        for name in sorted(files):
            record(Path(root) / name)
            count += 1
    return {
        "files": count,
        "directories": directory_count,
        "metadata_sha256": digest.hexdigest(),
    }


def command(args: list[str], receipt: Path) -> str:
    process = subprocess.run(args, capture_output=True, text=True, timeout=60)
    receipt.write_text(process.stdout + process.stderr)
    if process.returncode:
        raise RuntimeError(f"command failed ({process.returncode}), see {receipt}")
    return process.stdout


def index(
    binary: Path,
    source: Path,
    data: Path,
    ceiling: int,
    label: str,
    output: Path,
    expect_missing: bool = False,
    durable_floor: int | None = None,
) -> IndexResult:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    log = output / f"{label}.log"
    cmd = [
        str(binary),
        "--source-db",
        str(source),
        "--data-dir",
        str(data),
        "--listen",
        f"127.0.0.1:{port}",
        "--replay-ceiling",
        str(ceiling),
    ]
    started = time.monotonic()
    body: Readiness | None = None
    first_readyz: Readiness | None = None
    print(f"START {label}: ceiling={ceiling}", flush=True)
    with log.open("wb") as stream:
        process = subprocess.Popen(cmd, stdout=stream, stderr=subprocess.STDOUT)
        try:
            deadline = started + (45 if expect_missing else 180)
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"{label} exited {process.returncode}; see {log}")
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    connection.request("GET", "/readyz")
                    response = connection.getresponse()
                    if response.status not in (200, 503):
                        raise RuntimeError(f"unexpected readiness status {response.status}")
                    body = json.loads(response.read(65536))
                    assert body is not None
                    if first_readyz is None:
                        first_readyz = body
                    if durable_floor is not None:
                        assert body["initialized"]
                        cursor = body["masterchain_seqno"]
                        assert cursor is not None and cursor >= durable_floor
                except (OSError, http.client.HTTPException):
                    time.sleep(0.1)
                    continue
                finally:
                    connection.close()
                if expect_missing:
                    if "source has no masterchain block 1" in log.read_text(errors="replace"):
                        assert body["initialized"] is False and body["masterchain_seqno"] is None
                        assert body["caught_up"] is False
                        break
                elif body["masterchain_seqno"] == ceiling and body["settled"]:
                    break
                time.sleep(0.2)
            else:
                raise TimeoutError(f"{label} never reached expected state: {body}; see {log}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError(f"{label} did not stop after SIGTERM")
        if process.returncode != 0:
            raise RuntimeError(f"{label} shutdown exited {process.returncode}")
    assert body is not None and first_readyz is not None
    result: IndexResult = {
        "seconds": round(time.monotonic() - started, 3),
        "readyz": body,
        "first_readyz": first_readyz,
        "command": cmd,
    }
    (output / f"{label}.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"DONE {label}: {json.dumps(body, sort_keys=True)}", flush=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--full-source", type=Path, required=True)
    parser.add_argument("--joined-source", type=Path, required=True)
    parser.add_argument("--checkpoint", type=int, required=True)
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    assert 1 < args.checkpoint < args.target
    assert re.fullmatch("[0-9a-f]{40}", args.source_commit), "source commit must be a full Git ID"
    root = args.root.resolve()
    full_source = args.full_source.resolve(strict=True)
    joined_source = args.joined_source.resolve(strict=True)
    for source in (full_source, joined_source):
        if root == source or source in root.parents or root in source.parents:
            raise ValueError("output and source directories must not overlap")
        if not all((source / child).is_dir() for child in ("state", "celldb", "archive")):
            raise ValueError(f"source lacks native chain storage: {source}")
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    before = {str(source): source_inventory(source) for source in (full_source, joined_source)}
    service = (args.build / "services/tos-wallet-index").resolve(strict=True)
    tool = (args.build / "services/tos-wallet-index-snapshot").resolve(strict=True)
    results: dict[str, object] = {
        "source_commit": args.source_commit,
        "service_sha256": sha256(service),
        "snapshot_tool_sha256": sha256(tool),
        "checkpoint": args.checkpoint,
        "target": args.target,
        "source_inventory": before,
    }
    try:
        results["fresh_joined_refusal"] = index(
            service,
            joined_source,
            root / "fresh-joined",
            args.target,
            "fresh-joined-refusal",
            root,
            True,
        )
        results["full"] = index(service, full_source, root / "full", args.target, "full", root)
        results["donor"] = index(
            service, full_source, root / "donor", args.checkpoint, "donor", root
        )
        snapshot = root / "checkpoint.snapshot"
        text = command(
            [
                str(tool),
                "--action",
                "create",
                "--index-dir",
                str(root / "donor/index"),
                "--snapshot",
                str(snapshot),
            ],
            root / "create-checkpoint.log",
        )
        matched_digest = re.search(r"sha256=([0-9a-f]{64})", text)
        assert matched_digest is not None, "snapshot command did not report a digest"
        digest = matched_digest.group(1)
        (root / "resumed").mkdir()
        command(
            [
                str(tool),
                "--action",
                "restore",
                "--index-dir",
                str(root / "resumed/index"),
                "--snapshot",
                str(snapshot),
                "--sha256",
                digest,
            ],
            root / "restore-checkpoint.log",
        )
        resumed = index(
            service,
            joined_source,
            root / "resumed",
            args.target,
            "resumed",
            root,
            durable_floor=args.checkpoint,
        )
        results["resumed"] = resumed
        assert resumed["readyz"]["replay_stats"]["mc_blocks"] == args.target - args.checkpoint
        hashes = []
        records = []
        for label in ("full", "resumed"):
            destination = root / f"{label}.snapshot"
            text = command(
                [
                    str(tool),
                    "--action",
                    "create",
                    "--index-dir",
                    str(root / label / "index"),
                    "--snapshot",
                    str(destination),
                ],
                root / f"export-{label}.log",
            )
            hashes.append(sha256(destination))
            matched_records = re.search(r"records=(\d+)", text)
            assert matched_records is not None, "snapshot command did not report a record count"
            records.append(int(matched_records.group(1)))
        assert hashes[0] == hashes[1], "full logical index differs after native snapshot resume"
        assert records[0] == records[1] and records[0] > 2
        results.update(
            result="NATIVE_WALLET_SNAPSHOT_CONTINUITY_OK",
            final_sha256=hashes[0],
            records=records[0],
            checkpoint_sha256=digest,
        )
    finally:
        results["sources_unchanged"] = all(
            source_inventory(Path(path)) == entries for path, entries in before.items()
        )
        (root / "receipt.json").write_text(json.dumps(results, indent=2) + "\n")
        assert results["sources_unchanged"], (
            "stopped source file metadata changed during read-only replay"
        )
    print(json.dumps(results, indent=2), flush=True)
    print("NATIVE_WALLET_SNAPSHOT_CONTINUITY_OK", flush=True)


if __name__ == "__main__":
    main()
