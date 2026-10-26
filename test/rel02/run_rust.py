#!/usr/bin/env python3
"""Verify the native REL-02 export before continuous Rust account replay (Linux)."""

import argparse
import hashlib
import json
import os
import platform
import resource
import signal
import stat
import subprocess
import tempfile
from pathlib import Path

import run as native

MAX_CORPUS = 20_000_000
MAX_METADATA = 8 * 1024 * 1024
MAX_OUTPUT = 64 * 1024 * 1024
MAX_DIAGNOSTICS = 8 * 1024 * 1024
ADDRESS_SPACE = 4 * 1024 * 1024 * 1024
TIMEOUT = 600


def bounded_read(path, limit):
    # Nonblocking open rejects special files without waiting for a FIFO writer.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f"not a regular file: {path}")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"file byte limit exceeded: {path}")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(source, destination):
    data = bounded_read(source, MAX_METADATA)
    manifest = json.loads(data)
    entries = manifest.get("files", [])
    if not 1 <= len(entries) <= 10_000:
        raise ValueError("invalid corpus file count")
    seen = set()
    total = len(data)
    base = source.parent.resolve()
    for entry in entries:
        name = entry["path"]
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or name in seen:
            raise ValueError("invalid/duplicate snapshot path")
        seen.add(name)
        size = entry["size"]
        if type(size) is not int or not 0 <= size <= MAX_CORPUS - total:
            raise ValueError("corpus byte budget exceeded")
        original = (base / relative).resolve(strict=True)
        if not original.is_relative_to(base):
            raise ValueError("source escapes corpus")
        payload = bounded_read(original, size)
        if len(payload) != size or digest(payload) != entry["sha256"]:
            raise ValueError(f"corpus SHA-256/size mismatch: {name}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        total += size
    target_manifest = destination / "manifest.json"
    target_manifest.write_bytes(data)
    # Reuse all existing manifest selection/schema/oracle invariants on the
    # owned, bounded snapshot, not on files another writer can change.
    checked, files = native.read_manifest(target_manifest)
    return checked, files, target_manifest, digest(data)


def child_limits():
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE, ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def execute(command, directory, label):
    stdout = directory / f"{label}.stdout"
    stderr = directory / f"{label}.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        cancellation = (signal.SIGTERM, signal.SIGINT)
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, cancellation)
        previous_handlers = {sig: signal.getsignal(sig) for sig in cancellation}
        child = None

        def cancelled(signum, _frame):
            if signum == signal.SIGINT:
                raise KeyboardInterrupt
            raise SystemExit(128 + signum)

        def prepare_child():
            # The child must not inherit the parent's scoped cancellation setup.
            for sig in cancellation:
                signal.signal(sig, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            child_limits()

        try:
            for sig in cancellation:
                signal.signal(sig, cancelled)
            # Defer cancellation until the parent owns a Popen handle. Otherwise
            # a signal during Popen can leave a child whose pid we never receive.
            child = subprocess.Popen(
                command,
                stdout=out,
                stderr=err,
                start_new_session=True,
                preexec_fn=prepare_child,
            )
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            try:
                code = child.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                raise ValueError(f"{label} timed out; process group killed") from None
        finally:
            # A repeated SIGTERM/SIGINT must not interrupt group cleanup/reaping.
            signal.pthread_sigmask(signal.SIG_BLOCK, cancellation)
            try:
                if child is not None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
            finally:
                for sig, handler in previous_handlers.items():
                    signal.signal(sig, handler)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    output = bounded_read(stdout, MAX_DIAGNOSTICS)
    errors = bounded_read(stderr, MAX_DIAGNOSTICS)
    if code != 0:
        suffix = errors[-4096:].decode("utf-8", errors="replace")
        raise ValueError(f"{label} failed (exit {code}; resource caps active): {suffix}")
    return output, errors


def binary_hash(path):
    # Streaming receipt hashing; executable may exceed the fixture byte cap.
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def expected_shard_root(original, depth):
    if type(depth) is not int or not 0 <= depth <= 1024:
        raise ValueError("invalid native Account depth")
    # Ordinary cell: one reference, 320 bits; referenced depth precedes hash.
    data = (
        bytes([1, 80])
        + bytes.fromhex(original["result_hash"])
        + int(original["lt"]).to_bytes(8, "big")
        + depth.to_bytes(2, "big")
        + bytes.fromhex(original["account_hash"])
    )
    return digest(data)


def check_native_depths(depths, expected):
    transactions = [r for r in expected if r["kind"] == "transaction"]
    if len(depths) != len(transactions):
        raise ValueError("missing/extra native depth records")
    for index, (depth, original) in enumerate(zip(depths, transactions)):
        if depth != {
            "index": index,
            "transaction_hash": original["result_hash"].lower(),
            "account_depth": depth.get("account_depth"),
        }:
            raise ValueError("native depth identity mismatch")
        expected_shard_root(original, depth["account_depth"])
    return transactions


def check_rust_roots(actual, expected, depths):
    rows = [line.split("\t") for line in actual.decode().splitlines()]
    transactions = check_native_depths(depths, expected)
    if len(rows) != len(transactions):
        raise ValueError("missing/extra Rust output rows")
    for index, (row, original) in enumerate(zip(rows, transactions)):
        kind = {"ordinary": "1", "tick": "3", "tock": "4"}[original["description"]]
        wanted = [
            str(index),
            kind,
            original["lt"],
            "EQUAL",
            "account=",
            "-",
            original["result_hash"].lower(),
            original["account_hash"].lower(),
        ]
        if len(row) != 9 or row[:8] != wanted:
            raise ValueError(f"Rust output row {index} differs from complete parity result")
        if row[8] != expected_shard_root(original, depths[index]["account_depth"]):
            raise ValueError(f"Rust output row {index} differs from ShardAccount oracle")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).parent / "corpus/manifest.json"
    )
    parser.add_argument(
        "--topology", type=Path, default=Path(__file__).parent / "replay-topology.json"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    roots_path = args.output.with_suffix(".roots.tsv")
    depths_path = args.output.with_suffix(".native-depths.json")
    if args.output.exists() or roots_path.exists() or depths_path.exists():
        raise ValueError("output receipt already exists; use a fresh path")
    if platform.system() != "Linux":
        raise ValueError("replay resource isolation currently requires Linux")
    native_binary = args.native.resolve(strict=True)
    rust_binary = args.rust.resolve(strict=True)
    topology_bytes = bounded_read(args.topology, MAX_METADATA)
    topology = json.loads(topology_bytes)
    if (
        topology.get("rows") != 576
        or topology.get("carried_edges") != 474
        or topology.get("segments") != 102
    ):
        raise ValueError("unreviewed replay topology")
    with tempfile.TemporaryDirectory(prefix="rel02-rust-") as temporary:
        work = Path(temporary)
        corpus = work / "corpus"
        corpus.mkdir()
        manifest, files, manifest_path, manifest_hash = snapshot(args.manifest, corpus)
        topology_path = work / "topology.json"
        topology_path.write_bytes(topology_bytes)
        for selection in ("blocks", "supplements"):
            (work / selection).write_text(
                "".join(f"{files[name]}\n" for name in manifest[selection])
            )
        dump = work / "dump.tsv"
        output, _ = execute(
            [
                str(native_binary),
                "--dump",
                str(work / "blocks"),
                str(work / "supplements"),
                str(dump),
            ],
            work,
            "native",
        )
        records = [json.loads(line) for line in output.splitlines()]
        native.check_records(manifest["expected"], records, "native authenticated export")
        dump_bytes = bounded_read(dump, MAX_OUTPUT)
        dump_hash = digest(dump_bytes)
        export_lines = dump_bytes.decode().splitlines()
        if not export_lines or export_lines[0] != "#rel02-v2":
            raise ValueError("unsupported native export schema")
        depths = []
        for index, line in enumerate(export_lines[1:]):
            fields = line.split("\t")
            if len(fields) != 18:
                raise ValueError("invalid native export field count")
            depths.append(
                {
                    "index": index,
                    "transaction_hash": fields[9].lower(),
                    "account_depth": int(fields[17]),
                }
            )
        check_native_depths(depths, manifest["expected"])
        depth_bytes = (json.dumps(depths, separators=(",", ":")) + "\n").encode()
        # Invoke Rust only after successful native execution and complete
        # original on-chain oracle comparison. Digest pins this exact export.
        actual, _ = execute(
            [str(rust_binary), str(dump), str(manifest_path), str(topology_path), dump_hash],
            work,
            "rust",
        )
        rows = check_rust_roots(actual, manifest["expected"], depths)
        if len(rows) != topology["rows"]:
            raise ValueError("Rust output count differs from topology")
        receipt = {
            "schema": 3,
            "architecture": platform.machine(),
            "transactions": len(rows),
            "carried_edges": topology["carried_edges"],
            "anchors": topology["segments"],
            "manifest_sha256": manifest_hash,
            "topology_sha256": digest(topology_bytes),
            "dump_sha256": dump_hash,
            "native_depths_sha256": digest(depth_bytes),
            "native_output_sha256": digest(output),
            "rust_output_sha256": digest(actual),
            "native_binary_sha256": binary_hash(native_binary),
            "rust_binary_sha256": binary_hash(rust_binary),
            "limits": {
                "address_space": ADDRESS_SPACE,
                "file_bytes": MAX_OUTPUT,
                "wall_seconds": TIMEOUT,
            },
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Roots are actual Rust output, not reconstructed from expected hashes.
        # A partial write cannot acquire a success receipt.
        with depths_path.open("xb") as depths_file:
            depths_file.write(depth_bytes)
        with roots_path.open("xb") as roots_file:
            roots_file.write(actual)
        # No acceptance receipt is created before every check succeeds.
        with args.output.open("x") as output_file:
            output_file.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(
            f"PASS: {len(rows)} transactions; {topology['carried_edges']} carries; {topology['segments']} anchors"
        )


if __name__ == "__main__":
    main()
