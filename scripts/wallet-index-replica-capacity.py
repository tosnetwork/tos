#!/usr/bin/env python3
"""Measure a frozen real-chain replica with the production wallet-index tools.

Path A builds a fresh index from the retained window; Path B imports an untrusted
snapshot and verifies it. Neither path serves partial verification. This runner
does not create a network fixture, prepare a node, or authenticate its provenance.
"""

import argparse
import hashlib
import http.client
import json
import math
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

BLOCK = re.compile(r"\(-1,8000000000000000,(\d+)\):[0-9a-fA-F]{64}:[0-9a-fA-F]{64}\Z")


def sha256(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def inventory(path):
    """Metadata inventory, explicitly not a hash of all archive contents."""
    digest = hashlib.sha256()
    files = logical = allocated = 0
    for directory, dirs, names in os.walk(path):
        dirs.sort()
        if any((Path(directory) / name).is_symlink() for name in [*dirs, *names]):
            raise RuntimeError("frozen source/output inventory cannot follow symlinks")
        for item in [Path(directory), *(Path(directory) / n for n in sorted(names))]:
            info = item.lstat()
            row = [str(item.relative_to(path)), info.st_mode, info.st_size, info.st_mtime_ns]
            digest.update(json.dumps(row, separators=(",", ":")).encode() + b"\n")
            if item.is_file():
                files += 1
                logical += info.st_size
                allocated += info.st_blocks * 512
    return dict(
        files=files, bytes=logical, allocated_bytes=allocated, metadata_sha256=digest.hexdigest()
    )


def proc_memory(pid):
    try:
        text = Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return {}
    return {
        name: int(value)
        for name, value in re.findall(r"^(VmRSS|RssAnon|VmHWM):\s+(\d+) kB", text, re.M)
    }


def sampled_disk_bytes(path):
    """RocksDB can remove or rename files during an explicitly sampled size walk."""
    allocated = 0
    for directory, _dirs, names in os.walk(path):
        for name in names:
            try:
                allocated += (Path(directory) / name).lstat().st_blocks * 512
            except FileNotFoundError:
                continue
    return allocated


def readyz(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/readyz")
        reply = connection.getresponse()
        raw = reply.read((1 << 20) + 1)
        if len(raw) > 1 << 20:
            raise RuntimeError("oversized readiness response")
        return reply.status, json.loads(raw)
    except (OSError, http.client.HTTPException, json.JSONDecodeError):
        return None
    finally:
        connection.close()


def check_sample(previous, status, body, target):
    for key in ("masterchain_seqno", "source_seqno"):
        current = body.get(key)
        old = previous.get(key)
        if current is not None and (type(current) is not int or current < 0):
            raise RuntimeError(f"invalid {key}")
        if old is not None and (current is None or current < old):
            raise RuntimeError(f"{key} regressed")
    if body.get("source_seqno") not in (None, target):
        raise RuntimeError("the frozen source tip differs from the requested target")
    if status == 200 and body.get("verification") != "full":
        raise RuntimeError("index became ready without Full verification")
    return (
        status == 200
        and body.get("verification") == "full"
        and body.get("masterchain_seqno") == target
        and body.get("source_seqno") == target
        and body.get("caught_up") is True
        and body.get("settled") is True
    )


def run_stage(command, root, name, timeout, data, observe=None):
    """wait4 supplies per-child peak RSS even when an offline tool exits quickly."""
    log = root / f"{name}.log"
    started = time.monotonic()
    result = dict(
        command=command, reached=False, peak_sampled_anon_kib=None, peak_sampled_data_bytes=0
    )
    usage = None
    error = None
    next_disk_sample = 0
    with log.open("xb") as output, (root / f"{name}.samples.jsonl").open("x") as samples:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        def reap():
            nonlocal usage
            pid, status, measured = os.wait4(process.pid, os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                usage = measured
            return pid != 0

        try:
            while not reap():
                elapsed = time.monotonic() - started
                memory = proc_memory(process.pid)
                sample = dict(seconds=round(elapsed, 6), memory_kib=memory)
                if data.exists() and elapsed >= next_disk_sample:
                    disk = sampled_disk_bytes(data)
                    sample["data_bytes"] = disk
                    result["peak_sampled_data_bytes"] = max(result["peak_sampled_data_bytes"], disk)
                    next_disk_sample = elapsed + 5
                if "RssAnon" in memory:
                    result["peak_sampled_anon_kib"] = max(
                        result["peak_sampled_anon_kib"] or 0, memory["RssAnon"]
                    )
                if observe is not None:
                    reached, extra = observe(time.monotonic() - started)
                    sample.update(extra)
                    sample["seconds"] = round(time.monotonic() - started, 6)
                    if reached:
                        result.update(reached=True, ready_after_seconds=time.monotonic() - started)
                samples.write(json.dumps(sample, sort_keys=True) + "\n")
                samples.flush()
                if result["reached"]:
                    break
                if elapsed >= timeout:
                    raise TimeoutError(f"{name} exceeded {timeout} seconds")
                if log.stat().st_size > 1 << 30:
                    raise RuntimeError(f"{name} log exceeded 1 GiB")
                time.sleep(0.5)
        except BaseException as exc:
            error = exc
        finally:
            if usage is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 30
                while not reap() and time.monotonic() < deadline:
                    time.sleep(0.05)
                if usage is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
    result.update(
        elapsed_seconds=time.monotonic() - started,
        exit_code=process.returncode,
        peak_rss_kib=usage.ru_maxrss,
        user_cpu_seconds=usage.ru_utime,
        system_cpu_seconds=usage.ru_stime,
        data=inventory(data) if data.exists() else None,
        index=inventory(data / "index") if (data / "index").exists() else None,
        log_sha256=sha256(log),
    )
    (root / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
    if error is not None:
        raise error
    if process.returncode != 0 or (observe is not None and not result["reached"]):
        raise RuntimeError(f"{name} did not complete; see {log}")
    return result


def canonical_summary(log, target_id):
    fields = {}
    with log.open() as stream:
        for line in stream:
            for name in ("checkpoint", "head", "window_base", "sha256", "anchor_verified"):
                if line.startswith(name + "="):
                    fields[name] = line.rstrip().split("=", 1)[1]
    if fields.get("checkpoint", "").split()[-1:] != [target_id]:
        # Native block IDs conventionally use upper-case hashes.
        actual = fields.get("checkpoint", "").split()[-1:]
        if not actual or actual[0].lower() != target_id.lower():
            raise RuntimeError("canonical output is bound to a different target block")
    if not re.fullmatch(r"[0-9a-f]{64}", fields.get("sha256", "")):
        raise RuntimeError("canonical dump did not provide an integrity digest")
    target = int(BLOCK.fullmatch(target_id).group(1))
    if not fields.get("head", "").isdigit() or int(fields["head"]) != target:
        raise RuntimeError("canonical dump head does not match target")
    if not fields.get("window_base", "").isdigit() or not 0 <= int(fields["window_base"]) <= target:
        raise RuntimeError("canonical dump has no valid retained-window base")
    if fields.get("anchor_verified") not in ("yes", "no", "unrecorded"):
        raise RuntimeError("canonical dump has no valid anchor verification status")
    return fields


def historical_growth(path, target):
    if path is None:
        return {"status": "unavailable", "reason": "no real block-header timing receipt supplied"}
    rows = json.loads(path.read_text())
    if len(rows) < 2:
        raise ValueError("block timing receipt needs at least two real block headers")
    last_seq = last_time = -1
    for row in rows:
        match = BLOCK.fullmatch(row["block_id"])
        timestamp = row["gen_utime"]
        if not match or type(timestamp) is not int:
            raise ValueError("invalid block-header timing row")
        seqno = int(match.group(1))
        if seqno <= last_seq or timestamp < last_time or seqno > target:
            raise ValueError("block-header sequence/time is not monotonic")
        last_seq, last_time = seqno, timestamp
    first = rows[0]
    span = rows[-1]["gen_utime"] - first["gen_utime"]
    if span <= 0:
        raise ValueError("block-header timing span must be positive")
    delta = last_seq - int(BLOCK.fullmatch(first["block_id"]).group(1))
    return dict(
        status="measured_from_supplied_headers",
        mc_blocks_per_second=delta / span,
        headers=len(rows),
        seconds=span,
        receipt_sha256=sha256(path),
    )


def time_assessment(index_seconds, preparation_seconds, limit):
    measured = None if preparation_seconds is None else index_seconds + preparation_seconds
    return dict(
        limit=limit,
        measured=measured,
        status="unavailable" if measured is None else "pass" if measured <= limit else "fail",
    )


def stop_requested(signum, _frame):
    raise InterruptedError(f"measurement interrupted by signal {signum}")


def nonnegative_float(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("a finite nonnegative number is required")
    return number


def positive_float(value):
    number = nonnegative_float(value)
    if number == 0:
        raise argparse.ArgumentTypeError("a positive number is required")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--source-db", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--mode", choices=("path-a", "path-b"), required=True)
    parser.add_argument("--dataset-kind", choices=("real-replica", "fixture-smoke"), required=True)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--target-block-id", required=True)
    parser.add_argument("--reference-index", type=Path)
    parser.add_argument("--block-times", type=Path)
    parser.add_argument("--preparation-seconds", type=nonnegative_float)
    parser.add_argument("--max-total-seconds", type=positive_float)
    parser.add_argument("--max-rss-mib", type=positive_float)
    parser.add_argument("--stage-timeout", type=positive_float, default=21600)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, stop_requested)
    if sys.platform != "linux":
        parser.error("Linux /proc and wait4 accounting are required")
    match = BLOCK.fullmatch(args.target_block_id)
    if not match or not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("a complete masterchain target ID and source commit are required")
    if (args.mode == "path-b") != (args.snapshot is not None):
        parser.error("Path B requires --snapshot; Path A starts with no snapshot")
    source = args.source_db.resolve(strict=True)
    root = args.root.resolve()
    if source == root or source in root.parents or root in source.parents:
        parser.error("source and output directories must not overlap")
    if not all((source / part).is_dir() for part in ("state", "celldb", "archive")):
        parser.error("source is not a native node store")
    if args.reference_index is not None:
        reference = args.reference_index.resolve()
        if reference == root or root in reference.parents or reference in root.parents:
            parser.error("reference index and new output must not overlap")
        if not reference.is_dir():
            parser.error("reference index must already exist and be stopped")
    binaries = {
        name: (args.build / "services" / name).resolve(strict=True)
        for name in ("tos-wallet-index", "tos-wallet-index-snapshot", "tos-wallet-index-dump")
    }
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    data = root / "data"
    before = inventory(source)
    receipt = dict(
        schema="tos.wallet-index.replica-capacity.v1",
        result="incomplete",
        mode=args.mode,
        dataset_kind=args.dataset_kind,
        source_commit=args.source_commit,
        target_block_id=args.target_block_id,
        binaries={name: sha256(path) for name, path in binaries.items()},
        source_before=before,
        host=dict(platform=platform.platform(), cpu_count=os.cpu_count()),
        source_receipt_sha256=sha256(args.source_receipt) if args.source_receipt else None,
        preparation_seconds=args.preparation_seconds,
        stages={},
    )
    receipt["provenance"] = {
        "dataset_kind": "caller declaration; independently confirm the generation manifest",
        "source_commit": "caller declaration; bind binary hashes to the retained build receipt",
        "preparation_seconds": "caller measurement; retain its timing and preparation receipt",
        "source_receipt": "file hash only; this runner does not authenticate its publisher or contents",
    }
    target = int(match.group(1))
    previous = {}
    replay_points = []
    phases = []
    try:
        if args.snapshot:
            receipt["snapshot_sha256"] = sha256(args.snapshot)
            data.mkdir(mode=0o700)
            receipt["stages"]["import"] = run_stage(
                [
                    str(binaries["tos-wallet-index-snapshot"]),
                    "--action",
                    "import-untrusted",
                    "--snapshot",
                    str(args.snapshot.resolve()),
                    "--index-dir",
                    str(data / "index"),
                ],
                root,
                "import",
                args.stage_timeout,
                data,
            )
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        def observe(elapsed):
            nonlocal previous
            requested = time.monotonic()
            answer = readyz(port)
            elapsed += time.monotonic() - requested
            if answer is None:
                return False, {"readyz": None}
            status, body = answer
            done = check_sample(previous, status, body, target)
            if "initial_readyz" not in receipt:
                receipt["initial_readyz"] = body
            previous = body
            phase = (body.get("verification"), body.get("verification_phase"))
            if not phases or phases[-1][1:] != list(phase):
                phases.append([elapsed, *phase])
            counters = body.get("replay_stats", {})
            count = counters.get("mc_blocks")
            if type(count) is int:
                if replay_points and count < replay_points[-1][1]:
                    raise RuntimeError("replay counter regressed")
                if not replay_points or count != replay_points[-1][1]:
                    replay_points.append((elapsed, count))
            return done, {"http_status": status, "readyz": body}

        receipt["stages"]["service"] = run_stage(
            [
                str(binaries["tos-wallet-index"]),
                "--source-db",
                str(source),
                "--data-dir",
                str(data),
                "--listen",
                f"127.0.0.1:{port}",
            ],
            root,
            "service",
            args.stage_timeout,
            data,
            observe,
        )
        if args.mode == "path-a":
            marker = "building the index from the window's blocks"
            if marker not in (root / "service.log").read_text(errors="replace"):
                raise RuntimeError("Path A did not exercise the retained-window build")
        receipt.update(final_readyz=previous, phases=phases)
        receipt["stages"]["canonical"] = run_stage(
            [
                str(binaries["tos-wallet-index-dump"]),
                "--canonical",
                "--index-dir",
                str(data / "index"),
                "--head",
                str(target),
            ],
            root,
            "canonical",
            args.stage_timeout,
            data,
        )
        own = canonical_summary(root / "canonical.log", args.target_block_id)
        receipt["canonical"] = own
        receipt["reference_comparison"] = {"status": "unavailable"}
        if args.reference_index:
            receipt["stages"]["reference"] = run_stage(
                [
                    str(binaries["tos-wallet-index-dump"]),
                    "--canonical",
                    "--index-dir",
                    str(args.reference_index.resolve()),
                    "--head",
                    str(target),
                    "--window-base-from",
                    str(data / "index"),
                ],
                root,
                "reference",
                args.stage_timeout,
                data,
            )
            other = canonical_summary(root / "reference.log", args.target_block_id)
            if (other["sha256"], other["window_base"]) != (own["sha256"], own["window_base"]):
                raise RuntimeError("independent reference differs over the complete served window")
            receipt["reference_comparison"] = {"status": "equal", "canonical": other}
        growth = historical_growth(args.block_times, target)
        receipt["historical_chain_growth"] = growth
        receipt["replay_rate"] = {
            "status": "unavailable",
            "reason": "insufficient advancing replay samples",
        }
        if len(replay_points) >= 2:
            seconds = replay_points[-1][0] - replay_points[0][0]
            rate = (replay_points[-1][1] - replay_points[0][1]) / seconds
            receipt["replay_rate"] = dict(
                status="measured", mc_blocks_per_second=rate, seconds=seconds
            )
            if "mc_blocks_per_second" in growth:
                receipt["replay_rate"]["exceeds_historical_chain_growth"] = (
                    rate > growth["mc_blocks_per_second"]
                )
        total = receipt["stages"].get("import", {}).get("elapsed_seconds", 0)
        total += receipt["stages"]["service"]["ready_after_seconds"]
        receipt["index_ready_seconds"] = total
        receipt["total_with_preparation_seconds"] = (
            total + args.preparation_seconds if args.preparation_seconds is not None else None
        )
        limit = args.max_total_seconds or (7200 if args.mode == "path-b" else 21600)
        receipt["time_target"] = time_assessment(total, args.preparation_seconds, limit)
        receipt["time_target"]["basis"] = (
            "measured input/hardware envelope only; not a universal SLA"
        )
        if args.dataset_kind == "fixture-smoke":
            receipt["time_target"].update(
                status="unavailable", reason="fixture smoke is not capacity evidence"
            )
        receipt["optional_bounds"] = {}
        if args.max_rss_mib is not None:
            peak = max(stage["peak_rss_kib"] for stage in receipt["stages"].values()) / 1024
            receipt["optional_bounds"]["rss_mib"] = dict(
                limit=args.max_rss_mib,
                measured=peak,
                status="pass" if peak <= args.max_rss_mib else "fail",
            )
        receipt["result"] = "measured"
    except BaseException as exc:
        receipt.update(result="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        receipt.update(final_readyz=previous, phases=phases)
        receipt["source_after"] = inventory(source)
        receipt["source_metadata_unchanged"] = receipt["source_after"] == before
        if not receipt["source_metadata_unchanged"]:
            receipt.update(result="failed", error="source metadata changed during measurement")
        (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"result": receipt["result"], "receipt": str(root / "receipt.json")}))
    failed_bound = any(
        value["status"] == "fail" for value in receipt.get("optional_bounds", {}).values()
    )
    if (
        receipt["result"] != "measured"
        or failed_bound
        or receipt.get("time_target", {}).get("status") == "fail"
    ):
        return 1
    return 2 if receipt["time_target"]["status"] == "unavailable" else 0


if __name__ == "__main__":
    raise SystemExit(main())
