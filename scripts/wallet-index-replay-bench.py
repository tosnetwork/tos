#!/usr/bin/env python3
"""Measure tos-wallet-index replay throughput on a frozen source database.

The source must be a stopped node's database, made read-only, for example a
copy taken after the node was stopped. The script refuses a source whose
RocksDB LOCK is held by a running process (queried with F_GETLK, never taken)
and, unless --allow-writable-source is given, a source with any writable file.
Each run starts the index binary on a fresh, empty data directory, replays from
masterchain block 1 until --until-seqno or --duration, stops it with SIGTERM
and records one JSON object per run:

  rate after the warm-up, CPU cores, bytes read per masterchain block, peak
  descriptors and resident memory, the exit status, and (when the binary
  reports them in /readyz replay_stats) source requests, archive slice opens
  and closes, and the time per replay stage, per masterchain block.

Example A/B (stock behaviour, a larger target without retention, retention):

  scripts/wallet-index-replay-bench.py --binary build/services/tos-wallet-index \\
      --source /datax/bench316/source --work-dir /datax/bench316/runs \\
      --label stock --until-seqno 20000 -- --archive-keep-recent 0
  ... --label target-1024 -- --archive-keep-recent 0 --archive-open-files 1024
  ... --label keep-2

Arguments after `--` are passed to the index; only --archive-open-files and
--archive-keep-recent are accepted there, so a run can never read another
source, write another data directory or listen elsewhere than checked.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Index options a run may pass through, each taking one value. Everything else
# is refused: the source, data directory and listener are the ones this script
# checked and chose, and a repeated option would override them (the index
# keeps the last value it is given).
TUNING_OPTIONS = frozenset({"--archive-open-files", "--archive-keep-recent"})


def tuning_arguments(arguments: list[str]) -> list[str]:
    """The pass-through arguments, refused unless every one is a tuning option."""
    checked: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        name, separator, value = argument.partition("=")
        if name not in TUNING_OPTIONS:
            raise SystemExit(
                f"refusing index argument {argument!r}: only {', '.join(sorted(TUNING_OPTIONS))} "
                "may be passed through; the source, data directory and listener are set by this script"
            )
        if not separator:
            index += 1
            if index >= len(arguments):
                raise SystemExit(f"index argument {name} needs a value")
            value = arguments[index]
        if not value.isdigit():
            raise SystemExit(f"index argument {name} needs a non-negative integer, not {value!r}")
        checked += [name, value]
        index += 1
    return checked


STAT_KEYS = (
    "mc_blocks",
    "shard_blocks",
    "source_requests",
    "source_wait_ms",
    "catch_ups",
    "catch_up_ms",
    "walk_ms",
    "commits",
    "commit_ms",
    "drains",
    "drain_ms",
    "archive_slice_opens",
    "archive_slice_closes",
)


def lock_holder(path: Path) -> int | None:
    """The pid holding a POSIX write lock on `path`, without taking it."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return None
    try:
        # struct flock: l_type, l_whence, l_start, l_len, l_pid (Linux x86-64/arm64).
        query = struct.pack("hhqqi", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
        answer = fcntl.fcntl(fd, fcntl.F_GETLK, query)
        l_type, _, _, _, l_pid = struct.unpack("hhqqi", answer)
        return None if l_type == fcntl.F_UNLCK else l_pid
    finally:
        os.close(fd)


def check_source(source: Path, allow_writable: bool) -> str:
    """Refuse a live or writable source; return a fingerprint of its files."""
    if not (source / "celldb").is_dir():
        raise SystemExit(f"{source}: not a node database (no celldb)")
    digest = hashlib.sha256()
    writable: list[str] = []
    files = 0
    for directory, _, names in os.walk(source):
        for name in sorted(names):
            path = Path(directory) / name
            info = path.lstat()
            relative = str(path.relative_to(source))
            digest.update(f"{relative}\0{info.st_size}\0{info.st_mtime_ns}\n".encode())
            files += 1
            if name == "LOCK":
                holder = lock_holder(path)
                if holder is not None:
                    raise SystemExit(
                        f"{path} is locked by pid {holder}: the source is a live database"
                    )
            if info.st_mode & 0o222:
                writable.append(relative)
    if writable and not allow_writable:
        raise SystemExit(
            f"{len(writable)} writable files in the source (e.g. {writable[0]}); "
            "freeze it (chmod -R a-w) or pass --allow-writable-source"
        )
    return f"{files} files, sha256 {digest.hexdigest()}"


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def readyz(port: int) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=2) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        body = error.read()
    except (urllib.error.URLError, OSError):
        return None
    try:
        document = json.loads(body)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def proc_sample(pid: int) -> dict[str, int]:
    sample: dict[str, int] = {}
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        sample["cpu_ticks"] = int(fields[11]) + int(fields[12])
        for line in Path(f"/proc/{pid}/io").read_text().splitlines():
            key, value = line.split(":")
            if key in ("rchar", "read_bytes"):
                sample[key] = int(value)
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                sample["rss_kib"] = int(line.split()[1])
        sample["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except (OSError, ValueError, IndexError):
        pass
    return sample


def run_once(args: argparse.Namespace, index_args: list[str], run: int) -> dict[str, Any]:
    data_dir = args.work_dir / f"{args.label}-{run}"
    if data_dir.exists():
        raise SystemExit(f"{data_dir} exists; choose another --work-dir or --label")
    log_path = args.work_dir / f"{args.label}-{run}.log"
    command = [
        str(args.binary),
        "--source-db",
        str(args.source),
        "--data-dir",
        str(data_dir),
        "--listen",
        f"127.0.0.1:{args.port}",
        *index_args,
    ]
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    tick = os.sysconf("SC_CLK_TCK")
    started = time.monotonic()
    samples: list[tuple[float, dict[str, Any], dict[str, int]]] = []
    peak_fds = peak_rss = 0
    try:
        while process.poll() is None:
            time.sleep(args.interval)
            now = time.monotonic()
            status = readyz(args.port)
            proc = proc_sample(process.pid)
            peak_fds = max(peak_fds, proc.get("fds", 0))
            peak_rss = max(peak_rss, proc.get("rss_kib", 0))
            if status is not None and isinstance(status.get("masterchain_seqno"), int):
                samples.append((now, status, proc))
                if args.until_seqno and status["masterchain_seqno"] >= args.until_seqno:
                    break
            if args.duration and now - started >= args.duration:
                break
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    window = [sample for sample in samples if sample[0] - started >= args.warmup]
    result: dict[str, Any] = {
        "label": args.label,
        "run": run,
        "command": command,
        "exit": process.returncode,
        "peak_fds": peak_fds,
        "peak_rss_mib": round(peak_rss / 1024, 1),
        "log": str(log_path),
    }
    if len(window) < 2:
        result["error"] = "fewer than two samples after the warm-up"
        return result
    (t0, first, p0), (t1, last, p1) = window[0], window[-1]
    seconds = t1 - t0
    blocks = last["masterchain_seqno"] - first["masterchain_seqno"]
    result.update(
        {
            "window_s": round(seconds, 1),
            "seqno": [first["masterchain_seqno"], last["masterchain_seqno"]],
            "mc_blocks_per_s": round(blocks / seconds, 3) if seconds > 0 else None,
            "cpu_cores": round(
                (p1.get("cpu_ticks", 0) - p0.get("cpu_ticks", 0)) / tick / seconds, 3
            )
            if seconds > 0
            else None,
            "rchar_mb_per_mc_block": round(
                (p1.get("rchar", 0) - p0.get("rchar", 0)) / max(blocks, 1) / 1e6, 3
            ),
            "disk_read_kb_per_mc_block": round(
                (p1.get("read_bytes", 0) - p0.get("read_bytes", 0)) / max(blocks, 1) / 1e3, 3
            ),
        }
    )
    stats0, stats1 = first.get("replay_stats"), last.get("replay_stats")
    if isinstance(stats0, dict) and isinstance(stats1, dict):
        per_block: dict[str, float] = {}
        for key in STAT_KEYS:
            if isinstance(stats0.get(key), int) and isinstance(stats1.get(key), int):
                per_block[key] = round((stats1[key] - stats0[key]) / max(blocks, 1), 3)
        result["per_mc_block"] = per_block
    return result


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    split = argv.index("--") if "--" in argv else len(argv)
    own, passed = argv[:split], argv[split + 1 :]
    index_args = tuning_arguments(passed)
    usage = __doc__ or ""
    parser = argparse.ArgumentParser(
        description=usage.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage,
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--source", type=Path, required=True, help="frozen node database (read-only copy)"
    )
    parser.add_argument(
        "--work-dir", type=Path, required=True, help="where data directories and logs go"
    )
    parser.add_argument("--label", required=True)
    parser.add_argument("--port", type=int, default=26990)
    parser.add_argument("--until-seqno", type=int, default=0)
    parser.add_argument(
        "--duration", type=float, default=0, help="seconds per run (0: until --until-seqno)"
    )
    parser.add_argument("--warmup", type=float, default=15)
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--output", type=Path, help="append one JSON line per run")
    parser.add_argument("--allow-writable-source", action="store_true")
    args = parser.parse_args(own)
    if not args.until_seqno and not args.duration:
        parser.error("give --until-seqno or --duration")
    args.binary = args.binary.resolve()
    args.source = args.source.resolve()
    args.work_dir = args.work_dir.resolve()
    if (
        args.work_dir == args.source
        or args.source in args.work_dir.parents
        or args.work_dir in args.source.parents
    ):
        parser.error("--work-dir and --source must not overlap")
    if not port_free(args.port):
        parser.error(f"port {args.port} is in use")
    fingerprint = check_source(args.source, args.allow_writable_source)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    print(f"source {args.source}: {fingerprint}", file=sys.stderr)
    for run in range(1, args.repeat + 1):
        result = run_once(args, index_args, run)
        result["source"] = str(args.source)
        result["source_fingerprint"] = fingerprint
        line = json.dumps(result, sort_keys=True)
        print(line)
        if args.output:
            with args.output.open("a") as out:
                out.write(line + "\n")


if __name__ == "__main__":
    main()
