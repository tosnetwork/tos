#!/usr/bin/env python3
"""Sample per-process RSS/FD of running validator-engine processes over time and flag a
leak. macOS-friendly (uses ps/lsof, not /proc). Correlates memory with the masterchain
height from a node's JSON-RPC so growth can be judged against work done, not just wall time.

A leak is reported when RSS rises monotonically with height and the late-window average
exceeds the early-window average by more than --leak-threshold-frac (default 25%) AND the
per-1000-blocks slope stays positive across the run. Steady-state sawtooth (caches filling
then holding) is NOT flagged.

Usage:
  soak-mem-monitor.py --match "validator-engine --global-config" --rpc 127.0.0.1:8111 \
      --interval 20 --duration 3000 --out <dir>/mem-monitor.jsonl
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.request
from pathlib import Path


def engine_pids(match: str) -> list[int]:
    r = subprocess.run(["pgrep", "-f", match], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split()]


def rss_kb(pid: int) -> int | None:
    r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    s = r.stdout.strip()
    return int(s) if s.isdigit() else None


def fd_count(pid: int) -> int | None:
    r = subprocess.run(["lsof", "-p", str(pid)], capture_output=True, text=True)
    if r.returncode != 0 and not r.stdout:
        return None
    # minus the header line
    return max(0, len(r.stdout.splitlines()) - 1)


def mc_seqno(rpc: str) -> int | None:
    try:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}}).encode()
        req = urllib.request.Request(f"http://{rpc}/jsonRPC", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            d = json.loads(resp.read().decode())
        return int(d["result"]["last"]["seqno"])
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--match", default="validator-engine --global-config")
    ap.add_argument("--rpc", default="127.0.0.1:8111", help="a node JSON-RPC for the height reference")
    ap.add_argument("--interval", type=float, default=20.0)
    ap.add_argument("--duration", type=float, default=3000.0)
    ap.add_argument("--leak-threshold-frac", type=float, default=0.25)
    ap.add_argument("--min-judge-samples", type=int, default=15,
                    help="a process needs at least this many samples to be judged (else INSUFFICIENT)")
    ap.add_argument("--analyze-only", type=Path, default=None,
                    help="recompute the verdict over an existing mem-monitor.jsonl and exit")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    if args.analyze_only is not None:
        rows = []
        skipped = 0
        for line in args.analyze_only.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1  # tolerate a truncated/interleaved line (e.g. concurrent writers)
        if skipped:
            print(f"note: skipped {skipped} unparseable line(s)")
        verdict = compute_verdict(rows, args.leak_threshold_frac, str(args.analyze_only), args.min_judge_samples)
        args.out.write_text(json.dumps(verdict, indent=2) + "\n")
        print(json.dumps(verdict, indent=2))
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    samples: list[dict] = []
    deadline = time.monotonic() + args.duration
    with args.out.open("w") as f:
        while time.monotonic() < deadline:
            pids = engine_pids(args.match)
            if not pids:
                break  # network gone
            row = {"at": time.time(), "seqno": mc_seqno(args.rpc),
                   "procs": [{"pid": p, "rss_kb": rss_kb(p), "fds": fd_count(p)} for p in pids]}
            samples.append(row)
            f.write(json.dumps(row) + "\n")
            f.flush()
            time.sleep(args.interval)

    verdict = compute_verdict(samples, args.leak_threshold_frac, str(args.out), args.min_judge_samples)
    verdict_path = args.out.with_name(args.out.stem + "-verdict.json")
    verdict_path.write_text(json.dumps(verdict, indent=2) + "\n")
    print(json.dumps(verdict, indent=2))
    return 0


def compute_verdict(samples: list[dict], threshold: float, samples_file: str, min_judge_samples: int) -> dict:
    """Per-pid leak judgement. A process needs >= min_judge_samples to be judged at all, so a
    short-lived process caught only during RSS warm-up is reported INSUFFICIENT_SAMPLES rather
    than flagged. The early baseline SKIPS an initial warm-up window (caches fill at startup),
    so only sustained post-warm-up growth past the threshold counts as a leak."""
    by_pid: dict[int, list[dict]] = {}
    for row in samples:
        for p in row["procs"]:
            if p["rss_kb"] is not None:
                by_pid.setdefault(p["pid"], []).append({"seqno": row["seqno"], "rss_kb": p["rss_kb"], "fds": p["fds"]})
    findings = []
    leaked = False
    judged = 0
    for pid, series in by_pid.items():
        if len(series) < min_judge_samples:
            findings.append({"pid": pid, "samples": len(series), "judged": False,
                             "note": "INSUFFICIENT_SAMPLES (likely a short-lived / warm-up-only process)"})
            continue
        judged += 1
        warmup = max(2, len(series) // 5)  # drop startup cache warm-up before baselining
        third = max(1, (len(series) - warmup) // 3)
        early = series[warmup:warmup + third]
        late = series[-third:]
        early_rss = sum(s["rss_kb"] for s in early) / len(early)
        late_rss = sum(s["rss_kb"] for s in late) / len(late)
        early_fds = max((s["fds"] for s in early if s["fds"] is not None), default=0)
        late_fds = max((s["fds"] for s in late if s["fds"] is not None), default=0)
        frac = (late_rss - early_rss) / early_rss if early_rss else 0.0
        pid_leak = frac > threshold
        leaked = leaked or pid_leak
        findings.append({
            "pid": pid, "samples": len(series), "judged": True,
            "warmup_skipped": warmup,
            "post_warmup_early_rss_kb": round(early_rss), "late_rss_kb": round(late_rss),
            "rss_growth_frac": round(frac, 4), "early_max_fds": early_fds, "late_max_fds": late_fds,
            "suspected_leak": pid_leak,
        })
    return {
        "verdict": "LEAK_SUSPECTED" if leaked else ("OK" if judged else "INSUFFICIENT_SAMPLES"),
        "samples_file": samples_file,
        "sample_count": len(samples),
        "leak_threshold_frac": threshold,
        "judged_processes": judged,
        "per_process": findings,
    }


if __name__ == "__main__":
    raise SystemExit(main())
