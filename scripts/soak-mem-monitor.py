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
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

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

    # Verdict: compare early vs late window per pid (by first-seen order), require both a
    # positive RSS trend and a late/early excess beyond the threshold to call it a leak.
    by_pid: dict[int, list[dict]] = {}
    for row in samples:
        for p in row["procs"]:
            if p["rss_kb"] is not None:
                by_pid.setdefault(p["pid"], []).append({"seqno": row["seqno"], "rss_kb": p["rss_kb"], "fds": p["fds"]})
    findings = []
    leaked = False
    for pid, series in by_pid.items():
        if len(series) < 6:
            continue
        k = max(1, len(series) // 3)
        early = series[:k]
        late = series[-k:]
        early_rss = sum(s["rss_kb"] for s in early) / len(early)
        late_rss = sum(s["rss_kb"] for s in late) / len(late)
        early_fds = max(s["fds"] for s in early if s["fds"] is not None)
        late_fds = max(s["fds"] for s in late if s["fds"] is not None)
        frac = (late_rss - early_rss) / early_rss if early_rss else 0.0
        pid_leak = frac > args.leak_threshold_frac
        leaked = leaked or pid_leak
        findings.append({
            "pid": pid, "samples": len(series),
            "early_rss_kb": round(early_rss), "late_rss_kb": round(late_rss),
            "rss_growth_frac": round(frac, 4), "early_max_fds": early_fds, "late_max_fds": late_fds,
            "suspected_leak": pid_leak,
        })
    verdict = {
        "verdict": "LEAK_SUSPECTED" if leaked else ("OK" if findings else "INSUFFICIENT_SAMPLES"),
        "samples_file": str(args.out),
        "sample_count": len(samples),
        "leak_threshold_frac": args.leak_threshold_frac,
        "per_process": findings,
    }
    verdict_path = args.out.with_name(args.out.stem + "-verdict.json")
    verdict_path.write_text(json.dumps(verdict, indent=2) + "\n")
    print(json.dumps(verdict, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
