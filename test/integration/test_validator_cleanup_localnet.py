#!/usr/bin/env python3
"""Real-node acceptance for the GATED validator consensus-DB cleanup (Finding 1).

Brings up a real 4-node localnet (economics + Stage-A election profile, short
catchain lifetimes, tiny state-ttl) so that:
  * validators repeatedly retire consensus groups -> per-group RocksDB dirs
    `<db_root>/consensus/consensus.<wc>.<shard>.<cc>.<hex>` (no `.observer`) pile up;
  * a validator-set election produces a post-genesis key block, and >1024 mc blocks
    pass, so the GC masterchain floor advances -> try_validator_consensus_db_cleanup()
    actually runs with kValidatorConsensusCleanupEnabled == true.

It then asserts the gated deletion FIRED and was SAFE:
  * at least one validator-group dir was reclaimed (log line "reclaimed N consensus
    database(s)" from manager.cpp), i.e. real deletion happened;
  * every node kept producing masterchain blocks THROUGH the reclamations (a wrongful
    delete of a live consensus DB is exactly Finding 1's crash symptom, so survival +
    progress is the safety signal);
  * no FATAL / sanitizer / CHECK-failed diagnostics in any node log.

Run from the repo root:
    uv run python test/integration/test_validator_cleanup_localnet.py --duration 1200
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

from tostester.install import Install
from tostester.network import FullNode, Network, StartOptions

# manager.cpp cleanup / retirement log lines.
RECLAIMED = re.compile(r"reclaimed (?P<n>\d+) consensus database")
CLOSED_FOR_RETIREMENT = re.compile(r"consensus DB closed for retirement", re.IGNORECASE)
FATAL_LOG = re.compile(
    r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|"
    r"UndefinedBehaviorSanitizer|Aborted)\b",
    re.IGNORECASE,
)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--duration", type=float, default=1200.0, help="seconds to run (default 1200)")
    p.add_argument("--group-lifetime", type=int, default=12, help="catchain lifetimes (s)")
    p.add_argument("--shard-validators", type=int, default=3)
    p.add_argument("--state-ttl", type=int, default=10)
    p.add_argument("--archive-ttl", type=int, default=20)
    p.add_argument("--base-port", type=int, default=23100)
    p.add_argument("--threads", type=int, default=2)
    p.add_argument("--snapshot-interval", type=float, default=15.0)
    return p.parse_args()


async def _mc_height(node: FullNode) -> int:
    client = await node.toslib_client()
    info = await client.get_masterchain_info()
    assert info.last is not None
    return info.last.seqno


def _consensus_dirs(node_dir: Path) -> tuple[list[str], list[str]]:
    """Return (validator_group_dirs, observer_dirs) currently on disk for one node."""
    cdir = node_dir / "consensus"
    validators: list[str] = []
    observers: list[str] = []
    if cdir.is_dir():
        for child in cdir.iterdir():
            if not child.name.startswith("consensus."):
                continue
            (observers if ".observer." in child.name else validators).append(child.name)
    return sorted(validators), sorted(observers)


async def _main() -> int:
    args = _parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    artifact_dir = (repo_root / "build/validator-cleanup-localnet" / stamp).resolve()
    network_dir = artifact_dir / "network"
    network_dir.mkdir(parents=True)
    install = Install(repo_root / "build", repo_root)
    install.toslibjson.client_set_verbosity_level(0)

    node_dirs: list[Path] = []
    started_at = time.monotonic()
    snapshots: list[dict] = []
    # Peak validator-group dir count seen per node (proves dirs were actually created).
    peak_validator_dirs: dict[int, int] = {}

    async with Network(install, network_dir, base_port=args.base_port) as network:
        # Election-driven rotation (the only source of a post-genesis key block on a
        # localnet) needs the economics profile, which requires EXACTLY 4 validators.
        network.config.validator_economics_profile = True
        network.config.validator_election_stage_a_profile = True
        network.config.shard_validators = args.shard_validators
        network.config.mc_valgroup_lifetime = args.group_lifetime
        network.config.shard_valgroup_lifetime = args.group_lifetime
        network.config.shard_validators_lifetime = args.group_lifetime

        dht = network.create_dht_node()
        nodes: list[FullNode] = []
        for _ in range(4):
            node = network.create_full_node()
            node.make_initial_validator()
            node.announce_to(dht)
            nodes.append(node)
        for key_file in network_dir.glob("node*/keyring/*"):
            key_file.chmod(0o600)
        node_dirs = [network_dir / f"node{i + 1}" for i in range(len(nodes))]

        # Small state-ttl/archive-ttl so the GC masterchain floor can advance once a
        # post-genesis key block exists and >1024 mc blocks have passed.
        opts = StartOptions(
            threads=args.threads,
            verbosity=3,
            args=["--state-ttl", str(args.state_ttl), "--archive-ttl", str(args.archive_ttl)],
        )
        await dht.run(StartOptions(threads=1, verbosity=3))
        await asyncio.gather(*(node.run(opts) for node in nodes))

        await network.wait_mc_block(seqno=2)

        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            try:
                heights = list(await asyncio.gather(*(_mc_height(n) for n in nodes)))
            except BaseException as e:  # keep sampling even if one query blips
                heights = [f"err:{e!r}"]
            per_node = []
            for idx, nd in enumerate(node_dirs):
                v, o = _consensus_dirs(nd)
                peak_validator_dirs[idx] = max(peak_validator_dirs.get(idx, 0), len(v))
                per_node.append({"validator_dirs": len(v), "observer_dirs": len(o)})
            snap = {
                "elapsed": round(time.monotonic() - started_at, 1),
                "heights": heights,
                "consensus": per_node,
            }
            snapshots.append(snap)
            print(json.dumps(snap), flush=True)
            await asyncio.sleep(min(args.snapshot_interval, max(0.1, deadline - time.monotonic())))

        final_heights = list(await asyncio.gather(*(_mc_height(n) for n in nodes)))
        # Read logs BEFORE teardown.
        logs = [nd.read_text(errors="replace") if (nd := node.log_path) else "" for node in nodes]

    # ---- analysis (network torn down by the async-with exit) ----
    reclaimed_total = 0
    reclaimed_dirs_total = 0
    retirement_total = 0
    fatal_lines: list[str] = []
    per_node_report = []
    for i, text in enumerate(logs):
        reclaims = list(RECLAIMED.finditer(text))
        n_dirs = sum(int(m.group("n")) for m in reclaims)
        retire = len(CLOSED_FOR_RETIREMENT.findall(text))
        fatals = [ln[:1000] for ln in text.splitlines() if FATAL_LOG.search(ln)]
        reclaimed_total += len(reclaims)
        reclaimed_dirs_total += n_dirs
        retirement_total += retire
        fatal_lines += [f"node{i + 1}: {ln}" for ln in fatals]
        per_node_report.append(
            {
                "node": i + 1,
                "reclaim_log_lines": len(reclaims),
                "reclaimed_dirs": n_dirs,
                "retirements": retire,
                "peak_validator_dirs": peak_validator_dirs.get(i, 0),
                "final_height": final_heights[i],
                "fatal_lines": len(fatals),
            }
        )

    start_heights = snapshots[0]["heights"] if snapshots else []
    progressed = all(isinstance(h, int) for h in final_heights) and (
        not start_heights
        or all(isinstance(s, int) for s in start_heights)
        and min(final_heights) > min(start_heights)
    )

    failures: list[str] = []
    if reclaimed_dirs_total == 0:
        failures.append("no validator-group consensus DB was reclaimed (gated cleanup never fired)")
    if not progressed:
        failures.append(f"masterchain did not progress on every node: {start_heights} -> {final_heights}")
    if fatal_lines:
        failures.append(f"{len(fatal_lines)} fatal/crash diagnostics in node logs")

    verdict = "PASS" if not failures else "FAIL"
    summary = {
        "verdict": verdict,
        "artifact_dir": str(artifact_dir),
        "duration_s": args.duration,
        "reclaim_log_lines_total": reclaimed_total,
        "reclaimed_dirs_total": reclaimed_dirs_total,
        "retirement_total": retirement_total,
        "final_heights": final_heights,
        "nodes": per_node_report,
        "failures": failures,
        "fatal_sample": fatal_lines[:5],
    }
    (artifact_dir / "summary.json").write_text(json.dumps(summary | {"snapshots": snapshots}, indent=2) + "\n")
    print("==== VALIDATOR-CLEANUP LOCALNET SUMMARY ====", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if not failures else 1


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except (ValueError, TimeoutError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error
