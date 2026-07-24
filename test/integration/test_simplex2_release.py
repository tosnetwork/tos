#!/usr/bin/env python3
"""Release-level Simplex2 process tests.

This module deliberately uses real validator-engine, DHT, ADNL, QUIC, manager,
and consensus actors.  It is not part of the default CTest loop because it
starts seven validator processes and is intended to retain failure artifacts.

Run from the repository root:

    uv run python test/integration/test_simplex2_release.py observer-churn
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from tostester.install import Install
from tostester.network import FullNode, Network, StartOptions


OBSERVER_CREATED = re.compile(
    r"Created observer group (?P<shard>\S+)\.(?P<cc_seqno>\d+) at (?P<adnl>\S+)"
)
OBSERVER_STARTED = re.compile(
    r"Started observer group (?P<shard>\S+)\.(?P<cc_seqno>\d+) at (?P<adnl>\S+)"
)
OBSERVER_DESTROYED = re.compile(
    r"Destroying observer group (?P<shard>\S+)\.(?P<cc_seqno>\d+) at (?P<adnl>\S+)"
)
FATAL_LOG = re.compile(
    r"\b(FATAL|PANIC|CHECK failed|LOG_CHECK failed|AddressSanitizer|"
    r"UndefinedBehaviorSanitizer)\b",
    re.IGNORECASE,
)


@dataclass
class NodeEvidence:
    node: int
    start_height: int
    end_height: int
    observer_created: int
    observer_started: int
    observer_destroyed: int
    observer_sessions: list[str]
    fatal_lines: list[str]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="scenario", required=True)
    churn = subparsers.add_parser(
        "observer-churn",
        help="run real validator processes through repeated observer-group rotations",
    )
    churn.add_argument("--duration", type=float, default=60.0)
    churn.add_argument("--validators", type=int, default=7)
    churn.add_argument("--shard-validators", type=int, default=4)
    churn.add_argument("--group-lifetime", type=int, default=8)
    churn.add_argument("--base-port", type=int, default=22000)
    churn.add_argument("--threads", type=int, default=2)
    churn.add_argument(
        "--artifact-dir",
        type=Path,
        default=None,
        help="fresh output directory (default: build/simplex2-release/observer-churn-UTC)",
    )
    return parser.parse_args()


async def _masterchain_height(node: FullNode) -> int:
    client = await node.toslib_client()
    info = await client.get_masterchain_info()
    assert info.last is not None
    return info.last.seqno


async def _wait_all_heights(
    nodes: list[FullNode], minimum: int, timeout: float
) -> list[int]:
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            heights = list(
                await asyncio.gather(*(_masterchain_height(node) for node in nodes))
            )
            if min(heights) >= minimum:
                return heights
        except BaseException as error:
            last_error = error
        await asyncio.sleep(0.5)
    raise TimeoutError(
        f"validators did not all reach masterchain height {minimum}; "
        f"last error={last_error!r}"
    )


def _matches(text: str, pattern: re.Pattern[str]) -> list[re.Match[str]]:
    return list(pattern.finditer(text))


def _fresh_artifact_dir(repo_root: Path, requested: Path | None) -> Path:
    if requested is None:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        requested = repo_root / "build/simplex2-release" / f"observer-churn-{stamp}"
    requested = requested.resolve()
    safe_root = (repo_root / "build/simplex2-release").resolve()
    if safe_root not in requested.parents:
        raise ValueError(f"artifact directory must be below {safe_root}")
    if requested.exists():
        raise ValueError(f"artifact directory already exists: {requested}")
    requested.mkdir(parents=True)
    return requested


async def _observer_churn(args: argparse.Namespace) -> int:
    if args.validators < 4:
        raise ValueError("--validators must be at least 4")
    if not 1 <= args.shard_validators < args.validators:
        raise ValueError("--shard-validators must be in [1, validators)")
    if args.duration < args.group_lifetime * 3:
        raise ValueError("--duration must cover at least three group lifetimes")

    repo_root = Path(__file__).resolve().parents[2]
    artifact_dir = _fresh_artifact_dir(repo_root, args.artifact_dir)
    network_dir = artifact_dir / "network"
    network_dir.mkdir()
    install = Install(repo_root / "build", repo_root)
    install.toslibjson.client_set_verbosity_level(0)

    logging.basicConfig(
        level=logging.WARNING,
        format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
    )

    summary: dict[str, object] = {
        "scenario": "observer-churn",
        "git_commit": (
            await asyncio.create_subprocess_exec(
                "git",
                "-C",
                str(repo_root),
                "rev-parse",
                "HEAD",
                stdout=asyncio.subprocess.PIPE,
            )
        ),
        "validators": args.validators,
        "shard_validators": args.shard_validators,
        "group_lifetime_seconds": args.group_lifetime,
        "duration_seconds": args.duration,
        "base_port": args.base_port,
    }
    git_process = summary.pop("git_commit")
    assert isinstance(git_process, asyncio.subprocess.Process)
    stdout, _ = await git_process.communicate()
    summary["git_commit"] = stdout.decode().strip()

    started_at = time.monotonic()
    async with Network(install, network_dir, base_port=args.base_port) as network:
        network.config.shard_validators = args.shard_validators
        network.config.mc_valgroup_lifetime = args.group_lifetime
        network.config.shard_valgroup_lifetime = args.group_lifetime
        network.config.shard_validators_lifetime = args.group_lifetime

        dht = network.create_dht_node()
        nodes: list[FullNode] = []
        for _ in range(args.validators):
            node = network.create_full_node()
            node.make_initial_validator()
            node.announce_to(dht)
            nodes.append(node)
        for key_file in network_dir.glob("node*/keyring/*"):
            key_file.chmod(0o600)

        options = StartOptions(
            threads=args.threads,
            verbosity=3,
        )
        await dht.run(StartOptions(threads=1, verbosity=3))
        await asyncio.gather(*(node.run(options) for node in nodes))

        await network.wait_mc_block(seqno=2)
        start_heights = await _wait_all_heights(nodes, minimum=1, timeout=90.0)

        deadline = time.monotonic() + args.duration
        samples: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            heights = list(
                await asyncio.gather(*(_masterchain_height(node) for node in nodes))
            )
            samples.append(
                {
                    "elapsed_seconds": round(time.monotonic() - started_at, 3),
                    "heights": heights,
                    "spread": max(heights) - min(heights),
                }
            )
            await asyncio.sleep(min(2.0, max(0.1, deadline - time.monotonic())))

        end_heights = await _wait_all_heights(
            nodes, minimum=min(start_heights) + 3, timeout=30.0
        )

        evidence: list[NodeEvidence] = []
        for index, node in enumerate(nodes):
            text = node.log_path.read_text(errors="replace")
            created = _matches(text, OBSERVER_CREATED)
            started = _matches(text, OBSERVER_STARTED)
            destroyed = _matches(text, OBSERVER_DESTROYED)
            fatal_lines = [
                line[:1000] for line in text.splitlines() if FATAL_LOG.search(line)
            ]
            sessions = sorted(
                {
                    f"{match.group('shard')}.{match.group('cc_seqno')}@"
                    f"{match.group('adnl')}"
                    for match in created + started + destroyed
                }
            )
            evidence.append(
                NodeEvidence(
                    node=index + 1,
                    start_height=start_heights[index],
                    end_height=end_heights[index],
                    observer_created=len(created),
                    observer_started=len(started),
                    observer_destroyed=len(destroyed),
                    observer_sessions=sessions,
                    fatal_lines=fatal_lines,
                )
            )

        summary["samples"] = samples
        summary["nodes"] = [asdict(item) for item in evidence]
        summary["elapsed_seconds"] = round(time.monotonic() - started_at, 3)

        created_total = sum(item.observer_created for item in evidence)
        started_total = sum(item.observer_started for item in evidence)
        destroyed_total = sum(item.observer_destroyed for item in evidence)
        distinct_sessions = {
            session for item in evidence for session in item.observer_sessions
        }
        fatal_total = sum(len(item.fatal_lines) for item in evidence)

        failures: list[str] = []
        if min(end_heights) <= min(start_heights):
            failures.append("masterchain did not progress on every node")
        if max(end_heights) - min(end_heights) > 12:
            failures.append(f"final masterchain spread is too large: {end_heights}")
        if created_total == 0 or started_total == 0:
            failures.append("no real observer group was created and started")
        if destroyed_total == 0:
            failures.append("no observer group was destroyed during membership rotation")
        if len(distinct_sessions) < 2:
            failures.append("observer membership did not cover multiple sessions")
        if fatal_total:
            failures.append(f"validator logs contain {fatal_total} fatal diagnostics")

        verdict = "PASS" if not failures else "FAIL"
        summary.update(
            {
                "verdict": verdict,
                "observer_created": created_total,
                "observer_started": started_total,
                "observer_destroyed": destroyed_total,
                "distinct_observer_sessions": len(distinct_sessions),
                "failures": failures,
            }
        )
        (artifact_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n"
        )
        print(
            json.dumps(
                {
                    "verdict": verdict,
                    "artifact_dir": str(artifact_dir),
                    "start_heights": start_heights,
                    "end_heights": end_heights,
                    "observer_created": created_total,
                    "observer_started": started_total,
                    "observer_destroyed": destroyed_total,
                    "distinct_observer_sessions": len(distinct_sessions),
                    "failures": failures,
                },
                indent=2,
            )
        )
        return 0 if not failures else 1


async def _main() -> int:
    args = _parse_args()
    if args.scenario == "observer-churn":
        return await _observer_churn(args)
    raise AssertionError(args.scenario)


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except (ValueError, TimeoutError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error
