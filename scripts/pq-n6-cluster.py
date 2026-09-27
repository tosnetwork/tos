#!/usr/bin/env python3
"""Run the N6.3 diagnostic multi-process PQ cluster scaffold."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from tostester.install import Install
from tostester.n6_cluster import SustainedObservationConfig, run_cluster
from tostester.process_backend import LocalProcessBackend, RemoteCommandBackend


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--validators", type=int, default=4)
    parser.add_argument("--base-port", type=int, default=29400)
    parser.add_argument(
        "--scenario",
        choices=("live-finality", "lite-framed-tcp", "sustained-consensus"),
        required=True,
    )
    duration = parser.add_mutually_exclusive_group()
    duration.add_argument("--sustain-blocks", type=int)
    duration.add_argument("--sustain-seconds", type=float)
    parser.add_argument("--slow-interval-factor", type=float, default=3.0)
    parser.add_argument("--remote-command-inventory", type=Path)
    parser.add_argument(
        "--trace-adnl-queries",
        action="store_true",
        help="enable DEBUG client query-id logs for a diagnostic run",
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.remote_command_inventory is None:
        backend = LocalProcessBackend()
    else:
        inventory = json.loads(args.remote_command_inventory.read_text())
        backend = RemoteCommandBackend(inventory["commands"], inventory.get("network_profile"))
    if args.scenario == "sustained-consensus":
        if args.sustain_blocks is None and args.sustain_seconds is None:
            raise ValueError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: sustained-consensus requires "
                "--sustain-blocks or --sustain-seconds"
            )
        sustained = SustainedObservationConfig(
            blocks=args.sustain_blocks,
            seconds=args.sustain_seconds,
            target_block_rate_ms=400,
            slow_interval_factor=args.slow_interval_factor,
        )
    else:
        if args.sustain_blocks is not None or args.sustain_seconds is not None:
            raise ValueError(
                "N6_SUSTAINED_CONSENSUS_FAILURE: sustained duration requires "
                "--scenario sustained-consensus"
            )
        sustained = None
    install = Install(args.build_dir.resolve(), root)
    if args.trace_adnl_queries:
        install.toslibjson.client_set_verbosity_level(4)
    result = await run_cluster(
        install,
        args.artifact_dir.resolve(),
        backend,
        args.validators,
        args.base_port,
        args.scenario == "lite-framed-tcp",
        sustained=sustained,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except (RuntimeError, TimeoutError, ValueError) as error:
        print(error)
        raise SystemExit(1) from error
