#!/usr/bin/env python3
"""Run the diagnostic N6 scale-sweep instrument."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from tostester.install import Install
from tostester.n6_cluster import run_scale_sweep
from tostester.process_backend import LocalProcessBackend, RemoteCommandBackend


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--scales", type=int, nargs="+", required=True)
    parser.add_argument("--base-port", type=int, default=29800)
    parser.add_argument(
        "--allow-local-multi-scale-diagnostic",
        action="store_true",
        help="allow multiple co-located local scale points; never release evidence",
    )
    parser.add_argument("--remote-command-inventory", type=Path)
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.remote_command_inventory is None:
        backend = LocalProcessBackend()
    else:
        inventory = json.loads(args.remote_command_inventory.read_text(encoding="utf-8"))
        backend = RemoteCommandBackend(inventory["commands"], inventory.get("network_profile"))
    result = await run_scale_sweep(
        Install(args.build_dir.resolve(), root),
        args.artifact_dir.resolve(),
        backend,
        args.scales,
        args.profile.resolve(),
        args.base_port,
        args.allow_local_multi_scale_diagnostic,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except (RuntimeError, TimeoutError, ValueError) as error:
        print(error)
        raise SystemExit(1) from error
