"""How long block application waits on the wc0 index, with the index off, on, and slow.

One local chain, one workload, three full nodes that only follow it:

- ``off``  runs without JSON-RPC, so no index hook is installed;
- ``on``   runs JSON-RPC, so every applied wc0 block goes through the hook;
- ``slow`` runs JSON-RPC with every sync of its index database delayed (an
  LD_PRELOAD shim that does nothing else), until the indexing queue saturates.

Every applied block's duration and every hook call's duration come from the
nodes' own debug log lines. The result reports sample counts, p95 and maximum
for each, the peak RSS of each node, and the evidence that the slow node's
index really was slow and its queue really did fill.

The run fails when the slow node's apply or hook latency departs from the
node without an index, which is what restoring a synchronous hook does.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import time
from pathlib import Path

from contract import WalletV1Blueprint, tos
from tostester.install import Install
from tostester.network import FullNode, Network, StartOptions

APPLY_LINE = re.compile(
    r"successfully finishing apply block query for \((0,[0-9a-f]+,\d+)\)[^ ]* in ([0-9.e+-]+) s"
)
HOOK_LINE = re.compile(r"wc0 index hook for \((0,[0-9a-f]+,\d+)\)[^ ]* took ([0-9.e+-]+) s")
SATURATED_LINE = "blocks behind; block"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--base-port", type=int, required=True)
    parser.add_argument("--validators", type=int, default=4)
    parser.add_argument("--duration", type=float, default=420.0, help="seconds of workload")
    parser.add_argument("--slow-sync-ms", type=int, default=1_000)
    parser.add_argument("--shim", type=Path, required=True, help="built slow_sync_preload.so")
    parser.add_argument("--hook-max-s", type=float, default=0.05)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def ports_free(first: int, count: int) -> bool:
    for port in range(first, first + count):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as s:
                try:
                    s.bind(("127.0.0.1", port))
                except OSError:
                    return False
    return True


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def summary(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"samples": 0}
    return {
        "samples": len(values),
        "p50_s": percentile(values, 0.50),
        "p95_s": percentile(values, 0.95),
        "max_s": max(values),
    }


def node_pid(directory: Path) -> int:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if Path(os.readlink(entry / "cwd")) == directory and "validator-engine" in (
                entry / "cmdline"
            ).read_bytes().decode(errors="replace"):
                return int(entry.name)
        except OSError:
            continue
    raise AssertionError(f"no validator-engine runs in {directory}")


def memory_kib(pid: int) -> dict[str, int]:
    fields = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        name, _, value = line.partition(":")
        if name in ("VmRSS", "VmHWM"):
            fields[name] = int(value.split()[0])
    return fields


def read_log(path: Path) -> dict[str, object]:
    """Per wc0 block: how long it took to apply, and how long its hook call took.

    A block can be applied by more than one query; the later ones find it
    applied and finish at once. The slowest is kept, so those cannot pull the
    percentiles down."""
    apply_wc0: dict[str, float] = {}
    hook_wc0: dict[str, float] = {}
    saturated = 0
    with path.open(errors="replace") as log:
        for line in log:
            if m := APPLY_LINE.search(line):
                apply_wc0[m.group(1)] = max(apply_wc0.get(m.group(1), 0.0), float(m.group(2)))
            elif m := HOOK_LINE.search(line):
                hook_wc0[m.group(1)] = max(hook_wc0.get(m.group(1), 0.0), float(m.group(2)))
            elif SATURATED_LINE in line and "wc0-index" in line:
                saturated += 1
    return {
        "apply_wc0": list(apply_wc0.values()),
        "hook_wc0": list(hook_wc0.values()),
        "hooked_blocks_not_applied": len(set(hook_wc0) - set(apply_wc0)),
        "saturation_warnings": saturated,
    }


async def main(args: argparse.Namespace) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    # Each node's ADNL port, and its QUIC port 1000 above it, must be unused:
    # the defaults collide with a testnet running on the same host.
    require(
        ports_free(args.base_port, 200) and ports_free(args.base_port + 1000, 200),
        f"ports {args.base_port}+200 and {args.base_port + 1000}+200 are not all free",
    )
    working_dir = args.working_dir.resolve()
    working_dir.mkdir(parents=True, exist_ok=False)
    install = Install(repo_root / "build", repo_root)
    install.toslibjson.client_set_verbosity_level(1)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s][%(asctime)s] %(message)s")

    async with Network(install, working_dir, base_port=args.base_port) as network:
        dht = network.create_dht_node()
        network.config.shard_validators = args.validators
        validators: list[FullNode] = []
        for index in range(args.validators):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"latency-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"latency-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            validators.append(node)
        followers = {name: network.create_full_node() for name in ("off", "on", "slow")}
        for node in followers.values():
            node.announce_to(dht)

        rpc_port = args.base_port + 150
        report = working_dir / "slow-sync-report"
        options = {
            "off": StartOptions(verbosity=4),
            "on": StartOptions(verbosity=4, args=["--json-rpc-address", f"127.0.0.1:{rpc_port}"]),
            "slow": StartOptions(
                verbosity=4,
                args=["--json-rpc-address", f"127.0.0.1:{rpc_port + 1}"],
                env={
                    "LD_PRELOAD": str(args.shim.resolve()),
                    "TOS_SLOW_SYNC_PATH": "/wc0-index/",
                    "TOS_SLOW_SYNC_MS": str(args.slow_sync_ms),
                    "TOS_SLOW_SYNC_REPORT": str(report),
                },
            ),
        }

        async with asyncio.TaskGroup() as group:
            _ = group.create_task(dht.run())
            for node in validators:
                _ = group.create_task(node.run(StartOptions(verbosity=2)))
            for name, node in followers.items():
                _ = group.create_task(node.run(options[name]))

        await network.wait_mc_block(seqno=1)
        _ = await network.wait_block(workchain=0, shard=-(2**63), seqno=1)

        client = await validators[0].toslib_client()
        main_wallet = network.zerostate.main_wallet(client)

        # The workload: new wc0 accounts, one after another, for the whole run.
        deployed = 0
        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            wallet = await main_wallet.deploy(WalletV1Blueprint(workchain=0), tos(1))
            started = time.monotonic()
            while time.monotonic() - started < 30:
                state = await client.raw_get_account_state(wallet.address)
                if state.balance > 0:
                    deployed += 1
                    break
                await asyncio.sleep(0.5)

        pids = {name: node_pid(node._directory) for name, node in followers.items()}
        memory = {name: memory_kib(pid) for name, pid in pids.items()}
        logs = {name: read_log(node.log_path) for name, node in followers.items()}
        for node in followers.values():
            await node.stop()

    require(report.exists(), "the slow node never reported its syncs")
    slowed, passed = (int(x) for x in report.read_text().split())

    result: dict[str, object] = {
        "scenario": "wc0-index-apply-latency",
        "commit": subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "duration_s": args.duration,
        "slow_sync_ms": args.slow_sync_ms,
        "wallets_deployed": deployed,
        "slow_index_syncs_delayed": slowed,
        "slow_other_syncs": passed,
        "nodes": {},
    }
    for name in followers:
        log = logs[name]
        result["nodes"][name] = {
            "apply_wc0": summary(log["apply_wc0"]),
            "hook_wc0": summary(log["hook_wc0"]),
            "queue_saturation_warnings": log["saturation_warnings"],
            "hooked_blocks_not_applied": log["hooked_blocks_not_applied"],
            "rss_kib": memory[name].get("VmRSS"),
            "peak_rss_kib": memory[name].get("VmHWM"),
        }
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps(result, indent=2, sort_keys=True))

    nodes = result["nodes"]
    off, slow = nodes["off"], nodes["slow"]
    # The instruments: each node applied wc0 blocks, the index nodes called the
    # hook, the node without an index did not, and the slow node's index was
    # slowed until its queue filled.
    require(deployed > 0, "the workload produced no wc0 transactions")
    for name in ("off", "on", "slow"):
        require(nodes[name]["apply_wc0"]["samples"] >= 50, f"{name} applied too few wc0 blocks")
    require(off["hook_wc0"]["samples"] == 0, "the node without JSON-RPC called the hook")
    for name in ("on", "slow"):
        require(
            nodes[name]["hook_wc0"]["samples"] >= nodes[name]["apply_wc0"]["samples"] * 0.9,
            f"{name} did not call the hook for its applied wc0 blocks",
        )
    require(slowed > 0, "no sync of the slow node's index was delayed")

    # The claim: however slow the index, block application does not wait on it.
    for name in ("on", "slow"):
        require(
            nodes[name]["hook_wc0"]["max_s"] <= args.hook_max_s,
            f"{name}: the hook held block application for {nodes[name]['hook_wc0']['max_s']} s",
        )
        limit = max(2 * off["apply_wc0"]["p95_s"], off["apply_wc0"]["p95_s"] + 0.05)
        require(
            nodes[name]["apply_wc0"]["p95_s"] <= limit,
            f"{name}: apply p95 {nodes[name]['apply_wc0']['p95_s']} s against {limit} s without an index",
        )

    # And it held with the slow index's queue full, which is when a hook that
    # waited on the index would wait longest.
    require(slow["queue_saturation_warnings"] > 0, "the slow node's index queue never filled")


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
