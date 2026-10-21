#!/usr/bin/env python3
"""Run TOK-01 with disposable global-id-3 state and systemd-managed nodes."""

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

from contract import WalletV1Blueprint, tos
from tostester.install import Install
from tostester.network import Network, StartOptions
from tostester.pq_initial_validator import make_deterministic_pq_initial_validator
from tostester.process_backend import ProcessBackend

spec = importlib.util.spec_from_file_location(
    "tok01", Path(__file__).with_name("tok01-lifecycle.py")
)
tok01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tok01)


class SystemdBackend(ProcessBackend):
    def __init__(self, prefix, runtime_libraries=None):
        self.prefix = prefix
        self.runtime_libraries = runtime_libraries
        self.units = []

    async def spawn(self, node_name, executable, args, cwd, env, capture_stdout=False):
        unit = f"{self.prefix}-{node_name}"
        self.units.append(unit)
        command = [str(executable), *map(str, args)]
        if self.runtime_libraries:
            command = [
                str(self.runtime_libraries / "ld-linux-x86-64.so.2"),
                "--library-path",
                str(self.runtime_libraries),
                *command,
            ]
        return await asyncio.create_subprocess_exec(
            "systemd-run",
            "--user",
            "--wait",
            "--pipe",
            "--collect",
            "--quiet",
            "--unit",
            unit,
            "--slice",
            f"{self.prefix}.slice",
            "--working-directory",
            str(cwd),
            *[
                f"--setenv={key}={env[key]}"
                for key in ("PATH", "LD_LIBRARY_PATH", "TOS_AUTH_NETWORK_TAG")
                if key in env
            ],
            *command,
            stdout=asyncio.subprocess.PIPE if capture_stdout else None,
            stderr=asyncio.subprocess.PIPE,
        )

    def manifest(self):
        return {"kind": "systemd-user", "prefix": self.prefix}

    async def stop(self):
        for unit in self.units:
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "--user",
                "stop",
                unit,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await process.wait()
        # Let systemd-run reap each process before Network closes its log streams.
        await asyncio.sleep(2)


async def run(args):
    if args.runtime.exists() or args.output.exists():
        raise ValueError("Runtime and evidence paths must both be new")
    if shutil.disk_usage(args.runtime.parent).free < 240 * 1024**3:
        raise RuntimeError("Less than 240 GiB free before the 40 GiB budget")
    os.environ["TOS_AUTH_NETWORK_TAG"] = hashlib.sha256(args.prefix.encode()).hexdigest()
    backend = SystemdBackend(args.prefix, args.runtime_libraries)
    subprocess.run(
        [
            "systemctl",
            "--user",
            "set-property",
            f"{args.prefix}.slice",
            "CPUQuota=800%",
            "MemoryMax=12G",
            "MemorySwapMax=0",
        ],
        check=True,
    )
    network = Network(
        Install(args.build.resolve(), tok01.REPO),
        args.runtime,
        base_port=args.base_port,
        process_backend=backend,
    )
    async with network:
        network.config.global_id = 3
        network.config.deployment_fee_schedule = True
        node = network.create_full_node()
        dht = network.create_dht_node()
        make_deterministic_pq_initial_validator(node, 0)
        node.announce_to(dht)
        tasks = [
            asyncio.create_task(dht.run()),
            asyncio.create_task(
                node.run(
                    StartOptions(
                        args=["--json-rpc-address", f"127.0.0.1:{args.rpc_port}", "--threads", "4"]
                    )
                )
            ),
        ]
        try:
            await asyncio.wait_for(network.wait_mc_block(seqno=2), timeout=180)
            client = await node.toslib_client()
            faucet = network.zerostate.main_wallet(client)
            blueprints = [WalletV1Blueprint(workchain=0) for _ in range(3)]
            wallets = [bp.materialize(client) for bp in blueprints]

            async def send(sender, message):
                wallet = next(w for w in wallets if tok01.raw(w.address) == tok01.raw(sender))
                await wallet.send(message)

            harness = tok01.Harness(
                f"http://127.0.0.1:{args.rpc_port}/jsonRPC",
                args.output,
                send,
                [bp.address for bp in blueprints],
            )
            for blueprint in blueprints:
                await faucet.deploy(blueprint, tos(10))
                await harness.wait(
                    lambda: (
                        harness.rpc("getAddressState", address=tok01.raw(blueprint.address))
                        == "active"
                    )
                )
            provenance = {
                "source_head": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=tok01.REPO, text=True
                ).strip(),
                "global_id": 3,
                "limits": {"cpus": 8, "ram_gib": 12, "disk_gib": 40},
                "auth_network_tag": os.environ["TOS_AUTH_NETWORK_TAG"],
                "node_sha256": hashlib.sha256(
                    (args.build / "validator-engine/validator-engine").read_bytes()
                ).hexdigest(),
                "owners": [tok01.raw(bp.address) for bp in blueprints],
            }
            (args.output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
            return await harness.run()
        finally:
            await backend.stop()
            await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=tok01.REPO / "build")
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prefix", default="bailu-tok01")
    parser.add_argument("--base-port", type=int, default=28600)
    parser.add_argument("--rpc-port", type=int, default=28680)
    parser.add_argument(
        "--runtime-libraries",
        type=Path,
        help="Compatible loader and libraries for systemd-managed native nodes",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
