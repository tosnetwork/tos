#!/usr/bin/env python3
# Copyright (C) 2025-2026 TOS Network.
"""Real-localnet acceptance test for the ATOS TaskEscrow key-custody sidecar.

The test starts a real local TOS validator, provisions creator/provider/verifier
wallets, starts the Go sidecar over an owner-private Unix socket, and drives the
Go contract Economic Driver through deploy, accept, result, settle, replay and
cancel/refund. The driver independently observes every candidate transaction
through three loopback quorum proxies.
"""

import asyncio
import json
import logging
import os
import shutil
import socket
import sys
import time
from pathlib import Path

from contract import tos
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage
from tostester.install import Install
from tostester.network import Network, StartOptions

REPO = Path(__file__).resolve().parents[1]
TOS_PROTOCOL = Path(os.environ.get("TOS_PROTOCOL_DIR", REPO.parent / "tos-protocol")).resolve()
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = Path(os.environ.get("TOSCTL", REPO / "tosctl/src/target/debug/tosctl")).resolve()
GO = os.environ.get("GO", "go")
RPC = "127.0.0.1:18546"
RPC_URL = f"http://{RPC}/jsonRPC"
WORKDIR = REPO / "test/integration/.atos-task-escrow-publisher-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
VAULT = WORKDIR / "e2e-vault.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
NANO = 1_000_000_000
BUDGET = 5 * NANO
PAYOUT = 3 * NANO
OVERHEAD = 200_000_000
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"  PASS: {label}")
    else:
        print(f"  FAIL: {label} {detail}")
        failures.append(label)


def rpc_call(method: str, **params):
    import urllib.request

    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        RPC_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode())


def balance(address: str) -> int:
    return int(rpc_call("getAddressInformation", address=address)["result"]["balance"])


def norm_addr(address: str) -> str:
    return Address(address).to_str(is_user_friendly=False).lower()


async def command(*args: str, cwd: Path | None = None, env=None, timeout: float = 600) -> str:
    process = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError(f"command timed out: {' '.join(args)}")
    if process.returncode != 0:
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(args)}\n"
            f"stdout:\n{stdout.decode()}\nstderr:\n{stderr.decode()}"
        )
    return stdout.decode().strip()


async def tosctl(*args: str, timeout: float = 180) -> str:
    environment = dict(os.environ)
    environment["VAULT_URL"] = f"file://{VAULT}?master_key={MASTER_KEY}"
    return await command(
        str(TOSCTL), *args, "-c", str(CONFIG), env=environment, timeout=timeout
    )


async def tosctl_json(*args: str):
    return json.loads(await tosctl(*args, "--format", "json"))


def write_tosctl_config() -> None:
    CONFIG.write_text(
        json.dumps(
            {
                "nodes": {},
                "wallets": {},
                "pools": {},
                "bindings": {},
                "chain_rpc": {"urls": [f"http://{RPC}/"]},
                "http": {},
                "master_wallet": None,
                "tick_interval": 40,
                "log": None,
            },
            indent=2,
        )
    )


async def wallet_address(name: str) -> str:
    for item in await tosctl_json("wallet", "ls"):
        if item["name"] == name and item.get("address"):
            return norm_addr(item["address"])
    raise RuntimeError(f"wallet {name} has no address")


def faucet_transfer(faucet, destination: str, amount_tos: float) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=False,
                bounced=False,
                src=faucet.address,
                dest=Address(destination),
                value=tos(amount_tos),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=None,
            body=Cell.empty(),
        ),
    )


async def wait_balance(address: str, minimum: int, timeout: float = 90) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if balance(address) >= minimum:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def wait_rpc(timeout: float = 180) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if "result" in rpc_call("getMasterchainInfo"):
                return True
        except Exception:
            pass
        await asyncio.sleep(2)
    return False


async def wait_sidecar(socket_path: Path, timeout: float = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2)
            client.connect(str(socket_path))
            client.sendall(b"GET /healthz HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n\r\n")
            response = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
            client.close()
            if b" 200 " in response and b'"status":"ready"' in response:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def build_go_tools() -> tuple[Path, Path]:
    if not (TOS_PROTOCOL / "go.mod").exists():
        raise RuntimeError(f"tos-protocol source not found at {TOS_PROTOCOL}")
    sidecar = WORKDIR / "bin/tos-task-escrow-publisher"
    harness = WORKDIR / "bin/taskescrow-localnet"
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["GOWORK"] = "off"
    await command(
        GO,
        "build",
        "-trimpath",
        "-o",
        str(sidecar),
        "./cmd/tos-task-escrow-publisher",
        cwd=TOS_PROTOCOL,
        env=environment,
        timeout=600,
    )
    await command(
        GO,
        "build",
        "-trimpath",
        "-o",
        str(harness),
        "./tests/localnet/taskescrow",
        cwd=TOS_PROTOCOL,
        env=environment,
        timeout=600,
    )
    return sidecar, harness


async def run_checks(faucet) -> None:
    print("\n=== build publisher and driver harness ===")
    sidecar_binary, harness_binary = await build_go_tools()
    check("publisher binary built", sidecar_binary.exists())
    check("driver harness built", harness_binary.exists())

    print("\n=== provision TOS wallets ===")
    for name in ("creator", "provider", "verifier"):
        await tosctl("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    creator = await wallet_address("creator")
    provider = await wallet_address("provider")
    verifier = await wallet_address("verifier")
    for name, address in (("creator", creator), ("provider", provider), ("verifier", verifier)):
        await faucet.send(faucet_transfer(faucet, address, 50))
        check(f"{name} funded", await wait_balance(address, 49 * NANO))
        await tosctl("wallet", "activate", "-n", name)
    await asyncio.sleep(5)

    print("\n=== derive reviewed TaskEscrow code hash ===")
    deadline = int(time.time()) + 7200
    state = await tosctl_json(
        "agent",
        "task",
        "build-state",
        "--creator",
        creator,
        "--agent",
        provider,
        "--verifier",
        verifier,
        "--budget-nanotos",
        str(BUDGET),
        "--deadline",
        str(deadline),
        "--review-period",
        "3600",
        "--policy-hash",
        "11" * 32,
        "--permission-hash",
        "22" * 32,
        "--workchain",
        "0",
    )
    code_hash = "tvm-cell-sha256:" + state["code_hash"]
    check("TaskEscrow code hash derived", len(state["code_hash"]) == 64, code_hash)

    runtime_dir = WORKDIR / "run"
    state_dir = WORKDIR / "publisher-state"
    runtime_dir.mkdir(mode=0o700)
    state_dir.mkdir(mode=0o700)
    socket_path = runtime_dir / "task-escrow-publisher.sock"
    publisher_config = WORKDIR / "publisher.json"
    publisher_config.write_text(
        json.dumps(
            {
                "version": "1",
                "network": "tos-localnet",
                "socketPath": str(socket_path),
                "statePath": str(state_dir / "state.db"),
                "backend": {
                    "network": "tos-localnet",
                    "tosctlBinary": str(TOSCTL),
                    "tosctlConfig": str(CONFIG),
                    "vaultUrl": f"file://{VAULT}?master_key={MASTER_KEY}",
                    "rpcUrl": RPC_URL,
                    "wallets": {
                        creator: "creator",
                        provider: "provider",
                        verifier: "verifier",
                    },
                    "executorWallet": "verifier",
                    "workchain": 0,
                    "operationAmountNanoTOS": 10_000_000,
                    "commandTimeoutMillis": 120_000,
                    "publishTimeoutMillis": 90_000,
                    "recoveryWaitMillis": 15_000,
                    "pollIntervalMillis": 500,
                    "transactionLookback": 32,
                },
            },
            indent=2,
        )
    )
    publisher_config.chmod(0o600)
    sidecar_stdout_path = WORKDIR / "sidecar.stdout.log"
    sidecar_stderr_path = WORKDIR / "sidecar.stderr.log"
    sidecar_stdout = sidecar_stdout_path.open("wb")
    sidecar_stderr = sidecar_stderr_path.open("wb")
    environment = dict(os.environ)
    environment["TOS_TASK_ESCROW_PUBLISHER_CONFIG"] = str(publisher_config)
    sidecar_process = await asyncio.create_subprocess_exec(
        str(sidecar_binary),
        env=environment,
        stdout=sidecar_stdout,
        stderr=sidecar_stderr,
    )
    try:
        ready = await wait_sidecar(socket_path)
        check("publisher health ready", ready)
        if not ready:
            sidecar_stdout.flush()
            sidecar_stderr.flush()
            print("\n--- publisher sidecar stdout ---")
            print(sidecar_stdout_path.read_text(errors="replace") or "(empty)")
            print("--- publisher sidecar stderr ---")
            print(sidecar_stderr_path.read_text(errors="replace") or "(empty)")
            return
        harness_config = WORKDIR / "driver.json"
        harness_config.write_text(
            json.dumps(
                {
                    "version": "1",
                    "network": "tos-localnet",
                    "rpcUrl": RPC_URL,
                    "publisherSocket": str(socket_path),
                    "allowedCodeHash": code_hash,
                    "creator": creator,
                    "agent": provider,
                    "verifier": verifier,
                    "budgetNanoTOS": BUDGET,
                    "payoutNanoTOS": PAYOUT,
                    "fundingOverheadNanoTOS": OVERHEAD,
                },
                indent=2,
            )
        )
        harness_output = await command(str(harness_binary), str(harness_config), timeout=600)
        result = json.loads(harness_output)
        check("real-chain economic driver completed", result.get("ok") is True, harness_output)
        check("provider payout exact", result.get("providerPaidNanoTOS") == PAYOUT, harness_output)
        check(
            "principal refund exact-or-greater",
            result.get("principalRefundedNanoTOS", 0) >= BUDGET - PAYOUT,
            harness_output,
        )
        check("settlement has TOS tx reference", str(result.get("settlementReference", "")).startswith("tos:tx:v1:"))
        check("release has TOS tx reference", str(result.get("releaseReference", "")).startswith("tos:tx:v1:"))
    finally:
        sidecar_process.terminate()
        try:
            await asyncio.wait_for(sidecar_process.wait(), timeout=10)
        except TimeoutError:
            sidecar_process.kill()
            await sidecar_process.wait()
        sidecar_stdout.close()
        sidecar_stderr.close()


async def main() -> int:
    if not TOSCTL.exists():
        print(
            f"FATAL: tosctl binary not found at {TOSCTL} "
            "(build with cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
            file=sys.stderr,
        )
        return 2
    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    write_tosctl_config()
    install = Install(BUILD_DIR, REPO)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")
    async with Network(install, WORKDIR / "net", base_port=25000) as network:
        dht = network.create_dht_node()
        node = network.create_full_node()
        node.make_initial_validator()
        node.announce_to(dht)
        dht_task = asyncio.create_task(dht.run())
        node_task = asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", RPC])))
        try:
            await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=180)
            if not await wait_rpc():
                raise RuntimeError("localnet JSON-RPC did not become ready")
            client = await node.toslib_client()
            faucet = network.zerostate.main_wallet(client)
            await run_checks(faucet)
        finally:
            dht_task.cancel()
            node_task.cancel()
            await asyncio.gather(dht_task, node_task, return_exceptions=True)
    return 1 if failures else 0


if __name__ == "__main__":
    return_code = asyncio.run(main())
    if return_code == 0:
        print("\n=== RESULT: ALL PASS ===")
    else:
        print(f"\n=== RESULT: {len(failures)} FAILURES ===")
        for failure in failures:
            print(f"  - {failure}")
    raise SystemExit(return_code)
