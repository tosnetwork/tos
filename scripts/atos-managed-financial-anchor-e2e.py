#!/usr/bin/env python3
"""Real three-validator TOS localnet acceptance for Phase 7A anchors."""

import asyncio
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path

from contract import tos
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage
from tostester.install import Install
from tostester.network import Network, StartOptions

REPO = Path(__file__).resolve().parents[1]
TOS_PROTOCOL = Path(os.environ.get("TOS_PROTOCOL_DIR", REPO.parent / "tos-protocol")).resolve()
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build"))
TOSCTL = Path(os.environ.get("TOSCTL", REPO / "tosctl/src/target/debug/tosctl")).resolve()
WORKDIR = REPO / "test/integration/.atos-managed-financial-anchor-e2e"
CONFIG = WORKDIR / "tosctl.json"
VAULT = WORKDIR / "vault.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
RPC_PORTS = (28645, 28646, 28647)
RPC_URLS = [f"http://127.0.0.1:{port}/jsonRPC" for port in RPC_PORTS]


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
    return await command(str(TOSCTL), *args, "-c", str(CONFIG), env=environment, timeout=timeout)


async def wallet_address(name: str) -> str:
    wallets = json.loads(await tosctl("wallet", "ls", "--format", "json"))
    for wallet in wallets:
        if wallet["name"] == name:
            return Address(wallet["address"]).to_str(is_user_friendly=False).lower()
    raise RuntimeError(f"wallet not found: {name}")


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


def rpc_ready(url: str) -> bool:
    import urllib.request

    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}}).encode()
    try:
        request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return "result" in json.loads(response.read().decode())
    except Exception:
        return False


def address_balance(url: str, address: str) -> int:
    import urllib.request

    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "getAddressInformation", "params": {"address": address}}
    ).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.loads(response.read().decode()).get("result", {})
    return int(result.get("balance", 0))


async def wait_balance(address: str, minimum_nanotos: int, timeout: float = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if address_balance(RPC_URLS[0], address) >= minimum_nanotos:
                return
        except Exception:
            pass
        await asyncio.sleep(1)
    raise RuntimeError(f"wallet {address} did not reach {minimum_nanotos} nanotos")


async def wait_all_rpc(timeout: float = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all(rpc_ready(url) for url in RPC_URLS):
            return
        await asyncio.sleep(2)
    raise RuntimeError("three-validator JSON-RPC quorum did not become ready")


async def main() -> int:
    if not TOSCTL.exists() or not (TOS_PROTOCOL / "go.mod").exists():
        print("tosctl or tos-protocol checkout is missing", file=sys.stderr)
        return 2
    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True)
    CONFIG.write_text(
        json.dumps(
            {
                "nodes": {},
                "wallets": {},
                "pools": {},
                "bindings": {},
                "chain_rpc": {"urls": [f"http://127.0.0.1:{RPC_PORTS[0]}/"]},
                "http": {},
                "master_wallet": None,
                "tick_interval": 40,
                "log": None,
            },
            indent=2,
        )
    )
    install = Install(BUILD_DIR, REPO)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")
    async with Network(install, WORKDIR / "net", base_port=28000) as network:
        dht = network.create_dht_node()
        validators = [network.create_full_node() for _ in RPC_PORTS]
        for node in validators:
            node.make_initial_validator()
            node.announce_to(dht)
        tasks = [asyncio.create_task(dht.run())]
        tasks.extend(
            asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", f"127.0.0.1:{port}"])))
            for node, port in zip(validators, RPC_PORTS)
        )
        try:
            await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=180)
            await wait_all_rpc()
            await tosctl("wallet", "create", "-n", "anchor-payer", "-v", "V3R2", "-w", "0")
            await tosctl("wallet", "create", "-n", "anchor-payee", "-v", "V3R2", "-w", "0")
            payer, payee = await wallet_address("anchor-payer"), await wallet_address("anchor-payee")
            client = await validators[0].toslib_client()
            faucet = network.zerostate.main_wallet(client)
            await faucet.send(faucet_transfer(faucet, payer, 20))
            await wait_balance(payer, 20_000_000_000)
            # The faucet wallet has a sequence number. Wait for the first
            # transfer to commit before constructing the next wallet message,
            # otherwise both messages can carry the same sequence number.
            await faucet.send(faucet_transfer(faucet, payee, 2))
            await wait_balance(payee, 2_000_000_000)
            await tosctl("wallet", "activate", "-n", "anchor-payer")
            await tosctl("wallet", "activate", "-n", "anchor-payee")
            await wait_balance(payer, 1)
            await wait_balance(payee, 1)
            environment = dict(os.environ)
            environment.update(
                {
                    "GOWORK": "off",
                    "VAULT_URL": f"file://{VAULT}?master_key={MASTER_KEY}",
                    "TOS_FINANCIAL_LOCALNET_ENDPOINTS": ",".join(RPC_URLS),
                    "TOS_FINANCIAL_LOCALNET_PAYER": payer,
                    "TOS_FINANCIAL_LOCALNET_PAYEE": payee,
                    "TOS_FINANCIAL_LOCALNET_TOSCTL": str(TOSCTL),
                    "TOS_FINANCIAL_LOCALNET_TOSCTL_CONFIG": str(CONFIG),
                    "TOS_FINANCIAL_LOCALNET_WALLET": "anchor-payer",
                }
            )
            output = await command(
                "go",
                "test",
                "./pkg/atosrpc",
                "-run",
                "TestManagedFinancialAnchorRealTOSLocalnet",
                "-count=1",
                "-v",
                cwd=TOS_PROTOCOL,
                env=environment,
                timeout=600,
            )
            print(output)
            if "PASS" not in output or "tos:tx:v1:" not in output:
                raise RuntimeError("localnet anchor acceptance evidence is incomplete")
            print("=== RESULT: REAL TOS MANAGED FINANCIAL ANCHOR PASS ===")
            return 0
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
