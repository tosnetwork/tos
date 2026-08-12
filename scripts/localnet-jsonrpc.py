#!/usr/bin/env python3
"""
localnet-jsonrpc.py - Lightweight single-process local TOS chain + JSON-RPC (for wallet dev).

No systemd: uses tostester's Network to bring up 1 DHT + N validators in this process,
with every validator serving JSON-RPC HTTP on consecutive ports (default
127.0.0.1:18545-18547 for three validators), staying resident
once blocks are produced.

Run:
    uv run python scripts/localnet-jsonrpc.py
Self-test "balance change from a faucet transfer" (read via JSON-RPC, same path as the app):
    ... scripts/localnet-jsonrpc.py --demo
Fund your app wallet address (repeatable):
    ... scripts/localnet-jsonrpc.py --fund 0:abc...:25     # send 25 TOS to that address

Stop: Ctrl-C. In the Android emulator the wallet base url is http://10.0.2.2:18545 (10.0.2.2 = emulator -> host).
"""
import argparse
import asyncio
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import logging

from tostester.install import Install
from tostester.network import FullNode, Network, StartOptions
from contract import WalletV1Blueprint, tos
from pytosiq_core import (
    Address, Builder, Cell, InternalMsgInfo, MessageAny, WalletMessage,
)

REPO = Path(__file__).resolve().parents[1]


def rpc_call(rpc_addr: str, method: str, **params):
    """Read path identical to the Android wallet: POST http://<rpc>/jsonRPC."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{rpc_addr}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


def rpc_balance_nano(rpc_addr: str, address: str) -> int:
    r = rpc_call(rpc_addr, "getAddressInformation", address=address)
    return int(r["result"]["balance"])


def fmt(nano: int) -> str:
    return f"{nano/1e9:.9f} TOS"


def make_transfer(faucet, dest: Address, amount_tos) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=faucet.address, dest=dest, value=tos(amount_tos),
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0,
            ),
            init=None,
            body=Cell.empty(),
        ),
    )


async def wait_balance_at_least(rpc_addr, address, target_nano, timeout=30.0):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if rpc_balance_nano(rpc_addr, address) >= target_nano:
                return True
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return False


def start_control_server(control_addr, loop, faucet, rpc_addr):
    """Start a localhost-only faucet endpoint for autonomous integration tests."""

    async def transfer(address, amount):
        destination = Address(address)
        canonical = destination.to_str()
        before = rpc_balance_nano(rpc_addr, canonical)
        await faucet.send(make_transfer(faucet, destination, amount))
        ok = await wait_balance_at_least(rpc_addr, canonical, before + 1, timeout=40)
        after = rpc_balance_nano(rpc_addr, canonical)
        if not ok:
            raise TimeoutError("local-chain transfer did not confirm")
        return {"before": str(before), "after": str(after)}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def reply(self, status, value):
            payload = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/readyz":
                self.reply(200, {"ok": True})
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path != "/transfer":
                self.send_error(404)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                value = json.loads(self.rfile.read(size))
                future = asyncio.run_coroutine_threadsafe(
                    transfer(value["address"], float(value.get("amount", 1))), loop
                )
                self.reply(200, future.result(timeout=60))
            except Exception as error:
                self.reply(500, {"error": str(error)})

    host, port = control_addr.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


async def main(rpc_addr, control_addr, num_validators, workdir, boot_timeout, demo, fund):
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    install = Install(REPO / "build", REPO)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    async with Network(install, workdir) as network:
        dht = network.create_dht_node()
        nodes: list[FullNode] = []
        for _ in range(num_validators):
            node = network.create_full_node()
            node.make_initial_validator()
            node.announce_to(dht)
            nodes.append(node)

        rpc_host, rpc_port_text = rpc_addr.rsplit(":", 1)
        rpc_addresses = [f"{rpc_host}:{int(rpc_port_text) + index}" for index in range(num_validators)]
        node_tasks = [asyncio.create_task(dht.run())]
        for i, node in enumerate(nodes):
            extra = ["--json-rpc-address", rpc_addresses[i]]
            node_tasks.append(asyncio.create_task(node.run(StartOptions(args=extra))))

        print(f"[localnet] validators={num_validators}; waiting for masterchain block #1 ...")
        await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=boot_timeout)

        client = await nodes[0].toslib_client()
        faucet = network.zerostate.main_wallet(client)
        faucet_addr = faucet.address.to_str()
        control_server = start_control_server(control_addr, asyncio.get_running_loop(), faucet, rpc_addr)
        port = rpc_addr.rsplit(":", 1)[-1]

        print("=" * 70)
        print(" TOS LOCALNET READY")
        print(f"   JSON-RPC : {', '.join(f'http://{address}/jsonRPC' for address in rpc_addresses)}")
        print(f"   control  : http://{control_addr} (localhost test faucet only)")
        print(f"   faucet   : {faucet_addr}  balance {fmt(rpc_balance_nano(rpc_addr, faucet_addr))}")
        print(f"   emulator : http://10.0.2.2:{port}")
        print("=" * 70)

        # ---- Self-test: faucet deploys and funds a new wallet, observe balance change via JSON-RPC ----
        if demo:
            bp = WalletV1Blueprint(workchain=0)
            new_addr = bp.address.to_str()
            print(f"[demo] new wallet address: {new_addr}")
            before = rpc_balance_nano(rpc_addr, new_addr)
            print(f"[demo] balance before (via JSON-RPC): {fmt(before)}")
            print("[demo] faucet deploys and funds 5 TOS ...")
            _ = await faucet.deploy(bp, tos(5))
            ok = await wait_balance_at_least(rpc_addr, new_addr, before + 1, timeout=40)
            after = rpc_balance_nano(rpc_addr, new_addr)
            print(f"[demo] balance after (via JSON-RPC): {fmt(after)}   changed={'ok' if ok else 'TIMEOUT'} (+{fmt(after-before)})")

        # ---- Fund an arbitrary address (your app wallet) ----
        for spec in (fund or []):
            if ":" in spec and not spec.split(":", 1)[0].lstrip("-").isdigit():
                # form like 0:hex:amount -- the last segment is the amount
                addr_str, amt = spec.rsplit(":", 1)
                amount = float(amt)
            elif spec.count(":") >= 2:
                addr_str, amt = spec.rsplit(":", 1)
                amount = float(amt)
            else:
                addr_str, amount = spec, 10.0
            dest = Address(addr_str)
            before = rpc_balance_nano(rpc_addr, dest.to_str())
            print(f"[fund] sending {amount} TOS to {addr_str} (before {fmt(before)}) ...")
            await faucet.send(make_transfer(faucet, dest, amount))
            ok = await wait_balance_at_least(rpc_addr, dest.to_str(), before + 1, timeout=40)
            after = rpc_balance_nano(rpc_addr, dest.to_str())
            print(f"[fund] done: {fmt(after)}  {'ok' if ok else 'TIMEOUT'} (+{fmt(after-before)})")

        print("[localnet] resident; press Ctrl-C to exit.")
        try:
            await asyncio.Event().wait()
        finally:
            control_server.shutdown()
            for task in node_tasks:
                task.cancel()
            await asyncio.gather(*node_tasks, return_exceptions=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rpc", default="127.0.0.1:18545")
    p.add_argument("--control", default="127.0.0.1:18745")
    p.add_argument("--validators", type=int, default=1)
    p.add_argument("--workdir", default=str(REPO / "test/integration/.localnet"))
    p.add_argument("--boot-timeout", type=float, default=120.0)
    p.add_argument("--demo", action="store_true", help="self-test faucet -> new wallet balance change")
    p.add_argument("--fund", action="append", help="fund an address, form 0:hex or 0:hex:25")
    a = p.parse_args()
    try:
        asyncio.run(main(a.rpc, a.control, a.validators, Path(a.workdir), a.boot_timeout, a.demo, a.fund))
    except KeyboardInterrupt:
        print("\n[localnet] stopped.")
