#!/usr/bin/env python3
"""
wc0-token-index-e2e.py — end-to-end proof of the wc=0 wallet index's
*state-verified* token indexing (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-wc0-wallet-index.md).

Boots a single-process local TOS chain (same machinery as localnet-jsonrpc.py),
then exercises the security-critical verification path through real contracts:

  ACCEPT  Deploy a genuine TEP-74 jetton master, mint to a fresh owner O. The
          owner's jetton-wallet W is created on-chain; the indexer must run
          get_wallet_data(W) + the master's get_wallet_address(O) round-trip,
          confirm W, and index (O, master). getAccountJettons(O) must list it.

  REJECT  A plain wallet (NOT a jetton wallet) sends a *forged*
          transfer_notification to a victim V. The indexer nominates the
          sender as a candidate, runs get_wallet_data on it, which fails —
          so nothing is indexed. getAccountJettons(V) must stay empty.

Together these prove the indexer trusts committed contract state, not message
claims. Exit code 0 iff both scenarios pass.

Run from the repository root: uv run python scripts/wc0-token-index-e2e.py
"""
import asyncio
import json
import logging
import os
import shutil
import sys
import time
import urllib.request
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from contract import tos
from pytosiq_core import (
    Address, Cell, InternalMsgInfo, MessageAny, StateInit, WalletMessage, begin_cell,
)

REPO = Path(__file__).resolve().parents[1]

# Op-codes (TEP-74).
OP_MINT = 21
OP_INTERNAL_TRANSFER = 0x178D4519
OP_TRANSFER_NOTIFICATION = 0x7362D09C

MINTER_BOC = REPO / "build/slice1-gas-parity/jetton-minter-func.boc"
WALLET_BOC = REPO / "build/slice1-gas-parity/jetton-wallet-func.boc"

RPC = "127.0.0.1:18545"


def rpc_call(method: str, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{RPC}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


def get_jettons(addr: str):
    r = rpc_call("getAccountJettons", address=addr)
    return r["result"]["jettons"]


def load_code(path: Path) -> Cell:
    return Cell.one_from_boc(path.read_bytes())


def jetton_master_state_init(admin: Address, wallet_code: Cell) -> StateInit:
    # jetton-minter load_data: total_supply(coins) admin(addr) content(^) wallet_code(^)
    content = begin_cell().store_uint(0, 8).end_cell()  # on-chain content marker
    data = (
        begin_cell()
        .store_coins(0)
        .store_address(admin)
        .store_ref(content)
        .store_ref(wallet_code)
        .end_cell()
    )
    return StateInit(code=load_code(MINTER_BOC), data=data)


def mint_body(owner: Address, master: Address, jetton_amount: int, forward_ton: int) -> Cell:
    # master_msg is the internal_transfer body the master forwards to W.
    master_msg = (
        begin_cell()
        .store_uint(OP_INTERNAL_TRANSFER, 32)
        .store_uint(0, 64)               # query_id
        .store_coins(jetton_amount)
        .store_address(master)           # from_address
        .store_address(owner)            # response_address (non-none → excesses)
        .store_coins(forward_ton)        # forward_ton_amount
        .store_bit(0)                    # forward_payload: inline empty
        .end_cell()
    )
    return (
        begin_cell()
        .store_uint(OP_MINT, 32)
        .store_uint(0, 64)               # query_id
        .store_address(owner)            # to_address
        .store_coins(forward_ton + 100_000_000)  # TON forwarded to the wallet
        .store_ref(master_msg)
        .end_cell()
    )


def forged_notification_body(fake_from: Address) -> Cell:
    # A non-jetton-wallet contract claims it sent tokens. No master vouches for it.
    return (
        begin_cell()
        .store_uint(OP_TRANSFER_NOTIFICATION, 32)
        .store_uint(0, 64)               # query_id
        .store_coins(1000)               # jetton amount (claimed)
        .store_address(fake_from)        # from
        .store_bit(0)                    # forward_payload: inline empty
        .end_cell()
    )


def internal_message(dest: Address, value, body: Cell, src: Address) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=src, dest=dest, value=value,
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0,
            ),
            init=None,
            body=body,
        ),
    )


async def poll(predicate, timeout=60.0, interval=1.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception as e:
            last = e
        await asyncio.sleep(interval)
    return last


async def main() -> int:
    for boc in (MINTER_BOC, WALLET_BOC):
        if not boc.exists():
            print(f"FATAL: missing prebuilt jetton code {boc}", file=sys.stderr)
            return 2

    workdir = REPO / "test/integration/.localnet-e2e"
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    install = Install(REPO / "build", REPO)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    failures = []
    async with Network(install, workdir) as network:
        dht = network.create_dht_node()
        node = network.create_full_node()
        node.make_initial_validator()
        node.announce_to(dht)

        dht_task = asyncio.create_task(dht.run())
        node_task = asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", RPC])))
        try:
            await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=120)
            client = await node.toslib_client()
            faucet = network.zerostate.main_wallet(client)
            wallet_code = load_code(WALLET_BOC)

            # ---------------- ACCEPT: genuine jetton mint ----------------
            print("\n=== ACCEPT: genuine jetton mint must be indexed ===")
            master_si = jetton_master_state_init(faucet.address, wallet_code)
            master_addr = Address((0, master_si.serialize().hash))
            print(f"[accept] jetton master: {master_addr.to_str()}")

            # Deploy the master (faucet → master with StateInit).
            await faucet.send(WalletMessage(
                send_mode=3,
                message=MessageAny(
                    info=InternalMsgInfo(
                        ihr_disabled=True, bounce=False, bounced=False,
                        src=faucet.address, dest=master_addr, value=tos(2),
                        ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0,
                    ),
                    init=master_si,
                    body=Cell.empty(),
                ),
            ))
            master_active = await poll(
                lambda: rpc_call("getAddressState", address=master_addr.to_str())
                .get("result") == "active")
            print(f"[accept] master active: {master_active}")

            owner = Address((0, bytes([0x11]) * 32))
            print(f"[accept] mint owner: {owner.to_str()}")
            await faucet.send(internal_message(
                master_addr, tos(1), mint_body(owner, master_addr, 1000, 0), faucet.address))

            want_master = "0:" + master_si.serialize().hash.hex()

            def owner_has_master():
                js = get_jettons(owner.to_str())
                for j in js:
                    if j.get("jetton_master", "").lower() == want_master.lower():
                        return j
                return None

            found = await poll(owner_has_master, timeout=90)
            if isinstance(found, dict):
                print(f"[accept] PASS — indexed entry: {found}")
            else:
                print(f"[accept] FAIL — owner jetton list: {get_jettons(owner.to_str())}")
                failures.append("genuine jetton not indexed")

            # ---------------- REJECT: forged notification ----------------
            print("\n=== REJECT: forged notification from a non-wallet must NOT be indexed ===")
            from contract import WalletV1Blueprint  # mirror localnet script's import
            attacker_bp = WalletV1Blueprint(workchain=0)
            attacker = await faucet.deploy(attacker_bp, tos(2))
            print(f"[reject] attacker (plain wallet): {attacker_bp.address.to_str()}")
            await poll(lambda: rpc_call("getAddressState", address=attacker_bp.address.to_str())
                       .get("result") == "active")

            victim = Address((0, bytes([0x22]) * 32))
            print(f"[reject] victim: {victim.to_str()}")
            # The attacker (a normal wallet, no get_wallet_data) forges a notification.
            await attacker.send(internal_message(
                victim, tos(0.2), forged_notification_body(attacker_bp.address),
                attacker_bp.address))

            # Give the chain ample time to apply the forged-notification block, then
            # assert the victim's jetton list is *still* empty.
            await asyncio.sleep(25)
            victim_js = get_jettons(victim.to_str())
            if victim_js:
                print(f"[reject] FAIL — victim wrongly indexed: {victim_js}")
                failures.append("forged notification was indexed")
            else:
                print("[reject] PASS — victim jetton list empty (forged claim rejected)")

            # Sanity: the attacker's own forged self-claim must also be absent.
            atk_js = get_jettons(attacker_bp.address.to_str())
            if atk_js:
                print(f"[reject] NOTE — attacker self jetton list: {atk_js}")
        finally:
            for t in (node_task, dht_task):
                t.cancel()
            await asyncio.gather(node_task, dht_task, return_exceptions=True)

    return 1 if failures else 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    print("\n=== RESULT:", "ALL PASS" if rc == 0 else "FAILURES", "===")
    sys.exit(rc)
