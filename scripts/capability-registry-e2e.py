#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
capability-registry-e2e.py — real-localnet acceptance of the Capability
Registry contract and its `tosctl agent registry` CLI.

Boots a single-process local TOS chain (same machinery as
agent-task-escrow-e2e.py), provisions a file vault plus a tosctl config,
creates and funds an owner wallet, then drives the full lifecycle through
the real `tosctl agent registry` CLI against the running validator:

  deploy (bond 2, task/pricing/metadata/verification hashes, a verifier)
    -> local record persisted -> on-chain state matches
  send update-metadata (owner) -> new hashes recorded on-chain
  send stake (anyone) -> bond increases
  send update-reputation (verifier) -> reputation score changes;
    rejected from a non-verifier
  send withdraw-bond (owner) -> bond decreases, owner balance increases;
    rejected above the bond
  send deactivate (owner) -> active=false, bond swept back to owner;
    update-metadata rejected while inactive
  send reactivate (owner) -> active=true again

Exit code 0 iff every check passes.

Run:  cd /home/tomi/tos && uv run python scripts/capability-registry-e2e.py
"""
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:18746"
WORKDIR = REPO / "test/integration/.capability-registry-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000003"
NANO = 1_000_000_000

TASK_CATEGORIES_HASH = "11" * 32
PRICING_HASH = "22" * 32
METADATA_HASH = "33" * 32
VERIFICATION_METHOD_HASH = "44" * 32
NEW_TASK_CATEGORIES_HASH = "55" * 32
NEW_PRICING_HASH = "66" * 32
NEW_METADATA_HASH = "77" * 32
NEW_VERIFICATION_METHOD_HASH = "88" * 32

failures: list[str] = []


def check(label: str, ok: bool, detail: str = ""):
    if ok:
        print(f"  PASS: {label}")
    else:
        print(f"  FAIL: {label}  {detail}")
        failures.append(label)


def rpc_call(method: str, **params):
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{RPC}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


def balance(addr: str) -> int:
    return int(rpc_call("getAddressInformation", address=addr)["result"]["balance"])


async def tosctl(*args: str, may_fail: bool = False) -> str:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{WORKDIR}/e2e-vault.json?master_key={MASTER_KEY}"
    proc = await asyncio.create_subprocess_exec(
        TOSCTL, *args, "-c", str(CONFIG),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=180)
    except TimeoutError:
        proc.kill()
        raise RuntimeError(f"tosctl {' '.join(args)} timed out")
    if proc.returncode != 0 and not may_fail:
        raise RuntimeError(
            f"tosctl {' '.join(args)} failed:\n{out.decode()}\n{err.decode()}")
    return out.decode()


async def tosctl_json(*args: str):
    return json.loads(await tosctl(*args, "--format", "json"))


def norm_addr(addr: str) -> str:
    return Address(addr).to_str(is_user_friendly=False).lower()


def same_addr(candidate, want: str) -> bool:
    try:
        return candidate is not None and norm_addr(candidate) == norm_addr(want)
    except Exception:
        return False


async def wallet_address(name: str) -> str:
    for entry in await tosctl_json("wallet", "ls"):
        if entry["name"] == name and entry.get("address"):
            return norm_addr(entry["address"])
    raise RuntimeError(f"wallet {name} has no address in `wallet ls`")


def faucet_transfer(faucet, dest: str, amount_tos: float) -> WalletMessage:
    from contract import tos
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=faucet.address, dest=Address(dest), value=tos(amount_tos),
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0,
            ),
            init=None,
            body=Cell.empty(),
        ),
    )


async def poll_predicate(predicate, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def wait_balance_at_least(addr: str, target: int, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if balance(addr) >= target:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def wait_rpc_ready(timeout: float = 180.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if "result" in rpc_call("getMasterchainInfo"):
                return True
        except Exception:
            pass
        await asyncio.sleep(2)
    return False


def prepare_config():
    import subprocess
    subprocess.run([TOSCTL, "config", "generate", "-o", str(CONFIG), "--force"], check=True)
    cfg = json.loads(CONFIG.read_text())
    cfg["chain_rpc"] = {"urls": [f"http://{RPC}/"], "api_key": None}
    cfg["elections"] = None
    CONFIG.write_text(json.dumps(cfg, indent=2))


async def registry_show(name: str):
    return await tosctl_json("agent", "registry", "show", "--name", name)


async def send_op(operation: str, name: str, frm: str, *extra: str, may_fail: bool = False) -> str:
    return await tosctl(
        "agent", "registry", "send", "--operation", operation, "--name", name,
        "--from", frm, "--yes", *extra, may_fail=may_fail,
    )


async def run_checks(faucet) -> None:
    print("\n=== provision: tosctl wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    await tosctl("wallet", "create", "-n", "owner", "-v", "V3R2", "-w", "0")
    await tosctl("wallet", "create", "-n", "verifier", "-v", "V3R2", "-w", "0")
    await tosctl("wallet", "create", "-n", "outsider", "-v", "V3R2", "-w", "0")
    owner = await wallet_address("owner")
    verifier = await wallet_address("verifier")
    outsider = await wallet_address("outsider")
    print(f"  owner:     {owner}\n  verifier:  {verifier}\n  outsider:  {outsider}")

    for name, addr in (("owner", owner), ("verifier", verifier), ("outsider", outsider)):
        await faucet.send(faucet_transfer(faucet, addr, 50))
        check(f"{name} funded", await wait_balance_at_least(addr, 49 * NANO))
    for name in ("owner", "verifier", "outsider"):
        await tosctl("wallet", "activate", "-n", name)
    for name, addr in (("owner", owner), ("verifier", verifier), ("outsider", outsider)):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{name} wallet active", bool(active))

    print("\n=== deploy: Capability Registry entry ===")
    deploy = await tosctl_json(
        "agent", "registry", "deploy", "--name", "svc-1", "--owner", owner,
        "--verifier", verifier,
        "--task-categories-hash", TASK_CATEGORIES_HASH,
        "--pricing-hash", PRICING_HASH,
        "--metadata-hash", METADATA_HASH,
        "--verification-method-hash", VERIFICATION_METHOD_HASH,
        "--bond", "2", "--from", "owner", "--amount", "2.2", "-w", "0", "--yes",
    )
    address = deploy["address"]
    print(f"  registry: {address}")
    check("deployed and active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address).get("result") == "active"))

    data = await registry_show("svc-1")
    check("owner recorded on-chain", same_addr(data["owner"], owner), str(data))
    check("verifier recorded on-chain", same_addr(data["verifier"], verifier), str(data))
    check("active on deploy", data["active"] is True, str(data))
    check("bond recorded on-chain", abs(float(data["bond"]) - 2.0) < 1e-6, str(data))
    check("reputation starts at zero", data["reputation_score"] == 0, str(data))
    check("task_categories_hash recorded", data["task_categories_hash"] == TASK_CATEGORIES_HASH, str(data))

    print("\n=== update-metadata (owner only) ===")
    await send_op(
        "update-metadata", "svc-1", "outsider",
        "--task-categories-hash", NEW_TASK_CATEGORIES_HASH,
        "--pricing-hash", NEW_PRICING_HASH,
        "--metadata-hash", NEW_METADATA_HASH,
        "--verification-method-hash", NEW_VERIFICATION_METHOD_HASH,
        may_fail=True,
    )
    data = await registry_show("svc-1")
    check("non-owner update-metadata rejected", data["task_categories_hash"] == TASK_CATEGORIES_HASH, str(data))

    await send_op(
        "update-metadata", "svc-1", "owner",
        "--task-categories-hash", NEW_TASK_CATEGORIES_HASH,
        "--pricing-hash", NEW_PRICING_HASH,
        "--metadata-hash", NEW_METADATA_HASH,
        "--verification-method-hash", NEW_VERIFICATION_METHOD_HASH,
    )
    data = await registry_show("svc-1")
    check("task_categories_hash updated", data["task_categories_hash"] == NEW_TASK_CATEGORIES_HASH, str(data))
    check("pricing_hash updated", data["pricing_hash"] == NEW_PRICING_HASH, str(data))

    print("\n=== stake (permissionless) ===")
    bond_before = float((await registry_show("svc-1"))["bond"])
    await send_op("stake", "svc-1", "outsider", "--amount", "1")
    data = await registry_show("svc-1")
    check("bond increased after stake", float(data["bond"]) > bond_before + 0.9, str(data))

    print("\n=== update-reputation (verifier only) ===")
    await send_op("update-reputation", "svc-1", "outsider", "--delta", "10", may_fail=True)
    data = await registry_show("svc-1")
    check("non-verifier reputation update rejected", data["reputation_score"] == 0, str(data))

    await send_op("update-reputation", "svc-1", "verifier", "--delta", "10")
    data = await registry_show("svc-1")
    check("verifier reputation update applied", data["reputation_score"] == 10, str(data))

    print("\n=== withdraw-bond (owner only, bounded) ===")
    await send_op("withdraw-bond", "svc-1", "owner", "--withdraw-amount", "100", may_fail=True)
    data = await registry_show("svc-1")
    bond_before_withdraw = float(data["bond"])
    owner_before = balance(owner)
    await send_op("withdraw-bond", "svc-1", "owner", "--withdraw-amount", "1")
    data = await registry_show("svc-1")
    check("bond decreased by withdrawal", abs(float(data["bond"]) - (bond_before_withdraw - 1)) < 1e-6, str(data))
    check("owner balance increased", balance(owner) > owner_before, "")

    print("\n=== deactivate / reactivate ===")
    await send_op(
        "update-metadata", "svc-1", "owner",
        "--task-categories-hash", NEW_TASK_CATEGORIES_HASH,
        "--pricing-hash", NEW_PRICING_HASH,
        "--metadata-hash", NEW_METADATA_HASH,
        "--verification-method-hash", NEW_VERIFICATION_METHOD_HASH,
    )
    await send_op("deactivate", "svc-1", "owner")
    data = await registry_show("svc-1")
    check("deactivated", data["active"] is False, str(data))
    check("bond swept on deactivate", float(data["bond"]) == 0.0, str(data))

    await send_op(
        "update-metadata", "svc-1", "owner",
        "--task-categories-hash", NEW_TASK_CATEGORIES_HASH,
        "--pricing-hash", NEW_PRICING_HASH,
        "--metadata-hash", NEW_METADATA_HASH,
        "--verification-method-hash", NEW_VERIFICATION_METHOD_HASH,
        may_fail=True,
    )
    check("update-metadata rejected while inactive", (await registry_show("svc-1"))["active"] is False, "")

    await send_op("reactivate", "svc-1", "owner")
    data = await registry_show("svc-1")
    check("reactivated", data["active"] is True, str(data))

    print("\n=== persisted local record ===")
    records = {r["name"]: r for r in await tosctl_json("agent", "registry", "ls")}
    check("record tracked locally", "svc-1" in records, str(sorted(records)))
    check("record owner matches", same_addr(records["svc-1"]["owner"], owner), str(records["svc-1"]))


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    prepare_config()
    install = Install(BUILD_DIR, REPO)
    import logging
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    async with Network(install, WORKDIR / "net", base_port=23300) as network:
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
            await run_checks(faucet)
        finally:
            for t in (node_task, dht_task):
                t.cancel()
            await asyncio.gather(node_task, dht_task, return_exceptions=True)

    return 1 if failures else 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    if rc == 1:
        print(f"\n=== RESULT: {len(failures)} FAILURES ===")
        for f in failures:
            print(f"  - {f}")
    elif rc == 0:
        print("\n=== RESULT: ALL PASS ===")
    sys.exit(rc)
