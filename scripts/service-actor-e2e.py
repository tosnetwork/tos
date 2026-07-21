#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
service-actor-e2e.py — real-localnet acceptance of the Service Actor
contract and its `tosctl agent service` CLI.

Boots a single-process local TOS chain (same machinery as
agent-task-escrow-e2e.py), provisions a file vault plus a tosctl config,
creates and funds owner/caller/outsider wallets, then drives the full
lifecycle through the real `tosctl agent service` CLI against the running
validator:

  deploy (restricted to `caller`, price 0.05 TOS, rate limit 2/day)
    -> local record persisted -> on-chain state matches
  send call (outsider) -> rejected (not authorized)
  send call (caller, underpaying) -> rejected (insufficient payment)
  send call (caller, x2) -> accepted, revenue and calls_today accrue
  send call (caller, 3rd) -> rejected (rate limited)
  send respond (owner) -> response hash recorded; rejected from non-owner
  send update-policy (owner, open access) -> outsider can now call
  send withdraw-revenue (owner) -> revenue decreases, owner balance increases;
    rejected above revenue
  send deactivate (owner) -> active=false, revenue swept to owner;
    call rejected while inactive
  send reactivate (owner) -> active=true

Exit code 0 iff every check passes.

Run from the repository root: uv run python scripts/service-actor-e2e.py
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
RPC = "127.0.0.1:18846"
WORKDIR = REPO / "test/integration/.service-actor-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000004"
NANO = 1_000_000_000

METADATA_HASH = "11" * 32
PROOF_SCHEME_HASH = "22" * 32
NEW_METADATA_HASH = "33" * 32
NEW_PROOF_SCHEME_HASH = "44" * 32

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


async def service_show(name: str):
    return await tosctl_json("agent", "service", "show", "--name", name)


async def send_op(operation: str, name: str, frm: str, *extra: str, may_fail: bool = False) -> str:
    return await tosctl(
        "agent", "service", "send", "--operation", operation, "--name", name,
        "--from", frm, "--yes", *extra, may_fail=may_fail,
    )


async def run_checks(faucet) -> None:
    print("\n=== provision: tosctl wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    for name in ("owner", "caller", "outsider"):
        await tosctl("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    owner = await wallet_address("owner")
    caller = await wallet_address("caller")
    outsider = await wallet_address("outsider")
    print(f"  owner:    {owner}\n  caller:   {caller}\n  outsider: {outsider}")

    for name, addr in (("owner", owner), ("caller", caller), ("outsider", outsider)):
        await faucet.send(faucet_transfer(faucet, addr, 50))
        check(f"{name} funded", await wait_balance_at_least(addr, 49 * NANO))
    for name in ("owner", "caller", "outsider"):
        await tosctl("wallet", "activate", "-n", name)
    for name, addr in (("owner", owner), ("caller", caller), ("outsider", outsider)):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{name} wallet active", bool(active))

    print("\n=== deploy: Service Actor (restricted access) ===")
    deploy = await tosctl_json(
        "agent", "service", "deploy", "--name", "svc-1", "--owner", owner,
        "--authorized-caller", caller,
        "--price-per-call", "0.05", "--rate-limit-per-day", "2",
        "--metadata-hash", METADATA_HASH, "--proof-scheme-hash", PROOF_SCHEME_HASH,
        "--from", "owner", "--amount", "0.3", "-w", "0", "--yes",
    )
    address = deploy["address"]
    print(f"  service: {address}")
    check("deployed and active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address).get("result") == "active"))

    data = await service_show("svc-1")
    check("owner recorded on-chain", same_addr(data["owner"], owner), str(data))
    check("authorized_caller recorded on-chain", same_addr(data["authorized_caller"], caller), str(data))
    check("access restricted (not open)", data["open_access"] is False, str(data))
    check("active on deploy", data["active"] is True, str(data))
    check("price recorded", abs(float(data["price_per_call"]) - 0.05) < 1e-9, str(data))
    check("calls_today starts at zero", data["calls_today"] == 0, str(data))
    check("revenue starts at zero", float(data["total_revenue"]) == 0.0, str(data))

    print("\n=== call: access and payment gating ===")
    await send_op("call", "svc-1", "outsider", "--request-hash", "aa" * 32, "--amount", "0.05",
                  may_fail=True)
    data = await service_show("svc-1")
    check("outsider call rejected (not authorized)", data["calls_today"] == 0, str(data))

    await send_op("call", "svc-1", "caller", "--request-hash", "bb" * 32, "--amount", "0.01",
                  may_fail=True)
    data = await service_show("svc-1")
    check("underpaid call rejected", data["calls_today"] == 0, str(data))

    await send_op("call", "svc-1", "caller", "--request-hash", "cc" * 32, "--amount", "0.05")
    data = await service_show("svc-1")
    check("first call accepted", data["calls_today"] == 1, str(data))
    check("revenue accrued", abs(float(data["total_revenue"]) - 0.05) < 1e-9, str(data))

    print("\n=== respond (owner only) ===")
    # Calls are serialized on the single outstanding response slot: the first
    # call must be answered before a second one is accepted.
    await send_op("respond", "svc-1", "outsider", "--response-hash", "11" * 32, may_fail=True)
    data = await service_show("svc-1")
    check("non-owner respond rejected", int(data["last_response_hash"], 16) == 0, str(data))

    await send_op("respond", "svc-1", "owner", "--response-hash", "11" * 32)
    data = await service_show("svc-1")
    check("owner respond recorded (first call)", data["last_response_hash"] == "11" * 32, str(data))

    await send_op("call", "svc-1", "caller", "--request-hash", "dd" * 32, "--amount", "0.05")
    data = await service_show("svc-1")
    check("second call accepted", data["calls_today"] == 2, str(data))

    await send_op("respond", "svc-1", "owner", "--response-hash", "ff" * 32)
    data = await service_show("svc-1")
    check("owner respond recorded", data["last_response_hash"] == "ff" * 32, str(data))

    # calls_today is already at the rate limit and the second call has been
    # answered, so this attempt is rejected purely on the daily cap.
    await send_op("call", "svc-1", "caller", "--request-hash", "ee" * 32, "--amount", "0.05",
                  may_fail=True)
    data = await service_show("svc-1")
    check("third call rate-limited", data["calls_today"] == 2, str(data))

    print("\n=== update-policy: open access ===")
    await send_op(
        "update-policy", "svc-1", "owner",
        "--price-per-call", "0.02", "--rate-limit-per-day", "0", "--open-access",
        "--metadata-hash", NEW_METADATA_HASH, "--proof-scheme-hash", NEW_PROOF_SCHEME_HASH,
    )
    data = await service_show("svc-1")
    check("access now open", data["open_access"] is True, str(data))
    check("price updated", abs(float(data["price_per_call"]) - 0.02) < 1e-9, str(data))
    check("metadata hash updated", data["metadata_hash"] == NEW_METADATA_HASH, str(data))

    await send_op("call", "svc-1", "outsider", "--request-hash", "01" * 32, "--amount", "0.02")
    data = await service_show("svc-1")
    check("outsider can now call under open access", data["calls_today"] == 3, str(data))

    # Answer this call before the next one lands (calls are serialized).
    await send_op("respond", "svc-1", "owner", "--response-hash", "22" * 32)

    print("\n=== call: overpayment is refunded, not absorbed as revenue ===")
    revenue_before_overpay = float(data["total_revenue"])
    outsider_before_overpay = balance(outsider)
    await send_op("call", "svc-1", "outsider", "--request-hash", "03" * 32, "--amount", "0.2")
    data = await service_show("svc-1")
    check(
        "only the quoted price (0.02) is credited as revenue, not the full 0.2 sent",
        abs(float(data["total_revenue"]) - (revenue_before_overpay + 0.02)) < 1e-9,
        str(data),
    )
    outsider_delta = outsider_before_overpay - balance(outsider)
    check(
        "caller received most of the 0.18 overpayment back as a refund"
        " (net spend close to the 0.02 price, not the full 0.2 sent)",
        outsider_delta < int(0.05 * 1e9),
        f"net spend={outsider_delta} nanotons",
    )

    print("\n=== withdraw-revenue (owner only, bounded) ===")
    await send_op("withdraw-revenue", "svc-1", "outsider", "--withdraw-amount", "0.01", may_fail=True)
    data = await service_show("svc-1")
    revenue_before = float(data["total_revenue"])
    await send_op("withdraw-revenue", "svc-1", "owner", "--withdraw-amount", "100", may_fail=True)
    data = await service_show("svc-1")
    check("overdraw rejected", abs(float(data["total_revenue"]) - revenue_before) < 1e-9, str(data))

    owner_before = balance(owner)
    await send_op("withdraw-revenue", "svc-1", "owner", "--withdraw-amount", "0.05")
    data = await service_show("svc-1")
    check("revenue decreased by withdrawal",
          abs(float(data["total_revenue"]) - (revenue_before - 0.05)) < 1e-9, str(data))
    check("owner balance increased", balance(owner) > owner_before, "")

    print("\n=== deactivate / reactivate ===")
    await send_op("deactivate", "svc-1", "outsider", may_fail=True)
    data = await service_show("svc-1")
    check("non-owner deactivate rejected", data["active"] is True, str(data))

    await send_op("deactivate", "svc-1", "owner")
    data = await service_show("svc-1")
    check("deactivated", data["active"] is False, str(data))
    check("revenue swept on deactivate", float(data["total_revenue"]) == 0.0, str(data))

    await send_op("call", "svc-1", "outsider", "--request-hash", "02" * 32, "--amount", "0.02",
                  may_fail=True)
    check("call rejected while inactive", (await service_show("svc-1"))["active"] is False, "")

    await send_op("reactivate", "svc-1", "owner")
    data = await service_show("svc-1")
    check("reactivated", data["active"] is True, str(data))

    print("\n=== attestor path: respond requires a signature over response_hash ===")
    await tosctl("key", "add", "--name", "service-attestor-key")
    await tosctl("key", "add", "--name", "wrong-service-attestor-key")
    deploy2 = await tosctl_json(
        "agent", "service", "deploy", "--name", "svc-2", "--owner", owner,
        "--open-access", "--price-per-call", "0.01", "--rate-limit-per-day", "0",
        "--metadata-hash", METADATA_HASH, "--proof-scheme-hash", PROOF_SCHEME_HASH,
        "--signer-vault-key", "service-attestor-key",
        "--from", "owner", "--amount", "0.2", "-w", "0", "--yes",
    )
    address2 = deploy2["address"]
    check("attestor service deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address2).get("result") == "active"))
    data = await service_show("svc-2")
    check("attestor pubkey recorded on-chain", bool(data.get("attestor_pubkey")), str(data))

    # A response must answer an outstanding call.
    await send_op("call", "svc-2", "outsider", "--request-hash", "cc" * 32, "--amount", "0.01")

    await send_op("respond", "svc-2", "owner", "--response-hash", "dd" * 32, may_fail=True)
    data = await service_show("svc-2")
    check("respond without attestation rejected", int(data["last_response_hash"], 16) == 0, str(data))

    await send_op("respond", "svc-2", "owner", "--response-hash", "dd" * 32,
                  "--signer-vault-key", "wrong-service-attestor-key", may_fail=True)
    data = await service_show("svc-2")
    check("respond with wrong attestor key rejected",
          int(data["last_response_hash"], 16) == 0, str(data))

    await send_op("respond", "svc-2", "owner", "--response-hash", "dd" * 32,
                  "--signer-vault-key", "service-attestor-key")
    data = await service_show("svc-2")
    check("attestor respond recorded", data["last_response_hash"] == "dd" * 32, str(data))

    print("\n=== rotate/revoke: owner manages the attestor key post-deploy ===")
    await tosctl("key", "add", "--name", "rotated-service-attestor-key")
    deploy3 = await tosctl_json(
        "agent", "service", "deploy", "--name", "svc-3", "--owner", owner,
        "--open-access", "--price-per-call", "0.01", "--rate-limit-per-day", "0",
        "--metadata-hash", METADATA_HASH, "--proof-scheme-hash", PROOF_SCHEME_HASH,
        "--from", "owner", "--amount", "0.2", "-w", "0", "--yes",
    )
    address3 = deploy3["address"]
    check("rotate service deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address3).get("result") == "active"))
    data = await service_show("svc-3")
    check("no attestor at deploy", not data.get("attestor_pubkey"), str(data))

    await send_op("rotate-attestor-key", "svc-3", "outsider",
                  "--new-attestor-pubkey", "aa" * 32, may_fail=True)
    data = await service_show("svc-3")
    check("non-owner rotate rejected", not data.get("attestor_pubkey"), str(data))

    await send_op("rotate-attestor-key", "svc-3", "owner",
                  "--signer-vault-key", "rotated-service-attestor-key")
    data = await service_show("svc-3")
    check("owner rotate sets attestor pubkey", bool(data.get("attestor_pubkey")), str(data))

    await send_op("respond", "svc-3", "owner", "--response-hash", "ee" * 32, may_fail=True)
    data = await service_show("svc-3")
    check("respond after rotate still requires attestation",
          int(data["last_response_hash"], 16) == 0, str(data))

    await send_op("revoke-attestor", "svc-3", "outsider", may_fail=True)
    data = await service_show("svc-3")
    check("non-owner revoke rejected", bool(data.get("attestor_pubkey")), str(data))

    # No call is outstanding yet, so the owner is free to revoke/rotate --
    # there is nothing pending an attestor swap could bypass.
    check("no response pending yet", data.get("has_pending_response") is False, str(data))
    await send_op("revoke-attestor", "svc-3", "owner")
    data = await service_show("svc-3")
    check("owner can revoke while idle", not data.get("attestor_pubkey"), str(data))

    # A response must answer an outstanding call.
    await send_op("call", "svc-3", "outsider", "--request-hash", "02" * 32, "--amount", "0.01")
    await send_op("respond", "svc-3", "owner", "--response-hash", "ee" * 32)
    data = await service_show("svc-3")
    check("respond succeeds once attestor is gone", data["last_response_hash"] == "ee" * 32,
          str(data))

    # Re-configure an attestor, then let a call land: the response to that
    # call is now outstanding, so rotate/revoke must be rejected until it is
    # answered -- otherwise the owner could bypass the check the caller paid
    # for.
    await send_op("rotate-attestor-key", "svc-3", "owner",
                  "--signer-vault-key", "rotated-service-attestor-key")
    await send_op("call", "svc-3", "outsider", "--request-hash", "03" * 32, "--amount", "0.01")
    data = await service_show("svc-3")
    check("response now pending", data.get("has_pending_response") is True, str(data))

    await send_op("revoke-attestor", "svc-3", "owner", may_fail=True)
    data = await service_show("svc-3")
    check("revoke frozen while a response is pending", bool(data.get("attestor_pubkey")), str(data))
    await send_op("rotate-attestor-key", "svc-3", "owner",
                  "--new-attestor-pubkey", "aa" * 32, may_fail=True)
    data = await service_show("svc-3")
    check("rotate frozen while a response is pending",
          data.get("attestor_pubkey") != "aa" * 32, str(data))

    await send_op("respond", "svc-3", "owner", "--response-hash", "ff" * 32,
                  "--signer-vault-key", "rotated-service-attestor-key")
    data = await service_show("svc-3")
    check("attestor-signed respond clears the pending response",
          data.get("has_pending_response") is False, str(data))

    await send_op("revoke-attestor", "svc-3", "owner")
    data = await service_show("svc-3")
    check("owner can revoke again once the pending response is answered",
          not data.get("attestor_pubkey"), str(data))

    print("\n=== update-policy: frozen while a response is pending ===")
    svc4_metadata_hash = "44" * 32
    svc4_proof_scheme_hash = "55" * 32
    deploy4 = await tosctl_json(
        "agent", "service", "deploy", "--name", "svc-4", "--owner", owner,
        "--open-access", "--price-per-call", "0.01", "--rate-limit-per-day", "0",
        "--metadata-hash", svc4_metadata_hash, "--proof-scheme-hash", svc4_proof_scheme_hash,
        "--from", "owner", "--amount", "0.2", "-w", "0", "--yes",
    )
    address4 = deploy4["address"]
    check("policy-freeze service deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address4).get("result") == "active"))

    # A caller pays under the current price/metadata/proof scheme -- the
    # owner must not be able to change what the outstanding response has to
    # satisfy before answering it.
    await send_op("call", "svc-4", "outsider", "--request-hash", "05" * 32, "--amount", "0.01")
    await send_op(
        "update-policy", "svc-4", "owner",
        "--price-per-call", "0.05", "--rate-limit-per-day", "0", "--open-access",
        "--metadata-hash", NEW_METADATA_HASH, "--proof-scheme-hash", NEW_PROOF_SCHEME_HASH,
        may_fail=True,
    )
    data = await service_show("svc-4")
    check("update-policy rejected while a response is pending",
          abs(float(data["price_per_call"]) - 0.01) < 1e-9, str(data))
    check("proof scheme unchanged while pending",
          data["proof_scheme_hash"] == svc4_proof_scheme_hash, str(data))

    await send_op("respond", "svc-4", "owner", "--response-hash", "06" * 32)
    await send_op(
        "update-policy", "svc-4", "owner",
        "--price-per-call", "0.05", "--rate-limit-per-day", "0", "--open-access",
        "--metadata-hash", NEW_METADATA_HASH, "--proof-scheme-hash", NEW_PROOF_SCHEME_HASH,
    )
    data = await service_show("svc-4")
    check("update-policy succeeds once idle again",
          abs(float(data["price_per_call"]) - 0.05) < 1e-9, str(data))

    print("\n=== persisted local record ===")
    records = {r["name"]: r for r in await tosctl_json("agent", "service", "ls")}
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

    async with Network(install, WORKDIR / "net", base_port=23400) as network:
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
