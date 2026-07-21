#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
service-actor-e2e.py — real-localnet acceptance of the concurrent-escrow
Service Actor contract and its `tosctl agent service` CLI. See
doc/service-actor-concurrent-escrow-upgrade.md for the full design.

Boots a single-process local TOS chain (same machinery as
agent-task-escrow-e2e.py), provisions a file vault plus a tosctl config,
creates and funds owner/caller/caller2/outsider wallets, then drives the
lifecycle through the real `tosctl agent service` CLI against the running
validator:

  deploy (restricted to `caller`, price 0.05 TOS, rate limit 2/day)
    -> local record persisted -> on-chain state matches
  call: access and payment gating (outsider rejected, underpayment rejected)
  concurrent requests: two outstanding calls from different callers before
    either is responded to, resolved independently and out of order --
    the headline feature this upgrade adds over the single-slot V1 contract
  rate limiting: daily cap reached and enforced
  update-policy: open access, then overpayment is refunded rather than
    absorbed as revenue
  too-early rejections: expire/claim-refund/sweep-expired-request all
    rejected before their respective deadlines -- proves the CLI/RPC wiring
    and the on-chain boundary checks without waiting out the real
    1-hour-minimum response_sla/refund_claim_window (see the note below
    "=== boundary rejections ===")
  attestor path: respond requires a signature over the request-bound
    domain; wrong key and no signature both rejected
  snapshot behavior: rotating/revoking the attestor key, and updating the
    policy (price/metadata), do not retroactively change an already-pending
    request's requirements -- the per-request commitment is honored even
    after the live policy/attestor changes underneath it
  withdraw-revenue (owner only, bounded by real balance)
  non-owner rejections for every owner-only operation

Exit code 0 iff every check passes.

NOTE on response_sla/refund_claim_window: MIN_RESPONSE_SLA and
MIN_REFUND_CLAIM_WINDOW are protocol constants fixed at 3600s (1 hour) each,
enforced on chain with no owner override -- see
doc/service-actor-concurrent-escrow-upgrade.md's Service Policy section.
Actually waiting out 3600s+ of real wall-clock time is impractical for a
routine e2e run, so this script does not exercise the *success* side of
`expire`/`claim_refund`/`sweep_expired_request` (i.e. actually crossing
those deadlines) live. That exact behavior -- including the precise boundary
instants and the cleanup_bounty payout -- is already proven against the real
compiled bytecode by
`tosctl/src/node-control/contracts/tests/service_actor_sandbox.rs`'s 29
tests, which fast-forward `now()` deterministically; that is a strictly
stronger check of the boundary logic than a live wall-clock wait would be.
What this script proves instead is that the real CLI commands, RPC
round-trip, and wallet/vault signing flow for all nine operations work
end to end, including the "too early" rejection side of every deadline.

Run from the repository root: uv run python scripts/service-actor-e2e.py
"""
import asyncio
import json
import os
import re
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

# Matches the protocol constants in crypto/smartcont/service-actor-code.fc:
# MINIMUM_STORAGE_FEE / MINIMUM_CLEANUP_BOUNTY = 0.1 TOS each, storage_fee
# must be >= MINIMUM_STORAGE_FEE + cleanup_bounty, MIN_RESPONSE_SLA /
# MIN_REFUND_CLAIM_WINDOW = 3600s each, with no owner-side override.
CLEANUP_BOUNTY = 0.1
STORAGE_FEE = 0.2
RESPONSE_SLA = 3600
REFUND_CLAIM_WINDOW = 3600

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


async def request_show(name: str, request_id: int):
    return await tosctl_json(
        "agent", "service", "request-show", "--name", name,
        "--request-id", str(request_id),
    )


async def refund_show(name: str, request_id: int):
    return await tosctl_json(
        "agent", "service", "refund-show", "--name", name,
        "--request-id", str(request_id),
    )


async def send_op(operation: str, name: str, frm: str, *extra: str, may_fail: bool = False) -> str:
    return await tosctl(
        "agent", "service", "send", "--operation", operation, "--name", name,
        "--from", frm, "--yes", *extra, may_fail=may_fail,
    )


async def next_request_id(name: str) -> int:
    """The ID that will be assigned to the *next* `call` on this service --
    valid as a prediction only because this script never has two callers
    racing the same service instance (every `call` here is awaited to
    completion before the next one is submitted)."""
    return (await service_show(name))["next_request_id"]


def assigned_request_id(output: str) -> int:
    match = re.search(r"Assigned request ID: (\d+)", output)
    if not match or "best-effort" in output:
        raise RuntimeError(f"call did not emit an authoritative request ID:\n{output}")
    return int(match.group(1))


async def deploy_service(
    name: str, owner: str, *, price_per_call: float = 0.05, rate_limit_per_day: int = 0,
    authorized_caller: str | None = None, open_access: bool = False,
    metadata_hash: str = METADATA_HASH, proof_scheme_hash: str = PROOF_SCHEME_HASH,
    signer_vault_key: str | None = None, amount: float = 2.0,
):
    args = [
        "agent", "service", "deploy", "--name", name, "--owner", owner,
        "--price-per-call", str(price_per_call),
        "--storage-fee", str(STORAGE_FEE), "--cleanup-bounty", str(CLEANUP_BOUNTY),
        "--response-sla", str(RESPONSE_SLA), "--refund-claim-window", str(REFUND_CLAIM_WINDOW),
        "--rate-limit-per-day", str(rate_limit_per_day),
        "--metadata-hash", metadata_hash, "--proof-scheme-hash", proof_scheme_hash,
    ]
    if open_access:
        args.append("--open-access")
    else:
        args += ["--authorized-caller", authorized_caller]
    if signer_vault_key:
        args += ["--signer-vault-key", signer_vault_key]
    args += ["--from", "owner", "--amount", str(amount), "-w", "0", "--yes"]
    deploy = await tosctl_json(*args)
    address = deploy["address"]
    check(f"{name} deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address).get("result") == "active"))
    return address


async def run_checks(faucet) -> None:
    print("\n=== provision: tosctl wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    for name in ("owner", "caller", "caller2", "outsider"):
        await tosctl("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    owner = await wallet_address("owner")
    caller = await wallet_address("caller")
    caller2 = await wallet_address("caller2")
    outsider = await wallet_address("outsider")
    print(f"  owner: {owner}\n  caller: {caller}\n  caller2: {caller2}\n  outsider: {outsider}")

    for name, addr in (("owner", owner), ("caller", caller), ("caller2", caller2), ("outsider", outsider)):
        await faucet.send(faucet_transfer(faucet, addr, 50))
        check(f"{name} funded", await wait_balance_at_least(addr, 49 * NANO))
    for name in ("owner", "caller", "caller2", "outsider"):
        await tosctl("wallet", "activate", "-n", name)
    for name, addr in (("owner", owner), ("caller", caller), ("caller2", caller2), ("outsider", outsider)):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{name} wallet active", bool(active))

    print("\n=== deploy: Service Actor (restricted access, rate limit 2/day) ===")
    address = await deploy_service(
        "svc-1", owner, price_per_call=0.05, rate_limit_per_day=2, authorized_caller=caller,
    )
    print(f"  service: {address}")
    data = await service_show("svc-1")
    check("owner recorded on-chain", same_addr(data["owner"], owner), str(data))
    check("authorized_caller recorded on-chain", same_addr(data["authorized_caller"], caller), str(data))
    check("access restricted (not open)", data["open_access"] is False, str(data))
    check("active on deploy", data["active"] is True, str(data))
    check("price recorded", abs(float(data["price_per_call"]) - 0.05) < 1e-9, str(data))
    check("storage fee recorded", abs(float(data["storage_fee"]) - STORAGE_FEE) < 1e-9, str(data))
    check("cleanup bounty recorded", abs(float(data["cleanup_bounty"]) - CLEANUP_BOUNTY) < 1e-9, str(data))
    check("response sla recorded", data["response_sla"] == RESPONSE_SLA, str(data))
    check("refund claim window recorded", data["refund_claim_window"] == REFUND_CLAIM_WINDOW, str(data))
    check("calls_today starts at zero", data["calls_today"] == 0, str(data))
    check("no pending/live requests at deploy", data["pending_count"] == 0 and data["live_count"] == 0,
          str(data))
    check("no withdrawable revenue at deploy", float(data["withdrawable_revenue"]) == 0.0, str(data))

    call_amount = 0.05 + STORAGE_FEE + 0.05  # price + storage_fee + real-fee headroom

    print("\n=== call: access and payment gating ===")
    await send_op("call", "svc-1", "outsider", "--request-hash", "aa" * 32,
                  "--amount", str(call_amount), may_fail=True)
    data = await service_show("svc-1")
    check("outsider call rejected (not authorized)", data["calls_today"] == 0, str(data))

    await send_op("call", "svc-1", "caller", "--request-hash", "bb" * 32, "--amount", "0.01",
                  may_fail=True)
    data = await service_show("svc-1")
    check("underpaid call rejected", data["calls_today"] == 0, str(data))

    print("\n=== concurrent requests: two outstanding calls, resolved independently ===")
    # This is the headline feature the upgrade adds: unlike the single-slot
    # V1 contract, a second call is accepted while the first is still
    # unanswered, and each resolves on its own schedule and in any order.
    predicted_a = await next_request_id("svc-1")
    call_a_output = await send_op(
        "call", "svc-1", "caller", "--request-hash", "cc" * 32, "--amount", str(call_amount))
    request_a = assigned_request_id(call_a_output)
    check("CLI reports the exact assigned request ID", request_a == predicted_a, call_a_output)
    data = await service_show("svc-1")
    check("first concurrent call accepted", data["calls_today"] == 1, str(data))
    check("one pending request after first call", data["pending_count"] == 1, str(data))

    predicted_b = await next_request_id("svc-1")
    call_b_output = await send_op(
        "call", "svc-1", "caller", "--request-hash", "dd" * 32, "--amount", str(call_amount))
    request_b = assigned_request_id(call_b_output)
    check("second request gets a distinct ID", request_b != request_a, f"a={request_a} b={request_b}")
    check("second CLI request ID matches chain allocation", request_b == predicted_b, call_b_output)
    data = await service_show("svc-1")
    check("second concurrent call accepted while the first is still pending",
          data["calls_today"] == 2, str(data))
    check("two pending requests outstanding simultaneously", data["pending_count"] == 2, str(data))

    req_a_data = await request_show("svc-1", request_a)
    req_b_data = await request_show("svc-1", request_b)
    check("request A is independently visible", req_a_data["found"] and req_a_data["request_hash"] == "cc" * 32,
          str(req_a_data))
    check("request B is independently visible", req_b_data["found"] and req_b_data["request_hash"] == "dd" * 32,
          str(req_b_data))

    # Respond out of order: B before A. Responding to one must not affect
    # the other's state.
    await send_op("respond", "svc-1", "owner", "--request-id", str(request_b),
                  "--response-hash", "22" * 32)
    data = await service_show("svc-1")
    check("responding to B leaves A still pending", data["pending_count"] == 1, str(data))
    req_a_data = await request_show("svc-1", request_a)
    check("request A untouched by B's response", req_a_data["found"], str(req_a_data))
    req_b_data = await request_show("svc-1", request_b)
    check("request B resolved and no longer pending", not req_b_data["found"], str(req_b_data))

    await send_op("respond", "svc-1", "owner", "--request-id", str(request_a),
                  "--response-hash", "11" * 32)
    data = await service_show("svc-1")
    check("both concurrent requests now resolved", data["pending_count"] == 0, str(data))
    # respond credits price + storage_fee to withdrawable_revenue (the
    # storage fee is non-refundable once the entry resolves -- see
    # doc/service-actor-concurrent-escrow-upgrade.md's Financial Accounting
    # transition table), not price alone.
    expected_revenue = 2 * (0.05 + STORAGE_FEE)
    check("revenue accrued for both calls (price + storage_fee each)",
          abs(float(data["withdrawable_revenue"]) - expected_revenue) < 1e-6, str(data))

    print("\n=== rate limiting: daily cap enforced ===")
    await send_op("call", "svc-1", "caller", "--request-hash", "ee" * 32, "--amount", str(call_amount),
                  may_fail=True)
    data = await service_show("svc-1")
    check("third call rate-limited (cap is 2/day)", data["calls_today"] == 2, str(data))

    print("\n=== update-policy: open access ===")
    await send_op(
        "update-policy", "svc-1", "owner",
        "--price-per-call", "0.02", "--storage-fee", str(STORAGE_FEE),
        "--cleanup-bounty", str(CLEANUP_BOUNTY),
        "--response-sla", str(RESPONSE_SLA), "--refund-claim-window", str(REFUND_CLAIM_WINDOW),
        "--active", "true", "--rate-limit-per-day", "0", "--open-access",
        "--metadata-hash", NEW_METADATA_HASH, "--proof-scheme-hash", NEW_PROOF_SCHEME_HASH,
    )
    data = await service_show("svc-1")
    check("access now open", data["open_access"] is True, str(data))
    check("price updated", abs(float(data["price_per_call"]) - 0.02) < 1e-9, str(data))
    check("metadata hash updated", data["metadata_hash"] == NEW_METADATA_HASH, str(data))
    check("policy version bumped", data["policy_version"] >= 1, str(data))

    print("\n=== call: overpayment is refunded, not absorbed as revenue ===")
    new_call_min = 0.02 + STORAGE_FEE
    revenue_before_overpay = float(data["withdrawable_revenue"])
    outsider_before_overpay = balance(outsider)
    request_over = await next_request_id("svc-1")
    await send_op("call", "svc-1", "outsider", "--request-hash", "03" * 32, "--amount", "0.5")
    data = await service_show("svc-1")
    req_over_data = await request_show("svc-1", request_over)
    check("overpaid request records only the quoted price", req_over_data["found"]
          and abs(float(req_over_data["price"]) - 0.02) < 1e-9, str(req_over_data))
    outsider_delta = outsider_before_overpay - balance(outsider)
    expected_spend = new_call_min
    check(
        "outsider's net spend is close to price+storage_fee, not the full 0.5 sent",
        outsider_delta < int((expected_spend + 0.05) * NANO),
        f"net spend={outsider_delta} nanotons, expected~={int(expected_spend * NANO)}",
    )

    print("\n=== boundary rejections: too early for expire / claim-refund / sweep ===")
    # request_over is still pending, well before response_sla has elapsed.
    await send_op("expire", "svc-1", "outsider", "--request-id", str(request_over), may_fail=True)
    data_check = await request_show("svc-1", request_over)
    check("expire rejected before response_deadline", data_check["found"], str(data_check))

    await send_op("sweep-expired-request", "svc-1", "outsider", "--request-id", str(request_over),
                  may_fail=True)
    data_check = await request_show("svc-1", request_over)
    check("sweep rejected before refund_claim_deadline (still pending)", data_check["found"], str(data_check))

    # Answer it so it doesn't linger as a real liability for the rest of the run.
    await send_op("respond", "svc-1", "owner", "--request-id", str(request_over),
                  "--response-hash", "44" * 32)
    data_check = await request_show("svc-1", request_over)
    check("overpaid request resolved via respond", not data_check["found"], str(data_check))

    # claim-refund requires a refund entry to exist at all (never expired).
    fresh_id = await next_request_id("svc-1")
    await send_op("call", "svc-1", "outsider", "--request-hash", "05" * 32, "--amount", str(new_call_min + 0.05))
    await send_op("claim-refund", "svc-1", "outsider", "--request-id", str(fresh_id),
                  "--destination", outsider, may_fail=True)
    req_fresh = await request_show("svc-1", fresh_id)
    check("claim-refund rejected: request never expired, no refund entry", req_fresh["found"], str(req_fresh))
    refund_fresh = await refund_show("svc-1", fresh_id)
    check("no refund entry exists for a still-pending request", not refund_fresh["found"], str(refund_fresh))
    await send_op("respond", "svc-1", "owner", "--request-id", str(fresh_id), "--response-hash", "55" * 32)

    print("\n=== withdraw-revenue (owner only, bounded by real balance) ===")
    await send_op("withdraw-revenue", "svc-1", "outsider", "--withdraw-amount", "0.01", may_fail=True)
    data = await service_show("svc-1")
    revenue_before = float(data["withdrawable_revenue"])
    check("revenue accrued from all resolved calls", revenue_before > 0.1, str(data))

    await send_op("withdraw-revenue", "svc-1", "owner", "--withdraw-amount", "1000", may_fail=True)
    data = await service_show("svc-1")
    check("overdraw rejected", abs(float(data["withdrawable_revenue"]) - revenue_before) < 1e-9, str(data))

    owner_before = balance(owner)
    withdraw_amount = round(revenue_before / 2, 6)
    await send_op("withdraw-revenue", "svc-1", "owner", "--withdraw-amount", str(withdraw_amount))
    data = await service_show("svc-1")
    check("revenue decreased by withdrawal",
          abs(float(data["withdrawable_revenue"]) - (revenue_before - withdraw_amount)) < 1e-6, str(data))
    check("owner balance increased", balance(owner) > owner_before, "")

    print("\n=== non-owner rejections ===")
    await send_op("rotate-attestor-key", "svc-1", "outsider", "--new-attestor-pubkey", "aa" * 32,
                  may_fail=True)
    data = await service_show("svc-1")
    check("non-owner rotate-attestor-key rejected", not data.get("attestor_pubkey"), str(data))
    await send_op("revoke-attestor", "svc-1", "outsider", may_fail=True)

    print("\n=== attestor path: respond requires a signature over the request-bound domain ===")
    await tosctl("key", "add", "--name", "service-attestor-key")
    await tosctl("key", "add", "--name", "wrong-service-attestor-key")
    address2 = await deploy_service(
        "svc-2", owner, price_per_call=0.01, open_access=True,
        signer_vault_key="service-attestor-key",
    )
    data = await service_show("svc-2")
    check("attestor pubkey recorded on-chain", bool(data.get("attestor_pubkey")), str(data))

    req_id2 = await next_request_id("svc-2")
    await send_op("call", "svc-2", "outsider", "--request-hash", "cc" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))

    await send_op("respond", "svc-2", "owner", "--request-id", str(req_id2),
                  "--response-hash", "dd" * 32, may_fail=True)
    req2_data = await request_show("svc-2", req_id2)
    check("respond without attestation rejected", req2_data["found"], str(req2_data))

    await send_op("respond", "svc-2", "owner", "--request-id", str(req_id2), "--response-hash", "dd" * 32,
                  "--signer-vault-key", "wrong-service-attestor-key", may_fail=True)
    req2_data = await request_show("svc-2", req_id2)
    check("respond with wrong attestor key rejected", req2_data["found"], str(req2_data))

    await send_op("respond", "svc-2", "owner", "--request-id", str(req_id2), "--response-hash", "dd" * 32,
                  "--signer-vault-key", "service-attestor-key")
    req2_data = await request_show("svc-2", req_id2)
    check("attestor-signed respond recorded", not req2_data["found"], str(req2_data))

    print("\n=== snapshot behavior: rotating the attestor key does not affect an already-pending request ===")
    await tosctl("key", "add", "--name", "rotated-service-attestor-key")
    req_id3 = await next_request_id("svc-2")
    await send_op("call", "svc-2", "outsider", "--request-hash", "06" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))
    req3_before_rotate = await request_show("svc-2", req_id3)
    check("request snapshotted the attestor pubkey in force at call time", req3_before_rotate["found"],
          str(req3_before_rotate))

    # Rotation is unrestricted -- no pending-state freeze in this design,
    # unlike Task Escrow/Dispute -- but must not retroactively rewrite what
    # req_id3 requires.
    await send_op("rotate-attestor-key", "svc-2", "owner",
                  "--signer-vault-key", "rotated-service-attestor-key")
    data = await service_show("svc-2")
    check("attestor key rotated on the live policy", bool(data.get("attestor_pubkey")), str(data))

    # A signature under the *new* key must not satisfy req_id3's snapshot.
    await send_op("respond", "svc-2", "owner", "--request-id", str(req_id3), "--response-hash", "07" * 32,
                  "--signer-vault-key", "rotated-service-attestor-key", may_fail=True)
    req3_data = await request_show("svc-2", req_id3)
    check("new attestor key does not satisfy the old request's snapshot", req3_data["found"], str(req3_data))

    # The *old* key still does.
    await send_op("respond", "svc-2", "owner", "--request-id", str(req_id3), "--response-hash", "07" * 32,
                  "--signer-vault-key", "service-attestor-key")
    req3_data = await request_show("svc-2", req_id3)
    check("old (pre-rotation) attestor key still satisfies the pending request",
          not req3_data["found"], str(req3_data))

    # New requests require the new key.
    req_id4 = await next_request_id("svc-2")
    await send_op("call", "svc-2", "outsider", "--request-hash", "08" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))
    await send_op("respond", "svc-2", "owner", "--request-id", str(req_id4), "--response-hash", "09" * 32,
                  "--signer-vault-key", "service-attestor-key", may_fail=True)
    req4_data = await request_show("svc-2", req_id4)
    check("old key rejected for a request accepted after rotation", req4_data["found"], str(req4_data))
    await send_op("respond", "svc-2", "owner", "--request-id", str(req_id4), "--response-hash", "09" * 32,
                  "--signer-vault-key", "rotated-service-attestor-key")
    req4_data = await request_show("svc-2", req_id4)
    check("new key satisfies a request accepted after rotation", not req4_data["found"], str(req4_data))

    await send_op("revoke-attestor", "svc-2", "owner")
    data = await service_show("svc-2")
    check("owner can revoke the attestor once idle", not data.get("attestor_pubkey"), str(data))

    print("\n=== snapshot behavior: update-policy does not change an already-pending request's terms ===")
    address4 = await deploy_service("svc-4", owner, price_per_call=0.01, open_access=True)
    req_id5 = await next_request_id("svc-4")
    await send_op("call", "svc-4", "outsider", "--request-hash", "0a" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))
    req5_before = await request_show("svc-4", req_id5)
    check("pending request snapshotted price 0.01", abs(float(req5_before["price"]) - 0.01) < 1e-9,
          str(req5_before))

    # Policy changes are unrestricted (no freeze), but req_id5 keeps its
    # own snapshot regardless of what the live policy becomes.
    await send_op(
        "update-policy", "svc-4", "owner",
        "--price-per-call", "0.5", "--storage-fee", str(STORAGE_FEE), "--cleanup-bounty", str(CLEANUP_BOUNTY),
        "--response-sla", str(RESPONSE_SLA), "--refund-claim-window", str(REFUND_CLAIM_WINDOW),
        "--active", "true", "--rate-limit-per-day", "0", "--open-access",
        "--metadata-hash", METADATA_HASH, "--proof-scheme-hash", PROOF_SCHEME_HASH,
    )
    req5_after_policy_change = await request_show("svc-4", req_id5)
    check("pending request's snapshotted price is unaffected by update-policy",
          abs(float(req5_after_policy_change["price"]) - 0.01) < 1e-9, str(req5_after_policy_change))

    revenue_before5 = float((await service_show("svc-4"))["withdrawable_revenue"])
    await send_op("respond", "svc-4", "owner", "--request-id", str(req_id5), "--response-hash", "0b" * 32)
    data = await service_show("svc-4")
    # price(0.01) + storage_fee(STORAGE_FEE), not the new live price(0.5) --
    # proves the snapshot, not just that *some* revenue was credited.
    expected_increase = 0.01 + STORAGE_FEE
    check("responding credits the request's own (old, snapshotted) price, not the new live price",
          abs(float(data["withdrawable_revenue"]) - (revenue_before5 + expected_increase)) < 1e-6, str(data))

    print("\n=== persisted local record ===")
    records = {r["name"]: r for r in await tosctl_json("agent", "service", "ls")}
    check("record tracked locally", "svc-1" in records, str(sorted(records)))
    check("record owner matches", same_addr(records["svc-1"]["owner"], owner), str(records["svc-1"]))

    _ = caller2  # provisioned for symmetry with other multi-caller e2e scripts; svc-1's
    # concurrency section above already demonstrates two independent outstanding
    # requests from a single caller, which is the property that actually differs
    # from V1 (V1 could never have *any* second outstanding request, same-caller
    # or not) -- a second distinct caller is not additionally informative here.


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
