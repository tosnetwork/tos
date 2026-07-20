#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
agent-economy-composed-e2e.py — real-localnet acceptance of the full composed
AI-agent workflow from doc/ai-agent-workflow-example.md, exercised end to end
in a single running network rather than per-contract in isolation:

  Planner -> Task Escrow -> Agent Account (worker) -> Service Actor
    -> Proof Attestation (inline, on Task Escrow / Service Actor / Dispute)
    -> Settlement (happy path) / Dispute (contested path)

Each contract's own lifecycle is already covered by its dedicated
scripts/*-e2e.py; this script instead proves the *integration* points: an
Agent Account (controller-signed) accepting and completing a Task Escrow that
also requires an attested settlement, while mid-task paying an attested
Service Actor, and separately a contested Task Escrow routed through an
attested Dispute ruling back to Task Escrow's own resolve.

  SETUP     provision planner/verifier/reviewer/model-provider/worker-owner
            wallets, an Agent Wallet + deployed Agent Account for the worker,
            a Capability Registry advertisement, and an attested Service Actor

  HAPPY     planner posts an attested Task Escrow assigned to the worker's
            Agent Account -> worker's Agent Account accepts (controller-
            signed) -> worker's owner wallet pays and calls the Service Actor
            -> model provider responds with an attested signature -> worker's
            Agent Account submits the task result (controller-signed) ->
            verifier settles with the required attestation signature ->
            worker is paid, Service Actor accrued revenue and recorded the
            attested response

  CONTESTED a second attested Task Escrow follows the same accept/call/
            respond/result steps -> planner disputes it -> an attested
            Dispute case is deployed referencing the task -> worker submits
            respondent evidence -> reviewer rules (with the required
            attestation signature), splitting the award -> verifier resolves
            the Task Escrow with the split-translated payout

Exit code 0 iff every check passes.

Run from the repository root: uv run python scripts/agent-economy-composed-e2e.py
"""
import asyncio
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.request
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from contract import tos
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:19246"
WORKDIR = REPO / "test/integration/.agent-economy-composed-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000008"
NANO = 1_000_000_000
REVIEW_PERIOD = 120

TASK_CATEGORIES_HASH = "11" * 32
PRICING_HASH = "22" * 32
CAPABILITY_METADATA_HASH = "33" * 32
VERIFICATION_METHOD_HASH = "44" * 32
SERVICE_METADATA_HASH = CAPABILITY_METADATA_HASH
SERVICE_PROOF_SCHEME_HASH = VERIFICATION_METHOD_HASH
POLICY_HASH = "55" * 32
REQUEST_HASH = "66" * 32
RESPONSE_HASH = "77" * 32
RESULT_HASH = "88" * 32
EVIDENCE_HASH = "99" * 32
CONTESTED_RESULT_HASH = "aa" * 32
CONTESTED_EVIDENCE_HASH = "bb" * 32
DISPUTE_HASH = "cc" * 32
SUBJECT_HASH_PLACEHOLDER = "dd" * 32
CLAIMANT_EVIDENCE_HASH = "ee" * 32
RESPONDENT_EVIDENCE_HASH = "ff" * 32
RULING_HASH = "01" * 32

failures: list[str] = []


def check(label: str, ok: bool, detail: str = ""):
    if ok:
        print(f"  PASS: {label}")
    else:
        print(f"  FAIL: {label}  {detail}")
        failures.append(label)


def rpc_call(method: str, **params):
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


async def task_show(name: str):
    return await tosctl_json("agent", "task", "show", "--name", name)


async def wait_task_status(name: str, want: str, timeout: float = 90.0) -> str:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            last = (await task_show(name))["status"]
            if last == want:
                return last
        except Exception as e:
            last = f"error: {e}"
        await asyncio.sleep(2)
    return last


async def send_task_op(operation: str, name: str, *extra: str, may_fail: bool = False) -> str:
    return await tosctl(
        "agent", "task", "send", "--operation", operation, "--name", name,
        "--yes", *extra, may_fail=may_fail,
    )


async def run_checks(faucet) -> None:
    print("\n=== provision: wallets, Agent Wallet/Account, vault keys ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    for name in ("planner", "verifier", "reviewer", "model-provider", "worker-owner"):
        await tosctl("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    planner = await wallet_address("planner")
    verifier = await wallet_address("verifier")
    reviewer = await wallet_address("reviewer")
    model_provider = await wallet_address("model-provider")
    worker_owner = await wallet_address("worker-owner")
    print(f"  planner:        {planner}\n  verifier:       {verifier}\n"
          f"  reviewer:       {reviewer}\n  model-provider: {model_provider}\n"
          f"  worker-owner:   {worker_owner}")

    for name, addr in (
        ("planner", planner), ("verifier", verifier), ("reviewer", reviewer),
        ("model-provider", model_provider), ("worker-owner", worker_owner),
    ):
        await faucet.send(faucet_transfer(faucet, addr, 50))
        check(f"{name} funded", await wait_balance_at_least(addr, 49 * NANO))
    for name in ("planner", "verifier", "reviewer", "model-provider", "worker-owner"):
        await tosctl("wallet", "activate", "-n", name)
    for name, addr in (
        ("planner", planner), ("verifier", verifier), ("reviewer", reviewer),
        ("model-provider", model_provider), ("worker-owner", worker_owner),
    ):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{name} wallet active", bool(active))

    await tosctl(
        "agent", "wallet", "create", "--name", "research-agent", "-v", "V3R2", "-w", "0",
        "--max-per-tx", "2", "--daily-limit", "10", "--format", "json",
    )
    account_deploy = await tosctl_json(
        "agent", "account", "deploy", "--wallet", "research-agent", "--from", "planner",
        "-w", "0", "--amount", "2", "--yes",
    )
    worker_account = norm_addr(account_deploy["address"])
    check("worker Agent Account deployed", await poll_predicate(
        lambda: rpc_call("getAddressState", address=worker_account).get("result") == "active"))

    for key_name in ("task-attestor-key", "service-attestor-key", "dispute-attestor-key"):
        await tosctl("key", "add", "--name", key_name)

    print("\n=== capability advertisement + attested Service Actor ===")
    registry_deploy = await tosctl_json(
        "agent", "registry", "deploy", "--name", "model-provider-registry",
        "--owner", model_provider, "--verifier", verifier,
        "--task-categories-hash", TASK_CATEGORIES_HASH,
        "--pricing-hash", PRICING_HASH,
        "--metadata-hash", CAPABILITY_METADATA_HASH,
        "--verification-method-hash", VERIFICATION_METHOD_HASH,
        "--bond", "1", "--from", "model-provider", "--amount", "1.2", "-w", "0", "--yes",
    )
    registry_address = registry_deploy["address"]
    check("capability registry deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=registry_address).get("result") == "active"))

    service_deploy = await tosctl_json(
        "agent", "service", "deploy", "--name", "model-provider-service",
        "--owner", model_provider, "--open-access",
        "--price-per-call", "0.05", "--rate-limit-per-day", "1000",
        "--metadata-hash", SERVICE_METADATA_HASH,
        "--proof-scheme-hash", SERVICE_PROOF_SCHEME_HASH,
        "--signer-vault-key", "service-attestor-key",
        "--from", "model-provider", "--amount", "0.3", "-w", "0", "--yes",
    )
    service_address = service_deploy["address"]
    check("service actor deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=service_address).get("result") == "active"))
    service_data = await tosctl_json("agent", "service", "show", "--name", "model-provider-service")
    check("service actor is attested", bool(service_data.get("attestor_pubkey")), str(service_data))

    async def worker_calls_and_gets_response(response_hash: str) -> None:
        await tosctl(
            "agent", "service", "send", "--operation", "call", "--name", "model-provider-service",
            "--from", "worker-owner", "--request-hash", REQUEST_HASH, "--amount", "0.05", "--yes",
        )
        await tosctl(
            "agent", "service", "send", "--operation", "respond", "--name",
            "model-provider-service", "--from", "model-provider",
            "--response-hash", response_hash, "--signer-vault-key", "service-attestor-key",
            "--yes",
        )

    # ---------------- HAPPY PATH ----------------
    print("\n=== happy path: attested Task Escrow through Agent Account + Service Actor ===")
    happy_deadline = int(time.time()) + 3600
    happy_deploy = await tosctl_json(
        "agent", "task", "create", "--name", "workflow-happy",
        "--creator", planner, "--agent", worker_account, "--verifier", verifier,
        "--budget", "5", "--deadline", str(happy_deadline), "--review-period", str(REVIEW_PERIOD),
        "--policy-hash", POLICY_HASH, "--signer-vault-key", "task-attestor-key",
        "--from", "planner", "--amount", "5.2", "-w", "0", "--yes",
    )
    happy_escrow = happy_deploy["address"]
    check("happy task open after deploy",
          await wait_task_status("workflow-happy", "open") == "open")
    happy_data = await task_show("workflow-happy")
    check("happy task assigned to worker Agent Account",
          same_addr(happy_data["assigned_agent"], worker_account), str(happy_data))
    check("happy task is attested", bool(happy_data.get("attestor_pubkey")), str(happy_data))

    await tosctl(
        "agent", "task", "send", "--operation", "accept", "--name", "workflow-happy",
        "--via-agent-account", "research-agent", "--amount", "0.1", "--yes",
    )
    check("worker Agent Account accepted the task",
          await wait_task_status("workflow-happy", "accepted") == "accepted")

    revenue_before = float(
        (await tosctl_json("agent", "service", "show", "--name", "model-provider-service"))
        ["total_revenue"])
    await worker_calls_and_gets_response(RESPONSE_HASH)
    service_after_call = await tosctl_json(
        "agent", "service", "show", "--name", "model-provider-service")
    check("service actor accrued revenue for the mid-task call",
          float(service_after_call["total_revenue"]) > revenue_before, str(service_after_call))
    check("service actor recorded the attested response",
          service_after_call["last_response_hash"] == RESPONSE_HASH, str(service_after_call))

    await tosctl(
        "agent", "task", "send", "--operation", "result", "--name", "workflow-happy",
        "--via-agent-account", "research-agent", "--amount", "0.1",
        "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH, "--yes",
    )
    check("worker Agent Account submitted the task result",
          await wait_task_status("workflow-happy", "result_submitted") == "result_submitted")

    await send_task_op("settle", "workflow-happy", "--from", "verifier", "--payout", "5",
                       may_fail=True)
    await asyncio.sleep(5)
    check("settle without attestation rejected",
          (await task_show("workflow-happy"))["status"] == "result_submitted")

    worker_before = balance(worker_account)
    await send_task_op("settle", "workflow-happy", "--from", "verifier", "--payout", "5",
                       "--signer-vault-key", "task-attestor-key")
    check("happy task settled with attestation",
          await wait_task_status("workflow-happy", "settled") == "settled")
    await asyncio.sleep(5)
    check("worker Agent Account received the payout", balance(worker_account) > worker_before)

    # ---------------- CONTESTED PATH ----------------
    print("\n=== contested path: dispute -> attested ruling -> Task Escrow resolve ===")
    contested_deadline = int(time.time()) + 3600
    contested_deploy = await tosctl_json(
        "agent", "task", "create", "--name", "workflow-contested",
        "--creator", planner, "--agent", worker_account, "--verifier", verifier,
        "--budget", "4", "--deadline", str(contested_deadline),
        "--review-period", str(REVIEW_PERIOD),
        "--policy-hash", POLICY_HASH, "--from", "planner", "--amount", "4.2", "-w", "0", "--yes",
    )
    contested_escrow = contested_deploy["address"]
    check("contested task open after deploy",
          await wait_task_status("workflow-contested", "open") == "open")

    await tosctl(
        "agent", "task", "send", "--operation", "accept", "--name", "workflow-contested",
        "--via-agent-account", "research-agent", "--amount", "0.1", "--yes",
    )
    check("worker Agent Account accepted the contested task",
          await wait_task_status("workflow-contested", "accepted") == "accepted")

    await worker_calls_and_gets_response(RESPONSE_HASH)

    await tosctl(
        "agent", "task", "send", "--operation", "result", "--name", "workflow-contested",
        "--via-agent-account", "research-agent", "--amount", "0.1",
        "--result-hash", CONTESTED_RESULT_HASH, "--evidence-hash", CONTESTED_EVIDENCE_HASH,
        "--yes",
    )
    check("worker Agent Account submitted the contested result",
          await wait_task_status("workflow-contested", "result_submitted") == "result_submitted")

    await send_task_op("dispute", "workflow-contested", "--from", "planner",
                       "--dispute-hash", DISPUTE_HASH)
    check("planner opened a dispute on the contested task",
          await wait_task_status("workflow-contested", "disputed") == "disputed")

    subject_hash = hashlib.sha256(contested_escrow.encode()).hexdigest()
    dispute_deploy = await tosctl_json(
        "agent", "dispute", "deploy", "--name", "workflow-contested-dispute",
        "--claimant", planner, "--respondent", worker_owner, "--reviewer", reviewer,
        "--deadline", str(contested_deadline + 100),
        "--subject-hash", subject_hash, "--claimant-evidence-hash", CLAIMANT_EVIDENCE_HASH,
        "--signer-vault-key", "dispute-attestor-key",
        "--from", "planner", "--amount", "0.1", "-w", "0", "--yes",
    )
    dispute_address = dispute_deploy["address"]
    check("dispute case deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=dispute_address).get("result") == "active"))
    dispute_data = await tosctl_json(
        "agent", "dispute", "show", "--name", "workflow-contested-dispute")
    check("dispute case is attested", bool(dispute_data.get("attestor_pubkey")), str(dispute_data))
    check("dispute references the contested task",
          dispute_data["subject_hash"] == subject_hash, str(dispute_data))

    await tosctl(
        "agent", "dispute", "send", "--operation", "submit-respondent-evidence",
        "--name", "workflow-contested-dispute", "--from", "worker-owner",
        "--respondent-evidence-hash", RESPONDENT_EVIDENCE_HASH, "--yes",
    )
    dispute_data = await tosctl_json(
        "agent", "dispute", "show", "--name", "workflow-contested-dispute")
    check("worker submitted respondent evidence",
          dispute_data["status"] == "evidence_submitted", str(dispute_data))

    await tosctl(
        "agent", "dispute", "send", "--operation", "rule",
        "--name", "workflow-contested-dispute", "--from", "reviewer",
        "--ruling", "split", "--split-bps", "6500", "--ruling-hash", RULING_HASH,
        may_fail=True,
    )
    dispute_data = await tosctl_json(
        "agent", "dispute", "show", "--name", "workflow-contested-dispute")
    check("rule without attestation rejected",
          dispute_data["status"] == "evidence_submitted", str(dispute_data))

    await tosctl(
        "agent", "dispute", "send", "--operation", "rule",
        "--name", "workflow-contested-dispute", "--from", "reviewer",
        "--ruling", "split", "--split-bps", "6500", "--ruling-hash", RULING_HASH,
        "--signer-vault-key", "dispute-attestor-key", "--yes",
    )
    dispute_data = await tosctl_json(
        "agent", "dispute", "show", "--name", "workflow-contested-dispute")
    check("reviewer ruling resolved with attestation",
          dispute_data["status"] == "resolved" and dispute_data["ruling"] == "split",
          str(dispute_data))
    check("split bps recorded", dispute_data["split_bps"] == 6500, str(dispute_data))

    # 4 TOS budget * 6500 bps / 10000 = 2.6 TOS to the worker.
    worker_before = balance(worker_account)
    await send_task_op("resolve", "workflow-contested", "--from", "verifier", "--payout", "2.6")
    check("verifier resolved the contested task per the ruling",
          await wait_task_status("workflow-contested", "settled") == "settled")
    await asyncio.sleep(5)
    worker_delta = balance(worker_account) - worker_before
    check("worker Agent Account received the split-translated payout",
          abs(worker_delta - int(2.6 * NANO)) <= NANO // 100, f"delta={worker_delta}")


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps({
        "nodes": {}, "wallets": {}, "pools": {}, "bindings": {},
        "chain_rpc": {"urls": [f"http://{RPC}/"]}, "http": {},
        "master_wallet": None, "tick_interval": 40, "log": None,
    }, indent=2))
    install = Install(BUILD_DIR, REPO)

    async with Network(install, WORKDIR / "net", base_port=23800) as network:
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
    else:
        print("\n=== RESULT: ALL PASS ===")
    sys.exit(rc)
