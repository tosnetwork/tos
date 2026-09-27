#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
agent-economy-composed-e2e.py — real-localnet acceptance of the full composed
AI-agent workflow from https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ai-agent-workflow-example.md, exercised end to end
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
import base64
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from tostester.pq_initial_validator import make_deterministic_pq_initial_validator
from contract import tos
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:19246"
OBSERVER_RPCS = ("127.0.0.1:19247", "127.0.0.1:19248")
WORKDIR = REPO / "test/integration/.agent-economy-composed-e2e"
RPC_TRANSCRIPT = WORKDIR / "rpc-transcript.jsonl"
CLI_TRANSCRIPT = WORKDIR / "cli-transcript.jsonl"
CHAIN_EVIDENCE = WORKDIR / "chain-evidence.jsonl"
MANIFEST = WORKDIR / "manifest.json"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
OBSERVER_CONFIGS = tuple(WORKDIR / f"tosctl-observer-{index}.json" for index in (1, 2))
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000008"
NANO = 1_000_000_000
REVIEW_PERIOD = 3600

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


def write_manifest() -> None:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    source_dirty = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--"], cwd=REPO).returncode != 0
    binaries = {
        "validator_engine": BUILD_DIR / "validator-engine/validator-engine",
        "dht_server": BUILD_DIR / "dht-server/dht-server",
        "tosctl": Path(TOSCTL),
    }
    manifest = {
        "source_commit": source_commit,
        "source_tracked_dirty": source_dirty,
        "command": shlex.join([sys.executable, *sys.argv]),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "evidence_test_sha256": hashlib.sha256(
            (REPO / "test/pq-native/test_e10_composed_evidence.py").read_bytes()).hexdigest(),
        "quorum_test_sha256": hashlib.sha256(
            (REPO / "test/pq-native/test_e10_controller_quorum.py").read_bytes()).hexdigest(),
        "binaries": {
            name: {"path": str(path.resolve()),
                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for name, path in binaries.items()
        },
        "rpc_transcript": RPC_TRANSCRIPT.name,
        "cli_transcript": CLI_TRANSCRIPT.name,
        "chain_evidence": CHAIN_EVIDENCE.name,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if source_dirty:
        raise RuntimeError("E10 real-chain run requires a clean tracked source tree")


def check(label: str, ok: bool, detail: str = ""):
    if ok:
        print(f"  PASS: {label}")
    else:
        print(f"  FAIL: {label}  {detail}")
        failures.append(label)


def rpc_call(method: str, *, endpoint: str = RPC, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{endpoint}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as error:
        raw, status = error.read(), error.code
        record_jsonl(RPC_TRANSCRIPT, {"endpoint": endpoint, "method": method, "params": params,
                     "status": status, "request_base64": base64.b64encode(body).decode(),
                     "response_base64": base64.b64encode(raw).decode()})
        raise
    record_jsonl(RPC_TRANSCRIPT, {"endpoint": endpoint, "method": method, "params": params,
                 "status": status, "request_base64": base64.b64encode(body).decode(),
                 "response_base64": base64.b64encode(raw).decode()})
    return json.loads(raw.decode())


def record_jsonl(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, sort_keys=True) + "\n")


def finalized_mc_header() -> dict:
    block = rpc_call("getMasterchainInfo")["result"]["last"]
    header = rpc_call("getBlockHeader", workchain=block["workchain"],
                      shard=str(block["shard"]), seqno=block["seqno"])["result"]
    if any(header["id"][field] != block[field]
           for field in ("workchain", "shard", "seqno", "root_hash", "file_hash")):
        raise RuntimeError("finalized masterchain header did not match its block ID")
    return {"id": block, "gen_utime": int(header["gen_utime"])}


def last_lt(address: str) -> int:
    return int(rpc_call("getAddressInformation", address=address)
               ["result"]["last_transaction_id"]["lt"])


def transactions_after(address: str, baseline_lt: int) -> list[dict]:
    rows = rpc_call("getTransactions", address=address, limit=10)["result"]
    if len(rows) == 10 and all(
        int(row["transaction_id"]["lt"]) > baseline_lt for row in rows
    ):
        raise RuntimeError("composed-route transaction page did not cover baseline")
    return [row for row in rows if int(row["transaction_id"]["lt"]) > baseline_lt]


def balance(addr: str) -> int:
    return int(rpc_call("getAddressInformation", address=addr)["result"]["balance"])


async def tosctl(*args: str) -> str:
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
        out, err = await proc.communicate()
        record_jsonl(CLI_TRANSCRIPT, {"args": args, "timeout": True,
                     "stdout_base64": base64.b64encode(out).decode(),
                     "stderr_base64": base64.b64encode(err).decode()})
        raise RuntimeError(f"tosctl {' '.join(args)} timed out")
    record_jsonl(CLI_TRANSCRIPT, {"args": args, "exit_code": proc.returncode,
                 "stdout_base64": base64.b64encode(out).decode(),
                 "stderr_base64": base64.b64encode(err).decode()})
    if proc.returncode != 0:
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


async def wait_rpc_ready(timeout: float = 180.0, endpoint: str = RPC) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if "result" in rpc_call("getMasterchainInfo", endpoint=endpoint):
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


async def send_task_op(operation: str, name: str, *extra: str) -> str:
    return await tosctl(
        "agent", "task", "send", "--operation", operation, "--name", name,
        "--yes", *extra,
    )


async def rejected_operation(label: str, address: str, payer: str, expected_exit: int,
                             show_state, send) -> None:
    before_state = await show_state()
    before_head = finalized_mc_header()
    wallet_lt, contract_lt = last_lt(payer), last_lt(address)
    receipt = await send()
    deadline = time.monotonic() + 45
    wallet_tx = contract_tx = bounce_tx = None
    while time.monotonic() < deadline:
        wallet_rows = transactions_after(payer, wallet_lt)
        if wallet_rows:
            sends = [row for row in wallet_rows if any(
                same_addr(msg.get("destination"), address)
                for msg in row.get("out_msgs") or [])]
            if len(sends) != 1:
                raise RuntimeError(f"{label}: expected exactly one wallet send to target")
            wallet_tx = sends[0]
            outgoing = wallet_tx.get("out_msgs") or []
            if (wallet_tx.get("aborted") is not False
                    or (wallet_tx.get("compute") or {}).get("success") is not True
                    or (wallet_tx.get("action") or {}).get("success") is not True
                    or len(outgoing) != 1
                    or not same_addr(outgoing[0].get("destination"), address)):
                raise RuntimeError(f"{label}: wallet did not submit to target contract")
            contract_rows = transactions_after(address, contract_lt)
            if contract_rows:
                if len(contract_rows) != 1:
                    raise RuntimeError(f"{label}: multiple new target transactions")
                contract_tx = contract_rows[0]
                inbound = contract_tx.get("in_msg") or {}
                if (inbound.get("hash") != outgoing[0].get("hash")
                        or not same_addr(inbound.get("source"), payer)):
                    raise RuntimeError(f"{label}: target inbound hash differs from wallet outbound")
                refunds = contract_tx.get("out_msgs") or []
                if (len(refunds) != 1 or refunds[0].get("bounced") is not True
                        or not same_addr(refunds[0].get("source"), address)
                        or not same_addr(refunds[0].get("destination"), payer)):
                    raise RuntimeError(f"{label}: target did not emit one exact bounce")
                other_rows = [row for row in wallet_rows if row is not wallet_tx]
                if len(other_rows) > 1:
                    raise RuntimeError(f"{label}: unrelated or duplicate wallet transaction")
                if other_rows:
                    bounce_tx = other_rows[0]
                    bounce_in = bounce_tx.get("in_msg") or {}
                    if (bounce_in.get("hash") != refunds[0].get("hash")
                            or bounce_in.get("bounced") is not True
                            or not same_addr(bounce_in.get("source"), address)
                            or not same_addr(bounce_in.get("destination"), payer)
                            or bounce_tx.get("out_msgs")):
                        raise RuntimeError(f"{label}: wallet credit is not the target's exact bounce")
                    break
        await asyncio.sleep(1)
    if wallet_tx is None or contract_tx is None or bounce_tx is None:
        raise RuntimeError(f"{label}: exact wallet-target-bounce chain not observed")
    if (contract_tx.get("aborted") is not True
            or (contract_tx.get("compute") or {}).get("success") is not False
            or (contract_tx.get("compute") or {}).get("exit_code") != expected_exit):
        raise RuntimeError(f"{label}: expected VM exit {expected_exit}, got {contract_tx}")
    observations = []
    last_seqno = before_head["id"]["seqno"]
    while time.monotonic() < deadline and len(observations) < 2:
        head = finalized_mc_header()
        if head["id"]["seqno"] > last_seqno:
            state = await show_state()
            observations.append({"head": head, "state": state})
            if state != before_state:
                raise RuntimeError(f"{label}: contract state changed after VM rejection")
            last_seqno = head["id"]["seqno"]
        else:
            await asyncio.sleep(1)
    if len(observations) != 2:
        raise RuntimeError(f"{label}: two later finalized heads not observed")
    record_jsonl(CHAIN_EVIDENCE, {"label": label, "kind": "negative", "receipt": receipt,
                 "expected_exit": expected_exit, "before_state": before_state,
                 "before_head": before_head, "wallet_tx": wallet_tx,
                 "contract_tx": contract_tx, "bounce_tx": bounce_tx,
                 "observations": observations})
    check(label, True)


async def verify_payout_edge(label: str, escrow: str, recipient: str,
                             escrow_lt: int, recipient_lt: int, amount: int,
                             before_head: dict) -> None:
    """Tie one successful Escrow action to its exact Agent Account credit message."""
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        source_rows = transactions_after(escrow, escrow_lt)
        recipient_rows = transactions_after(recipient, recipient_lt)
        if source_rows and recipient_rows:
            if len(source_rows) != 1:
                raise RuntimeError(f"{label}: multiple new escrow transactions")
            source_tx = source_rows[0]
            if (source_tx.get("aborted") is not False
                    or (source_tx.get("compute") or {}).get("success") is not True
                    or (source_tx.get("action") or {}).get("success") is not True):
                raise RuntimeError(f"{label}: escrow payout transaction failed")
            outgoing = [msg for msg in source_tx.get("out_msgs") or []
                        if same_addr(msg.get("destination"), recipient)]
            if len(outgoing) != 1 or int(outgoing[0]["value"]) != amount:
                raise RuntimeError(f"{label}: exact payout message and amount not found")
            matching = [row for row in recipient_rows
                        if (row.get("in_msg") or {}).get("hash") == outgoing[0].get("hash")]
            if len(matching) != 1:
                raise RuntimeError(f"{label}: recipient inbound hash did not match payout")
            inbound = matching[0]["in_msg"]
            if (not same_addr(inbound.get("source"), escrow)
                    or int(inbound["value"]) != amount
                    or matching[0].get("aborted") is not False):
                raise RuntimeError(f"{label}: recipient did not accept exact escrow payout")
            heads = []
            last_seqno = before_head["id"]["seqno"]
            while time.monotonic() < deadline and len(heads) < 2:
                head = finalized_mc_header()
                if head["id"]["seqno"] > last_seqno:
                    heads.append(head)
                    last_seqno = head["id"]["seqno"]
                else:
                    await asyncio.sleep(1)
            if len(heads) != 2:
                raise RuntimeError(f"{label}: two later finalized heads not observed")
            record_jsonl(CHAIN_EVIDENCE, {"label": label, "kind": "payout",
                         "escrow_tx": source_tx, "recipient_tx": matching[0],
                         "amount": amount, "before_head": before_head, "final_heads": heads})
            check(label, True)
            return
        await asyncio.sleep(1)
    raise RuntimeError(f"{label}: exact escrow-to-agent-account payout not observed")
def controller_task_args(operation: str, name: str) -> tuple[str, ...]:
    """Stable per-action ID and two independent read-only RPC configurations."""
    action_id = hashlib.sha256(f"e10:{name}:{operation}".encode()).hexdigest()
    return ("--controller-action-id", action_id, "--quorum-config",
            str(OBSERVER_CONFIGS[0]), str(OBSERVER_CONFIGS[1]))


def write_config() -> None:
    config = {
        "nodes": {}, "wallets": {}, "pools": {}, "bindings": {},
        "chain_rpc": {"urls": [f"http://{RPC}/"]}, "http": {},
        "master_wallet": None, "tick_interval": 40, "log": None,
    }
    CONFIG.write_text(json.dumps(config, indent=2))
    for path, endpoint in zip(OBSERVER_CONFIGS, OBSERVER_RPCS, strict=True):
        observer = dict(config)
        observer["chain_rpc"] = {"urls": [f"http://{endpoint}/"]}
        path.write_text(json.dumps(observer, indent=2))


def require_same_zerostate() -> None:
    if len(set((RPC, *OBSERVER_RPCS))) != 3:
        raise RuntimeError("E10 quorum RPC endpoints are not independent")
    primary = rpc_call("getMasterchainInfo")["result"]["init"]
    for endpoint in OBSERVER_RPCS:
        observed = rpc_call("getMasterchainInfo", endpoint=endpoint)["result"]["init"]
        if observed != primary:
            raise RuntimeError(f"E10 observer {endpoint} has a different zerostate")


def require_independent_processes(process_map: list[dict]) -> None:
    if (len(process_map) != 3 or
            len({row["pid"] for row in process_map}) != 3 or
            len({row["directory"] for row in process_map}) != 3 or
            len({row["rpc"] for row in process_map}) != 3 or
            any(row["pid"] is None for row in process_map)):
        raise RuntimeError("E10 observer processes are not independent")


async def run_checks(faucet) -> None:
    print("\n=== provision: wallets, Agent Wallet/Account, vault keys ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")
    for endpoint in OBSERVER_RPCS:
        if not await wait_rpc_ready(endpoint=endpoint):
            check(f"independent observer RPC {endpoint} ready", False)
            return
    require_same_zerostate()
    check("two independent observers share the validator zerostate", True)

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

    # storage_fee/cleanup_bounty/response_sla/refund_claim_window match the
    # protocol minimums enforced in crypto/smartcont/service-actor-code.fc
    # (MINIMUM_STORAGE_FEE=MINIMUM_CLEANUP_BOUNTY=0.1 TOS,
    # MIN_RESPONSE_SLA=MIN_REFUND_CLAIM_WINDOW=3600s); amount covers the
    # protocol's MINIMUM_OPERATING_RESERVE (1 TOS) plus headroom for the two
    # mid-workflow calls this script makes against this same instance.
    service_deploy = await tosctl_json(
        "agent", "service", "deploy", "--name", "model-provider-service",
        "--owner", model_provider, "--open-access",
        "--price-per-call", "0.05", "--storage-fee", "0.2", "--cleanup-bounty", "0.1",
        "--response-sla", "3600", "--refund-claim-window", "3600",
        "--rate-limit-per-day", "1000",
        "--metadata-hash", SERVICE_METADATA_HASH,
        "--proof-scheme-hash", SERVICE_PROOF_SCHEME_HASH,
        "--signer-vault-key", "service-attestor-key",
        "--from", "model-provider", "--amount", "2", "-w", "0", "--yes",
    )
    service_address = service_deploy["address"]
    check("service actor deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=service_address).get("result") == "active"))
    service_data = await tosctl_json("agent", "service", "show", "--name", "model-provider-service")
    check("service actor is attested", bool(service_data.get("attestor_pubkey")), str(service_data))

    async def worker_calls_and_gets_response(response_hash: str) -> int:
        # request_id is contract-assigned; predicting it as next_request_id
        # is only valid because this script never has two callers racing
        # this same service instance (each call is awaited to completion
        # here before the next one is submitted).
        pre_call = await tosctl_json("agent", "service", "show", "--name", "model-provider-service")
        request_id = pre_call["next_request_id"]
        await tosctl(
            "agent", "service", "send", "--operation", "call", "--name", "model-provider-service",
            "--from", "worker-owner", "--request-hash", REQUEST_HASH,
            "--amount", "0.3", "--yes",  # 0.05 price + 0.2 storage_fee + real-fee headroom
        )
        await tosctl(
            "agent", "service", "send", "--operation", "respond", "--name",
            "model-provider-service", "--from", "model-provider",
            "--request-id", str(request_id),
            "--response-hash", response_hash, "--signer-vault-key", "service-attestor-key",
            "--yes",
        )
        return request_id

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
        *controller_task_args("accept", "workflow-happy"),
    )
    check("worker Agent Account accepted the task",
          await wait_task_status("workflow-happy", "accepted") == "accepted")

    revenue_before = float(
        (await tosctl_json("agent", "service", "show", "--name", "model-provider-service"))
        ["withdrawable_revenue"])
    happy_request_id = await worker_calls_and_gets_response(RESPONSE_HASH)
    service_after_call = await tosctl_json(
        "agent", "service", "show", "--name", "model-provider-service")
    check("service actor accrued revenue for the mid-task call",
          float(service_after_call["withdrawable_revenue"]) > revenue_before, str(service_after_call))
    # There is no terminal per-request record once a request resolves (see
    # https://github.com/tosnetwork/doc/blob/main/tos-blockchain/service-actor-concurrent-escrow-upgrade.md's Persistent State
    # section) -- the attested response having been accepted is observed by
    # the request no longer being pending, not by a stored response hash.
    happy_request_after = await tosctl_json(
        "agent", "service", "request-show", "--name", "model-provider-service",
        "--request-id", str(happy_request_id))
    check("service actor recorded the attested response (request resolved)",
          not happy_request_after["found"], str(happy_request_after))

    await tosctl(
        "agent", "task", "send", "--operation", "result", "--name", "workflow-happy",
        "--via-agent-account", "research-agent", "--amount", "0.1",
        "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH, "--yes",
        *controller_task_args("result", "workflow-happy"),
    )
    check("worker Agent Account submitted the task result",
          await wait_task_status("workflow-happy", "result_submitted") == "result_submitted")

    await rejected_operation(
        "settle without attestation rejected", happy_escrow, verifier, 9,
        lambda: task_show("workflow-happy"),
        lambda: send_task_op("settle", "workflow-happy", "--from", "verifier", "--payout", "5"))

    worker_before = balance(worker_account)
    happy_escrow_lt, worker_lt = last_lt(happy_escrow), last_lt(worker_account)
    payout_before_head = finalized_mc_header()
    await send_task_op("settle", "workflow-happy", "--from", "verifier", "--payout", "5",
                       "--signer-vault-key", "task-attestor-key")
    check("happy task settled with attestation",
          await wait_task_status("workflow-happy", "settled") == "settled")
    await verify_payout_edge("worker Agent Account received the payout", happy_escrow,
                             worker_account, happy_escrow_lt, worker_lt, 5 * NANO,
                             payout_before_head)
    check("worker Agent Account balance rose after exact payout",
          balance(worker_account) > worker_before)

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
        *controller_task_args("accept", "workflow-contested"),
    )
    check("worker Agent Account accepted the contested task",
          await wait_task_status("workflow-contested", "accepted") == "accepted")

    await worker_calls_and_gets_response(RESPONSE_HASH)

    await tosctl(
        "agent", "task", "send", "--operation", "result", "--name", "workflow-contested",
        "--via-agent-account", "research-agent", "--amount", "0.1",
        "--result-hash", CONTESTED_RESULT_HASH, "--evidence-hash", CONTESTED_EVIDENCE_HASH,
        "--yes",
        *controller_task_args("result", "workflow-contested"),
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

    await rejected_operation(
        "rule without attestation rejected", dispute_address, reviewer, 9,
        lambda: tosctl_json("agent", "dispute", "show", "--name", "workflow-contested-dispute"),
        lambda: tosctl("agent", "dispute", "send", "--operation", "rule",
                       "--name", "workflow-contested-dispute", "--from", "reviewer",
                       "--ruling", "split", "--split-bps", "6500",
                       "--ruling-hash", RULING_HASH, "--yes"))

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
    contested_escrow_lt, worker_lt = last_lt(contested_escrow), last_lt(worker_account)
    payout_before_head = finalized_mc_header()
    await send_task_op("resolve", "workflow-contested", "--from", "verifier", "--payout", "2.6")
    check("verifier resolved the contested task per the ruling",
          await wait_task_status("workflow-contested", "settled") == "settled")
    await verify_payout_edge("worker Agent Account received the split-translated payout",
                             contested_escrow, worker_account, contested_escrow_lt, worker_lt,
                             26 * NANO // 10, payout_before_head)
    worker_delta = balance(worker_account) - worker_before
    check("worker Agent Account balance reflects the split-translated payout",
          abs(worker_delta - int(2.6 * NANO)) <= NANO // 100, f"delta={worker_delta}")


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    write_manifest()
    write_config()
    install = Install(BUILD_DIR, REPO)

    async with Network(install, WORKDIR / "net", base_port=23800) as network:
        dht = network.create_dht_node()
        node = network.create_full_node()
        observers = [network.create_full_node() for _ in OBSERVER_RPCS]
        make_deterministic_pq_initial_validator(node, 0)
        node.announce_to(dht)
        for observer in observers:
            observer.announce_to(dht)

        dht_task = asyncio.create_task(dht.run())
        node_task = asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", RPC])))
        observer_tasks = [
            asyncio.create_task(observer.run(StartOptions(args=["--json-rpc-address", endpoint])))
            for observer, endpoint in zip(observers, OBSERVER_RPCS, strict=True)
        ]
        try:
            await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=120)
            if len({id(node), *(id(observer) for observer in observers)}) != 3:
                raise RuntimeError("E10 observer node objects are not independent")
            process_map = [
                {"role": role, "pid": process.process_id,
                 "rpc": endpoint, "directory": str(process.directory)}
                for role, process, endpoint in (
                    ("validator", node, RPC),
                    ("observer-1", observers[0], OBSERVER_RPCS[0]),
                    ("observer-2", observers[1], OBSERVER_RPCS[1]),
                )
            ]
            require_independent_processes(process_map)
            (WORKDIR / "process-map.json").write_text(json.dumps(process_map, indent=2) + "\n")
            client = await node.toslib_client()
            faucet = network.zerostate.main_wallet(client)
            await run_checks(faucet)
        finally:
            for t in (node_task, dht_task, *observer_tasks):
                t.cancel()
            await asyncio.gather(node_task, dht_task, *observer_tasks, return_exceptions=True)
            await node.stop()
            for observer in observers:
                await observer.stop()
            await dht.stop()

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
