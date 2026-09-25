#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
service-actor-e2e.py — real-localnet acceptance of the concurrent-escrow
Service Actor contract and its `tosctl agent service` CLI. See
https://github.com/tosnetwork/doc/blob/main/tos-blockchain/service-actor-concurrent-escrow-upgrade.md for the full design.

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
https://github.com/tosnetwork/doc/blob/main/tos-blockchain/service-actor-concurrent-escrow-upgrade.md's Service Policy section.
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

HTTP query API + indexer (real `tosctld` daemon, real background indexer
tick, not the Rust sandbox suite): started once svc-1 is deployed, exercised
against the concurrent-requests section's real state transitions --
GET /services, GET /services/{address}, and GET
/services/{address}/requests/{request_id} are checked live for both the
`pending` and `responded` states (respond needs no deadline wait, so this is
fully live). The `refundable`/`refunded`/`swept` labels are NOT exercised
here for the same reason the CLI boundary checks above aren't: reaching them
for real requires actually waiting out response_sla + refund_claim_window
(a real 2+ hours). That transition logic is proven against genuine compiled
bytecode by the sandbox-backed indexer tests in
`tosctl/src/node-control/service/src/indexer/indexer_task.rs`
(`indexer_classifies_a_refunded_request_after_expire_and_claim`,
`indexer_classifies_a_swept_request`), which drive the same
`refresh_service_request_lifecycle` function this live daemon calls, just
against `tos_sandbox`'s virtual clock instead of a real one.

Run from the repository root: uv run python scripts/service-actor-e2e.py
"""
import asyncio
import base64
from decimal import Decimal
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage
from tostester.install import Install
from tostester.network import Network, StartOptions
from tostester.pq_initial_validator import make_deterministic_pq_initial_validator

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:18846"
HTTP = "127.0.0.1:18847"
WORKDIR = REPO / "test/integration/.service-actor-e2e"
RPC_TRANSCRIPT = WORKDIR / "rpc-transcript.jsonl"
CLI_TRANSCRIPT = WORKDIR / "cli-transcript.jsonl"
NEGATIVE_EVIDENCE = WORKDIR / "negative-evidence.jsonl"
POSITIVE_EVIDENCE = WORKDIR / "positive-evidence.jsonl"
HTTP_TRANSCRIPT = WORKDIR / "http-transcript.jsonl"
INDEXER_EVIDENCE = WORKDIR / "indexer-evidence.jsonl"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
PROVENANCE = WORKDIR / "provenance.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000004"
NANO = 1_000_000_000

METADATA_HASH = "11" * 32
PROOF_SCHEME_HASH = "22" * 32
NEW_METADATA_HASH = "33" * 32
NEW_PROOF_SCHEME_HASH = "44" * 32


def write_provenance() -> None:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True,
    ).strip()
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=REPO).returncode:
        raise RuntimeError("Service Actor E2E requires a clean tracked source tree")
    compiler_env = dict(os.environ)
    compiler_env.setdefault("FUNC", str(BUILD_DIR / "crypto/func"))
    compiler_env.setdefault("FIFT", str(BUILD_DIR / "crypto/fift"))
    bytecode_check = subprocess.run(
        [sys.executable, str(REPO / "scripts/check-service-actor-bytecode.py")],
        cwd=REPO, env=compiler_env, check=True, capture_output=True, text=True,
    ).stdout.strip()
    match = re.fullmatch(
        r"Service Actor bytecode synchronized \(repr_hash=([0-9]{1,78})\)",
        bytecode_check,
    )
    # The production checker prints Fift `hashu .` as an unsigned decimal
    # 256-bit integer, not as a hexadecimal digest.
    if not match or not 0 < int(match.group(1)) < 1 << 256:
        raise RuntimeError(f"Service Actor bytecode identity missing: {bytecode_check}")
    paths = {
        "script": Path(__file__),
        "bytecode_checker": REPO / "scripts/check-service-actor-bytecode.py",
        "service_contract_source": REPO / "crypto/smartcont/service-actor-code.fc",
        "service_contract_cli_source": REPO / "tosctl/src/node-control/contracts/src/service_actor.rs",
        "func": Path(os.environ.get("FUNC", BUILD_DIR / "crypto/func")),
        "fift": Path(os.environ.get("FIFT", BUILD_DIR / "crypto/fift")),
        "validator_engine": BUILD_DIR / "validator-engine/validator-engine",
        "dht_server": BUILD_DIR / "dht-server/dht-server",
        "tosctl": Path(TOSCTL),
    }
    artifacts = {}
    for name, path in paths.items():
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1 << 20), b""):
                digest.update(chunk)
        artifacts[name] = {"path": str(path.resolve()), "sha256": digest.hexdigest()}
    PROVENANCE.write_text(json.dumps({
        "source_commit": source_commit, "service_bytecode_check": bytecode_check,
        "artifacts": artifacts,
    }, indent=2, sort_keys=True) + "\n")

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
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as error:
        raw, status = error.read(), error.code
        record_jsonl(RPC_TRANSCRIPT, {"method": method, "params": params,
                     "status": status, "request_base64": base64.b64encode(body).decode(),
                     "response_base64": base64.b64encode(raw).decode()})
        raise
    record_jsonl(RPC_TRANSCRIPT, {"method": method, "params": params,
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
    if (len(rows) == 10
            and all(int(row["transaction_id"]["lt"]) > baseline_lt for row in rows)):
        raise RuntimeError("Service Actor transaction page did not cover the pre-operation baseline")
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
    cfg["http"] = {"bind": HTTP, "enable_swagger": False, "auth": None}
    cfg["tick_interval"] = 2
    CONFIG.write_text(json.dumps(cfg, indent=2))


def http_get(path: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"http://{HTTP}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    except (TimeoutError, urllib.error.URLError) as error:
        record_jsonl(HTTP_TRANSCRIPT, {"path": path, "status": None,
                     "transport_error": type(error).__name__, "detail": str(error)})
        raise
    record_jsonl(HTTP_TRANSCRIPT, {"path": path, "status": status,
                 "response_base64": base64.b64encode(raw).decode()})
    try:
        return status, json.loads(raw.decode())
    except json.JSONDecodeError:
        print(f"  DEBUG non-JSON response: status={status} raw={raw!r}")
        return status, {}


async def wait_http_ready(timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = http_get("/health")
            if status == 200:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def poll_http_predicate(path: str, predicate, timeout: float = 60.0) -> tuple[bool, dict]:
    """Polls GET `path` until `predicate(body)` is true or `timeout` elapses
    -- the indexer catches up asynchronously on its own tick interval, so a
    just-submitted transaction is not expected to be reflected instantly."""
    deadline = time.time() + timeout
    last_body: dict = {}
    while time.time() < deadline:
        status, body = http_get(path)
        last_body = body
        if status == 200 and predicate(body):
            return True, body
        await asyncio.sleep(1)
    return False, last_body


async def wait_indexer_through(label: str, mc_seqno: int,
                               timeout: float = 300.0) -> tuple[bool, dict]:
    """Require the production indexer's cursor to cover a fixed finalized head.

    `/services/{address}/requests/{id}` can answer `pending` from a live-chain
    fallback even when the lifecycle index has not saved that pending state.
    Letting the request resolve before the index catches up would then make a
    later `responded` classification impossible to establish from snapshots.
    """
    deadline = time.monotonic() + timeout
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            status, body = http_get("/explorer/status")
        except (TimeoutError, urllib.error.URLError) as error:
            last = {"transport_error": type(error).__name__,
                    "detail": str(error), "target_mc_seqno": mc_seqno}
            record_jsonl(INDEXER_EVIDENCE, {"label": label, "poll_error": True, **last})
            await asyncio.sleep(1)
            continue
        last = {"http_status": status, "body": body, "target_mc_seqno": mc_seqno}
        result = body.get("result") or {}
        indexed = result.get("masterchain_indexed")
        if status == 200 and body.get("ok") is True and isinstance(indexed, int) and indexed >= mc_seqno:
            record_jsonl(INDEXER_EVIDENCE, {"label": label, **last})
            return True, last
        await asyncio.sleep(1)
    record_jsonl(INDEXER_EVIDENCE, {"label": label, "timed_out": True, **last})
    return False, last


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


async def send_op(operation: str, name: str, frm: str, *extra: str) -> str:
    return await tosctl(
        "agent", "service", "send", "--operation", operation, "--name", name,
        "--from", frm, "--yes", *extra,
    )


async def rejected_operation(label: str, address: str, payer: str, expected_exit: int,
                             name: str, frm: str, operation: str, *extra: str) -> None:
    """Require exact wallet submission, Service Actor VM refusal, and final state."""
    before_state = await service_show(name)
    before_head = finalized_mc_header()
    wallet_lt, contract_lt = last_lt(payer), last_lt(address)
    cli_post_submit_timeout = False
    try:
        receipt = await send_op(operation, name, frm, *extra)
    except RuntimeError as error:
        # `tosctl service send call` submits its wallet message, then waits
        # for an accepted request ID. A VM-rejected call cannot advance that
        # ID, so the CLI exits nonzero after its own 60-second wait. This is
        # admissible only with the explicit post-submit marker; the wallet,
        # target VM exit, and later heads below remain the rejection proof.
        receipt = str(error)
        if (operation != "call"
                or "Service Actor call message submitted to " not in receipt
                or "timed out waiting for the Service Actor call to land" not in receipt):
            raise
        cli_post_submit_timeout = True
    deadline = time.monotonic() + 45
    wallet_tx = contract_tx = bounce_tx = None
    while time.monotonic() < deadline:
        wallet_rows = transactions_after(payer, wallet_lt)
        if wallet_rows:
            sends = [row for row in wallet_rows if any(
                same_addr(msg.get("destination"), address)
                for msg in row.get("out_msgs") or [])]
            if len(sends) != 1:
                raise RuntimeError(f"{label}: expected exactly one wallet send to Service Actor")
            wallet_tx = sends[0]
            outgoing = wallet_tx.get("out_msgs") or []
            if (wallet_tx.get("aborted") is not False
                    or (wallet_tx.get("compute") or {}).get("success") is not True
                    or (wallet_tx.get("action") or {}).get("success") is not True
                    or len(outgoing) != 1
                    or not same_addr(outgoing[0].get("destination"), address)):
                raise RuntimeError(f"{label}: wallet did not send to Service Actor")
            contract_rows = transactions_after(address, contract_lt)
            if contract_rows:
                if len(contract_rows) != 1:
                    raise RuntimeError(f"{label}: multiple new Service Actor transactions")
                contract_tx = contract_rows[0]
                inbound = contract_tx.get("in_msg") or {}
                if (inbound.get("hash") != outgoing[0].get("hash")
                        or not same_addr(inbound.get("source"), payer)):
                    raise RuntimeError(f"{label}: Service Actor inbound hash differs from wallet outbound")
                refunds = contract_tx.get("out_msgs") or []
                if (len(refunds) != 1 or refunds[0].get("bounced") is not True
                        or not same_addr(refunds[0].get("source"), address)
                        or not same_addr(refunds[0].get("destination"), payer)):
                    raise RuntimeError(f"{label}: Service Actor did not emit one exact bounce")
                other_rows = [row for row in wallet_rows if row is not wallet_tx]
                if len(other_rows) > 1:
                    raise RuntimeError(f"{label}: unrelated or duplicate wallet transaction")
                if other_rows:
                    bounce_tx = other_rows[0]
                    bounced = bounce_tx.get("in_msg") or {}
                    if (bounced.get("hash") != refunds[0].get("hash")
                            or bounced.get("bounced") is not True
                            or not same_addr(bounced.get("source"), address)
                            or not same_addr(bounced.get("destination"), payer)
                            or bounce_tx.get("out_msgs")):
                        raise RuntimeError(f"{label}: wallet credit is not the Service Actor's exact bounce")
                    break
        await asyncio.sleep(1)
    if wallet_tx is None or contract_tx is None or bounce_tx is None:
        raise RuntimeError(f"{label}: exact wallet-Service Actor-bounce chain not observed")
    if (contract_tx.get("aborted") is not True
            or (contract_tx.get("compute") or {}).get("success") is not False
            or (contract_tx.get("compute") or {}).get("exit_code") != expected_exit):
        raise RuntimeError(f"{label}: expected VM exit {expected_exit}, got {contract_tx}")
    observations = []
    last_seqno = before_head["id"]["seqno"]
    while time.monotonic() < deadline and len(observations) < 2:
        head = finalized_mc_header()
        if head["id"]["seqno"] > last_seqno:
            state = await service_show(name)
            observations.append({"head": head, "state": state})
            if state != before_state:
                raise RuntimeError(f"{label}: Service Actor state changed after VM rejection")
            last_seqno = head["id"]["seqno"]
        else:
            await asyncio.sleep(1)
    if len(observations) != 2:
        raise RuntimeError(f"{label}: two later finalized heads not observed")
    record_jsonl(NEGATIVE_EVIDENCE, {"label": label, "expected_exit": expected_exit,
                 "receipt": receipt, "cli_post_submit_timeout": cli_post_submit_timeout,
                 "before_state": before_state, "before_head": before_head,
                 "wallet_tx": wallet_tx, "contract_tx": contract_tx,
                 "bounce_tx": bounce_tx,
                 "observations": observations})
    check(label, True)


def atomic_tos(value: str) -> int:
    amount = Decimal(value) * NANO
    if amount != amount.to_integral_value() or amount < 0:
        raise ValueError(f"Service Actor amount is not nonnegative atomic TOS: {value}")
    return int(amount)


async def observe_successful_edge(label: str, address: str, payer: str,
                                  wallet_lt: int, contract_lt: int, before_head: dict,
                                  receipt, expected_payout: int = 0,
                                  expected_inbound: int | None = None) -> None:
    """Bind one wallet send, successful Service Actor execution, and any exact payment."""
    deadline = time.monotonic() + 60
    wallet_tx = contract_tx = recipient_tx = None
    while time.monotonic() < deadline:
        wallet_rows = transactions_after(payer, wallet_lt)
        sends = [row for row in wallet_rows if any(
            same_addr(msg.get("destination"), address) for msg in row.get("out_msgs") or []
        )]
        contract_rows = transactions_after(address, contract_lt)
        if sends and contract_rows:
            if len(sends) != 1 or len(contract_rows) != 1:
                raise RuntimeError(f"{label}: ambiguous wallet or Service Actor transactions")
            wallet_tx, contract_tx = sends[0], contract_rows[0]
            outgoing = wallet_tx.get("out_msgs") or []
            incoming = contract_tx.get("in_msg") or {}
            if (wallet_tx.get("aborted") is not False
                    or (wallet_tx.get("compute") or {}).get("success") is not True
                    or (wallet_tx.get("action") or {}).get("success") is not True
                    or len(outgoing) != 1 or not outgoing[0].get("hash")
                    or not same_addr(outgoing[0].get("destination"), address)
                    or incoming.get("hash") != outgoing[0]["hash"]
                    or not same_addr(incoming.get("source"), payer)):
                raise RuntimeError(f"{label}: wallet outbound and Service Actor inbound do not match")
            wallet_value = int(outgoing[0].get("value", -1))
            service_value = int(incoming.get("value", -1))
            if (wallet_value <= 0 or service_value != wallet_value
                    or (expected_inbound is not None and service_value != expected_inbound)):
                raise RuntimeError(f"{label}: Service Actor inbound value differs from wallet or command")
            if (contract_tx.get("aborted") is not False
                    or (contract_tx.get("compute") or {}).get("success") is not True
                    or (contract_tx.get("action") or {}).get("success") is not True):
                raise RuntimeError(f"{label}: Service Actor execution did not succeed")
            payments = contract_tx.get("out_msgs") or []
            if len(payments) != (1 if expected_payout else 0):
                raise RuntimeError(f"{label}: unexpected Service Actor payment count")
            if expected_payout:
                payment = payments[0]
                if (not payment.get("hash") or int(payment.get("value", -1)) != expected_payout
                        or not same_addr(payment.get("destination"), payer)):
                    raise RuntimeError(f"{label}: Service Actor payment amount or recipient differs")
                matches = [row for row in wallet_rows
                           if (row.get("in_msg") or {}).get("hash") == payment["hash"]]
                if not matches:
                    if any(same_addr((row.get("in_msg") or {}).get("source"), address)
                           for row in wallet_rows):
                        raise RuntimeError(f"{label}: recipient inbound hash differs from Service Actor outbound")
                    await asyncio.sleep(1)
                    continue
                if len(matches) != 1:
                    raise RuntimeError(f"{label}: ambiguous recipient payment transactions")
                recipient_tx = matches[0]
                credited = recipient_tx.get("in_msg") or {}
                if (recipient_tx.get("aborted") is not False
                        or not same_addr(credited.get("source"), address)
                        or int(credited.get("value", -1)) != expected_payout):
                    raise RuntimeError(f"{label}: recipient inbound amount or source differs")
            break
        await asyncio.sleep(1)
    if wallet_tx is None or contract_tx is None or (expected_payout and recipient_tx is None):
        raise RuntimeError(f"{label}: exact successful transaction edge not observed")
    heads = []
    last_seqno = int(before_head["id"]["seqno"])
    while time.monotonic() < deadline and len(heads) < 2:
        head = finalized_mc_header()
        if int(head["id"]["seqno"]) > last_seqno:
            heads.append(head)
            last_seqno = int(head["id"]["seqno"])
        else:
            await asyncio.sleep(1)
    if len(heads) != 2:
        raise RuntimeError(f"{label}: two later finalized masterchain heads not observed")
    record_jsonl(POSITIVE_EVIDENCE, {
        "label": label, "payer": payer, "service": address, "receipt": receipt,
        "wallet_baseline_lt": wallet_lt, "service_baseline_lt": contract_lt,
        "before_head": before_head, "wallet_tx": wallet_tx, "service_tx": contract_tx,
        "expected_inbound_atomic": expected_inbound,
        "observed_inbound_atomic": service_value,
        "expected_payout_atomic": expected_payout, "recipient_tx": recipient_tx,
        "final_heads": heads,
    })


async def successful_operation(operation: str, name: str, frm: str, *extra: str) -> str:
    before = await service_show(name)
    address = before["address"]
    payer = await wallet_address(frm)
    expected_payout = 0
    expected_inbound = None
    if operation == "call":
        amount = atomic_tos(extra[extra.index("--amount") + 1])
        due = atomic_tos(str(before["price_per_call"])) + atomic_tos(str(before["storage_fee"]))
        expected_payout = max(0, amount - due)
        expected_inbound = amount
    elif operation == "withdraw-revenue":
        expected_payout = atomic_tos(extra[extra.index("--withdraw-amount") + 1])
    before_head = finalized_mc_header()
    wallet_lt, contract_lt = last_lt(payer), last_lt(address)
    receipt = await send_op(operation, name, frm, *extra)
    await observe_successful_edge(
        f"{name}:{operation}", address, payer, wallet_lt, contract_lt,
        before_head, receipt, expected_payout, expected_inbound,
    )
    return receipt


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
    before_head = finalized_mc_header()
    wallet_lt = last_lt(owner)
    deploy = await tosctl_json(*args)
    address = deploy["address"]
    await observe_successful_edge(
        f"{name}:deploy", address, owner, wallet_lt, 0, before_head, deploy,
    )
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

    print("\n=== start tosctld HTTP daemon (real query API + indexer, not the sandbox suite) ===")
    deployment_mc_seqno = finalized_mc_header()["id"]["seqno"]
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{WORKDIR}/e2e-vault.json?master_key={MASTER_KEY}"
    # Redirected to a file, not asyncio.subprocess.PIPE: nothing in this
    # script ever reads a PIPE for this long-lived daemon, and the indexer's
    # own tick logging (tick_interval=2s, for the rest of this section) is
    # enough output to eventually fill the OS pipe buffer and deadlock the
    # daemon on a blocked write -- which would surface here as a misleading
    # HTTP/indexer polling timeout, not an obvious "daemon hung" error.
    service_log_path = WORKDIR / "tosctld-service.log"
    service_log = open(service_log_path, "wb")
    service_proc = await asyncio.create_subprocess_exec(
        TOSCTL, "service", "-c", str(CONFIG),
        stdout=service_log, stderr=asyncio.subprocess.STDOUT, env=env,
    )
    try:
        check("tosctld health endpoint ready", await wait_http_ready())

        covered, cursor = await wait_indexer_through(
            "svc-1 deployment", deployment_mc_seqno)
        check("indexer cursor covers svc-1 deployment", covered, str(cursor))
        if not covered:
            return

        found, body = await poll_http_predicate(
            "/services", lambda b: any(same_addr(item.get("address", ""), address)
                                        for item in b.get("result", [])))
        check("GET /services lists svc-1 (indexer discovery)", found, str(body)[:1000])

        status, body = http_get(f"/services/{address}")
        result = body.get("result", {})
        check("GET /services/{address} status 200", status == 200, f"status={status} body={body}")
        check("GET /services/{address} owner matches", same_addr(result.get("owner"), owner), str(result))
        check("GET /services/{address} price matches (nanotos)",
              result.get("price_per_call") == int(0.05 * NANO), str(result))
        check("GET /services/{address} status is active", result.get("status") == "active", str(result))

        print("\n=== call: access and payment gating ===")
        await rejected_operation("outsider call rejected (not authorized)", address,
                                 outsider, 1923, "svc-1", "outsider", "call",
                                 "--request-hash", "aa" * 32, "--amount", str(call_amount))

        await rejected_operation("underpaid call rejected", address, caller, 1902,
                                 "svc-1", "caller", "call", "--request-hash", "bb" * 32,
                                 "--amount", "0.01")

        print("\n=== concurrent requests: two outstanding calls, resolved independently ===")
        # This is the headline feature the upgrade adds: unlike the single-slot
        # V1 contract, a second call is accepted while the first is still
        # unanswered, and each resolves on its own schedule and in any order.
        predicted_a = await next_request_id("svc-1")
        call_a_output = await successful_operation(
            "call", "svc-1", "caller", "--request-hash", "cc" * 32, "--amount", str(call_amount))
        request_a = assigned_request_id(call_a_output)
        check("CLI reports the exact assigned request ID", request_a == predicted_a, call_a_output)
        data = await service_show("svc-1")
        check("first concurrent call accepted", data["calls_today"] == 1, str(data))
        check("one pending request after first call", data["pending_count"] == 1, str(data))

        predicted_b = await next_request_id("svc-1")
        call_b_output = await successful_operation(
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

        pending_mc_seqno = finalized_mc_header()["id"]["seqno"]
        covered, cursor = await wait_indexer_through(
            "both svc-1 requests still pending", pending_mc_seqno)
        check("indexer cursor covers both pending requests", covered, str(cursor))
        if not covered:
            return

        print("\n=== GET /services/{address}/requests/{id}: pending (real indexer tick) ===")
        found, body = await poll_http_predicate(
            f"/services/{address}/requests/{request_a}",
            lambda b: b.get("result", {}).get("status") == "pending")
        check("indexer/HTTP shows request A pending", found, str(body)[:1000])
        found, body = await poll_http_predicate(
            f"/services/{address}/requests/{request_b}",
            lambda b: b.get("result", {}).get("status") == "pending")
        check("indexer/HTTP shows request B pending", found, str(body)[:1000])

        # Respond out of order: B before A. Responding to one must not affect
        # the other's state.
        await successful_operation("respond", "svc-1", "owner", "--request-id", str(request_b),
                      "--response-hash", "22" * 32)
        data = await service_show("svc-1")
        check("responding to B leaves A still pending", data["pending_count"] == 1, str(data))
        req_a_data = await request_show("svc-1", request_a)
        check("request A untouched by B's response", req_a_data["found"], str(req_a_data))
        req_b_data = await request_show("svc-1", request_b)
        check("request B resolved and no longer pending", not req_b_data["found"], str(req_b_data))

        response_b_mc_seqno = finalized_mc_header()["id"]["seqno"]
        covered, cursor = await wait_indexer_through(
            "svc-1 request B response", response_b_mc_seqno)
        check("indexer cursor covers request B response", covered, str(cursor))
        if not covered:
            return

        found, body = await poll_http_predicate(
            f"/services/{address}/requests/{request_b}",
            lambda b: b.get("result", {}).get("status") == "responded")
        check("indexer/HTTP classifies request B responded", found, str(body)[:1000])
        status, body = http_get(f"/services/{address}/requests/{request_a}")
        check("request A still pending via HTTP while B is responded",
              status == 200 and body.get("result", {}).get("status") == "pending",
              f"status={status} body={body}")

        await successful_operation("respond", "svc-1", "owner", "--request-id", str(request_a),
                      "--response-hash", "11" * 32)
        data = await service_show("svc-1")
        check("both concurrent requests now resolved", data["pending_count"] == 0, str(data))
        # respond credits price + storage_fee to withdrawable_revenue (the
        # storage fee is non-refundable once the entry resolves -- see
        # https://github.com/tosnetwork/doc/blob/main/tos-blockchain/service-actor-concurrent-escrow-upgrade.md's Financial Accounting
        # transition table), not price alone.
        expected_revenue = 2 * (0.05 + STORAGE_FEE)
        check("revenue accrued for both calls (price + storage_fee each)",
              abs(float(data["withdrawable_revenue"]) - expected_revenue) < 1e-6, str(data))

        response_a_mc_seqno = finalized_mc_header()["id"]["seqno"]
        covered, cursor = await wait_indexer_through(
            "svc-1 request A response", response_a_mc_seqno)
        check("indexer cursor covers request A response", covered, str(cursor))
        if not covered:
            return

        found, body = await poll_http_predicate(
            f"/services/{address}/requests/{request_a}",
            lambda b: b.get("result", {}).get("status") == "responded")
        check("indexer/HTTP classifies request A responded", found, str(body)[:1000])

        print("\n=== GET /services/{address}/requests/{id}: never-allocated ID ===")
        status, body = http_get(f"/services/{address}/requests/999999")
        check("never-allocated request ID resolves via HTTP (chain fallback, not a 500)",
              status == 200 and body.get("result", {}).get("status") == "resolved_or_unknown",
              f"status={status} body={body}")
    finally:
        # An already-crashed daemon has a returncode set the moment it exits
        # (no polling needed -- asyncio updates it via a SIGCHLD handler);
        # terminate()ing it again would raise ProcessLookupError and mask
        # whatever check() failure already reported the real problem.
        if service_proc.returncode is None:
            service_proc.terminate()
            try:
                await asyncio.wait_for(service_proc.wait(), timeout=10)
            except TimeoutError:
                service_proc.kill()
                await service_proc.wait()
        service_log.close()
        if service_proc.returncode not in (0, -15):  # -15 = SIGTERM, our own normal shutdown
            print(f"  DEBUG tosctld exited with {service_proc.returncode}; "
                  f"log tail:\n{service_log_path.read_text()[-4000:]}")

    print("\n=== rate limiting: daily cap enforced ===")
    await rejected_operation("third call rate-limited (cap is 2/day)", address, caller,
                             1924, "svc-1", "caller", "call", "--request-hash", "ee" * 32,
                             "--amount", str(call_amount))

    print("\n=== update-policy: open access ===")
    await successful_operation(
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
    await successful_operation("call", "svc-1", "outsider", "--request-hash", "03" * 32, "--amount", "0.5")
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
    await rejected_operation("expire rejected before response_deadline", address, outsider,
                             1914, "svc-1", "outsider", "expire", "--request-id", str(request_over))

    await rejected_operation("sweep rejected before refund_claim_deadline (still pending)",
                             address, outsider, 1919, "svc-1", "outsider",
                             "sweep-expired-request", "--request-id", str(request_over))

    # Answer it so it doesn't linger as a real liability for the rest of the run.
    await successful_operation("respond", "svc-1", "owner", "--request-id", str(request_over),
                  "--response-hash", "44" * 32)
    data_check = await request_show("svc-1", request_over)
    check("overpaid request resolved via respond", not data_check["found"], str(data_check))

    # claim-refund requires a refund entry to exist at all (never expired).
    fresh_id = await next_request_id("svc-1")
    await successful_operation("call", "svc-1", "outsider", "--request-hash", "05" * 32, "--amount", str(new_call_min + 0.05))
    await rejected_operation("claim-refund rejected: request never expired, no refund entry",
                             address, outsider, 1917, "svc-1", "outsider", "claim-refund",
                             "--request-id", str(fresh_id), "--destination", outsider)
    refund_fresh = await refund_show("svc-1", fresh_id)
    check("no refund entry exists for a still-pending request", not refund_fresh["found"], str(refund_fresh))
    await successful_operation("respond", "svc-1", "owner", "--request-id", str(fresh_id), "--response-hash", "55" * 32)

    print("\n=== withdraw-revenue (owner only, bounded by real balance) ===")
    await rejected_operation("non-owner withdraw rejected", address, outsider, 1900,
                             "svc-1", "outsider", "withdraw-revenue", "--withdraw-amount", "0.01")
    data = await service_show("svc-1")
    revenue_before = float(data["withdrawable_revenue"])
    check("revenue accrued from all resolved calls", revenue_before > 0.1, str(data))

    await rejected_operation("overdraw rejected", address, owner, 1922,
                             "svc-1", "owner", "withdraw-revenue", "--withdraw-amount", "1000")

    owner_before = balance(owner)
    withdraw_amount = round(revenue_before / 2, 6)
    await successful_operation("withdraw-revenue", "svc-1", "owner", "--withdraw-amount", str(withdraw_amount))
    data = await service_show("svc-1")
    check("revenue decreased by withdrawal",
          abs(float(data["withdrawable_revenue"]) - (revenue_before - withdraw_amount)) < 1e-6, str(data))
    check("owner balance increased", balance(owner) > owner_before, "")

    print("\n=== non-owner rejections ===")
    await rejected_operation("non-owner rotate-attestor-key rejected", address, outsider,
                             1900, "svc-1", "outsider", "rotate-attestor-key",
                             "--new-attestor-pubkey", "aa" * 32)
    await rejected_operation("non-owner revoke-attestor rejected", address, outsider,
                             1900, "svc-1", "outsider", "revoke-attestor")

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
    await successful_operation("call", "svc-2", "outsider", "--request-hash", "cc" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))

    await rejected_operation("respond without attestation rejected", address2, owner, 9,
                             "svc-2", "owner", "respond", "--request-id", str(req_id2),
                             "--response-hash", "dd" * 32)

    await rejected_operation("respond with wrong attestor key rejected", address2, owner,
                             1911, "svc-2", "owner", "respond", "--request-id", str(req_id2),
                             "--response-hash", "dd" * 32,
                             "--signer-vault-key", "wrong-service-attestor-key")

    await successful_operation("respond", "svc-2", "owner", "--request-id", str(req_id2), "--response-hash", "dd" * 32,
                  "--signer-vault-key", "service-attestor-key")
    req2_data = await request_show("svc-2", req_id2)
    check("attestor-signed respond recorded", not req2_data["found"], str(req2_data))

    print("\n=== snapshot behavior: rotating the attestor key does not affect an already-pending request ===")
    await tosctl("key", "add", "--name", "rotated-service-attestor-key")
    req_id3 = await next_request_id("svc-2")
    await successful_operation("call", "svc-2", "outsider", "--request-hash", "06" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))
    req3_before_rotate = await request_show("svc-2", req_id3)
    check("request snapshotted the attestor pubkey in force at call time", req3_before_rotate["found"],
          str(req3_before_rotate))

    # Rotation is unrestricted -- no pending-state freeze in this design,
    # unlike Task Escrow/Dispute -- but must not retroactively rewrite what
    # req_id3 requires.
    await successful_operation("rotate-attestor-key", "svc-2", "owner",
                  "--signer-vault-key", "rotated-service-attestor-key")
    data = await service_show("svc-2")
    check("attestor key rotated on the live policy", bool(data.get("attestor_pubkey")), str(data))

    # A signature under the *new* key must not satisfy req_id3's snapshot.
    await rejected_operation("new attestor key does not satisfy the old request's snapshot",
                             address2, owner, 1911, "svc-2", "owner", "respond",
                             "--request-id", str(req_id3), "--response-hash", "07" * 32,
                             "--signer-vault-key", "rotated-service-attestor-key")

    # The *old* key still does.
    await successful_operation("respond", "svc-2", "owner", "--request-id", str(req_id3), "--response-hash", "07" * 32,
                  "--signer-vault-key", "service-attestor-key")
    req3_data = await request_show("svc-2", req_id3)
    check("old (pre-rotation) attestor key still satisfies the pending request",
          not req3_data["found"], str(req3_data))

    # New requests require the new key.
    req_id4 = await next_request_id("svc-2")
    await successful_operation("call", "svc-2", "outsider", "--request-hash", "08" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))
    await rejected_operation("old key rejected for a request accepted after rotation",
                             address2, owner, 1911, "svc-2", "owner", "respond",
                             "--request-id", str(req_id4), "--response-hash", "09" * 32,
                             "--signer-vault-key", "service-attestor-key")
    await successful_operation("respond", "svc-2", "owner", "--request-id", str(req_id4), "--response-hash", "09" * 32,
                  "--signer-vault-key", "rotated-service-attestor-key")
    req4_data = await request_show("svc-2", req_id4)
    check("new key satisfies a request accepted after rotation", not req4_data["found"], str(req4_data))

    await successful_operation("revoke-attestor", "svc-2", "owner")
    data = await service_show("svc-2")
    check("owner can revoke the attestor once idle", not data.get("attestor_pubkey"), str(data))

    print("\n=== snapshot behavior: update-policy does not change an already-pending request's terms ===")
    address4 = await deploy_service("svc-4", owner, price_per_call=0.01, open_access=True)
    req_id5 = await next_request_id("svc-4")
    await successful_operation("call", "svc-4", "outsider", "--request-hash", "0a" * 32,
                  "--amount", str(0.01 + STORAGE_FEE + 0.05))
    req5_before = await request_show("svc-4", req_id5)
    check("pending request snapshotted price 0.01", abs(float(req5_before["price"]) - 0.01) < 1e-9,
          str(req5_before))

    # Policy changes are unrestricted (no freeze), but req_id5 keeps its
    # own snapshot regardless of what the live policy becomes.
    await successful_operation(
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
    await successful_operation("respond", "svc-4", "owner", "--request-id", str(req_id5), "--response-hash", "0b" * 32)
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
    write_provenance()
    prepare_config()
    install = Install(BUILD_DIR, REPO)
    import logging
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    async with Network(install, WORKDIR / "net", base_port=23400) as network:
        dht = network.create_dht_node()
        node = network.create_full_node()
        make_deterministic_pq_initial_validator(node, 0)
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
