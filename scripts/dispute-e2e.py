#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
dispute-e2e.py — real-localnet acceptance of the Dispute contract and its
`tosctl agent dispute` CLI.

Boots a single-process local TOS chain (same machinery as
agent-task-escrow-e2e.py), provisions a file vault plus a tosctl config,
creates and funds claimant/respondent/reviewer/outsider wallets, then drives
the full lifecycle through the real `tosctl agent dispute` CLI against the
running validator:

  deploy dispute-1 (claimant funds it) -> local record persisted -> on-chain
    state matches
  send submit-respondent-evidence (outsider) -> rejected (not respondent)
  send submit-respondent-evidence (respondent) -> accepted, status advances
  send rule (outsider) -> rejected (not reviewer)
  send rule (reviewer, ruling=claimant) -> resolved
  send submit-respondent-evidence again -> rejected (already resolved)

  deploy dispute-2 -> send rule (reviewer, ruling=split, split-bps=6500)
    -> split_bps recorded correctly

Exit code 0 iff every check passes.

Run from the repository root: uv run python scripts/dispute-e2e.py
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
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:18946"
WORKDIR = REPO / "test/integration/.dispute-e2e"
RPC_TRANSCRIPT = WORKDIR / "rpc-transcript.jsonl"
CLI_TRANSCRIPT = WORKDIR / "cli-transcript.jsonl"
NEGATIVE_EVIDENCE = WORKDIR / "negative-evidence.jsonl"
MANIFEST = WORKDIR / "manifest.json"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000005"
NANO = 1_000_000_000

SUBJECT_HASH = "11" * 32
CLAIMANT_EVIDENCE_HASH = "22" * 32
RESPONDENT_EVIDENCE_HASH = "33" * 32
RULING_HASH = "44" * 32

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
        "test_sha256": hashlib.sha256(
            (REPO / "test/pq-native/test_e12_dispute_negative_finality.py").read_bytes()
        ).hexdigest(),
        "binaries": {
            name: {"path": str(path.resolve()),
                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for name, path in binaries.items()
        },
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if source_dirty:
        raise RuntimeError("E12 real-chain run requires a clean tracked source tree")


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
        raise RuntimeError("dispute transaction page did not cover the pre-operation baseline")
    return [row for row in rows if int(row["transaction_id"]["lt"]) > baseline_lt]


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
            if int(rpc_call("getAddressInformation", address=addr)["result"]["balance"]) >= target:
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


async def dispute_show(name: str):
    return await tosctl_json("agent", "dispute", "show", "--name", name)


async def send_op(operation: str, name: str, frm: str, *extra: str) -> str:
    return await tosctl(
        "agent", "dispute", "send", "--operation", operation, "--name", name,
        "--from", frm, "--yes", *extra,
    )


async def rejected_operation(label: str, address: str, payer: str, expected_exit: int,
                             operation: str, name: str, frm: str, *extra: str) -> None:
    """Require wallet submission, the exact Dispute VM error, and finalized unchanged state."""
    before_state = await dispute_show(name)
    before_head = finalized_mc_header()
    wallet_lt = last_lt(payer)
    contract_lt = last_lt(address)
    receipt = await send_op(operation, name, frm, *extra)
    deadline = time.monotonic() + 45
    wallet_tx = contract_tx = bounce_tx = None
    while time.monotonic() < deadline:
        wallet_rows = transactions_after(payer, wallet_lt)
        if wallet_rows:
            sends = [row for row in wallet_rows if any(
                same_addr(msg.get("destination"), address)
                for msg in row.get("out_msgs") or [])]
            if len(sends) != 1:
                raise RuntimeError(f"{label}: expected exactly one wallet send to dispute")
            wallet_tx = sends[0]
            outgoing = wallet_tx.get("out_msgs") or []
            if (wallet_tx.get("aborted") is not False
                    or wallet_tx.get("compute", {}).get("success") is not True
                    or wallet_tx.get("action", {}).get("success") is not True
                    or len(outgoing) != 1
                    or not same_addr(outgoing[0].get("destination"), address)):
                raise RuntimeError(f"{label}: wallet transaction did not send to dispute")
            contract_rows = transactions_after(address, contract_lt)
            if contract_rows:
                if len(contract_rows) != 1:
                    raise RuntimeError(f"{label}: multiple new dispute transactions")
                contract_tx = contract_rows[0]
                inbound = contract_tx.get("in_msg") or {}
                if (inbound.get("hash") != outgoing[0].get("hash")
                        or not same_addr(inbound.get("source"), payer)):
                    raise RuntimeError(f"{label}: dispute inbound hash differs from wallet outbound")
                refunds = contract_tx.get("out_msgs") or []
                if (len(refunds) != 1 or refunds[0].get("bounced") is not True
                        or not same_addr(refunds[0].get("source"), address)
                        or not same_addr(refunds[0].get("destination"), payer)):
                    raise RuntimeError(f"{label}: dispute did not emit one exact bounce")
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
                        raise RuntimeError(f"{label}: wallet credit is not the dispute's exact bounce")
                    break
        await asyncio.sleep(1)
    if contract_tx is None or wallet_tx is None or bounce_tx is None:
        raise RuntimeError(f"{label}: exact wallet-dispute-bounce chain not observed")
    compute = contract_tx.get("compute") or {}
    if (contract_tx.get("aborted") is not True
            or compute.get("success") is not False
            or compute.get("exit_code") != expected_exit):
        raise RuntimeError(f"{label}: expected VM exit {expected_exit}, got {contract_tx}")

    observations = []
    last_seqno = before_head["id"]["seqno"]
    while time.monotonic() < deadline and len(observations) < 2:
        head = finalized_mc_header()
        if head["id"]["seqno"] > last_seqno:
            state = await dispute_show(name)
            observations.append({"head": head, "state": state})
            if state != before_state:
                raise RuntimeError(f"{label}: dispute state changed after rejected transaction")
            last_seqno = head["id"]["seqno"]
        else:
            await asyncio.sleep(1)
    if len(observations) != 2:
        raise RuntimeError(f"{label}: finalized masterchain did not advance twice")
    record_jsonl(NEGATIVE_EVIDENCE, {"label": label, "expected_exit": expected_exit,
                 "cli_receipt": receipt, "before_state": before_state,
                 "before_head": before_head, "wallet_transaction": wallet_tx,
                 "dispute_transaction": contract_tx, "bounce_transaction": bounce_tx,
                 "observations": observations})
    check(label, True)


async def wait_dispute_state(name: str, predicate, timeout: float = 45.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = await dispute_show(name)
        if predicate(state):
            return state
        await asyncio.sleep(1)
    raise RuntimeError(f"{name}: expected positive state not observed within {timeout}s")


async def run_checks(faucet) -> None:
    print("\n=== provision: tosctl wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    for name in ("claimant", "respondent", "reviewer", "outsider"):
        await tosctl("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    claimant = await wallet_address("claimant")
    respondent = await wallet_address("respondent")
    reviewer = await wallet_address("reviewer")
    outsider = await wallet_address("outsider")
    print(f"  claimant:   {claimant}\n  respondent: {respondent}\n"
          f"  reviewer:   {reviewer}\n  outsider:   {outsider}")

    for name, addr in (
        ("claimant", claimant), ("respondent", respondent),
        ("reviewer", reviewer), ("outsider", outsider),
    ):
        await faucet.send(faucet_transfer(faucet, addr, 50))
        check(f"{name} funded", await wait_balance_at_least(addr, 49 * NANO))
    for name in ("claimant", "respondent", "reviewer", "outsider"):
        await tosctl("wallet", "activate", "-n", name)
    for name, addr in (
        ("claimant", claimant), ("respondent", respondent),
        ("reviewer", reviewer), ("outsider", outsider),
    ):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{name} wallet active", bool(active))

    deadline = int(time.time()) + 3600

    print("\n=== deploy: Dispute case (claimant ruling) ===")
    deploy = await tosctl_json(
        "agent", "dispute", "deploy", "--name", "case-1",
        "--claimant", claimant, "--respondent", respondent, "--reviewer", reviewer,
        "--deadline", str(deadline),
        "--subject-hash", SUBJECT_HASH, "--claimant-evidence-hash", CLAIMANT_EVIDENCE_HASH,
        "--from", "claimant", "--amount", "0.1", "-w", "0", "--yes",
    )
    address = deploy["address"]
    print(f"  dispute: {address}")
    check("deployed and active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address).get("result") == "active"))

    data = await dispute_show("case-1")
    check("claimant recorded on-chain", same_addr(data["claimant"], claimant), str(data))
    check("respondent recorded on-chain", same_addr(data["respondent"], respondent), str(data))
    check("reviewer recorded on-chain", same_addr(data["reviewer"], reviewer), str(data))
    check("status starts open", data["status"] == "open", str(data))
    check("ruling starts none", data["ruling"] == "none", str(data))
    check("subject hash recorded", data["subject_hash"] == SUBJECT_HASH, str(data))

    print("\n=== submit-respondent-evidence ===")
    await rejected_operation("outsider submit rejected", address, outsider, 2000,
                             "submit-respondent-evidence", "case-1", "outsider",
                             "--respondent-evidence-hash", RESPONDENT_EVIDENCE_HASH)

    await send_op("submit-respondent-evidence", "case-1", "respondent",
                  "--respondent-evidence-hash", RESPONDENT_EVIDENCE_HASH)
    data = await wait_dispute_state("case-1", lambda d: d["status"] == "evidence_submitted")
    check("respondent evidence recorded", data["status"] == "evidence_submitted", str(data))
    check("respondent evidence hash matches",
          data["respondent_evidence_hash"] == RESPONDENT_EVIDENCE_HASH, str(data))

    print("\n=== rule (claimant wins) ===")
    await rejected_operation("outsider rule rejected", address, outsider, 2001,
                             "rule", "case-1", "outsider", "--ruling", "claimant",
                             "--ruling-hash", RULING_HASH)

    await send_op("rule", "case-1", "reviewer", "--ruling", "claimant", "--ruling-hash", RULING_HASH)
    data = await wait_dispute_state("case-1", lambda d: d["status"] == "resolved")
    check("resolved with claimant ruling", data["status"] == "resolved", str(data))
    check("ruling is claimant", data["ruling"] == "claimant", str(data))
    check("ruling hash recorded", data["ruling_hash"] == RULING_HASH, str(data))

    print("\n=== already-resolved rejection ===")
    await rejected_operation("action after resolution rejected", address, respondent, 2002,
                             "submit-respondent-evidence", "case-1", "respondent",
                             "--respondent-evidence-hash", "55" * 32)

    print("\n=== deploy: Dispute case (split ruling) ===")
    deploy2 = await tosctl_json(
        "agent", "dispute", "deploy", "--name", "case-2",
        "--claimant", claimant, "--respondent", respondent, "--reviewer", reviewer,
        "--deadline", str(deadline + 10),
        "--subject-hash", SUBJECT_HASH, "--claimant-evidence-hash", CLAIMANT_EVIDENCE_HASH,
        "--from", "claimant", "--amount", "0.1", "-w", "0", "--yes",
    )
    address2 = deploy2["address"]
    check("second dispute deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address2).get("result") == "active"))

    await send_op("rule", "case-2", "reviewer", "--ruling", "split", "--split-bps", "6500",
                  "--ruling-hash", RULING_HASH)
    data = await wait_dispute_state("case-2", lambda d: d["ruling"] == "split")
    check("split ruling recorded", data["ruling"] == "split", str(data))
    check("split bps recorded", data["split_bps"] == 6500, str(data))

    print("\n=== attestor path: rule requires a signature over ruling_hash ===")
    await tosctl("key", "add", "--name", "dispute-attestor-key")
    await tosctl("key", "add", "--name", "wrong-dispute-attestor-key")
    deploy3 = await tosctl_json(
        "agent", "dispute", "deploy", "--name", "case-3",
        "--claimant", claimant, "--respondent", respondent, "--reviewer", reviewer,
        "--deadline", str(deadline + 20),
        "--subject-hash", SUBJECT_HASH, "--claimant-evidence-hash", CLAIMANT_EVIDENCE_HASH,
        "--signer-vault-key", "dispute-attestor-key",
        "--from", "claimant", "--amount", "0.1", "-w", "0", "--yes",
    )
    address3 = deploy3["address"]
    check("attestor dispute deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address3).get("result") == "active"))
    data = await dispute_show("case-3")
    check("attestor pubkey recorded on-chain", bool(data.get("attestor_pubkey")), str(data))

    await rejected_operation("rule without attestation rejected", address3, reviewer, 9,
                             "rule", "case-3", "reviewer", "--ruling", "claimant",
                             "--ruling-hash", RULING_HASH)

    await rejected_operation("rule with wrong attestor key rejected", address3, reviewer, 2006,
                             "rule", "case-3", "reviewer", "--ruling", "claimant",
                             "--ruling-hash", RULING_HASH,
                             "--signer-vault-key", "wrong-dispute-attestor-key")

    await send_op("rule", "case-3", "reviewer", "--ruling", "claimant",
                  "--ruling-hash", RULING_HASH, "--signer-vault-key", "dispute-attestor-key")
    data = await wait_dispute_state("case-3", lambda d: d["status"] == "resolved")
    check("attestor dispute resolved", data["status"] == "resolved", str(data))

    print("\n=== rotate/revoke: reviewer manages the attestor key post-deploy ===")
    await tosctl("key", "add", "--name", "rotated-dispute-attestor-key")
    deploy4 = await tosctl_json(
        "agent", "dispute", "deploy", "--name", "case-4",
        "--claimant", claimant, "--respondent", respondent, "--reviewer", reviewer,
        "--deadline", str(deadline + 30),
        "--subject-hash", SUBJECT_HASH, "--claimant-evidence-hash", CLAIMANT_EVIDENCE_HASH,
        "--from", "claimant", "--amount", "0.1", "-w", "0", "--yes",
    )
    address4 = deploy4["address"]
    check("rotate dispute deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address4).get("result") == "active"))
    data = await dispute_show("case-4")
    check("no attestor at deploy", not data.get("attestor_pubkey"), str(data))

    await rejected_operation("non-reviewer rotate rejected", address4, outsider, 2001,
                             "rotate-attestor-key", "case-4", "outsider",
                             "--new-attestor-pubkey", "aa" * 32)

    await send_op("rotate-attestor-key", "case-4", "reviewer",
                  "--signer-vault-key", "rotated-dispute-attestor-key")
    data = await wait_dispute_state("case-4", lambda d: bool(d.get("attestor_pubkey")))
    check("reviewer rotate sets attestor pubkey", bool(data.get("attestor_pubkey")), str(data))

    await rejected_operation("rule after rotate still requires attestation", address4, reviewer, 9,
                             "rule", "case-4", "reviewer", "--ruling", "claimant",
                             "--ruling-hash", RULING_HASH)

    await rejected_operation("non-reviewer revoke rejected", address4, outsider, 2001,
                             "revoke-attestor", "case-4", "outsider")

    await rejected_operation("reviewer cannot revoke configured attestor while open",
                             address4, reviewer, 2007, "revoke-attestor", "case-4", "reviewer")

    await send_op("rule", "case-4", "reviewer", "--ruling", "claimant",
                  "--ruling-hash", RULING_HASH,
                  "--signer-vault-key", "rotated-dispute-attestor-key")
    data = await wait_dispute_state("case-4", lambda d: d["status"] == "resolved")
    check("rule still requires configured attestor", data["status"] == "resolved", str(data))

    print("\n=== rotate/revoke frozen from deployment ===")
    # Once the respondent has submitted evidence relying on a configured
    # attestor, the reviewer must not be able to swap in a key they control
    # (or drop the requirement entirely) right before ruling -- that would
    # let them forge the independent check the respondent relied on.
    deploy5 = await tosctl_json(
        "agent", "dispute", "deploy", "--name", "case-5",
        "--claimant", claimant, "--respondent", respondent, "--reviewer", reviewer,
        "--deadline", str(deadline + 40),
        "--subject-hash", SUBJECT_HASH, "--claimant-evidence-hash", CLAIMANT_EVIDENCE_HASH,
        "--attestor-pubkey", "cc" * 32,
        "--from", "claimant", "--amount", "0.1", "-w", "0", "--yes",
    )
    address5 = deploy5["address"]
    check("frozen-attestor dispute deployed and active", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address5).get("result") == "active"))
    data = await dispute_show("case-5")
    check("attestor configured at deploy", bool(data.get("attestor_pubkey")), str(data))

    await rejected_operation("rotate already frozen while open", address5, reviewer, 2007,
                             "rotate-attestor-key", "case-5", "reviewer",
                             "--new-attestor-pubkey", "dd" * 32)

    await send_op("submit-respondent-evidence", "case-5", "respondent",
                  "--respondent-evidence-hash", RESPONDENT_EVIDENCE_HASH)
    data = await wait_dispute_state("case-5", lambda d: d["status"] == "evidence_submitted")
    check("case-5 evidence submitted", data["status"] == "evidence_submitted", str(data))

    await rejected_operation("rotate frozen once evidence submitted", address5, reviewer, 2007,
                             "rotate-attestor-key", "case-5", "reviewer",
                             "--new-attestor-pubkey", "dd" * 32)

    await rejected_operation("revoke frozen once evidence submitted", address5, reviewer, 2007,
                             "revoke-attestor", "case-5", "reviewer")

    print("\n=== persisted local records ===")
    records = {r["name"]: r for r in await tosctl_json("agent", "dispute", "ls")}
    check("all records tracked locally",
          {"case-1", "case-2", "case-3", "case-4"} <= set(records), str(sorted(records)))
    check("record claimant matches", same_addr(records["case-1"]["claimant"], claimant),
          str(records["case-1"]))


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    write_manifest()
    prepare_config()
    install = Install(BUILD_DIR, REPO)
    import logging
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    async with Network(install, WORKDIR / "net", base_port=23500) as network:
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
