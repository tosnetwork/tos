#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
aipow-epoch-e2e.py — phase-A AIPoW shadow-scoring rehearsal on a real localnet.

Closes the loop specified by the shadow-scoring data plane doc
(https://github.com/tosnetwork/doc/blob/main/tos-blockchain/aipow-shadow-scoring.md): real settlements on a real chain flow through
the tosctld indexer's settlement-event table, out of `GET /aipow/settled-work`,
into the external AIPoW scorer, and back out as a signed epoch commitment.

  SETTLE   boot a single-process localnet; two creators each fund, create,
           and settle a Task Escrow (budget 5) against the same agent via the
           real `tosctl agent task` CLI; a third escrow is created and then
           cancelled as a negative control.

  INDEX    a second tosctld config (which never ran a single agent command)
           serves `GET /aipow/settled-work`; the two settlements must appear
           with earner = agent, payers = the two creators, amount = budget,
           evidence = Observed (no attestor key), and the cancelled escrow
           must not appear at all.

  SCORE    the external `aipow-scorer` binary (env AIPOW_SCORER) shadow-scores
           the epoch through `--tosctld`: organic settled value must equal
           the sum of both budgets (two balanced payers keep the
           counterparty discount full), the agent must be the only organic
           identity with an evidence-weighted score equal to that sum, and a
           payout must be allocated.

  COMMIT   the scorer publishes a signed commitment envelope; this script
           re-derives the aipow-commit-v0 canonical bytes and digest
           *independently in Python* per the published methodology and
           verifies the ed25519 signature -- a small cross-implementation
           check of the envelope spec itself.

Exit code 0 iff every check passes.

Run from the repository root: uv run python scripts/aipow-epoch-e2e.py
"""
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from nacl.signing import VerifyKey
from tostester.install import Install
from tostester.network import Network, StartOptions
from contract import tos
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
AIPOW_SCORER = os.environ.get(
    "AIPOW_SCORER", str(REPO.parent / "aipow-scorer/target/debug/aipow-scorer"))
RPC = "127.0.0.1:19646"
HTTP_B = "127.0.0.1:19647"
WORKDIR = REPO / "test/integration/.aipow-epoch-e2e"
CONFIG_A = WORKDIR / "tosctl-e2e-config-a.json"
CONFIG_B = WORKDIR / "tosctl-e2e-config-b.json"
COMMIT_DIR = WORKDIR / "commitments"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
SIGN_SEED = "07" * 32

POLICY_HASH = "11" * 32
RESULT_HASH = "aa" * 32
EVIDENCE_HASH = "bb" * 32
REVIEW_PERIOD = 3600
EPOCH_SECONDS = 65536
NANO = 1_000_000_000
BUDGET_TOS = 5

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(label)
    return ok


def rpc_call(method: str, **params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{RPC}/jsonRPC", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def http_get(path: str):
    req = urllib.request.Request(f"http://{HTTP_B}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    try:
        return status, json.loads(raw.decode())
    except json.JSONDecodeError:
        return status, {}


async def tosctl(config: Path, *args: str, may_fail: bool = False) -> str:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{config.parent}/e2e-vault.json?master_key={MASTER_KEY}"
    proc = await asyncio.create_subprocess_exec(
        TOSCTL, *args, "-c", str(config),
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


async def tosctl_json(config: Path, *args: str):
    return json.loads(await tosctl(config, *args, "--format", "json"))


async def tosctl_status(config: Path, *args: str):
    """Run tosctl and return (returncode, stdout+stderr) for negative tests."""
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{config.parent}/e2e-vault.json?master_key={MASTER_KEY}"
    proc = await asyncio.create_subprocess_exec(
        TOSCTL, *args, "-c", str(config),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=180)
    return proc.returncode, out.decode() + err.decode()


def norm_addr(addr: str) -> str:
    return Address(addr).to_str(is_user_friendly=False).lower()


def same_addr(a: str, b: str) -> bool:
    try:
        return norm_addr(a) == norm_addr(b)
    except Exception:
        return False


def addr_hex(addr: str) -> str:
    """The 64-hex account part of a normalized address (the AIPoW identity)."""
    return norm_addr(addr).split(":", 1)[1]


async def wallet_address(config: Path, name: str) -> str:
    for entry in await tosctl_json(config, "wallet", "ls"):
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


def balance(addr: str) -> int:
    return int(rpc_call("getAddressInformation", address=addr)["result"]["balance"])


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


async def poll_http_predicate(path: str, predicate, timeout: float):
    deadline = time.time() + timeout
    last_body: dict = {}
    while time.time() < deadline:
        status, body = http_get(path)
        last_body = body
        if status == 200 and predicate(body):
            return True, body
        await asyncio.sleep(1)
    return False, last_body


def prepare_config(config: Path, http_bind: str | None):
    subprocess.run([TOSCTL, "config", "generate", "-o", str(config), "--force"], check=True)
    cfg = json.loads(config.read_text())
    cfg["chain_rpc"] = {"urls": [f"http://{RPC}/"], "api_key": None}
    if http_bind is not None:
        cfg["http"] = {"bind": http_bind, "enable_swagger": False, "auth": None}
    cfg["elections"] = None
    cfg.pop("voting", None)
    cfg["tick_interval"] = 2
    config.write_text(json.dumps(cfg, indent=2))


async def task_status(name: str) -> str:
    return (await tosctl_json(CONFIG_A, "agent", "task", "show", "--name", name))["status"]


async def wait_task_status(name: str, want: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if await task_status(name) == want:
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


async def create_task(name: str, creator: str, from_wallet: str, agent: str | None) -> str:
    deadline = int(time.time()) + 3600
    args = ["agent", "task", "create", "--name", name, "--creator", creator,
            "--budget", str(BUDGET_TOS), "--deadline", str(deadline),
            "--review-period", str(REVIEW_PERIOD),
            "--policy-hash", POLICY_HASH, "--from", from_wallet,
            "--amount", str(BUDGET_TOS + 0.2), "-w", "0", "--yes"]
    if agent is not None:
        args += ["--agent", agent]
    out = json.loads(await tosctl(CONFIG_A, *args, "--format", "json"))
    return norm_addr(out["address"])


async def send_op(operation: str, name: str, frm: str, *extra: str):
    await tosctl(CONFIG_A, "agent", "task", "send", "--operation", operation,
                 "--name", name, "--from", frm, "--yes", *extra)


async def settle_task(name: str, creator_wallet: str, agent_addr: str, payout: int):
    await send_op("accept", name, "agent")
    if not check(f"{name} accepted", await wait_task_status(name, "accepted")):
        return
    await send_op("result", name, "agent",
                  "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH)
    if not check(f"{name} result submitted",
                 await wait_task_status(name, "result_submitted")):
        return
    await send_op("settle", name, creator_wallet, "--payout", str(payout))
    check(f"{name} settled", await wait_task_status(name, "settled"))


def verify_commitment_signature(commitment: dict) -> bool:
    """Independently re-derive the aipow-commit-v0 digest per the published
    methodology (docs/methodology.md section 10.1 in the scorer repository)
    and verify the ed25519 signature. This is a deliberate second
    implementation of the envelope encoding, not a call into the scorer."""
    env = commitment["envelope"]
    version = env["methodology_version"].encode()
    payload = (
        b"aipow-commit-v0"
        + int(env["epoch"]).to_bytes(8, "big")
        + len(version).to_bytes(4, "big")
        + version
        + bytes.fromhex(env["score_root_hex"])
        + int(env["entry_count"]).to_bytes(8, "big")
        + int(env["total_score"]).to_bytes(16, "big")
        + int(env["organic_settled_value"]).to_bytes(16, "big")
    )
    digest = hashlib.sha256(payload).digest()
    key = VerifyKey(bytes.fromhex(commitment["public_key_hex"]))
    try:
        key.verify(digest, bytes.fromhex(commitment["signature_hex"]))
        return True
    except Exception:
        return False


async def run_checks(faucet) -> None:
    print("\n=== provision: wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    for name in ("creator1", "creator2", "agent"):
        await tosctl(CONFIG_A, "wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    creator1 = await wallet_address(CONFIG_A, "creator1")
    creator2 = await wallet_address(CONFIG_A, "creator2")
    agent = await wallet_address(CONFIG_A, "agent")
    print(f"  creator1: {creator1}\n  creator2: {creator2}\n  agent:    {agent}")

    for label, addr in (("creator1", creator1), ("creator2", creator2), ("agent", agent)):
        await faucet.send(faucet_transfer(faucet, addr, 60))
        check(f"{label} funded", await wait_balance_at_least(addr, 59 * NANO))
        await tosctl(CONFIG_A, "wallet", "activate", "-n", label)
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{label} wallet active", bool(active))

    print("\n=== create three escrows (all open) ===")
    task1 = await create_task("aipow-t1", creator1, "creator1", agent)
    task2 = await create_task("aipow-t2", creator2, "creator2", agent)
    task3 = await create_task("aipow-t3", creator1, "creator1", agent)
    for name in ("aipow-t1", "aipow-t2", "aipow-t3"):
        check(f"{name} open", await wait_task_status(name, "open"))

    # The indexer records a settlement's amount from its own
    # pre-settlement observation of the escrow (settlement drains the
    # on-chain budget field), so config-b's tosctld starts *before* the
    # settlements -- the production posture of a continuously-running
    # indexer.
    print("\n=== INDEX: start config-b tosctld before any settlement ===")
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{CONFIG_B.parent}/e2e-vault-b.json?master_key={MASTER_KEY}"
    service_proc = await asyncio.create_subprocess_exec(
        TOSCTL, "service", "-c", str(CONFIG_B),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        check("config-b tosctld health endpoint ready", await wait_http_ready())
        all_tasks = {task1, task2, task3}
        found, body = await poll_http_predicate(
            "/tasks",
            lambda b: all_tasks <= {norm_addr(i["address"])
                                    for i in b.get("result", []) if i.get("address")},
            timeout=90.0,
        )
        check("indexer observed all three open escrows pre-settlement", found,
              str(body)[:2000])

        print("\n=== SETTLE: two escrows settle to the same agent; one is cancelled ===")
        await settle_task("aipow-t1", "creator1", agent, 3)
        await settle_task("aipow-t2", "creator2", agent, 4)
        await send_op("cancel", "aipow-t3", "creator1")
        check("aipow-t3 cancelled", await wait_task_status("aipow-t3", "cancelled"))

        print("\n=== settlement events served with pre-settlement budgets ===")
        found, body = await poll_http_predicate(
            "/aipow/settled-work", lambda b: b.get("total") == 2, timeout=90.0)
        check("exactly two settlement events served", found, str(body)[:2000])
        if not found:
            return
        events = body["result"]
        by_addr = {norm_addr(e["address"]): e for e in events}
        check("settled escrows are the recorded events",
              set(by_addr) == {task1, task2}, str(sorted(by_addr)))
        check("cancelled escrow produced no event", task3 not in by_addr)
        for e in events:
            check(f"event {e['address'][:16]}… earner is the agent",
                  same_addr(e["earner"], agent), str(e))
            check(f"event {e['address'][:16]}… amount is the budget",
                  e["amount"] == BUDGET_TOS * NANO, str(e["amount"]))
            check(f"event {e['address'][:16]}… evidence is Observed",
                  e["evidence"] == "Observed", e["evidence"])
            check(f"event {e['address'][:16]}… kind is task_escrow",
                  e["kind"] == "task_escrow", e["kind"])
        payers = {norm_addr(e["payer"]) for e in events}
        check("payers are the two creators", payers == {creator1, creator2}, str(payers))

        epochs = {e["observed_at"] // EPOCH_SECONDS for e in events}
        if not check("both settlements fall in one epoch", len(epochs) == 1,
                     f"epochs={sorted(epochs)} (rerun: the wall clock crossed an "
                     f"epoch boundary mid-test)"):
            return
        epoch = epochs.pop()

        print(f"\n=== SCORE: aipow-scorer shadow-scores epoch {epoch} via --tosctld ===")
        COMMIT_DIR.mkdir(parents=True, exist_ok=True)
        scorer = subprocess.run(
            [AIPOW_SCORER, "--tosctld", f"http://{HTTP_B}", str(epoch),
             "--commit-out", str(COMMIT_DIR), "--sign-seed-hex", SIGN_SEED],
            capture_output=True, text=True, timeout=120,
        )
        if not check("aipow-scorer exits 0", scorer.returncode == 0,
                     f"stdout={scorer.stdout[-1000:]} stderr={scorer.stderr[-1000:]}"):
            return
        output = json.loads(scorer.stdout)
        expected_value = 2 * BUDGET_TOS * NANO
        check("organic settled value is the sum of both budgets",
              output["organic_settled_value"] == expected_value,
              str(output["organic_settled_value"]))
        check("scored epoch matches", output["epoch"] == epoch)
        organic = output["organic"]
        check("agent is the only organic identity", len(organic) == 1
              and organic[0]["identity_hex"] == addr_hex(agent), str(organic))
        if organic:
            check("agent's evidence-weighted score equals the settled value",
                  organic[0]["score"] == expected_value, str(organic[0]["score"]))
            check("agent receives a payout", organic[0]["payout"] > 0,
                  str(organic[0]["payout"]))
        check("no challenge entries", output["challenge"] == [], str(output["challenge"]))
        check("demand-coupled pool is k x organic value",
              output["pool"] == 3 * expected_value, str(output["pool"]))

        print("\n=== COMMIT: signed envelope published and independently verified ===")
        commit_path = COMMIT_DIR / f"aipow-commitment-epoch-{epoch}.json"
        if not check("commitment file published", commit_path.exists(), str(commit_path)):
            return
        commitment = json.loads(commit_path.read_text())
        check("committed root matches the scorer output",
              commitment["envelope"]["score_root_hex"] == output["score_root_hex"])
        check("committed organic value matches",
              commitment["envelope"]["organic_settled_value"] == expected_value)
        check("ed25519 signature verifies against an independent Python "
              "re-derivation of the canonical digest",
              verify_commitment_signature(commitment))
        tampered = json.loads(commit_path.read_text())
        tampered["envelope"]["total_score"] = int(tampered["envelope"]["total_score"]) + 1
        check("tampered envelope fails the independent verification",
              not verify_commitment_signature(tampered))

        print("\n=== ONCHAIN: commit the scored root through the commitment contract ===")
        score_root = output["score_root_hex"]
        methodology_hash = hashlib.sha256(b"aipow-methodology-v0").hexdigest()
        window_deadline = int(time.time()) + 40
        committed_total_score = str(commitment["envelope"]["total_score"])
        committed_organic = str(commitment["envelope"]["organic_settled_value"])
        deploy_out = await tosctl_json(
            CONFIG_A, "agent", "aipow", "deploy", "--name", "e2e-commit",
            "--committer", creator1, "--reviewer", creator2,
            "--epoch", str(epoch), "--window-deadline", str(window_deadline),
            "--commit-bond", "2", "--score-root", score_root,
            "--methodology-hash", methodology_hash,
            "--total-score", committed_total_score,
            "--organic-settled-value", committed_organic,
            "--from", "creator1", "-w", "0", "--yes",
        )
        commitment_addr = norm_addr(deploy_out["address"])
        print(f"  commitment: {commitment_addr}")
        check("commitment active on chain", await poll_predicate(
            lambda: rpc_call("getAddressState", address=commitment_addr).get("result")
            == "active"))

        show = await tosctl_json(
            CONFIG_A, "agent", "aipow", "show", "--name", "e2e-commit")
        check("on-chain root matches the scorer output",
              show["score_root"] == score_root, str(show))
        check("on-chain status is committed", show["status"] == "committed", str(show))
        check("on-chain epoch matches", show["epoch"] == epoch, str(show))
        check("on-chain total score matches the committed envelope",
              show["total_score"] == committed_total_score, str(show))
        check("on-chain organic settled value matches the committed envelope",
              show["organic_settled_value"] == committed_organic, str(show))

        found, body = await poll_http_predicate(
            "/aipow/commitments",
            lambda b: any(same_addr(i.get("address", ""), commitment_addr)
                          for i in b.get("result", [])),
            timeout=60.0,
        )
        check("indexer discovers the commitment chain-wide", found, str(body)[:2000])
        if found:
            entry = next(i for i in body["result"]
                         if same_addr(i["address"], commitment_addr))
            check("indexed commitment root matches", entry["score_root"] == score_root,
                  str(entry))

        # Wait out the challenge window, then finalize permissionlessly from
        # a wallet that is not the committer; the bond returns to the
        # committer regardless.
        wait_for = max(0, window_deadline - int(time.time())) + 3
        print(f"  waiting {wait_for}s for the challenge window to close…")
        await asyncio.sleep(wait_for)
        committer_before = balance(creator1)
        await tosctl(CONFIG_A, "agent", "aipow", "send", "--operation", "finalize",
                     "--name", "e2e-commit", "--from", "creator2", "--yes")
        finalized, body = await poll_http_predicate(
            f"/aipow/commitments/{commitment_addr}",
            lambda b: b.get("result", {}).get("status") == "final",
            timeout=60.0,
        )
        check("indexer observes the finalized commitment", finalized, str(body)[:1000])
        show = await tosctl_json(
            CONFIG_A, "agent", "aipow", "show", "--name", "e2e-commit")
        check("commitment final on chain", show["status"] == "final", str(show))
        bond_delta = balance(creator1) - committer_before
        check("committer's bond returned on finalize",
              int(1.9 * NANO) < bond_delta <= 2 * NANO, str(bond_delta))

        print("\n=== VERIFIED BINDING: distributor deploy checks the finalized commitment ===")
        # Positive: an entries file that reproduces the committed single-member
        # root, bound to the finalized commitment by address. The CLI queries
        # the commitment, requires it final with a matching root/total/epoch,
        # and derives the reference from its account id.
        agent_score = output["organic"][0]["score"]
        bound_file = WORKDIR / "bound-entries.json"
        bound_file.write_text(json.dumps([{"identity": addr_hex(agent), "score": agent_score}]))
        bound_out = await tosctl_json(
            CONFIG_A, "agent", "aipow-dist", "deploy", "--name", "e2e-dist-bound",
            "--operator", creator1, "--epoch", str(epoch),
            "--entries-file", str(bound_file), "--pool", "6",
            "--commitment", commitment_addr,
            "--from", "creator1", "-w", "0", "--yes",
        )
        check("distributor binds to the finalized commitment", "address" in bound_out,
              str(bound_out))
        # Negative: a mismatched entries file against the same commitment is
        # rejected -- the denominator/root binding is enforced, not decorative.
        mismatch_file = WORKDIR / "mismatch-entries.json"
        mismatch_file.write_text(json.dumps([{"identity": addr_hex(creator1), "score": 12345}]))
        rc, combined = await tosctl_status(
            CONFIG_A, "agent", "aipow-dist", "deploy", "--name", "e2e-dist-bad",
            "--operator", creator1, "--epoch", str(epoch),
            "--entries-file", str(mismatch_file), "--pool", "6",
            "--commitment", commitment_addr,
            "--from", "creator1", "-w", "0", "--yes",
        )
        check("a distributor that mismatches the commitment is rejected",
              rc != 0 and "does not match" in combined, f"rc={rc} out={combined[-400:]}")

        print("\n=== DISTRIBUTOR: deploy over an entries file and claim a share ===")
        # A small published scoring: three real chain accounts with scores
        # summing to 1,000,000. The distributor CLI computes the score root
        # and total from this file; the agent claims its pro-rata share.
        entries = [
            {"identity": addr_hex(creator1), "score": 300_000},
            {"identity": addr_hex(creator2), "score": 200_000},
            {"identity": addr_hex(agent), "score": 500_000},
        ]
        entries_file = WORKDIR / "entries.json"
        entries_file.write_text(json.dumps(entries))
        commitment_ref = hashlib.sha256(b"aipow-dist-e2e-ref").hexdigest()
        dist_out = await tosctl_json(
            CONFIG_A, "agent", "aipow-dist", "deploy", "--name", "e2e-dist",
            "--operator", creator1, "--epoch", str(epoch),
            "--entries-file", str(entries_file), "--pool", "6",
            "--commitment-ref", commitment_ref,
            "--from", "creator1", "-w", "0", "--yes",
        )
        dist_addr = norm_addr(dist_out["address"])
        print(f"  distributor: {dist_addr}")
        check("distributor active on chain", await poll_predicate(
            lambda: rpc_call("getAddressState", address=dist_addr).get("result") == "active"))

        show = await tosctl_json(CONFIG_A, "agent", "aipow-dist", "show", "--name", "e2e-dist")
        check("distributor total score computed from entries",
              show["total_score"] == "1000000", str(show))
        check("distributor claimed count starts at zero",
              show["claimed_count"] == 0, str(show))

        # The agent claims: CLI builds the inclusion proof from the entries
        # file and verifies the computed root against the on-chain root.
        await tosctl(CONFIG_A, "agent", "aipow-dist", "claim", "--name", "e2e-dist",
                     "--entries-file", str(entries_file), "--identity", addr_hex(agent),
                     "--from", "agent", "--yes")
        show_after = None
        for _ in range(30):
            show_after = await tosctl_json(
                CONFIG_A, "agent", "aipow-dist", "show", "--name", "e2e-dist")
            if show_after["claimed_count"] == 1:
                break
            await asyncio.sleep(1)
        check("agent's claim advances the claimed count",
              show_after and show_after["claimed_count"] == 1, str(show_after))

        print("\n=== FORFEIT: the operator forfeits the agent's claim ===")
        before = await tosctl_json(
            CONFIG_A, "agent", "aipow-dist", "show", "--name", "e2e-dist",
            "--identity", addr_hex(agent))
        check("agent claim is not forfeited before the operator acts",
              before.get("claim", {}).get("forfeited") is False, str(before.get("claim")))
        await tosctl(CONFIG_A, "agent", "aipow-dist", "forfeit", "--name", "e2e-dist",
                     "--identity", addr_hex(agent), "--from", "creator1", "--yes")
        forfeited = None
        for _ in range(30):
            forfeited = await tosctl_json(
                CONFIG_A, "agent", "aipow-dist", "show", "--name", "e2e-dist",
                "--identity", addr_hex(agent))
            if forfeited.get("claim", {}).get("forfeited"):
                break
            await asyncio.sleep(1)
        check("operator forfeit freezes the agent's claim",
              forfeited and forfeited.get("claim", {}).get("forfeited") is True,
              str(forfeited.get("claim") if forfeited else None))

        print("\n=== CHALLENGE: a challenged commitment ruled rejected ===")
        ch_deadline = int(time.time()) + 3600  # long window: no wait needed
        ch_out = await tosctl_json(
            CONFIG_A, "agent", "aipow", "deploy", "--name", "e2e-commit-ch",
            "--committer", creator1, "--reviewer", creator2,
            "--epoch", str(epoch), "--window-deadline", str(ch_deadline),
            "--commit-bond", "2", "--score-root", score_root,
            "--methodology-hash", methodology_hash,
            "--total-score", committed_total_score,
            "--organic-settled-value", committed_organic,
            "--from", "creator1", "-w", "0", "--yes",
        )
        ch_addr = norm_addr(ch_out["address"])
        check("challenged-path commitment active", await poll_predicate(
            lambda: rpc_call("getAddressState", address=ch_addr).get("result") == "active"))
        # The agent challenges with a bond at least matching the commit bond.
        await tosctl(CONFIG_A, "agent", "aipow", "send", "--operation", "challenge",
                     "--name", "e2e-commit-ch", "--from", "agent",
                     "--challenge-evidence-hash", "cc" * 32, "--amount", "2.5", "--yes")
        challenged = None
        for _ in range(30):
            challenged = await tosctl_json(
                CONFIG_A, "agent", "aipow", "show", "--name", "e2e-commit-ch")
            if challenged["status"] == "challenged":
                break
            await asyncio.sleep(1)
        check("commitment enters challenged state", challenged
              and challenged["status"] == "challenged", str(challenged))
        # The reviewer upholds the challenge: the root is rejected.
        await tosctl(CONFIG_A, "agent", "aipow", "send", "--operation", "rule",
                     "--uphold", "true", "--name", "e2e-commit-ch", "--from", "creator2", "--yes")
        ruled = None
        for _ in range(30):
            ruled = await tosctl_json(
                CONFIG_A, "agent", "aipow", "show", "--name", "e2e-commit-ch")
            if ruled["status"] == "rejected":
                break
            await asyncio.sleep(1)
        check("upheld challenge rejects the root",
              ruled and ruled["status"] == "rejected", str(ruled))

    finally:
        service_proc.terminate()
        try:
            await asyncio.wait_for(service_proc.wait(), timeout=10)
        except TimeoutError:
            service_proc.kill()


async def main() -> int:
    for path, hint in (
        (Path(TOSCTL),
         "build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl"),
        (Path(AIPOW_SCORER),
         "build with: cargo build -p aipow-cli  (in the aipow-scorer repository, "
         "or set AIPOW_SCORER)"),
    ):
        if not path.exists():
            print(f"FATAL: required binary not found at {path} ({hint})", file=sys.stderr)
            return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    prepare_config(CONFIG_A, http_bind=None)
    prepare_config(CONFIG_B, http_bind=HTTP_B)
    install = Install(BUILD_DIR, REPO)

    async with Network(install, WORKDIR / "net", base_port=24100) as network:
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

    print("\n=== RESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILURE(S)", "===")
    return 1 if failures else 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    sys.exit(rc)
