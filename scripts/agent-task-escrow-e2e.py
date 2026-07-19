#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
agent-task-escrow-e2e.py — real-localnet acceptance of the Task Escrow lifecycle.

Boots a single-process local TOS chain (same machinery as localnet-jsonrpc.py),
provisions a file vault plus a tosctl config, creates and funds two wallets
(creator + agent), then drives every Task Escrow flow through the real
`tosctl agent task` CLI against the running validator:

  HAPPY    create (budget 5) -> open -> accept by agent -> accepted
           -> unauthorized result by creator rejected (still accepted)
           -> result by agent -> result_submitted (hashes recorded)
           -> unauthorized settle by agent rejected (still result_submitted)
           -> settle by creator (payout 3) -> settled;
           agent receives exactly the payout, creator receives the remainder,
           escrow balance is drained.

  CONTROL  deploy an Agent Account -> create an assigned task -> controller-
           signed accept -> controller-signed result -> creator settlement.

  CLAIM    create an unassigned task -> controller-signed atomic claim ->
           assigned Agent Account recorded -> result -> settlement.

  DISPUTE create with verifier -> result -> creator dispute -> unauthorized
           resolution rejected -> verifier resolution.

  REJECT   create an Agent Account-assigned task -> controller-signed reject;
           refund returns to the creator and the escrow is drained.

  CANCEL   create (budget 2) -> cancel by creator -> cancelled; refund returns
           to the creator and the escrow is drained.

  TIMEOUT  create (budget 2, short deadline) -> accept -> premature timeout
           rejected (still accepted) -> after the deadline, timeout -> expired;
           refund returns to the creator.

  RECORDS  `agent task create` persists a record in the tosctl config;
           `agent task ls` lists it and every show/send above resolves the
           escrow through `--name`; on-chain discovery filters cover status,
           creator, dynamic assigned agent and unassigned tasks.

Exit code 0 iff every check passes.

Run:  cd /home/tomi/tos && uv run python scripts/agent-task-escrow-e2e.py
"""
import asyncio
import hashlib
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
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build-remove-workchains-full"))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
RPC = "127.0.0.1:18546"
WORKDIR = REPO / "test/integration/.task-escrow-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000001"

POLICY_HASH = "11" * 32
RESULT_HASH = "aa" * 32
EVIDENCE_HASH = "bb" * 32
DISPUTE_HASH = "cc" * 32
PERMISSION_ID = "e2e-agent:bounded-task:1"
REVIEW_PERIOD = 120
NANO = 1_000_000_000

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


# tosctl runs as an *async* subprocess: a blocking subprocess.run would stall
# the event loop that drains the in-process node's log pipes, deadlocking the
# chain (and therefore the tosctl call itself) until the subprocess timeout.
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
    """Normalize base64 and raw address forms to lowercase `wc:hex`."""
    return Address(addr).to_str(is_user_friendly=False).lower()


def same_addr(candidate, want: str) -> bool:
    try:
        return candidate is not None and norm_addr(candidate) == want
    except Exception:
        return False


async def task_show(name: str):
    return await tosctl_json("agent", "task", "show", "--name", name)


async def wait_status(name: str, want: str, timeout: float = 90.0) -> str:
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


async def assert_status_stays(name: str, want: str, label: str, settle_secs: float = 8.0):
    await asyncio.sleep(settle_secs)
    status = (await task_show(name))["status"]
    check(label, status == want, f"status={status}")


async def send_op(operation: str, name: str, frm: str, *extra: str):
    await tosctl("agent", "task", "send", "--operation", operation, "--name", name,
                 "--from", frm, "--yes", *extra)


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


def write_config():
    CONFIG.write_text(json.dumps({
        "nodes": {},
        "wallets": {},
        "pools": {},
        "bindings": {},
        "chain_rpc": {"urls": [f"http://{RPC}/"]},
        "http": {},
        "master_wallet": None,
        "tick_interval": 40,
        "log": None,
    }, indent=2))


async def wallet_address(name: str) -> str:
    for entry in await tosctl_json("wallet", "ls"):
        if entry["name"] == name and entry.get("address"):
            return norm_addr(entry["address"])
    raise RuntimeError(f"wallet {name} has no address in `wallet ls`")


async def create_task(name: str, creator: str, agent: str | None, budget: float,
                      deadline: int, amount: float, verifier: str | None = None) -> str:
    args = ["agent", "task", "create", "--name", name, "--creator", creator,
            "--budget", str(budget), "--deadline", str(deadline),
            "--review-period", str(REVIEW_PERIOD),
            "--policy-hash", POLICY_HASH, "--from", "creator",
            "--permission-id", PERMISSION_ID,
            "--amount", str(amount), "-w", "0", "--yes"]
    if agent is not None:
        args += ["--agent", agent]
    if verifier is not None:
        args += ["--verifier", verifier]
    out = json.loads(await tosctl(*args, "--format", "json"))
    return out["address"]


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


async def run_checks(faucet) -> None:
    print("\n=== provision: tosctl wallets ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")
    await tosctl("wallet", "create", "-n", "creator", "-v", "V3R2", "-w", "0")
    await tosctl("wallet", "create", "-n", "agent", "-v", "V3R2", "-w", "0")
    await tosctl("wallet", "create", "-n", "verifier", "-v", "V3R2", "-w", "0")
    creator = await wallet_address("creator")
    agent = await wallet_address("agent")
    verifier = await wallet_address("verifier")
    print(f"  creator:  {creator}\n  agent:    {agent}\n  verifier: {verifier}")

    # Fund sequentially: two in-flight external messages from the faucet share
    # a seqno, so the second would replace the first.
    await faucet.send(faucet_transfer(faucet, creator, 50))
    check("creator funded", await wait_balance_at_least(creator, 49 * NANO))
    await faucet.send(faucet_transfer(faucet, agent, 50))
    check("agent funded", await wait_balance_at_least(agent, 49 * NANO))
    await faucet.send(faucet_transfer(faucet, verifier, 50))
    check("verifier funded", await wait_balance_at_least(verifier, 49 * NANO))
    await tosctl("wallet", "activate", "-n", "creator")
    await tosctl("wallet", "activate", "-n", "agent")
    await tosctl("wallet", "activate", "-n", "verifier")
    for label, addr in (("creator", creator), ("agent", agent), ("verifier", verifier)):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{label} wallet active", bool(active))

    await tosctl(
        "agent", "wallet", "create", "--name", "runtime-agent", "-v", "V3R2", "-w", "0",
        "--max-per-tx", "1", "--daily-limit", "5", "--format", "json",
    )
    account_deploy = await tosctl_json(
        "agent", "account", "deploy", "--wallet", "runtime-agent", "--from", "creator",
        "-w", "0", "--amount", "2", "--yes",
    )
    agent_account = norm_addr(account_deploy["address"])
    check("Agent Account deployed", await poll_predicate(
        lambda: rpc_call("getAddressState", address=agent_account).get("result") == "active"))

    # ---------------- HAPPY PATH ----------------
    print("\n=== happy path: create -> accept -> result -> settle ===")
    deadline = int(time.time()) + 3600
    escrow = await create_task("e2e-main", creator, agent, 5, deadline, 5.2)
    print(f"  escrow: {escrow}")
    check("open after deploy", await wait_status("e2e-main", "open") == "open")

    data = await task_show("e2e-main")
    check("creator recorded on-chain", same_addr(data["creator"], creator), str(data))
    check("agent recorded on-chain", same_addr(data["assigned_agent"], agent), str(data))
    check("policy hash recorded", data["settlement_policy_hash"] == POLICY_HASH)
    check("permission linkage shown", data.get("permission_id") == PERMISSION_ID, str(data))
    check("permission hash recorded on-chain",
          data.get("permission_hash") == hashlib.sha256(PERMISSION_ID.encode()).hexdigest(),
          str(data))

    await send_op("accept", "e2e-main", "creator")
    await assert_status_stays("e2e-main", "open", "accept by creator rejected")

    await send_op("accept", "e2e-main", "agent")
    check("accepted", await wait_status("e2e-main", "accepted") == "accepted")

    await send_op("accept", "e2e-main", "agent")
    await assert_status_stays("e2e-main", "accepted", "second accept rejected")

    await send_op("result", "e2e-main", "creator",
                  "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH)
    await assert_status_stays("e2e-main", "accepted", "result by creator rejected")

    await send_op("result", "e2e-main", "agent",
                  "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH)
    check("result submitted",
          await wait_status("e2e-main", "result_submitted") == "result_submitted")
    data = await task_show("e2e-main")
    check("result hash recorded", data["result_hash"] == RESULT_HASH, str(data))
    check("evidence hash recorded", data["evidence_hash"] == EVIDENCE_HASH)
    check("review period recorded", data["review_period"] == REVIEW_PERIOD, str(data))
    check("review deadline started",
          int(time.time()) + REVIEW_PERIOD - 30 <= data["review_deadline"] <=
          int(time.time()) + REVIEW_PERIOD + 30, str(data))

    await send_op("settle", "e2e-main", "agent", "--payout", "3")
    await assert_status_stays("e2e-main", "result_submitted", "settle by agent rejected")

    agent_before = balance(agent)
    creator_before = balance(creator)
    await send_op("settle", "e2e-main", "creator", "--payout", "3")
    check("settled", await wait_status("e2e-main", "settled") == "settled")
    await asyncio.sleep(5)
    agent_delta = balance(agent) - agent_before
    creator_delta = balance(creator) - creator_before
    escrow_left = balance(escrow)
    print(f"  agent delta:   {agent_delta / NANO:+.9f} TOS")
    print(f"  creator delta: {creator_delta / NANO:+.9f} TOS")
    print(f"  escrow left:   {escrow_left / NANO:.9f} TOS")
    check("agent received exact payout", abs(agent_delta - 3 * NANO) <= NANO // 1000,
          f"delta={agent_delta}")
    check("creator received remainder", creator_delta > int(1.9 * NANO),
          f"delta={creator_delta}")
    check("escrow drained after settle", escrow_left < NANO // 100,
          f"left={escrow_left}")

    # ---------------- CONTROLLER PATH ----------------
    print("\n=== controller path: Agent Account -> Task Escrow ===")
    controller_deadline = int(time.time()) + 3600
    await create_task(
        "e2e-controller", creator, agent_account, 2, controller_deadline, 2.2)
    check("controller task open", await wait_status("e2e-controller", "open") == "open")
    await tosctl(
        "agent", "task", "send", "--operation", "accept", "--name", "e2e-controller",
        "--via-agent-account", "runtime-agent", "--amount", "0.1", "--yes",
    )
    check("controller accepted task",
          await wait_status("e2e-controller", "accepted") == "accepted")
    await tosctl(
        "agent", "task", "send", "--operation", "result", "--name", "e2e-controller",
        "--via-agent-account", "runtime-agent", "--amount", "0.1",
        "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH, "--yes",
    )
    check("controller submitted result",
          await wait_status("e2e-controller", "result_submitted") == "result_submitted")
    await send_op("settle", "e2e-controller", "creator", "--payout", "1")
    check("controller task settled",
          await wait_status("e2e-controller", "settled") == "settled")

    # ---------------- OPEN CLAIM PATH ----------------
    print("\n=== claim path: open Task Escrow -> Agent Account ===")
    claim_deadline = controller_deadline + 2
    await create_task("e2e-claim", creator, None, 1.5, claim_deadline, 1.7)
    check("claim task open", await wait_status("e2e-claim", "open") == "open")
    await tosctl(
        "agent", "task", "send", "--operation", "claim", "--name", "e2e-claim",
        "--via-agent-account", "runtime-agent", "--amount", "0.1", "--yes",
    )
    check("controller claimed open task",
          await wait_status("e2e-claim", "accepted") == "accepted")
    claim_data = await task_show("e2e-claim")
    check("claim records Agent Account on-chain",
          same_addr(claim_data.get("assigned_agent"), agent_account), str(claim_data))
    await tosctl(
        "agent", "task", "send", "--operation", "result", "--name", "e2e-claim",
        "--via-agent-account", "runtime-agent", "--amount", "0.1",
        "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH, "--yes",
    )
    check("claim winner submitted result",
          await wait_status("e2e-claim", "result_submitted") == "result_submitted")
    await send_op("settle", "e2e-claim", "creator", "--payout", "0.5")
    check("claimed task settled", await wait_status("e2e-claim", "settled") == "settled")

    # ---------------- DISPUTE PATH ----------------
    print("\n=== dispute path: creator -> verifier resolution ===")
    dispute_deadline = controller_deadline + 3
    await create_task(
        "e2e-dispute", creator, agent, 2.5, dispute_deadline, 2.7, verifier)
    check("dispute task open", await wait_status("e2e-dispute", "open") == "open")
    await send_op("accept", "e2e-dispute", "agent")
    check("dispute task accepted",
          await wait_status("e2e-dispute", "accepted") == "accepted")
    await send_op("result", "e2e-dispute", "agent",
                  "--result-hash", RESULT_HASH, "--evidence-hash", EVIDENCE_HASH)
    check("dispute result submitted",
          await wait_status("e2e-dispute", "result_submitted") == "result_submitted")
    await send_op("dispute", "e2e-dispute", "creator", "--dispute-hash", DISPUTE_HASH)
    check("creator opened dispute",
          await wait_status("e2e-dispute", "disputed") == "disputed")
    dispute_data = await task_show("e2e-dispute")
    check("dispute hash recorded", dispute_data.get("dispute_hash") == DISPUTE_HASH,
          str(dispute_data))
    await send_op("resolve", "e2e-dispute", "agent", "--payout", "1.5")
    await assert_status_stays(
        "e2e-dispute", "disputed", "resolve by non-verifier rejected")
    await send_op("resolve", "e2e-dispute", "verifier", "--payout", "1.5")
    check("verifier resolved dispute",
          await wait_status("e2e-dispute", "settled") == "settled")

    # ---------------- REJECT PATH ----------------
    print("\n=== reject path: Agent Account -> Task Escrow ===")
    reject_deadline = controller_deadline + 1
    escrow = await create_task(
        "e2e-reject", creator, agent_account, 2, reject_deadline, 2.1)
    check("reject task open", await wait_status("e2e-reject", "open") == "open")
    creator_before = balance(creator)
    await tosctl(
        "agent", "task", "send", "--operation", "reject", "--name", "e2e-reject",
        "--via-agent-account", "runtime-agent", "--amount", "0.1", "--yes",
    )
    check("controller rejected task",
          await wait_status("e2e-reject", "rejected") == "rejected")
    await asyncio.sleep(5)
    creator_delta = balance(creator) - creator_before
    check("reject refunded creator", creator_delta > int(1.9 * NANO),
          f"delta={creator_delta}")
    check("escrow drained after reject", balance(escrow) < NANO // 100)

    # ---------------- CANCEL PATH ----------------
    print("\n=== cancel path ===")
    escrow = await create_task("e2e-cancel", creator, agent, 2, deadline, 2.1)
    check("cancel task open", await wait_status("e2e-cancel", "open") == "open")
    creator_before = balance(creator)
    await send_op("cancel", "e2e-cancel", "creator")
    check("cancelled", await wait_status("e2e-cancel", "cancelled") == "cancelled")
    await asyncio.sleep(5)
    creator_delta = balance(creator) - creator_before
    check("cancel refunded creator", creator_delta > int(1.9 * NANO),
          f"delta={creator_delta}")
    check("escrow drained after cancel", balance(escrow) < NANO // 100)

    # ---------------- TIMEOUT PATH ----------------
    print("\n=== timeout path ===")
    short_deadline = int(time.time()) + 75
    escrow = await create_task("e2e-timeout", creator, agent, 2, short_deadline, 2.1)
    check("timeout task open", await wait_status("e2e-timeout", "open") == "open")
    await send_op("accept", "e2e-timeout", "agent")
    check("timeout task accepted",
          await wait_status("e2e-timeout", "accepted") == "accepted")

    if time.time() < short_deadline - 20:
        await send_op("timeout", "e2e-timeout", "creator")
        await assert_status_stays("e2e-timeout", "accepted", "premature timeout rejected")
    else:
        print("  SKIP: premature timeout window already passed")

    wait_for = short_deadline + 5 - time.time()
    if wait_for > 0:
        print(f"  waiting {wait_for:.0f}s for the deadline to pass ...")
        await asyncio.sleep(wait_for)
    creator_before = balance(creator)
    await send_op("timeout", "e2e-timeout", "creator")
    check("expired", await wait_status("e2e-timeout", "expired") == "expired")
    await asyncio.sleep(5)
    creator_delta = balance(creator) - creator_before
    check("timeout refunded creator", creator_delta > int(1.9 * NANO),
          f"delta={creator_delta}")
    check("escrow drained after timeout", balance(escrow) < NANO // 100)

    # ---------------- PERSISTED RECORDS ----------------
    print("\n=== persisted task records ===")
    records = {r["name"]: r for r in await tosctl_json("agent", "task", "ls")}
    expected_records = {
        "e2e-main", "e2e-controller", "e2e-claim", "e2e-reject", "e2e-cancel",
        "e2e-dispute", "e2e-timeout"}
    check("seven records tracked", set(records) == expected_records,
          str(sorted(records)))
    main_rec = records.get("e2e-main", {})
    check("record creator", same_addr(main_rec.get("creator"), creator))
    check("record agent", same_addr(main_rec.get("assigned_agent"), agent))
    check("record policy hash", main_rec.get("policy_hash") == POLICY_HASH)
    check("record permission linkage", main_rec.get("permission_id") == PERMISSION_ID)
    check("record deadline", main_rec.get("deadline") == deadline)
    check("record review period", main_rec.get("review_period") == REVIEW_PERIOD)
    check("record created_at set", bool(main_rec.get("created_at")))
    saved = json.loads(CONFIG.read_text())
    check("records persisted in config file",
          set(saved.get("agent_tasks", {})) == expected_records)
    check("permission linkage persisted in config file",
          saved.get("agent_tasks", {}).get("e2e-main", {}).get("permission_id") == PERMISSION_ID)

    chain_records = {
        r["name"]: r for r in await tosctl_json("agent", "task", "ls", "--on-chain")}
    check("on-chain list has no lookup errors",
          all("chain_error" not in record for record in chain_records.values()),
          str(chain_records))
    check("on-chain list reports lifecycle statuses", {
        name: record.get("chain_status") for name, record in chain_records.items()
    } == {
        "e2e-main": "settled",
        "e2e-controller": "settled",
        "e2e-claim": "settled",
        "e2e-dispute": "settled",
        "e2e-reject": "rejected",
        "e2e-cancel": "cancelled",
        "e2e-timeout": "expired",
    }, str(chain_records))
    check("on-chain list reports permission hashes",
          all(record.get("chain_permission_hash") ==
              hashlib.sha256(PERMISSION_ID.encode()).hexdigest()
              for record in chain_records.values()), str(chain_records))

    settled_records = await tosctl_json(
        "agent", "task", "ls", "--on-chain", "--status", "settled")
    check("status filter returns settled tasks",
          {record["name"] for record in settled_records} == {
              "e2e-main", "e2e-controller", "e2e-claim", "e2e-dispute"},
          str(settled_records))
    account_records = await tosctl_json(
        "agent", "task", "ls", "--on-chain", "--agent", agent_account)
    check("agent filter uses dynamic on-chain assignment",
          {record["name"] for record in account_records} == {
              "e2e-controller", "e2e-claim", "e2e-reject"}, str(account_records))
    unassigned_records = await tosctl_json(
        "agent", "task", "ls", "--on-chain", "--unassigned")
    check("unassigned filter observes claimed task", not unassigned_records,
          str(unassigned_records))
    creator_records = await tosctl_json(
        "agent", "task", "ls", "--creator", creator)
    check("creator filter returns all owned tasks", len(creator_records) == 7,
          str(creator_records))


async def main() -> int:
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl binary not found at {TOSCTL} "
              f"(build with: cargo build --manifest-path tosctl/src/Cargo.toml -p tosctl)",
              file=sys.stderr)
        return 2

    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    write_config()
    install = Install(BUILD_DIR, REPO)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    # base_port keeps the throwaway localnet clear of any long-running
    # systemd testnet that occupies the default 2000-range ports.
    async with Network(install, WORKDIR / "net", base_port=23000) as network:
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
