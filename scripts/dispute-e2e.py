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
RPC = "127.0.0.1:18946"
WORKDIR = REPO / "test/integration/.dispute-e2e"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000005"
NANO = 1_000_000_000

SUBJECT_HASH = "11" * 32
CLAIMANT_EVIDENCE_HASH = "22" * 32
RESPONDENT_EVIDENCE_HASH = "33" * 32
RULING_HASH = "44" * 32

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


async def send_op(operation: str, name: str, frm: str, *extra: str, may_fail: bool = False) -> str:
    return await tosctl(
        "agent", "dispute", "send", "--operation", operation, "--name", name,
        "--from", frm, "--yes", *extra, may_fail=may_fail,
    )


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
    await send_op("submit-respondent-evidence", "case-1", "outsider",
                  "--respondent-evidence-hash", RESPONDENT_EVIDENCE_HASH, may_fail=True)
    data = await dispute_show("case-1")
    check("outsider submit rejected", data["status"] == "open", str(data))

    await send_op("submit-respondent-evidence", "case-1", "respondent",
                  "--respondent-evidence-hash", RESPONDENT_EVIDENCE_HASH)
    data = await dispute_show("case-1")
    check("respondent evidence recorded", data["status"] == "evidence_submitted", str(data))
    check("respondent evidence hash matches",
          data["respondent_evidence_hash"] == RESPONDENT_EVIDENCE_HASH, str(data))

    print("\n=== rule (claimant wins) ===")
    await send_op("rule", "case-1", "outsider", "--ruling", "claimant",
                  "--ruling-hash", RULING_HASH, may_fail=True)
    data = await dispute_show("case-1")
    check("outsider rule rejected", data["status"] == "evidence_submitted", str(data))

    await send_op("rule", "case-1", "reviewer", "--ruling", "claimant", "--ruling-hash", RULING_HASH)
    data = await dispute_show("case-1")
    check("resolved with claimant ruling", data["status"] == "resolved", str(data))
    check("ruling is claimant", data["ruling"] == "claimant", str(data))
    check("ruling hash recorded", data["ruling_hash"] == RULING_HASH, str(data))

    print("\n=== already-resolved rejection ===")
    await send_op("submit-respondent-evidence", "case-1", "respondent",
                  "--respondent-evidence-hash", "55" * 32, may_fail=True)
    data = await dispute_show("case-1")
    check("action after resolution rejected",
          data["respondent_evidence_hash"] == RESPONDENT_EVIDENCE_HASH, str(data))

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
    data = await dispute_show("case-2")
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

    await send_op("rule", "case-3", "reviewer", "--ruling", "claimant",
                  "--ruling-hash", RULING_HASH, may_fail=True)
    data = await dispute_show("case-3")
    check("rule without attestation rejected", data["status"] == "open", str(data))

    await send_op("rule", "case-3", "reviewer", "--ruling", "claimant",
                  "--ruling-hash", RULING_HASH,
                  "--signer-vault-key", "wrong-dispute-attestor-key", may_fail=True)
    data = await dispute_show("case-3")
    check("rule with wrong attestor key rejected", data["status"] == "open", str(data))

    await send_op("rule", "case-3", "reviewer", "--ruling", "claimant",
                  "--ruling-hash", RULING_HASH, "--signer-vault-key", "dispute-attestor-key")
    data = await dispute_show("case-3")
    check("attestor dispute resolved", data["status"] == "resolved", str(data))

    print("\n=== persisted local records ===")
    records = {r["name"]: r for r in await tosctl_json("agent", "dispute", "ls")}
    check("all records tracked locally", {"case-1", "case-2", "case-3"} <= set(records),
          str(sorted(records)))
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
    prepare_config()
    install = Install(BUILD_DIR, REPO)
    import logging
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    async with Network(install, WORKDIR / "net", base_port=23500) as network:
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
