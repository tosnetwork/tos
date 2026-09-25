#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
proof-attestation-e2e.py — real-localnet acceptance of the Proof Attestation
contract and its `tosctl agent attestation` CLI.

Boots a single-process local TOS chain (same machinery as
agent-task-escrow-e2e.py), provisions a file vault plus a tosctl config,
creates and funds owner/outsider wallets and two ed25519 vault keys, then
drives the full lifecycle through the real `tosctl agent attestation` CLI
against the running validator -- crucially, this exercises the real
`--signer-vault-key` signing path (the CLI reads the vault secret and signs
locally with `ed25519_dalek`/the vault's ed25519 backend) against the real
compiled contract's `CHKSIGNU` verification, on a live node:

  deploy (signer-vault-key: reviewer-key) -> local record persisted ->
    on-chain state matches
  send attest (outsider funds it; permissionless) -> accepted, state updated
  send attest with a different (wrong) key's signature -> on-chain rejected,
    state unchanged
  send rotate-key (owner) -> resets the attestation; non-owner rejected
  send attest with the now-stale old key -> rejected; with the new key ->
    accepted
  send revoke (owner) -> blocks further attestations; non-owner rejected

Exit code 0 iff every check passes.

Run from the repository root: uv run python scripts/proof-attestation-e2e.py
"""
import asyncio
import base64
import json
import os
import shutil
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
RPC = "127.0.0.1:19146"
WORKDIR = REPO / "test/integration/.proof-attestation-e2e"
RPC_TRANSCRIPT = WORKDIR / "rpc-transcript.jsonl"
CLI_TRANSCRIPT = WORKDIR / "cli-transcript.jsonl"
NEGATIVE_EVIDENCE = WORKDIR / "negative-evidence.jsonl"
CONFIG = WORKDIR / "tosctl-e2e-config.json"
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000007"
NANO = 1_000_000_000

SUBJECT_HASH = "11" * 32
ATTESTED_HASH_1 = "22" * 32
ATTESTED_HASH_2 = "33" * 32

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


async def attestation_show(name: str):
    return await tosctl_json("agent", "attestation", "show", "--name", name)


async def send_op(operation: str, name: str, frm: str, *extra: str) -> str:
    return await tosctl(
        "agent", "attestation", "send", "--operation", operation, "--name", name,
        "--from", frm, "--yes", *extra,
    )


async def rejected_operation(label: str, address: str, payer: str, expected_exit: int,
                             operation: str, name: str, frm: str, *extra: str) -> None:
    before_state = await attestation_show(name)
    before_head = finalized_mc_header()
    wallet_lt = last_lt(payer)
    contract_lt = last_lt(address)
    receipt = await send_op(operation, name, frm, *extra)
    deadline = time.monotonic() + 45
    wallet_tx = contract_tx = None
    while time.monotonic() < deadline:
        wallet_rows = transactions_after(payer, wallet_lt)
        if wallet_rows:
            if len(wallet_rows) != 1:
                raise RuntimeError(f"{label}: wallet history contains multiple new transactions")
            wallet_tx = wallet_rows[0]
            outgoing = wallet_tx.get("out_msgs") or []
            if (wallet_tx.get("aborted") is not False
                    or wallet_tx.get("compute", {}).get("success") is not True
                    or wallet_tx.get("action", {}).get("success") is not True
                    or len(outgoing) != 1
                    or not same_addr(outgoing[0].get("destination"), address)):
                raise RuntimeError(f"{label}: wallet transaction did not send to attestation")
            contract_rows = transactions_after(address, contract_lt)
            if contract_rows:
                if len(contract_rows) != 1:
                    raise RuntimeError(f"{label}: multiple new attestation transactions")
                contract_tx = contract_rows[0]
                if (contract_tx.get("in_msg") or {}).get("hash") != outgoing[0].get("hash"):
                    raise RuntimeError(f"{label}: attestation inbound hash differs from wallet outbound")
                break
        await asyncio.sleep(1)
    if contract_tx is None or wallet_tx is None:
        raise RuntimeError(f"{label}: exact wallet-to-attestation transaction not observed")
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
            state = await attestation_show(name)
            observations.append({"head": head, "state": state})
            if state != before_state:
                raise RuntimeError(f"{label}: attestation state changed after rejected transaction")
            last_seqno = head["id"]["seqno"]
        else:
            await asyncio.sleep(1)
    if len(observations) != 2:
        raise RuntimeError(f"{label}: finalized masterchain did not advance twice")
    record_jsonl(NEGATIVE_EVIDENCE, {"label": label, "expected_exit": expected_exit,
                 "cli_receipt": receipt, "before_state": before_state,
                 "before_head": before_head, "wallet_transaction": wallet_tx,
                 "attestation_transaction": contract_tx, "observations": observations})
    check(label, True)


async def run_checks(faucet) -> None:
    print("\n=== provision: tosctl wallets and vault keys ===")
    if not await wait_rpc_ready():
        check("json-rpc endpoint ready", False, f"no response from http://{RPC}/jsonRPC")
        return
    print(f"  json-rpc ready at http://{RPC}/jsonRPC")

    for name in ("owner", "outsider"):
        await tosctl("wallet", "create", "-n", name, "-v", "V3R2", "-w", "0")
    owner = await wallet_address("owner")
    outsider = await wallet_address("outsider")
    print(f"  owner:    {owner}\n  outsider: {outsider}")

    for name, addr in (("owner", owner), ("outsider", outsider)):
        await faucet.send(faucet_transfer(faucet, addr, 50))
        check(f"{name} funded", await wait_balance_at_least(addr, 49 * NANO))
    for name in ("owner", "outsider"):
        await tosctl("wallet", "activate", "-n", name)
    for name, addr in (("owner", owner), ("outsider", outsider)):
        active = await poll_predicate(
            lambda a=addr: rpc_call("getAddressState", address=a).get("result") == "active")
        check(f"{name} wallet active", bool(active))

    await tosctl("key", "add", "--name", "reviewer-key")
    await tosctl("key", "add", "--name", "wrong-key")
    await tosctl("key", "add", "--name", "new-reviewer-key")

    print("\n=== deploy: Proof Attestation ===")
    deploy = await tosctl_json(
        "agent", "attestation", "deploy", "--name", "case-1",
        "--owner", owner, "--signer-vault-key", "reviewer-key",
        "--subject-hash", SUBJECT_HASH,
        "--from", "owner", "--amount", "0.1", "--yes",
    )
    address = deploy["address"]
    print(f"  attestation: {address}")
    check("deployed and active on chain", await poll_predicate(
        lambda: rpc_call("getAddressState", address=address).get("result") == "active"))

    data = await attestation_show("case-1")
    check("owner recorded on-chain", same_addr(data["owner"], owner), str(data))
    check("not revoked initially", data["revoked"] is False, str(data))
    check("no attestation initially", data["has_attestation"] is False, str(data))
    reviewer_key_pub = data["public_key"]

    print("\n=== attest: permissionless, valid signature ===")
    await send_op("attest", "case-1", "outsider",
                  "--attested-hash", ATTESTED_HASH_1, "--signer-vault-key", "reviewer-key")
    data = await attestation_show("case-1")
    check("attestation accepted", data["has_attestation"] is True, str(data))
    check("attested hash matches", data["attested_hash"] == ATTESTED_HASH_1, str(data))
    check("attested_at is set", data["attested_at"] > 0, str(data))

    print("\n=== attest: wrong key rejected on-chain ===")
    await rejected_operation("wrong-key attestation rejected", address, outsider, 2101,
                             "attest", "case-1", "outsider", "--attested-hash",
                             ATTESTED_HASH_2, "--signer-vault-key", "wrong-key")

    print("\n=== rotate-key: owner only, resets attestation ===")
    await rejected_operation("non-owner rotate-key rejected", address, outsider, 2102,
                             "rotate-key", "case-1", "outsider",
                             "--new-signer-vault-key", "new-reviewer-key")

    await send_op("rotate-key", "case-1", "owner",
                  "--new-signer-vault-key", "new-reviewer-key")
    data = await attestation_show("case-1")
    check("public key rotated", data["public_key"] != reviewer_key_pub, str(data))
    check("attestation reset by rotation", data["has_attestation"] is False, str(data))

    print("\n=== attest after rotation: old key rejected, new key accepted ===")
    await rejected_operation("stale old-key attestation rejected", address, outsider, 2101,
                             "attest", "case-1", "outsider", "--attested-hash",
                             ATTESTED_HASH_1, "--signer-vault-key", "reviewer-key")

    await send_op("attest", "case-1", "outsider",
                  "--attested-hash", ATTESTED_HASH_2, "--signer-vault-key", "new-reviewer-key")
    data = await attestation_show("case-1")
    check("new-key attestation accepted", data["has_attestation"] is True, str(data))
    check("new attested hash matches", data["attested_hash"] == ATTESTED_HASH_2, str(data))

    print("\n=== revoke: owner only, permanent ===")
    await rejected_operation("non-owner revoke rejected", address, outsider, 2102,
                             "revoke", "case-1", "outsider")

    await send_op("revoke", "case-1", "owner")
    data = await attestation_show("case-1")
    check("revoked", data["revoked"] is True, str(data))

    await rejected_operation("attestation after revoke rejected", address, outsider, 2100,
                             "attest", "case-1", "outsider", "--attested-hash",
                             ATTESTED_HASH_1, "--signer-vault-key", "new-reviewer-key")

    print("\n=== persisted local record ===")
    records = {r["name"]: r for r in await tosctl_json("agent", "attestation", "ls")}
    check("record tracked locally", "case-1" in records, str(sorted(records)))
    check("record owner matches", same_addr(records["case-1"]["owner"], owner),
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

    async with Network(install, WORKDIR / "net", base_port=23700) as network:
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
