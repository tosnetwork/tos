#!/usr/bin/env python3
"""
wc0-token-index-e2e.py — end-to-end proof of the wc=0 wallet index's
*state-verified* token indexing (https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-wc0-wallet-index.md).

Boots a single-process local TOS chain (same machinery as localnet-jsonrpc.py),
then exercises the security-critical verification path through real contracts:

  ACCEPT  Deploy a genuine TEP-74 jetton master, mint to a fresh owner O. The
          owner's jetton-wallet W is created on-chain; the indexer must run
          get_wallet_data(W) + the master's get_wallet_address(O) round-trip,
          confirm W, and index (O, master). getAccountJettons(O) must list it.

  REJECT  A plain wallet (NOT a jetton wallet) sends a *forged*
          transfer_notification to a victim V. The indexer nominates the
          sender as a candidate, runs get_wallet_data on it, which fails —
          so nothing is indexed. getAccountJettons(V) must stay empty.

Together these prove the indexer trusts committed contract state, not message
claims. Exit code 0 iff both scenarios pass.

Run from the repository root: uv run python scripts/wc0-token-index-e2e.py
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from tostester.pq_initial_validator import make_deterministic_pq_initial_validator
from contract import tos
from pytosiq_core import (
    Address, Cell, InternalMsgInfo, MessageAny, StateInit, WalletMessage, begin_cell,
)

REPO = Path(__file__).resolve().parents[1]

# Op-codes (TEP-74).
OP_MINT = 21
OP_INTERNAL_TRANSFER = 0x178D4519
OP_TRANSFER_NOTIFICATION = 0x7362D09C

MINTER_BOC = REPO / "build/slice1-gas-parity/jetton-minter-func.boc"
WALLET_BOC = REPO / "build/slice1-gas-parity/jetton-wallet-func.boc"

RPC = "127.0.0.1:18545"
WORKDIR = REPO / "test/integration/.wc0-token-index-e2e"
RPC_TRANSCRIPT = WORKDIR / "rpc-transcript.jsonl"
CHAIN_EVIDENCE = WORKDIR / "chain-evidence.jsonl"


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
    result = json.loads(raw.decode())
    if status != 200 or "error" in result or "result" not in result:
        raise RuntimeError(f"{method} RPC failed: HTTP {status}, {result}")
    return result


def record_jsonl(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def record_provenance() -> None:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    tracked = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO, text=True)
    if tracked.strip():
        raise RuntimeError("wc0 index source tree has uncommitted tracked changes")
    build_command = ["cmake", "--build", str(REPO / "build"),
                     "--target", "slice1_gas_parity_contracts"]
    build = subprocess.run(build_command, cwd=REPO, capture_output=True)
    (WORKDIR / "boc-build.json").write_text(json.dumps({
        "command": build_command, "exit_code": build.returncode,
        "stdout_base64": base64.b64encode(build.stdout).decode(),
        "stderr_base64": base64.b64encode(build.stderr).decode(),
    }, sort_keys=True, indent=2) + "\n")
    if build.returncode != 0:
        raise RuntimeError("jetton BOC build failed; see boc-build.json")
    paths = [Path(__file__).resolve(), MINTER_BOC, WALLET_BOC,
             REPO / "CMakeLists.txt",
             REPO / "crypto/func/auto-tests/legacy_tests/jetton-minter/jetton-minter.fc",
             REPO / "crypto/func/auto-tests/legacy_tests/jetton-wallet/jetton-wallet.fc",
             REPO / "build/crypto/func", REPO / "build/crypto/fift",
             REPO / "build/validator-engine/validator-engine"]
    hashes = {str(path.relative_to(REPO)): sha256_file(path) for path in paths}
    (WORKDIR / "provenance.json").write_text(
        json.dumps({"source_head": head, "build_command": build_command,
                    "sha256": hashes}, sort_keys=True, indent=2) + "\n")


def finalized_mc_header() -> dict:
    block = rpc_call("getMasterchainInfo")["result"]["last"]
    header = rpc_call("getBlockHeader", workchain=block["workchain"],
                      shard=str(block["shard"]), seqno=block["seqno"])["result"]
    if any(header["id"][field] != block[field]
           for field in ("workchain", "shard", "seqno", "root_hash", "file_hash")):
        raise RuntimeError("finalized masterchain header did not match its block ID")
    return {"id": block, "gen_utime": int(header["gen_utime"])}


def last_lt(address: str) -> int:
    info = rpc_call("getAddressInformation", address=address)["result"]
    return int((info.get("last_transaction_id") or {}).get("lt", 0))


def transactions_after(address: str, baseline_lt: int) -> list[dict]:
    rows = rpc_call("getTransactions", address=address, limit=10)["result"]
    return [row for row in rows if int(row["transaction_id"]["lt"]) > baseline_lt]


def same_addr(left: str, right: str) -> bool:
    try:
        return (Address(left).to_str(is_user_friendly=False).lower()
                == Address(right).to_str(is_user_friendly=False).lower())
    except Exception:
        return False


async def observe_edge(label: str, sender: str, target: str, sender_lt: int,
                       target_lt: int, require_target_success: bool) -> dict:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        sender_rows = transactions_after(sender, sender_lt)
        target_rows = transactions_after(target, target_lt)
        if len(sender_rows) > 1 or len(target_rows) > 1:
            raise RuntimeError(f"{label}: multiple new sender or target transactions")
        if sender_rows and target_rows:
            sent, received = sender_rows[0], target_rows[0]
            outgoing = [msg for msg in sent.get("out_msgs") or []
                        if same_addr(msg.get("destination"), target)]
            if (sent.get("aborted") is not False
                    or (sent.get("compute") or {}).get("success") is not True
                    or (sent.get("action") or {}).get("success") is not True
                    or len(outgoing) != 1
                    or not outgoing[0].get("hash")
                    or (received.get("in_msg") or {}).get("hash") != outgoing[0]["hash"]
                    or not same_addr((received.get("in_msg") or {}).get("source"), sender)):
                raise RuntimeError(f"{label}: sender-to-target message did not match")
            if require_target_success and (
                    received.get("aborted") is not False
                    or (received.get("compute") or {}).get("success") is not True
                    or (received.get("action") or {}).get("success") is not True):
                raise RuntimeError(f"{label}: target transaction did not succeed")
            record_jsonl(CHAIN_EVIDENCE, {"label": label, "sender_tx": sent,
                         "target_tx": received, "outgoing": outgoing[0]})
            return received
        await asyncio.sleep(1)
    raise RuntimeError(f"{label}: exact sender-to-target transaction not observed")


async def later_final_heads(before: dict, count: int = 2) -> list[dict]:
    deadline = time.monotonic() + 45
    heads = []
    last_seqno = before["id"]["seqno"]
    while time.monotonic() < deadline and len(heads) < count:
        head = finalized_mc_header()
        if head["id"]["seqno"] > last_seqno:
            heads.append(head)
            last_seqno = head["id"]["seqno"]
        else:
            await asyncio.sleep(1)
    if len(heads) != count:
        raise RuntimeError("finalized masterchain did not advance after observed transaction")
    return heads


def get_jettons(addr: str):
    r = rpc_call("getAccountJettons", address=addr)
    return r["result"]["jettons"]


def stack_entry_kind(entry) -> str:
    if isinstance(entry, list) and len(entry) == 2:
        return entry[0]
    if isinstance(entry, dict):
        return {
            "tvm.stackEntryNumber": "num", "tvm.stackEntryCell": "cell",
            "tvm.stackEntrySlice": "slice",
        }.get(entry.get("@type"), "")
    return ""


def stack_address(entry) -> str:
    kind = stack_entry_kind(entry)
    if kind not in ("slice", "cell"):
        raise RuntimeError("jetton getter did not return an address slice")
    payload = entry[1] if isinstance(entry, list) else entry[kind]
    address = Cell.one_from_boc(base64.b64decode(payload["bytes"], validate=True))
    return address.begin_parse().load_address().to_str(is_user_friendly=False)


def getter_stack(address: str, method: str, stack: list) -> list:
    result = rpc_call("runGetMethodStd", address=address, method=method,
                      stack=stack)["result"]
    if result.get("exit_code") not in (0, 1) or not isinstance(result.get("stack"), list):
        raise RuntimeError(f"{method} did not succeed at {address}")
    return result["stack"]


def verify_indexed_wallet(wallet: str, owner: str, master: str) -> None:
    data = getter_stack(wallet, "get_wallet_data", [])
    if len(data) != 4:
        raise RuntimeError("jetton wallet getter returned unexpected stack depth")
    kinds = [stack_entry_kind(entry) for entry in data]
    if kinds == ["cell", "slice", "slice", "num"]:
        observed_master, observed_owner = stack_address(data[1]), stack_address(data[2])
    elif kinds == ["num", "slice", "slice", "cell"]:
        observed_owner, observed_master = stack_address(data[1]), stack_address(data[2])
    else:
        raise RuntimeError(f"jetton wallet getter returned unexpected stack types: {kinds}")
    if not same_addr(observed_owner, owner) or not same_addr(observed_master, master):
        raise RuntimeError("indexed jetton wallet getter owner/master differs")
    owner_slice = begin_cell().store_address(Address(owner)).end_cell()
    resolver_input = [["slice", {"bytes": base64.b64encode(owner_slice.to_boc()).decode()}]]
    resolved = getter_stack(master, "get_wallet_address", resolver_input)
    if len(resolved) != 1 or not same_addr(stack_address(resolved[0]), wallet):
        raise RuntimeError("jetton master does not resolve back to indexed wallet")


def indexed_entry(owner: str, master: str) -> dict | None:
    matches = [row for row in get_jettons(owner)
               if row.get("jetton_master", "").lower() == master.lower()]
    if len(matches) > 1:
        raise RuntimeError("duplicate jetton master rows in owner index")
    if not matches:
        return None
    entry = matches[0]
    wallet = entry.get("jetton_wallet", "")
    if (not wallet.startswith("0:") or len(wallet) != 66
            or wallet[2:] == "0" * 64 or int(entry.get("last_lt", 0)) <= 0):
        raise RuntimeError("indexed jetton row lacks an observed wallet transaction")
    if rpc_call("getAddressState", address=wallet)["result"] != "active":
        raise RuntimeError("indexed jetton wallet is not active")
    verify_indexed_wallet(wallet, owner, master)
    return entry


async def victim_index_after_canary(victim: str, canary_owner: str,
                                    master: str) -> tuple[dict, list]:
    canary = await poll(lambda: indexed_entry(canary_owner, master), timeout=90)
    if not isinstance(canary, dict):
        raise RuntimeError("post-forgery canary mint was not indexed")
    return canary, get_jettons(victim)


def check_attacker_self_index(attacker: str, failures: list[str]) -> None:
    jettons = get_jettons(attacker)
    record_jsonl(CHAIN_EVIDENCE, {"label": "attacker self index",
                 "attacker": attacker, "jettons": jettons})
    if jettons:
        print(f"[reject] FAIL — attacker self jetton list: {jettons}")
        failures.append("attacker self-claim was indexed")


def require_later_same_shard(forged_tx: dict, canary_tx: dict) -> None:
    forged = forged_tx.get("block_id") or {}
    canary = canary_tx.get("block_id") or {}
    if (not forged.get("root_hash") or not forged.get("file_hash")
            or not canary.get("root_hash") or not canary.get("file_hash")
            or forged.get("workchain") != 0 or canary.get("workchain") != 0
            or forged.get("shard") != canary.get("shard")
            or int(canary.get("seqno", 0)) <= int(forged.get("seqno", 0))):
        raise RuntimeError("post-forgery canary is not in a later block of the same shard")


def load_code(path: Path) -> Cell:
    return Cell.one_from_boc(path.read_bytes())


def jetton_master_state_init(admin: Address, wallet_code: Cell) -> StateInit:
    # jetton-minter load_data: total_supply(coins) admin(addr) content(^) wallet_code(^)
    content = begin_cell().store_uint(0, 8).end_cell()  # on-chain content marker
    data = (
        begin_cell()
        .store_coins(0)
        .store_address(admin)
        .store_ref(content)
        .store_ref(wallet_code)
        .end_cell()
    )
    return StateInit(code=load_code(MINTER_BOC), data=data)


def mint_body(owner: Address, master: Address, jetton_amount: int, forward_ton: int) -> Cell:
    # master_msg is the internal_transfer body the master forwards to W.
    master_msg = (
        begin_cell()
        .store_uint(OP_INTERNAL_TRANSFER, 32)
        .store_uint(0, 64)               # query_id
        .store_coins(jetton_amount)
        .store_address(master)           # from_address
        .store_address(owner)            # response_address (non-none → excesses)
        .store_coins(forward_ton)        # forward_ton_amount
        .store_bit(0)                    # forward_payload: inline empty
        .end_cell()
    )
    return (
        begin_cell()
        .store_uint(OP_MINT, 32)
        .store_uint(0, 64)               # query_id
        .store_address(owner)            # to_address
        .store_coins(forward_ton + 100_000_000)  # TOS forwarded to the wallet
        .store_ref(master_msg)
        .end_cell()
    )


def forged_notification_body(fake_from: Address) -> Cell:
    # A non-jetton-wallet contract claims it sent tokens. No master vouches for it.
    return (
        begin_cell()
        .store_uint(OP_TRANSFER_NOTIFICATION, 32)
        .store_uint(0, 64)               # query_id
        .store_coins(1000)               # jetton amount (claimed)
        .store_address(fake_from)        # from
        .store_bit(0)                    # forward_payload: inline empty
        .end_cell()
    )


def internal_message(dest: Address, value, body: Cell, src: Address) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=src, dest=dest, value=value,
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0,
            ),
            init=None,
            body=body,
        ),
    )


async def poll(predicate, timeout=60.0, interval=1.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception as e:
            last = e
        await asyncio.sleep(interval)
    return last


async def main() -> int:
    workdir = WORKDIR
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    record_provenance()
    install = Install(REPO / "build", REPO)
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    failures = []
    async with Network(install, workdir) as network:
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
            wallet_code = load_code(WALLET_BOC)

            # ---------------- ACCEPT: genuine jetton mint ----------------
            print("\n=== ACCEPT: genuine jetton mint must be indexed ===")
            master_si = jetton_master_state_init(faucet.address, wallet_code)
            master_addr = Address((0, master_si.serialize().hash))
            print(f"[accept] jetton master: {master_addr.to_str()}")

            # Deploy the master (faucet → master with StateInit).
            await faucet.send(WalletMessage(
                send_mode=3,
                message=MessageAny(
                    info=InternalMsgInfo(
                        ihr_disabled=True, bounce=False, bounced=False,
                        src=faucet.address, dest=master_addr, value=tos(2),
                        ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0,
                    ),
                    init=master_si,
                    body=Cell.empty(),
                ),
            ))
            master_active = await poll(
                lambda: rpc_call("getAddressState", address=master_addr.to_str())
                .get("result") == "active")
            print(f"[accept] master active: {master_active}")
            if master_active is not True:
                raise RuntimeError("jetton master deployment was not observed active")

            owner = Address((0, bytes([0x11]) * 32))
            print(f"[accept] mint owner: {owner.to_str()}")
            faucet_addr = faucet.address.to_str(is_user_friendly=False)
            master_raw = master_addr.to_str(is_user_friendly=False)
            mint_sender_lt, mint_target_lt = last_lt(faucet_addr), last_lt(master_raw)
            mint_before_head = finalized_mc_header()
            await faucet.send(internal_message(
                master_addr, tos(1), mint_body(owner, master_addr, 1000, 0), faucet.address))
            await observe_edge("genuine mint", faucet_addr, master_raw,
                               mint_sender_lt, mint_target_lt, True)
            mint_heads = await later_final_heads(mint_before_head)
            record_jsonl(CHAIN_EVIDENCE, {"label": "genuine mint finality",
                         "before_head": mint_before_head, "after_heads": mint_heads})

            want_master = "0:" + master_si.serialize().hash.hex()

            found = await poll(lambda: indexed_entry(owner.to_str(), want_master), timeout=90)
            if isinstance(found, dict):
                print(f"[accept] PASS — indexed entry: {found}")
            else:
                print(f"[accept] FAIL — owner jetton list: {get_jettons(owner.to_str())}")
                failures.append("genuine jetton not indexed")

            # ---------------- REJECT: forged notification ----------------
            print("\n=== REJECT: forged notification from a non-wallet must NOT be indexed ===")
            from contract import WalletV1Blueprint  # mirror localnet script's import
            attacker_bp = WalletV1Blueprint(workchain=0)
            attacker = await faucet.deploy(attacker_bp, tos(2))
            print(f"[reject] attacker (plain wallet): {attacker_bp.address.to_str()}")
            attacker_active = await poll(
                lambda: rpc_call("getAddressState", address=attacker_bp.address.to_str())
                .get("result") == "active")
            if attacker_active is not True:
                raise RuntimeError("attacker plain wallet was not observed active")

            victim = Address((0, bytes([0x22]) * 32))
            print(f"[reject] victim: {victim.to_str()}")
            # The attacker (a normal wallet, no get_wallet_data) forges a notification.
            attacker_raw = attacker_bp.address.to_str(is_user_friendly=False)
            victim_raw = victim.to_str(is_user_friendly=False)
            forged_sender_lt, forged_target_lt = last_lt(attacker_raw), last_lt(victim_raw)
            forged_before_head = finalized_mc_header()
            await attacker.send(internal_message(
                victim, tos(0.2), forged_notification_body(attacker_bp.address),
                attacker_bp.address))
            forged_target_tx = await observe_edge(
                "forged notification", attacker_raw, victim_raw,
                forged_sender_lt, forged_target_lt, False)
            forged_heads = await later_final_heads(forged_before_head)

            # A later genuine mint must reach this same index before an empty
            # victim list can count as evidence that the forged event was seen.
            canary_owner = Address((0, bytes([0x33]) * 32))
            canary_raw = canary_owner.to_str(is_user_friendly=False)
            if get_jettons(canary_raw):
                raise RuntimeError("canary owner index was nonempty before its mint")
            canary_sender_lt, canary_target_lt = last_lt(faucet_addr), last_lt(master_raw)
            canary_before_head = finalized_mc_header()
            await faucet.send(internal_message(
                master_addr, tos(1), mint_body(canary_owner, master_addr, 1000, 0),
                faucet.address))
            canary_master_tx = await observe_edge(
                "post-forgery canary mint", faucet_addr, master_raw,
                canary_sender_lt, canary_target_lt, True)
            canary_heads = await later_final_heads(canary_before_head)
            require_later_same_shard(forged_target_tx, canary_master_tx)
            canary_entry, victim_js = await victim_index_after_canary(
                victim_raw, canary_raw, want_master)
            owner_js = get_jettons(owner.to_str())
            owner_control = any(j.get("jetton_master", "").lower() == want_master.lower()
                                for j in owner_js)
            record_jsonl(CHAIN_EVIDENCE, {"label": "forged notification finality",
                         "before_head": forged_before_head, "after_heads": forged_heads,
                         "canary_before_head": canary_before_head,
                         "forged_target_tx": forged_target_tx,
                         "canary_master_tx": canary_master_tx,
                         "canary_after_heads": canary_heads,
                         "canary_owner": canary_raw, "canary_entry": canary_entry,
                         "victim_jettons": victim_js, "owner_jettons": owner_js})
            if not owner_control:
                raise RuntimeError("positive owner index control disappeared during rejection check")
            if victim_js:
                print(f"[reject] FAIL — victim wrongly indexed: {victim_js}")
                failures.append("forged notification was indexed")
            else:
                print("[reject] PASS — victim jetton list empty (forged claim rejected)")

            # Sanity: the attacker's own forged self-claim must also be absent.
            check_attacker_self_index(attacker_raw, failures)
        finally:
            for t in (node_task, dht_task):
                t.cancel()
            await asyncio.gather(node_task, dht_task, return_exceptions=True)

    return 1 if failures else 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    print("\n=== RESULT:", "ALL PASS" if rc == 0 else "FAILURES", "===")
    sys.exit(rc)
