#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
agent-account-mldsa44-strict-rehearsal.py -- local-chain rehearsal of the
irreversible strict cutover of an ML-DSA-44 Agent Account, driven through
tosctl against a real validator on an isolated network.

  install (c1) -> cutover refused while the staged module has authenticated
  nothing -> send relayed by a non-owner wallet r1, rebroadcast byte for byte
  through r2, resolved by three RPC views -> cutover refusals (mode 3, mode 1,
  a mistyped address) -> cutover to mode 2 -> a second cutover refused ->
  strict rotation of the root to c2 -> the old root refused (by tosctl, and on
  chain: a submission c1 signed earlier, relayed again through c1's module,
  is refused by the account) -> send with the new root -> the Ed25519
  controller refused in strict mode.

The network is disposable: its own directory, ports found free with `ss -ltn`,
one PQ validator, two observer RPC nodes and a DHT node, a fresh AUTH network
tag; nothing under /data and no system service is touched. Run it in its own
process group under the thermal guard. It refuses to start from a tree with
uncommitted changes, records the commit, tree, binaries and code hashes it
exercised in evidence.json, and ends with "=== RESULT: ALL PASS ===" or the
failures.

Usage, from a clean checkout of the commit under test:
  TOSCTL=<tosctl built from this commit> TOS_BUILD_DIR=<node build> \
  TOS_SOURCE_DIR=<source tree of that build> REHEARSAL_DIR=<empty dir> \
  uv run --frozen python scripts/agent-account-mldsa44-strict-rehearsal.py
"""

import asyncio
import base64
import datetime
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", "/tos/build/pr371-rerun/build"))
SOURCE_DIR = Path(os.environ.get("TOS_SOURCE_DIR", str(REPO)))
TOSCTL = os.environ.get("TOSCTL", str(REPO / "tosctl/src/target/debug/tosctl"))
WORKDIR = Path(os.environ.get("REHEARSAL_DIR", str(REPO / "test/integration/.mldsa44-strict")))
MASTER_KEY = "0000000000000000000000000000000000000000000000000000000000000011"
NANO = 1_000_000_000
ERR_NOT_MODULE = 1800
ERR_LEGACY_DISABLED = 1807

failures: list[str] = []
evidence: dict = {"schema": "tos.agent-account.mldsa44-strict-rehearsal.v1", "steps": []}
RPC = ""
OBSERVER_RPCS: tuple[str, str] = ("", "")
CONFIG = Path("/dev/null/unset")
OBSERVER_CONFIGS: tuple[Path, Path] = (CONFIG, CONFIG)
PRIVATE_DIR = Path("/dev/null/unset")


def check(label: str, ok: bool, detail="") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}: {label}" + ("" if ok else f"  {detail}"))
    evidence["steps"].append({"check": label, "pass": bool(ok), "detail": str(detail)[:4000]})
    if not ok:
        failures.append(label)
    return ok


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def free_ports() -> tuple[int, list[int]]:
    """A base port with 400 free ports above it, and three RPC ports past them."""
    listening = set()
    out = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            try:
                listening.add(int(fields[3].rsplit(":", 1)[1]))
            except ValueError:
                pass
    for base in range(47_000, 60_000, 500):
        if not any(port in listening for port in range(base, base + 500)):
            return base, [base + 450, base + 451, base + 452]
    raise SystemExit("no free port range found")


def rpc_call(method: str, *, endpoint: str = "", **params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        f"http://{endpoint or RPC}/jsonRPC",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        return json.loads(response.read().decode())


def balance(address: str) -> int:
    return int(rpc_call("getAddressInformation", address=address)["result"]["balance"])


def chain_time() -> int:
    last = rpc_call("getMasterchainInfo")["result"]["last"]
    header = rpc_call(
        "getBlockHeader", workchain=last["workchain"], shard=str(last["shard"]), seqno=last["seqno"]
    )["result"]
    return int(header["gen_utime"])


def account_auth(address: str) -> dict:
    """The Agent Account's counters and auth state, parsed from its raw data."""
    from pytosiq_core import Cell

    info = rpc_call("getAddressInformation", address=address)["result"]
    s = Cell.one_from_boc(base64.b64decode(info["data"])).begin_parse()
    s.load_address()
    s.load_uint(256)
    s.load_uint(256)
    state = {"controller_epoch": s.load_uint(64), "seqno": s.load_uint(32)}
    s.load_uint(32)
    s.load_coins()
    s.load_ref()
    if s.remaining_refs == 0:
        state.update(mode=0, auth_epoch=0, auth_nonce=0, module_hash="00" * 32)
        return state
    a = s.load_ref().begin_parse()
    state.update(
        mode=a.load_uint(2),
        auth_epoch=a.load_uint(64),
        auth_nonce=a.load_uint(64),
        module_hash=f"{a.load_uint(256):064x}",
    )
    return state


def code_hash(address: str) -> str:
    from pytosiq_core import Cell

    info = rpc_call("getAddressInformation", address=address)["result"]
    return Cell.one_from_boc(base64.b64decode(info["code"])).hash.hex()


def norm(address: str) -> str:
    from pytosiq_core import Address

    return Address(address).to_str(is_user_friendly=False).lower()


async def tosctl(*args: str, may_fail: bool = False) -> tuple[int, str]:
    env = dict(os.environ)
    env["VAULT_URL"] = f"file://{PRIVATE_DIR}/vault.json?master_key={MASTER_KEY}"
    process = await asyncio.create_subprocess_exec(
        TOSCTL,
        *args,
        "-c",
        str(CONFIG),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout=600)
    except TimeoutError:
        process.kill()
        raise RuntimeError(f"tosctl {' '.join(args)} timed out")
    text = out.decode() + err.decode()
    evidence["steps"].append(
        {"tosctl": list(args), "exit": process.returncode, "output": text[-4000:]}
    )
    if process.returncode != 0 and not may_fail:
        raise RuntimeError(f"tosctl {' '.join(args)} failed:\n{text}")
    return process.returncode, out.decode()


def last_json(text: str) -> dict:
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise RuntimeError(f"no JSON line in output: {text[-2000:]}")


async def wait_for(predicate, timeout: float = 120.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        await asyncio.sleep(1)
    return False


def faucet_message(faucet, destination: str, amount: int, body=None, bounce=False):
    from pytosiq_core import (
        Address,
        Cell,
        CurrencyCollection,
        InternalMsgInfo,
        MessageAny,
        WalletMessage,
    )

    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=bounce,
                bounced=False,
                src=faucet.address,
                dest=Address(destination),
                value=CurrencyCollection(tomis=amount),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=None,
            body=body if body is not None else Cell.empty(),
        ),
    )


def journal_record(action_id: str) -> dict:
    path = PRIVATE_DIR / ".tosctl-agent-controller-journal" / "controller-actions.json"
    document = json.loads(path.read_text())
    return next(r for r in document["records"] if r["idempotency_key"] == action_id)


def write_configs():
    subprocess.run(
        [TOSCTL, "config", "generate", "-o", str(CONFIG), "--force"],
        check=True,
        env={**os.environ, "VAULT_URL": f"file://{PRIVATE_DIR}/vault.json?master_key={MASTER_KEY}"},
    )
    config = json.loads(CONFIG.read_text())
    config["chain_rpc"] = {"urls": [f"http://{RPC}/"], "api_key": None}
    config["elections"] = None
    config.pop("voting", None)
    CONFIG.write_text(json.dumps(config, indent=2))
    for path, endpoint in zip(OBSERVER_CONFIGS, OBSERVER_RPCS, strict=True):
        observer = dict(config)
        observer["chain_rpc"] = {"urls": [f"http://{endpoint}/"], "api_key": None}
        path.write_text(json.dumps(observer, indent=2))


def resolved_transfer_hash(
    account_rows: list, transaction_hash_hex: str, target: str, value: int
) -> str | None:
    """The hash of the one outbound transfer of `value` to `target` in the
    account transaction whose hash is `transaction_hash_hex`."""
    for row in account_rows:
        if base64.b64decode(row["transaction_id"]["hash"]).hex() != transaction_hash_hex:
            continue
        transfers = [
            message
            for message in row.get("out_msgs") or []
            if message.get("kind") == "internal"
            and norm(message.get("destination", "")) == target
            and int(message.get("value", "0")) == value
        ]
        return transfers[0]["hash"] if len(transfers) == 1 else None
    return None


def credit_matches(target_rows: list, message_hash: str, source: str, value: int) -> bool:
    """Whether one of the target's transactions took exactly that message."""
    return any(
        (row.get("in_msg") or {}).get("kind") == "internal"
        and (row.get("in_msg") or {}).get("hash") == message_hash
        and norm((row.get("in_msg") or {}).get("source", "")) == source
        and int((row.get("in_msg") or {}).get("value", "0")) == value
        for row in target_rows
    )


def self_test() -> None:
    """Offline: the credit predicate takes only the resolved message."""
    account = "0:" + "11" * 32
    target = "0:" + "22" * 32
    value = 200_000_000
    sent, other = base64.b64encode(b"\x01" * 32).decode(), base64.b64encode(b"\x02" * 32).decode()
    tx_hash = b"\x03" * 32
    account_rows = [
        {
            "transaction_id": {"hash": base64.b64encode(b"\x04" * 32).decode()},
            "out_msgs": [
                {"kind": "internal", "destination": target, "value": str(value), "hash": other}
            ],
        },
        {
            "transaction_id": {"hash": base64.b64encode(tx_hash).decode()},
            "out_msgs": [
                {"kind": "internal", "destination": target, "value": str(value), "hash": sent}
            ],
        },
    ]
    assert resolved_transfer_hash(account_rows, tx_hash.hex(), target, value) == sent
    assert resolved_transfer_hash(account_rows, (b"\x05" * 32).hex(), target, value) is None
    credit = {"kind": "internal", "source": account, "value": str(value), "hash": sent}
    assert credit_matches([{"in_msg": credit}], sent, account, value)
    # An equal-value credit from the same account under another message hash.
    assert not credit_matches([{"in_msg": {**credit, "hash": other}}], sent, account, value)
    assert not credit_matches(
        [{"in_msg": {**credit, "value": str(value + 1)}}], sent, account, value
    )
    assert not credit_matches(
        [{"in_msg": {**credit, "source": "0:" + "33" * 32}}], sent, account, value
    )
    print("REHEARSAL_SELF_TEST_OK")


async def send_and_resolve(
    account: str,
    controller: str,
    target: str,
    action_id: str,
    relayer: str,
    rebroadcast_relayer: str | None,
) -> dict:
    valid_until = chain_time() + 3_000
    args = (
        "agent",
        "account",
        "mldsa44-send",
        "-n",
        "agent-1",
        "--controller",
        controller,
        "--target",
        target,
        "--value",
        "0.2",
        "--valid-until",
        str(valid_until),
        "--action-id",
        action_id,
        "--relay-amount",
        "2",
        "--yes",
    )
    _, out = await tosctl(*args, "--relayer", relayer)
    sent = last_json(out)
    record = journal_record(action_id)
    result = {
        "sent": sent,
        "valid_until": valid_until,
        "submission_boc": record["exact_signed_boc_base64"],
        "submission_digest": record["exact_signed_boc_digest"],
    }
    if rebroadcast_relayer:
        _, out = await tosctl(*args, "--rebroadcast", "--relayer", rebroadcast_relayer)
        again = last_json(out)
        record = journal_record(action_id)
        relays = record.get("mldsa44_relays", [])
        check(
            "the rebroadcast resends the identical journaled submission",
            again["exact_submission_digest"]
            == sent["exact_submission_digest"]
            == record["exact_signed_boc_digest"],
            json.dumps([sent, again]),
        )
        check(
            "the journal records both relayers, in order",
            [r["relayer"] for r in relays] == [sent["relayer"], again["relayer"]]
            and sent["relayer"] != again["relayer"],
            json.dumps(relays),
        )
        result["rebroadcast"] = again
    code, out = 1, ""
    for _ in range(30):
        code, out = await tosctl(
            "agent",
            "account",
            "mldsa44-resolve",
            "-n",
            "agent-1",
            "--action-id",
            action_id,
            "--quorum-config",
            str(OBSERVER_CONFIGS[0]),
            str(OBSERVER_CONFIGS[1]),
            may_fail=True,
        )
        if code == 0:
            break
        await asyncio.sleep(4)
    resolved = last_json(out) if code == 0 else {"error": out[-2000:]}
    result["resolved"] = resolved
    check(
        f"{action_id[:8]}: three views resolve the send as transferred",
        resolved.get("state") == "transferred",
        json.dumps(resolved)[:2000],
    )

    # The target's credit is the exact outbound message of the account
    # transaction the three views resolved: matched by message hash, source
    # and value, so no other transfer of the same value can stand in for it.
    transaction_hash = ((resolved.get("observation") or {}).get("transaction") or {}).get(
        "transaction_hash", ""
    )
    account_rows = rpc_call("getTransactions", address=account, limit=50)["result"]
    message_hash = resolved_transfer_hash(
        account_rows, transaction_hash.removeprefix("sha256:"), target, int(0.2 * NANO)
    )
    result["transfer_message_hash"] = message_hash
    check(
        f"{action_id[:8]}: the resolved account transaction sent exactly one signed transfer",
        message_hash is not None,
        transaction_hash,
    )
    check(
        f"{action_id[:8]}: the target was credited by that exact message",
        message_hash is not None
        and await wait_for(
            lambda: credit_matches(
                rpc_call("getTransactions", address=target, limit=20)["result"],
                message_hash,
                account,
                int(0.2 * NANO),
            ),
            timeout=60,
        ),
    )
    if rebroadcast_relayer:
        check(
            "the rebroadcast's delivery was refused, not applied twice",
            resolved.get("observation", {}).get("aborted_deliveries", 0) >= 1,
            json.dumps(resolved.get("observation")),
        )
    return result


async def refused(label: str, account: str, args: tuple, expected: str):
    before = account_auth(account)
    code, out = await tosctl(*args, may_fail=True)
    message = evidence["steps"][-1]["output"]
    check(
        label,
        code != 0 and expected in message and account_auth(account) == before,
        message[-1500:],
    )


async def run(faucet) -> None:
    print("\n=== provision ===")
    await tosctl("wallet", "create", "-n", "funder", "-v", "V3R2", "-w", "0")
    wallets = {
        e["name"]: norm(e["address"])
        for e in json.loads((await tosctl("wallet", "ls", "--format", "json"))[1])
    }
    await faucet.send(faucet_message(faucet, wallets["funder"], 400 * NANO))
    check("funder funded", await wait_for(lambda: balance(wallets["funder"]) >= 399 * NANO))
    await tosctl("wallet", "activate", "-n", "funder")
    for name in ("r1", "r2", "target"):
        await tosctl("wallet", "create", "-n", name, "-v", "V5R1", "-w", "0")
    wallets = {
        e["name"]: norm(e["address"])
        for e in json.loads((await tosctl("wallet", "ls", "--format", "json"))[1])
    }
    for name in ("r1", "r2"):
        await faucet.send(faucet_message(faucet, wallets[name], 50 * NANO))
        check(
            f"relayer {name} funded",
            await wait_for(lambda name=name: balance(wallets[name]) >= 49 * NANO),
        )
        await tosctl("wallet", "activate", "-n", name)
    await tosctl(
        "agent",
        "wallet",
        "create",
        "--name",
        "agent-1",
        "-v",
        "V5R1",
        "-w",
        "0",
        "--max-per-tx",
        "2",
        "--daily-limit",
        "10",
    )
    _, out = await tosctl(
        "agent",
        "account",
        "deploy",
        "--wallet",
        "agent-1",
        "--from",
        "funder",
        "-w",
        "0",
        "--amount",
        "5",
        "--yes",
        "--format",
        "json",
    )
    account = norm(json.loads(out)["address"])
    check(
        "Agent Account deployed",
        await wait_for(lambda: rpc_call("getAddressState", address=account)["result"] == "active"),
    )
    shown = json.loads(
        (await tosctl("agent", "wallet", "show", "-n", "agent-1", "--format", "json"))[1]
    )
    owner = norm(shown.get("address", shown.get("result", {}).get("address", "")))
    await tosctl(
        "agent",
        "wallet",
        "fund",
        "--name",
        "agent-1",
        "--from",
        "funder",
        "--amount",
        "10",
        "--yes",
    )
    check("owner wallet funded", await wait_for(lambda: balance(owner) >= 9 * NANO))
    await tosctl("agent", "wallet", "activate", "-n", "agent-1")
    check("relayers are not the owner", owner not in (wallets["r1"], wallets["r2"]))
    for name in ("c1", "c2"):
        await tosctl("agent", "native-registry", "new-controller", "--name", name)
    evidence["account"] = account
    evidence["owner"] = owner
    evidence["relayers"] = {"r1": wallets["r1"], "r2": wallets["r2"]}

    print("\n=== install ===")
    await tosctl(
        "agent",
        "account",
        "mldsa44-install",
        "-n",
        "agent-1",
        "--controller",
        "c1",
        "--deploy-amount",
        "1",
        "--amount",
        "0.5",
        "--yes",
    )
    staged = account_auth(account)
    check("staged mode 1, nonce 0", staged["mode"] == 1 and staged["auth_nonce"] == 0, staged)
    evidence["staged"] = staged

    def strict_args(command: str, *extra: str, mode="2", confirm=None) -> tuple:
        return (
            "agent",
            "account",
            command,
            "-n",
            "agent-1",
            "--controller",
            "c1",
            "--mode",
            mode,
            "--confirm-account",
            confirm or account,
            "--valid-until",
            str(chain_time() + 1_200),
            "--relay-amount",
            "2",
            "--relayer",
            "r2",
            "--yes",
            *extra,
        )

    print("\n=== cutover refused before the staged module authenticated anything ===")
    await refused(
        "cutover refused at auth nonce 0",
        account,
        strict_args("mldsa44-cutover"),
        "has not authenticated a request",
    )

    print("\n=== send (relayer r1, rebroadcast through r2) ===")
    first = await send_and_resolve(account, "c1", wallets["target"], "a" * 64, "r1", "r2")
    evidence["first_send"] = first
    used = account_auth(account)
    check("the staged module authenticated one request", used["auth_nonce"] == 1, used)

    print("\n=== cutover refusals ===")
    await refused(
        "cutover to mode 3 refused",
        account,
        strict_args("mldsa44-cutover", mode="3"),
        "mode 3 is refused",
    )
    await refused(
        "cutover to mode 1 refused",
        account,
        strict_args("mldsa44-cutover", mode="1"),
        "mode 1 is refused",
    )
    mistyped = account[:-1] + ("0" if account[-1] != "0" else "1")
    await refused(
        "a mistyped account address is refused",
        account,
        strict_args("mldsa44-cutover", confirm=mistyped),
        "--confirm-account must be exactly",
    )

    print("\n=== cutover ===")
    _, out = await tosctl(*strict_args("mldsa44-cutover"))
    cutover = last_json(out)
    after = account_auth(account)
    check(
        "cutover landed: mode 2, epoch +1, nonce 0, same root",
        cutover.get("state") == "landed"
        and after["mode"] == 2
        and after["auth_epoch"] == used["auth_epoch"] + 1
        and after["auth_nonce"] == 0
        and after["module_hash"] == used["module_hash"]
        and after["controller_epoch"] == used["controller_epoch"] + 1
        and after["seqno"] == used["seqno"] + 1,
        json.dumps([cutover, after]),
    )
    check("the cutover was relayed by r2", cutover.get("relayer") == wallets["r2"], cutover)
    evidence["cutover"] = {"output": cutover, "after": after}
    await refused(
        "a second cutover is refused",
        account,
        strict_args("mldsa44-cutover"),
        "already in strict authentication mode 2",
    )

    print("\n=== strict rotation to c2 ===")
    _, out = await tosctl(
        *strict_args("mldsa44-rotate", "--new-controller", "c2", "--deploy-amount", "1")
    )
    rotated = last_json(out)
    rotated_state = account_auth(account)
    check(
        "rotation landed: mode 2, epoch +1, another root",
        rotated.get("state") == "landed"
        and rotated_state["mode"] == 2
        and rotated_state["auth_epoch"] == after["auth_epoch"] + 1
        and rotated_state["module_hash"] != after["module_hash"],
        json.dumps([rotated, rotated_state]),
    )
    old_module = first["sent"]["module"]
    new_module = norm(rotated["root"])
    check(
        "the new root's module runs the module code",
        code_hash(new_module) == code_hash(norm(old_module)),
    )
    evidence["rotation"] = {
        "output": rotated,
        "after": rotated_state,
        "old_module": old_module,
        "new_module": new_module,
    }

    print("\n=== the old root is refused ===")
    await refused(
        "tosctl refuses a send with the old root",
        account,
        (
            "agent",
            "account",
            "mldsa44-send",
            "-n",
            "agent-1",
            "--controller",
            "c1",
            "--target",
            wallets["target"],
            "--value",
            "0.2",
            "--valid-until",
            str(chain_time() + 600),
            "--action-id",
            "b" * 64,
            "--relay-amount",
            "2",
            "--relayer",
            "r1",
            "--yes",
        ),
        "is not this controller's ML-DSA-44 module",
    )
    # On chain: the c1-signed submission of the first send, still inside its
    # expiry, relayed again through c1's module. The module verifies it; the
    # account refuses its sender, which is no longer the root.
    from pytosiq_core import Cell

    check("the old submission is still inside its expiry", chain_time() < first["valid_until"])
    before = account_auth(account)
    old_last = rpc_call("getAddressInformation", address=account)["result"]["last_transaction_id"]
    body = Cell.one_from_boc(base64.b64decode(first["submission_boc"]))
    await faucet.send(faucet_message(faucet, norm(old_module), 2 * NANO, body=body, bounce=True))

    envelope_hash = body.refs[0].hash

    def delivery_of_old_envelope(row) -> bool:
        """The account transaction whose inbound message is the old module's
        forward of exactly the saved envelope."""
        in_msg = row.get("in_msg") or {}
        if in_msg.get("kind") != "internal" or norm(in_msg.get("source", "")) != norm(old_module):
            return False
        transaction = Cell.one_from_boc(base64.b64decode(row["data"]))
        inbound = transaction.refs[0].refs[0]
        return inbound.refs[-1].hash == envelope_hash

    def account_refusal():
        rows = rpc_call("getTransactions", address=account, limit=10)["result"]
        newer = [r for r in rows if int(r["transaction_id"]["lt"]) > int(old_last["lt"])]
        matching = [r for r in newer if delivery_of_old_envelope(r)]
        return matching[0] if matching else None

    check(
        "the old module's relay of the saved envelope reached the account",
        await wait_for(lambda: account_refusal() is not None, timeout=90),
    )
    row = account_refusal() or {}
    compute = row.get("compute") or {}
    check(
        "the account refuses the old root's request with exactly 1800 and changes nothing",
        row.get("aborted") is True
        and compute.get("skipped") is False
        and compute.get("exit_code") == ERR_NOT_MODULE
        and account_auth(account) == before,
        json.dumps(row)[:3000],
    )
    evidence["old_root_refusal"] = row

    print("\n=== send with the new root ===")
    evidence["second_send"] = await send_and_resolve(
        account, "c2", wallets["target"], "c" * 64, "r1", None
    )

    print("\n=== the Ed25519 controller is refused in strict mode ===")
    code, out = await tosctl(
        "agent",
        "account",
        "native-prepare",
        "--wallet",
        "agent-1",
        "--target",
        wallets["target"],
        "--amount-nanotos",
        str(100_000_000),
        "--fee-reserve-nanotos",
        str(50_000_000),
        "--valid-until",
        str(chain_time() + 300),
        "--action-id",
        "d" * 64,
        "--request-digest",
        "sha256:" + "1" * 64,
        "--response-digest",
        "sha256:" + "2" * 64,
        "--owner-authorization-digest",
        "sha256:" + "3" * 64,
        "--unsigned-transfer-digest",
        "sha256:" + "4" * 64,
        "--yes",
        may_fail=True,
    )
    if code == 0:
        prepared = last_json(out)
        try:
            response = rpc_call("sendBoc", boc=prepared["exact_signed_boc"])
        except urllib.error.HTTPError as error:
            response = {"http_status": error.code, "body": error.read().decode(errors="replace")}
        text = json.dumps(response)
        check(
            "the node refuses the Ed25519 controller message (1807)",
            "result" not in response and f"exitcode={ERR_LEGACY_DISABLED}" in text,
            text[:2000],
        )
        evidence["legacy_refusal"] = response
    else:
        check(
            "tosctl refuses the Ed25519 controller message in strict mode",
            str(ERR_LEGACY_DISABLED) in evidence["steps"][-1]["output"]
            or "strict" in evidence["steps"][-1]["output"],
            evidence["steps"][-1]["output"][-1500:],
        )


def identify_tree():
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()
    if status:
        raise SystemExit(f"refusing to rehearse a tree with uncommitted changes:\n{status}")

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout.strip()

    binaries = {
        "tosctl": Path(TOSCTL),
        "validator-engine": BUILD_DIR / "validator-engine/validator-engine",
        "dht-server": BUILD_DIR / "dht-server/dht-server",
        "create-state": BUILD_DIR / "crypto/create-state",
        "generate-random-id": BUILD_DIR / "utils/generate-random-id",
        "tos-pq-consensus-key": BUILD_DIR / "crypto/pq/tos-pq-consensus-key",
        "validator-engine-console": BUILD_DIR / "validator-engine-console/validator-engine-console",
        "lite-client": BUILD_DIR / "lite-client/lite-client",
        "libtoslibjson": BUILD_DIR / "toslib/libtoslibjson.so",
    }
    evidence["tree"] = {
        "commit": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "build_dir": str(BUILD_DIR),
        "source_dir": str(SOURCE_DIR),
        "binaries": {name: sha256_file(path) for name, path in binaries.items()},
        "embedded_code": embedded_code(),
    }


def embedded_code() -> dict:
    """The bytecode tosctl embeds and deploys: BOC sha256 and cell code hash."""
    from pytosiq_core import Cell

    sources = {
        "agent_account": (
            "tosctl/src/node-control/contracts/src/agent_account.rs",
            "AGENT_ACCOUNT_CODE_B64",
        ),
        "mldsa44_module": (
            "tosctl/src/node-control/contracts/src/agent_account_auth.rs",
            "MLDSA44_AUTH_MODULE_CODE_B64",
        ),
    }
    result = {}
    for name, (path, constant) in sources.items():
        text = (REPO / path).read_text()
        start = text.index(f'pub const {constant}: &str = "') + len(
            f'pub const {constant}: &str = "'
        )
        boc = base64.b64decode(text[start : text.index('"', start)])
        result[name] = {
            "boc_sha256": hashlib.sha256(boc).hexdigest(),
            "code_hash": Cell.one_from_boc(boc).hash.hex(),
        }
    return result


async def main() -> int:
    global RPC, OBSERVER_RPCS, CONFIG, OBSERVER_CONFIGS, PRIVATE_DIR
    if not Path(TOSCTL).exists():
        print(f"FATAL: tosctl not found at {TOSCTL}", file=sys.stderr)
        return 2
    identify_tree()
    from tostester.install import Install
    from tostester.network import Network, StartOptions
    from tostester.pq_initial_validator import make_deterministic_pq_initial_validator

    os.umask(0o077)
    os.environ["TOS_AUTH_NETWORK_TAG"] = secrets.token_hex(32)
    os.environ.setdefault("RAYON_NUM_THREADS", "2")
    os.environ.setdefault("TOKIO_WORKER_THREADS", "2")
    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_DIR = WORKDIR / "private"
    PRIVATE_DIR.mkdir(mode=0o700)
    CONFIG = PRIVATE_DIR / "tosctl.json"
    OBSERVER_CONFIGS = (PRIVATE_DIR / "observer-1.json", PRIVATE_DIR / "observer-2.json")
    base, rpc_ports = free_ports()
    RPC = f"127.0.0.1:{rpc_ports[0]}"
    OBSERVER_RPCS = (f"127.0.0.1:{rpc_ports[1]}", f"127.0.0.1:{rpc_ports[2]}")
    evidence["network"] = {
        "base_port": base,
        "rpc": [RPC, *OBSERVER_RPCS],
        "started_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    }
    write_configs()

    async with Network(Install(BUILD_DIR, SOURCE_DIR), WORKDIR / "net", base_port=base) as network:
        dht = network.create_dht_node()
        node = network.create_full_node()
        observers = [network.create_full_node() for _ in OBSERVER_RPCS]
        make_deterministic_pq_initial_validator(node, 0)
        node.announce_to(dht)
        for observer in observers:
            observer.announce_to(dht)
        tasks = [
            asyncio.create_task(dht.run()),
            asyncio.create_task(node.run(StartOptions(args=["--json-rpc-address", RPC]))),
        ]
        tasks += [
            asyncio.create_task(o.run(StartOptions(args=["--json-rpc-address", e])))
            for o, e in zip(observers, OBSERVER_RPCS, strict=True)
        ]
        try:
            await asyncio.wait_for(network.wait_mc_block(seqno=1), timeout=180)
            for endpoint in (RPC, *OBSERVER_RPCS):
                check(
                    f"RPC {endpoint} ready",
                    await wait_for(
                        lambda endpoint=endpoint: (
                            "result" in rpc_call("getMasterchainInfo", endpoint=endpoint)
                        ),
                        240,
                    ),
                )
            zerostate = network.zerostate.as_block()
            evidence["network"]["zerostate_root"] = zerostate.root_hash.hex()
            evidence["network"]["zerostate_file"] = zerostate.file_hash.hex()
            faucet = network.zerostate.main_wallet(await node.toslib_client())
            await run(faucet)
            if "account" in evidence:
                deployed = {"agent_account": code_hash(evidence["account"])}
                rotation = evidence.get("rotation", {})
                for name in ("old_module", "new_module"):
                    if name in rotation:
                        deployed[name] = code_hash(norm(rotation[name]))
                evidence["deployed_code_hashes"] = deployed
                embedded = evidence["tree"]["embedded_code"]
                check(
                    "the deployed account runs the embedded account code",
                    deployed["agent_account"] == embedded["agent_account"]["code_hash"],
                    deployed,
                )
                for name in ("old_module", "new_module"):
                    if name in deployed:
                        check(
                            f"the {name} runs the embedded module code",
                            deployed[name] == embedded["mldsa44_module"]["code_hash"],
                            deployed,
                        )
        except Exception as error:
            check("the rehearsal ran to completion", False, repr(error))
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await node.stop()
            for observer in observers:
                await observer.stop()
            await dht.stop()

    evidence["failures"] = failures
    evidence["result"] = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S)"
    evidence["finished_utc"] = datetime.datetime.now(datetime.UTC).isoformat()
    (WORKDIR / "evidence.json").write_text(json.dumps(evidence, indent=1) + "\n")
    print(f"\nevidence: {WORKDIR / 'evidence.json'}")
    print("\n=== RESULT:", evidence["result"], "===")
    return 1 if failures else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        sys.exit(0)
    self_test()
    sys.exit(asyncio.run(main()))
