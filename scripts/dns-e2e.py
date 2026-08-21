#!/usr/bin/env python3
# Copyright (C) 2025-2026  TOS Network.
"""
dns-e2e.py -- full-node e2e for the .tos naming system baseline port.

Boots a localnet whose genesis pins ConfigParam 4 (dns_root_addr) to the
counterfactual address of the .tos Root, deploys the Root and Collection at
runtime, and drives a registration through the inherited open-auction flow:

  ARTIFACTS  regenerate deploy artifacts with the fift toolchain and assert
             the deterministic Root/Collection addresses match the committed
             vector corpus (crypto/smartcont/dns + domains vectors).
  BOOT       genesis sets ConfigParam 4 to the Root's address before the Root
             account exists (clients fail closed until it is deployed).
  DEPLOY     deploy Root (masterchain) and Collection (workchain 0) from the
             genesis wallet using their StateInits.
  RESOLVE-0  pre-registration resolution: the Root answers "tos\\0..." with a
             partial dns_next_resolver to the Collection; a foreign TLD does
             not resolve; lite-client walks the chain against one pinned
             block and reports the structured provenance lines.
  REGISTER   an op-0 comment carrying the label, with at least the current
             minimum price attached, deploys the Domain Item at the derived
             address (byte-exact vs the committed vector) and opens the
             auction with the sender as max bidder.
  RESOLVE-1  the resolution chain now reaches the live item; its auction
             state is visible through get_auction_info.

A second network then rehearses the OTHER activation path (DNS.md §11):

  GOVERNANCE genesis has no ConfigParam 4 and relaxes ConfigParam 11 (the
             default voting setup needs multi-round validator-set rotation
             that a single-validator localnet never produces); resolution
             fails closed; the Root and Collection deploy; an ordinary
             config-change proposal carrying the Root account id is
             registered with the config contract, the genesis validator
             votes for it with its validator key, ConfigParam 4 appears,
             and resolution starts working on the running chain.

Full-lifecycle pieces that need wall-clock time (auction completion after the
one-hour minimum duration, 366-day release) are exercised by the vendored
contract suites (crypto/smartcont/dns/run-tests.sh), not here.

Exit 0 iff every check passes. Run from the repo root:
  ninja -C build validator-engine dht-server create-state fift lite-client
  uv run python scripts/dns-e2e.py
"""
import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from tostester.install import Install
from tostester.network import Network, StartOptions
from pytosiq_core import (
    Address,
    Cell,
    CurrencyCollection,
    InternalMsgInfo,
    MessageAny,
    WalletMessage,
)
from pytosiq_core.boc import begin_cell
from pytosiq_core.tlb.account import StateInit

REPO = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("TOS_BUILD_DIR", REPO / "build"))
RPC = "127.0.0.1:19667"
WORKDIR = REPO / "test/integration/.dns-e2e"
DNS_DIR = REPO / "crypto/smartcont/dns"
VECTORS = json.loads((REPO / "domains/packages/protocol/test/vectors.json").read_text())

NANO = 1_000_000_000
LABEL = "alice"
ONE_MONTH = 2_592_000

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(label)
    return ok


def rpc_call(rpc_method: str, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": rpc_method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://{RPC}/jsonRPC", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def min_price(label_bytes: int, now: int, auction_start_time: int) -> int:
    """Mirror of get_min_price in crypto/smartcont/dns/func/dns-utils.fc."""
    tiers = {4: (1000, 100), 5: (500, 50), 6: (400, 40), 7: (300, 30),
             8: (200, 20), 9: (100, 10), 10: (50, 5)}
    start_tokens, end_tokens = tiers.get(label_bytes, (10, 1))
    price = start_tokens * NANO
    months = (now - auction_start_time) // ONE_MONTH
    if months > 21:
        return end_tokens * NANO
    for _ in range(months):
        price = price * 90 // 100
    return price


def stack_slice(cell: Cell) -> list:
    return ["slice", {"bytes": base64.b64encode(cell.to_boc()).decode()}]


def stack_num(value: int) -> list:
    return ["num", hex(value)]


def parse_stack_entry(entry):
    """(kind, value) from either the compact or the named stack encoding."""
    if isinstance(entry, list) and len(entry) == 2:
        kind, val = entry[0], entry[1]
        if kind == "num":
            return "num", int(val, 0) if isinstance(val, str) else int(val)
        if kind in ("cell", "slice"):
            return "cell", Cell.one_from_boc(base64.b64decode(val["bytes"]))
        if kind == "null":
            return "null", None
        return kind, val
    if isinstance(entry, dict):
        t = entry.get("@type", "")
        if t == "tvm.stackEntryNumber":
            return "num", int(entry["number"]["number"])
        if t == "tvm.stackEntryCell":
            return "cell", Cell.one_from_boc(base64.b64decode(entry["cell"]["bytes"]))
        if t == "tvm.stackEntrySlice":
            return "cell", Cell.one_from_boc(base64.b64decode(entry["slice"]["bytes"]))
        if t == "tvm.stackEntryNull":
            return "null", None
        if t == "tvm.stackEntryList" and not entry["list"]["elements"]:
            # TVM unifies null with the empty list
            return "null", None
        if t in ("tvm.stackEntryTuple", "tvm.stackEntryList"):
            return "tuple", entry
    if isinstance(entry, list) and len(entry) == 2 and entry[0] in ("tuple", "list"):
        return "tuple", entry
    raise RuntimeError(f"unhandled stack entry: {entry!r}")


def run_get_method(address: str, method: str, stack: list):
    resp = rpc_call("runGetMethodStd", address=address, method=method, stack=stack)
    result = resp.get("result")
    if result is None:
        raise RuntimeError(f"runGetMethodStd failed: {resp}")
    if result.get("exit_code") not in (0, 1):
        raise RuntimeError(f"{method} exit_code={result.get('exit_code')}")
    return [parse_stack_entry(e) for e in result["stack"]]


def dnsresolve(address: str, encoded: bytes, category: int = 0):
    """(used_bits, value_cell_or_None) via the dnsresolve get-method."""
    query = begin_cell().store_bytes(encoded).end_cell()
    entries = run_get_method(address, "dnsresolve", [stack_slice(query), stack_num(category)])
    # the server serializes the stack top-first: [cell|null, num]
    kinds = [k for k, _ in entries]
    if kinds == ["num", "cell"] or kinds == ["num", "null"]:
        entries = list(reversed(entries))
    (_, value), (_, used_bits) = entries[0], entries[1]
    if entries[0][0] == "null":
        value = None
    return used_bits, value


def next_resolver_target(record: Cell) -> str:
    """Raw address from a dns_next_resolver record cell."""
    s = record.begin_parse()
    tag = s.load_uint(16)
    if tag != 0xBA93:
        raise RuntimeError(f"not a dns_next_resolver record: tag 0x{tag:04x}")
    addr = s.load_address()
    return addr.to_str(is_user_friendly=False).lower()


def account_state(addr: str) -> str:
    return rpc_call("getAddressState", address=addr).get("result", "")


def balance(addr: str) -> int:
    return int(rpc_call("getAddressInformation", address=addr)["result"]["balance"])


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


async def async_poll(fn, timeout: float = 90.0, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        await asyncio.sleep(interval)
    return False


def gen_artifacts() -> dict:
    """Run gen-deploy.fif; return addresses and StateInit cells."""
    env = dict(os.environ)
    env["PATH"] = f"{BUILD_DIR}/crypto:{env['PATH']}"
    env["FIFTPATH"] = str(REPO / "crypto/fift/lib")
    out = subprocess.run(
        ["fift", "-s", "deploy/gen-deploy.fif"],
        cwd=DNS_DIR, env=env, capture_output=True, text=True, check=True).stdout
    addrs = {}
    for line in out.splitlines():
        if line.startswith("collection address: "):
            addrs["collection"] = line.split(": ")[1].strip()
        if line.startswith("root address (ConfigParam 4 value): "):
            addrs["root"] = line.split(": ")[1].strip()
    addrs["collection_init"] = Cell.one_from_boc(
        (DNS_DIR / "func/build/collection-state-init.boc").read_bytes())
    addrs["root_init"] = Cell.one_from_boc(
        (DNS_DIR / "func/build/root-state-init.boc").read_bytes())
    return addrs


def state_init_of(cell: Cell) -> StateInit:
    """Split a serialized StateInit cell (b{00110} ^code ^data) into parts."""
    refs = cell.refs
    if len(refs) != 2:
        raise RuntimeError("StateInit cell must carry exactly [code, data]")
    return StateInit(code=refs[0], data=refs[1])


def deploy_message(faucet, dest: str, amount: int, init: StateInit, body: Cell) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=faucet.address, dest=Address(dest),
                value=CurrencyCollection(tomis=amount),
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0),
            init=init, body=body))


def transfer_message(faucet, dest: str, amount: int, body: Cell) -> WalletMessage:
    return WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True, bounce=False, bounced=False,
                src=faucet.address, dest=Address(dest),
                value=CurrencyCollection(tomis=amount),
                ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0),
            init=None, body=body))


def lite_client_dnsresolve(global_config: Path, name: str) -> str:
    lite = BUILD_DIR / "lite-client/lite-client"
    proc = subprocess.run(
        [str(lite), "-C", str(global_config), "-t", "30", "-c", f"dnsresolve {name}"],
        capture_output=True, text=True, timeout=90)
    return proc.stdout + proc.stderr


def param4_root_id() -> str | None:
    """Hex account id in ConfigParam 4, or None while the parameter is absent."""
    try:
        cfg = rpc_call("getConfigParam", config_id=4).get("result") or {}
        raw = cfg.get("config", {}).get("bytes", "")
        if not raw:
            return None
        cell = Cell.one_from_boc(base64.b64decode(raw))
        return cell.begin_parse().load_bytes(32).hex()
    except Exception:
        return None


def config_contract_address() -> str:
    cfg = rpc_call("getConfigParam", config_id=0)["result"]
    cell = Cell.one_from_boc(base64.b64decode(cfg["config"]["bytes"]))
    return "-1:" + cell.begin_parse().load_bytes(32).hex()


async def run_governance_checks(faucet, artifacts: dict, global_config: Path,
                                validator_key) -> None:
    root_addr = artifacts["root"]
    collection_addr = artifacts["collection"]
    root_id = bytes.fromhex(root_addr.split(":")[1])

    print("\n=== GOVERNANCE: ConfigParam 4 introduced by proposal ===")
    if not check("json-rpc ready", await wait_rpc_ready()):
        return
    check("ConfigParam 4 absent at genesis", param4_root_id() is None)
    out = lite_client_dnsresolve(global_config, f"{LABEL}.tos")
    check("lite-client fails closed without parameter 4",
          "cannot obtain root dns address" in out or "parameter #4" in out, out[-400:])

    await faucet.send(deploy_message(
        faucet, root_addr, 2 * NANO, state_init_of(artifacts["root_init"]),
        begin_cell().end_cell()))
    check("Root active", await async_poll(lambda: account_state(root_addr) == "active"))
    fill_up = begin_cell().store_uint(0x370FEC51, 32).store_uint(0, 64).end_cell()
    await faucet.send(deploy_message(
        faucet, collection_addr, 5 * NANO, state_init_of(artifacts["collection_init"]), fill_up))
    check("Collection active",
          await async_poll(lambda: account_state(collection_addr) == "active", timeout=120))

    config_addr = config_contract_address()
    print(f"  config contract: {config_addr}")
    p11 = rpc_call("getConfigParam", config_id=11).get("result") or {}
    check("ConfigParam 11 (voting setup) present at genesis",
          bool(p11.get("config", {}).get("bytes")))

    # cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)
    value = begin_cell().store_uint(int.from_bytes(root_id, "big"), 256).end_cell()
    proposal = (begin_cell()
                .store_uint(0xF3, 8)
                .store_uint(4, 32)
                .store_bit(1)
                .store_ref(value)
                .store_bit(0)
                .end_cell())
    phash_bytes = proposal.hash
    # new voting proposal: tag query_id expire_at(relative) ^proposal critical=0
    body = (begin_cell()
            .store_uint(0x6E565052, 32)
            .store_uint(0, 64)
            .store_uint(100_000, 32)
            .store_ref(proposal)
            .store_bit(0)
            .end_cell())
    await faucet.send(transfer_message(faucet, config_addr, 10 * NANO, body))

    def proposal_registered() -> bool:
        entries = run_get_method(
            config_addr, "get_proposal",
            [stack_num(int.from_bytes(phash_bytes, "big"))])
        return any(k not in ("null",) for k, _ in entries)

    registered = await async_poll(proposal_registered, timeout=90)
    if not registered:
        try:
            entries = run_get_method(
                config_addr, "get_proposal",
                [stack_num(int.from_bytes(phash_bytes, "big"))])
            print(f"  get_proposal -> {entries!r}")
        except Exception as exc:
            print(f"  get_proposal error: {exc}")
        try:
            txs = rpc_call("getTransactions", address=config_addr, limit=6)["result"]
            print(f"  config txs={len(txs)} balance={balance(config_addr)}")
            for tx in txs:
                for label, msg in [("in", tx.get("in_msg") or {})] + [
                        ("out", m) for m in tx.get("out_msgs", [])]:
                    body = (msg.get("msg_data") or {}).get("body", "")
                    tag = ""
                    if body:
                        try:
                            s = Cell.one_from_boc(base64.b64decode(body)).begin_parse()
                            tag = f" tag=0x{s.load_uint(32):08x}"
                        except Exception:
                            tag = " tag=?"
                    print(f"  {label}: value={msg.get('value')}{tag}")
        except Exception as exc:
            print(f"  tx dump error: {exc}")
        try:
            faucet_addr = faucet.address.to_str(is_user_friendly=False)
            txs = rpc_call("getTransactions", address=faucet_addr, limit=6)["result"]
            print(f"  faucet {faucet_addr} txs={len(txs)}")
            for tx in txs:
                msgs = [("in", tx.get("in_msg") or {})]
                msgs += [("out", m) for m in tx.get("out_msgs", [])]
                for label, m in msgs:
                    body = (m.get("msg_data") or {}).get("body", "")
                    tag = ""
                    if body:
                        try:
                            s = Cell.one_from_boc(base64.b64decode(body)).begin_parse()
                            tag = f" tag=0x{s.load_uint(32):08x}"
                        except Exception:
                            tag = " tag=?"
                    print(f"  faucet {label}: src={m.get('source')} dst={m.get('destination')} "
                          f"value={m.get('value')}{tag}")
                    if label == "in" and m.get("source", "").startswith("Ef9VVVV"):
                        print(f"  raw answer msg: {json.dumps(m)[:600]}")
            std = rpc_call("getTransactionsStd", address=faucet_addr, limit=6)["result"]
            for tx in (std if isinstance(std, list) else std.get("transactions", [])):
                inb = tx.get("in_msg") or {}
                src = str(inb.get("source", ""))
                if "5555" in src or src.startswith("Ef9VVVV"):
                    print(f"  std answer msg: {json.dumps(inb)[:700]}")
        except Exception as exc:
            print(f"  faucet dump error: {exc}")
    check("proposal registered with the config contract", registered)

    # the genesis validator (index 0 in ConfigParam 34) votes: the vote body
    # carries an Ed25519 signature over sign_tag(32) idx(16) proposal_hash(256)
    to_sign = (0x566F7445).to_bytes(4, "big") + (0).to_bytes(2, "big") + phash_bytes
    signature = validator_key.key.sign(to_sign).signature
    vote = (begin_cell()
            .store_uint(0x566F7465, 32)
            .store_uint(0, 64)
            .store_bytes(signature)
            .store_bytes(to_sign)
            .end_cell())
    await faucet.send(transfer_message(faucet, config_addr, 1 * NANO, vote))

    check("ConfigParam 4 appears after the validator vote",
          await async_poll(lambda: param4_root_id() == root_addr.split(":")[1], timeout=120))

    out = lite_client_dnsresolve(global_config, f"{LABEL}.tos")
    check("resolution works on the running chain after activation",
          VECTORS["alice_item_address"].split(":")[1].upper() in out, out[-400:])


async def run_checks(faucet, artifacts: dict, global_config: Path) -> None:
    root_addr = artifacts["root"]
    collection_addr = artifacts["collection"]

    print("\n=== BOOT: ConfigParam 4 pinned at genesis ===")
    if not check("json-rpc ready", await wait_rpc_ready()):
        return
    cfg = rpc_call("getConfigParam", config_id=4).get("result", {})
    cfg_bytes = base64.b64decode(cfg.get("config", {}).get("bytes", ""))
    root_id_hex = root_addr.split(":")[1]
    check("ConfigParam 4 carries the Root account id",
          root_id_hex in cfg_bytes.hex(),
          f"param cell {cfg_bytes.hex()} vs root {root_id_hex}")
    check("Root account does not exist yet (clients fail closed)",
          account_state(root_addr) in ("uninitialized", "nonexist", ""))

    print("\n=== DEPLOY: Root (masterchain) + Collection (workchain 0) ===")
    # sequential sends: each external message consumes one wallet seqno, so
    # the second deploy waits until the first is applied
    await faucet.send(deploy_message(
        faucet, root_addr, 2 * NANO, state_init_of(artifacts["root_init"]),
        begin_cell().end_cell()))
    check("Root active", await async_poll(lambda: account_state(root_addr) == "active"))
    # the Collection's recv_internal reads an op from every message, so the
    # deploy body must be a valid op: fill_up (0x370fec51) is accepted from
    # anyone and does nothing beyond keeping the balance
    fill_up = begin_cell().store_uint(0x370FEC51, 32).store_uint(0, 64).end_cell()
    await faucet.send(deploy_message(
        faucet, collection_addr, 5 * NANO, state_init_of(artifacts["collection_init"]), fill_up))
    ok = await async_poll(lambda: account_state(collection_addr) == "active", timeout=120)
    if not ok:
        try:
            info = rpc_call("getAddressInformation", address=collection_addr)["result"]
            print(f"  collection: state={account_state(collection_addr)!r} "
                  f"balance={info.get('balance')!r}")
        except Exception as exc:  # diagnostics only
            print(f"  collection info error: {exc}")
        try:
            mc = rpc_call("getMasterchainInfo")["result"]["last"]["seqno"]
            print(f"  shards at mc seqno {mc}: {rpc_call('getShards', seqno=mc)}")
        except Exception as exc:
            print(f"  shards error: {exc}")
    check("Collection active", ok)

    print("\n=== RESOLVE-0: pre-registration resolution ===")
    # inherited root semantics: without a leading zero byte the root consumes
    # exactly the TLD bytes ("tos", 24 bits) and the next resolver receives
    # the query from its zero-byte component boundary
    used, value = dnsresolve(root_addr, b"tos\0" + LABEL.encode() + b"\0")
    check("Root consumes exactly the 'tos' TLD bytes", used == 24, f"used_bits={used}")
    check("Root answers with dns_next_resolver to the Collection",
          value is not None and next_resolver_target(value) == collection_addr,
          f"target={next_resolver_target(value) if value else None}")

    used, value = dnsresolve(root_addr, b"toz\0" + LABEL.encode() + b"\0")
    check("foreign TLD 'toz' does not resolve", used == 0 and value is None,
          f"used_bits={used}")

    used, value = dnsresolve(collection_addr, b"\0" + LABEL.encode() + b"\0")
    item_addr = VECTORS["alice_item_address"]
    check("Collection delegates the label to the derived item address",
          used > 0 and value is not None and next_resolver_target(value) == item_addr,
          f"used={used} target={next_resolver_target(value) if value else None}")
    check("derived item account does not exist before registration",
          account_state(item_addr) in ("uninitialized", "nonexist", ""))

    # an unregistered name dead-ends at the derived-but-nonexistent item
    # account; lite-client reports that as a distinct error, never as a
    # successful "not found" record answer
    out = lite_client_dnsresolve(global_config, f"{LABEL}.tos")
    check("lite-client walks the delegation chain to the derived item address",
          item_addr.split(":")[1].upper() in out, out[-400:])
    check("lite-client reports the nonexistent item as an empty-account error",
          "is empty (cannot run method" in out, out[-400:])

    print("\n=== REGISTER: op-0 comment opens the auction and deploys the item ===")
    now = int(time.time())
    price = min_price(len(LABEL), now, VECTORS["auction_start_time"])
    bid = price + 1 * NANO
    print(f"  minimum price now: {price / NANO} TOS; sending {bid / NANO} TOS")
    body = begin_cell().store_uint(0, 32).store_bytes(LABEL.encode()).end_cell()
    await faucet.send(transfer_message(faucet, collection_addr, bid, body))
    check("Domain Item deployed at the derived (vector) address",
          await async_poll(lambda: account_state(item_addr) == "active", timeout=120))

    entries = run_get_method(item_addr, "get_auction_info", [])
    values = [v for _, v in entries]
    kinds = [k for k, _ in entries]
    # (max_bid_address slice, max_bid_amount int, auction_end_time int),
    # possibly reported top-first
    nums = [v for k, v in entries if k == "num"]
    check("auction is live with a recorded max bid", len(nums) >= 2 and max(nums) > now,
          f"kinds={kinds} nums={nums}")
    amounts = [n for n in nums if n < 10**15]
    check("max bid is the forwarded registration value (minus fees)",
          any(0 < n <= bid for n in amounts), f"amounts={amounts} bid={bid}")

    lt = run_get_method(item_addr, "get_last_fill_up_time", [])
    check("last_fill_up_time is the registration time",
          any(k == "num" and abs(v - now) < 600 for k, v in lt), f"{lt}")

    print("\n=== RESOLVE-1: the chain reaches the live item ===")
    used, value = dnsresolve(item_addr, b"\0")
    check("item dnsresolve answers for its own zero component", used == 8, f"used={used}")

    out = lite_client_dnsresolve(global_config, f"{LABEL}.tos")
    check("lite-client resolution reaches the item and stays pinned to one block",
          "resolved at block" in out, out[-400:])
    check("lite-client reports the full resolver path (root -> collection -> item)",
          out.count(":") >= 3 and "resolver path:" in out, out[-400:])


async def main() -> int:
    for tool in ("validator-engine/validator-engine", "lite-client/lite-client", "crypto/fift"):
        if not (BUILD_DIR / tool).exists():
            print(f"FATAL: {BUILD_DIR / tool} missing; build the toolchain first", file=sys.stderr)
            return 2
    shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)

    artifacts = gen_artifacts()
    print(f"root:       {artifacts['root']}")
    print(f"collection: {artifacts['collection']}")
    ok = artifacts["collection"] == VECTORS["collection_address"] \
        and artifacts["root"] == VECTORS["root_address"]
    print(f"  [{'PASS' if ok else 'FAIL'}] deterministic addresses match the committed vectors")
    if not ok:
        return 1

    phases = os.environ.get("DNS_E2E_PHASES", "genesis,governance").split(",")
    install = Install(BUILD_DIR, REPO)
    if "genesis" not in phases:
        print("(skipping genesis phase per DNS_E2E_PHASES)")
    if "genesis" in phases:
      async with Network(install, WORKDIR / "net", base_port=25400) as network:
        network.config.dns_root_addr = int(artifacts["root"].split(":")[1], 16)
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
            lite_cfg = WORKDIR / "liteclient.config.json"
            lite_cfg.write_text(node.liteserver_config.to_json())
            await run_checks(faucet, artifacts, lite_cfg)
        finally:
            for t in (node_task, dht_task):
                t.cancel()
            await asyncio.gather(node_task, dht_task, return_exceptions=True)

    # Phase B: governance activation on a chain born without ConfigParam 4
    if "governance" in phases:
      async with Network(install, WORKDIR / "net-gov", base_port=25500) as network:
        network.config.enable_config_voting = True
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
            lite_cfg = WORKDIR / "liteclient.gov.config.json"
            lite_cfg.write_text(node.liteserver_config.to_json())
            await run_governance_checks(faucet, artifacts, lite_cfg, node.validator_key)
        finally:
            for t in (node_task, dht_task):
                t.cancel()
            await asyncio.gather(node_task, dht_task, return_exceptions=True)

    print("\n=== RESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILURE(S)", "===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
