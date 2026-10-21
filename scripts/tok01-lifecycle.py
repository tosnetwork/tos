#!/usr/bin/env python3
"""TOK-01 real-transaction lifecycle; see doc/tok01-lifecycle.md."""

import argparse
import asyncio
import base64
import json
import os
import re
import secrets
import shlex
import signal
import subprocess
import time
import urllib.request
from decimal import Decimal
from pathlib import Path

from contract import tos
from pytosiq_core import (
    Address,
    Cell,
    InternalMsgInfo,
    MessageAny,
    StateInit,
    WalletMessage,
    begin_cell,
)

REPO = Path(__file__).resolve().parents[1]


def clean_source_head(root=REPO):
    """Bind evidence to committed source, including staged changes."""
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=root, text=True
    )
    if status:
        raise RuntimeError("Lifecycle evidence requires a clean tracked source tree")
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def raw(address):
    return (
        Address(address).to_str(is_user_friendly=False).lower()
        if isinstance(address, str)
        else address.to_str(is_user_friendly=False).lower()
    )


def boc(cell):
    return base64.b64encode(cell.to_boc()).decode()


def code(family, name):
    source = (REPO / f"sdk/js/packages/contracts/src/{family}/codes.ts").read_text()
    declaration = source.split(f"export const {name} =", 1)[1].split(";", 1)[0]
    return Cell.one_from_boc(
        bytes.fromhex("".join(re.findall(r"[\"\']([0-9a-fA-F]+)[\"\']", declaration)))
    )


def entry_kind(entry):
    return (
        entry[0]
        if isinstance(entry, list)
        else {
            "tvm.stackEntryNumber": "num",
            "tvm.stackEntryCell": "cell",
            "tvm.stackEntrySlice": "slice",
        }.get(entry.get("@type"))
    )


def entry_value(entry):
    if isinstance(entry, list):
        return entry[1]
    kind = entry_kind(entry)
    return entry["number"]["number"] if kind == "num" else entry[kind]


def number(entry):
    value = entry_value(entry)
    return int(value, 0) if isinstance(value, str) and ("x" in value.lower()) else int(value)


def cell(entry):
    return Cell.one_from_boc(base64.b64decode(entry_value(entry)["bytes"]))


def address(entry):
    return raw(cell(entry).begin_parse().load_address())


def ordered(stack, kinds):
    observed = [entry_kind(e) for e in stack]
    if observed == kinds:
        return stack
    if observed[::-1] == kinds:
        return stack[::-1]
    raise RuntimeError(f"Unexpected getter stack {observed}; expected {kinds}")


def equal(label, actual, expected):
    if actual != expected:
        raise AssertionError(f"{label}: actual={actual!r}, expected={expected!r}")
    return {"field": label, "getter": actual, "rpc_or_expected": expected, "pass": True}


def outgoing_message_hash(transactions, destination):
    """Hash of the sender's single new outgoing message to the destination, once sent."""
    hashes = [
        message["hash"]
        for tx in transactions
        for message in tx.get("out_msgs", [])
        if message.get("destination") and raw(message["destination"]) == destination
    ]
    if len(hashes) > 1:
        raise RuntimeError("sender emitted several messages to the destination")
    return hashes[0] if hashes else None


def select_target(transactions, message_hash):
    """The transaction that consumed exactly this inbound message, not merely a later one."""
    matches = [tx for tx in transactions if (tx.get("in_msg") or {}).get("hash") == message_hash]
    if len(matches) > 1:
        raise RuntimeError("several transactions claim the same inbound message")
    return matches[0] if matches else None


def decode_global_id(config_bytes):
    """Network identity from the ConfigParam 19 cell that getConfigParam returns."""
    body = Cell.one_from_boc(base64.b64decode(config_bytes)).begin_parse()
    value = body.load_int(32)
    if body.remaining_bits or body.remaining_refs:
        raise RuntimeError("ConfigParam 19 carries unexpected trailing data")
    return value


def check_global_id(reported, allowed):
    """Refuse any network the operator did not list explicitly."""
    if reported not in allowed:
        raise RuntimeError(
            f"endpoint global id {reported} is not in the allowed set {sorted(allowed)}"
        )
    return reported


def rpc_call(endpoint, rpc_method, **params):
    payload = {"jsonrpc": "2.0", "id": 1, "method": rpc_method, "params": params}
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.load(response)
    if "error" in result or "result" not in result:
        raise RuntimeError(f"{rpc_method}: {result}")
    return payload, result


class Harness:
    def __init__(self, endpoint, output, send, owners, provenance=None):
        self.endpoint, self.output, self.send, self.owners = endpoint, output, send, owners
        output.mkdir(parents=True, exist_ok=False)
        self.supply = 0
        self.balances = {raw(owner): 0 for owner in owners}
        self.admin = raw(owners[0])
        self.wallets = {}
        self.failures = []
        self.steps = []
        self.item = None
        self.item_owner = None
        # Contracts that a completed step deployed or minted; later snapshots require them active.
        self.expected_active = set()
        self.run_id = secrets.token_hex(16)
        self.provenance = dict(provenance or {})

    def write_provenance(self):
        (self.output / "provenance.json").write_text(
            json.dumps(self.provenance, indent=2, sort_keys=True) + "\n"
        )

    def record(self, filename, value):
        with (self.output / filename).open("a") as stream:
            stream.write(json.dumps(value, sort_keys=True) + "\n")

    def compare(self, label, actual, expected):
        try:
            row = equal(label, actual, expected)
        except AssertionError as error:
            failure = {"step": self.current_step, "error": str(error)}
            self.failures.append(failure)
            self.record("failures.jsonl", failure)
            row = {"field": label, "getter": actual, "rpc_or_expected": expected, "pass": False}
        self.record("checks.jsonl", {"step": self.current_step, **row})
        return row

    RPC_ATTEMPTS = 3

    def rpc(self, rpc_method, **params):
        # Every query the harness makes is an idempotent read, so a transport stall
        # (timeout, connection error) is retried a bounded number of times; each failed
        # attempt is recorded. A JSON-RPC error answer is final.
        for attempt in range(1, self.RPC_ATTEMPTS + 1):
            try:
                payload, result = rpc_call(self.endpoint, rpc_method, **params)
            except RuntimeError as error:
                self.record("rpc.jsonl", {"request": {"method": rpc_method}, "error": str(error)})
                raise
            except (TimeoutError, OSError) as error:
                self.record(
                    "rpc.jsonl",
                    {
                        "request": {"method": rpc_method, "params": params},
                        "error": str(error),
                        "attempt": attempt,
                    },
                )
                if attempt == self.RPC_ATTEMPTS:
                    raise
                continue
            self.record("rpc.jsonl", {"request": payload, "response": result})
            return result["result"]
        raise RuntimeError("unreachable")

    def new_transactions(self, account, before):
        return [
            tx
            for tx in self.transactions(account)
            if int(tx["transaction_id"]["lt"]) > before[raw(account)]
        ]

    def getter(self, account, method, stack=None):
        result = self.rpc("runGetMethodStd", address=raw(account), method=method, stack=stack or [])
        equal(f"{method} exit", result["exit_code"], 0)
        return result["stack"]

    def transactions(self, account):
        return self.rpc("getTransactions", address=raw(account), limit=100)

    def lt(self, account):
        info = self.rpc("getAddressInformation", address=raw(account))
        return int((info.get("last_transaction_id") or {}).get("lt", 0))

    async def wait(self, predicate, timeout=90):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except Exception as error:
                last = error
            await asyncio.sleep(1)
        raise TimeoutError(f"Condition not met within {timeout}s; last error: {last}")

    async def complete_index(self, method, owner):
        def ready():
            result = self.rpc(method, address=raw(owner))
            return result if result.get("index_state", {}).get("complete") is True else None

        return await self.wait(ready)

    async def transfer(self, sender, destination, body, value=500_000_000, init=None):
        message = WalletMessage(
            send_mode=3,
            message=MessageAny(
                info=InternalMsgInfo(
                    ihr_disabled=True,
                    bounce=True,
                    bounced=False,
                    src=sender,
                    dest=destination,
                    value=tos(Decimal(value) / Decimal(1_000_000_000)),
                    ihr_fee=0,
                    fwd_fee=0,
                    created_lt=0,
                    created_at=0,
                ),
                init=init,
                body=body,
            ),
        )
        await self.send(sender, message)

    async def step(
        self, label, sender, destination, body, expected_exit=0, init=None, update=None, extra=None
    ):
        print(f"STEP {label}", flush=True)
        self.current_step = label
        accounts = list(
            dict.fromkeys(
                [
                    raw(a)
                    for a in [
                        *self.owners,
                        self.master,
                        self.collection,
                        *self.wallets.values(),
                        destination,
                        *([self.item] if self.item else []),
                    ]
                ]
            )
        )
        before = {a: self.lt(a) for a in accounts}
        before_data = {
            a: self.rpc("getAddressInformation", address=a)["data"]
            for a in accounts
            if a not in [raw(owner) for owner in self.owners]
        }
        before_head = self.rpc("getMasterchainInfo")["last"]
        await self.transfer(sender, destination, body, init=init)
        # The receipt is the transaction that consumed this step's own message: the sender's
        # outgoing message hash selects it, so a bounce or an unrelated inbound message on the
        # destination cannot stand in for it.
        sent = await self.wait(
            lambda: outgoing_message_hash(self.new_transactions(sender, before), raw(destination))
        )
        target = await self.wait(
            lambda: select_target(self.new_transactions(destination, before), sent)
        )
        rows = []
        try:
            equal(label + " compute exit", target["compute"]["exit_code"], expected_exit)
            equal(label + " aborted", target["aborted"], expected_exit != 0)
            if expected_exit == 0 and target.get("action"):
                equal(label + " action success", target["action"]["success"], True)
            if update:
                update()
            # State observations happen only after multiple later finalized heads.
            await self.wait(
                lambda: (
                    int(self.rpc("getMasterchainInfo")["last"]["seqno"])
                    >= int(before_head["seqno"]) + 4
                )
            )
            await asyncio.sleep(2)
            rows = await self.snapshot(label)
            if extra:
                await extra(target)
        except Exception as error:
            self.failures.append({"step": label, "error": str(error)})
            self.record("failures.jsonl", self.failures[-1])
        finally:
            transactions = {a: self.new_transactions(a, before) for a in accounts}
            for txs in transactions.values():
                for tx in txs:
                    equal(
                        "transaction BOC hash",
                        Cell.one_from_boc(base64.b64decode(tx["data"])).hash.hex(),
                        base64.b64decode(tx["transaction_id"]["hash"]).hex(),
                    )
                    for field in ("root_hash", "file_hash", "seqno", "workchain", "shard"):
                        if field not in tx["block_id"]:
                            raise RuntimeError(f"Transaction block lacks {field}")
            evidence = {
                "step": label,
                "transactions": transactions,
                "target": target,
                "sender": raw(sender),
                "message_hash": sent,
                "destination": raw(destination),
                "expected_exit": expected_exit,
                "comparisons": rows,
                "head": self.rpc("getMasterchainInfo")["last"],
            }
            self.record("steps.jsonl", evidence)
            self.steps.append(label)
            if expected_exit:
                for a, previous in before_data.items():
                    self.compare(
                        "refused operation persistent data " + a,
                        self.rpc("getAddressInformation", address=a)["data"],
                        previous,
                    )
                try:
                    self.bounce_accounting(label, target, transactions)
                except Exception as error:
                    failure = {"step": label, "error": str(error)}
                    self.failures.append(failure)
                    self.record("failures.jsonl", failure)
            if label == "transfer payload notification":
                self.notification(transactions)

    def notification(self, transactions):
        from pytosiq_core import Transaction

        found = []
        for tx in transactions[raw(self.owners[1])]:
            parsed = Transaction.deserialize(
                Cell.one_from_boc(base64.b64decode(tx["data"])).begin_parse()
            )
            if not parsed.in_msg:
                continue
            body = parsed.in_msg.body.begin_parse()
            if body.remaining_bits >= 32 and body.load_uint(32) == 0x7362D09C:
                self.compare("notification query", body.load_uint(64), 17)
                self.compare("notification amount", body.load_coins(), 25)
                self.compare("notification from", raw(body.load_address()), raw(self.owners[0]))
                payload = body.load_ref().begin_parse() if body.load_bit() else body
                self.compare("notification payload marker", payload.load_uint(32), 0)
                self.compare(
                    "notification payload", payload.load_bytes(13).decode(), "tok01-forward"
                )
                self.compare(
                    "notification source",
                    raw(parsed.in_msg.info.src),
                    raw(self.wallets[raw(self.owners[1])]),
                )
                found.append(tx["transaction_id"])
        self.compare("notification count", len(found), 1)
        self.record("notifications.jsonl", {"transactions": found})

    def bounce_accounting(self, label, target, transactions):
        from pytosiq_core import Transaction

        parsed = Transaction.deserialize(
            Cell.one_from_boc(base64.b64decode(target["data"])).begin_parse()
        )
        bounce = (
            [message for message in parsed.out_msgs.values() if message.info.bounced]
            if isinstance(parsed.out_msgs, dict)
            else [message for message in parsed.out_msgs if message.info.bounced]
        )
        equal("one bounce", len(bounce), 1)
        msg = bounce[0]
        # The serialized message carries the forwarding remainder separately.
        incoming = parsed.in_msg.info.value.tomis
        returned = msg.info.value.tomis
        fees = parsed.total_fees.tomis
        forward = msg.info.fwd_fee
        storage = parsed.description.storage_ph.storage_fees_collected
        checks = [
            self.compare("bounce value conservation", incoming, returned + fees - storage + forward)
        ]
        matches = [
            tx
            for txs in transactions.values()
            for tx in txs
            if (tx.get("in_msg") or {}).get("hash")
            == base64.b64encode(msg.serialize().hash).decode()
        ]
        checks.append(self.compare("bounce receipt count", len(matches), 1))
        self.record(
            "bounce.jsonl",
            {
                "step": label,
                "incoming": incoming,
                "returned": returned,
                "transaction_fees": fees,
                "storage_fees_from_existing_balance": storage,
                "forwarding_remainder": forward,
                "checks": checks,
            },
        )

    async def snapshot(self, label):
        rows = []
        for name, account in (
            ("token master", self.master),
            ("collection", self.collection),
            ("NFT item", self.item),
        ):
            if account is not None and raw(account) in self.expected_active:
                equal(
                    f"{name} active after {label}",
                    self.rpc("getAddressState", address=raw(account)),
                    "active",
                )
        if self.rpc("getAddressState", address=raw(self.master)) == "active":
            stack = ordered(
                self.getter(self.master, "get_token_data"), ["num", "num", "slice", "cell", "cell"]
            )
            data = self.rpc("getTokenData", address=raw(self.master))
            values = {
                "total_supply": str(number(stack[0])),
                "mintable": number(stack[1]) != 0,
                "admin_address": address(stack[2]),
                "token_content": cell(stack[3]).hash.hex(),
                "token_wallet_code": cell(stack[4]).hash.hex(),
            }
            for key, value in values.items():
                other = data[key]
                if key == "admin_address":
                    other = raw(other)
                elif key in ("token_content", "token_wallet_code"):
                    other = Cell.one_from_boc(base64.b64decode(other)).hash.hex()
                rows.append(self.compare(key, value, other))
            rows.append(self.compare("expected supply", number(stack[0]), self.supply))
            rows.append(self.compare("expected admin", address(stack[2]), self.admin))
            observed_balances = []
            for owner in self.owners:
                owner = raw(owner)
                wallet = self.wallets[owner]
                active = self.rpc("getAddressState", address=raw(wallet)) == "active"
                balance = 0
                index = await self.complete_index("getAccountTokens", owner)
                entries = [
                    entry
                    for entry in index["tokens"]
                    if raw(entry["token_master"]) == raw(self.master)
                ]
                if active:
                    wallet_data = ordered(
                        self.getter(wallet, "get_wallet_data"), ["num", "slice", "slice", "cell"]
                    )
                    balance = number(wallet_data[0])
                    rows.extend(
                        [
                            self.compare("wallet owner", address(wallet_data[1]), owner),
                            self.compare(
                                "wallet master", address(wallet_data[2]), raw(self.master)
                            ),
                            self.compare(
                                "wallet code",
                                cell(wallet_data[3]).hash.hex(),
                                self.wallet_code.hash.hex(),
                            ),
                        ]
                    )
                    if len(entries) != 1:
                        raise AssertionError("Complete token index must contain exactly one wallet")
                    entry = entries[0]
                    rows.append(
                        self.compare("indexed wallet", raw(entry["token_wallet"]), raw(wallet))
                    )
                else:
                    rows.append(self.compare("undeployed wallet index", entries, []))
                rows.extend(
                    [
                        self.compare("expected balance " + owner, balance, self.balances[owner]),
                        self.compare("nonnegative balance", balance >= 0, True),
                    ]
                )
                observed_balances.append(balance)
            rows.append(
                self.compare("supply equals wallet sum", sum(observed_balances), number(stack[0]))
            )
            self.record(
                "invariants.jsonl",
                {
                    "step": label,
                    "supply": number(stack[0]),
                    "expected_supply": self.supply,
                    "balances": observed_balances,
                    "sum": sum(observed_balances),
                    "pass": sum(observed_balances) == number(stack[0]) == self.supply
                    and min(observed_balances) >= 0,
                },
            )
        if self.rpc("getAddressState", address=raw(self.collection)) == "active":
            stack = ordered(
                self.getter(self.collection, "get_collection_data"), ["num", "cell", "slice"]
            )
            data = self.rpc("getTokenData", address=raw(self.collection))
            rows.extend(
                [
                    self.compare(
                        "collection next index", str(number(stack[0])), data["next_item_index"]
                    ),
                    self.compare("collection owner", address(stack[2]), raw(data["owner_address"])),
                    self.compare(
                        "collection metadata",
                        cell(stack[1]).hash.hex(),
                        Cell.one_from_boc(base64.b64decode(data["collection_content"])).hash.hex(),
                    ),
                ]
            )
        if self.item and self.rpc("getAddressState", address=raw(self.item)) == "active":
            stack = ordered(
                self.getter(self.item, "get_nft_data"), ["num", "num", "slice", "slice", "cell"]
            )
            data = self.rpc("getTokenData", address=raw(self.item))
            rows.extend(
                [
                    self.compare("item initialized", number(stack[0]) != 0, data["init"]),
                    self.compare("item index", str(number(stack[1])), data["index"]),
                    self.compare(
                        "item collection", address(stack[2]), raw(data["collection_address"])
                    ),
                    self.compare("item owner", address(stack[3]), raw(data["owner_address"])),
                    self.compare("expected NFT owner", address(stack[3]), self.item_owner),
                    self.compare(
                        "item metadata",
                        cell(stack[4]).hash.hex(),
                        Cell.one_from_boc(base64.b64decode(data["individual_content"])).hash.hex(),
                    ),
                ]
            )
            for owner in self.owners:
                index = await self.complete_index("getAccountNfts", owner)
                entries = index["nfts"]
                matches = [e for e in entries if raw(e["nft_item"]) == raw(self.item)]
                rows.append(
                    self.compare(
                        "NFT owner index " + raw(owner),
                        len(matches),
                        int(raw(owner) == self.item_owner),
                    )
                )
                if matches:
                    rows.append(
                        self.compare(
                            "NFT indexed collection",
                            raw(matches[0]["collection"]),
                            raw(self.collection),
                        )
                    )
            full = self.getter(
                self.collection,
                "get_nft_content",
                [["num", "0"], ["cell", {"bytes": boc(cell(stack[4]))}]],
            )
            self.record("metadata.jsonl", {"step": label, "full_content_stack": full})
        self.record("tables.jsonl", {"step": label, "rows": rows})
        return rows

    async def run(self):
        # Evidence binds to committed source: the same clean head before and after the run.
        source_head = clean_source_head()
        self.provenance.update(
            run_id=self.run_id,
            source_head=source_head,
            endpoint=self.endpoint,
            owners=[raw(owner) for owner in self.owners],
            completed=False,
        )
        self.write_provenance()
        self.wallet_code = code("token", "TOKEN_WALLET_CODE_HEX")
        content = (
            begin_cell()
            .store_uint(1, 8)
            .store_bytes(b"https://example.invalid/tok01/token.json")
            .end_cell()
        )
        master_init = StateInit(
            code=code("token", "TOKEN_MASTER_CODE_HEX"),
            data=begin_cell()
            .store_coins(0)
            .store_address(self.owners[0])
            .store_ref(content)
            .store_ref(self.wallet_code)
            .end_cell(),
        )
        self.master = Address((0, master_init.serialize().hash))
        collection_content = (
            begin_cell()
            .store_ref(
                begin_cell()
                .store_uint(1, 8)
                .store_bytes(b"https://example.invalid/tok01/collection.json")
                .end_cell()
            )
            .store_ref(begin_cell().store_bytes(b"https://example.invalid/tok01/").end_cell())
            .end_cell()
        )
        collection_init = StateInit(
            code=code("nft", "NFT_COLLECTION_CODE_HEX"),
            data=begin_cell()
            .store_address(self.owners[0])
            .store_uint(0, 64)
            .store_ref(collection_content)
            .store_ref(code("nft", "NFT_ITEM_CODE_HEX"))
            .store_ref(
                begin_cell()
                .store_uint(0, 16)
                .store_uint(100, 16)
                .store_address(self.owners[0])
                .end_cell()
            )
            .end_cell(),
        )
        self.collection = Address((0, collection_init.serialize().hash))
        for owner in self.owners:
            wallet_init = StateInit(
                code=self.wallet_code,
                data=begin_cell()
                .store_coins(0)
                .store_address(owner)
                .store_address(self.master)
                .store_ref(self.wallet_code)
                .end_cell(),
            )
            self.wallets[raw(owner)] = Address((0, wallet_init.serialize().hash))
        self.record(
            "contracts.jsonl",
            {
                "master": raw(self.master),
                "collection": raw(self.collection),
                "wallets": {k: raw(v) for k, v in self.wallets.items()},
                "code_hashes": {
                    name: code(family, name).hash.hex()
                    for family, name in [
                        ("token", "TOKEN_MASTER_CODE_HEX"),
                        ("token", "TOKEN_WALLET_CODE_HEX"),
                        ("nft", "NFT_COLLECTION_CODE_HEX"),
                        ("nft", "NFT_ITEM_CODE_HEX"),
                    ]
                },
            },
        )
        await self.step(
            "token deploy",
            self.owners[0],
            self.master,
            Cell.empty(),
            init=master_init,
            update=lambda: self.expected_active.add(raw(self.master)),
        )
        await self.step(
            "collection deploy",
            self.owners[0],
            self.collection,
            Cell.empty(),
            init=collection_init,
            update=lambda: self.expected_active.add(raw(self.collection)),
        )
        for owner, amount in [(self.owners[0], 1000), (self.owners[1], 100)]:
            internal = (
                begin_cell()
                .store_uint(0x178D4519, 32)
                .store_uint(0, 64)
                .store_coins(amount)
                .store_address(self.master)
                .store_address(owner)
                .store_coins(0)
                .store_bit(0)
                .end_cell()
            )
            body = (
                begin_cell()
                .store_uint(21, 32)
                .store_uint(0, 64)
                .store_address(owner)
                .store_coins(200_000_000)
                .store_ref(internal)
                .end_cell()
            )

            def minted(owner=owner, amount=amount):
                self.supply += amount
                self.balances[raw(owner)] += amount

            await self.step("mint " + str(amount), self.owners[0], self.master, body, update=minted)
        for label, receiver, amount, forward in [
            ("transfer existing wallet", self.owners[1], 100, 0),
            ("transfer undeployed wallet", self.owners[2], 50, 0),
            ("transfer payload notification", self.owners[1], 25, 20_000_000),
            ("insufficient balance", self.owners[1], 1000000, 0),
        ]:
            payload = begin_cell().store_uint(0, 32).store_bytes(b"tok01-forward").end_cell()
            body = (
                begin_cell()
                .store_uint(0x0F8A7EA5, 32)
                .store_uint(17, 64)
                .store_coins(amount)
                .store_address(receiver)
                .store_address(self.owners[0])
                .store_bit(0)
                .store_coins(forward)
                .store_bit(1)
                .store_ref(payload)
                .end_cell()
            )

            def moved(receiver=receiver, amount=amount):
                self.balances[raw(self.owners[0])] -= amount
                self.balances[raw(receiver)] += amount

            await self.step(
                label,
                self.owners[0],
                self.wallets[raw(self.owners[0])],
                body,
                expected_exit=706 if amount == 1000000 else 0,
                update=None if amount == 1000000 else moved,
            )

        def burned():
            self.supply -= 10
            self.balances[raw(self.owners[0])] -= 10

        burn = (
            begin_cell()
            .store_uint(0x595F07BC, 32)
            .store_uint(19, 64)
            .store_coins(10)
            .store_address(self.owners[0])
            .store_bit(0)
            .end_cell()
        )
        await self.step(
            "burn", self.owners[0], self.wallets[raw(self.owners[0])], burn, update=burned
        )
        await self.step(
            "admin change",
            self.owners[0],
            self.master,
            begin_cell()
            .store_uint(3, 32)
            .store_uint(20, 64)
            .store_address(self.owners[1])
            .end_cell(),
            update=lambda: setattr(self, "admin", raw(self.owners[1])),
        )
        nft_content = begin_cell().store_bytes(b"item-0.json").end_cell()
        item_init = StateInit(
            code=code("nft", "NFT_ITEM_CODE_HEX"),
            data=begin_cell().store_uint(0, 64).store_address(self.collection).end_cell(),
        )
        self.item = Address((0, item_init.serialize().hash))
        self.item_owner = raw(self.owners[0])
        mint = (
            begin_cell()
            .store_uint(1, 32)
            .store_uint(21, 64)
            .store_uint(0, 64)
            .store_coins(200_000_000)
            .store_ref(begin_cell().store_address(self.owners[0]).store_ref(nft_content).end_cell())
            .end_cell()
        )
        await self.step(
            "NFT mint",
            self.owners[0],
            self.collection,
            mint,
            update=lambda: self.expected_active.add(raw(self.item)),
        )

        def nft_transfer(owner):
            return (
                begin_cell()
                .store_uint(0x5FCC3D14, 32)
                .store_uint(22, 64)
                .store_address(owner)
                .store_address(self.owners[0])
                .store_bit(0)
                .store_coins(20_000_000)
                .store_bit(0)
                .end_cell()
            )

        await self.step(
            "NFT transfer",
            self.owners[0],
            self.item,
            nft_transfer(self.owners[1]),
            update=lambda: setattr(self, "item_owner", raw(self.owners[1])),
        )
        await self.step(
            "NFT non-owner refused",
            self.owners[0],
            self.item,
            nft_transfer(self.owners[2]),
            expected_exit=401,
        )
        self.record(
            "summary.jsonl",
            {
                "run_id": self.run_id,
                "steps": self.steps,
                "failures": self.failures,
                "pass": not self.failures,
            },
        )
        source_head_after = clean_source_head()
        if source_head_after != source_head:
            raise RuntimeError("Source revision changed during the lifecycle run")
        # Only a run whose source stayed clean and unchanged is marked complete; the
        # verifier refuses everything else.
        self.provenance.update(source_head_after=source_head_after, completed=True)
        self.write_provenance()
        return int(bool(self.failures))


def make_sender(command, timeout):
    """Submit through the operator's signer adapter, bounded by a deadline."""

    async def send(sender, message):
        request = {
            "sender": raw(sender),
            "message_boc": boc(message.message.serialize()),
            "send_mode": message.send_mode,
        }
        # The adapter runs in its own process group so a deadline kills whatever it spawned.
        process = await asyncio.create_subprocess_exec(
            *shlex.split(command),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(json.dumps(request).encode()), timeout
            )
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
            # The adapter may already have submitted: the submission state is unknown.
            raise TimeoutError(
                f"Signer adapter did not answer within {timeout}s; submission state unknown"
            ) from None
        if process.returncode != 0:
            raise RuntimeError(f"Signer adapter failed with exit {process.returncode}")
        result = json.loads(stdout)
        equal("signer submitted", result.get("submitted"), True)

    return send


def read_global_id(endpoint):
    """The network identity the endpoint actually serves, from its ConfigParam 19."""
    _, response = rpc_call(endpoint, "getConfigParam", param=19)
    return decode_global_id(response["result"]["config"]["bytes"])


async def endpoint_run(args):
    owners = [Address(a) for a in args.owners]
    # An endpoint alone does not authorize a run: the network it serves must be listed.
    global_id = check_global_id(read_global_id(args.endpoint), set(args.allow_global_id))
    harness = Harness(
        args.endpoint,
        args.output,
        make_sender(args.sender_command, args.signer_timeout),
        owners,
        {"global_id": global_id, "mode": "endpoint"},
    )
    return await harness.run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--owners", nargs=3, required=True)
    parser.add_argument("--sender-command", required=True)
    parser.add_argument(
        "--allow-global-id",
        type=int,
        action="append",
        help="Network identity the endpoint must report; repeatable (default: the local 3)",
    )
    parser.add_argument(
        "--signer-timeout",
        type=float,
        default=120.0,
        help="Seconds the signer adapter may take per submission",
    )
    args = parser.parse_args()
    if args.allow_global_id is None:
        args.allow_global_id = [3]
    if args.signer_timeout <= 0:
        parser.error("--signer-timeout must be positive")
    raise SystemExit(asyncio.run(endpoint_run(args)))


if __name__ == "__main__":
    main()
