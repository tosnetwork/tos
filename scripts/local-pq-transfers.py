#!/usr/bin/env python3
"""Generate and verify random transfers on the disposable local PQ network."""

import argparse
import asyncio
import base64
import fcntl
import json
import math
import os
import random
import subprocess
import time
from contextlib import AsyncExitStack
from decimal import Decimal
from pathlib import Path

import local_pq_testnet as local
import nacl.signing
from contract import WalletV1, WalletV1Blueprint
from pytosiq_core import (
    Address,
    CurrencyCollection,
    InternalMsgInfo,
    MessageAny,
    Transaction,
    WalletMessage,
    begin_cell,
)
from tosapi import tos_api

from toslib import ToslibCDLL, ToslibClient

REPO = Path(__file__).resolve().parents[1]
NANO = 10**9


def require(value, message):
    if not value:
        raise ValueError(message)


def nanos(value):
    amount = Decimal(value) * NANO
    require(
        amount.is_finite() and amount == amount.to_integral_value() and amount > 0,
        "amount must be positive whole nanatos",
    )
    return int(amount)


def snapshot(account):
    return {
        "balance": account.balance,
        "lt": account.last_transaction_id.lt,
        "hash": base64.b64encode(account.last_transaction_id.hash).decode(),
    }


def verify_transfer(
    sender_before,
    sender_after,
    recipient_before,
    recipient_after,
    seq_before,
    seq_after,
    amount,
    fee,
):
    require(seq_after == seq_before + 1, "sender seqno did not advance exactly once")
    require(sender_before - sender_after >= amount, "sender debit is below transferred value")
    require(
        fee >= 0 and recipient_after - recipient_before == amount - fee,
        "recipient balance delta differs from value minus transaction fee",
    )


def verify_message(msg, sender, recipient, amount, body_hash):
    require(
        Address(msg.source.account_address).to_str(is_user_friendly=False) == sender
        and Address(msg.destination.account_address).to_str(is_user_friendly=False) == recipient,
        "transaction message endpoints differ",
    )
    require(
        msg.value == amount and msg.body_hash == body_hash, "transaction amount or body differs"
    )


def check_transaction(raw):
    tx = Transaction.deserialize(begin_cell_from_boc(raw.data).begin_parse())
    require(not tx.description.aborted, "transaction aborted")
    compute = tx.description.compute_ph
    require(compute.success and compute.exit_code in (0, 1), "transaction computation failed")
    if tx.description.action is not None:
        require(tx.description.action.success, "transaction action phase failed")
    return tx


def begin_cell_from_boc(data):
    from pytosiq_core import Cell

    return Cell.one_from_boc(data)


def record(directory, row):
    row = {"at": time.time(), **row}
    encoded = json.dumps(row) + "\n"
    path = directory / "transfers.jsonl"
    if path.exists() and path.stat().st_size + len(encoded.encode()) > 16 * 1024**2:
        for i in range(3, 0, -1):
            older = directory / f"transfers.jsonl.{i}"
            if older.exists():
                older.replace(directory / f"transfers.jsonl.{i + 1}")
        path.replace(directory / "transfers.jsonl.1")
    with path.open("a") as f:
        f.write(encoded)
        f.flush()
        os.fsync(f.fileno())
    local.write_json(directory / "status.json", row)
    print(json.dumps({k: v for k, v in row.items() if k != "transaction_bocs"}), flush=True)


async def wait_for(predicate, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = await predicate()
        if result:
            return result
        await asyncio.sleep(0.5)
    raise TimeoutError("transfer confirmation timed out; not automatically resubmitted")


async def send(wallet, destination, amount, body, init=None):
    seqno = (await wallet.current).seqno
    message = WalletMessage(
        send_mode=3,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=False,
                bounced=False,
                src=wallet.address,
                dest=destination,
                value=CurrencyCollection(tomis=amount),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=init,
            body=body,
        ),
    )
    await wallet.send(message, seqno=seqno)

    async def included():
        return (await wallet.current).seqno == seqno + 1

    await wait_for(included)
    return seqno


async def bootstrap(args, client, blueprints):
    # The election service exclusively owns the Genesis wallet during normal operation.
    state = subprocess.run(
        ["systemctl", "is-active", "tos-pq-elections"], capture_output=True, text=True
    )
    require(state.stdout.strip() == "inactive", "stop the election service before bootstrap")
    faucet = WalletV1(
        client,
        Address(json.loads((args.data / "network.json").read_text())["genesis_wallet_address"]),
        nacl.signing.SigningKey((args.data / "testnet/state/main-wallet.pk").read_bytes()),
    )
    for blueprint in blueprints:
        before = await client.raw_get_account_state(blueprint.address)
        require(not before.code, "bootstrap wallet already deployed; do not fund it again")
        await send(
            faucet, blueprint.address, 200 * NANO, begin_cell().end_cell(), blueprint.state_init
        )

        async def deployed(blueprint=blueprint):
            account = await client.raw_get_account_state(blueprint.address)
            return bool(account.code) and account.balance > 190 * NANO

        await wait_for(deployed)
    record(
        args.output,
        {
            "kind": "bootstrapped",
            "wallets": [b.address.to_str(is_user_friendly=False) for b in blueprints],
        },
    )
    local.write_json(
        args.data / "configs" / getattr(args, "bootstrap_config", "transfer-test.json"),
        {
            "wallets": [b.address.to_str(is_user_friendly=False) for b in blueprints],
            "purpose": "disposable local transfer verification; non-consensus wallet keys",
        },
    )
    (args.data / "configs" / getattr(args, "bootstrap_config", "transfer-test.json")).chmod(0o644)


async def run(args):
    require(4 <= args.nodes <= 21, "full-node count must be 4..21")
    require(
        math.isfinite(args.min_interval)
        and math.isfinite(args.max_interval)
        and 0 < args.min_interval <= args.max_interval,
        "invalid interval range",
    )
    low, high = nanos(args.min_amount), nanos(args.max_amount)
    require(low <= high <= 10 * NANO and args.count >= 0, "invalid amount or count")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.output, 0o700)
    with (args.output / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        blueprints = []
        for i in range(3):
            key_file = args.output / f"wallet-{i}.seed"
            if not key_file.exists():
                require(args.bootstrap, "run bootstrap before starting traffic")
                fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(nacl.signing.SigningKey.generate().encode())
            require(
                not key_file.is_symlink() and key_file.stat().st_mode & 0o077 == 0,
                "wallet seed permissions differ",
            )
            blueprints.append(WalletV1Blueprint(0, nacl.signing.SigningKey(key_file.read_bytes())))
        cdll = ToslibCDLL(args.build / "toslib/libtoslibjson.so")
        cdll.client_set_verbosity_level(0)
        async with AsyncExitStack() as stack:
            clients = []
            for i in range(1, args.nodes + 1):
                config = tos_api.Liteclient_config_global.from_dict(
                    json.loads((args.data / f"configs/node-{i}-lite.json").read_text())
                )
                clients.append(await stack.enter_async_context(ToslibClient(config, cdll)))
            if args.bootstrap:
                await bootstrap(args, clients[0], blueprints)
                return
            rng = random.Random(args.seed)
            previous = json.loads((args.output / "status.json").read_text())
            require(
                previous["kind"] in ("bootstrapped", "confirmed"),
                "previous transfer is unresolved; inspect retained receipts before restarting",
            )
            sequence = previous.get("sequence", 0)
            completed = 0
            while args.count == 0 or completed < args.count:
                await asyncio.sleep(rng.uniform(args.min_interval, args.max_interval))
                source, destination = rng.sample(range(3), 2)
                client = clients[sequence % len(clients)]
                sender, recipient = [
                    blueprints[i].materialize(client) for i in (source, destination)
                ]
                before_s, before_r = await asyncio.gather(
                    client.raw_get_account_state(sender.address),
                    client.raw_get_account_state(recipient.address),
                )
                amount = rng.randint(low, high)
                require(before_s.balance >= amount + 2 * NANO, "test wallet balance too low")
                body = begin_cell().store_uint(0, 32).store_bytes(os.urandom(24)).end_cell()
                raw_sender = sender.address.to_str(is_user_friendly=False)
                raw_recipient = recipient.address.to_str(is_user_friendly=False)
                record(
                    args.output,
                    {
                        "kind": "submitting",
                        "sequence": sequence,
                        "sender": raw_sender,
                        "recipient": raw_recipient,
                        "amount_nanotos": amount,
                        "body_hash": body.hash.hex(),
                    },
                )
                started = time.monotonic()
                seqno = await send(sender, recipient.address, amount, body)

                async def received():
                    account = await client.raw_get_account_state(recipient.address)
                    if account.last_transaction_id.lt == before_r.last_transaction_id.lt:
                        return None
                    transactions = await client.raw_get_transactions(
                        recipient.address, account.last_transaction_id
                    )
                    for transaction in transactions.transactions:
                        if transaction.in_msg.body_hash == body.hash:
                            return account, transaction
                    return None

                after_r, receipt = await wait_for(received)
                after_s = await client.raw_get_account_state(sender.address)
                outgoing = await client.raw_get_transactions(
                    sender.address, after_s.last_transaction_id
                )
                matches = [
                    (tx, msg)
                    for tx in outgoing.transactions
                    for msg in tx.out_msgs
                    if msg.body_hash == body.hash
                ]
                require(
                    len(matches) == 1, "sender does not have exactly one matching outgoing message"
                )
                sender_tx, sent_msg = matches[0]
                for msg in (sent_msg, receipt.in_msg):
                    verify_message(msg, raw_sender, raw_recipient, amount, body.hash)
                require(sent_msg.hash == receipt.in_msg.hash, "send/receive message hashes differ")
                check_transaction(sender_tx)
                check_transaction(receipt)
                require(not receipt.out_msgs, "recipient unexpectedly emitted messages")
                verify_transfer(
                    before_s.balance,
                    after_s.balance,
                    before_r.balance,
                    after_r.balance,
                    seqno,
                    (await sender.current).seqno,
                    amount,
                    receipt.fee,
                )

                async def synchronized():
                    states = await asyncio.gather(
                        *[
                            c.raw_get_account_state(address)
                            for c in clients
                            for address in (sender.address, recipient.address)
                        ]
                    )
                    expected = [snapshot(after_s), snapshot(after_r)]
                    return (
                        states
                        if all(snapshot(s) == expected[i % 2] for i, s in enumerate(states))
                        else None
                    )

                await wait_for(synchronized)
                ports = json.loads((args.data / "testnet-ports.json").read_text())["nodes"]
                infos = await asyncio.gather(
                    *[
                        asyncio.to_thread(local.rpc, row["json_rpc_port"], "getMasterchainInfo")
                        for row in ports
                    ]
                )
                height = min(info["last"]["seqno"] for info in infos)
                headers = await asyncio.gather(
                    *[
                        asyncio.to_thread(
                            local.rpc,
                            row["json_rpc_port"],
                            "getBlockHeader",
                            workchain=-1,
                            shard="-9223372036854775808",
                            seqno=height,
                        )
                        for row in ports
                    ]
                )
                require(
                    len({local.block_id(h["id"]) for h in headers}) == 1,
                    "nodes disagree on common-height block ID",
                )
                sequence += 1
                completed += 1
                record(
                    args.output,
                    {
                        "kind": "confirmed",
                        "sequence": sequence,
                        "sender": raw_sender,
                        "recipient": raw_recipient,
                        "amount_nanotos": amount,
                        "confirmation_seconds": round(time.monotonic() - started, 3),
                        "recipient_fee_nanotos": receipt.fee,
                        "sender_seqno": seqno + 1,
                        "sender_after": snapshot(after_s),
                        "recipient_after": snapshot(after_r),
                        "message_hash": sent_msg.hash.hex(),
                        "nodes_agree": len(clients),
                        "common_block": headers[0]["id"],
                        "transaction_bocs": [
                            base64.b64encode(tx.data).decode() for tx in (sender_tx, receipt)
                        ],
                    },
                )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("--output", type=Path, default=Path("/data/transfers"))
    parser.add_argument("--nodes", type=int, default=7, help="fixed full-node inventory size")
    parser.add_argument("--build", type=Path, default=REPO / "build")
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--min-interval", type=float, default=2)
    parser.add_argument("--max-interval", type=float, default=8)
    parser.add_argument("--min-amount", default="0.01")
    parser.add_argument("--max-amount", default="1")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--count", type=int, default=0, help="0 runs continuously")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        asyncio.run(run(args))
    except Exception as exc:
        if args.output.exists():
            record(args.output, {"kind": "failed", "error": f"{type(exc).__name__}: {exc}"})
        raise


if __name__ == "__main__":
    main()
