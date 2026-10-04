#!/usr/bin/env python3
"""Random real shielded-pool operations on the disposable development network.

The local pool uses the development proof key. Private notes and generated
proofs stay under a mode-0700 directory. No production wallet is involved.
"""

import argparse
import asyncio
import base64
import fcntl
import importlib.util
import json
import math
import os
import random
import signal
import time
from contextlib import AsyncExitStack
from pathlib import Path

import local_pq_testnet as local
import nacl.signing
from contract import WalletV1Blueprint
from pytosiq_core import Address, Cell
from tosapi import tos_api

from toslib import ToslibCDLL, ToslibClient

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "local_transfers", REPO / "scripts/local-pq-transfers.py"
)
transfers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transfers)
require = transfers.require
NANO = 10**9
METHODS = (
    "commitment_root",
    "nullifier_root",
    "commitment_next_index",
    "nullifier_next_index",
    "native_liability",
    "backed",
)


def write_private_json(path, value):
    local.write_json(path, value, 0o600)


def record(directory, row):
    transfers.record(directory, row, status_mode=0o600)


def verify_state(actual, expected):
    require(set(actual) == set(METHODS) and set(expected) == set(METHODS), "incomplete pool state")
    require(
        all(int(actual[k]) == int(expected[k]) for k in METHODS),
        "pool roots, indices, liability or backing differ",
    )


def verify_withdrawal(before, after, amount, fee, sent, received, pool, recipient):
    require(
        amount > 0 and fee >= 0 and after - before == amount - fee,
        "withdrawal balance delta differs",
    )
    require(
        sent.hash == received.hash and sent.value == amount and received.value == amount,
        "withdrawal message differs",
    )
    for msg in (sent, received):
        require(
            Address(msg.source.account_address).to_str(is_user_friendly=False) == pool,
            "withdrawal source differs",
        )
        require(
            Address(msg.destination.account_address).to_str(is_user_friendly=False) == recipient,
            "withdrawal destination differs",
        )


def choose(state, rng, sequence):
    notes = state["notes"]
    operation = (
        ("deposit", "deposit", "transfer", "withdraw")[sequence]
        if sequence < 4
        else rng.choice(("deposit", "transfer", "withdraw"))
    )
    if len(notes) < 2:
        operation = "deposit"
    if operation == "deposit":
        return {
            "operation": operation,
            "amount": rng.choice((NANO, NANO, NANO, 10 * NANO)),
            "owner": rng.randrange(3),
        }
    inputs = rng.sample(notes, 2)
    total = sum(n["amount"] for n in inputs)
    fee = 20_000_000 if operation == "withdraw" else 0
    maximum = min(NANO, total - fee - 2)
    if maximum < 1 or (operation == "withdraw" and total - fee - 2 < NANO):
        return {"operation": "deposit", "amount": NANO, "owner": rng.randrange(3)}
    owner = rng.choice([i for i in range(3) if i != inputs[0]["owner"]])
    return {
        "operation": operation,
        "amount": (
            rng.choice(
                [v for v in (NANO, 10 * NANO, 100 * NANO, 1000 * NANO) if v <= total - fee - 2]
            )
            if operation == "withdraw"
            else rng.randint(1, maximum)
        ),
        "owner": owner,
        "inputs": [n["index"] for n in inputs],
    }


async def pool_state(args, address):
    return {
        k: await asyncio.to_thread(local.get_method, args.build, args.data, address, k)
        for k in METHODS
    }


async def generate(process, request):
    encoded = json.dumps(request).encode() + b"\n"
    require(len(encoded) <= 32 * 1024**2, "private model request exceeds bound")
    process.stdin.write(encoded)
    await process.stdin.drain()
    line = await asyncio.wait_for(process.stdout.readline(), 300)
    require(line and len(line) <= 32 * 1024**2, "generator returned no bounded response")
    response = json.loads(line)
    require(response.get("ok") is True, f"generator refused: {response.get('error')}")
    return response["result"]


async def run(args):
    require(4 <= args.nodes <= 21, "full-node count must be 4..21")
    require(
        math.isfinite(args.min_interval)
        and math.isfinite(args.max_interval)
        and 0 < args.min_interval <= args.max_interval,
        "invalid interval",
    )
    require(args.count >= 0, "invalid count")
    local.secure_output_dir(args.output)
    with os.fdopen(local.open_private(args.output / "run.lock", os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        wallets = []
        for i in range(3):
            p = args.output / f"wallet-{i}.seed"
            if not p.exists():
                require(args.bootstrap, "bootstrap private traffic wallets first")
                with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                    f.write(nacl.signing.SigningKey.generate().encode())
            require(
                not p.is_symlink() and p.stat().st_mode & 0o077 == 0,
                "wallet seed permissions differ",
            )
            wallets.append(WalletV1Blueprint(0, nacl.signing.SigningKey(p.read_bytes())))
        cdll = ToslibCDLL(args.build / "toslib/libtoslibjson.so")
        cdll.client_set_verbosity_level(0)
        async with AsyncExitStack() as stack:
            clients = []
            for i in range(1, args.nodes + 1):
                cfg = tos_api.Liteclient_config_global.from_dict(
                    json.loads((args.data / f"configs/node-{i}-lite.json").read_text())
                )
                clients.append(await stack.enter_async_context(ToslibClient(cfg, cdll)))
            if args.bootstrap:
                # Separate wallet keys; the existing regular-transfer config is untouched.
                args.bootstrap_config = "privacy-test.json"
                await transfers.bootstrap(args, clients[0], wallets)
                return
            status = json.loads((args.output / "status.json").read_text())
            require(
                status["kind"] in ("bootstrapped", "confirmed"),
                "previous operation unresolved; inspect private receipts",
            )
            require(
                not (args.output / "pending.json").exists(),
                "pending private operation requires review before restarting",
            )
            sequence = status.get("sequence", 0)
            counts = status.get("counts", {k: 0 for k in ("deposit", "transfer", "withdraw")})
            pool = json.loads((args.data / "shielded-pool/pool.json").read_text())
            address = pool["address"]
            network = json.loads((args.data / "network.json").read_text())
            stderr = stack.enter_context(
                os.fdopen(
                    local.open_private(
                        args.output / "generator.stderr",
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                    ),
                    "ab",
                )
            )
            generator = await asyncio.create_subprocess_exec(
                str(
                    args.generator
                ),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr,
                limit=32 * 1024**2 + 1,
                start_new_session=True,
                env={**os.environ, "RAYON_NUM_THREADS": "4"},
            )
            try:
                statepath = args.output / "notes.json"
                if statepath.exists():
                    model = json.loads(statepath.read_text())
                    require(
                        model["zerostate_root"] == network["zerostate_root"]
                        and model["pool"] == address,
                        "model belongs to another chain or pool",
                    )
                    state = model["state"]
                    expected = model["expected"]
                else:
                    require(sequence == 0, "confirmed operations but missing private model")
                    initial = await generate(generator, {"operation": "init"})
                    state, expected = initial["state"], initial["expected"]
                verify_state(await pool_state(args, address), expected)
                rng = random.Random(args.seed)
                done = 0
                while args.count == 0 or done < args.count:
                    await asyncio.sleep(rng.uniform(args.min_interval, args.max_interval))
                    request = choose(state, rng, sequence)
                    client = clients[sequence % len(clients)]
                    source = rng.randrange(3)
                    recipient_index = (source + 1) % 3
                    sender = wallets[source].materialize(client)
                    recipient = wallets[recipient_index].materialize(client)
                    recipient_raw = recipient.address.to_str(is_user_friendly=False)
                    request.update(
                        state=state,
                        global_id=network["global_id"],
                        pool=address.split(":")[1],
                        recipient=recipient_raw.split(":")[1],
                        valid_until=int(time.time()) + 1800,
                    )
                    started = time.monotonic()
                    plan = await generate(generator, request)
                    verify_state(await pool_state(args, address), plan["before"])
                    before_s, before_r = await asyncio.gather(
                        client.raw_get_account_state(sender.address),
                        client.raw_get_account_state(recipient.address),
                    )
                    require(
                        before_s.balance >= plan["value"] + NANO,
                        "private traffic funding wallet too low",
                    )
                    body = Cell.one_from_boc(bytes.fromhex(plan["body_hex"]))
                    write_private_json(
                        args.output / "pending.json", {"request": request, "plan": plan}
                    )
                    record(
                        args.output,
                        {
                            "kind": "submitting",
                            "sequence": sequence,
                            "operation": request["operation"],
                            "body_hash": body.hash.hex(),
                        },
                    )
                    seqno = await transfers.send(sender, Address(address), plan["value"], body)

                    async def included():
                        account = await client.raw_get_account_state(Address(address))
                        txs = await client.raw_get_transactions(
                            Address(address), account.last_transaction_id
                        )
                        found = [tx for tx in txs.transactions if tx.in_msg.body_hash == body.hash]
                        require(len(found) <= 1, "duplicate pool input")
                        return (account, found[0]) if found else None

                    pool_account, tx = await transfers.wait_for(included, timeout=120)
                    local.write_bytes(args.output / "last-pool-transaction.boc", tx.data, 0o600)
                    transfers.check_transaction(tx)
                    transfers.verify_message(
                        tx.in_msg,
                        sender.address.to_str(is_user_friendly=False),
                        address,
                        plan["value"],
                        body.hash,
                    )
                    verify_state(await pool_state(args, address), plan["expected"])
                    require((await sender.current).seqno == seqno + 1, "sender seqno differs")
                    outgoing = await client.raw_get_transactions(
                        sender.address,
                        (await client.raw_get_account_state(sender.address)).last_transaction_id,
                    )
                    matches = [
                        (t, m)
                        for t in outgoing.transactions
                        for m in t.out_msgs
                        if m.body_hash == body.hash
                    ]
                    require(
                        len(matches) == 1 and matches[0][1].hash == tx.in_msg.hash,
                        "funding send and pool receipt differ",
                    )
                    transfers.check_transaction(matches[0][0])
                    require(
                        before_s.balance
                        - (await client.raw_get_account_state(sender.address)).balance
                        >= plan["value"],
                        "funding debit differs",
                    )
                    payout_boc = None
                    if request["operation"] == "withdraw":
                        require(len(tx.out_msgs) == 1, "withdrawal did not emit exactly one payout")
                        sent = tx.out_msgs[0]

                        async def paid():
                            a = await client.raw_get_account_state(recipient.address)
                            txs = await client.raw_get_transactions(
                                recipient.address, a.last_transaction_id
                            )
                            return next(
                                ((a, t) for t in txs.transactions if t.in_msg.hash == sent.hash),
                                None,
                            )

                        after_r, paid_tx = await transfers.wait_for(paid, timeout=120)
                        transfers.check_transaction(paid_tx)
                        require(not paid_tx.out_msgs, "withdrawal bounced or emitted messages")
                        verify_withdrawal(
                            before_r.balance,
                            after_r.balance,
                            request["amount"],
                            paid_tx.fee,
                            sent,
                            paid_tx.in_msg,
                            address,
                            recipient_raw,
                        )
                        payout_boc = base64.b64encode(paid_tx.data).decode()
                    else:
                        require(not tx.out_msgs, "deposit or private transfer emitted a payout")
                    expected_pool = transfers.snapshot(pool_account)
                    expected_data = Cell.one_from_boc(pool_account.data).hash
                    funding_after = await client.raw_get_account_state(sender.address)
                    recipient_after = await client.raw_get_account_state(recipient.address)
                    wallet_expected = [
                        transfers.snapshot(funding_after),
                        transfers.snapshot(recipient_after),
                    ]

                    async def synchronized():
                        states = await asyncio.gather(
                            *[c.raw_get_account_state(Address(address)) for c in clients]
                        )
                        wallet_states = await asyncio.gather(
                            *[
                                c.raw_get_account_state(addr)
                                for c in clients
                                for addr in (sender.address, recipient.address)
                            ]
                        )
                        return all(
                            transfers.snapshot(a) == wallet_expected[i % 2]
                            for i, a in enumerate(wallet_states)
                        ) and all(
                            transfers.snapshot(a) == expected_pool
                            and Cell.one_from_boc(a.data).hash == expected_data
                            for a in states
                        )

                    await transfers.wait_for(synchronized, timeout=120)
                    state, expected = plan["state"], plan["expected"]
                    write_private_json(
                        statepath,
                        {
                            "zerostate_root": network["zerostate_root"],
                            "pool": address,
                            "state": state,
                            "expected": expected,
                        },
                    )
                    sequence += 1
                    done += 1
                    counts[request["operation"]] += 1
                    record(
                        args.output,
                        {
                            "kind": "confirmed",
                            "sequence": sequence,
                            "operation": request["operation"],
                            "counts": counts,
                            "amount_nanotos": request["amount"],
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                            "nodes_agree": len(clients),
                            "expected": expected,
                            "transaction_bocs": [base64.b64encode(tx.data).decode(), payout_boc],
                        },
                    )
                    (args.output / "pending.json").unlink()
            finally:
                if generator.returncode is None:
                    os.killpg(generator.pid, signal.SIGTERM)
                    try:
                        await asyncio.wait_for(generator.wait(), 5)
                    except asyncio.TimeoutError:
                        os.killpg(generator.pid, signal.SIGKILL)
                        await generator.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, default=Path("/data"))
    p.add_argument("--output", type=Path, default=Path("/data/privacy-transfers"))
    p.add_argument("--nodes", type=int, default=7, help="fixed full-node inventory size")
    p.add_argument("--build", type=Path, default=REPO / "build")
    p.add_argument(
        "--generator", type=Path,
        default=REPO / "tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic",
    )
    p.add_argument("--bootstrap", action="store_true")
    p.add_argument("--count", type=int, default=0)
    p.add_argument("--min-interval", type=float, default=20)
    p.add_argument("--max-interval", type=float, default=60)
    p.add_argument("--seed", type=int)
    args = p.parse_args()
    os.umask(0o077)
    try:
        asyncio.run(run(args))
    except Exception as exc:
        if args.output.exists():
            record(args.output, {"kind": "failed", "error": f"{type(exc).__name__}: {exc}"})
        raise


if __name__ == "__main__":
    main()
