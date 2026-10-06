"""Small durable sender for the disposable local faucet, not a wallet service.

Persist the exact WalletV1 signed message before broadcasting it. Recovery may
resend those bytes at the SAME wallet seqno, never rebuild the payment at a new
seqno. A wallet inclusion is followed through to the destination transaction.
"""

import asyncio
import base64
import fcntl
import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import local_pq_testnet as local
from pytosiq_core import (
    Address, Cell, CurrencyCollection, ExternalMsgInfo, InternalMsgInfo, MessageAny, Transaction, WalletMessage,
)

from local_pq_funding_policy import coins


def atomic_json(path, value):
    """Publish a complete owner-private record, including across power loss."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".intent-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    with os.fdopen(local.open_private(path, os.O_RDONLY)) as handle:
        return json.load(handle)


@contextmanager
def faucet_lock(data):
    fd = local.open_private(Path(data) / ".local-pq-faucet.lock", os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def raw(address):
    return address.to_str(is_user_friendly=False)


def cursor(value):
    return {"lt": value.lt, "hash": value.hash.hex()} if value else {"lt": 0, "hash": "00" * 32}


def decoded(transaction):
    if not transaction.data:
        raise ValueError("transaction evidence has no BOC")
    cell = Cell.one_from_boc(transaction.data)
    tx = Transaction.deserialize(cell.begin_parse())
    if cell.hash != transaction.transaction_id.hash or tx.lt != transaction.transaction_id.lt:
        raise ValueError("transaction BOC does not match its advertised identity")
    return tx


def successful(transaction):
    description = transaction.description
    compute = getattr(description, "compute_ph", None)
    action = getattr(description, "action", None)
    return (getattr(description, "aborted", True) is False
            and getattr(compute, "success", False) is True
            and (action is None or (action.success and action.valid)))


async def history_since(client, address, baseline, max_pages=64):
    """Require the complete window, including the exact baseline hash."""
    account = await client.raw_get_account_state(address)
    position = account.last_transaction_id
    result = []
    for _ in range(max_pages):
        current = cursor(position)
        if current == baseline:
            return result
        if current["lt"] <= baseline["lt"]:
            raise ValueError("transaction history crossed or changed its baseline")
        page = await client.raw_get_transactions(address, position)
        for item in page.transactions:
            ident = cursor(item.transaction_id)
            if ident["lt"] == baseline["lt"]:
                if ident != baseline:
                    raise ValueError("transaction baseline hash changed")
                return result
            if ident["lt"] < baseline["lt"]:
                raise ValueError("incomplete transaction history")
            if not result or ident != cursor(result[-1].transaction_id):
                result.append(item)
        previous = page.previous_transaction_id
        if cursor(previous)["lt"] >= current["lt"]:
            raise ValueError("transaction history made no progress")
        position = previous
    raise ValueError("transaction history exceeds the bounded evidence window")


def fingerprint(message):
    info = message.info
    if not isinstance(info, InternalMsgInfo):
        return None
    return dict(src=raw(info.src), dest=raw(info.dest), lt=info.created_lt,
                body=message.body.hash.hex(), value=info.value.tomis,
                init=message.init.serialize().hash.hex() if message.init else None)


class Faucet:
    def __init__(self, client, wallet, directory, network_id, *, readonly=False):
        self.client, self.wallet = client, wallet
        self.directory = Path(directory) if readonly else local.secure_output_dir(directory)
        self.network_id = network_id
        self.pending = self.directory / "pending.json"

    def path(self, label):
        return self.directory / (hashlib.sha256(label.encode()).hexdigest() + ".json")

    def record(self, label):
        path = self.path(label)
        if path.exists():
            value = read_json(path)
        elif self.pending.exists():
            value = read_json(self.pending)
            if value["label"] != label:
                return None
        else:
            return None
        if (value["label"] != label or value["network"] != self.network_id
                or value["wallet"] != raw(self.wallet.address)):
            raise ValueError("faucet intent belongs to another chain, wallet or operation")
        return value

    def clear_pending(self, label):
        if self.pending.exists() and read_json(self.pending)["label"] == label:
            self.pending.unlink()
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    async def recover(self):
        if not self.pending.exists():
            return []
        value = read_json(self.pending)
        value = self.record(value["label"])
        receipt = await self.finish(value)
        self.clear_pending(value["label"])
        return [receipt]

    async def transfer(self, label, dest, amount, body=None, init=None, bounce=False):
        value = self.record(label)
        if value is None:
            # Finish any earlier uncertain payment before consuming another seqno.
            await self.recover()
            coins(amount, "message value")
            body = body if body is not None else Cell.empty()
            account = await self.client.raw_get_account_state(self.wallet.address)
            seqno = (await self.wallet.current).seqno
            message = WalletMessage(send_mode=3, message=MessageAny(
                info=InternalMsgInfo(ihr_disabled=True, bounce=bounce, bounced=False,
                                     src=self.wallet.address, dest=dest,
                                     value=CurrencyCollection(tomis=amount), ihr_fee=0,
                                     fwd_fee=0, created_lt=0, created_at=0),
                init=init, body=body))
            signed = self.wallet.sign(message, seqno)
            destination = await self.client.raw_get_account_state(dest)
            value = dict(label=label, network=self.network_id, wallet=raw(self.wallet.address),
                         dest=raw(dest), amount=amount, body=body.hash.hex(), init=init.serialize().hash.hex() if init else None,
                         bounce=bounce, seqno=seqno,
                         signed=base64.b64encode(signed.to_boc()).decode(),
                         wallet_baseline=cursor(account.last_transaction_id),
                         destination_baseline=cursor(destination.last_transaction_id),
                         state="prepared")
            atomic_json(self.pending, value)
        elif (value["dest"] != raw(dest) or value["amount"] != amount
              or value["body"] != (body if body is not None else Cell.empty()).hash.hex()
              or value["init"] != (init.serialize().hash.hex() if init else None)
              or value["bounce"] != bounce):
            raise ValueError("operation label reused for a different payment")
        return await self.finish(value)

    async def finish(self, value, timeout=60):
        if value["state"] == "done":
            self.clear_pending(value["label"])
            return value
        signed = Cell.one_from_boc(base64.b64decode(value["signed"], validate=True))
        seqno = (await self.wallet.current).seqno
        if seqno < value["seqno"]:
            raise ValueError("faucet seqno moved backwards")
        if seqno == value["seqno"]:
            # The WAL is durable already. A transport exception cannot authorize
            # a second payment: recovery only ever resends this signed body.
            await self.wallet.send_external(body=signed)
        deadline = time.monotonic() + timeout
        outgoing = None
        while time.monotonic() < deadline:
            if outgoing is None:
                history = await history_since(self.client, self.wallet.address,
                                              value["wallet_baseline"])
                transactions = [decoded(t) for t in history]
                matches = [tx for tx in transactions
                           if tx.in_msg is not None
                           and isinstance(tx.in_msg.info, ExternalMsgInfo)
                           and tx.in_msg.info.dest == self.wallet.address
                           and tx.in_msg.body.hash == signed.hash]
                if len(matches) > 1:
                    raise ValueError("signed faucet intent appears more than once")
                if matches:
                    tx = matches[0]
                    if not successful(tx):
                        raise ValueError("faucet transaction failed; operator reconciliation required")
                    outputs = [m for m in tx.out_msgs
                               if isinstance(m.info, InternalMsgInfo)
                               and m.info.src == self.wallet.address
                               and raw(m.info.dest) == value["dest"]
                               and m.body.hash.hex() == value["body"]
                               and m.info.value.tomis == value["amount"]]
                    if len(outputs) != 1:
                        raise ValueError("wallet inclusion did not emit the exact intended payment")
                    outgoing = fingerprint(outputs[0])
                # State and transaction RPCs can briefly expose different heads.
                # Do not mistake that lag for an unrelated wallet payment; retain
                # the intent and keep looking within this bounded observation.
            if outgoing is not None:
                history = await history_since(self.client, Address(value["dest"]),
                                              value["destination_baseline"])
                for item in history:
                    tx = decoded(item)
                    if tx.in_msg is not None and fingerprint(tx.in_msg) == outgoing:
                        compute = getattr(tx.description, "compute_ph", None)
                        action = getattr(tx.description, "action", None)
                        value.update(state="done", ok=successful(tx),
                                     transaction=cursor(item.transaction_id),
                                     exit_code=getattr(compute, "exit_code", None),
                                     action_code=getattr(action, "result_code", None))
                        atomic_json(self.path(value["label"]), value)
                        self.clear_pending(value["label"])
                        return value
            await asyncio.sleep(0.5)
        raise TimeoutError(f"unresolved faucet operation {value['label']}; signed intent retained")


def require_success(receipt):
    if not receipt["ok"]:
        raise ValueError(f"{receipt['label']} refused: exit={receipt['exit_code']}, "
                         f"action={receipt['action_code']}")
