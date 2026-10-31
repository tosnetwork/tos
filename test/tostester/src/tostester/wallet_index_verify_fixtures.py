"""Real wallet traffic for the disposable native index-verification image.

Every lifecycle step waits for a committed transaction and checks its VM/action
result. Destruction uses the fixture wallet's own signature and send mode 160
to return its balance to the local Genesis wallet. Redeployment uses exactly
the same StateInit, so the second incarnation has the same account address.
"""

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import NotRequired, TypedDict

import nacl.signing
from contract import tos
from contract.wallet_v1 import WalletV1, WalletV1Blueprint
from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage
from pytosiq_core.tlb.transaction import Transaction, TransactionOrdinary
from tosapi import toslib_api

from tl import JSONSerializable
from toslib import ToslibClient

MAX_TRANSACTIONS = 32
MAX_TRANSACTION_BOC_BYTES = 64 << 10


class TransactionReceipt(TypedDict):
    operation: str
    account: str
    lt: int
    hash: str
    boc_sha256: str
    boc: str
    prev_lt: int
    orig_status: str
    end_status: str
    compute_exit: int
    action_result: int
    destroyed: bool
    shard_block: NotRequired[dict[str, JSONSerializable]]
    absent_at: NotRequired[dict[str, JSONSerializable]]


async def master_tip(client: ToslibClient, minimum: int = 1) -> toslib_api.Tos_blockIdExt:
    async with asyncio.timeout(120):
        while True:
            last = (await client.get_masterchain_info()).last
            if last is not None and last.seqno >= minimum:
                return last
            await asyncio.sleep(0.2)


async def shard_tip(client: ToslibClient) -> toslib_api.Tos_blockIdExt:
    shards = (await client.get_shards(await master_tip(client))).shards
    if len(shards) != 1 or shards[0].workchain != 0 or shards[0].shard != -(1 << 63):
        raise RuntimeError("wallet fixtures require the disposable image's single basechain shard")
    return shards[0]


def transfer(sender: Address, recipient: Address, amount: str, mode: int = 3) -> WalletMessage:
    return WalletMessage(
        send_mode=mode,
        message=MessageAny(
            info=InternalMsgInfo(
                ihr_disabled=True,
                bounce=False,
                bounced=False,
                src=sender,
                dest=recipient,
                value=tos(amount),
                ihr_fee=0,
                fwd_fee=0,
                created_lt=0,
                created_at=0,
            ),
            init=None,
            body=Cell.empty(),
        ),
    )


def blueprint(name: str) -> WalletV1Blueprint:
    # These keys only control tiny balances on this isolated, disposable chain.
    seed = hashlib.sha256(f"native-wallet-index-fixture:{name}".encode()).digest()
    return WalletV1Blueprint(private_key=nacl.signing.SigningKey(seed))


def account_is_absent(state: toslib_api.Raw_fullAccountState) -> bool:
    # The native client leaves balance=-1 for a proof-validated absent root.
    # Zero is a valid balance of an existing account and does not prove absence.
    return (
        state.balance == -1
        and not state.code
        and not state.data
        and not state.frozen_hash
        and not state.extra_currencies
    )


@dataclass
class WalletFixtures:
    client: ToslibClient
    treasury: WalletV1
    root: Path
    accounts: dict[str, dict[str, object]] = field(default_factory=dict)
    transactions: list[TransactionReceipt] = field(default_factory=list)
    stale_checkpoint: int = 0

    async def record_transaction(
        self, name: str, address: Address, transaction_id: toslib_api.Internal_transactionId
    ) -> TransactionReceipt:
        found = await self.client.raw_get_transactions(address, transaction_id)
        raw = next(
            (item for item in found.transactions if item.transaction_id == transaction_id), None
        )
        if raw is None:
            raise RuntimeError(f"{name}: committed transaction cannot be read back")
        if len(self.transactions) >= MAX_TRANSACTIONS or len(raw.data) > MAX_TRANSACTION_BOC_BYTES:
            raise RuntimeError("wallet fixture transaction evidence exceeds its bounded archive")
        cell = Cell.one_from_boc(raw.data)
        transaction = Transaction.deserialize(cell.begin_parse())
        if not isinstance(transaction, Transaction):
            raise RuntimeError(f"{name}: transaction is not an ordinary cell")
        if (
            cell.hash != transaction_id.hash
            or transaction.account_addr != address.hash_part
            or transaction.lt != transaction_id.lt
        ):
            raise RuntimeError(f"{name}: transaction identity does not match the chain response")
        description = transaction.description
        if (
            not isinstance(description, TransactionOrdinary)
            or description.aborted
            or description.compute_ph is None
            or description.compute_ph.type_ != "vm"
            or description.compute_ph.success is not True
            or description.compute_ph.exit_code not in (0, 1)
            or description.action is None
            or not description.action.success
            or description.action.result_code != 0
        ):
            raise RuntimeError(f"{name}: fixture transaction did not execute successfully")
        self.root.mkdir(parents=True, exist_ok=True)
        boc = self.root / f"{name}.boc"
        boc.write_bytes(raw.data)
        receipt: TransactionReceipt = {
            "operation": name,
            "account": address.to_str(is_user_friendly=False),
            "lt": transaction.lt,
            "hash": cell.hash.hex(),
            "boc_sha256": hashlib.sha256(raw.data).hexdigest(),
            "boc": boc.name,
            "prev_lt": transaction.prev_trans_lt,
            "orig_status": transaction.orig_status.type_,
            "end_status": transaction.end_status.type_,
            "compute_exit": description.compute_ph.exit_code,
            "action_result": description.action.result_code,
            "destroyed": description.destroyed,
        }
        self.transactions.append(receipt)
        return receipt

    async def wait_active(
        self, address: Address, after: int = 0
    ) -> toslib_api.Internal_transactionId:
        async with asyncio.timeout(120):
            while True:
                state = await self.client.raw_get_account_state(address)
                last = state.last_transaction_id
                if state.code and last is not None and last.lt > after:
                    return last
                await asyncio.sleep(0.2)

    async def wait_treasury_seqno(self, expected: int) -> None:
        async with asyncio.timeout(120):
            while (await self.treasury.current).seqno < expected:
                await asyncio.sleep(0.2)

    async def fund(
        self, name: str, target: WalletV1Blueprint, *, deploy: bool, after: int = 0
    ) -> TransactionReceipt:
        seqno = (await self.treasury.current).seqno
        if deploy:
            await self.treasury.deploy(target, tos("2"), seqno)
        else:
            await self.treasury.send(transfer(self.treasury.address, target.address, "0.25"), seqno)
        await self.wait_treasury_seqno(seqno + 1)
        last = await self.wait_active(target.address, after)
        return await self.record_transaction(name, target.address, last)

    async def destroy(self, name: str, target: WalletV1Blueprint) -> TransactionReceipt:
        wallet = target.materialize(self.client)
        previous = await shard_tip(self.client)
        await wallet.send(transfer(wallet.address, self.treasury.address, "0", mode=160))
        checked = previous.seqno
        receipt = None
        async with asyncio.timeout(120):
            while receipt is None:
                current = await shard_tip(self.client)
                for seqno in range(checked + 1, current.seqno + 1):
                    block = await self.client.lookup_block(0, current.shard, seqno=seqno)
                    for item in await self.client.get_block_transactions(block):
                        if item.account == target.address.hash_part:
                            receipt = await self.record_transaction(
                                name,
                                target.address,
                                toslib_api.Internal_transactionId(lt=item.lt, hash=item.hash),
                            )
                            receipt["shard_block"] = block.to_dict()
                            break
                    if receipt is not None:
                        break
                checked = current.seqno
                if receipt is None:
                    await asyncio.sleep(0.2)
        if receipt["destroyed"] is not True or receipt["end_status"] != "nonexist":
            raise RuntimeError(f"{name}: mode 160 did not destroy the fixture account")
        async with asyncio.timeout(120):
            while True:
                state = await self.client.raw_get_account_state(target.address)
                if account_is_absent(state):
                    receipt["absent_at"] = (await master_tip(self.client)).to_dict()
                    return receipt
                await asyncio.sleep(0.2)

    async def before_init(self) -> None:
        dormant = blueprint("dormant")
        deployed = await self.fund("dormant-deploy", dormant, deploy=True)
        last = await master_tip(self.client)
        stale = await master_tip(self.client, last.seqno + 2)
        header = await self.client.get_block_header(stale)
        if header.is_key_block or header.prev_key_block_seqno != 0:
            raise RuntimeError("dormant fixture was not committed before the init key block")
        self.stale_checkpoint = stale.seqno
        self.accounts["dormant"] = {
            "address": dormant.address.to_str(is_user_friendly=False),
            "last_lt": deployed["lt"],
            "last_hash": deployed["hash"],
        }

    async def after_init(self, init_seqno: int) -> toslib_api.Tos_blockIdExt:
        if not 0 < self.stale_checkpoint < init_seqno:
            raise RuntimeError("the stale snapshot checkpoint must precede the joined init block")
        for name in ("history", "destroyed", "recreated"):
            target = blueprint(name)
            deployed = await self.fund(f"{name}-deploy", target, deploy=True)
            funded = await self.fund(
                f"{name}-fund", target, deploy=False, after=int(deployed["lt"])
            )
            account: dict[str, object] = {
                "address": target.address.to_str(is_user_friendly=False),
                "first_lt": deployed["lt"],
                "last_lt": funded["lt"],
            }
            if name == "history":
                funded = await self.fund(
                    "history-fund-again", target, deploy=False, after=int(funded["lt"])
                )
                account["last_lt"] = funded["lt"]
            else:
                destroyed = await self.destroy(f"{name}-destroy", target)
                account["destroy_lt"] = destroyed["lt"]
                account["destroy_hash"] = destroyed["hash"]
                absent_at = destroyed.get("absent_at")
                if absent_at is None:
                    raise RuntimeError("the destruction receipt has no observed account absence")
                account["absent_at"] = absent_at
                account["last_lt"] = destroyed["lt"]
                if name == "recreated":
                    recreated = await self.fund("recreated-redeploy", target, deploy=True)
                    if recreated["prev_lt"] != 0 or recreated["orig_status"] != "nonexist":
                        raise RuntimeError("redeployment did not start a new account incarnation")
                    funded = await self.fund(
                        "recreated-fund-again", target, deploy=False, after=int(recreated["lt"])
                    )
                    account["new_first_lt"] = recreated["lt"]
                    account["last_lt"] = funded["lt"]
            self.accounts[name] = account
        last = await master_tip(self.client)
        checkpoint = await master_tip(self.client, last.seqno + 3)
        dormant = await self.client.raw_get_account_state(blueprint("dormant").address)
        if (
            dormant.last_transaction_id is None
            or dormant.last_transaction_id.lt != self.accounts["dormant"]["last_lt"]
        ):
            raise RuntimeError("the dormant account changed after its pre-window transaction")
        destroyed = await self.client.raw_get_account_state(blueprint("destroyed").address)
        if not account_is_absent(destroyed):
            raise RuntimeError("the destroyed account exists at the donor checkpoint")
        receipt = {
            "result": "NATIVE_WALLET_INDEX_FIXTURES_OK",
            "schema": 1,
            "init_seqno": init_seqno,
            "stale_checkpoint": self.stale_checkpoint,
            "checkpoint": checkpoint.to_dict(),
            "accounts": self.accounts,
            "transactions": self.transactions,
        }
        (self.root.parent / "wallet-index-fixtures.json").write_text(
            json.dumps(receipt, indent=2) + "\n"
        )
        return checkpoint
