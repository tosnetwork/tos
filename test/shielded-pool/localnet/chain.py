"""Reads of the isolated chain and the one kind of write the tooling makes:
a transfer from the network's genesis wallet, which exists only on a local
development network and holds tokens of no value.

Reads go through a local node's JSON-RPC, which these drivers trust for the
facts they record alongside the client's own proof-verified reads. The genesis
transfer goes through `toslib` with the lite-client config the network wrote,
as the earlier local drivers did; the import is deferred so the pure modules
and their unit tests need neither the library nor a running network.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

from adjudicate import Bounce, Payout
from localnet_common import MASTERCHAIN_SHARD, NANOTOS, Localnet, LocalnetError, rpc

JSON = dict[str, Any]


def friendly_to_raw(address: str) -> str:
    """A user-friendly base64url address as `workchain:hex`."""
    import base64

    normalised = address.replace("-", "+").replace("_", "/")
    data = base64.b64decode(normalised + "=" * (-len(normalised) % 4))
    if len(data) != 36:
        raise LocalnetError(f"not an address: {address!r}")
    workchain = int.from_bytes(data[1:2], "big", signed=True)
    return f"{workchain}:{data[2:34].hex()}"


def raw_address(address: str) -> str:
    """Any address the node prints, as lower-case `workchain:hex`."""
    if ":" in address:
        workchain, _, account = address.partition(":")
        return f"{int(workchain)}:{account.lower()}"
    return friendly_to_raw(address)


def account_information(net: Localnet, address: str) -> JSON:
    return rpc(net.rpc_url, "getAddressInformation", address=address)


def balance(net: Localnet, address: str) -> int:
    return int(rpc(net.rpc_url, "getAddressBalance", address=address))


def account_state(net: Localnet, address: str) -> str:
    return str(account_information(net, address).get("state"))


def wait_active(net: Localnet, address: str, timeout: float = 120.0) -> JSON:
    deadline = time.monotonic() + timeout
    while True:
        info = account_information(net, address)
        if info.get("state") == "active":
            return info
        if time.monotonic() > deadline:
            raise LocalnetError(f"{address} did not become active within {timeout:.0f} s")
        time.sleep(1)


def code_hash_hex(info: JSON) -> str:
    """The hash of an active account's code cell, from its BOC."""
    import base64

    from pytosiq_core import Cell

    code = info.get("code")
    if not code:
        raise LocalnetError("the account has no code")
    return Cell.one_from_boc(base64.b64decode(code)).hash.hex()


def transactions(net: Localnet, address: str, limit: int = 20) -> list[JSON]:
    return list(rpc(net.rpc_url, "getTransactions", address=address, limit=limit))


def masterchain_seqno(net: Localnet) -> int:
    return int(rpc(net.rpc_url, "getMasterchainInfo")["last"]["seqno"])


def find_bounce(net: Localnet, pool: str, source: str, since_lt: int) -> Bounce | None:
    """The pool's transaction, after `since_lt`, that received a bounce from `source`."""
    for tx in transactions(net, pool, limit=50):
        message = tx.get("in_msg") or {}
        lt = int(tx["transaction_id"]["lt"])
        if lt <= since_lt or not message or message.get("kind") != "internal":
            continue
        if raw_address(str(message.get("source"))) != raw_address(source):
            continue
        return Bounce(
            transaction_hash=str(tx["transaction_id"]["hash"]),
            lt=lt,
            source=raw_address(str(message["source"])),
            value=int(message["value"]),
            bounced=bool(message.get("bounced")),
        )
    return None


def find_payout(net: Localnet, recipient: str, pool: str, since_lt: int) -> Payout | None:
    """The recipient's transaction, after `since_lt`, that received a message from the pool."""
    for tx in transactions(net, recipient, limit=50):
        message = tx.get("in_msg") or {}
        lt = int(tx["transaction_id"]["lt"])
        if lt <= since_lt or not message or message.get("kind") != "internal":
            continue
        if raw_address(str(message.get("source"))) != raw_address(pool):
            continue
        return Payout(
            transaction_hash=str(tx["transaction_id"]["hash"]),
            source=raw_address(str(message["source"])),
            value=int(message["value"]),
            bounced=bool(message.get("bounced")),
            fee=int(tx.get("fee", 0)),
        )
    return None


def last_lt(net: Localnet, address: str) -> int:
    """The logical time of the account's newest transaction, 0 for none."""
    rows = transactions(net, address, limit=1)
    return int(rows[0]["transaction_id"]["lt"]) if rows else 0


def wait_for(predicate: Any, what: str, timeout: float = 180.0, interval: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            raise LocalnetError(f"{what} did not happen within {timeout:.0f} s")
        time.sleep(interval)


# -------------------------------------------------------- genesis transfers ---


class PatientClient:
    """A toslib client that waits out a lite server's admission limit.

    A query refused with LITE_SERVER_NOTREADY was never executed, so asking
    again is safe. Every other error is raised at once.
    """

    def __init__(self, client: Any, attempts: int = 7, delay: float = 0.5) -> None:
        self._client, self._attempts, self._delay = client, attempts, delay

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._client, name)
        if not inspect.iscoroutinefunction(attr):
            return attr

        async def call(*args: Any, **kwargs: Any) -> Any:
            wait = self._delay
            for attempt in range(self._attempts):
                try:
                    return await attr(*args, **kwargs)
                except Exception as exc:
                    if "LITE_SERVER_NOTREADY" not in str(exc) or attempt + 1 == self._attempts:
                        raise
                    await asyncio.sleep(wait)
                    wait = min(wait * 2, 8)

        return call


def lite_config(net: Localnet) -> Any:
    """The lite-client config with its proof chain started at the latest key
    block, which a short archive retention makes necessary for a fresh client."""
    from tosapi import tos_api

    config = json.loads(Path(net.toslib_config).read_text())
    head = masterchain_seqno(net)
    header = rpc(net.rpc_url, "getBlockHeader", workchain=-1, shard=MASTERCHAIN_SHARD, seqno=head)
    key = int(header["seqno"] if header.get("is_key_block") else header["prev_key_block_seqno"])
    if key > 0:
        block = rpc(net.rpc_url, "lookupBlock", workchain=-1, shard=MASTERCHAIN_SHARD, seqno=key)
        config["validator"]["init_block"] = {
            "workchain": int(block["workchain"]),
            "shard": int(block["shard"]),
            "seqno": int(block["seqno"]),
            "root_hash": block["root_hash"],
            "file_hash": block["file_hash"],
        }
    return tos_api.Liteclient_config_global.from_dict(config)


async def _send_from_genesis(
    net: Localnet, destination: str, amount: int, init_boc: bytes | None, bounce: bool
) -> None:
    import nacl.signing
    from contract import WalletV1, tos
    from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, StateInit, WalletMessage
    from toslib.toslib_cdll import ToslibCDLL

    from toslib import ToslibClient

    # The wallet helpers are typed against their own copy of the cell library;
    # this driver only hands them to each other.
    wallet_v1: Any = WalletV1
    wallet_message: Any = WalletMessage
    message_any: Any = MessageAny
    internal_info: Any = InternalMsgInfo
    address_of: Any = Address

    cdll = ToslibCDLL(Path(net.toslib_library))
    cdll.client_set_verbosity_level(0)
    genesis = net.network()["genesis_wallet_address"]
    init = None
    if init_boc is not None:
        init = StateInit.deserialize(Cell.one_from_boc(init_boc).begin_parse())
    async with ToslibClient(lite_config(net), cdll) as raw_client:
        client = cast(Any, PatientClient(raw_client))
        wallet = wallet_v1(
            client,
            address_of(genesis),
            nacl.signing.SigningKey(Path(net.genesis_key).read_bytes()),
        )
        await wallet.send(
            wallet_message(
                send_mode=3,
                message=message_any(
                    info=internal_info(
                        ihr_disabled=True,
                        bounce=bounce,
                        bounced=False,
                        src=wallet.address,
                        dest=address_of(destination),
                        value=tos(Decimal(amount) / NANOTOS),
                        ihr_fee=0,
                        fwd_fee=0,
                        created_lt=0,
                        created_at=0,
                    ),
                    init=init,
                    body=Cell.empty(),
                ),
            )
        )


def fund(
    net: Localnet,
    destination: str,
    amount: int,
    *,
    init_boc: bytes | None = None,
    marker: Path | None = None,
) -> None:
    """One transfer from the genesis wallet. With `marker`, the transfer is
    attempted once: a marker left by an earlier attempt means its outcome is
    unknown and must be reconciled from the chain, never repeated blindly."""
    if amount <= 0:
        raise LocalnetError("a funding amount of zero")
    if marker is not None:
        with marker.open("x") as handle:
            handle.write("one setup transfer; reconcile on unknown outcome\n")
    asyncio.run(_send_from_genesis(net, destination, amount, init_boc, bounce=False))
