"""Remote mode for the shard bench: one bounded hop burst against existing JSON-RPC endpoints.

``run_shard_bench.py --remote`` lands here before any liteserver or local-net
module is imported, so nothing on this path opens a liteserver connection or
boots a node. Every read and send goes through ``rpc.PacedRpc`` inside
``--rpc-share`` of each node's per-source budget.

A run:

1. checks the burst caps and computes an upper bound on the burst's work
   (messages and transactions) and on the value it attaches, and refuses
   to go on when it exceeds ``--max-messages`` or ``--max-cost``. Nothing
   is read or sent before this step;
2. reads the gas, forwarding and storage prices from the live configuration
   (ConfigParams 21, 25 and 18 for the basechain), derives a bound on the
   bench wallet's own fees for both of its externals, and refuses when the
   attached value plus that bound exceeds ``--max-cost``. Nothing is
   written or sent before this step either;
3. funds the hop accounts from the supplied bench wallet (a self-pay Quantum
   wallet whose ML-DSA-44 seed is read from ``--key-file``) in one
   deployment tree, and checks the deployment's real fee against its bound;
4. opens the window at an empty outbound queue, sends the start message, waits
   past the deadline and closes the window at an empty queue. When chain
   time stops advancing the wait ends and the run is recorded INCONCLUSIVE;
5. counts by an RPC chain walk (``t2collect``), and records the value left in
   the hop accounts, which nothing can withdraw.

How the work bound holds: ``hop.fc`` decrements ``remaining`` on every hop
and ends the chain when it reaches 0, forks only while ``forks`` is positive
and decrements it on every fork, and sends hop messages without bounce. The
start message carries ``remaining`` (``--hops``) and ``forks``, and
``chains`` is a uint8, so the contract itself stops every chain at the cap;
running out of value or passing the deadline only ends chains sooner.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import math
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from contract.pq_auth import transfer_message
from pqbench.workload import (
    PUBLIC_KEY_BYTES,
    QSP_PRIMARY_CONTEXT,
    SIGNATURE_BYTES,
    QuantumWallet,
    primary_nonce,
)
from pytosiq_core import Address, Cell, ExternalMsgInfo, MessageAny

from shard import hopbench, t2collect
from shard.rpc import PacedRpc, RpcError

NANO = 1_000_000_000
MAX_CHAINS = hopbench.MAX_CHAINS
MAX_FORKS = 12
MAX_HOPS = 1_000_000
MAX_ACCOUNTS = 65_536
# A self-pay request is valid for at most an hour after the chain's now().
REQUEST_LIFETIME = 600
REFUSED = 3
# The run stopped without an answer, for example because chain time stopped advancing.
INCONCLUSIVE = 4
# The T2 checker found a broken layout, continuity or conservation.
T2_FAILED = 1


def exit_status(t2_status: str) -> int:
    """The process status of a counted run: 0 only for a T2 PASS."""
    return {"PASS": 0, "FAIL": T2_FAILED}.get(t2_status, INCONCLUSIVE)


log = logging.getLogger("shard-bench-remote")


# ─── caps and the work bound ─────────────────────────────────────────


@dataclass(frozen=True)
class Caps:
    chains: int
    forks: int
    hops: int
    accounts: int
    account_funding: int  # nanotos kept by every hop account
    load_funding: int  # nanotos attached to the start message


def _int_in(name: str, value: object, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{name} must be an integer in [{lo}, {hi}]")
    return value


def validate_caps(caps: Caps) -> Caps:
    """Refuse any cap outside the range the bound and the contract support."""
    _int_in("chains", caps.chains, 1, MAX_CHAINS)
    _int_in("forks", caps.forks, 0, MAX_FORKS)
    _int_in("hops", caps.hops, 1, MAX_HOPS)
    _int_in("accounts", caps.accounts, 2, MAX_ACCOUNTS)
    for name in ("account_funding", "load_funding"):
        _int_in(name, getattr(caps, name), 1, (1 << 120) - 1)
    return caps


def hop_transactions(remaining: int, forks: int) -> int:
    """Transactions a hop message with ``remaining`` and ``forks`` causes, itself included.

    hop.fc: with remaining 0 the receiver ends the chain (one transaction);
    otherwise it sends two hops with (remaining - 1, forks - 1) while forks
    is positive and one hop with (remaining - 1, 0) after that.
    """
    _int_in("remaining", remaining, 0, (1 << 32) - 1)
    _int_in("forks", forks, 0, 255)
    if forks >= remaining:
        return (1 << (remaining + 1)) - 1
    return (1 << forks) - 1 + (1 << forks) * (remaining - forks + 1)


@dataclass(frozen=True)
class Bound:
    deploy_messages: int
    deploy_transactions: int
    burst_messages: int
    burst_transactions: int
    messages: int
    transactions: int
    attached_value: int
    wallet_fees: int
    cost: int

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = asdict(self)
        out["cost_tos"] = self.cost / NANO
        return out


def work_bound(caps: Caps, wallet_fees: int = 0) -> Bound:
    """An upper bound on the run's messages, transactions and cost to the bench wallet.

    Deployment: one external, one message from the wallet to copy 0 and one
    message into every other copy, each executed once. Burst: one external,
    the start message, and ``chains`` hop trees of ``hop_transactions(hops,
    forks)`` transactions, each executing one inbound message. Cost: the
    value the wallet attaches (account funding and load funding; every
    hop's fee comes out of that value) plus ``wallet_fees``, the bound on
    the wallet's own fees that ``wallet_fee_bound`` derives from the live
    configuration. Before the configuration is read the bound is taken
    with no wallet fees, which already refuses a run whose attached value
    alone exceeds ``--max-cost``.
    """
    validate_caps(caps)
    fees = _int_in("wallet fees", wallet_fees, 0, 1 << 120)
    tree = hop_transactions(caps.hops, caps.forks)
    deploy_messages = caps.accounts
    deploy_transactions = 1 + caps.accounts
    burst_messages = 1 + caps.chains * tree
    burst_transactions = 2 + caps.chains * tree
    attached = caps.accounts * caps.account_funding + caps.load_funding
    return Bound(
        deploy_messages,
        deploy_transactions,
        burst_messages,
        burst_transactions,
        deploy_messages + burst_messages,
        deploy_transactions + burst_transactions,
        attached,
        fees,
        attached + fees,
    )


def refusal(bound: Bound, max_messages: int, max_cost: int) -> str | None:
    """Why the bound is over a limit, or None when it is inside both."""
    _int_in("max messages", max_messages, 1, 1 << 64)
    _int_in("max cost", max_cost, 1, 1 << 120)
    reasons = []
    if bound.messages > max_messages:
        reasons.append(f"message bound {bound.messages} exceeds --max-messages {max_messages}")
    if bound.cost > max_cost:
        reasons.append(f"cost bound {bound.cost} nanotos exceeds --max-cost {max_cost}")
    return "; ".join(reasons) or None


# ─── the wallet fee bound from the live configuration ────────────────
#
# What one wallet external can cost the wallet, mirrored from the node's
# transaction code (crypto/block/transaction.cpp):
#
# - import: Transaction::unpack_input_msg charges an inbound external
#   MsgPrices::compute_fwd_fees(cells, bits) of the message tree without its
#   root cell and root bits: lump_price + ceil((bit_price * bits +
#   cell_price * cells) / 2^16).
# - computation: compute_gas_limits caps gas at gas_max, the gas the balance
#   buys and never more than gas_limit, and the fee is
#   ComputePhaseConfig::compute_gas_price(gas_used): flat_gas_price up to
#   flat_gas_limit, then + ceil(gas_price * (gas_used - flat_gas_limit) /
#   2^16). The fee at gas_limit bounds every external.
# - forwarding: try_action_send_message prices every out message by the init
#   and body trees it carries; send mode 1 (the bench's mode 3) takes the
#   whole fwd_fee from the wallet's balance. first_frac only splits that fee
#   between this block and the next, so the wallet pays all of it. A failed
#   send is fined at most (cell_price >> 16) / 4 per cell instead, which the
#   forwarding fee covers.
# - storage: StoragePrices::compute_storage_fees charges ceil(sum over the
#   elapsed seconds of (bit_price_ps * bits + cell_price_ps * cells) / 2^16)
#   since last_paid, plus any due payment.
#
# The prices come from ConfigParam 21 (gas) and 25 (forwarding) for the
# basechain, 20 and 24 for the masterchain, and 18 (storage), in the TL-B
# of crypto/block/block.tlb.

CONFIG_PARAM_ABSENT = -32004
# Gas and forwarding ConfigParams by workchain.
FEE_PARAMS = {0: (21, 25), -1: (20, 24)}
STORAGE_PARAM = 18
# An account root holds the address, the storage statistics and the balance
# next to the StateInit; a whole cell of bits covers it.
ACCOUNT_ROOT_BITS = 1023


def _ceil_shr16(value: int) -> int:
    return -((-value) >> 16)


@dataclass(frozen=True)
class GasPrices:
    gas_price: int
    gas_limit: int
    special_gas_limit: int
    gas_credit: int
    flat_gas_limit: int
    flat_gas_price: int

    def fee(self, gas: int) -> int:
        """ComputePhaseConfig::compute_gas_price."""
        if gas <= self.flat_gas_limit:
            return self.flat_gas_price
        return _ceil_shr16(self.gas_price * (gas - self.flat_gas_limit)) + self.flat_gas_price

    def max_fee(self) -> int:
        """The fee at gas_limit, the most gas a non-special account can buy."""
        return self.fee(self.gas_limit)

    def bought_for(self, nanotos: int) -> int:
        """ComputePhaseConfig::gas_bought_for: the gas ``nanotos`` buys, at most gas_limit."""
        if nanotos < self.flat_gas_price:
            return 0
        if nanotos >= self.max_fee():  # max_gas_threshold
            return self.gas_limit
        bought = ((nanotos - self.flat_gas_price) << 16) // self.gas_price + self.flat_gas_limit
        return min(bought, self.gas_limit)

    def internal_fee(self, value: int) -> int:
        """The most computation an inbound internal message carrying ``value`` can cost.

        compute_gas_limits starts an ordinary internal message at the gas its
        value buys; only accept_message raises the limit, and a receiver that
        never accepts (the self-pay wallet's recv_internal) keeps it there.
        """
        return self.fee(self.bought_for(value))


def parse_gas_prices(cell: Cell) -> GasPrices:
    """GasLimitsPrices: gas_prices#dd, gas_prices_ext#de, or either behind gas_flat_pfx#d1."""
    s = cell.begin_parse()
    flat_limit = flat_price = 0
    tag = s.load_uint(8)
    if tag == 0xD1:
        flat_limit, flat_price = s.load_uint(64), s.load_uint(64)
        tag = s.load_uint(8)
    if tag == 0xDE:
        price, limit, special, credit = (s.load_uint(64) for _ in range(4))
    elif tag == 0xDD:
        price, limit, credit = (s.load_uint(64) for _ in range(3))
        special = limit
    else:
        raise ValueError(f"not a GasLimitsPrices cell (tag {tag:#x})")
    for _ in range(3):  # block_gas_limit, freeze_due_limit, delete_due_limit must be present
        s.load_uint(64)
    return GasPrices(price, limit, special, credit, flat_limit, flat_price)


@dataclass(frozen=True)
class MsgPrices:
    lump_price: int
    bit_price: int
    cell_price: int
    ihr_price_factor: int
    first_frac: int
    next_frac: int

    def fee(self, cells: int, bits: int) -> int:
        """MsgPrices::compute_fwd_fees."""
        return self.lump_price + _ceil_shr16(self.bit_price * bits + self.cell_price * cells)


def parse_msg_prices(cell: Cell) -> MsgPrices:
    """msg_forward_prices#ea lump_price bit_price cell_price ihr_price_factor first_frac next_frac."""
    s = cell.begin_parse()
    tag = s.load_uint(8)
    if tag != 0xEA:
        raise ValueError(f"not a MsgForwardPrices cell (tag {tag:#x})")
    return MsgPrices(
        s.load_uint(64),
        s.load_uint(64),
        s.load_uint(64),
        s.load_uint(32),
        s.load_uint(16),
        s.load_uint(16),
    )


@dataclass(frozen=True)
class StoragePrice:
    utime_since: int
    bit_price_ps: int
    cell_price_ps: int
    mc_bit_price_ps: int
    mc_cell_price_ps: int


def _storage_price(s: Any) -> StoragePrice:
    tag = s.load_uint(8)
    if tag != 0xCC:
        raise ValueError(f"not a StoragePrices value (tag {tag:#x})")
    return StoragePrice(*(s.load_uint(32 if i == 0 else 64) for i in range(5)))


def parse_storage_prices(cell: Cell) -> list[StoragePrice]:
    """ConfigParam 18: Hashmap 32 StoragePrices, in key order."""
    prices = cell.begin_parse().load_hashmap(32, value_deserializer=_storage_price)
    if not prices:
        raise ValueError("ConfigParam 18 holds no storage prices")
    return [prices[k] for k in sorted(prices)]


def tree_size(cells: list[Cell]) -> tuple[int, int]:
    """(cells, bits) of the distinct cells under ``cells``, roots included."""
    seen: set[bytes] = set()
    bits = 0
    stack = list(cells)
    while stack:
        cell = stack.pop()
        if cell.hash in seen:
            continue
        seen.add(cell.hash)
        bits += len(cell.bits)
        stack.extend(cell.refs)
    return len(seen), bits


def import_size(external: MessageAny) -> tuple[int, int]:
    """The size an inbound external is charged for: its tree without the root cell.

    The root's bits are counted too, which the node leaves to the lump price.
    """
    cells, bits = tree_size([external.serialize()])
    return cells - 1, bits


def forward_size(message: MessageAny) -> tuple[int, int]:
    """The size an out message is charged for: every cell of its init and body.

    The node skips the init and body roots when they sit inline in the
    message root and counts them when the rewritten message moves them into
    references; counting them always covers both.
    """
    trees = [message.body] + ([message.init.serialize()] if message.init is not None else [])
    return tree_size(trees)


@dataclass(frozen=True)
class FeeConfig:
    workchain: int
    gas: GasPrices
    forwarding: MsgPrices
    storage: list[StoragePrice]  # empty when ConfigParam 18 is absent
    params: dict[str, str]  # ConfigParam number -> its cell's hash, or "absent"

    def as_dict(self) -> dict[str, Any]:
        return {
            "workchain": self.workchain,
            "gas": asdict(self.gas),
            "forwarding": asdict(self.forwarding),
            "storage": [asdict(x) for x in self.storage],
            "config_param_hashes": self.params,
        }


def fee_config(
    workchain: int,
    gas: Cell,
    forwarding: Cell,
    storage: Cell | None,
    params: dict[str, str] | None = None,
) -> FeeConfig:
    if workchain not in FEE_PARAMS:
        raise ValueError(f"no fee ConfigParams for workchain {workchain}")
    return FeeConfig(
        workchain,
        parse_gas_prices(gas),
        parse_msg_prices(forwarding),
        parse_storage_prices(storage) if storage is not None else [],
        params or {},
    )


@dataclass(frozen=True)
class ExternalFee:
    """The most one wallet external can cost the wallet, storage aside, and its inputs."""

    what: str
    import_cells: int
    import_bits: int
    import_fee: int
    gas_limit: int
    gas_fee: int
    out_messages: list[dict[str, int]]
    forward_fees: int
    total: int


def external_fee_bound(
    config: FeeConfig, what: str, external: MessageAny, actions: list[MessageAny]
) -> ExternalFee:
    """The import, computation and forwarding fee bound of ``external``.

    ``external`` must be the wallet external exactly as it will be sent,
    built from ``actions``; a signature of the right length stands in for
    the real one, which has the same size.
    """
    if not actions:
        raise ValueError("a wallet external sends at least one message")
    cells, bits = import_size(external)
    import_fee = config.forwarding.fee(cells, bits)
    gas_fee = config.gas.max_fee()
    out: list[dict[str, int]] = []
    for message in actions:
        destination = getattr(message.info, "dest", None)
        if not isinstance(destination, Address) or destination.wc != config.workchain:
            raise ValueError("an out message leaves the wallet's workchain; its prices differ")
        m_cells, m_bits = forward_size(message)
        out.append(
            {"cells": m_cells, "bits": m_bits, "fee": config.forwarding.fee(m_cells, m_bits)}
        )
    forward_fees = sum(x["fee"] for x in out)
    return ExternalFee(
        what,
        cells,
        bits,
        import_fee,
        config.gas.gas_limit,
        gas_fee,
        out,
        forward_fees,
        import_fee + gas_fee + forward_fees,
    )


@dataclass(frozen=True)
class StorageFee:
    cells: int
    bits: int
    since: int
    until: int
    due_payment: int
    fee: int


def storage_fee_bound(
    config: FeeConfig, cells: int, bits: int, since: int, until: int, due: int
) -> StorageFee:
    """The storage the wallet can be charged between ``since`` and ``until``.

    Every second is priced at the highest rate any ConfigParam 18 entry
    sets, so no change of prices inside the interval can exceed it.
    """
    for name, value in (("cells", cells), ("bits", bits), ("due payment", due)):
        _int_in(name, value, 0, 1 << 120)
    if until < since:
        raise ValueError("a storage interval cannot end before it starts")
    masterchain = config.workchain == -1
    rate = max(
        (
            (p.mc_bit_price_ps if masterchain else p.bit_price_ps) * bits
            + (p.mc_cell_price_ps if masterchain else p.cell_price_ps) * cells
            for p in config.storage
        ),
        default=0,
    )
    return StorageFee(cells, bits, since, until, due, _ceil_shr16(rate * (until - since)) + due)


def account_storage(
    config: FeeConfig,
    state_init: Cell,
    stat: tuple[int, int, int, int] | None,
    now: int,
    until: int,
) -> StorageFee:
    """A wallet's storage bound up to ``until``: the larger of what the node reports and its
    StateInit plus a whole account root, since its last payment (``now`` if never)."""
    cells, bits = tree_size([state_init])
    cells, bits = cells + 1, bits + ACCOUNT_ROOT_BITS
    since, due = now, 0
    if stat is not None:
        cells, bits = max(cells, stat[0]), max(bits, stat[1])
        since, due = (stat[2] if stat[2] > 0 else now), stat[3]
    if since > until:
        raise ValueError("a wallet's last storage payment lies past the fee horizon")
    return storage_fee_bound(config, cells, bits, since, until, due)


@dataclass(frozen=True)
class WalletFeeBound:
    externals: list[ExternalFee]
    storage: StorageFee
    total: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "externals": [asdict(x) for x in self.externals],
            "storage": asdict(self.storage),
            "total": self.total,
        }


def wallet_fee_bound(externals: list[ExternalFee], storage: StorageFee) -> WalletFeeBound:
    return WalletFeeBound(externals, storage, sum(x.total for x in externals) + storage.fee)


# ─── the bench wallet key ────────────────────────────────────────────


class Secret:
    """Key bytes that never render: repr and str hide them."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes):
        self._value = value

    def reveal(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class WalletKey:
    seed: Secret
    rescue_public_key: bytes
    wallet_id: int


def load_key(path: Path) -> WalletKey:
    """The bench wallet key file: JSON with ``mldsa44_seed`` and ``rescue_public_key`` (hex).

    The file must be readable by its owner only. Errors name the field, never its value.
    """
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(f"{path}: the key file must not be readable by group or others")
    try:
        document = json.loads(path.read_text())
    except ValueError as error:
        raise ValueError(f"{path}: the key file is not JSON") from error
    if not isinstance(document, dict):
        raise ValueError(f"{path}: the key file is not a JSON object")
    fields: dict[str, bytes] = {}
    for name in ("mldsa44_seed", "rescue_public_key"):
        value = document.get(name)
        try:
            raw = bytes.fromhex(value) if isinstance(value, str) else b""
        except ValueError:
            raw = b""
        if len(raw) != 32:
            raise ValueError(f"{path}: {name} must be 32 bytes of hex")
        fields[name] = raw
    wallet_id = document.get("wallet_id", 0)
    if type(wallet_id) is not int or not 0 <= wallet_id < (1 << 32):
        raise ValueError(f"{path}: wallet_id must fit uint32")
    return WalletKey(Secret(fields["mldsa44_seed"]), fields["rescue_public_key"], wallet_id)


class Signer:
    """ML-DSA-44 through the bench signer executable; the seed goes over stdin only."""

    def __init__(self, executable: Path, key: WalletKey):
        if not executable.is_file():
            raise FileNotFoundError(f"bench signer not found: {executable}")
        self.executable, self.key = executable.resolve(), key

    def _run(self, args: list[str], line: str, size: int) -> bytes:
        result = subprocess.run(
            [str(self.executable), *args, "--threads", "1"],
            input=line + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            # The signer's stderr could echo its input; report only the exit status.
            raise RuntimeError(f"bench signer failed with exit status {result.returncode}")
        lines = result.stdout.splitlines()
        try:
            out = bytes.fromhex(lines[0]) if len(lines) == 1 else b""
        except ValueError:
            out = b""
        if len(out) != size:
            raise RuntimeError("bench signer returned a malformed answer")
        return out

    def public_key(self) -> bytes:
        return self._run(["public"], self.key.seed.reveal().hex(), PUBLIC_KEY_BYTES)

    def sign(self, message: bytes) -> bytes:
        line = f"{self.key.seed.reveal().hex()} {message.hex()}"
        return self._run(["sign", QSP_PRIMARY_CONTEXT.hex()], line, SIGNATURE_BYTES)


# ─── chain reads and sends over JSON-RPC ─────────────────────────────


def raw(address: Address) -> str:
    return f"{address.wc}:{address.hash_part.hex()}"


class Remote:
    def __init__(self, rpcs: list[PacedRpc], poll: float):
        if not rpcs:
            raise ValueError("remote mode needs at least one --rpc endpoint")
        self.rpcs, self.rpc, self.poll = rpcs, rpcs[0], poll

    async def mc_header(self) -> dict[str, Any]:
        info = await self.rpc.call("getMasterchainInfo")
        last = t2collect.parse_block_id(info.get("last"))
        return await self.rpc.call(
            "getBlockHeader",
            {"workchain": -1, "shard": str(t2collect.MASTERCHAIN_SHARD), "seqno": last.seqno},
        )

    async def now(self) -> int:
        return int((await self.mc_header())["gen_utime"])

    async def wait_past(self, target: int, slack: float) -> int | None:
        """The first chain time after ``target``, or None when it does not come in time.

        The wait is bounded on the monotonic clock: the chain-time distance
        still to go when the wait starts, plus ``slack`` seconds. A network
        whose block production stalls ends the wait instead of holding it.
        """
        first = await self.now()
        limit = time.monotonic() + max(0, target - first) + slack
        now = first
        while now <= target:
            if time.monotonic() >= limit:
                return None
            await asyncio.sleep(self.poll)
            now = await self.now()
        return now

    async def config_cell(self, param: int) -> Cell | None:
        """ConfigParam ``param`` as a cell, None when the network does not set it."""
        try:
            answer = await self.rpc.call("getConfigParam", {"param": param})
        except RpcError as error:
            if isinstance(error.error, dict) and error.error.get("code") == CONFIG_PARAM_ABSENT:
                return None
            raise
        boc = answer.get("config", {}).get("bytes") if isinstance(answer, dict) else None
        if not isinstance(boc, str):
            raise ValueError(f"ConfigParam {param}: the answer carries no cell")
        return Cell.one_from_boc(base64.b64decode(boc))

    async def fee_config(self, workchain: int) -> FeeConfig:
        """The gas, forwarding and storage prices of ``workchain`` from the live configuration."""
        if workchain not in FEE_PARAMS:
            raise ValueError(f"no fee ConfigParams for workchain {workchain}")
        gas_param, fwd_param = FEE_PARAMS[workchain]
        cells: dict[int, Cell | None] = {}
        for param in (gas_param, fwd_param, STORAGE_PARAM):
            cells[param] = await self.config_cell(param)
        gas, fwd = cells[gas_param], cells[fwd_param]
        if gas is None or fwd is None:
            raise ValueError(f"the network sets no ConfigParam {gas_param} or {fwd_param}")
        hashes = {str(k): (v.hash.hex() if v is not None else "absent") for k, v in cells.items()}
        return fee_config(workchain, gas, fwd, cells[STORAGE_PARAM], hashes)

    async def account(self, address: Address) -> dict[str, Any]:
        answer = await self.rpc.call("getAddressInformation", {"address": raw(address)})
        if not isinstance(answer, dict):
            raise ValueError("an account state answer is not an object")
        return answer

    async def balance(self, address: Address) -> int:
        return int((await self.account(address)).get("balance", 0))

    async def balances(self, addresses: list[Address], parallel: int = 8) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in range(0, len(addresses), parallel):
            chunk = addresses[i : i + parallel]
            for address, value in zip(
                chunk, await asyncio.gather(*(self.balance(x) for x in chunk))
            ):
                out[raw(address)] = value
        return out

    async def wait_active(self, addresses: list[Address], timeout: float) -> list[Address]:
        """The accounts still not active when ``timeout`` runs out (empty when all are)."""
        pending = list(addresses)
        deadline = time.monotonic() + timeout
        while pending:
            states = [await self.account(x) for x in pending]
            pending = [x for x, s in zip(pending, states) if s.get("state") != "active"]
            if not pending or time.monotonic() >= deadline:
                break
            log.info(
                "deployment: %d of %d hop accounts not active yet", len(pending), len(addresses)
            )
            await asyncio.sleep(self.poll)
        return pending

    async def send(self, message: MessageAny) -> None:
        boc = base64.b64encode(message.serialize().to_boc()).decode()
        await self.rpc.call("sendBoc", {"boc": boc})


def _count(value: object, name: str) -> int:
    """A non-negative integer the node writes as a JSON number or a decimal string."""
    if isinstance(value, str) and value.isdigit():
        return int(value)
    if type(value) is int and value >= 0:
        return value
    raise ValueError(f"the storage statistic {name} is malformed")


def storage_stat(account: dict[str, Any]) -> tuple[int, int, int, int] | None:
    """(cells, bits, last_paid, due payment) from an account state answer, None when absent."""
    stat = account.get("storage_stat")
    if not isinstance(stat, dict):
        return None
    due = stat.get("due_payment")
    return (
        _count(stat.get("used_cells"), "used_cells"),
        _count(stat.get("used_bits"), "used_bits"),
        _count(stat.get("last_paid"), "last_paid"),
        0 if due is None else _count(due, "due_payment"),
    )


class HorizonPassed(Exception):
    """A request could no longer execute inside the horizon the fee bound covers."""


def bench_wallet(
    code: Cell, global_id: int, auth: bytes, key: WalletKey, public_key: bytes
) -> QuantumWallet:
    """The self-pay Quantum wallet of the key; it holds no seed (the signer does)."""
    return QuantumWallet.derive(
        code,
        global_id,
        auth,
        bytes(32),  # only used to derive a RESCUE key, and the key file supplies one
        "bench",
        key.wallet_id,
        public_key,
        b"",
        rescue=key.rescue_public_key,
    )


class BenchWallet:
    def __init__(self, wallet: QuantumWallet, signer: Signer, remote: Remote):
        self.wallet, self.signer, self.remote = wallet, signer, remote

    @property
    def address(self) -> Address:
        return self.wallet.address

    async def state(self) -> tuple[int, int | None]:
        """(balance, PRIMARY nonce); the nonce is None while the wallet is not deployed."""
        answer = await self.remote.account(self.address)
        balance = int(answer.get("balance", 0))
        if answer.get("state") != "active":
            return balance, None
        data = answer.get("data")
        if not isinstance(data, str) or not data:
            raise ValueError("the bench wallet is active but has no data")
        return balance, primary_nonce(Cell.one_from_boc(base64.b64decode(data)))

    async def storage(self) -> tuple[int, int, int, int]:
        """(cells, bits, last_paid, due payment) of the wallet's storage as the node reports it."""
        stat = storage_stat(await self.remote.account(self.address))
        if stat is None:
            raise ValueError("the node reports no storage statistics for the bench wallet")
        return stat

    def external(self, request: Cell, signature: bytes, deploy: bool) -> MessageAny:
        """The external of a signed request; a deploying external carries the StateInit."""
        external = self.wallet.external(request, signature)
        if not deploy:
            return external
        # The first request also deploys the wallet from its funded address.
        return MessageAny(
            info=ExternalMsgInfo(None, self.address, 0),
            init=self.wallet.state_init,
            body=external.body,
        )

    def unsigned_external(self, actions: list[MessageAny], deploy: bool) -> MessageAny:
        """The external as it will be sent, with a placeholder of the signature's size.

        Nonce and deadline are fixed-width fields, so their values do not change the size.
        """
        request = self.wallet.request(0, actions, 0)
        return self.external(request, bytes(SIGNATURE_BYTES), deploy)

    async def send(self, actions: list[MessageAny], what: str, timeout: float, latest: int) -> int:
        """Send one signed request; wait until its nonce is consumed. Returns the balance spent.

        The request expires at chain time ``latest`` at the latest, so the
        wallet cannot execute it after the horizon its storage bound covers.
        """
        balance, nonce = await self.state()
        now = await self.remote.now()
        deadline = min(now + REQUEST_LIFETIME, latest)
        if deadline <= now:
            raise HorizonPassed(f"the {what} request would expire before chain time {now}")
        request = self.wallet.request(nonce or 0, actions, deadline)
        external = self.external(request, self.signer.sign(request.hash), nonce is None)
        await self.remote.send(external)
        deadline = time.monotonic() + timeout
        while True:
            after, now_nonce = await self.state()
            if now_nonce is not None and now_nonce > (nonce or 0):
                return balance - after
            if time.monotonic() >= deadline:
                raise RuntimeError(f"the bench wallet never executed the {what} request")
            await asyncio.sleep(self.remote.poll)


def window_counts(result: dict[str, Any]) -> dict[str, Any]:
    stats = result["conservation"]["stats"]
    return {
        "window_transactions": stats["window_transactions"],
        "run_owned_messages": stats["run_owned_emitted"],
        "delivered": stats["delivered"],
        "window_blocks": result["continuity"]["stats"]["window_blocks"],
    }


# ─── the run ─────────────────────────────────────────────────────────


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="run_shard_bench.py --remote",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--remote", action="store_true", required=True)
    p.add_argument("--rpc", action="append", required=True, help="JSON-RPC URL (repeatable)")
    p.add_argument("--rpc-share", type=float, default=0.25, help="share of the per-IP budget")
    p.add_argument("--out", type=Path, required=True, help="new directory for all outputs")
    p.add_argument(
        "--key-file", type=Path, required=True, help="bench wallet key (JSON, mode 0600)"
    )
    p.add_argument("--signer", type=Path, required=True, help="bench-pq-signer executable")
    p.add_argument("--auth-tag", required=True, help="the network's 32-byte AUTH tag (hex)")
    p.add_argument("--build", type=Path, default=hopbench.ROOT / "build")
    p.add_argument("--hop-code", type=Path, help="precompiled hop.fc BOC instead of --build")
    p.add_argument("--wallet-code", type=Path, help="precompiled wallet BOC instead of --build")
    p.add_argument("--accounts", type=int, required=True)
    p.add_argument("--chains", type=int, required=True)
    p.add_argument("--forks", type=int, required=True)
    p.add_argument("--hops", type=int, required=True, help="hop cap of every chain")
    p.add_argument("--local", type=float, default=0.0)
    p.add_argument("--account-funding", type=float, required=True, help="TOS per hop account")
    p.add_argument("--load-funding", type=float, required=True, help="TOS attached to the burst")
    p.add_argument("--max-cost", type=float, required=True, help="TOS the run may cost at most")
    p.add_argument("--max-messages", type=int, required=True)
    p.add_argument("--duration", type=int, default=60, help="seconds the chains may run")
    p.add_argument("--with-init", action="store_true")
    p.add_argument("--verify-sender", action="store_true")
    p.add_argument("--payload", type=int, default=0)
    p.add_argument("--seed", default="tos-shard-bench-remote", help="public run seed")
    p.add_argument("--deploy-wait", type=float, default=900)
    p.add_argument("--drain-wait", type=float, default=900)
    p.add_argument("--poll", type=float, default=2.0)
    a = p.parse_args(argv)
    if not 0 < a.rpc_share <= 1:
        p.error("--rpc-share must be in (0, 1]")
    if a.duration < 1:
        p.error("--duration must be positive")
    for name in ("deploy_wait", "drain_wait", "poll"):
        if not getattr(a, name) >= 0:
            p.error(f"--{name.replace('_', '-')} must not be negative")
    try:
        a.auth = bytes.fromhex(a.auth_tag)
    except ValueError:
        p.error("--auth-tag must be hex")
    if len(a.auth) != 32:
        p.error("--auth-tag must be 32 bytes")
    return a


def nano(value: float) -> int:
    return round(value * NANO)


def caps_of(a: argparse.Namespace) -> Caps:
    return Caps(
        a.chains,
        a.forks,
        a.hops,
        a.accounts,
        nano(a.account_funding),
        nano(a.load_funding),
    )


def local_refusal(local: float) -> str | None:
    """Why ``--local`` cannot run remotely, or None for 0.

    The start message carries shard depth 0, and hop.fc applies locality
    only when the depth is positive, so any other value would silently run
    the uniform workload instead of the one asked for.
    """
    if local == 0:
        return None
    return (
        f"--local {local} has no effect in remote mode: the start message carries shard "
        "depth 0 and hop.fc keeps hops local only at a positive depth; use --local 0"
    )


def load_code(path: Path | None, build: Path, compile_to: Path, which: str) -> Cell:
    if path is not None:
        return Cell.one_from_boc(path.read_bytes())
    if which == "hop":
        return hopbench.build(build, compile_to)
    from pqbench import contracts

    return contracts.build(build, compile_to)["quantum"]


def fee_horizon(now: int, deploy_wait: float, drain_wait: float) -> int:
    """The latest chain time a wallet request of the run may execute at.

    The deployment request is signed at once; the start request after the
    deployment wait, the activation wait and the opening queue wait. Each
    expires within ``REQUEST_LIFETIME``. Requests are signed to expire by
    this horizon, so the storage bound up to it holds even if chain time
    runs ahead of these waits.
    """
    return now + 2 * REQUEST_LIFETIME + math.ceil(2 * deploy_wait + drain_wait)


async def fee_plan(
    remote: Remote,
    bench: "BenchWallet",
    now: int,
    horizon: int,
    deploy_actions: list[MessageAny],
    start_actions: list[MessageAny],
) -> tuple[FeeConfig, WalletFeeBound]:
    """The wallet fee bound of the run, from the live configuration; reads only."""
    workchain = bench.address.wc
    if workchain != 0:
        raise ValueError(
            f"the bench wallet is on workchain {workchain}; the self-pay Quantum wallet "
            "runs on the basechain"
        )
    config = await remote.fee_config(workchain)
    _, nonce = await bench.state()
    externals = [
        external_fee_bound(
            config,
            "deployment",
            bench.unsigned_external(deploy_actions, nonce is None),
            deploy_actions,
        ),
        external_fee_bound(
            config, "start", bench.unsigned_external(start_actions, False), start_actions
        ),
    ]
    storage = account_storage(
        config, bench.wallet.state_init.serialize(), await bench.storage(), now, horizon
    )
    return config, wallet_fee_bound(externals, storage)


def refuse(why: str) -> int:
    print(f"refused: {why}", file=sys.stderr)
    return REFUSED


async def run(a: argparse.Namespace) -> int:
    try:
        caps = validate_caps(caps_of(a))
    except ValueError as error:
        return refuse(str(error))
    why = local_refusal(a.local)
    if why is not None:
        return refuse(why)
    # Nothing is read before this first check: the attached value alone must fit.
    bound = work_bound(caps)
    print(json.dumps({"work_bound": bound.as_dict(), "caps": asdict(caps)}, indent=2), flush=True)
    why = refusal(bound, a.max_messages, nano(a.max_cost))
    if why is not None:
        return refuse(why)
    with tempfile.TemporaryDirectory() as scratch:
        return await run_bounded(a, caps, Path(scratch))


async def run_bounded(a: argparse.Namespace, caps: Caps, scratch: Path) -> int:
    key = load_key(a.key_file)
    signer = Signer(a.signer, key)
    hop_code = load_code(a.hop_code, a.build, scratch / "contracts", "hop")
    wallet_code = load_code(a.wallet_code, a.build, scratch / "contracts", "wallet")
    rpcs = [PacedRpc(url, a.rpc_share) for url in a.rpc]
    remote = Remote(rpcs, a.poll)

    header = await remote.mc_header()
    now = int(header["gen_utime"])
    global_id = int(header["global_id"])
    cp12 = await remote.rpc.call("getConfigParam", {"param": 12})
    wallet = bench_wallet(wallet_code, global_id, a.auth, key, signer.public_key())
    bench = BenchWallet(wallet, signer, remote)

    seed = hashlib.sha256(a.seed.encode()).digest()
    family = hopbench.HopFamily(hop_code, int.from_bytes(seed[:8], "big"), caps.accounts)
    addresses = family.addresses()
    deploy_value = caps.accounts * caps.account_funding
    deploy_actions = [
        transfer_message(
            wallet.address,
            addresses[0],
            deploy_value,
            body=hopbench.deploy_body(0, caps.accounts),
            init=family.state_init(0),
        )
    ]
    flags = (hopbench.FLAG_WITH_INIT if a.with_init else 0) | (
        hopbench.FLAG_VERIFY_SENDER if a.verify_sender else 0
    )

    def start_actions(deadline: int) -> list[MessageAny]:
        return [
            transfer_message(
                wallet.address,
                addresses[0],
                caps.load_funding,
                body=hopbench.start_body(
                    caps.chains,
                    caps.hops,
                    caps.forks,
                    hopbench.local_scaled(a.local),
                    0,
                    deadline,
                    caps.accounts,
                    flags,
                    hopbench.payload_cell(a.payload),
                ),
            )
        ]

    # The second check, before anything is written or sent: the attached value
    # plus the wallet fee bound derived from the live configuration must fit.
    horizon = fee_horizon(now, a.deploy_wait, a.drain_wait)
    try:
        # The deadline is a fixed-width field; its value does not change the size.
        config, fees = await fee_plan(remote, bench, now, horizon, deploy_actions, start_actions(0))
    except (ValueError, RpcError) as error:
        return refuse(f"no wallet fee bound: {error}")
    bound = work_bound(caps, fees.total)
    print(
        json.dumps(
            {
                "work_bound": bound.as_dict(),
                "wallet_fee_bound": fees.as_dict(),
                "fee_config": config.as_dict(),
            },
            indent=2,
        ),
        flush=True,
    )
    why = refusal(bound, a.max_messages, nano(a.max_cost))
    if why is not None:
        return refuse(why)
    balance, _ = await bench.state()
    if balance < bound.cost:
        return refuse(f"the bench wallet holds {balance} nanotos; the run may cost {bound.cost}")

    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(a.out / "bench.log")],
        force=True,
    )
    if (scratch / "contracts").is_dir():
        shutil.copytree(scratch / "contracts", a.out / "contracts")
    log.info("bench wallet %s on global id %d", raw(wallet.address), global_id)
    out_record = a.out / "results.json"
    record: dict[str, Any] = {
        "scope": "REMOTE: bounded hop burst over JSON-RPC",
        "source_commit": source_commit(),
        "endpoints": a.rpc,
        "global_id": global_id,
        "config_param_12": cp12,
        "caps": asdict(caps),
        "work_bound": bound.as_dict(),
        "wallet_fee_bound": fees.as_dict(),
        "fee_config": config.as_dict(),
        "fee_horizon": horizon,
        "bench_wallet": raw(wallet.address),
        "hop_code_hash": hop_code.hash.hex(),
    }

    def stop(outcome: str, why: str, code: int) -> int:
        record["outcome"], record["stopped"] = outcome, why
        record["rpc"] = [r.stats() for r in rpcs]
        out_record.write_text(json.dumps(record, indent=2) + "\n")
        log.error(why)
        return code

    spent_deploy = await bench.send(deploy_actions, "deployment", a.deploy_wait, horizon)
    deploy_fee = spent_deploy - deploy_value
    record["deployment_wallet_fee"] = deploy_fee
    # A cross-check of the fee model on a real transaction: the deployment
    # cannot cost more than its own bound plus all the storage the run may owe.
    deploy_bound = fees.externals[0].total + fees.storage.fee
    if deploy_fee > deploy_bound:
        return stop(
            "REFUSED",
            f"the deployment's wallet fee {deploy_fee} exceeds its derived bound {deploy_bound}",
            REFUSED,
        )
    missing = await remote.wait_active(addresses, a.deploy_wait)
    if missing:
        return stop("REFUSED", f"{len(missing)} hop accounts never became active", REFUSED)
    before = await remote.balances(addresses)

    opening = await t2collect.wait_empty_queue(remote.rpc, a.drain_wait, a.poll)
    log.info("opening boundary: %s", opening)
    record["boundaries"] = {"opening": asdict(opening)}
    if opening.empty is not True or opening.mc_seqno is None:
        # A window that does not open at a known-empty queue can only be INCONCLUSIVE,
        # so the load funding is not spent on it.
        return stop(
            "INCONCLUSIVE",
            "the outbound queue was not known to be empty before the start; nothing sent",
            INCONCLUSIVE,
        )
    deadline = await remote.now() + a.duration
    record["deadline"] = deadline
    try:
        spent_start = await bench.send(start_actions(deadline), "start", a.drain_wait, horizon)
    except HorizonPassed as error:
        return stop("INCONCLUSIVE", str(error), INCONCLUSIVE)
    record["start_wallet_fee"] = spent_start - caps.load_funding
    past = await remote.wait_past(deadline + 5, a.drain_wait)
    if past is None:
        return stop(
            "INCONCLUSIVE",
            f"chain time did not pass the deadline {deadline} + 5 within the wait "
            f"--drain-wait {a.drain_wait} s allows",
            INCONCLUSIVE,
        )
    closing = await t2collect.wait_empty_queue(remote.rpc, a.drain_wait, a.poll)
    log.info("closing boundary: %s", closing)
    result = await t2collect.check_window(
        remote.rpc,
        opening,
        closing,
        {raw(x) for x in addresses},
        {raw(wallet.address)},
        a.out / "t2",
        finality=rpcs,
    )
    # Send mode 3 lets the wallet skip a failing send, so a consumed nonce does not
    # prove the burst started: the start message itself must have been delivered.
    t2_status = result["status"]
    stats = result["conservation"]["stats"]
    start_delivered = stats["delivered"]["entry"]
    hops_delivered = stats["delivered"]["hop"]
    load_note = None
    if start_delivered < 1 and t2_status == "PASS":
        t2_status = "INCONCLUSIVE"
        load_note = "the start message was not emitted and delivered inside the window"
    elif hops_delivered < 1 and t2_status == "PASS":
        # The start transaction ran but launched no chain, for example because its action
        # phase failed: the window holds no load, so it measures nothing.
        t2_status = "INCONCLUSIVE"
        load_note = (
            "the start message launched no hop "
            f"({stats['aborted_transactions']} aborted, "
            f"{stats['failed_action_phases']} failed action phases in the window)"
        )
    after = await remote.balances(addresses)
    wallet_after, _ = await bench.state()
    attached = deploy_value + caps.load_funding
    record |= {
        "outcome": "COUNTED",
        "start_delivered": start_delivered,
        "hops_delivered": hops_delivered,
        "load_note": load_note,
        "boundaries": {"opening": asdict(opening), "closing": asdict(closing)},
        "counts": window_counts(result),
        "t2_status": t2_status,
        "finalized_mc": result["finalized_mc"],
        "stranded": {
            "hop_accounts_total": sum(after.values()),
            "burst_left_in_hop_accounts": sum(after.values()) - sum(before.values()),
            "account_funding_total": deploy_value,
            "recoverable": 0,
        },
        "wallet_balance": {
            "before": balance,
            "after": wallet_after,
            "spent": balance - wallet_after,
            "fees_spent": balance - wallet_after - attached,
            "fee_bound": fees.total,
        },
        "rpc": [r.stats() for r in rpcs],
    }
    out_record.write_text(json.dumps(record, indent=2) + "\n")
    log.info("T2 %s; stranded %d nanotos", t2_status, record["stranded"]["hop_accounts_total"])
    return exit_status(t2_status)


def source_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=hopbench.ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str]) -> int:
    os.umask(0o077)
    return asyncio.run(run(parse_args(argv)))
