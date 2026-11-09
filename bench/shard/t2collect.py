#!/usr/bin/env python3
"""Collect T2 evidence over JSON-RPC and check it with ``t2check``.

Reads go through ``rpc.PacedRpc``, so the collector stays inside its share of
each node's per-source budget and retries rate-gate refusals:

- ``read_masterchain`` reads every masterchain block in a range: its header
  (time and root hash) and the basechain shard tops it references. Every
  block is read, so a layout change that lasts one block is still seen.
- ``walk_blocks`` reads shard block headers from those tops back to the
  opening boundary's tops, following both predecessors of a merge and
  crossing a split into the parent shard.
- ``read_transactions`` reads every page of each window block's
  transaction list, with inbound and outbound message summaries.
- ``queue_boundary`` binds an outbound-queue reading to the masterchain
  block whose shard tops it was taken at.
- ``read_finalized`` reads the finalized masterchain seqno
  (``getConsensusBlock``: the masterchain state the node serves reads
  from, which never runs ahead of the blocks it has applied as finalized),
  taking the lowest over every node asked. The window is checked only up
  to it.

Records are written next to the verdict, so the check can be rerun offline:

    t2collect.py boundary --rpc URL
    t2collect.py check --rpc URL --from-mc A --to-mc B --run-accounts FILE --out DIR
"""

import argparse
import asyncio
import base64
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shard import t2check  # noqa: E402
from shard.rpc import PacedRpc, RateLimited, RpcError  # noqa: E402
from shard.t2check import (  # noqa: E402
    BlockKey,
    BlockRecord,
    BlockRef,
    BlockTxs,
    McRecord,
    Msg,
    QueueBoundary,
    Tx,
)

MASTERCHAIN_SHARD = -(1 << 63)
TX_PAGE = 256
MAX_TX_PAGES = 4096


def _hash_hex(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{what} is not a base64 string")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32:
        raise ValueError(f"{what} is not 32 bytes")
    return raw.hex()


def parse_block_id(value: Any) -> BlockRef:
    """A ``tos.blockIdExt`` JSON object as a BlockRef."""
    if not isinstance(value, dict):
        raise ValueError("a block id is not an object")
    try:
        workchain, seqno = int(value["workchain"]), int(value["seqno"])
        shard = int(value["shard"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"a block id is malformed: {value!r}") from error
    return BlockRef(workchain, shard, seqno, _hash_hex(value.get("root_hash"), "root_hash"))


def parse_header(value: Any) -> BlockRecord:
    """A ``blocks.header`` answer; a header without its predecessor list is refused."""
    if not isinstance(value, dict):
        raise ValueError("a block header is not an object")
    prev = value.get("prev_blocks")
    if not isinstance(prev, list):
        raise ValueError("a block header carries no predecessor list")
    flags = {}
    for name in ("after_merge", "after_split", "before_split"):
        flag = value.get(name)
        if type(flag) is not bool:
            raise ValueError(f"a block header has no boolean {name}")
        flags[name] = flag
    utime = value.get("gen_utime")
    if type(utime) is not int:
        raise ValueError("a block header has no gen_utime")
    return BlockRecord(
        parse_block_id(value.get("id")),
        tuple(parse_block_id(p) for p in prev),
        gen_utime=utime,
        **flags,
    )


def raw_address(value: Any) -> str | None:
    """A user-friendly or raw address as ``wc:hex``; None when absent or undecodable."""
    if not isinstance(value, str) or not value:
        return None
    from pytosiq_core import Address

    try:
        address = Address(value)
    except Exception:
        return None
    return f"{address.wc}:{address.hash_part.hex()}"


def parse_message(value: Any) -> Msg:
    if not isinstance(value, dict) or not isinstance(value.get("hash"), str):
        return Msg("", "unknown")
    try:
        digest = _hash_hex(value["hash"], "message hash")
    except ValueError:
        return Msg("", "unknown")
    kind = value.get("kind")
    if kind == "external":
        return Msg(digest, "external")
    if kind != "internal":
        return Msg(digest, "unknown")
    source, destination = raw_address(value.get("source")), raw_address(value.get("destination"))
    if source is None or destination is None or type(value.get("bounced")) is not bool:
        return Msg(digest, "unknown")
    amount = value.get("value")
    carried = int(amount) if isinstance(amount, str) and amount.isdigit() else None
    return Msg(digest, "internal", source, destination, value["bounced"], carried)


def parse_transaction(value: Any, block: BlockKey) -> Tx:
    if not isinstance(value, dict):
        raise ValueError("a transaction is not an object")
    account = value.get("account")
    if not isinstance(account, str) or len(account) != 64:
        raise ValueError("a transaction has no account")
    raw_compute, raw_action = value.get("compute"), value.get("action")
    compute: dict[str, Any] = raw_compute if isinstance(raw_compute, dict) else {}
    action: dict[str, Any] | None = raw_action if isinstance(raw_action, dict) else None
    in_msg = value.get("in_msg")
    skipped = action.get("skipped_actions", 0) if action else 0
    fee = value.get("fee")
    return Tx(
        hash=_hash_hex(value.get("hash"), "transaction hash"),
        account=f"{block[0]}:{account.lower()}",
        lt=int(value.get("lt", 0)),
        block=block,
        in_msg=None if in_msg is None else parse_message(in_msg),
        out_msgs=tuple(parse_message(m) for m in value.get("out_msgs") or ()),
        aborted=value.get("aborted") is True,
        activated=compute.get("account_activated") is True,
        action_success=None if action is None else action.get("success") is True,
        skipped_actions=skipped if type(skipped) is int and skipped >= 0 else 0,
        fee=int(fee) if isinstance(fee, str) and fee.isdigit() else None,
    )


def _block_params(ref: BlockRef) -> dict[str, Any]:
    return {"workchain": ref.workchain, "shard": str(ref.shard), "seqno": ref.seqno}


async def read_masterchain(rpc: PacedRpc, lo: int, hi: int, parallel: int = 4) -> list[McRecord]:
    """Every masterchain block in [lo, hi], with its basechain shard tops."""
    if not 0 <= lo <= hi:
        raise ValueError("a masterchain range needs 0 <= lo <= hi")

    async def one(seqno: int) -> McRecord | None:
        try:
            return await read_one(seqno)
        except (RpcError, RateLimited):
            # An unread masterchain block is a gap in the layout record, never a guess.
            return None

    async def read_one(seqno: int) -> McRecord:
        header = await rpc.call(
            "getBlockHeader",
            {"workchain": -1, "shard": str(MASTERCHAIN_SHARD), "seqno": seqno},
        )
        ref = parse_block_id(header.get("id"))
        if ref.seqno != seqno or ref.workchain != -1:
            raise ValueError(f"masterchain header {seqno} answered for {ref.label()}")
        shards = await rpc.call("getShards", {"seqno": seqno})
        tops = tuple(
            parse_block_id(s) for s in shards.get("shards", []) if int(s.get("workchain", -1)) == 0
        )
        return McRecord(seqno, int(header.get("gen_utime", 0)), ref.root_hash, tops)

    out: list[McRecord] = []
    for start in range(lo, hi + 1, parallel):
        batch = range(start, min(hi, start + parallel - 1) + 1)
        out.extend(m for m in await asyncio.gather(*(one(s) for s in batch)) if m is not None)
    return out


async def walk_blocks(
    rpc: PacedRpc, mcs: list[McRecord], max_blocks: int = 200_000
) -> dict[BlockKey, BlockRecord]:
    """Headers of every block between the opening tops and the later tops, by back-links.

    The walk stops at the opening tops and at ``max_blocks``; ``check_continuity``
    reports whatever is left unread as a gap, never as a loss.
    """
    if len(mcs) < 2:
        return {}
    frontier = {t.key: t for t in mcs[0].tops}
    blocks: dict[BlockKey, BlockRecord] = {}
    queued: set[BlockKey] = set()
    pending = [t for m in mcs[1:] for t in m.tops]
    while pending and len(blocks) < max_blocks:
        wave: list[BlockRef] = []
        while pending and len(wave) < 8:
            ref = pending.pop()
            if ref.key in frontier or ref.key in queued:
                continue
            if t2check.below_frontier(ref, frontier) is not None:
                continue
            queued.add(ref.key)
            wave.append(ref)
        headers = await asyncio.gather(
            *(rpc.call("getBlockHeader", _block_params(r)) for r in wave), return_exceptions=True
        )
        for header in headers:
            if isinstance(header, (RpcError, RateLimited)):
                # The block stays unread; check_continuity reports it as a gap.
                continue
            if isinstance(header, BaseException):
                raise header
            record = parse_header(header)
            blocks[record.ref.key] = record
            pending.extend(record.prev)
    return blocks


async def read_transactions(rpc: PacedRpc, ref: BlockRef) -> BlockTxs:
    """Every page of one block's transaction list."""
    txs: list[Tx] = []
    params = _block_params(ref) | {"count": TX_PAGE}
    for _ in range(MAX_TX_PAGES):
        answer = await rpc.call("getBlockTransactionsExt", params)
        got = parse_block_id(answer.get("id"))
        if got != ref:
            raise ValueError(f"transactions of {ref.label()} answered for {got.label()}")
        page = [parse_transaction(t, ref.key) for t in answer.get("transactions", [])]
        txs.extend(page)
        if answer.get("incomplete") is not True:
            return BlockTxs(tuple(txs), True)
        if not page:
            break
        last = page[-1]
        params = _block_params(ref) | {
            "count": TX_PAGE,
            "after_lt": str(last.lt),
            "after_account": last.account.split(":", 1)[1],
        }
    return BlockTxs(tuple(txs), False)


async def read_all_transactions(
    rpc: PacedRpc, refs: list[BlockRef], parallel: int = 8
) -> dict[BlockKey, BlockTxs]:
    out: dict[BlockKey, BlockTxs] = {}
    for start in range(0, len(refs), parallel):
        batch = refs[start : start + parallel]
        for ref, block in zip(
            batch,
            await asyncio.gather(
                *(read_transactions(rpc, r) for r in batch), return_exceptions=True
            ),
        ):
            if isinstance(block, (RpcError, RateLimited)):
                # A transaction list that could not be read is incomplete, so a gap.
                out[ref.key] = BlockTxs((), False)
                continue
            if isinstance(block, BaseException):
                raise block
            out[ref.key] = block
    return out


async def queue_boundary(rpc: PacedRpc) -> QueueBoundary:
    """The outbound queues now, bound to the masterchain block they were read at.

    The node reports the queue of its masterchain state block first, under that
    block's own id, and then the queue of each shard top of that state. The
    masterchain id is used as the boundary; the reported basechain tops must be the
    ones that block references. A reading that cannot be bound this way is unknown,
    not empty.
    """
    sizes = await rpc.call("getOutMsgQueueSize")
    rows = [s for s in sizes.get("shards", []) if isinstance(s, dict)]
    ids = [parse_block_id(s.get("id")) for s in rows]
    masterchain = [r for r in ids if r.workchain == -1]
    if len(masterchain) != 1:
        return QueueBoundary(None, None)
    seqno = masterchain[0].seqno
    basechain = {r for r in ids if r.workchain == 0}
    shards = await rpc.call("getShards", {"seqno": seqno})
    tops = {parse_block_id(s) for s in shards.get("shards", []) if int(s.get("workchain", -1)) == 0}
    if tops != basechain:
        return QueueBoundary(None, None)
    empty = all(int(s.get("size", -1)) == 0 for s in rows)
    return QueueBoundary(seqno, empty)


async def wait_empty_queue(rpc: PacedRpc, timeout: float, poll: float = 2.0) -> QueueBoundary:
    """The first boundary with an empty queue, or the last reading when time runs out."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        boundary = await queue_boundary(rpc)
        if boundary.empty is True and boundary.mc_seqno is not None:
            return boundary
        if loop.time() >= deadline:
            return boundary
        await asyncio.sleep(poll)


async def read_finalized(rpcs: list[PacedRpc]) -> int | None:
    """The lowest finalized masterchain seqno the nodes report; None when any read fails."""
    if not rpcs:
        return None
    seqnos: list[int] = []
    for rpc in rpcs:
        try:
            answer = await rpc.call("getConsensusBlock")
        except Exception:
            return None
        value = answer.get("consensus_block") if isinstance(answer, dict) else None
        if type(value) is not int or value < 0:
            return None
        seqnos.append(value)
    return min(seqnos)


async def wait_finalized(
    rpcs: list[PacedRpc], target: int, timeout: float, poll: float = 2.0
) -> int | None:
    """The finalized seqno once it reaches ``target``, or the last reading when time runs out."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        finalized = await read_finalized(rpcs)
        if (finalized is not None and finalized >= target) or loop.time() >= deadline:
            return finalized
        await asyncio.sleep(poll)


async def collect(
    rpc: PacedRpc, lo: int, hi: int, max_blocks: int = 200_000
) -> tuple[list[McRecord], dict[BlockKey, BlockRecord], dict[BlockKey, BlockTxs]]:
    mcs = await read_masterchain(rpc, lo, hi)
    blocks = await walk_blocks(rpc, mcs, max_blocks)
    # The masterchain blocks after the opening one are read too: an entry source on the
    # masterchain emits a run's first messages there.
    masterchain = [
        BlockRef(-1, MASTERCHAIN_SHARD, m.seqno, m.root_hash) for m in mcs if m.seqno > lo
    ]
    txs = await read_all_transactions(rpc, [*(b.ref for b in blocks.values()), *masterchain])
    return mcs, blocks, txs


def records_json(
    mcs: list[McRecord],
    blocks: dict[BlockKey, BlockRecord],
    txs: dict[BlockKey, BlockTxs],
    finalized_mc: int | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "finalized_mc": finalized_mc,
        "diagnostics": diagnostics or {},
        "masterchain": [asdict(m) for m in mcs],
        "blocks": [asdict(b) for b in blocks.values()],
        "transactions": [
            {"block": list(k), "complete": v.complete, "txs": [asdict(t) for t in v.txs]}
            for k, v in txs.items()
        ],
    }


async def check_window(
    rpc: PacedRpc,
    opening: QueueBoundary,
    closing: QueueBoundary,
    run_accounts: set[str],
    entry_sources: set[str],
    out: Path,
    observed: list[BlockRef] | None = None,
    max_blocks: int = 200_000,
    finality: list[PacedRpc] | None = None,
    finality_wait: float = 120.0,
) -> dict[str, Any]:
    """Collect one window, write its records and verdict under ``out``, return the verdict.

    The closing block must be finalized on every node in ``finality``
    (default: the reading node). The collector waits up to ``finality_wait``
    seconds for that; a window still above finality is INCONCLUSIVE.
    """
    if opening.mc_seqno is None or closing.mc_seqno is None:
        raise ValueError("both boundaries need a masterchain seqno")
    finalized = await wait_finalized(finality or [rpc], closing.mc_seqno, finality_wait)
    mcs, blocks, txs = await collect(rpc, opening.mc_seqno, closing.mc_seqno, max_blocks)
    result = t2check.evaluate(
        mcs,
        blocks,
        txs,
        run_accounts,
        entry_sources,
        opening,
        closing,
        observed or (),
        max_blocks,
        finalized_mc=finalized,
    )
    reached = t2check.check_continuity(
        mcs, blocks, observed or (), max_blocks, finalized_mc=finalized
    )
    diagnostics = {
        "run_owned_balance": t2check.run_owned_balance(
            reached,
            txs,
            run_accounts,
            entry_sources,
            t2check.masterchain_window_keys(mcs, opening.mc_seqno),
        ),
        "note": "diagnostic only; the verdict requires the whole queue to be empty",
    }
    result["finalized_mc"] = finalized
    result["boundaries"] = {"opening": asdict(opening), "closing": asdict(closing)}
    result["rpc"] = rpc.stats()
    out.mkdir(parents=True, exist_ok=True)
    records = records_json(mcs, blocks, txs, finalized, diagnostics)
    (out / "t2-records.json").write_text(json.dumps(records) + "\n")
    (out / "t2-verdict.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("boundary", "check"):
        s = sub.add_parser(name)
        s.add_argument(
            "--rpc", required=True, help="JSON-RPC URL, e.g. http://127.0.0.1:8081/jsonRPC"
        )
        s.add_argument(
            "--share", type=float, default=0.25, help="share of the per-IP budget (0..1]"
        )
    c = sub.choices["check"]
    c.add_argument("--from-mc", type=int, required=True, help="opening boundary masterchain seqno")
    c.add_argument("--to-mc", type=int, required=True, help="closing boundary masterchain seqno")
    c.add_argument("--opening-empty", action="store_true", help="the queue was empty at --from-mc")
    c.add_argument("--closing-empty", action="store_true", help="the queue was empty at --to-mc")
    c.add_argument("--run-accounts", type=Path, required=True, help="JSON list of run addresses")
    c.add_argument("--entry-source", action="append", default=[], help="funding address")
    c.add_argument("--max-blocks", type=int, default=200_000)
    c.add_argument(
        "--finality-rpc",
        action="append",
        default=[],
        help="more JSON-RPC URLs whose finalized seqno bounds the window (lowest wins)",
    )
    c.add_argument(
        "--finality-wait", type=float, default=120.0, help="seconds to wait for finality"
    )
    c.add_argument("--out", type=Path, required=True)
    return p.parse_args()


async def _main(a: argparse.Namespace) -> int:
    rpc = PacedRpc(a.rpc, a.share)
    if a.command == "boundary":
        print(json.dumps(asdict(await queue_boundary(rpc))))
        return 0
    accounts = json.loads(a.run_accounts.read_text())
    run = {r for r in (raw_address(x) for x in accounts) if r is not None}
    if len(run) != len(accounts):
        raise SystemExit("a run account address does not decode")
    entries = {r for r in (raw_address(x) for x in a.entry_source) if r is not None}
    result = await check_window(
        rpc,
        QueueBoundary(a.from_mc, True if a.opening_empty else None),
        QueueBoundary(a.to_mc, True if a.closing_empty else None),
        run,
        entries,
        a.out,
        max_blocks=a.max_blocks,
        finality=[rpc] + [PacedRpc(url, a.share) for url in a.finality_rpc],
        finality_wait=a.finality_wait,
    )
    print(result["status"])
    return {"PASS": 0, "FAIL": 1}.get(result["status"], 2)


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(_parse_args())))
