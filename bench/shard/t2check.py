"""T2 evidence checks over recorded chain data: shard layout, block continuity, message conservation.

Everything here is a pure function of records the collection layer
(``t2collect``) reads over JSON-RPC, so each verdict can be reproduced from
the saved records alone and every rule can be tested without a chain.

Verdicts are PASS, FAIL and INCONCLUSIVE. A FAIL names the offending blocks
or messages and is only reported from data that is complete enough to prove
it. When data is missing (a block that was not read, a walk cut short, a
queue that has not drained) the verdict is INCONCLUSIVE and the missing
items are listed as gaps: a message that has not been seen delivered yet is
never reported as lost unless the walk is complete and the closing queue was
empty.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

U64 = (1 << 64) - 1
PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"

BlockKey = tuple[int, int, int]  # (workchain, signed shard id, seqno)


def _unsigned(shard: int) -> int:
    return shard & U64


def _signed(shard: int) -> int:
    shard &= U64
    return shard - (1 << 64) if shard >> 63 else shard


def _low_bit(shard: int) -> int:
    x = _unsigned(shard)
    if x == 0:
        raise ValueError("shard id 0 is not a shard")
    return x & -x


def shard_label(shard: int) -> str:
    return f"{_unsigned(shard):016x}"


def shard_parent(shard: int) -> int:
    x, low = _unsigned(shard), _low_bit(shard)
    if low == 1 << 63:
        raise ValueError("the root shard has no parent")
    return _signed((x - low) | (low << 1))


def shard_children(shard: int) -> tuple[int, int]:
    x, low = _unsigned(shard), _low_bit(shard)
    if low == 1:
        raise ValueError("a shard of depth 63 has no children")
    half = low >> 1
    return _signed(x - half), _signed(x + half)


def shards_overlap(a: int, b: int) -> bool:
    """Whether two shard prefixes cover a common account (one contains the other)."""
    wide = max(_low_bit(a), _low_bit(b))
    mask = ~((wide << 1) - 1) & U64
    return ((_unsigned(a) ^ _unsigned(b)) & mask) == 0


@dataclass(frozen=True)
class BlockRef:
    """A full block id; ``root_hash`` is lower-case hex."""

    workchain: int
    shard: int
    seqno: int
    root_hash: str

    @property
    def key(self) -> BlockKey:
        return (self.workchain, self.shard, self.seqno)

    def label(self) -> str:
        return f"({self.workchain},{shard_label(self.shard)},{self.seqno}):{self.root_hash[:16]}"


@dataclass(frozen=True)
class BlockRecord:
    """A basechain block header as the walk needs it."""

    ref: BlockRef
    prev: tuple[BlockRef, ...]
    after_merge: bool = False
    after_split: bool = False
    before_split: bool = False
    gen_utime: int = 0


@dataclass(frozen=True)
class McRecord:
    """A masterchain block and the basechain shard tops it references."""

    seqno: int
    gen_utime: int
    root_hash: str
    tops: tuple[BlockRef, ...]

    def layout(self) -> tuple[int, ...]:
        return tuple(sorted({t.shard for t in self.tops}, key=_unsigned))


@dataclass
class Verdict:
    status: str
    failures: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "failures": self.failures,
            "gaps": self.gaps,
            "stats": self.stats,
        }


def _decide(failures: list[dict[str, Any]], gaps: list[dict[str, Any]]) -> str:
    if failures:
        return FAIL
    if gaps:
        return INCONCLUSIVE
    return PASS


# ─── shard layout ────────────────────────────────────────────────────


@dataclass(frozen=True)
class LayoutChange:
    mc_seqno: int
    gen_utime: int
    old: tuple[str, ...]
    new: tuple[str, ...]
    kind: str  # "split", "merge" or "split+merge"

    def as_dict(self) -> dict[str, Any]:
        return {
            "mc_seqno": self.mc_seqno,
            "gen_utime": self.gen_utime,
            "old": list(self.old),
            "new": list(self.new),
            "kind": self.kind,
        }


def change_kind(old: Iterable[int], new: Iterable[int]) -> str:
    """Classify a layout change; anything that is neither a split nor a merge is refused."""
    before, after = set(old), set(new)
    split = merge = False
    for shard in after - before:
        if _low_bit(shard) != 1 << 63 and shard_parent(shard) in before:
            split = True
        elif _low_bit(shard) != 1 and set(shard_children(shard)) <= before:
            merge = True
        else:
            raise ValueError(f"shard {shard_label(shard)} appeared without a parent or children")
    if not split and not merge:
        raise ValueError("a layout change must add a shard")
    return "split+merge" if split and merge else "split" if split else "merge"


def layout_changes(mcs: Iterable[McRecord]) -> tuple[list[LayoutChange], Verdict]:
    """Every basechain layout change across consecutive masterchain blocks.

    Each change is recorded at the first masterchain block that shows the
    new layout. A missing masterchain seqno is a gap: a layout could have
    changed and changed back inside it, so the record is then INCONCLUSIVE.
    """
    rows = sorted(mcs, key=lambda m: m.seqno)
    gaps: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    changes: list[LayoutChange] = []
    if not rows:
        return changes, Verdict(INCONCLUSIVE, gaps=[{"reason": "no masterchain blocks"}])
    for prev, cur in zip(rows, rows[1:]):
        if cur.seqno == prev.seqno:
            failures.append({"reason": "masterchain seqno recorded twice", "mc_seqno": cur.seqno})
            continue
        if cur.seqno != prev.seqno + 1:
            gaps.append(
                {
                    "reason": "masterchain blocks not read",
                    "from": prev.seqno + 1,
                    "to": cur.seqno - 1,
                }
            )
        old, new = prev.layout(), cur.layout()
        if old == new:
            continue
        try:
            kind = change_kind(old, new)
        except ValueError as error:
            failures.append({"reason": str(error), "mc_seqno": cur.seqno, "old": old, "new": new})
            continue
        changes.append(
            LayoutChange(
                cur.seqno,
                cur.gen_utime,
                tuple(shard_label(s) for s in old),
                tuple(shard_label(s) for s in new),
                kind,
            )
        )
    for m in rows:
        if not m.tops:
            failures.append({"reason": "no basechain shard top", "mc_seqno": m.seqno})
    verdict = Verdict(
        _decide(failures, gaps),
        failures,
        gaps,
        {
            "mc_from": rows[0].seqno,
            "mc_to": rows[-1].seqno,
            "changes": len(changes),
            "initial_layout": [shard_label(s) for s in rows[0].layout()],
            "final_layout": [shard_label(s) for s in rows[-1].layout()],
            "max_shards": max(len(m.layout()) for m in rows),
        },
    )
    return changes, verdict


# ─── block continuity ────────────────────────────────────────────────


def expected_parents(record: BlockRecord) -> str | None:
    """Why a block's predecessor list is malformed, or None when it is well formed."""
    ref, prev = record.ref, record.prev
    if any(p.workchain != ref.workchain for p in prev):
        return "a predecessor is in another workchain"
    if record.after_merge:
        if len(prev) != 2:
            return f"a merge block lists {len(prev)} predecessors, not 2"
        try:
            children = set(shard_children(ref.shard))
        except ValueError as error:
            return str(error)
        if {p.shard for p in prev} != children:
            return "a merge block's predecessors are not the two halves of its shard"
        if ref.seqno != max(p.seqno for p in prev) + 1:
            return "a merge block's seqno does not follow its later predecessor"
        return None
    if len(prev) != 1:
        return f"a block lists {len(prev)} predecessors, not 1"
    if record.after_split:
        try:
            parent = shard_parent(ref.shard)
        except ValueError as error:
            return str(error)
        if prev[0].shard != parent:
            return "a split block's predecessor is not its parent shard"
    elif prev[0].shard != ref.shard:
        return "a block's predecessor is in another shard"
    if ref.seqno != prev[0].seqno + 1:
        return "a block's seqno does not follow its predecessor"
    return None


def below_frontier(ref: BlockRef, frontier: Mapping[BlockKey, BlockRef]) -> BlockRef | None:
    """The opening top this block lies at or before, if any: it is then not a window block."""
    for top in frontier.values():
        if (
            top.workchain == ref.workchain
            and shards_overlap(top.shard, ref.shard)
            and ref.seqno <= top.seqno
        ):
            return top
    return None


@dataclass
class Continuity:
    verdict: Verdict
    reached: dict[BlockKey, BlockRef]


def finality_gaps(rows: list[McRecord], finalized_mc: int | None) -> list[dict[str, Any]]:
    """Masterchain blocks of the window that are not known to be finalized.

    ``finalized_mc`` is the highest masterchain seqno the node reports as
    finalized; every block the walk starts from must be at or below it.
    """
    if finalized_mc is None:
        return [{"reason": "the finalized masterchain seqno was not read"}]
    above = [m.seqno for m in rows if m.seqno > finalized_mc]
    if not above:
        return []
    return [
        {
            "reason": "masterchain blocks above the finalized seqno",
            "finalized_mc": finalized_mc,
            "mc_seqnos": above,
        }
    ]


def check_continuity(
    mcs: Iterable[McRecord],
    blocks: Mapping[BlockKey, BlockRecord],
    observed: Iterable[BlockRef] = (),
    max_blocks: int | None = None,
    *,
    finalized_mc: int | None,
) -> Continuity:
    """Every window block is reached by ``prev`` links from finalized masterchain shard tops.

    The first masterchain block is the opening boundary: its shard tops form
    the frontier, and the window is every block after it. The walk starts
    from the shard tops of every later masterchain block, follows both
    predecessors of a merge and crosses a split into the parent shard, and
    ends at the frontier. ``observed`` are block ids seen by an independent
    reader; one inside the window (after the opening tops and at or before
    the closing tops) that the walk does not reach is a FAIL.
    ``max_blocks`` caps the walk; a walk cut short is INCONCLUSIVE. So is a
    window whose masterchain blocks are not all at or below ``finalized_mc``:
    shard tops of an unfinalized block are not evidence.
    """
    rows = sorted(mcs, key=lambda m: m.seqno)
    failures: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = finality_gaps(rows, finalized_mc)
    if len(rows) < 2:
        verdict = Verdict(
            INCONCLUSIVE, gaps=[{"reason": "the window needs two masterchain blocks"}]
        )
        return Continuity(verdict, {})
    for prev, cur in zip(rows, rows[1:]):
        if cur.seqno != prev.seqno + 1:
            gaps.append(
                {
                    "reason": "masterchain blocks not read",
                    "from": prev.seqno + 1,
                    "to": cur.seqno - 1,
                }
            )
    frontier = {t.key: t for t in rows[0].tops}
    reached: dict[BlockKey, BlockRef] = {}
    pending: list[tuple[BlockRef, str]] = []
    for m in rows[1:]:
        pending.extend((t, f"mc {m.seqno} shard top") for t in m.tops)
    truncated = False
    walked = merges = splits = 0
    while pending:
        ref, via = pending.pop()
        opening = frontier.get(ref.key)
        if opening is not None:
            if opening.root_hash != ref.root_hash:
                failures.append(
                    {
                        "reason": "a link names a block other than the opening top",
                        "block": ref.label(),
                        "opening_top": opening.label(),
                        "via": via,
                    }
                )
            continue
        known = reached.get(ref.key)
        if known is not None:
            if known.root_hash != ref.root_hash:
                failures.append(
                    {
                        "reason": "two links name different blocks at one shard and seqno",
                        "block": ref.label(),
                        "other": known.label(),
                        "via": via,
                    }
                )
            continue
        top = below_frontier(ref, frontier)
        if top is not None:
            failures.append(
                {
                    "reason": "the walk passed the opening frontier without meeting it",
                    "block": ref.label(),
                    "opening_top": top.label(),
                    "via": via,
                }
            )
            continue
        if max_blocks is not None and walked >= max_blocks:
            truncated = True
            gaps.append({"reason": "walk truncated", "block": ref.label(), "via": via})
            continue
        record = blocks.get(ref.key)
        if record is None:
            gaps.append({"reason": "block not read", "block": ref.label(), "via": via})
            continue
        if record.ref.root_hash != ref.root_hash:
            failures.append(
                {
                    "reason": "the block read is not the block the link names",
                    "block": ref.label(),
                    "read": record.ref.label(),
                    "via": via,
                }
            )
            continue
        walked += 1
        reached[ref.key] = ref
        problem = expected_parents(record)
        if problem is not None:
            failures.append({"reason": problem, "block": ref.label(), "via": via})
        merges += record.after_merge
        splits += record.after_split
        for parent in record.prev:
            pending.append((parent, ref.label()))
    closing = {t.key: t for t in rows[-1].tops}
    unreached = []
    for ref in observed:
        if ref.key in frontier or below_frontier(ref, frontier) is not None:
            continue
        if ref.key not in closing and below_frontier(ref, closing) is None:
            continue  # generated after the closing boundary
        got = reached.get(ref.key)
        if got is None or got.root_hash != ref.root_hash:
            unreached.append(ref.label())
    if unreached:
        entry = {"reason": "observed window blocks not reached by the walk", "blocks": unreached}
        # Only a complete walk can show that a block is unreachable.
        (gaps if gaps else failures).append(entry)
    verdict = Verdict(
        _decide(failures, gaps),
        failures,
        gaps,
        {
            "opening_mc": rows[0].seqno,
            "closing_mc": rows[-1].seqno,
            "window_blocks": len(reached),
            "merge_blocks": merges,
            "split_blocks": splits,
            "truncated": truncated,
            "observed_unreached": len(unreached),
            "finalized_mc": finalized_mc,
        },
    )
    return Continuity(verdict, reached)


# ─── message conservation ────────────────────────────────────────────


@dataclass(frozen=True)
class Msg:
    """A message summary; addresses are raw ``wc:hex`` strings, the hash is the cell hash."""

    hash: str
    kind: str  # "internal", "external" or "unknown"
    source: str | None = None
    destination: str | None = None
    bounced: bool = False


@dataclass(frozen=True)
class Tx:
    hash: str
    account: str  # raw "wc:hex"
    lt: int
    block: BlockKey
    in_msg: Msg | None
    out_msgs: tuple[Msg, ...] = ()
    aborted: bool = False
    activated: bool = False
    action_success: bool | None = None
    skipped_actions: int = 0


@dataclass(frozen=True)
class BlockTxs:
    txs: tuple[Tx, ...]
    complete: bool  # every page of the block's transaction list was read


@dataclass(frozen=True)
class QueueBoundary:
    """The outbound queue at a boundary masterchain block: ``empty`` is None when unknown."""

    mc_seqno: int | None
    empty: bool | None


def check_conservation(
    continuity: Continuity,
    txs: Mapping[BlockKey, BlockTxs],
    run_accounts: Iterable[str],
    entry_sources: Iterable[str] = (),
    opening: QueueBoundary = QueueBoundary(None, None),
    closing: QueueBoundary = QueueBoundary(None, None),
) -> Verdict:
    """Every run-owned internal message emitted in the window is imported exactly once.

    Run-owned messages are the internal messages that transactions on run
    accounts emit inside the window, plus those an entry source (the funding
    wallet) sends to a run account. Delivery is a transaction on the
    message's destination account whose inbound message is that message;
    queue and routing records do not count. Bounces and deployments are
    delivered like any other message and reported in their own classes;
    skipped and failed actions emit no message and are counted on their own.
    Any message imported by two transactions is a FAIL, run-owned or not.
    """
    run = set(run_accounts)
    entries = set(entry_sources)
    failures: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    if continuity.verdict.status != PASS:
        gaps.append(
            {
                "reason": "block continuity is not established",
                "continuity": continuity.verdict.status,
            }
        )
    if opening.empty is not True:
        gaps.append({"reason": "the opening queue is not known to be empty"})
    window: list[Tx] = []
    for key in sorted(continuity.reached):
        block = txs.get(key)
        if block is None:
            gaps.append({"reason": "transactions not read", "block": key})
            continue
        if not block.complete:
            gaps.append({"reason": "transaction list incomplete", "block": key})
        window.extend(block.txs)

    emitted: dict[str, tuple[Msg, Tx]] = {}
    imports: dict[str, list[Tx]] = {}
    skipped = failed_actions = aborted = 0
    unknown = 0
    for tx in window:
        on_run = tx.account in run
        if on_run:
            skipped += tx.skipped_actions
            failed_actions += tx.action_success is False
            aborted += tx.aborted
        if tx.in_msg is not None:
            if tx.in_msg.kind == "internal":
                imports.setdefault(tx.in_msg.hash, []).append(tx)
            elif tx.in_msg.kind == "unknown" and on_run:
                unknown += 1
                gaps.append({"reason": "inbound message not decoded", "tx": tx.hash})
        for msg in tx.out_msgs:
            if msg.kind == "unknown" and on_run:
                unknown += 1
                gaps.append({"reason": "outbound message not decoded", "tx": tx.hash})
                continue
            if msg.kind != "internal":
                continue
            owned = on_run or (tx.account in entries and msg.destination in run)
            if not owned:
                continue
            if msg.hash in emitted:
                failures.append(
                    {
                        "reason": "one message emitted twice",
                        "message": msg.hash,
                        "txs": [emitted[msg.hash][1].hash, tx.hash],
                    }
                )
                continue
            emitted[msg.hash] = (msg, tx)

    for digest, importers in sorted(imports.items()):
        if len(importers) > 1:
            failures.append(
                {
                    "reason": "one message imported more than once",
                    "message": digest,
                    "txs": [t.hash for t in importers],
                }
            )

    complete = not gaps
    classes = {"entry": 0, "hop": 0, "deployment": 0, "bounce": 0}
    pending: list[str] = []
    dropped: list[str] = []
    for digest, (msg, origin) in sorted(emitted.items()):
        importers = imports.get(digest, [])
        if not importers:
            if complete and closing.empty is True:
                dropped.append(digest)
            else:
                pending.append(digest)
            continue
        target = importers[0]
        if any(t.account != msg.destination for t in importers):
            failures.append(
                {
                    "reason": "a message imported by an account other than its destination",
                    "message": digest,
                    "destination": msg.destination,
                    "importers": [t.account for t in importers],
                }
            )
            continue
        if msg.bounced:
            classes["bounce"] += 1
        elif target.activated:
            classes["deployment"] += 1
        elif origin.account in entries and origin.account not in run:
            classes["entry"] += 1
        else:
            classes["hop"] += 1
    if dropped:
        failures.append(
            {
                "reason": "run-owned messages never delivered after the queue drained",
                "messages": dropped,
            }
        )
    if pending:
        gaps.append(
            {
                "reason": "run-owned messages not delivered inside the window",
                "closing_queue_empty": closing.empty,
                "messages": pending,
            }
        )

    carried_in: list[str] = []
    foreign = 0
    for digest, importers in sorted(imports.items()):
        if digest in emitted:
            continue
        tx = importers[0]
        if tx.account not in run:
            continue
        msg = tx.in_msg
        if msg is None:
            continue
        if msg.source in run or msg.source in entries:
            carried_in.append(digest)
        else:
            foreign += 1
    if carried_in:
        entry = {
            "reason": "run-owned messages imported without an emission inside the window",
            "messages": carried_in,
        }
        # With an empty opening queue nothing can arrive from before the window.
        (failures if complete and opening.empty is True else gaps).append(entry)

    return Verdict(
        _decide(failures, gaps),
        failures,
        gaps,
        {
            "window_transactions": len(window),
            "run_owned_emitted": len(emitted),
            "delivered": classes,
            "pending": len(pending),
            "dropped": len(dropped),
            "carried_in": len(carried_in),
            "foreign_imports": foreign,
            "skipped_actions": skipped,
            "failed_action_phases": failed_actions,
            "aborted_transactions": aborted,
            "undecoded_messages": unknown,
            "opening_mc": opening.mc_seqno,
            "closing_mc": closing.mc_seqno,
        },
    )


def evaluate(
    mcs: list[McRecord],
    blocks: Mapping[BlockKey, BlockRecord],
    txs: Mapping[BlockKey, BlockTxs],
    run_accounts: Iterable[str],
    entry_sources: Iterable[str] = (),
    opening: QueueBoundary = QueueBoundary(None, None),
    closing: QueueBoundary = QueueBoundary(None, None),
    observed: Iterable[BlockRef] = (),
    max_blocks: int | None = None,
    *,
    finalized_mc: int | None,
) -> dict[str, Any]:
    """The layout record and the continuity and conservation verdicts of one window."""
    changes, layout = layout_changes(mcs)
    continuity = check_continuity(mcs, blocks, observed, max_blocks, finalized_mc=finalized_mc)
    conservation = check_conservation(
        continuity, txs, run_accounts, entry_sources, opening, closing
    )
    statuses = [layout.status, continuity.verdict.status, conservation.status]
    overall = FAIL if FAIL in statuses else INCONCLUSIVE if INCONCLUSIVE in statuses else PASS
    return {
        "status": overall,
        "layout_changes": [c.as_dict() for c in changes],
        "layout": layout.as_dict(),
        "continuity": continuity.verdict.as_dict(),
        "conservation": conservation.as_dict(),
    }


def run_owned_balance(
    continuity: Continuity,
    txs: Mapping[BlockKey, BlockTxs],
    run_accounts: Iterable[str],
    entry_sources: Iterable[str] = (),
) -> dict[str, int]:
    """Run-owned messages emitted in the window against those imported in it.

    A diagnostic for the records only; the verdict comes from
    ``check_conservation``, which requires the whole queue to be empty.
    """
    run, entries = set(run_accounts), set(entry_sources)
    emitted: set[str] = set()
    imported: set[str] = set()
    for key in continuity.reached:
        block = txs.get(key)
        for tx in block.txs if block is not None else ():
            if tx.in_msg is not None and tx.in_msg.kind == "internal":
                imported.add(tx.in_msg.hash)
            for msg in tx.out_msgs:
                if msg.kind == "internal" and (
                    tx.account in run or (tx.account in entries and msg.destination in run)
                ):
                    emitted.add(msg.hash)
    delivered = len(emitted & imported)
    return {
        "emitted": len(emitted),
        "imported": delivered,
        "emitted_minus_imported": len(emitted) - delivered,
    }
