"""Parsers for what the shielded client prints and the pure decisions the
end-to-end gate makes about it.

Nothing here touches a network or a file. The driver feeds these functions
what it read and records what they decided, and the unit tests feed them the
same shapes with one fact wrong at a time to show that each decision can fail.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

from localnet_common import LocalnetError, nanotos

JSON = dict[str, Any]


class Adjudication(LocalnetError):
    """A step's facts do not support the claim the gate makes for it."""


# ---------------------------------------------------------------- parsing ---

NOTE_LINE = re.compile(
    r"^\s+index\s+(?P<index>\d+)\s+leaf\s+(?P<leaf>\d+|-)\s+(?P<kind>\w+)\s+"
    r"(?P<amount>[\d.]+) TOS(?P<spent>\s+spent)?"
)
BALANCE_LINE = re.compile(r"^Balance: (?P<amount>[\d.]+) TOS in (?P<count>\d+) spendable notes")
SYNC_LINE = re.compile(
    r"OK (?P<verified>verified|UNVERIFIED) at masterchain (?P<seqno>\d+) \(.*\): "
    r"(?P<steps>\d+) transactions replayed \((?P<applied>\d+) applied, (?P<skipped>\d+) without "
    r"state change\), (?P<new>\d+) new notes, (?P<total>\d+) notes in all"
)
REQUEST_LINE = re.compile(
    r"OK request (?P<request>[0-9a-f]+) submitted; the relayer claims it is (?P<status>[\w-]+)"
)
SPEND_MESSAGE_LINE = re.compile(r"OK spend message (?P<hash>[0-9a-f]{64}) submitted")
DEPOSIT_MESSAGE_LINE = re.compile(r"OK deposit message (?P<hash>[0-9a-f]{64}) submitted")
INPUT_LEAF = re.compile(r"(?P<amount>[\d.]+) TOS \(leaf (?P<leaf>\d+)\)")
CHANGE_LINE = re.compile(r"^\s+Change:\s+(?P<amount>[\d.]+) TOS")
POOL_FEE_LINE = re.compile(r"^\s+Pool fee:\s+(?P<amount>[\d.]+) TOS")
# A relayed summary names the pool's fee inside its funding line, because the
# relayer, not the notes, pays it.
RELAYED_POOL_FEE = re.compile(r"the pool's transact fee is (?P<amount>[\d.]+) TOS")
STATUS_CHAIN_LINE = re.compile(r"^\s+Chain:\s+(?P<outcome>.+?)(?: \(|$)")
STATUS_RELAYER_LINE = re.compile(r"^\s+Relayer:\s+(?P<claim>.+)$")
STATUS_JOURNAL_LINE = re.compile(r"^\s+Journal:\s+(?P<entry>.+)$")
INTENT_LINE = re.compile(r"accepted intent (?P<intent>[0-9a-f]{64})")


@dataclasses.dataclass(frozen=True)
class Note:
    index: int
    leaf: int | None
    kind: str
    amount: int
    spent: bool

    def as_json(self) -> JSON:
        return dataclasses.asdict(self)


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def parse_notes(stdout: str) -> list[Note]:
    notes: list[Note] = []
    for line in strip_ansi(stdout).splitlines():
        match = NOTE_LINE.match(line)
        if match is None:
            continue
        leaf = None if match.group("leaf") == "-" else int(match.group("leaf"))
        notes.append(
            Note(
                int(match.group("index")),
                leaf,
                match.group("kind"),
                nanotos(match.group("amount")),
                match.group("spent") is not None,
            )
        )
    return notes


def parse_balance(stdout: str) -> tuple[int, int]:
    for line in strip_ansi(stdout).splitlines():
        match = BALANCE_LINE.match(line)
        if match is not None:
            return nanotos(match.group("amount")), int(match.group("count"))
    raise Adjudication("no balance line in the client's output")


def parse_sync(stdout: str) -> JSON:
    match = SYNC_LINE.search(strip_ansi(stdout))
    if match is None:
        raise Adjudication("no sync summary in the client's output")
    return {
        "verified": match.group("verified") == "verified",
        "checkpoint_seqno": int(match.group("seqno")),
        "replayed": int(match.group("steps")),
        "applied": int(match.group("applied")),
        "skipped": int(match.group("skipped")),
        "new_notes": int(match.group("new")),
        "notes_in_all": int(match.group("total")),
    }


def parse_request(stdout: str) -> tuple[str, str]:
    match = REQUEST_LINE.search(strip_ansi(stdout))
    if match is None:
        raise Adjudication("no submitted request in the client's output")
    return match.group("request"), match.group("status")


def parse_message_hash(stdout: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(strip_ansi(stdout))
    if match is None:
        raise Adjudication("no submitted message in the client's output")
    return match.group("hash")


def parse_intent(stdout: str) -> str:
    match = INTENT_LINE.search(strip_ansi(stdout))
    if match is None:
        raise Adjudication("no intent digest in the client's output")
    return match.group("intent")


@dataclasses.dataclass(frozen=True)
class SpendPlan:
    inputs: list[tuple[int, int]]  # (amount, leaf)
    change: int
    pool_fee: int

    def as_json(self) -> JSON:
        return {
            "inputs": [{"amount": amount, "leaf": leaf} for amount, leaf in self.inputs],
            "change": self.change,
            "pool_fee": self.pool_fee,
        }


def parse_spend_plan(stdout: str) -> SpendPlan:
    text = strip_ansi(stdout)
    inputs: list[tuple[int, int]] = []
    change = pool_fee = None
    for line in text.splitlines():
        if line.strip().startswith("Inputs:"):
            inputs = [
                (nanotos(m.group("amount")), int(m.group("leaf")))
                for m in INPUT_LEAF.finditer(line)
            ]
        elif (match := CHANGE_LINE.match(line)) is not None:
            change = nanotos(match.group("amount"))
        elif (match := POOL_FEE_LINE.match(line)) is not None:
            pool_fee = nanotos(match.group("amount"))
        elif (match := RELAYED_POOL_FEE.search(line)) is not None:
            pool_fee = nanotos(match.group("amount"))
    if not inputs or change is None or pool_fee is None:
        raise Adjudication("no complete spend summary in the client's output")
    return SpendPlan(inputs, change, pool_fee)


def parse_status(stdout: str) -> JSON:
    chain = relayer = journal = None
    for line in strip_ansi(stdout).splitlines():
        if (match := STATUS_CHAIN_LINE.match(line)) is not None:
            chain = match.group("outcome")
        elif (match := STATUS_RELAYER_LINE.match(line)) is not None:
            relayer = match.group("claim")
        elif (match := STATUS_JOURNAL_LINE.match(line)) is not None:
            journal = match.group("entry")
    if chain is None or journal is None:
        raise Adjudication("no request status in the client's output")
    return {"chain": chain, "relayer": relayer, "journal": journal}


# ----------------------------------------------------------- adjudication ---


def new_notes(before: list[Note], after: list[Note]) -> list[Note]:
    seen = {(note.index, note.leaf) for note in before}
    return [note for note in after if (note.index, note.leaf) not in seen]


def require_exactly_one_import(
    before: list[Note], after: list[Note], amount: int, kind: str
) -> Note:
    """The recipient's sync imported exactly one new note of `amount`."""
    fresh = new_notes(before, after)
    if len(fresh) != 1:
        raise Adjudication(f"expected exactly one new note, found {len(fresh)}")
    note = fresh[0]
    if note.amount != amount:
        raise Adjudication(f"the imported note carries {note.amount}, not {amount}")
    if note.kind != kind:
        raise Adjudication(f"the imported note is a {note.kind} note, not {kind}")
    if note.leaf is None:
        raise Adjudication("the imported note has no leaf")
    return note


def require_inputs_spent(before: list[Note], after: list[Note], leaves: list[int]) -> None:
    """Every planned input is marked spent after the sync, and was not before."""
    for leaf in leaves:
        prior = [note for note in before if note.leaf == leaf]
        later = [note for note in after if note.leaf == leaf]
        if len(prior) != 1 or len(later) != 1:
            raise Adjudication(f"leaf {leaf} is not exactly one note on both sides")
        if prior[0].spent:
            raise Adjudication(f"leaf {leaf} was already spent before the spend")
        if not later[0].spent:
            raise Adjudication(f"leaf {leaf} is not spent after the spend")


def require_two_real_inputs(plan: SpendPlan, amount: int, relayer_fee: int) -> None:
    """The amount vector forced two inputs: neither alone covers amount + fee."""
    if len(plan.inputs) != 2:
        raise Adjudication(f"the plan used {len(plan.inputs)} inputs, not two")
    need = amount + relayer_fee
    for value, leaf in plan.inputs:
        if value >= need:
            raise Adjudication(f"leaf {leaf} alone covers {need}; two inputs were not forced")
    total = sum(value for value, _ in plan.inputs)
    if total - need != plan.change:
        raise Adjudication(f"change {plan.change} is not inputs {total} less {need}")


@dataclasses.dataclass(frozen=True)
class FeeNote:
    transaction_hash: str
    leaf: int


def require_exactly_one_fee_credit(
    before: list[FeeNote],
    after: list[FeeNote],
    credits: list[JSON],
    *,
    note_key_index: int,
    slot: int,
    amount: int,
    transaction_hash: str,
) -> JSON:
    """The operator recorded exactly one new fee note, and its fee-credit record
    names the quoted index and slot, the fee and the executing transaction."""
    fresh = [note for note in after if note not in before]
    if len(fresh) != 1:
        raise Adjudication(f"expected exactly one new fee note, found {len(fresh)}")
    matching = [
        credit
        for credit in credits
        if credit.get("schema") == "tos.relayer.fee-credit.v1"
        and credit.get("transaction") == transaction_hash
    ]
    if len(matching) != 1:
        raise Adjudication(
            f"expected one fee-credit record for the transaction, found {len(matching)}"
        )
    credit = matching[0]
    if credit.get("note_key_index") != note_key_index:
        raise Adjudication("the fee credit's note key index is not the quoted one")
    if credit.get("slot") != slot:
        raise Adjudication("the fee credit's slot is not the quoted one")
    if str(credit.get("amount")) != str(amount):
        raise Adjudication("the fee credit's amount is not the quoted fee")
    if credit.get("leaf_index") != fresh[0].leaf:
        raise Adjudication("the fee credit's leaf is not the recorded fee note's leaf")
    return credit


def require_socks_boundary(receipts: list[JSON], *, expected_groups: int) -> JSON:
    """Every connection authenticated, every admitted target was the one
    allowed name, every refused target was refused before forwarding, and the
    connections fell into exactly `expected_groups` isolation groups."""
    if not receipts:
        raise Adjudication("the SOCKS peer saw no connection")
    groups: set[int] = set()
    forwarded = 0
    for receipt in receipts:
        if not receipt.get("authenticated"):
            raise Adjudication(f"connection {receipt.get('connection')} did not authenticate")
        if receipt.get("refused_target"):
            if receipt.get("forwarded"):
                raise Adjudication("a refused target was forwarded")
            continue
        if not receipt.get("target_allowed"):
            raise Adjudication(f"connection {receipt.get('connection')} reached another target")
        group = receipt.get("isolation_group")
        if not isinstance(group, int):
            raise Adjudication("an admitted connection has no isolation group")
        groups.add(group)
        forwarded += int(bool(receipt.get("forwarded")))
    if len(groups) != expected_groups:
        raise Adjudication(f"{len(groups)} isolation groups, expected {expected_groups}")
    return {"connections": len(receipts), "forwarded": forwarded, "isolation_groups": len(groups)}


def require_single_submission(receipts: list[JSON], group: int) -> None:
    """One isolation group forwarded exactly one submit, so an unacknowledged
    submission was never rebuilt or resent."""
    submits = [
        r
        for r in receipts
        if r.get("isolation_group") == group and r.get("endpoint") == "/v1/submit"
    ]
    if len(submits) != 1:
        raise Adjudication(f"group {group} carried {len(submits)} submits, not one")
    if not submits[0].get("forwarded"):
        raise Adjudication("the one submit was not forwarded")


@dataclasses.dataclass(frozen=True)
class Bounce:
    """The pool's transaction that received the bounced payout."""

    transaction_hash: str
    lt: int
    source: str
    value: int
    bounced: bool


def require_recovery(
    *,
    bounce: Bounce | None,
    payout_destination: str,
    payout_value: int,
    recovery_charge: int,
    before: list[Note],
    after: list[Note],
    prior_leaf_count: int,
) -> Note:
    """A real bounce from the payout's destination came back to the pool, the
    pool minted one recovery note worth the returned value less its recovery
    charge, and that note sits at a leaf appended after the withdrawal."""
    if bounce is None:
        raise Adjudication("no bounce transaction reached the pool")
    if not bounce.bounced:
        raise Adjudication("the pool's incoming message was not a bounce")
    if bounce.source != payout_destination:
        raise Adjudication("the bounce did not come from the payout's destination")
    if not 0 < bounce.value <= payout_value:
        raise Adjudication(f"the bounce returned {bounce.value}, outside (0, {payout_value}]")
    if recovery_charge <= 0:
        raise Adjudication("a recovery charge of zero")
    fresh = new_notes(before, after)
    # The withdrawal itself leaves a recovery template: the index it consumed,
    # listed without a leaf and without money. The bounce then mints the note.
    templates = [note for note in fresh if note.kind == "recovery" and note.leaf is None]
    if len(templates) != 1 or templates[0].amount != 0:
        raise Adjudication(
            f"expected exactly one leafless recovery template of 0 TOS, found {templates}"
        )
    recoveries = [note for note in fresh if note.kind == "recovery" and note.leaf is not None]
    if len(recoveries) != 1:
        raise Adjudication(f"expected exactly one new recovery note, found {len(recoveries)}")
    note = recoveries[0]
    if note.index != templates[0].index:
        raise Adjudication(
            f"the recovery note's index {note.index} is not the template's {templates[0].index}"
        )
    if note.amount != bounce.value - recovery_charge:
        raise Adjudication(
            f"the recovery note carries {note.amount}, not {bounce.value} less {recovery_charge}"
        )
    if note.leaf is None or note.leaf < prior_leaf_count:
        raise Adjudication(f"the recovery leaf {note.leaf} is not after the withdrawal's leaves")
    return note


PROFILE_CODE_HASH_REFUSAL = re.compile(
    r"the pool's code hash (?P<chain>[0-9a-f]{64}) is not the profile's (?P<profile>[0-9a-f]{64})"
)


def require_profile_refusal(
    returncode: int, stderr: str, *, planted: str, genuine: str
) -> dict[str, str]:
    """The tampered-profile control went red for the right reason only.

    `planted` is the code hash the control wrote into the profile, `genuine`
    the one the untampered profile carries. An init that fails for any other
    reason (an unreachable node, a verifier failure, a crash) is not evidence
    that the profile check exists, and is refused as such."""
    if returncode == 0:
        raise Adjudication("a tampered profile was accepted")
    match = PROFILE_CODE_HASH_REFUSAL.search(strip_ansi(stderr))
    if match is None:
        raise Adjudication(
            "init failed, but not because of the profile's code hash: " + stderr.strip()[-400:]
        )
    if match["profile"] != planted:
        raise Adjudication("the refusal names a profile code hash the control did not plant")
    if match["chain"] != genuine:
        raise Adjudication("the chain's code hash in the refusal is not the genuine profile's")
    return {"chain_code_hash": match["chain"], "refused_profile_code_hash": match["profile"]}


def require_spends_leaf(plan: SpendPlan, leaf: int) -> None:
    """The later spend consumed exactly the recovered leaf, not only change."""
    if leaf not in {planned for _, planned in plan.inputs}:
        raise Adjudication(f"the spend did not consume the recovered leaf {leaf}")


@dataclasses.dataclass(frozen=True)
class Payout:
    """The recipient's transaction that received the withdrawal's payout."""

    transaction_hash: str
    source: str
    value: int
    bounced: bool
    fee: int


def require_public_payout(
    *,
    payout: Payout | None,
    pool: str,
    amount: int,
    balance_before: int,
    balance_after: int,
) -> None:
    """The recipient was paid exactly the requested amount by the pool, and its
    balance moved by that amount less its own transaction fee."""
    if payout is None:
        raise Adjudication("no payout reached the recipient")
    if payout.source != pool:
        raise Adjudication("the payout did not come from the pool")
    if payout.bounced:
        raise Adjudication("the payout was a bounce")
    if payout.value != amount:
        raise Adjudication(f"the payout carried {payout.value}, not {amount}")
    if balance_after - balance_before != payout.value - payout.fee:
        raise Adjudication(
            f"the balance moved by {balance_after - balance_before}, "
            f"not {payout.value} less fee {payout.fee}"
        )


def require_withdrawal_plan(plan: SpendPlan, amount: int, withdrawal_fee: int) -> None:
    """The fee is charged on top of the public amount, out of the notes."""
    if plan.pool_fee != withdrawal_fee:
        raise Adjudication(f"the plan's pool fee {plan.pool_fee} is not {withdrawal_fee}")
    total = sum(value for value, _ in plan.inputs)
    if total - amount - withdrawal_fee != plan.change:
        raise Adjudication("change is not inputs less the amount and the fee")
