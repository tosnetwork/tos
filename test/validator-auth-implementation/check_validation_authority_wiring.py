"""Require a validator to rebuild the authority a block was produced with.

A block is produced once and re-executed by every validator. The producer
assembles a registry authority and the privileged instructions run against it;
a validator that rebuilds no authority re-executes those instructions with
nothing behind them, refuses a transaction the producer accepted, reconstructs
a different block, and rejects a candidate that was correct. Nothing in the
producer can detect that, because the producer's own run succeeded.

So both sides must assemble, and from one assembler rather than two readings of
the same facts. Neither may reach past it to the admission calls underneath: a
second assembly is a second answer waiting to differ from the first.

Where a candidate prefix stops being a candidate is the same property seen one
step later. The host stages one and the configuration contract writes the
persistent registry; the two are joined only when the account actually commits,
so the prefix may advance only after that commit and only from what it left in
the account. A virtual machine commit is not that moment -- the action phase can
still fail and roll the account back -- and a producer that advanced on the
earlier signal while a validator did not would disagree about every later
transaction in the block.

Where the assembled authority is then kept is part of the same property. It
belongs to the transaction that received it. A block-scoped field has to be
installed before a transaction and cleared after it, which holds only while one
transaction runs at a time -- and validation re-executes different accounts in
concurrent actors against one shared compute configuration. An authority written
there by one account would be visible to all of them, and whether a candidate
validated would depend on which actor ran when. So the compute configuration may
not carry one, and the transaction must.

These files cannot be instantiated by any test here, so this reads them. That is
weaker than executing them and is not a substitute for the end-to-end case; it
is what can be checked before one exists.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ASSEMBLER = "assemble_registry_authority("
BINDER = "assemble_election_binding_authority("
# The calls the assembler is made of. Reaching them directly is how a second
# assembly appears.
UNDERNEATH = ("admit_registry_message(", "gather_registry_admission_inputs(")
# And what neither side may consult on the way: an answer that depends on what
# one node happened to hold is not an answer both sides can reach.
NODE_LOCAL = ("NativeAnchorCache", "NativeHistoryResolutionQueue", "NativeBlockReader", "resolve_declared_history")

PRODUCER = "validator/impl/collator.cpp"
VALIDATOR = "validator/impl/validate-query.cpp"
# Admission to the message pool executes the destination contract, so it is a
# third place that must be able to build this authority -- see below.
INGRESS = "validator/impl/ext-message-checker.cpp"
CARRIER = "validator/impl/external-message.cpp"
EXECUTION = "crypto/block/transaction.h"

AUTHORITY = "std::shared_ptr<vm::ValidatorAuthHost>"
EXECUTE = "ExtMessageQ::run_message_on_account("
# Where a candidate prefix stops being a candidate. A virtual machine commit is
# not a transaction commit: the action phase can still fail afterwards and roll
# the account back, so the prefix may only advance after the account itself has
# committed, and from what that commit left in the account.
SETTLE = "settle_validator_auth("
COMMIT = "commit("
CLEAR = "validator_auth_claim_ = nullptr;"


def settles_after_commit(text: str) -> bool:
    """Every binding of a committed prefix follows a commit in its own function.

    Reading order rather than data flow, which is weaker than executing it and
    is what can be checked here. A binding placed before the commit would bind a
    candidate against an account that has not been written yet, and a virtual
    machine commit that the action phase later undoes looks identical to a real
    one from inside the compute phase.

    The rule is function scope, not a line budget: how much failure handling
    sits between the two is a matter of style, and a checker whose threshold
    has to be raised whenever that changes is measuring the style."""
    code = re.sub(r"//[^\n]*", "", text)
    for settle in [m.start() for m in re.finditer(re.escape(SETTLE), code)]:
        line = code.rfind("\n", 0, settle)
        # The definition itself is not a call site.
        if "bool " in code[line:settle]:
            continue
        # The enclosing function begins after the previous one ends.
        opened = code.rfind("\n}\n", 0, settle)
        if code.find(COMMIT, opened + 1, settle) < 0:
            return False
    return True


def structure(text: str, name: str) -> str:
    # The definition, not the forward declaration that precedes it: matching
    # "struct Transaction" alone lands on "struct Transaction;" and then reads
    # to the end of whatever type happens to be declared next.
    match = re.search(r"^(?:struct|class) " + re.escape(name) + r"\s*\{", text, re.MULTILINE)
    return text[match.start():text.index("\n};", match.start())] if match else ""


def verify(files: dict[str, str]) -> None:
    # Both sides must bind what the account committed, and bind it after the
    # commit. A producer that advances its prefix and a validator that does not
    # disagree about every later transaction in the block.
    for path in (PRODUCER, VALIDATOR):
        if files[path].count(SETTLE) < 2:
            raise ValueError(f"{path} does not bind a committed prefix")
        if not settles_after_commit(files[path]):
            raise ValueError(f"{path} binds a prefix before the account commits")
        if CLEAR not in files[path]:
            raise ValueError(f"{path} does not clear a candidate a transaction failed to commit")
    for path in (PRODUCER, VALIDATOR, INGRESS):
        if files[path].count(ASSEMBLER) != 1:
            raise ValueError(f"{path} does not assemble the authority exactly once")
        for call in UNDERNEATH:
            if call in files[path]:
                raise ValueError(f"{path} assembles a second time through {call}")
        for token in NODE_LOCAL:
            if token in files[path]:
                raise ValueError(f"{path} reaches {token}")

    # An elected set is the other message the configuration contract answers, and
    # it is decided the same way on both sides. A producer that bound a set its
    # validator did not would rebuild a different block for a reason neither
    # could see -- the same divergence, through the other message.
    for path in (PRODUCER, VALIDATOR):
        if files[path].count(BINDER) != 1:
            raise ValueError(f"{path} does not assemble the binding authority exactly once")
    # Admission to the message pool is not one of them. The pool carries
    # external messages, and an elected set never arrives that way.
    if BINDER in files[INGRESS]:
        raise ValueError("the message pool assembles a binding authority for a message it cannot carry")

    # The pool runs the destination contract before admitting a message, and the
    # configuration contract applies a registry update before accepting one. A
    # message offered no authority there is refused at the door, so every valid
    # update would be dropped before any collator saw one -- and a chain where
    # that happens is indistinguishable from a chain nobody submits updates to.
    # That is why ingress assembles, and why it assembles the same way.
    if files[CARRIER].count("std::move(validator_auth_host)") != 2:
        raise ValueError("the ingress execution path does not carry the authority to the transaction")

    # And that the checker hands one to each execution. It runs the message
    # twice when the first attempt fails, to produce a log, and applying an
    # update stages state inside the authority -- so a second run against the
    # first run's authority would be replaying against a host that has already
    # moved. Counted rather than described, because the difference between one
    # call and two is invisible in a review and fatal in a retry.
    attempts = files[INGRESS].count(EXECUTE)
    if attempts != 2:
        raise ValueError(f"the checker executes {attempts} times, not twice")
    if files[INGRESS].count("authority()") != attempts:
        raise ValueError("the checker does not assemble a fresh authority for each execution")

    # Where the authority is kept decides whether concurrent validation is safe.
    configuration = structure(files[EXECUTION], "ComputePhaseConfig")
    if not configuration:
        raise ValueError("ComputePhaseConfig is not declared")
    if AUTHORITY in configuration or "validator_auth" in configuration:
        raise ValueError("ComputePhaseConfig carries an authority that concurrent checkers would share")
    transaction = structure(files[EXECUTION], "Transaction")
    if not transaction:
        raise ValueError("Transaction is not declared")
    if not re.search(re.escape(AUTHORITY) + r"\s+validator_auth_host;", transaction):
        raise ValueError("Transaction does not own the authority assembled for its message")


def main() -> int:
    files = {path: (ROOT / path).read_text() for path in (PRODUCER, VALIDATOR, INGRESS, CARRIER, EXECUTION)}

    # Silence is not evidence: each requirement is removed in memory and the
    # check has to reject what is left.
    probes = (
        {**files, PRODUCER: files[PRODUCER].replace(ASSEMBLER, "some_other_call(", 1)},
        {**files, VALIDATOR: files[VALIDATOR].replace(ASSEMBLER, "some_other_call(", 1)},
        {**files, VALIDATOR: files[VALIDATOR] + "\nauto x = admit_registry_message(y);\n"},
        {**files, VALIDATOR: files[VALIDATOR] + "\nconst tos::auth::NativeAnchorCache* c = nullptr;\n"},
        {**files, INGRESS: files[INGRESS].replace(ASSEMBLER, "some_other_call(", 1)},
        # The divergence through the other message: one side binds, the other
        # does not.
        {**files, VALIDATOR: files[VALIDATOR].replace(BINDER, "some_other_call(", 1)},
        {**files, PRODUCER: files[PRODUCER].replace(BINDER, "some_other_call(", 1)},
        {**files, INGRESS: files[INGRESS] + f"\nauto b = tos::auth::{BINDER}x);\n"},
        # The shape the defect had: the ingress runs the contract with nothing.
        {**files, CARRIER: files[CARRIER].replace("std::move(validator_auth_host)", "{}", 1)},
        # The retry replaying against an authority the first attempt already
        # spent, and the retry running with none at all.
        {**files, INGRESS: files[INGRESS].replace("*exec_config.log, authority()", "*exec_config.log, host", 1)},
        {**files, INGRESS: files[INGRESS].replace("*exec_config.nolog, authority()", "*exec_config.nolog, {}", 1)},
        # And the retry disappearing, so "twice" is counted rather than assumed.
        {**files, INGRESS: files[INGRESS].replace(EXECUTE, "skipped(", 1)},
        # The move that would undo this: park the authority back on the shared
        # configuration, where one account's write is every account's read.
        {**files, EXECUTION: files[EXECUTION].replace(
            "  SizeLimitsConfig size_limits;",
            f"  SizeLimitsConfig size_limits;\n  {AUTHORITY} validator_auth_host;", 1)},
        {**files, EXECUTION: files[EXECUTION].replace(
            f"  {AUTHORITY} validator_auth_host;\n", "", 1)},
        # The prefix advancing on a signal the action phase can still undo, and
        # on one side only.
        {**files, PRODUCER: files[PRODUCER].replace(SETTLE, "skipped(")},
        {**files, VALIDATOR: files[VALIDATOR].replace(SETTLE, "skipped(")},
        # And a candidate surviving a transaction that never committed, which
        # would authorize the next transaction with the last one's prefix.
        {**files, PRODUCER: files[PRODUCER].replace(CLEAR, "")},
        {**files, VALIDATOR: files[VALIDATOR].replace(CLEAR, "")},
    )
    for probe in probes:
        try:
            verify(probe)
        except ValueError:
            pass
        else:
            raise RuntimeError("validation authority negative control survived")

    try:
        verify(files)
    except ValueError as reason:
        print(f"VALIDATION-AUTHORITY-NOT-WIRED {reason}", file=sys.stderr)
        return 1
    print("PASS: production and validation rebuild one authority from the same facts, "
          "each transaction owns the one assembled for its message, and a prefix advances only on a "
          "committed account")
    return 0


if __name__ == "__main__":
    sys.exit(main())
