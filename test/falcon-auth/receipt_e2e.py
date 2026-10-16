#!/usr/bin/env python3
"""Native transaction -> authenticated test adapter -> AuthProvider receipts.

The local emulator is the test trust anchor. Deliver exact emitted cells, keep
real action phases, and never substitute phase booleans for operation evidence.
The optional Rust driver re-executes every captured transaction independently.
All deterministic keys are PUBLIC TEST DATA.
"""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402
import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "tools/falcon"),
    str(ROOT / "test/tostester/src"),
    str(ROOT / "test/auth-extensions"),
]
import e2e
from backup import encrypt
from build_contracts import build_contracts
from contract.agent_account import AgentAccountState
from contract.pq_auth import transfer_message
from contract.wallet_v5 import WalletV5State
from native import GLOBAL_ID, NOW, account_data, config, outgoing
from protocol import Cell as NativeCell
from protocol import Signer, emulator_library, from_boc, parse_message
from provider import AuthProvider, TrustedChainSnapshot, TrustedModuleSnapshot
from pytosiq_core import Address, Builder, Cell
from pytosiq_core.tlb.account import Account
from pytosiq_core.tlb.transaction import Transaction
from pytosiq_core.tlb.utils import HashUpdate
from receipts import TrustedReceiptEvidence, TrustedTransactionObservation


def sdk(native):
    return Cell.one_from_boc(native.boc())


def addr(value):
    return Address((value[0], value[1].to_bytes(32, "big")))


def observe(result, before, after):
    return TrustedTransactionObservation(
        Cell.one_from_boc(result["transaction"]), sdk(before.refs[0]), sdk(after.refs[0])
    )


def deliver(actor, message, label):
    prior = actor.shard
    actor.e.lt = max(actor.e.lt, parse_message(message)["created_lt"])
    result = actor.e.send(prior, message)
    assert result["success"], result
    actor.shard = from_boc(result["shard_account"])
    e2e.capture_transaction(label, prior, message, actor.e.lt, result)
    return observe(result, prior, actor.shard), result


def actions(messages):
    tail = Cell.empty()
    for mode, msg in messages:
        tail = (
            Builder()
            .store_uint(0x0EC3C86D, 32)
            .store_uint(mode, 8)
            .store_ref(tail)
            .store_ref(msg.serialize())
            .end_cell()
        )
    return tail


def configuration_mismatches(evidence, account_kind):
    """Synthetic negative adapter cells, never claimed as native transactions.

    Keep HASH_UPDATE internally consistent to reach the operation-state guard.
    A production inclusion proof must additionally reject these fabricated cells.
    """
    original = evidence.target
    tx = Transaction.deserialize(original.transaction.begin_parse())
    for field, value in [("mode", 1), ("epoch", 99), ("nonce", 99), ("module_hash", b"x" * 32)]:
        account = Account.deserialize(original.after.begin_parse())
        init = account.storage.state.state_init
        parser = AgentAccountState if account_kind == "agent" else WalletV5State
        state = parser.parse(init.data)
        init.data = replace(state, auth=replace(state.auth, **{field: value})).serialize()
        after = account.serialize()
        update = HashUpdate(tx.state_update.old_hash, after.hash).serialize()
        cell = (
            Builder()
            .store_bits(original.transaction.bits)
            .store_ref(original.transaction.refs[0])
            .store_ref(update)
            .store_ref(original.transaction.refs[2])
            .end_cell()
        )
        yield replace(evidence, target=replace(original, transaction=cell, after=after))


def run_cases(args):
    build, out = args.build.resolve(), args.out.resolve()
    os.environ.update(
        FUNC_PATH=str(build / "crypto/func"),
        FIFT_PATH=str(build / "crypto/fift"),
        TOL_PATH=str(build / "tol/tol"),
        EMULATOR_PATH=str(emulator_library(build)),
    )
    manifest = build_contracts(build, out)
    e2e.ARTIFACTS = out
    e2e.SIGNER = Signer(args.library)
    for name in ("wallet-func", "wallet-tol", "agent"):
        e2e.CODES[name] = from_boc((out / f"{name}.boc").read_bytes())
    for language in ("func", "tol"):
        e2e.MODULE_CODES[language] = from_boc((out / f"module-{language}.boc").read_bytes())
    provider = AuthProvider(e2e.SIGNER.backend, manifest)
    reports = []
    for language in ("func", "tol"):
        for impl in ("wallet-func", "wallet-tol", "agent"):
            for mode in (2, 3):
                for case in (
                    ("normal", "configure", "empty", "policy")
                    if impl == "agent"
                    else ("ignored", "partial", "normal", "configure", "delayed-bounce", "empty")
                ):
                    if args.case is not None and case != args.case:
                        continue
                    p = e2e.Pair(language, impl, 0, mode)
                    recipient = e2e.Module(language, 0, key=2)
                    destination = e2e.Module(language, 0, key=1)
                    try:
                        a, m = p.account, p.module
                        snapshot = TrustedChainSnapshot(
                            GLOBAL_ID,
                            16,
                            NOW,
                            addr(a.address),
                            sdk(e2e.CODES[impl]),
                            sdk(a.data),
                            addr(m.address),
                            sdk(m.code),
                            sdk(m.data),
                        )
                        body = (
                            Builder().store_uint(0x46414C31, 32).end_cell()
                            if case == "delayed-bounce"
                            else Cell.empty()
                        )
                        good = transfer_message(
                            addr(a.address),
                            addr(recipient.address),
                            1_000_000_000,
                            body,
                            bounce=case == "delayed-bounce",
                        )
                        impossible = transfer_message(
                            addr(a.address), addr(recipient.address), 1_000_000_000_000
                        )
                        payload = actions(
                            [(3, impossible)]
                            if case == "ignored"
                            else [(3, good), (3, impossible)]
                            if case == "partial"
                            else []
                            if case == "empty"
                            else [(3, good)]
                        )
                        if impl == "agent":
                            if case == "policy":
                                payload = (
                                    Builder()
                                    .store_uint(0x41475001, 32)
                                    .store_uint(0, 64)
                                    .store_coins(4_000_000_000)
                                    .store_coins(5_000_000_000)
                                    .store_uint(1800, 64)
                                    .store_uint(0, 2)
                                    .end_cell()
                                )
                            else:
                                payload = (
                                    Builder()
                                    .store_uint(0x41475005 if case == "empty" else 0x41475004, 32)
                                    .store_int(GLOBAL_ID, 32)
                                    .store_uint(a.counters()[0], 64)
                                    .store_uint(a.counters()[1], 32)
                                    .store_uint(NOW + 600, 32)
                                )
                                if case != "empty":
                                    payload.store_address(addr(recipient.address)).store_coins(
                                        1_000_000_000
                                    )
                                payload = payload.end_cell()
                        if case == "configure":
                            new_mode = 3 if mode == 2 else 2
                            proof = TrustedModuleSnapshot(
                                GLOBAL_ID,
                                16,
                                NOW,
                                addr(destination.address),
                                sdk(destination.code),
                                sdk(destination.data),
                                "active",
                            )
                            password = b"PUBLIC TEST DATA receipt recovery"
                            backup = encrypt(
                                e2e.SIGNER.handle(1),
                                password,
                                GLOBAL_ID,
                                addr(a.address).to_str(False),
                                addr(destination.address).to_str(False),
                            )
                            request = provider.buildMigrationSigningRequest(
                                snapshot, proof, backup, password, new_mode, NOW + 600, True
                            )
                        else:
                            request = provider.buildSigningRequest(
                                snapshot,
                                snapshot.account,
                                dict(
                                    kind=2 if case == "policy" else 0,
                                    payload=payload,
                                    valid_until=NOW + 600,
                                ),
                            )
                        entropy = hashlib.sha384(
                            b"PUBLIC TEST DATA RECEIPT SIGN " + request.message
                        ).digest()
                        with patch("backend.os.urandom", return_value=entropy):
                            proof = provider.sign(e2e.SIGNER.handle(0), request)
                        co = (
                            e2e.framework.SECRET.sign(request.request.commitment)
                            if mode == 3
                            else None
                        )
                        envelope = from_boc(provider.buildSubmission(request, proof, co).to_boc())
                        prior_module, prior_account = m.shard, a.shard
                        label = f"{language}/{impl}/mode{mode}/{case}"
                        mr, ar, _ = p.execute(envelope, label=label)
                        evidence = TrustedReceiptEvidence(
                            GLOBAL_ID,
                            observe(mr, prior_module, m.shard),
                            observe(ar, prior_account, a.shard),
                        )
                        tx = Transaction.deserialize(evidence.target.transaction.begin_parse())
                        action = tx.description.action
                        receipt = provider.trackReceipt(request, evidence)
                        assert receipt.nonce_consumed, (label, receipt)
                        assert receipt.reserve == "preserved", (label, receipt)
                        if case == "ignored":
                            assert (
                                action.success
                                and action.skipped_actions == 1
                                and action.msgs_created == 0
                            )
                            assert receipt.state == "target actions skipped", (label, receipt)
                        elif case == "partial":
                            assert (
                                action.success
                                and action.skipped_actions == 1
                                and action.msgs_created == 1
                            )
                            assert receipt.state == "target actions partially completed", (
                                label,
                                receipt,
                            )
                            actual = outgoing(from_boc(ar["transaction"]))
                            balance = account_data(recipient.shard)[1]
                            delivery, _ = deliver(
                                recipient, actual[0], label + "/partial-recipient"
                            )
                            assert account_data(recipient.shard)[1] > balance
                            evidence = replace(evidence, deliveries=(delivery,))
                            receipt = provider.trackReceipt(request, evidence)
                            assert receipt.state == "target actions partially completed", (
                                label,
                                receipt,
                            )
                            assert receipt.delivery == "confirmed for emitted subset", (
                                label,
                                receipt,
                            )
                        elif case in ("empty", "configure", "policy"):
                            assert not tx.out_msgs
                            assert receipt.state == "actions completed", (label, receipt)
                            if case == "configure":
                                for mismatch in configuration_mismatches(evidence, impl):
                                    assert (
                                        provider.trackReceipt(request, mismatch).state
                                        == "target outcome incomplete"
                                    ), "configuration result guard"
                        else:
                            assert receipt.state == "actions emitted; delivery pending", (
                                label,
                                receipt,
                            )
                            actual = outgoing(from_boc(ar["transaction"]))
                            assert len(actual) == 1
                            before_balance = account_data(recipient.shard)[1]
                            delivery, result = deliver(recipient, actual[0], label + "/recipient")
                            evidence = replace(evidence, deliveries=(delivery,))
                            receipt = provider.trackReceipt(request, evidence)
                            if case == "normal":
                                assert account_data(recipient.shard)[1] > before_balance
                                assert (
                                    receipt.state == "actions completed"
                                    and receipt.delivery == "confirmed"
                                ), (label, receipt)
                            else:
                                assert receipt.state == "target delivery failed", (label, receipt)
                                assert receipt.bounce == "emitted; return pending", (label, receipt)
                                bounced = outgoing(from_boc(result["transaction"]))
                                assert len(bounced) == 1 and parse_message(bounced[0])["bounced"]
                                wallet_balance = account_data(a.shard)[1]
                                returned, _ = deliver(a, bounced[0], label + "/bounce-return")
                                assert account_data(a.shard)[1] > wallet_balance
                                assert a.auth()[2] == 1, (
                                    "bounce must not undo or consume another nonce"
                                )
                                evidence = replace(evidence, bounce_returns=(returned,))
                                receipt = provider.trackReceipt(request, evidence)
                                assert (
                                    receipt.state == "target delivery failed"
                                    and receipt.bounce == "returned"
                                ), (label, receipt)
                        # Removal/swap of authenticated operation evidence must not
                        # inherit a successful result from the phase/state flags.
                        for missing in (
                            replace(evidence, target=replace(evidence.target, before=None)),
                            replace(evidence, target=replace(evidence.target, after=None)),
                            replace(evidence, network=GLOBAL_ID + 1),
                        ):
                            assert (
                                provider.trackReceipt(request, missing).state
                                == "target outcome incomplete"
                            )
                        unfunded_evidence = replace(
                            evidence, module=replace(evidence.module, before=None, after=None)
                        )
                        assert (
                            provider.trackReceipt(request, unfunded_evidence).reserve
                            == "not observed"
                        )
                        if case == "normal":
                            for unrelated in (
                                (evidence.module,),
                                (evidence.deliveries[0], evidence.deliveries[0]),
                            ):
                                assert (
                                    provider.trackReceipt(
                                        request, replace(evidence, deliveries=unrelated)
                                    ).state
                                    == "target outcome incomplete"
                                )
                        reports.append(
                            dict(
                                case=label,
                                skipped_actions=action.skipped_actions if action else 0,
                                msgs_created=action.msgs_created if action else 0,
                                receipt=asdict(receipt),
                            )
                        )
                    finally:
                        p.close()
                        recipient.close()
                        destination.close()
    return out, reports


def parity(out, driver):
    rows = e2e.TRANSACTIONS
    cases = out / "receipt-scenarios.tsv"
    cases.write_text(
        "\n".join(
            "\t".join([name, str(now), str(lt), before.boc().hex(), msg.boc().hex(), "-"])
            for name, before, msg, lt, now, _ in rows
        )
        + "\n"
    )
    left = [row for *_, row in rows]
    (out / "receipt-cpp.tsv").write_text("\n".join(left) + "\n")
    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    cfg = out / "receipt-config.boc"
    cfg.write_bytes(NativeCell().uint(int(fixture.bits, 2), 256).ref(config(16)).boc())
    result = subprocess.run(
        [str(driver.resolve()), str(cfg), str(cases), "16"],
        capture_output=True,
        text=True,
        check=True,
    )
    (out / "receipt-rust.tsv").write_text(result.stdout)
    assert left == result.stdout.splitlines(), "receipt transaction executor divergence"
    return len(left)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--driver", type=Path)
    parser.add_argument(
        "--case",
        choices=("ignored", "partial", "normal", "configure", "delayed-bounce", "empty", "policy"),
    )
    args = parser.parse_args()
    out, reports = run_cases(args)
    compared = parity(out, args.driver) if args.driver else 0
    report = dict(
        success=True,
        source_commit=subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        scope="native transactions -> test trust adapter -> trackReceipt; not a production chain adapter",
        cases=len(reports),
        transactions_compared=compared,
        events=reports,
    )
    (out / "receipt-e2e.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(dict(success=True, cases=len(reports), transactions_compared=compared)))
