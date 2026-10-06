"""Continuous funded recovery with dual-key POP and no primary AUTH signing."""

import json
import os
import subprocess
from contextlib import ExitStack

import native
from cached_fee_session import CachedFeeSession
from cells import Cell, from_boc
from test_identity import chain
from test_receiver_auth import request
from test_rescue_e2e import digest
from test_state import state


def preserve_module_funds(before, after, transaction):
    """Incoming-funded work may charge prior funds only the recorded protocol rent."""
    s = transaction.refs[2].slice()
    assert s.uint(4) == 0, "ordinary transaction required"
    s.uint(1)  # credit_first; storage charge below is authoritative in either order.
    collected = 0
    if s.uint(1):
        collected = s.coins()
        due = s.coins() if s.uint(1) else 0
        assert due == 0 and s.uint(1) == 0, "module acquired storage debt or changed status"
    assert after[0].hash == before[0].hash, "module data changed"
    assert 0 <= collected <= before[1], "unexpected storage funding"
    assert after[1] + collected >= before[1], "module spent prior funds beyond protocol rent"
    return collected


def run(e, out, **kwargs):
    original_time = getattr(e, "transaction_time", native.NOW)
    try:
        with ExitStack() as stack:
            return _run(e, out, stack=stack, **kwargs)
    finally:
        e.lib.transaction_emulator_set_unixtime(e.ptr, original_time)
        e.transaction_time = original_time


def _run(
    e,
    out,
    *,
    old,
    new,
    wallet,
    recipient,
    prepare,
    pop_external,
    sign_old,
    sign_new,
    fee_intent,
    sign_fee,
    work,
    stack,
    cache_driver=None,
    fee_encoder=None,
    retime_prepare=None,
    retime_pop=None,
    primary_pop=None,
):
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    transactions = {}
    now = native.NOW
    epoch0 = native.NOW - 2 * 3600 - 10
    old_session = new_session = None
    if fee_encoder:
        original_fee_intent = fee_intent

        def fee_intent(**kwargs):
            return fee_encoder.encode(original_fee_intent(**kwargs), now)

    def fee_body(intent, signature):
        return (
            fee_encoder.encode(intent, now, signature)
            if fee_encoder
            else Cell().ref(intent).ref(chain(signature))
        )

    def advance(time):
        nonlocal now
        assert time >= now
        now = time
        assert e.lib.transaction_emulator_set_unixtime(e.ptr, now)
        e.transaction_time = now

    if cache_driver:
        old_session = stack.enter_context(
            CachedFeeSession(
                cache_driver,
                out / "sdk-old",
                tree=old.tree,
                key=old.key,
                vault=old.vault_address,
                epoch0=epoch0,
                opened_time=now,
            )
        )
        old_session.wait_required(now)
        old_session.wait_required(epoch0 + 3 * 3600 - 1)
        advance(epoch0 + 3 * 3600)
        prepare = retime_prepare(now)

    def send(name, account, message, exit_code=0, outputs=0):
        result = e.send(account, message)
        (out / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        assert result["success"], (name, result.get("vm_exit_code"))
        details = result["details"]
        assert details["exit"] == exit_code, (name, details)
        messages = native.outgoing(from_boc(result["transaction"]))
        if exit_code == 0:
            assert not details["aborted"] and len(messages) == outputs, (name, details)
        else:
            assert details["aborted"], (name, details)
            assert (
                native.account_data(from_boc(result["shard_account"]))[0].hash
                == native.account_data(account)[0].hash
            )
        transactions[name] = from_boc(result["transaction"])
        results[name] = details
        return from_boc(result["shard_account"]), messages

    def auth(root, epoch, kind, body=None, signer=sign_old):
        req = request(
            root=root,
            account=wallet.address,
            role=2,
            epoch=epoch,
            kind=kind,
            body=body,
            deadline=now + 600,
        )
        return Cell().uint(0x53554233, 32).ref(req).ref(chain(signer(digest(req))))

    def old_hop(
        name, vault_state, module_state, leaf, payload, kind=1, value=5_000_000_000, outputs=1
    ):
        intent = fee_intent(kind=kind, leaf=leaf, payload=payload, value=value, deadline=now + 600)
        if old_session:
            signature = old_session.signature(intent, now, leaf)
            external = native.external(old.vault_address, fee_body(intent, signature))
        else:
            external = sign_fee(intent, leaf)
        vault_state, messages = send(name + "-fee", vault_state, external, outputs=1)
        prior = native.account_data(module_state)
        module_state, messages = send(name + "-module", module_state, messages[0], outputs=outputs)
        after = native.account_data(module_state)
        results[name + "-module"]["storage_fees_collected"] = preserve_module_funds(
            prior, after, transactions[name + "-module"]
        )
        return vault_state, module_state, messages

    # Only SLH and LMS are used throughout this chain. No synthetic wallet
    # state transitions or balance top-ups are inserted between transactions.
    v0, m0, w = old.vault, old.module, wallet.initial
    v0, m0, messages = old_hop("lock", v0, m0, 12 if cache_driver else 8, auth(old.root, 1, 3))
    lock_relay = messages[0]
    w, _ = send("lock-wallet", w, lock_relay)
    expected = state(
        old.witness, metadata=old.metadata, mode=2, seqno=0, epoch=2, primary=0, rescue=0, retired=2
    )
    assert native.account_data(w)[0].hash == expected.hash, "lock state transition missing"
    send("lock-replay", w, lock_relay, exit_code=1803)

    v0, m0, messages = old_hop(
        "prepare",
        v0,
        m0,
        13 if cache_driver else 9,
        prepare,
        kind=3,
        value=50_000_000_000,
        outputs=2,
    )
    deployed = []
    for name, message, data in zip(("module", "vault"), messages, (new.data, new.vault_data)):
        empty = Cell().uint(0, 320).ref(Cell().uint(0, 1))
        account, _ = send("deploy-" + name, empty, message)
        actual, balance = native.account_data(account)
        assert actual.hash == data.hash and balance > 0
        deployed.append(account)
    m1, v1 = deployed
    if cache_driver:
        new_session = stack.enter_context(
            CachedFeeSession(
                cache_driver,
                out / "sdk-new",
                tree=new.tree,
                key=new.key,
                vault=new.vault_address,
                epoch0=epoch0,
                opened_time=now,
                successor=True,
            )
        )
        new_session.wait_required(now)
        new_session.wait_required(epoch0 + 4 * 3600 - 1)
        advance(epoch0 + 4 * 3600)
        intent = fee_intent(
            kind=2,
            target=new.vault_address,
            config_hash=new.header,
            leaf=16,
            deadline=now + 600,
            value=5_000_000_000,
            payload=retime_pop(now),
        )
        signature = new_session.signature(intent, now, 16)
        pop_external = native.external(new.vault_address, fee_body(intent, signature))
    v1, messages = send("successor-pop-fee", v1, pop_external, outputs=1)
    before = native.account_data(m1)
    m1, _ = send("successor-pop-module", m1, messages[0])
    after = native.account_data(m1)
    results["successor-pop-module"]["storage_fees_collected"] = preserve_module_funds(
        before, after, transactions["successor-pop-module"]
    )

    def new_external(intent, leaf):
        if new_session:
            signature = new_session.signature(intent, now, leaf)
            external = native.external(new.vault_address, fee_body(intent, signature))
        else:
            msg, sig = work / "recovery-fee-message", work / "recovery-fee-signature"
            msg.write_bytes(intent.hash)
            subprocess.run(
                [
                    os.environ["LMS_TOOL"],
                    "sign",
                    "77" * 32,
                    "88" * 16,
                    "20",
                    str(new.tree),
                    str(leaf),
                    str(msg),
                    "66" * 32,
                    str(sig),
                ],
                check=True,
                capture_output=True,
            )
            external = native.external(
                new.vault_address, Cell().ref(intent).ref(chain(sig.read_bytes()))
            )
        return external

    # The primary key proves possession only; REQUIRED policy and the wallet's
    # retired primary bit continue to forbid primary AUTH spending.
    assert primary_pop is not None, "primary POP constructor missing"
    primary_leaf = 17 if cache_driver else 9
    primary_intent = fee_intent(
        kind=2,
        target=new.vault_address,
        config_hash=new.header,
        leaf=primary_leaf,
        deadline=now + 600,
        value=5_000_000_000,
        payload=primary_pop(now),
    )
    primary_external = new_external(primary_intent, primary_leaf)
    v1, messages = send("successor-primary-pop-fee", v1, primary_external, outputs=1)
    before = native.account_data(m1)
    m1, _ = send("successor-primary-pop-module", m1, messages[0])
    results["successor-primary-pop-module"]["storage_fees_collected"] = preserve_module_funds(
        before, native.account_data(m1), transactions["successor-primary-pop-module"]
    )

    migration = (
        Cell().uint(0x4D494752, 32).ref(new.witness).ref(new.metadata).ref(new.vault_witness)
    )
    v0, m0, messages = old_hop(
        "migrate", v0, m0, 16 if cache_driver else 10, auth(old.root, 2, 4, migration)
    )
    migration_relay = messages[0]
    w, _ = send("migrate-wallet", w, migration_relay)
    expected = state(
        new.witness, metadata=new.metadata, mode=2, seqno=0, epoch=3, primary=0, rescue=0, retired=2
    )
    assert native.account_data(w)[0].hash == expected.hash, "migration state transition missing"
    send("old-module-refused", w, migration_relay, exit_code=1800)

    # A new SLH authorization pays through the deployed V1 and reaches the
    # recipient from the actual migrated account. Policy REQUIRED is retained.
    payment = native.internal(wallet.address, recipient.address, Cell(), value=1_000_000_000)
    actions = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()).ref(payment)
    payload = auth(new.root, 3, 0, Cell().uint(0x45584543, 32).ref(actions), signer=sign_new)
    intent = fee_intent(
        kind=1,
        target=new.vault_address,
        config_hash=new.header,
        leaf=18 if cache_driver else 10,
        deadline=now + 600,
        value=5_000_000_000,
        payload=payload,
    )
    external = new_external(intent, 18 if cache_driver else 10)
    v1, messages = send("payment-fee", v1, external, outputs=1)
    before = native.account_data(m1)
    m1, messages = send("payment-module", m1, messages[0], outputs=1)
    after = native.account_data(m1)
    results["payment-module"]["storage_fees_collected"] = preserve_module_funds(
        before, after, transactions["payment-module"]
    )
    payment_relay = messages[0]
    w, messages = send("payment-wallet", w, payment_relay, outputs=1)
    expected = state(
        new.witness, metadata=new.metadata, mode=2, seqno=1, epoch=3, primary=0, rescue=1, retired=2
    )
    assert native.account_data(w)[0].hash == expected.hash
    received, _ = send("recipient", recipient.initial, messages[0])
    data, balance = native.account_data(received)
    assert data.hash == Cell().uint(1, 32).hash
    assert balance > native.account_data(recipient.initial)[1]
    send("payment-replay", w, payment_relay, exit_code=1804)
    replay = e.send(v1, external)
    (out / "fee-replay.json").write_text(json.dumps(replay, indent=2) + "\n")
    assert not replay["success"] and replay.get("vm_exit_code") == 2004
    for account, leaf in ((v0, 17 if cache_driver else 11), (v1, 19 if cache_driver else 11)):
        data = native.account_data(account)[0].slice()
        assert data.uint(8) == 3 and data.uint(32) == leaf
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return {
        "sdk_cached_signatures": 6 if cache_driver else 0,
        "final_chain_time": now,
        "transactions": len(results) + 1,
        "recipient_received": True,
        "primary_auth_signing_used": False,
        "primary_pop_signing_used": True,
        "funded_pop_roles": [1, 2],
        "production_admission_passed": False,
    }
