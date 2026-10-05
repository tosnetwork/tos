"""Continuous funded recovery with real account receipts; no primary signing operation."""

import json
import os
import subprocess

import native
from cells import Cell, from_boc
from test_identity import chain
from test_receiver_auth import request
from test_rescue_e2e import digest
from test_state import state


def run(
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
):
    out.mkdir(parents=True, exist_ok=True)
    results = {}

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
        results[name] = details
        return from_boc(result["shard_account"]), messages

    def auth(root, epoch, kind, body=None, signer=sign_old):
        req = request(root=root, account=wallet.address, role=2, epoch=epoch, kind=kind, body=body)
        return Cell().uint(0x53554233, 32).ref(req).ref(chain(signer(digest(req))))

    def old_hop(
        name, vault_state, module_state, leaf, payload, kind=1, value=5_000_000_000, outputs=1
    ):
        external = sign_fee(fee_intent(kind=kind, leaf=leaf, payload=payload, value=value), leaf)
        vault_state, messages = send(name + "-fee", vault_state, external, outputs=1)
        prior = native.account_data(module_state)
        module_state, messages = send(name + "-module", module_state, messages[0], outputs=outputs)
        after = native.account_data(module_state)
        assert after[0].hash == prior[0].hash and after[1] >= prior[1]
        return vault_state, module_state, messages

    # Only SLH and LMS are used throughout this chain. No synthetic wallet
    # state transitions or balance top-ups are inserted between transactions.
    v0, m0, w = old.vault, old.module, wallet.initial
    v0, m0, messages = old_hop("lock", v0, m0, 8, auth(old.root, 1, 3))
    lock_relay = messages[0]
    w, _ = send("lock-wallet", w, lock_relay)
    expected = state(
        old.witness, metadata=old.metadata, mode=2, seqno=0, epoch=2, primary=0, rescue=0, retired=2
    )
    assert native.account_data(w)[0].hash == expected.hash, "lock state transition missing"
    send("lock-replay", w, lock_relay, exit_code=1803)

    v0, m0, messages = old_hop(
        "prepare", v0, m0, 9, prepare, kind=3, value=50_000_000_000, outputs=2
    )
    deployed = []
    for name, message, data in zip(("module", "vault"), messages, (new.data, new.vault_data)):
        empty = Cell().uint(0, 320).ref(Cell().uint(0, 1))
        account, _ = send("deploy-" + name, empty, message)
        actual, balance = native.account_data(account)
        assert actual.hash == data.hash and balance > 0
        deployed.append(account)
    m1, v1 = deployed
    v1, messages = send("successor-pop-fee", v1, pop_external, outputs=1)
    before = native.account_data(m1)
    m1, _ = send("successor-pop-module", m1, messages[0])
    after = native.account_data(m1)
    assert after[0].hash == before[0].hash and after[1] >= before[1]

    migration = (
        Cell().uint(0x4D494752, 32).ref(new.witness).ref(new.metadata).ref(new.vault_witness)
    )
    v0, m0, messages = old_hop("migrate", v0, m0, 10, auth(old.root, 2, 4, migration))
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
        leaf=9,
        value=5_000_000_000,
        payload=payload,
    )
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
            "9",
            str(msg),
            "66" * 32,
            str(sig),
        ],
        check=True,
        capture_output=True,
    )
    external = native.external(new.vault_address, Cell().ref(intent).ref(chain(sig.read_bytes())))
    v1, messages = send("payment-fee", v1, external, outputs=1)
    before = native.account_data(m1)
    m1, messages = send("payment-module", m1, messages[0], outputs=1)
    after = native.account_data(m1)
    assert after[0].hash == before[0].hash and after[1] >= before[1]
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
    for account, leaf in ((v0, 11), (v1, 10)):
        data = native.account_data(account)[0].slice()
        assert data.uint(8) == 3 and data.uint(32) == leaf
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return {
        "transactions": len(results) + 1,
        "recipient_received": True,
        "primary_signing_used": False,
        "production_admission_passed": False,
    }
