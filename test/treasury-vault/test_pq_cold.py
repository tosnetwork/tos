"""The cold administrator leg, executed through a post-quantum multisig account.

A 2-of-3 ML-DSA-44 multisig (crypto/smartcont/pq-multisig-code.fc) holds the vault's cold
role; the business and guardian roles are the post-quantum wallets of test_pq_wallets.py,
so every signer in these scenarios is post-quantum. Each multisig submission is a relayed
request carrying exactly `quorum` signatures from the TEST ONLY signer; the multisig
executes at global version 16, the VM log must show one verification per signature, and
the multisig's actual emitted message is delivered to the vault unchanged.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/pq-contracts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pqtest  # noqa: E402
import test_native  # noqa: E402
import test_pq_wallets  # noqa: E402
from cells import Cell, from_boc, make_dict  # noqa: E402
from native import (  # noqa: E402
    GLOBAL_ID,
    account_data,
    active_account,
    internal,
    outgoing,
    state_init,
)
from test_native import PAUSER, SOURCE, TARGET, Vault, compile_fresh  # noqa: E402
from test_pq_wallets import PqWallet  # noqa: E402
from wire import (  # noqa: E402
    APPLY,
    APPROVE,
    COIN,
    DELAY,
    PAUSE,
    SCHEDULE,
    SUBMIT,
    VETO,
    decode_message,
    envelope,
    roles,
    set_asset,
)

MULTISIG_SOURCE = Path(
    os.environ.get("PQ_MULTISIG_SOURCE", ROOT / "crypto/smartcont/pq-multisig-code.fc")
)
CONTEXT = b"TOS-PQ-QUORUM-v1"
SUBMIT_OP = 0x504D5353
SEND_MSG = 0x0EC3C86D
EXECUTE, CONFIGURE = 1, 2
DOMAIN = {EXECUTE: 0x504D5331, CONFIGURE: 0x504D5332}
ADD, REMOVE, QUORUM = 1, 2, 3
ERR = {
    "invalid_config": 0x1B01,
    "unknown_signer": 0x1B03,
    "invalid_signature": 0x1B05,
    "wrong_signature_count": 0x1B06,
    "expired": 0x1B07,
    "unknown_kind": 0x1C83,
    "invalid_action": 0x1C84,
    "invalid_mode": 0x1C85,
    "invalid_message": 0x1C86,
    "insufficient_value": 0x1C87,
    "unknown_change": 0x1C88,
    "seqno_exhausted": 0x1C89,
    "stored_count": 0x1C8A,
    "key_id_mismatch": 0x1B09,
}
RELAYER = (0, 78)
RELAY_VALUE = 20 * COIN
SIGNERS = (21, 22, 23)
MULTISIG_CODE = None
GAS = {}


def verifier_set(keys):
    return make_dict(
        {
            pqtest.key_id(pqtest.public_key(k)): Cell().ref(pqtest.stored(pqtest.public_key(k)))
            for k in keys
        },
        256,
    )


def multisig_data(keys, quorum, seqno=0):
    """Deployment builder: the trusted config plus a fresh sequence number."""
    return Cell().maybe(verifier_set(keys)).uint(len(keys), 8).uint(quorum, 8).uint(seqno, 64)


def relaxed(destination, value, body, bounce=0):
    return (
        Cell()
        .uint(0, 1)
        .uint(1, 1)
        .uint(bounce, 1)
        .uint(0, 1)
        .uint(0, 2)
        .addr(destination)
        .coins(value)
        .uint(0, 1)
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(0, 32)
        .uint(0, 1)
        .uint(1, 1)
        .ref(body)
    )


def out_list(sends):
    node = Cell()
    for mode, message in sends:
        node = Cell().ref(node).uint(SEND_MSG, 32).uint(mode, 8).ref(message)
    return node


def action_count(payload):
    count, node = 0, payload
    while node.refs:
        count += 1
        node = node.refs[0]
    return count


# Mirrors the contract's funding quote; the test asserts measured gas stays under it.
FEE = dict(base=20_000, signature=4_000, action=8_000, configure=30_000)


def allowed_gas(quorum, kind, payload):
    gas = FEE["base"] + FEE["signature"] * quorum
    if kind == EXECUTE:
        return gas + FEE["action"] * action_count(payload)
    return gas + FEE["configure"]


class PqMultisig:
    def __init__(self, keys=SIGNERS, quorum=2, data=None):
        self.keys, self.quorum = list(keys), quorum
        data = multisig_data(self.keys, quorum) if data is None else data
        self.address = (0, int.from_bytes(state_init(MULTISIG_CODE, data).hash, "big"))
        self.shard = active_account(self.address, MULTISIG_CODE, data, balance=100 * COIN)

    @property
    def data(self):
        return account_data(self.shard)[0]

    @property
    def seqno(self):
        s = self.data.slice()
        s.maybe()
        s.uint(8)
        s.uint(8)
        return s.uint(64)

    def get(self, method, *args):
        return pqtest.get_method(MULTISIG_CODE, self.data, self.address, method, args)

    def quote(self, kind, actions=1):
        exit_code, values = self.get("get_required_value", kind, actions)
        assert exit_code == 0, exit_code
        return values[0]

    def signing_hash(
        self, kind, payload, valid_until, *, seqno=None, target=None, domain=None, global_id=None
    ):
        return (
            Cell()
            .sint(GLOBAL_ID if global_id is None else global_id, 32)
            .uint(DOMAIN[kind] if domain is None else domain, 32)
            .addr(self.address if target is None else target)
            .uint(self.seqno if seqno is None else seqno, 64)
            .uint(valid_until, 32)
            .ref(payload)
            .hash
        )

    def submission(self, kind, payload, valid_until, signers, **overrides):
        """A relayed request signed by `signers`, each filed under its own key id."""
        digest = self.signing_hash(kind, payload, valid_until, **overrides)
        sigs = make_dict(
            {
                pqtest.key_id(pqtest.public_key(filed)): Cell().ref(
                    pqtest.stored(pqtest.sign(k, digest, CONTEXT))
                )
                for k, filed in signers
            },
            256,
        )
        request = Cell().uint(kind, 8).uint(valid_until, 32).ref(payload)
        return Cell().uint(SUBMIT_OP, 32).uint(self.seqno, 64).ref(request).maybe(sigs)

    def submit(
        self,
        vault,
        kind,
        payload,
        signers=None,
        *,
        value=RELAY_VALUE,
        expected=0,
        valid_until=None,
        verifications=None,
        body=None,
        **overrides,
    ):
        """Relay a signed request; return the emitted messages other than the refund."""
        if signers is None:
            signers = [(k, k) for k in self.keys[: self.quorum]]
        valid_until = vault.now + 600 if valid_until is None else valid_until
        if body is None:
            body = self.submission(kind, payload, valid_until, signers, **overrides)
        before = self.data.hash
        result = vault.e.send(self.shard, internal(RELAYER, self.address, body, value))
        details = pqtest.details_of(result)
        self.shard = from_boc(result["shard_account"])
        assert details["exit"] == expected, (
            f"expected multisig exit {expected}, got {details}\n{result.get('vm_log', '')[-6000:]}"
        )
        if verifications is not None:
            assert details["verifications"] == verifications, details
        messages = outgoing(from_boc(result["transaction"]))
        if expected:
            assert self.data.hash == before, "a refused request changed state"
            assert not messages, "a refused request emitted messages"
            return []
        assert details["verifications"] == self.quorum, details
        assert not details["aborted"], details
        assert details["action"] is None or details["action"]["success"], details
        label = f"{kind}:{self.quorum}:{action_count(payload) if kind == EXECUTE else 0}"
        GAS[label] = max(GAS.get(label, 0), details["gas"])
        allowance = allowed_gas(self.quorum, kind, payload)
        assert details["gas"] <= allowance, (
            f"gas {details['gas']} exceeds the funding quote's allowance {allowance}"
        )
        refunds = [m for m in messages if decode_message(m)["target"] == RELAYER]
        assert len(refunds) == 1, "the multisig refunds the relayer exactly once"
        return [m for m in messages if decode_message(m)["target"] != RELAYER]

    def send_to_vault(self, vault, body, signers=None, *, amount=COIN // 2, **kw):
        payload = out_list([(1, relaxed(vault.address, amount, body))])
        return self.submit(vault, EXECUTE, payload, signers, **kw)


class PqColdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global MULTISIG_CODE
        for key in ("FUNC_PATH", "FIFT_PATH", "EMULATOR_PATH", "PQ_TEST_SIGNER"):
            if not os.environ.get(key):
                raise RuntimeError(f"{key} is required; cold-leg tests cannot be skipped")
        cls.tmp = tempfile.TemporaryDirectory(prefix="treasury-pq-cold-")
        test_native.CODE = compile_fresh(SOURCE, Path(cls.tmp.name) / "treasury.boc")
        test_pq_wallets.WALLET_CODE = pqtest.compile_source(
            test_pq_wallets.WALLET_SOURCE, Path(cls.tmp.name) / "pq-wallet.boc"
        )
        MULTISIG_CODE = pqtest.compile_source(MULTISIG_SOURCE, Path(cls.tmp.name) / "multisig.boc")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.cold = PqMultisig()
        self.business, self.guardian = PqWallet(11), PqWallet(12)
        role_cell = roles(self.business.address, self.guardian.address, self.cold.address, PAUSER)
        self.v = Vault(role_cell=role_cell)
        self.addCleanup(self.v.close)

    def deliver(self, messages, expected=0):
        self.assertEqual(len(messages), 1)
        msg = decode_message(messages[0])
        self.assertEqual((msg["source"], msg["target"]), (self.cold.address, self.v.address))
        self.assertEqual(msg["value"], COIN // 2)
        return self.v.send(message=messages[0], expected=expected)

    def admin(self, payload):
        return self.v.req(payload, admin=True)

    # -- the multisig itself -------------------------------------------------------------

    def test_deployment_check_rejects_a_bad_initial_configuration(self):
        exit_code, values = self.cold.get("get_checked_config")
        self.assertEqual((exit_code, values), (0, [3]))
        good = pqtest.public_key(21)
        wrong_id = make_dict(
            {
                pqtest.key_id(pqtest.public_key(22)): Cell().ref(pqtest.stored(good)),
                pqtest.key_id(pqtest.public_key(23)): Cell().ref(
                    pqtest.stored(pqtest.public_key(23))
                ),
            },
            256,
        )
        bad = PqMultisig(data=Cell().maybe(wrong_id).uint(2, 8).uint(2, 8).uint(0, 64))
        self.assertEqual(bad.get("get_checked_config")[0], ERR["key_id_mismatch"])
        miscounted = PqMultisig(
            data=Cell().maybe(verifier_set(SIGNERS)).uint(2, 8).uint(2, 8).uint(0, 64)
        )
        self.assertEqual(miscounted.get("get_checked_config")[0], ERR["stored_count"])
        over = PqMultisig(
            data=Cell().maybe(verifier_set(SIGNERS)).uint(3, 8).uint(4, 8).uint(0, 64)
        )
        self.assertEqual(over.get("get_checked_config")[0], ERR["invalid_config"])

    def test_threshold_and_membership_are_enforced_before_verification(self):
        v, cold = self.v, self.cold
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        cold.send_to_vault(
            v, body, [(21, 21)], expected=ERR["wrong_signature_count"], verifications=0
        )
        cold.send_to_vault(
            v,
            body,
            [(21, 21), (22, 22), (23, 23)],
            expected=ERR["wrong_signature_count"],
            verifications=0,
        )
        cold.send_to_vault(
            v, body, [(21, 21), (24, 24)], expected=ERR["unknown_signer"], verifications=0
        )
        # A member's slot filled by another member's signature fails at verification.
        cold.send_to_vault(v, body, [(21, 21), (23, 22)], expected=ERR["invalid_signature"])
        cold.send_to_vault(v, body, [], expected=ERR["wrong_signature_count"], verifications=0)
        self.assertEqual(cold.seqno, 0)
        self.assertIsNone(v.state["admin"])

    def test_request_binding_and_replay(self):
        v, cold = self.v, self.cold
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        cold.send_to_vault(v, body, expected=ERR["expired"], valid_until=v.now - 1, verifications=0)
        cold.send_to_vault(v, body, expected=ERR["invalid_signature"], seqno=1)
        cold.send_to_vault(v, body, expected=ERR["invalid_signature"], target=self.business.address)
        cold.send_to_vault(v, body, expected=ERR["invalid_signature"], domain=DOMAIN[CONFIGURE])
        cold.send_to_vault(v, body, expected=ERR["invalid_signature"], global_id=GLOBAL_ID + 1)
        payload = out_list([(1, relaxed(v.address, COIN // 2, body))])
        accepted = cold.submission(EXECUTE, payload, v.now + 600, [(21, 21), (22, 22)])
        self.deliver(cold.submit(v, EXECUTE, payload, body=accepted))
        self.assertEqual(cold.seqno, 1)
        cold.submit(v, EXECUTE, payload, body=accepted, expected=ERR["invalid_signature"])
        self.assertEqual(cold.seqno, 1)

    def test_malformed_requests_are_refused_before_verification(self):
        v, cold = self.v, self.cold
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        message = relaxed(v.address, COIN // 2, body)
        # The same message with this account named as its source instead of addr_none.
        sourced = (
            Cell()
            .uint(0, 1)
            .uint(1, 1)
            .uint(0, 1)
            .uint(0, 1)
            .addr(cold.address)
            .addr(v.address)
            .coins(COIN // 2)
            .uint(0, 1)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(0, 32)
            .uint(0, 1)
            .uint(1, 1)
            .ref(body)
        )
        set_code = Cell().ref(Cell()).uint(0xAD4DE08E, 32).uint(0, 8).ref(message)
        cases = [
            (EXECUTE, out_list([(1, sourced)]), ERR["invalid_message"]),
            (EXECUTE, set_code, ERR["invalid_action"]),
            (EXECUTE, out_list([(1, message)] * 17), ERR["invalid_action"]),
            (EXECUTE, out_list([]), ERR["invalid_action"]),
            (EXECUTE, out_list([(32, message)]), ERR["invalid_mode"]),
            (EXECUTE, out_list([(1, relaxed(v.address, COIN // 2, body).uint(1, 1))]), 9),
            (CONFIGURE, Cell().uint(9, 8), ERR["unknown_change"]),
            (CONFIGURE, Cell().uint(QUORUM, 8).uint(2, 8).uint(1, 1), 9),
        ]
        for kind, payload, expected in cases:
            with self.subTest(expected=expected):
                cold.submit(v, kind, payload, expected=expected, verifications=0)
        unknown = Cell().uint(3, 8).uint(v.now + 600, 32).ref(Cell())
        raw = Cell().uint(SUBMIT_OP, 32).uint(0, 64).ref(unknown).maybe(None)
        cold.submit(v, EXECUTE, Cell(), body=raw, expected=ERR["unknown_kind"], verifications=0)
        trailing = Cell().uint(SUBMIT_OP, 32).uint(0, 64).ref(unknown).maybe(None).uint(1, 1)
        cold.submit(v, EXECUTE, Cell(), body=trailing, expected=9, verifications=0)
        with_init = (
            Cell()
            .uint(0, 1)
            .uint(1, 1)
            .uint(0, 1)
            .uint(0, 1)
            .uint(0, 2)
            .addr(v.address)
            .coins(COIN // 2)
            .uint(0, 1)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(0, 32)
            .uint(1, 1)
            .uint(1, 1)
            .ref(Cell())
            .uint(1, 1)
            .ref(body)
        )
        cold.submit(
            v, EXECUTE, out_list([(1, with_init)]), expected=ERR["invalid_message"], verifications=0
        )
        extra = make_dict({1: Cell().uint(1, 5).uint(1, 8)}, 32)
        with_extra = (
            Cell()
            .uint(0, 1)
            .uint(1, 1)
            .uint(0, 1)
            .uint(0, 1)
            .uint(0, 2)
            .addr(v.address)
            .coins(COIN // 2)
            .maybe(extra)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(0, 32)
            .uint(0, 1)
            .uint(1, 1)
            .ref(body)
        )
        cold.submit(
            v,
            EXECUTE,
            out_list([(1, with_extra)]),
            expected=ERR["invalid_message"],
            verifications=0,
        )
        self.assertEqual(cold.seqno, 0)

    def test_a_failed_send_is_skipped_but_a_refused_request_leaves_nothing(self):
        v, cold = self.v, self.cold
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        # The first send asks for more than the account holds. Sends run with +2, so it is
        # skipped, the sequence number is consumed and the rest of the batch still goes out.
        payload = out_list(
            [(1, relaxed(v.address, 1000 * COIN, body)), (1, relaxed(v.address, COIN // 2, body))]
        )
        messages = cold.submit(v, EXECUTE, payload, value=cold.quote(EXECUTE, 2))
        self.assertEqual([decode_message(m)["value"] for m in messages], [COIN // 2])
        self.assertEqual(cold.seqno, 1)
        self.deliver(messages)
        self.assertIsNotNone(v.state["admin"])
        # A request refused in the compute phase aborts the whole transaction: no sequence
        # number is consumed and nothing leaves the account, not even the relayer refund.
        before = cold.data.hash
        cold.send_to_vault(
            v,
            envelope(SCHEDULE, self.admin(set_asset(0))),
            [(21, 21), (23, 22)],
            expected=ERR["invalid_signature"],
        )
        self.assertEqual(cold.seqno, 1)
        self.assertEqual(cold.data.hash, before)

    def test_funding_quote_is_exact_and_covers_measured_gas(self):
        v, cold = self.v, self.cold
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        quote = cold.quote(EXECUTE, 1)
        cold.send_to_vault(
            v, body, expected=ERR["insufficient_value"], value=quote - 1, verifications=0
        )
        self.deliver(cold.send_to_vault(v, body, value=quote))
        configure = cold.quote(CONFIGURE)
        payload = Cell().uint(QUORUM, 8).uint(2, 8)
        cold.submit(
            v,
            CONFIGURE,
            payload,
            expected=ERR["insufficient_value"],
            value=configure - 1,
            verifications=0,
        )
        cold.submit(v, CONFIGURE, payload, value=configure)
        self.assertEqual(cold.seqno, 2)

    def test_largest_supported_quorum_fits_one_transaction(self):
        keys = list(range(100, 164))
        cold = PqMultisig(keys, quorum=12)
        self.assertEqual(cold.get("get_checked_config"), (0, [64]))
        v = self.v
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        payload = out_list([(1, relaxed(v.address, COIN // 2, body))] * 16)
        messages = cold.submit(v, EXECUTE, payload, value=cold.quote(EXECUTE, 16))
        self.assertEqual(len(messages), 16)

    def test_seqno_exhaustion_fails_closed(self):
        cold = PqMultisig(data=multisig_data(SIGNERS, 2, seqno=(1 << 64) - 1))
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        cold.send_to_vault(self.v, body, expected=ERR["seqno_exhausted"], verifications=0)

    def test_deposits_and_bounces_change_nothing(self):
        v, cold = self.v, self.cold
        before = cold.data.hash
        for message in (
            internal(RELAYER, cold.address, Cell(), COIN),
            internal(RELAYER, cold.address, Cell().uint(0, 32).uint(0, 64), COIN),
            internal(RELAYER, cold.address, Cell().uint(SUBMIT_OP, 32), COIN, bounced=True),
        ):
            result = v.e.send(cold.shard, message)
            details = pqtest.details_of(result)
            self.assertEqual(details["exit"], 0, details)
            cold.shard = from_boc(result["shard_account"])
        self.assertEqual(cold.data.hash, before)

    def test_membership_rotation_authenticates_against_the_old_quorum(self):
        v, cold = self.v, self.cold
        add = Cell().uint(ADD, 8).ref(pqtest.stored(pqtest.public_key(24)))
        cold.submit(
            v, CONFIGURE, add, [(21, 21), (24, 24)], expected=ERR["unknown_signer"], verifications=0
        )
        cold.submit(v, CONFIGURE, add, [(21, 21), (22, 22)])
        self.assertEqual(cold.get("get_quorum"), (0, [4, 2]))
        self.assertEqual(
            cold.get("get_is_verifier", pqtest.key_id(pqtest.public_key(24))), (0, [-1])
        )
        remove = Cell().uint(REMOVE, 8).uint(pqtest.key_id(pqtest.public_key(21)), 256)
        cold.submit(v, CONFIGURE, remove, [(21, 21), (24, 24)])
        self.assertEqual(cold.get("get_quorum"), (0, [3, 2]))
        self.assertEqual(
            cold.get("get_is_verifier", pqtest.key_id(pqtest.public_key(21))), (0, [0])
        )
        body = envelope(SCHEDULE, self.admin(set_asset(0)))
        cold.send_to_vault(
            v, body, [(21, 21), (22, 22)], expected=ERR["unknown_signer"], verifications=0
        )
        cold.keys = [22, 23, 24]
        self.deliver(cold.send_to_vault(v, body, [(22, 22), (24, 24)]))
        cold.submit(v, CONFIGURE, Cell().uint(QUORUM, 8).uint(3, 8), [(22, 22), (23, 23)])
        cold.quorum = 3
        cold.submit(v, CONFIGURE, Cell().uint(QUORUM, 8).uint(4, 8), expected=ERR["invalid_config"])
        remove = Cell().uint(REMOVE, 8).uint(pqtest.key_id(pqtest.public_key(22)), 256)
        cold.submit(v, CONFIGURE, remove, expected=ERR["invalid_config"])
        self.assertEqual(cold.get("get_quorum"), (0, [3, 3]))

    # -- the vault's cold leg (#378) -------------------------------------------------------

    def test_quorum_schedules_and_the_vault_still_waits(self):
        v, cold = self.v, self.cold
        req = self.admin(set_asset(0, per=2 * COIN, window=3 * COIN, total=4 * COIN))
        messages = cold.send_to_vault(v, envelope(SCHEDULE, req))
        self.assertEqual(len(messages), 1)
        self.deliver(messages)
        self.assertIsNotNone(v.state["admin"])
        v.send(envelope(APPLY, req), expected=2418)
        self.deliver(cold.send_to_vault(v, envelope(APPLY, req)), expected=2418)
        v.advance(DELAY - 1)
        v.send(envelope(APPLY, req), expected=2418)
        v.advance(1)
        v.send(envelope(APPLY, req))
        self.assertEqual(v.budget()["per"], 2 * COIN)
        self.assertEqual(v.state["epoch"], 1)

    def test_quorum_veto_and_pause_are_accepted(self):
        v, cold = self.v, self.cold
        req = self.admin(set_asset(0))
        self.deliver(cold.send_to_vault(v, envelope(SCHEDULE, req)))
        self.deliver(cold.send_to_vault(v, v.ctl(VETO, admin=True)))
        self.assertIsNone(v.state["admin"])
        self.assertEqual(v.state["admin_nonce"], 1)
        self.deliver(cold.send_to_vault(v, v.ctl(PAUSE, admin=True)))
        self.assertTrue(v.state["paused"])

    def test_quorum_has_no_payment_path(self):
        v, cold = self.v, self.cold
        req = v.req()
        self.deliver(cold.send_to_vault(v, envelope(SUBMIT, req)), expected=2401)
        self.deliver_to(
            v, self.business.send(v, envelope(SUBMIT, req)), source=self.business.address
        )
        self.deliver(cold.send_to_vault(v, envelope(APPROVE, req)), expected=2401)
        self.assertEqual(v.budget()["cumulative"], 0)

    def test_full_post_quantum_lifecycle(self):
        cold, business, guardian = self.cold, self.business, self.guardian
        role_cell = roles(business.address, guardian.address, cold.address, PAUSER)
        v = Vault(records={}, role_cell=role_cell)
        self.addCleanup(v.close)
        req = v.req(set_asset(0), admin=True)
        self.deliver_to(v, cold.send_to_vault(v, envelope(SCHEDULE, req)))
        v.advance(DELAY)
        v.send(envelope(APPLY, req))
        self.assertEqual(v.state["count"], 1)
        pay = v.req()
        self.deliver_to(v, business.send(v, envelope(SUBMIT, pay)), source=business.address)
        payout = self.deliver_to(
            v, guardian.send(v, envelope(APPROVE, pay)), source=guardian.address
        )
        self.assertEqual(len(payout), 1)
        msg = decode_message(payout[0])
        self.assertEqual((msg["target"], msg["value"]), (TARGET, COIN))
        self.assertEqual(v.budget()["cumulative"], COIN)

    def deliver_to(self, vault, messages, source=None, expected=0):
        self.assertEqual(len(messages), 1)
        msg = decode_message(messages[0])
        self.assertEqual(msg["source"], self.cold.address if source is None else source)
        self.assertEqual(msg["target"], vault.address)
        return vault.send(message=messages[0], expected=expected)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    report = dict(
        source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        multisig_source_sha256=hashlib.sha256(MULTISIG_SOURCE.read_bytes()).hexdigest(),
        tests=result.testsRun,
        failures=len(result.failures),
        errors=len(result.errors),
        skipped=len(result.skipped),
        code_hash=test_native.CODE.hash.hex() if test_native.CODE is not None else None,
        multisig_code_hash=MULTISIG_CODE.hash.hex() if MULTISIG_CODE is not None else None,
        max_observed_gas=GAS,
    )
    path = os.environ.get("TREASURY_PQ_COLD_RESULTS")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if result.testsRun and result.wasSuccessful() and not result.skipped else 1)
