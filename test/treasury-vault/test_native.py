"""Treasury regressions using freshly compiled code and the native action phase.

Internal-message fixtures test the vault's authenticated-sender boundary. They
are not claims that a synthetic sender address can sign a production message.
The Token integration test also executes the actual source and recipient wallets.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))

from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from native import (  # noqa: E402
    GLOBAL_ID,
    NOW,
    Emulator,
    account_data,
    active_account,
    compile_contract,
    config,
    distinct_cells,
    external,
    internal,
    outgoing,
    state_init,
    uninitialized_account,
)
from wire import (  # noqa: E402
    APPLY,
    APPROVE,
    CANCEL_PAYMENT,
    COIN,
    DELAY,
    EXPIRE_ADMIN,
    EXPIRE_PAYMENT,
    MAX_COINS,
    MAX_COUNTER,
    PAUSE,
    PAYMENT_TTL,
    SCHEDULE,
    SUBMIT,
    TOKEN_TRANSFER,
    VETO,
    WINDOW,
    asset_record,
    control,
    decode_asset,
    decode_message,
    decode_state,
    envelope,
    payment,
    request,
    roles,
    set_asset,
    set_roles,
    state_data,
    unpause,
)

BUSINESS, GUARDIAN, COLD, PAUSER, OTHER, TARGET = [(0, x) for x in range(11, 17)]
SOURCE_WALLET, TOKEN_ID = (0, 101), 501
ROLE_CELL = roles(BUSINESS, GUARDIAN, COLD, PAUSER)
CODE = None
GAS = []
SOURCE = Path(os.environ.get("TREASURY_SOURCE", ROOT / "crypto/smartcont/treasury-vault-code.fc"))


def compile_fresh(source, output):
    try:
        return compile_contract(str(source), output)
    except subprocess.CalledProcessError as exc:
        diagnostic = (exc.stderr or b"").decode(errors="replace")
        raise RuntimeError(f"contract compilation failed: {exc.cmd}\n{diagnostic}") from exc


class Vault:
    def __init__(self, records=None, role_cell=ROLE_CELL, **state):
        if records is None:
            records = {0: asset_record(), TOKEN_ID: asset_record(SOURCE_WALLET, 100, 150, 200)}
        data = state_data(role_cell, records, **state)
        self.address = (0, int.from_bytes(state_init(CODE, data).hash, "big"))
        self.shard = active_account(self.address, CODE, data, balance=1000 * COIN)
        self.e, self.now = Emulator(), NOW

    def close(self):
        self.e.close()

    def advance(self, seconds):
        self.now += seconds
        self.e.lib.transaction_emulator_set_unixtime(self.e.ptr, self.now)

    @property
    def data(self):
        return account_data(self.shard)[0]

    @property
    def state(self):
        return decode_state(self.data)

    def budget(self, asset=0):
        return decode_asset(self.state["assets"][asset])

    def req(self, payload=None, *, admin=False, **overrides):
        state = self.state
        return request(
            overrides.get("vault", self.address),
            overrides.get("epoch", state["epoch"]),
            overrides.get("nonce", state["admin_nonce" if admin else "payment_nonce"]),
            overrides.get("deadline", self.now + (DELAY + 3600 if admin else 600)),
            payload if payload is not None else payment(0, COIN, TARGET),
            network=overrides.get("network", GLOBAL_ID),
            admin=admin,
        )

    def ctl(self, op, admin=False):
        state = self.state
        return control(op, state["epoch"], state["admin_nonce" if admin else "payment_nonce"])

    def send(
        self,
        body,
        sender=OTHER,
        *,
        expected=0,
        value=COIN // 2,
        bounced=False,
        action_failure=False,
    ):
        before = self.data.hash
        result = self.e.send(self.shard, internal(sender, self.address, body, value, bounced))
        assert result["success"], result
        details = result["details"]
        self.shard = from_boc(result["shard_account"])
        assert details["exit"] == expected, (
            f"expected VM exit {expected}, got {details}\n{result.get('vm_log', '')[-6000:]}"
        )
        GAS.append(details.get("gas", 0))
        messages = outgoing(from_boc(result["transaction"]))
        if expected:
            assert self.data.hash == before, "rejection changed contract state"
            assert not messages, "rejection emitted an outgoing message"
        elif action_failure:
            assert details["aborted"] and details["action"] is not None, details
            assert not details["action"]["success"], details
            assert self.data.hash == before, "failed action committed accounting"
            assert not messages, "failed action dispatched value"
        else:
            assert not details["aborted"], details
            assert details["action"] is None or details["action"]["success"], details
        return messages

    def propose(self, payload=None, **overrides):
        req = self.req(payload, **overrides)
        assert not self.send(envelope(SUBMIT, req), BUSINESS)
        return req

    def pay(self, payload=None):
        req = self.propose(payload)
        return self.send(envelope(APPROVE, req), GUARDIAN)

    def queue(self, payload, sender=COLD):
        req = self.req(payload, admin=True)
        assert not self.send(envelope(SCHEDULE, req), sender)
        return req

    def govern(self, payload, sender=COLD):
        req = self.queue(payload, sender)
        self.advance(DELAY)
        assert not self.send(envelope(APPLY, req))


class TreasuryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CODE
        for key in ("FUNC_PATH", "FIFT_PATH", "EMULATOR_PATH"):
            if not os.environ.get(key):
                raise RuntimeError(f"{key} is required; native tests cannot be skipped")
        cls.tmp = tempfile.TemporaryDirectory(prefix="treasury-native-")
        CODE = compile_fresh(SOURCE, Path(cls.tmp.name) / "treasury.boc")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def vault(self, *args, **kwargs):
        v = Vault(*args, **kwargs)
        self.addCleanup(v.close)
        return v

    def test_native_payment_requires_both_roles(self):
        v = self.vault()
        req = v.propose()
        self.assertEqual(v.budget()["cumulative"], 0)
        result = v.send(envelope(APPROVE, req), GUARDIAN)
        self.assertEqual(len(result), 1)
        msg = decode_message(result[0])
        self.assertEqual((msg["source"], msg["target"], msg["value"]), (v.address, TARGET, COIN))
        self.assertFalse(msg["body"].bits or msg["body"].refs)
        self.assertEqual(v.budget()["cumulative"], COIN)
        self.assertIsNone(v.state["payment"])
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2410)

    def test_required_guardian(self):
        v = self.vault()
        req = v.propose()
        for sender in (BUSINESS, COLD, PAUSER, OTHER):
            v.send(envelope(APPROVE, req), sender, expected=2401)
        self.assertEqual(v.budget()["cumulative"], 0)

    def test_guardian_cannot_propose_or_pay_alone(self):
        v = self.vault()
        req = v.req()
        v.send(envelope(SUBMIT, req), GUARDIAN, expected=2401)
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2406)
        v.send(envelope(SUBMIT, req), OTHER, expected=2401)

    def test_approval_commits_exact_request(self):
        v = self.vault()
        v.propose()
        for payload in (payment(0, 2 * COIN, TARGET), payment(0, COIN, OTHER)):
            v.send(envelope(APPROVE, v.req(payload)), GUARDIAN, expected=2407)

    def test_request_nonce(self):
        v = self.vault()
        v.send(envelope(SUBMIT, v.req(nonce=7)), BUSINESS, expected=2410)

    def test_domain_account_network_epoch_and_expiry(self):
        cases = [
            ({"vault": OTHER}, 2402),
            ({"network": GLOBAL_ID + 1}, 2408),
            ({"epoch": 7}, 2409),
            ({"deadline": NOW}, 2411),
            ({"deadline": NOW + PAYMENT_TTL + 1}, 2411),
        ]
        for fields, expected in cases:
            with self.subTest(fields=fields):
                v = self.vault()
                v.send(envelope(SUBMIT, v.req(**fields)), BUSINESS, expected=expected)
        v = self.vault()
        v.send(envelope(SUBMIT, v.req(admin=True)), BUSINESS, expected=2412)

    def test_trailing_data_and_unknown_operations(self):
        v = self.vault()
        malformed = envelope(SUBMIT, v.req()).uint(1, 1)
        v.send(malformed, BUSINESS, expected=9)
        v.send(envelope(SUBMIT, v.req(payment(0, COIN, TARGET).uint(1, 1))), BUSINESS, expected=9)
        v.send(Cell().uint(0xDEADBEEF, 32).uint(0, 64), COLD, expected=2400)

    def test_external_messages_are_never_accepted(self):
        v = self.vault()
        before = v.data.hash
        result = v.e.send(v.shard, external(v.address, envelope(SUBMIT, v.req())))
        self.assertFalse(result["success"], result)
        self.assertEqual(result.get("vm_exit_code"), 2400)
        self.assertEqual(v.data.hash, before)

    def test_pending_payment_is_bounded(self):
        v = self.vault()
        first = v.propose()
        v.send(envelope(SUBMIT, v.req(payment(0, 2 * COIN, TARGET))), BUSINESS, expected=2405)
        self.assertEqual(v.state["payment"].hash, first.hash)

    def test_payment_cancel_and_expiry_consume_nonce(self):
        v = self.vault()
        old = v.propose()
        v.send(v.ctl(CANCEL_PAYMENT), OTHER, expected=2401)
        v.send(v.ctl(CANCEL_PAYMENT), BUSINESS)
        v.send(envelope(SUBMIT, old), BUSINESS, expected=2410)
        current = v.propose()
        v.send(v.ctl(EXPIRE_PAYMENT), expected=2411)
        v.advance(600)
        v.send(envelope(APPROVE, current), GUARDIAN, expected=2411)
        v.send(v.ctl(EXPIRE_PAYMENT))
        self.assertEqual(v.state["payment_nonce"], 2)

    def test_per_payment_limit(self):
        v = self.vault()
        req = v.propose(payment(0, 5 * COIN + 1, TARGET))
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2415)

    def test_split_payments_hit_window_limit(self):
        v = self.vault()
        v.pay(payment(0, 4 * COIN, TARGET))
        req = v.propose(payment(0, 3 * COIN, TARGET))
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2416)
        self.assertEqual(v.budget()["cumulative"], 4 * COIN)

    def test_window_refresh_does_not_refresh_total(self):
        v = self.vault()
        v.pay(payment(0, 4 * COIN, TARGET))
        v.advance(WINDOW)
        v.pay(payment(0, 4 * COIN, TARGET))
        v.advance(WINDOW)
        req = v.propose(payment(0, 3 * COIN, TARGET))
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2417)
        self.assertEqual(v.budget()["cumulative"], 8 * COIN)

    def test_fixed_window_boundary_is_explicit(self):
        v = self.vault(records={0: asset_record(per=3 * COIN, window=6 * COIN, total=20 * COIN)})
        v.pay(payment(0, 3 * COIN, TARGET))
        v.advance(WINDOW - 1)
        v.pay(payment(0, 3 * COIN, TARGET))
        v.advance(1)
        v.pay(payment(0, 3 * COIN, TARGET))
        self.assertEqual(v.budget()["spent"], 3 * COIN)
        self.assertEqual(v.budget()["cumulative"], 9 * COIN)

    def test_token_amount_not_native_attachment_is_budgeted(self):
        v = self.vault()
        req = v.propose(payment(TOKEN_ID, 101, TARGET, COIN // 100))
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2415)
        self.assertEqual(v.budget(TOKEN_ID)["cumulative"], 0)

    def test_token_wire_and_independent_asset_accounting(self):
        v = self.vault()
        result = v.pay(payment(TOKEN_ID, 99, TARGET, COIN // 100))
        self.assertEqual(len(result), 1)
        msg = decode_message(result[0])
        self.assertEqual((msg["target"], msg["value"]), (SOURCE_WALLET, COIN // 100))
        s = msg["body"].slice()
        self.assertEqual((s.uint(32), s.uint(64), s.coins()), (TOKEN_TRANSFER, 0, 99))
        self.assertEqual(
            (s.addr(), s.addr(), s.uint(1), s.coins(), s.uint(1)), (TARGET, v.address, 0, 0, 0)
        )
        s.end()
        self.assertEqual(v.budget()["cumulative"], 0)
        self.assertEqual(v.budget(TOKEN_ID)["cumulative"], 99)
        v.pay()
        self.assertEqual(v.budget(TOKEN_ID)["cumulative"], 99)

    def test_receipts_bounces_and_comments_never_release_budget(self):
        v = self.vault()
        v.pay(payment(TOKEN_ID, 99, TARGET, COIN // 100))
        before = v.data.hash
        for op in (0, 0x7362D09C, 0xD53276DB):
            v.send(Cell().uint(op, 32).uint(0, 64), SOURCE_WALLET)
        v.send(Cell().uint(0xFFFFFFFF, 32), SOURCE_WALLET, bounced=True)
        self.assertEqual(v.data.hash, before)
        self.assertEqual(v.budget(TOKEN_ID)["cumulative"], 99)

    def test_disabled_or_unregistered_asset_cannot_pay(self):
        for records, asset in [({0: asset_record(enabled=False)}, 0), ({}, 0)]:
            v = self.vault(records=records)
            req = v.propose(payment(asset, COIN, TARGET))
            v.send(envelope(APPROVE, req), GUARDIAN, expected=2413)

    def test_only_cold_authority_schedules_management(self):
        v = self.vault()
        req = v.req(set_asset(0), admin=True)
        for sender in (BUSINESS, GUARDIAN, PAUSER, OTHER):
            v.send(envelope(SCHEDULE, req), sender, expected=2401)

    def test_management_timelock(self):
        v = self.vault()
        req = v.queue(set_asset(0))
        v.send(envelope(APPLY, req), expected=2418)
        v.advance(DELAY - 1)
        v.send(envelope(APPLY, req), expected=2418)
        v.advance(1)
        v.send(envelope(APPLY, req))
        self.assertIsNone(v.state["admin"])
        self.assertEqual(v.state["epoch"], 1)

    def test_pending_management_is_bounded_and_exact(self):
        v = self.vault()
        req = v.queue(set_asset(0))
        other = v.req(set_asset(0, per=COIN), admin=True)
        v.send(envelope(SCHEDULE, other), COLD, expected=2405)
        v.advance(DELAY)
        v.send(envelope(APPLY, other), expected=2407)
        v.send(envelope(APPLY, req))

    def test_management_veto_and_expiry(self):
        v = self.vault()
        req = v.queue(set_asset(0))
        v.send(v.ctl(VETO, admin=True), BUSINESS, expected=2401)
        v.send(v.ctl(VETO, admin=True), PAUSER)
        v.advance(DELAY)
        v.send(envelope(APPLY, req), expected=2410)
        req = v.queue(set_asset(0))
        v.send(v.ctl(EXPIRE_ADMIN, admin=True), expected=2411)
        v.advance(DELAY + 3600)
        v.send(v.ctl(EXPIRE_ADMIN, admin=True))
        self.assertEqual(v.state["admin_nonce"], 2)

    def test_role_change_invalidates_live_payment(self):
        v = self.vault()
        changed = roles((0, 31), (0, 32), (0, 33), (0, 34))
        gov = v.queue(set_roles(changed))
        v.advance(DELAY - 1)
        old = v.propose()
        v.advance(1)
        v.send(envelope(APPLY, gov))
        self.assertIsNone(v.state["payment"])
        v.send(envelope(APPROVE, old), (0, 32), expected=2409)
        v.send(envelope(SUBMIT, v.req()), BUSINESS, expected=2401)

    def test_policy_change_preserves_cumulative_spend(self):
        v = self.vault()
        v.pay(payment(0, 4 * COIN, TARGET))
        v.govern(set_asset(0))
        self.assertEqual(v.budget()["cumulative"], 4 * COIN)
        v.pay(payment(0, 5 * COIN, TARGET))
        v.advance(WINDOW)
        req = v.propose(payment(0, 2 * COIN, TARGET))
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2417)

    def test_registration_uses_delayed_governance(self):
        v = self.vault(records={})
        self.assertEqual(v.state["count"], 0)
        v.govern(set_asset(0))
        self.assertEqual(v.state["count"], 1)
        self.assertEqual(len(v.pay()), 1)

    def test_source_wallet_binding_and_aliases(self):
        v = self.vault()
        for payload in (
            set_asset(TOKEN_ID, (0, 999), 100, 150, 200),
            set_asset(TOKEN_ID + 1, SOURCE_WALLET, 100, 150, 200),
        ):
            v.send(envelope(SCHEDULE, v.req(payload, admin=True)), COLD, expected=2413)

    def test_role_aliases_fail_on_chain(self):
        v = self.vault()
        bad = Cell().ref(Cell().addr(BUSINESS).addr(BUSINESS)).ref(Cell().addr(COLD).addr(PAUSER))
        v.send(envelope(SCHEDULE, v.req(set_roles(bad), admin=True)), COLD, expected=2403)

    def test_pause_invalidates_both_pending_requests(self):
        v = self.vault()
        pay = v.propose()
        gov = v.queue(set_asset(0))
        v.send(v.ctl(PAUSE, admin=True), BUSINESS, expected=2401)
        v.send(v.ctl(PAUSE, admin=True), PAUSER)
        self.assertTrue(v.state["paused"])
        self.assertIsNone(v.state["payment"])
        self.assertIsNone(v.state["admin"])
        v.send(envelope(APPROVE, pay), GUARDIAN, expected=2404)
        v.advance(DELAY)
        v.send(envelope(APPLY, gov), expected=2409)

    def test_recovery_and_unpause_require_separate_delays(self):
        v = self.vault()
        v.send(v.ctl(PAUSE, admin=True), GUARDIAN)
        new_business, new_guardian, new_cold, new_pauser = [(0, x) for x in range(31, 35)]
        v.govern(set_roles(roles(new_business, new_guardian, new_cold, new_pauser)))
        self.assertTrue(v.state["paused"])
        req = v.req(unpause(), admin=True)
        v.send(envelope(SCHEDULE, req), COLD, expected=2401)
        v.send(envelope(SCHEDULE, req), new_cold)
        v.send(envelope(APPLY, req), expected=2418)
        v.advance(DELAY)
        v.send(envelope(APPLY, req))
        self.assertFalse(v.state["paused"])
        req = v.req()
        v.send(envelope(SUBMIT, req), new_business)
        self.assertEqual(len(v.send(envelope(APPROVE, req), new_guardian)), 1)

    def test_registry_and_state_are_bounded(self):
        records = {0: asset_record()}
        records.update({i: asset_record((0, 1000 + i)) for i in range(1, 16)})
        v = self.vault(records=records)
        payload = set_asset(16, (0, 1016))
        v.send(envelope(SCHEDULE, v.req(payload, admin=True)), COLD, expected=2422)
        v.propose()
        v.queue(set_asset(0))
        self.assertLessEqual(distinct_cells(v.data), 80)
        self.assertEqual(v.state["count"], 16)

    def test_counter_and_coin_overflow_fail_closed(self):
        v = self.vault(payment_nonce=MAX_COUNTER)
        v.send(envelope(SUBMIT, v.req()), BUSINESS, expected=2420)
        v = self.vault(records={0: asset_record(total=MAX_COINS, cumulative=MAX_COINS)})
        req = v.propose(payment(0, 1, TARGET))
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2420)
        v = self.vault(epoch=MAX_COUNTER)
        v.send(v.ctl(PAUSE, admin=True), PAUSER, expected=2420)

    def test_funding_and_storage_reserve(self):
        v = self.vault()
        # Fund compute while staying below the 0.1 TOS control-message minimum.
        # One nanotoken skips compute and never reaches the contract's guard.
        v.send(envelope(SUBMIT, v.req()), BUSINESS, expected=2421, value=COIN // 20)
        # A funded guardian message must not turn the inbound fee contribution
        # into unbudgeted principal available to this payment.
        v = self.vault(
            records={0: asset_record(per=1000 * COIN, window=1000 * COIN, total=1000 * COIN)}
        )
        req = v.propose(payment(0, 1000 * COIN, TARGET))
        v.send(envelope(APPROVE, req), GUARDIAN, expected=2421)

    def test_action_failure_rolls_back_accounting(self):
        v = self.vault()
        req = v.propose()
        entries = read_dict(config(), 32)
        # Deterministically make an outgoing message cost more than the funded
        # fee contribution. Principal must remain reserved, not pay that fee.
        entries[25] = Cell().ref(
            Cell()
            .uint(0xEA, 8)
            .uint(2 * COIN, 64)
            .uint(0, 64)
            .uint(0, 64)
            .uint(0, 32)
            .uint(21845, 16)
            .uint(21845, 16)
        )
        v.e.close()
        v.e = Emulator.from_config(make_dict(entries, 32))
        v.send(envelope(APPROVE, req), GUARDIAN, action_failure=True)
        self.assertEqual(v.budget()["cumulative"], 0)
        self.assertIsNotNone(v.state["payment"])

    def test_real_token_wallet_transfer(self):
        if not os.environ.get("TOL_PATH"):
            self.fail("TOL_PATH required for real Token integration; do not skip")
        token_code = compile_fresh("token-wallet.tol", Path(self.tmp.name) / "token.boc")
        v = self.vault(records={})
        master = (0, 9001)

        def data(owner, balance=0):
            return Cell().coins(balance).addr(owner).addr(master).ref(token_code)

        source = (0, int.from_bytes(state_init(token_code, data(v.address)).hash, "big"))
        recipient_wallet = (0, int.from_bytes(state_init(token_code, data(TARGET)).hash, "big"))
        v.govern(set_asset(master[1], source, 100, 150, 200))
        req = v.propose(payment(master[1], 50, TARGET, COIN // 2))
        dispatched = v.send(envelope(APPROVE, req), GUARDIAN, value=COIN)
        self.assertEqual(len(dispatched), 1)
        source_account = active_account(source, token_code, data(v.address, 1000))
        result = v.e.send(source_account, dispatched[0])
        self.assertTrue(result["success"], result)
        self.assertFalse(result["details"]["aborted"], result["details"])
        self.assertEqual(account_data(from_boc(result["shard_account"]))[0].slice().coins(), 950)
        delivered = [
            m
            for m in outgoing(from_boc(result["transaction"]))
            if decode_message(m)["target"] == recipient_wallet
        ]
        self.assertEqual(len(delivered), 1)
        recipient = uninitialized_account(recipient_wallet, balance=0)
        result = v.e.send(recipient, delivered[0])
        self.assertTrue(result["success"], result)
        self.assertFalse(result["details"]["aborted"], result["details"])
        self.assertEqual(account_data(from_boc(result["shard_account"]))[0].slice().coins(), 50)
        self.assertEqual(v.budget(master[1])["cumulative"], 50)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    report = dict(
        source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        tests=result.testsRun,
        failures=len(result.failures),
        errors=len(result.errors),
        skipped=len(result.skipped),
        max_observed_gas=max(GAS, default=0),
        code_hash=CODE.hash.hex() if CODE is not None else None,
    )
    path = os.environ.get("TREASURY_RESULTS")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if result.testsRun and result.wasSuccessful() and not result.skipped else 1)
