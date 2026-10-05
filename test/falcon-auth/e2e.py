#!/usr/bin/env python3
"""Actual v19 transactions: paid relayer -> Falcon module -> existing account.

No fabricated module sender, no replacement VM, no signature-ignore switch.
Normal cases change only the test config version; gas limits/prices
are left intact. One explicitly labeled destination-limit failure injection
exercises account commit semantics, not production calibration.
Public deterministic keys are TEST ONLY.
"""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import argparse
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))

import test_auth as framework
from build_contracts import build_contracts
from native import (
    GLOBAL_ID,
    NOW,
    Emulator,
    account_data,
    active_account,
    external,
    internal,
    outgoing,
    state_init,
)
from protocol import (
    CONTEXT,
    SUBMIT,
    Cell,
    Signer,
    chain,
    clone,
    commitment,
    emulator_library,
    from_boc,
    module_data,
    parse_message,
    signing_message,
    submission,
)

CODES = framework.CODES
MODULE_CODES = {}
SIGNER = None
OLD_SIGNER = None
ARTIFACTS = None
MODULE_FILTER = None
EVENTS = []
TOTALS = []
TRANSACTIONS = []
FUNDING = 10_000_000_000
BALANCE = 100_000_000_000


def require_result(result, expected, before, shard, label, commits=False):
    details = result.get("details", result)
    actual = details.get("exit", result.get("vm_exit_code"))
    log = result.get("vm_log", "")[-5000:]
    if expected == "failure":
        assert result["success"], (
            f"{label}: expected a real rejected transaction, not an emulator error"
        )
        assert actual != 0 and not details.get("compute_success", False), f"{label}: {details}"
    else:
        assert actual == expected, f"{label}: expected {expected}, got {details}\n{log}"
    after = account_data(shard)[0].hash
    if expected != 0 and not commits:
        assert before == after, f"{label}: rejected transaction changed persistent data"
    if expected != 0 and commits:
        assert before != after, f"{label}: committed refusal must consume account counters"
    if expected == 0:
        assert result["success"] and not details["aborted"], f"{label}: {details}"
        assert details["action"] is None or details["action"]["success"], f"{label}: {details}"
    return details


def capture_transaction(name, prior, message, lt, result, now=NOW):
    import tx_parity

    name = str(len(TRANSACTIONS)) + ":" + name
    tx_parity.outgoing = outgoing
    after = from_boc(result["shard_account"])
    row = tx_parity.transcript(
        name, result["details"], from_boc(result["transaction"]), after.refs[0]
    )
    TRANSACTIONS.append((name, prior.refs[0], message, lt, now, row))


def record(label, phase, result, shard):
    details = result.get("details", {})
    messages = outgoing(from_boc(result["transaction"])) if result["success"] else []
    EVENTS.append(
        {
            "case": label,
            "phase": phase,
            "exit": details.get("exit", result.get("vm_exit_code")),
            "gas": details.get("gas"),
            "aborted": details.get("aborted"),
            "action": details.get("action"),
            "data_hash": account_data(shard)[0].hash.hex(),
            "outgoing_hashes": [message.hash.hex() for message in messages],
        }
    )


class Module:
    def __init__(self, language, workchain=-1, key=0, version=16, profile=1, network=GLOBAL_ID):
        self.language, self.workchain, self.key = language, workchain, key
        self.version = version
        self.code = MODULE_CODES[language]
        self.data = module_data(SIGNER.public_key(key), network, profile)
        self.address = (workchain, int.from_bytes(state_init(self.code, self.data).hash, "big"))
        self.shard = active_account(self.address, self.code, self.data, BALANCE)
        self.e = Emulator(version)

    def close(self):
        self.e.close()

    def set_version(self, version):
        self.version = version
        last_lt = self.e.lt
        self.e.close()
        self.e = Emulator(version)
        self.e.lt = last_lt

    def signed(self, account, request=None, co=None, key=None, context=CONTEXT):
        request = request if request is not None else account.request()
        envelope = account.envelope(request, co)
        _, signature = SIGNER.sign(
            signing_message(self.address, commitment(request)),
            context,
            self.key if key is None else key,
        )
        return submission(envelope, signature)

    def call(self, body, expected=0, value=FUNDING, label="", bounced=False, ext=False):
        before = account_data(self.shard)[0].hash
        msg = (
            external(self.address, body)
            if ext
            else internal((self.workchain, 17), self.address, body, value, bounced)
        )
        prior = self.shard
        result = self.e.send(self.shard, msg)
        if result["success"] and not ext and self.version >= 16:
            capture_transaction(label + "/module", prior, msg, self.e.lt, result)
        if result["success"]:
            self.shard = from_boc(result["shard_account"])
        require_result(result, expected, before, self.shard, label)
        assert account_data(self.shard)[0].hash == self.data.hash, "module must remain immutable"
        record(label, "module", result, self.shard)
        messages = outgoing(from_boc(result["transaction"])) if result["success"] else []
        if expected != 0:
            assert not messages, "non-bouncing rejection must not emit AUTH or spend reserve"
        return result, messages


class Pair:
    def __init__(self, language, impl, workchain=-1, mode=2, root=None):
        self.module = root if root is not None else Module(language, workchain)
        self.account = framework.Account(impl, mode=mode, module=self.module.address)
        a = self.account
        data = a.data
        a.e.close()
        a.e = Emulator(16)
        a.address = (workchain, int.from_bytes(state_init(CODES[impl], data).hash, "big"))
        a.shard = active_account(a.address, CODES[impl], data, BALANCE)
        self.label = f"{language}/{impl}/wc{workchain}"
        self.limit_injection = False
        self.now = NOW

    def close(self):
        self.module.close()
        self.account.close()

    def deliver(self, message, expected=0, label="", envelope=None, commits=False):
        a = self.account
        wire = parse_message(message)
        assert wire["destination"] == a.address
        assert wire["sender"] == self.module.address, "VM must supply the actual module source"
        assert not wire["bounced"] and wire["bounce"] == 1
        assert 0 < wire["value"] < FUNDING
        if envelope is not None:
            assert wire["body"].hash == envelope.hash, "relay must preserve the exact AUTH body"
        before = a.data.hash
        # Each instance must execute after the actual emitted message's LT.
        a.e.lt = max(a.e.lt, wire["created_lt"])
        # CRITICAL: deliver the exact message returned by the module action phase.
        prior = a.shard
        result = a.e.send(a.shard, message)
        if result["success"] and not self.limit_injection:
            capture_transaction(label + "/account", prior, message, a.e.lt, result, self.now)
        if result["success"]:
            a.shard = from_boc(result["shard_account"])
        details = require_result(result, expected, before, a.shard, label, commits=commits)
        record(label, "account", result, a.shard)
        if expected:
            for out in outgoing(from_boc(result["transaction"])):
                assert parse_message(out)["bounced"], (
                    "rejection may bounce, but must not transfer assets"
                )
        return result, details

    def execute(self, body, account_exit=0, label="", commits=False):
        module_before = account_data(self.module.shard)[1]
        mr, messages = self.module.call(body, label=label)
        assert len(messages) == 1, "successful module must emit exactly one message"
        assert account_data(self.module.shard)[1] >= module_before, (
            "relay spent pre-existing reserve"
        )
        ar, ad = self.deliver(messages[0], account_exit, label, body.refs[0], commits=commits)
        TOTALS.append(
            {
                "case": label,
                "module_gas": mr["details"]["gas"],
                "account_gas": ad["gas"],
                "total_compute_gas": mr["details"]["gas"] + ad["gas"],
                "relay_value": parse_message(messages[0])["value"],
                "funding": FUNDING,
                "account_exit": account_exit,
                "limit_injection": self.limit_injection,
            }
        )
        return mr, ar, messages[0]


class FalconAuthTests(unittest.TestCase):
    def pairs(self, mode=2, workchains=(-1, 0)):
        for language in MODULE_CODES:
            if MODULE_FILTER and MODULE_FILTER != language:
                continue
            for impl in CODES:
                for wc in workchains:
                    p = Pair(language, impl, wc, mode)
                    self.addCleanup(p.close)
                    yield p

    def label(self, pair, suffix=""):
        return f"{self._testMethodName}/{pair.label}/{suffix}"

    def assert_transfer(self, pair, result):
        messages = outgoing(from_boc(result["transaction"]))
        self.assertEqual(len(messages), 1)
        transfer = parse_message(messages[0])
        self.assertEqual(transfer["sender"], pair.account.address)
        self.assertEqual(transfer["destination"], framework.TARGET)
        self.assertEqual(transfer["value"], 1_000_000_000)
        self.assertFalse(transfer["bounced"])

    def test_funded_pq_from_genesis_and_wrong_state_init(self):
        # Exercise the SDK's actual funded StateInit wire from an absent account,
        # rather than injecting an already-active shard account as a substitute.
        sys.path.insert(0, str(ROOT / "test/tostester/src"))
        from contract.pq_auth import transfer_message
        from pytosiq_core import Address, StateInit
        from pytosiq_core import Cell as SdkCell

        def deployment(address, code, data):
            init = StateInit(
                code=SdkCell.one_from_boc(code.boc()), data=SdkCell.one_from_boc(data.boc())
            )
            wire = transfer_message(
                Address((address[0], (17).to_bytes(32, "big"))),
                Address((address[0], address[1].to_bytes(32, "big"))),
                BALANCE,
                init=init,
                bounce=False,
            )
            return from_boc(wire.serialize().to_boc())

        empty = Cell().uint(0, 256).uint(0, 64).ref(Cell().uint(0, 1))
        for mode in (2, 3):
            for p in self.pairs(mode=mode):
                a, m = p.account, p.module
                original = a.data
                # A different classical/legacy StateInit cannot activate the
                # address whose genesis committed to strict authorization.
                legacy = framework.Account(a.impl)
                self.addCleanup(legacy.close)
                wrong = deployment(a.address, CODES[a.impl], legacy.data)
                rejected = a.e.send(empty, wrong)
                self.assertTrue(rejected["success"])
                self.assertTrue(rejected["details"]["skipped"])
                self.assertNotIn("gas", rejected["details"])
                for owner, code, data, label in [
                    (m, m.code, m.data, "module"),
                    (a, CODES[a.impl], original, "account"),
                ]:
                    message = deployment(owner.address, code, data)
                    result = owner.e.send(empty, message)
                    self.assertTrue(result["success"], str(result))
                    self.assertEqual(result["details"]["exit"], 0)
                    owner.shard = from_boc(result["shard_account"])
                    self.assertEqual(account_data(owner.shard)[0].hash, data.hash)
                    capture_transaction(
                        self.label(p, f"genesis-{mode}-{label}"), empty, message, owner.e.lt, result
                    )
                self.assertEqual(a.auth(), (mode, 1, 0, m.address[1]))
                req = a.request()
                body = m.signed(a, req, a.cosign(req) if mode == 3 else None)
                _, result, _ = p.execute(body, label=self.label(p, f"genesis-{mode}-execute"))
                self.assert_transfer(p, result)
                self.assertEqual(a.auth()[2], 1)

    def test_valid_signature_and_exact_relay_then_account_replay(self):
        for p in self.pairs():
            a = p.account
            body = p.module.signed(a)
            _, result, _ = p.execute(body, label=self.label(p, "accepted"))
            self.assert_transfer(p, result)
            self.assertEqual(a.auth()[2], 1)
            self.assertEqual(a.counters()[1], 1)
            if a.agent:
                self.assertEqual(a.counters()[2], 1_000_000_000)
            p.execute(body, 1804, self.label(p, "replay"))
            self.assertEqual(a.auth()[2], 1)
            self.assertEqual(a.counters()[1], 1)

    def test_bad_pq_signatures_keys_context_and_encoding(self):
        for p in self.pairs():
            a, m = p.account, p.module
            req = a.request()
            good = m.signed(a, req)
            self.assertEqual(len(SIGNER.public_key()), 897)
            _, sig = SIGNER.sign(signing_message(m.address, commitment(req)))
            damaged = bytearray(sig)
            damaged[len(sig) // 2] ^= 1
            cases = [
                ("bad-signature", submission(a.envelope(req), bytes(damaged)), 1808),
                ("wrong-key", m.signed(a, req, key=1), 1808),
                ("wrong-context", m.signed(a, req, context=b"wrong-context"), 1808),
                (
                    "empty-signature",
                    Cell().uint(SUBMIT, 32).uint(0, 64).ref(a.envelope(req)).ref(Cell()),
                    9,
                ),
                (
                    "noncanonical-chain",
                    Cell()
                    .uint(SUBMIT, 32)
                    .uint(0, 64)
                    .ref(a.envelope(req))
                    .ref(Cell().raw(sig[:126]).ref(chain(sig[126:]))),
                    9,
                ),
                ("trailing-body-bit", Cell(good.bits + "0", good.refs), 9),
            ]
            for name, body, expected in cases:
                m.call(body, expected, label=self.label(p, name))
                self.assertEqual(a.auth()[2], 0)
            p.execute(good, label=self.label(p, "positive-control"))

    def test_every_request_field_and_payload_are_authenticated(self):
        for p in self.pairs():
            a, m = p.account, p.module
            request = a.request()
            _, sig = SIGNER.sign(signing_message(m.address, commitment(request)))
            changed_payload = clone(a.execute_payload())
            changed_payload.bits = changed_payload.bits[:-1] + (
                "0" if changed_payload.bits[-1] == "1" else "1"
            )
            cases = [
                ("account", a.request(account=(m.workchain, 99)), 1808),
                ("epoch", a.request(epoch=2), 1808),
                ("nonce", a.request(nonce=1), 1808),
                ("expiry", a.request(valid_until=NOW + 601), 1808),
                ("kind", a.request(kind=2), 1808),
                ("payload", a.request(payload=changed_payload), 1808),
                ("network", a.request(global_id=GLOBAL_ID + 1), 1801),
            ]
            # These proofs are cryptographically valid for the wrong network.
            # Removing a network guard must reach forwarding, rather than merely
            # changing which signature-format check rejects the request.
            wrong_request = a.request(global_id=GLOBAL_ID + 1)
            m.call(m.signed(a, wrong_request), 1801, label=self.label(p, "signed-wrong-network"))
            wrong_module = Module(m.language, m.workchain, network=GLOBAL_ID + 1)
            self.addCleanup(wrong_module.close)
            wrong_module.call(
                wrong_module.signed(a, wrong_request),
                1801,
                label=self.label(p, "wrong-chain-module"),
            )
            for name, changed, error in cases:
                m.call(submission(a.envelope(changed), sig), error, label=self.label(p, name))
            p.execute(m.signed(a), label=self.label(p, "positive-control"))

    def test_signed_stale_epoch_nonce_and_expiry(self):
        for p in self.pairs():
            a, m = p.account, p.module
            for field, value, error in [("epoch", 0, 1803), ("nonce", 1, 1804)]:
                p.execute(m.signed(a, a.request(**{field: value})), error, self.label(p, field))
                self.assertEqual(a.auth()[2], 0)
            for target in (m.address, (0 if m.workchain == -1 else -1, 99)):
                m.call(
                    m.signed(a, a.request(account=target)),
                    1809,
                    label=self.label(p, "invalid-target-" + str(target[0])),
                )
            for until in (NOW, NOW + 3601):
                m.call(
                    m.signed(a, a.request(valid_until=until)), 1805, label=self.label(p, str(until))
                )
            body = m.signed(a)
            _, messages = m.call(body, label=self.label(p, "before-expiry"))
            self.assertEqual(len(messages), 1)
            a.e.lib.transaction_emulator_set_unixtime(a.e.ptr, NOW + 601)
            p.now = NOW + 601
            p.deliver(messages[0], 1805, self.label(p, "expired-in-transit"))
            self.assertEqual(a.auth()[2], 0)

    def test_hybrid_requires_both_signatures_on_the_same_request(self):
        for p in self.pairs(mode=3):
            a, m = p.account, p.module
            req = a.request()
            for name, co in [
                ("missing", None),
                ("wrong-key", a.cosign(req, framework.OTHER_SECRET)),
                ("mixed-request", a.cosign(a.request(valid_until=NOW + 601))),
            ]:
                p.execute(m.signed(a, req, co), 1808, self.label(p, name))
                self.assertEqual(a.auth()[2], 0)
            m.call(
                m.signed(a, req, a.cosign(req), key=1), 1808, label=self.label(p, "valid-ed-bad-pq")
            )
            a.send(a.legacy_body(), ext=True, expected=1807)
            _, result, _ = p.execute(
                m.signed(a, req, a.cosign(req)), label=self.label(p, "both-valid")
            )
            self.assert_transfer(p, result)
            self.assertEqual(a.auth()[2], 1)

    def test_authenticated_rotation_and_no_classical_downgrade(self):
        for p in self.pairs():
            a, old = p.account, p.module
            new = Module(old.language, old.workchain, key=1)
            self.addCleanup(new.close)
            stale = a.request()
            cfg = a.request(1, Cell().uint(2, 2).addr(new.address))
            p.execute(old.signed(a, cfg), label=self.label(p, "rotate"))
            self.assertEqual(a.auth(), (2, 2, 0, new.address[1]))
            p.execute(old.signed(a, stale), 1800, self.label(p, "old-module"))
            self.addCleanup(old.close)
            p.module = new
            p.execute(new.signed(a, stale), 1803, self.label(p, "old-epoch-new-module"))
            downgrade = a.request(1, Cell().uint(1, 2).addr(new.address))
            p.execute(new.signed(a, downgrade), 1806, self.label(p, "downgrade"))
            new.call(new.signed(a, key=0), 1808, label=self.label(p, "old-key"))
            _, result, _ = p.execute(new.signed(a), label=self.label(p, "new-key"))
            self.assert_transfer(p, result)
            self.assertEqual(a.auth()[:3], (2, 2, 1))
            a.send(a.legacy_body(), ext=True, expected=1807)

    def test_legacy_stage_then_pq_confirmed_strict_cutover(self):
        for p in self.pairs(mode=None, workchains=(-1,)):
            a, m = p.account, p.module
            if a.agent:
                stage = (
                    Cell()
                    .uint(0x41475008, 32)
                    .uint(0, 64)
                    .sint(GLOBAL_ID, 32)
                    .uint(0, 64)
                    .addr(m.address)
                )
                a.send(stage, sender=framework.OWNER)
            else:
                actions = Cell().uint(0, 1).uint(1, 1).uint(5, 8).uint(0, 64).addr(m.address)
                a.send(a.legacy_body(actions), ext=True)
            self.assertEqual(a.auth()[:3], (1, 1, 0))
            cfg = a.request(1, Cell().uint(2, 2).addr(m.address))
            p.execute(m.signed(a, cfg), label=self.label(p, "cutover"))
            self.assertEqual(a.auth()[:3], (2, 2, 0))
            a.send(a.legacy_body(), ext=True, expected=1807)
            _, result, _ = p.execute(m.signed(a), label=self.label(p, "strict-execution"))
            self.assert_transfer(p, result)

    def test_signed_requests_cannot_bypass_account_policy(self):
        for p in self.pairs():
            a, m = p.account, p.module
            if a.agent:
                bad = a.request(payload=a.execute_payload(5_000_000_001))
                error = 1707
            else:
                bad = a.request(payload=a.execute_payload(mode=35))
                error = 1811
            p.execute(m.signed(a, bad), error, self.label(p, "policy-refused"))
            self.assertEqual(a.auth()[2], 0)
            self.assertEqual(a.counters()[1], 0)
            self.assertEqual(a.counters()[2], 0)
            _, result, _ = p.execute(m.signed(a), label=self.label(p, "allowed-transfer"))
            self.assert_transfer(p, result)

    def test_agent_post_accept_refusal_consumes_nonce_without_transfer(self):
        for language in MODULE_CODES:
            if MODULE_FILTER and MODULE_FILTER != language:
                continue
            for wc in (-1, 0):
                p = Pair(language, "agent", wc)
                self.addCleanup(p.close)
                a, m = p.account, p.module
                # Destination-only failure injection, not calibration or network configuration.
                a.e.close()
                a.e = Emulator(16, max_msg_cells=0)
                p.limit_injection = True
                req = a.request(payload=a.execute_payload(operation=0x41475003))
                body = m.signed(a, req)
                _, result, _ = p.execute(
                    body, 1713, self.label(p, "committed-refusal"), commits=True
                )
                self.assertFalse(result["details"]["aborted"])
                self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 0)
                self.assertEqual(a.counters()[2], 0)
                self.assertEqual(a.auth()[2], 1)
                self.assertEqual(a.counters()[1], 1)
                p.execute(body, 1804, self.label(p, "consumed-replay"))

    def test_root_domain_and_profile_are_bound(self):
        for p in self.pairs():
            m, a = p.module, p.account
            request = a.request()
            for root in (
                (m.workchain, 0),
                (m.workchain, 42),
                (-1 if m.workchain == 0 else 0, m.address[1]),
            ):
                _, signature = SIGNER.sign(signing_message(root, commitment(request)))
                m.call(
                    submission(a.envelope(request), signature),
                    1808,
                    label=self.label(p, "other-root"),
                )
            invalid = Module(m.language, m.workchain, profile=2)
            self.addCleanup(invalid.close)
            invalid.call(invalid.signed(a), 1811, label=self.label(p, "unknown-profile"))
            p.execute(m.signed(a), label=self.label(p, "valid-domain-control"))

    def test_mldsa_to_falcon_rotation_requires_the_old_root(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "legacy_mldsa_wire", ROOT / "test/mldsa-auth/protocol.py"
        )
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
        old_signer = legacy.Signer(OLD_SIGNER)
        for language in MODULE_CODES:
            for impl in CODES:
                for mode in (2, 3):
                    old = Module(language, 0)
                    old.code = from_boc((ARTIFACTS / f"mldsa-module-{language}.boc").read_bytes())
                    old.data = legacy.module_data(old_signer.public_key(), GLOBAL_ID)
                    old.address = (0, int.from_bytes(state_init(old.code, old.data).hash, "big"))
                    old.shard = active_account(old.address, old.code, old.data, BALANCE)
                    p = Pair(language, impl, 0, mode, root=old)
                    self.addCleanup(p.close)
                    a = p.account
                    new = Module(language, 0)
                    self.addCleanup(new.close)
                    configure = a.request(1, Cell().uint(mode, 2).addr(new.address))
                    # The new key cannot authorize a switch away from the old root.
                    saved = p.module
                    p.module = new
                    p.execute(
                        new.signed(a, configure, a.cosign(configure) if mode == 3 else None),
                        1800,
                        self.label(p, "new-root-unauthorized"),
                    )
                    p.module = saved
                    _, signature = old_signer.sign(commitment(configure))
                    if mode == 3:
                        p.execute(
                            legacy.submission(a.envelope(configure), signature),
                            1808,
                            self.label(p, "missing-old-ed25519"),
                        )
                    body = legacy.submission(
                        a.envelope(configure, a.cosign(configure) if mode == 3 else None), signature
                    )
                    p.execute(body, label=self.label(p, "old-policy-rotation"))
                    self.assertEqual(a.auth(), (mode, 2, 0, new.address[1]))
                    p.module = new
                    req = a.request()
                    _, result, _ = p.execute(
                        new.signed(a, req, a.cosign(req) if mode == 3 else None),
                        label=self.label(p, "new-root-execution"),
                    )
                    self.assert_transfer(p, result)
                    self.assertEqual(a.auth()[:3], (mode, 2, 1))

    def test_funding_bounce_and_version_gates(self):
        for p in self.pairs():
            m, a = p.module, p.account
            body = m.signed(a)
            m.call(body, "failure", value=1000, label=self.label(p, "underfunded"))
            _, out = m.call(body, bounced=True, label=self.label(p, "bounce"))
            self.assertFalse(out)
            _, out = m.call(Cell(), label=self.label(p, "top-up"))
            self.assertFalse(out)
            m.call(body, 1900, ext=True, label=self.label(p, "external-rejected"))
            m.set_version(15)
            m.call(body, 6, label=self.label(p, "v18-rejected"))
            m.set_version(16)
            p.execute(body, label=self.label(p, "v19-positive-control"))

    def test_refused_relay_bounces_the_value_back_into_the_module(self):
        """Close the loop: the account's own bounce, delivered back unmodified."""
        for p in self.pairs():
            m, a = p.module, p.account
            body = m.signed(a)
            p.execute(body, label=self.label(p, "accepted"))
            # The replay is refused by the account, which bounces the relay value.
            _, messages = m.call(body, label=self.label(p, "replayed-relay"))
            result, _ = p.deliver(
                messages[0], 1804, label=self.label(p, "account-refuses"), envelope=body.refs[0]
            )
            bounces = [
                out
                for out in outgoing(from_boc(result["transaction"]))
                if parse_message(out)["bounced"]
            ]
            self.assertEqual(len(bounces), 1, "a refused relay must bounce exactly once")
            wire = parse_message(bounces[0])
            self.assertEqual(wire["destination"], m.address, "the bounce must address the module")
            self.assertGreater(wire["value"], 0, "an empty bounce would prove nothing")
            data_before, balance_before = account_data(m.shard)
            # CRITICAL: the message the account actually produced, not a rebuilt one.
            m.e.lt = max(m.e.lt, wire["created_lt"])
            returned = m.e.send(m.shard, bounces[0])
            self.assertTrue(returned["success"], "the module must accept its own bounce")
            m.shard = from_boc(returned["shard_account"])
            details = returned.get("details", returned)
            self.assertEqual(details.get("exit"), 0, f"{p.label}: {details}")
            self.assertEqual(
                outgoing(from_boc(returned["transaction"])),
                [],
                "a bounce must not be relayed onward",
            )
            data_after, balance_after = account_data(m.shard)
            self.assertEqual(data_after.hash, data_before.hash, "the module stays immutable")
            self.assertEqual(data_after.hash, m.data.hash)
            # The value returns to a contract with no withdrawal path: it stays here.
            self.assertGreater(
                balance_after, balance_before, "the bounced value must be credited to the module"
            )
            self.assertGreater(
                balance_after - balance_before,
                wire["value"] // 2,
                "most of the bounced value must survive the fees",
            )
            record(self.label(p, "bounce-returned"), "module", returned, m.shard)
            p.close()


def main():
    global SIGNER, MODULE_FILTER, OLD_SIGNER, ARTIFACTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--old-signer", type=Path, required=True)
    parser.add_argument("--driver", type=Path)
    parser.add_argument("--module", choices=("func", "tol"))
    parser.add_argument(
        "--case", choices=sorted(n for n in dir(FalconAuthTests) if n.startswith("test_"))
    )
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    MODULE_FILTER = args.module
    OLD_SIGNER, ARTIFACTS = args.old_signer.resolve(), out
    os.environ.update(
        FUNC_PATH=str(build / "crypto/func"),
        FIFT_PATH=str(build / "crypto/fift"),
        TOL_PATH=str(build / "tol/tol"),
        EMULATOR_PATH=str(emulator_library(build)),
    )
    build_contracts(build, out)
    SIGNER = Signer(args.signer)
    for impl in ("wallet-func", "wallet-tol", "agent"):
        CODES[impl] = from_boc((out / f"{impl}.boc").read_bytes())
    for language in ("func", "tol"):
        MODULE_CODES[language] = from_boc((out / f"module-{language}.boc").read_bytes())
    suite = (
        unittest.TestSuite([FalconAuthTests(args.case)])
        if args.case
        else unittest.defaultTestLoader.loadTestsFromTestCase(FalconAuthTests)
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    (out / "e2e.json").write_text(
        json.dumps({"success": result.wasSuccessful(), "events": EVENTS}, indent=2, sort_keys=True)
        + "\n"
    )
    (out / "gas.json").write_text(
        json.dumps(
            {
                "units": "gas; values are raw nanotomis",
                "network_activation": False,
                "transactions": TOTALS,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if args.driver and result.wasSuccessful():
        import subprocess

        from native import config

        cases = out / "two-hop-scenarios.tsv"
        cases.write_text(
            "\n".join(
                "\t".join([name, str(now), str(lt), prior.boc().hex(), message.boc().hex(), "-"])
                for name, prior, message, lt, now, row in TRANSACTIONS
            )
            + "\n"
        )
        left = [row for name, prior, message, lt, now, row in TRANSACTIONS]
        (out / "two-hop-cpp.tsv").write_text("\n".join(left) + "\n")
        fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
        cfg = out / "two-hop-config.boc"
        cfg.write_bytes(Cell().uint(int(fixture.bits, 2), 256).ref(config(16)).boc())
        other = subprocess.run(
            [str(args.driver.resolve()), str(cfg), str(cases), "16"],
            capture_output=True,
            text=True,
            check=True,
        )
        (out / "two-hop-rust.tsv").write_text(other.stdout)
        right = other.stdout.splitlines()
        if len(left) < 100 or left != right:
            different = [(x, y) for x, y in zip(left, right) if x != y]
            raise AssertionError("two-hop executor divergence: " + repr(different[:3]))
        (out / "two-hop-parity.json").write_text(
            json.dumps(
                dict(
                    success=True,
                    transactions=len(left),
                    compared="exit/action/outgoing/account state",
                )
            )
            + "\n"
        )
    print("E2E_ASSERTION_FAILURE" if result.failures else "E2E_NO_ASSERTION_FAILURE")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
