"""Account-level authentication tests against the native action-phase emulator.

No post-quantum algorithm is mocked or claimed: module-sender tests cover the
account authorization boundary. The separate relay test exercises an actual
signed module transaction and delivers its emitted message to the account.
"""

import hashlib
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cells import Cell, from_boc, make_dict, read_dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from native import (
    CURRENT_GLOBAL_VERSION,
    GLOBAL_ID,
    NOW,
    ROOT,
    Emulator,
    account_data,
    active_account,
    compile_contract,
    config,
    distinct_cells,
    external,
    genesis_size_limits,
    internal,
    outgoing,
    state_init,
    uninitialized_account,
)

SECRET = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
KEY = int.from_bytes(SECRET.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), "big")
OTHER_SECRET = Ed25519PrivateKey.from_private_bytes(bytes([0x43]) * 32)
OWNER, MODULE, OTHER, TARGET = (-1, 17), (-1, 18), (-1, 19), (-1, 20)
AUTH = 0x41555448
SIGNED_EXTERNAL, SIGNED_INTERNAL = 0x7369676E, 0x73696E74
EXTENSION = (-1, 21)
DOMAIN = int("ede715a9852fbba2c3c234ed0d27329ae34d6263a82cfb6215da87c91683b471", 16)
CODES = {}
GAS = {}


def policy(maximum=5_000_000_000, daily=6_000_000_000):
    return Cell().coins(maximum).coins(daily).uint(3600, 64).uint(0, 2)


def auth_cell(mode, epoch=1, nonce=0, module=MODULE):
    return Cell().uint(mode, 2).uint(epoch, 64).uint(nonce, 64).uint(module[1], 256)


def send_action(mode, message, previous=None):
    return Cell().uint(0x0EC3C86D, 32).uint(mode, 8).ref(previous or Cell()).ref(message)


def ext_out():
    """ext_out_msg_info$11 from and to addr_none, no StateInit, empty inline body."""
    return Cell().uint(3, 2).uint(0, 2).uint(0, 2).uint(0, 64).uint(0, 32).uint(0, 1).uint(0, 1)


class Account:
    def __init__(
        self,
        impl,
        mode=None,
        nonce=0,
        epoch=1,
        seqno=0,
        module=MODULE,
        extensions=False,
        pubkey=KEY,
        global_version=CURRENT_GLOBAL_VERSION,
        workchain=-1,
        limits=None,
    ):
        self.impl, self.agent = impl, impl == "agent"
        if self.agent:
            data = (
                Cell()
                .addr(OWNER)
                .uint(pubkey, 256)
                .uint(5, 256)
                .uint(0, 64)
                .uint(seqno, 32)
                .uint(0, 32)
                .coins(0)
                .ref(policy())
            )
        else:
            if isinstance(extensions, Cell):
                ext = extensions
            else:
                ext = make_dict({OTHER[1]: Cell().sint(-1, 1)}, 256) if extensions else None
            data = Cell().uint(1, 1).uint(seqno, 32).uint(0, 32).uint(pubkey, 256).maybe(ext)
        if mode is not None:
            data.ref(auth_cell(mode, epoch, nonce, module))
        self.address = (workchain, int.from_bytes(state_init(CODES[impl], data).hash, "big"))
        self.shard = active_account(self.address, CODES[impl], data)
        self.e = Emulator(global_version, limits=limits)

    def close(self):
        self.e.close()

    @property
    def data(self):
        return account_data(self.shard)[0]

    def counters(self):
        s = self.data.slice()
        if self.agent:
            s.addr()
            s.uint(256)
            s.uint(256)
            epoch, seq = s.uint(64), s.uint(32)
            s.uint(32)
            spent = s.coins()
            return epoch, seq, spent
        s.uint(1)
        return 0, s.uint(32), 0

    def auth(self):
        s = self.data.slice()
        if self.agent:
            s.ref()
        else:
            s.uint(321)
            s.maybe()
        if not s.refs:
            return 0, 0, 0, 0
        a = s.ref().slice()
        return a.uint(2), a.uint(64), a.uint(64), a.uint(256)

    def send(self, body, sender=MODULE, ext=False, expected=0, bounced=False, commits=False):
        before = self.data.hash
        message = (
            external(self.address, body)
            if ext
            else internal(sender, self.address, body, bounced=bounced)
        )
        result = self.e.send(self.shard, message)
        if result["success"]:
            details = result["details"]
            actual = details["exit"]
            self.shard = from_boc(result["shard_account"])
        else:
            actual = result.get("vm_exit_code")
            details = result
        assert actual == expected, (
            f"{self.impl}: expected exit {expected}, got {details}\n{result.get('vm_log', '')[-7000:]}"
        )
        if expected and not commits:
            assert self.data.hash == before, (
                "rejection must not commit authentication or account data"
            )
        elif expected:
            # `commits` marks the one family of rejections that deliberately
            # keeps state: those raised after the account has already accepted
            # the message and committed the consumed seqno. Leaving that
            # advance uncommitted is what would make the request replayable.
            assert self.data.hash != before, "a committing rejection must advance the account"
        else:
            assert result["success"] and not details["aborted"], str(details)
            assert details["action"] is None or details["action"]["success"], str(details)
        return result

    def request(self, kind=0, payload=None, **overrides):
        _, epoch, nonce, _ = self.auth()
        return (
            Cell()
            .sint(overrides.get("global_id", GLOBAL_ID), 32)
            .addr(overrides.get("account", self.address))
            .uint(overrides.get("epoch", epoch), 64)
            .uint(overrides.get("nonce", nonce), 64)
            .uint(overrides.get("valid_until", NOW + 600), 32)
            .uint(kind, 8)
            .ref(payload if payload is not None else self.execute_payload())
        )

    def envelope(self, request, cosignature=None):
        return Cell().uint(AUTH, 32).ref(request).maybe(cosignature)

    def cosign(self, request, key=SECRET):
        digest = Cell().uint(0x544F532D41555448, 64).ref(request).hash
        return Cell().raw(key.sign(digest))

    def execute_payload(self, value=1_000_000_000, mode=3, operation=0x41475004):
        if self.agent:
            epoch, seq, _ = self.counters()
            payload = (
                Cell()
                .uint(operation, 32)
                .sint(GLOBAL_ID, 32)
                .uint(epoch, 64)
                .uint(seq, 32)
                .uint(NOW + 600, 32)
            )
            if operation != 0x41475005:
                payload.addr(TARGET).coins(value)
            if operation == 0x41475003:
                payload.ref(Cell().uint(123, 32))
            return payload
        message = internal(self.address, TARGET, Cell(), value)
        return Cell().uint(0x0EC3C86D, 32).uint(mode, 8).ref(Cell()).ref(message)

    def legacy_body(self, payload=None, signature=None, prefix=SIGNED_EXTERNAL):
        if self.agent:
            payload = payload or self.execute_payload()
            digest = (
                Cell()
                .uint(DOMAIN, 256)
                .sint(GLOBAL_ID, 32)
                .sint(self.address[0], 8)
                .uint(self.address[1], 256)
                .raw(payload.hash)
                .hash
            )
            return Cell(
                "".join(f"{x:08b}" for x in SECRET.sign(digest)) + payload.bits, payload.refs
            )
        body = (
            Cell()
            .uint(prefix, 32)
            .sint(GLOBAL_ID, 32)
            .uint(0, 32)
            .uint(NOW + 600, 32)
            .uint(self.counters()[1], 32)
        )
        if payload is None:
            body.maybe(self.execute_payload()).uint(0, 1)
        else:
            body.bits += payload.bits
            body.refs.extend(payload.refs)
        signature = SECRET.sign(body.hash) if signature is None else signature
        return Cell(body.bits + "".join(f"{x:08b}" for x in signature), body.refs)

    def configure(self, mode, module=MODULE, expected=0):
        req = self.request(1, Cell().uint(mode, 2).addr(module))
        co = self.cosign(req) if self.auth()[0] == 3 else None
        return self.send(self.envelope(req, co), expected=expected)

    def extensions(self):
        s = self.data.slice()
        s.uint(1 + 32 + 32 + 256)
        return s.maybe()

    def state_cells(self):
        return distinct_cells(CODES[self.impl], self.data)


# ---------------------------------------------------------------------------
# Account-state bound. The executor fails the action phase with result 50 when
# the account state outgrows ConfigParam 43, and that discards the committed
# seqno with the rest of the new data, so a signed request that grows the
# wallet past the limit used to be accepted and charged on every delivery.

LEAF = Cell().sint(-1, 1)
# The wallet's bound: data root, authentication cell and 509 dictionary cells.
STATE_SOURCES = {
    "wallet-func": ("wallet-v5-code.fc", r"const int state::max_cells_beyond_code = (\d+);"),
    "wallet-tol": ("wallet-v5.tol", r"const STATE_MAX_CELLS_BEYOND_CODE = (\d+)"),
}


def beyond_code(impl):
    source, pattern = STATE_SOURCES[impl]
    text = (ROOT / "crypto/smartcont" / source).read_text()
    found = re.findall(pattern, text)
    assert len(found) == 1, (impl, found)
    return int(found[0])


def state_bound(impl):
    return distinct_cells(CODES[impl]) + beyond_code(impl)


def key(tag, i):
    return int.from_bytes(hashlib.sha256(f"{tag}:{i}".encode()).digest(), "big")


def shared_block(prefix):
    """Eight keys under one prefix: their subtrees are identical, so the
    whole block is four distinct cells, and removing one key breaks the sharing.
    """
    return [(prefix << 3) | i for i in range(8)]


def dictionary_with(cells, required=()):
    """An extensions dictionary of exactly `cells` distinct cells."""
    keys = list(required)

    def count(ks):
        return distinct_cells(make_dict(dict.fromkeys(ks, LEAF), 256)) if ks else 0

    need = cells - count(keys)
    assert need >= 0, (cells, count(keys))
    # Each further unrelated key adds its leaf and one fork.
    keys += [key("fill", i) for i in range((need + (0 if keys else 1)) // 2)]
    if count(keys) == cells - 1:
        # A key next to an existing one at bit 1 shares its new leaf with it:
        # one fork and one leaf replace the old leaf, so it adds one cell.
        keys.append(next(k ^ 2 for k in keys[len(required) :] if not k & 1))
    result = make_dict(dict.fromkeys(keys, LEAF), 256)
    assert count(keys) == cells, (count(keys), cells)
    return result


def account_at(impl, total, required=(), mode=None, workchain=-1, limits=None):
    """A V5 account whose state (code and data) is exactly `total` cells."""
    if limits is None:
        limits = genesis_size_limits()[0]
    empty = Account(impl, mode=mode, workchain=workchain, limits=limits)
    fixed = empty.state_cells()
    empty.close()
    # An empty dictionary is one bit in the root; filling it adds only its own cells.
    a = Account(
        impl,
        mode=mode,
        workchain=workchain,
        limits=limits,
        extensions=dictionary_with(total - fixed, required),
    )
    assert a.state_cells() == total, (impl, a.state_cells(), total)
    return a


def observe(a, body, deliveries=2):
    """Deliver one signed external `deliveries` times and record each outcome."""
    observations = []
    for _ in range(deliveries):
        balance = account_data(a.shard)[1]
        result = a.e.send(a.shard, external(a.address, body))
        seen = {"accepted": result["success"], "balance_before": balance}
        if result["success"]:
            a.shard = from_boc(result["shard_account"])
            seen["details"] = result["details"]
            seen["outgoing"] = len(outgoing(from_boc(result["transaction"])))
        else:
            seen["exit"] = result.get("vm_exit_code")
        seen["balance_after"] = account_data(a.shard)[1]
        seen["seqno"] = a.counters()[1]
        seen["extensions"] = None if a.extensions() is None else a.extensions().hash
        observations.append(seen)
    return observations


def past_limit_by_addition(impl, workchain=-1):
    """One below the limit; one request adds two extensions beside a send."""
    limits, fields = genesis_size_limits()
    limit = fields["max_mc_acc_state_cells" if workchain == -1 else "max_acc_state_cells"]
    a = account_at(impl, limit - 1, workchain=workchain, limits=limits)
    second = Cell().uint(2, 8).addr((workchain, key("new", 2)))
    actions = (
        Cell()
        .maybe(send_action(3, internal(a.address, TARGET, Cell(), 1_000_000_000)))
        .uint(1, 1)
        .uint(2, 8)
        .addr((workchain, key("new", 1)))
        .ref(second)
    )
    return a, a.legacy_body(actions)


def past_limit_by_removal(impl):
    """At the limit; removing one key of a shared block grows the dictionary."""
    limits, fields = genesis_size_limits()
    block = shared_block(key("block", 0) >> 3)
    a = account_at(impl, fields["max_mc_acc_state_cells"], required=block, limits=limits)
    actions = Cell().uint(0, 1).uint(1, 1).uint(3, 8).addr((-1, block[0]))
    return a, a.legacy_body(actions)


def past_limit_by_staging(impl):
    """At the limit without an authentication cell; staging adds that cell."""
    limits, fields = genesis_size_limits()
    a = account_at(impl, fields["max_mc_acc_state_cells"], limits=limits)
    actions = Cell().uint(0, 1).uint(1, 1).uint(5, 8).uint(0, 64).addr(MODULE)
    return a, a.legacy_body(actions)


SCENARIOS = {
    "addition": past_limit_by_addition,
    "removal": past_limit_by_removal,
    "staging": past_limit_by_staging,
}


def refused_once_problems(observations, seqno, extensions):
    """Why the observations are not one charged refusal (exit 149) and a dead replay."""
    first, second = observations
    problems = []
    details = first.get("details") or {}
    if not first["accepted"] or details.get("exit") != 149:
        problems.append(f"first delivery: expected exit 149, got {first}")
    else:
        # A throw after ACCEPT and COMMIT keeps the committed state: compute
        # counts as successful and an empty action list runs successfully.
        if not details["compute_success"] or details["aborted"]:
            problems.append(f"the commit must hold: {details}")
        if details["action"] != {"success": True, "code": 0, "actions": 0}:
            problems.append(f"expected an empty successful action phase: {details['action']}")
        if not details["gas"] > 0:
            problems.append(f"expected gas to be charged: {details}")
    if first.get("outgoing") != 0:
        problems.append(f"no message may leave: {first}")
    if first["seqno"] != seqno + 1:
        problems.append(f"the seqno must be consumed: {first['seqno']} after {seqno}")
    if first["extensions"] != extensions:
        problems.append("the extensions must be unchanged")
    if not first["balance_after"] < first["balance_before"]:
        problems.append(f"the request must be charged once: {first}")
    if second["accepted"] or second.get("exit") != 133:
        problems.append(f"the replay must be refused with 133: {second}")
    if second["balance_after"] != second["balance_before"]:
        problems.append(f"the replay must not be charged: {second}")
    return problems


def result_50_problems(observations, seqno):
    """Why the observations are not the unguarded failure: result 50, the
    seqno lost, and the same request accepted and charged on every delivery."""
    problems = []
    for n, seen in enumerate(observations):
        details = seen.get("details") or {}
        if not seen["accepted"] or details.get("exit") != 0:
            problems.append(f"delivery {n}: expected compute exit 0, got {seen}")
        elif (details["action"] or {}).get("success") is not False or details["action"][
            "code"
        ] != 50:
            problems.append(f"delivery {n}: expected action result 50, got {details['action']}")
        if seen["seqno"] != seqno:
            problems.append(f"delivery {n}: the seqno must stay {seqno}, got {seen['seqno']}")
        if not seen["balance_after"] < seen["balance_before"]:
            problems.append(f"delivery {n}: expected a charge, got {seen}")
    return problems


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        for impl, source in [
            ("agent", "agent-account-code.fc"),
            ("wallet-func", "wallet-v5-code.fc"),
            ("wallet-tol", "wallet-v5.tol"),
        ]:
            CODES[impl] = compile_contract(source, Path(cls.tmp.name) / f"{impl}.boc")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def accounts(self, **kwargs):
        for impl in CODES:
            a = Account(impl, **kwargs)
            self.addCleanup(a.close)
            yield a

    def test_default_configuration_matches_genesis_within_the_vm_capability(self):
        genesis = (ROOT / "crypto/smartcont/gen-zerostate.fif").read_text()
        versions = re.findall(r"^(\d+) .+ config\.version!$", genesis, re.MULTILINE)
        self.assertEqual(len(versions), 1, "Genesis global version must be unambiguous")
        expected = int(versions[0])
        header = (ROOT / "common/global-version.h").read_text()
        self.assertGreaterEqual(int(re.search(r"SUPPORTED_VERSION = (\d+);", header)[1]), expected)
        rust = (ROOT / "tosctl/src/block/src/config_params.rs").read_text()
        self.assertGreaterEqual(
            int(re.search(r"SUPPORTED_VERSION: u32 = (\d+);", rust)[1]), expected
        )
        self.assertEqual(CURRENT_GLOBAL_VERSION, expected)
        with patch.object(Emulator, "_initialize") as initialize:
            Emulator()
        for configuration in (config(), initialize.call_args.args[0]):
            version = read_dict(configuration, 32)[8].refs[0].slice()
            self.assertEqual(version.uint(8), 0xC4)
            self.assertEqual(version.uint(32), expected)

    def test_legacy_success_and_real_signatures(self):
        for a in self.accounts():
            result = a.send(a.legacy_body(), ext=True)
            self.assertEqual(a.counters()[1], 1)
            self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)
            GAS[f"{a.impl}-legacy"] = result["details"]["gas"]
            bad = a.legacy_body()
            bad.bits = (
                ("1" if bad.bits[0] == "0" else "0") + bad.bits[1:]
                if a.agent
                else bad.bits[:-1] + ("1" if bad.bits[-1] == "0" else "0")
            )
            a.send(bad, ext=True, expected=1704 if a.agent else 135)

    def test_ext_out_send_with_a_mode_the_executor_refuses_is_consumed(self):
        # The executor accepts an ext_out send only with mode bits +1 and +2, and +2
        # does not skip that refusal, so such a send used to fail the whole action
        # phase and leave the committed seqno unpersisted: the same signed request was
        # charged again on every delivery. Both builds now refuse it after the commit.
        # 18 and 19 are refused too, even where the executor would strip +16.
        for mode in [66, 130, 18, 19, 34]:
            for a in self.accounts():
                if a.agent:
                    continue
                with self.subTest(impl=a.impl, mode=mode):
                    body = a.legacy_body(Cell().maybe(send_action(mode, ext_out())).uint(0, 1))
                    before = account_data(a.shard)[1]
                    result = a.send(body, ext=True, expected=147, commits=True)
                    self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 0)
                    charged = account_data(a.shard)[1]
                    self.assertLess(charged, before)
                    self.assertEqual(a.counters()[1], 1)
                    a.send(body, ext=True, expected=133)
                    self.assertEqual(account_data(a.shard)[1], charged)
        for mode in [2, 3]:
            for a in self.accounts():
                if a.agent:
                    continue
                with self.subTest(impl=a.impl, mode=mode):
                    body = a.legacy_body(Cell().maybe(send_action(mode, ext_out())).uint(0, 1))
                    result = a.send(body, ext=True)
                    self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)
                    self.assertEqual(a.counters()[1], 1)

    def test_malformed_message_beside_a_valid_send_is_still_skipped(self):
        # A message cell too short to carry a constructor is not an ext_out message:
        # the executor skips it under +2 and runs the rest of the list. The new check
        # reads the constructor only when the cell has one.
        for malformed in [Cell(), Cell("1")]:
            for a in self.accounts():
                if a.agent:
                    continue
                with self.subTest(impl=a.impl, bits=len(malformed.bits)):
                    transfer = internal(a.address, TARGET, Cell(), 1_000_000_000)
                    actions = (
                        Cell()
                        .uint(0x0EC3C86D, 32)
                        .uint(3, 8)
                        .ref(send_action(66, malformed))
                        .ref(transfer)
                    )
                    result = a.send(a.legacy_body(Cell().maybe(actions).uint(0, 1)), ext=True)
                    self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)
                    self.assertEqual(a.counters()[1], 1)

    def test_module_request_cannot_carry_an_ext_out_send_the_executor_refuses(self):
        for a in self.accounts(mode=2):
            if a.agent:
                continue
            with self.subTest(impl=a.impl):
                a.send(a.envelope(a.request(payload=send_action(66, ext_out()))), expected=147)
                self.assertEqual(a.counters()[1], 0)
                result = a.send(a.envelope(a.request(payload=send_action(2, ext_out()))))
                self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)

    def test_request_refused_by_action_checks_consumes_its_seqno(self):
        # External sends without the ignore-errors bit are refused after the
        # wallet accepted the request. Both builds must have committed the
        # consumed seqno by then, so the wallet pays for the request once and
        # the same signed body is dead on its second delivery.
        for a in self.accounts():
            if a.agent:
                continue
            body = a.legacy_body(Cell().maybe(a.execute_payload(mode=1)).uint(0, 1))
            before = account_data(a.shard)[1]
            result = a.send(body, ext=True, expected=137, commits=True)
            self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 0)
            charged = account_data(a.shard)[1]
            self.assertLess(charged, before)
            self.assertEqual(a.counters()[1], 1)
            a.send(body, ext=True, expected=133)
            self.assertEqual(account_data(a.shard)[1], charged)

    def test_weak_key_cannot_authorize_a_signed_request(self):
        # For an identity key A, R = identity and S = 0 satisfy S*B = R + h*A
        # for every message, so no private key is involved. The canonical
        # identity is also refused by the VM; its sign-bit alias is not.
        signature = (1 << 248).to_bytes(32, "big") + bytes(32)
        for key in [1 << 248, (1 << 248) | 0x80]:
            for a in self.accounts(pubkey=key):
                if a.agent:
                    continue
                with self.subTest(impl=a.impl, key=hex(key)):
                    a.send(a.legacy_body(signature=signature), ext=True, expected=135)
                    a.send(
                        a.legacy_body(signature=signature, prefix=SIGNED_INTERNAL),
                        sender=OTHER,
                        expected=135,
                    )
                    self.assertEqual(a.counters()[1], 0)

    def test_request_refused_at_its_second_extension_change_keeps_neither(self):
        # The FunC build applies the first addition and then throws on the
        # second, so this exercises its rollback. The Tol build refuses the
        # chain in validateActions, on a simulated dictionary, before
        # processActions changes anything; there it checks the refusal point.
        def extensions(a):
            s = a.data.slice()
            s.uint(1 + 32 + 32 + 256)
            return s.maybe()

        add = Cell().uint(2, 8).addr(EXTENSION)
        twice = Cell().uint(0, 1).uint(1, 1).uint(2, 8).addr(EXTENSION).ref(add)
        once = Cell().uint(0, 1).uint(1, 1).uint(2, 8).addr(EXTENSION)
        for a in self.accounts():
            if a.agent:
                continue
            with self.subTest(impl=a.impl):
                # Internal: nothing is committed, so no addition and no seqno
                # advance survives.
                a.send(a.legacy_body(twice, prefix=SIGNED_INTERNAL), sender=OTHER, expected=139)
                self.assertIsNone(extensions(a))
                self.assertEqual(a.counters()[1], 0)
                # External: only the committed seqno survives the refusal.
                a.send(a.legacy_body(twice), ext=True, expected=139, commits=True)
                self.assertIsNone(extensions(a))
                self.assertEqual(a.counters()[1], 1)
                # Positive control: the same addition alone is applied.
                a.send(a.legacy_body(once, prefix=SIGNED_INTERNAL), sender=OTHER)
                self.assertIsNotNone(extensions(a))
                self.assertEqual(a.counters()[1], 2)

    def test_pre_genesis_authentication_remains_compatible(self):
        # Keep minimum-version coverage explicit while the main suite runs at genesis.
        for impl, version in [("agent", 6), ("wallet-func", 6), ("wallet-tol", 14)]:
            with self.subTest(impl=impl, version=version):
                account = Account(impl, global_version=version)
                self.addCleanup(account.close)
                result = account.send(account.legacy_body(), ext=True)
                self.assertEqual(account.counters()[1], 1)
                self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)

    def test_stage_and_module_confirmed_cutover(self):
        for a in self.accounts():
            if a.agent:
                body = (
                    Cell()
                    .uint(0x41475008, 32)
                    .uint(0, 64)
                    .sint(GLOBAL_ID, 32)
                    .uint(0, 64)
                    .addr(MODULE)
                )
                a.send(body, sender=OWNER)
            else:
                actions = Cell().uint(0, 1).uint(1, 1).uint(5, 8).uint(0, 64).addr(MODULE)
                a.send(a.legacy_body(actions), ext=True)
            self.assertEqual(a.auth()[:3], (1, 1, 0))
            a.send(a.legacy_body(), ext=True)
            a.configure(2)
            self.assertEqual(a.auth()[:3], (2, 2, 0))
            a.send(a.legacy_body(), ext=True, expected=1807)
            a.send(a.envelope(a.request()))
            self.assertEqual(a.auth()[2], 1)

    def test_module_executes_and_replay_is_rejected(self):
        for a in self.accounts(mode=2):
            request = a.request()
            result = a.send(a.envelope(request))
            self.assertEqual(a.auth()[2], 1)
            self.assertEqual(a.counters()[1], 1)
            self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)
            if a.agent:
                self.assertEqual(a.counters()[2], 1_000_000_000)
            a.send(a.envelope(request), expected=1804)
            GAS[f"{a.impl}-module"] = result["details"]["gas"]

    def test_each_binding_is_enforced(self):
        for a in self.accounts(mode=2):
            for field, value, error in [
                ("global_id", 43, 1801),
                ("account", TARGET, 1802),
                ("epoch", 0, 1803),
                ("nonce", 1, 1804),
                ("valid_until", NOW, 1805),
                ("valid_until", NOW + 3601, 1805),
            ]:
                with self.subTest(impl=a.impl, field=field, value=value):
                    a.send(a.envelope(a.request(**{field: value})), expected=error)
            a.send(a.envelope(a.request()), sender=OTHER, expected=1800)
            a.send(a.envelope(a.request()), sender=(0, MODULE[1]), expected=1809)
            a.send(a.envelope(a.request(kind=99)), expected=1811)
            a.send(a.envelope(a.request()), bounced=True)
            self.assertEqual(a.auth()[2], 0)
            a.send(a.envelope(a.request()))  # prove the instrument can accept

    def test_hybrid_is_and_on_exact_request(self):
        for a in self.accounts(mode=3):
            req = a.request()
            a.send(a.envelope(req), expected=1808)
            a.send(a.envelope(req, a.cosign(req, OTHER_SECRET)), expected=1808)
            different = a.request(valid_until=NOW + 601)
            a.send(a.envelope(req, a.cosign(different)), expected=1808)
            a.send(a.envelope(req, a.cosign(req)), sender=OTHER, expected=1800)
            a.send(a.legacy_body(), ext=True, expected=1807)
            a.send(a.envelope(req, a.cosign(req)))
            self.assertEqual(a.auth()[2], 1)

    def test_rotation_and_no_downgrade(self):
        for a in self.accounts(mode=2):
            a.configure(1, expected=1806)
            old = a.request()
            a.configure(2, OTHER)
            self.assertEqual(a.auth(), (2, 2, 0, OTHER[1]))
            a.send(a.envelope(old), expected=1800)
            a.send(a.envelope(old), sender=OTHER, expected=1803)
            a.send(a.envelope(a.request()), sender=OTHER)

    def test_strict_blocks_legacy_management(self):
        for a in self.accounts(mode=2, extensions=True):
            if a.agent:
                body = Cell().uint(0x41475001, 32).uint(0, 64)
                p = policy()
                body.bits += p.bits
                a.send(body, sender=OWNER, expected=1807)
                # The same management operation succeeds through the module.
                a.send(a.envelope(a.request(2, body)))
                self.assertEqual(a.auth()[2], 1)
            else:
                legacy = (
                    Cell()
                    .uint(0x6578746E, 32)
                    .uint(0, 64)
                    .uint(0, 1)
                    .uint(1, 1)
                    .uint(4, 8)
                    .uint(1, 1)
                )
                a.send(legacy, sender=OTHER, expected=1807)
                signed = a.legacy_body()
                signed.bits = f"{0x73696E74:032b}" + signed.bits[32:]
                a.send(signed, sender=OWNER, expected=1807)
                a.configure(2)
                s = a.data.slice()
                self.assertEqual(s.uint(1), 0)
                s.uint(320)
                self.assertIsNone(s.maybe(), "strict mode removes old extensions")

    def test_hybrid_activation_rejects_weak_classical_keys(self):
        # Zero, the identity, and the identity and the order-2 point with the
        # sign bit set: x = 0 aliases whose y is in range.
        for key in [
            0,
            1 << 248,
            (1 << 248) | 0x80,
            0xECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        ]:
            for a in self.accounts(mode=2, pubkey=key):
                a.configure(3, expected=1720 if a.agent else 1808)
                self.assertEqual(a.auth()[:3], (2, 1, 0))

    def test_counter_overflow_is_closed(self):
        for a in self.accounts(mode=2, nonce=(1 << 64) - 1):
            a.send(a.envelope(a.request()), expected=1810)
        for a in self.accounts(mode=2, epoch=(1 << 64) - 1):
            a.configure(2, expected=1810)
        for a in self.accounts(mode=2, seqno=(1 << 32) - 1):
            a.send(a.envelope(a.request()), expected=1716 if a.agent else 1810)

    def test_module_request_rejected_after_acceptance_is_consumed_not_bounced(self):
        """A module request can still be refused after the account accepted it.

        The agent account accepts, commits the consumed seqno, and only then
        measures the attached trees -- that measurement is priced by the
        caller's payload and cannot be paid for out of the fixed admission
        credit. A refusal at that point therefore behaves differently from one
        raised earlier, and the difference is worth pinning: no value moves and
        the daily budget is untouched, but the seqno and the authentication
        nonce are spent, and the transaction is not aborted, so the module
        receives no bounce and has to read the chain to learn what happened.

        A ConfigParam 43 of zero cells makes any attached tree oversized, which
        is the cheapest way to reach a refusal on that side of the commit.
        """
        a = Account(
            "agent",
            mode=2,
        )
        self.addCleanup(a.close)
        a.e = Emulator(max_msg_cells=0)
        before_nonce, before_seqno = a.auth()[2], a.counters()[1]
        request = a.request(payload=a.execute_payload(operation=0x41475003))
        result = a.send(a.envelope(request), expected=1713, commits=True)

        self.assertFalse(result["details"]["aborted"], "a committed refusal must not abort")
        self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 0)
        self.assertEqual(a.counters()[2], 0, "a refused transfer must not spend the daily budget")
        self.assertEqual(a.auth()[2], before_nonce + 1, "the nonce must be consumed")
        self.assertEqual(a.counters()[1], before_seqno + 1, "the seqno must be consumed")

        # Consuming them is the point: the identical request is now dead.
        a.send(a.envelope(request), expected=1804)

    def test_agent_policy_still_applies(self):
        a = Account("agent", mode=2)
        self.addCleanup(a.close)
        a.send(a.envelope(a.request(payload=a.execute_payload(5_000_000_001))), expected=1707)
        a.send(a.envelope(a.request(payload=a.execute_payload(4_000_000_000))))
        a.send(a.envelope(a.request(payload=a.execute_payload(3_000_000_000))), expected=1707)
        a.send(a.envelope(a.request(payload=a.execute_payload(2_000_000_000))))
        self.assertEqual(a.counters()[2], 6_000_000_000)

    def test_real_module_transaction_and_hybrid_relay(self):
        module_code = compile_contract(
            str(ROOT / "test/auth-extensions/test-module.fc"),
            Path(self.tmp.name) / "test-module.boc",
        )
        module_key = int.from_bytes(
            OTHER_SECRET.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), "big"
        )
        module_data = Cell().uint(module_key, 256).uint(0, 32)
        module_address = (-1, int.from_bytes(state_init(module_code, module_data).hash, "big"))
        for a in self.accounts(mode=3, module=module_address):
            module_shard = active_account(module_address, module_code, module_data)
            request = a.request()
            envelope = a.envelope(request, a.cosign(request))
            signed = Cell().uint(0, 32).ref(envelope)
            proof = OTHER_SECRET.sign(signed.hash)
            message_body = Cell("".join(f"{x:08b}" for x in proof) + signed.bits, signed.refs)
            invalid = Cell(
                "".join(f"{x:08b}" for x in SECRET.sign(signed.hash)) + signed.bits, signed.refs
            )
            bad = a.e.send(module_shard, external(module_address, invalid))
            self.assertFalse(bad["success"])
            self.assertEqual(bad["vm_exit_code"], 1900)
            result = a.e.send(module_shard, external(module_address, message_body))
            self.assertTrue(result["success"])
            self.assertEqual(result["details"]["exit"], 0)
            self.assertFalse(result["details"]["aborted"])
            emitted = outgoing(from_boc(result["transaction"]))
            self.assertEqual(len(emitted), 1)
            # Deliver the exact message emitted by the module action phase;
            # do not fabricate the module's sender identity in this test.
            execution = a.e.send(a.shard, emitted[0])
            self.assertTrue(execution["success"])
            self.assertEqual(execution["details"]["exit"], 0)
            self.assertFalse(execution["details"]["aborted"])
            a.shard = from_boc(execution["shard_account"])
            self.assertEqual(a.auth()[2], 1)
            self.assertEqual(len(outgoing(from_boc(execution["transaction"]))), 1)
            replay = a.e.send(
                from_boc(result["shard_account"]), external(module_address, message_body)
            )
            self.assertFalse(replay["success"])
            self.assertEqual(replay["vm_exit_code"], 1901)

    def test_agent_legacy_deploy_stays_inside_admission_credit(self):
        a = Account("agent")
        self.addCleanup(a.close)
        # Minimal ordinary-cell deployment profile, matching the bounded path.
        init = state_init(Cell().uint(0, 8), Cell().uint(0, 32))
        target = (-1, int.from_bytes(init.hash, "big"))
        payload = (
            Cell()
            .uint(0x41475006, 32)
            .sint(GLOBAL_ID, 32)
            .uint(0, 64)
            .uint(0, 32)
            .uint(NOW + 600, 32)
            .addr(target)
            .coins(1_000_000_000)
            .ref(init)
            .ref(Cell())
        )
        result = a.send(a.legacy_body(payload), ext=True)
        self.assertEqual(a.counters()[1], 1)
        self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)
        GAS["agent-legacy-deploy"] = result["details"]["gas"]

    def wallets(self):
        return [impl for impl in CODES if impl != "agent"]

    def check_refused_once(self, scenario, impl, **kwargs):
        a, body = SCENARIOS[scenario](impl, **kwargs)
        self.addCleanup(a.close)
        seqno = a.counters()[1]
        extensions = a.extensions().hash
        problems = refused_once_problems(observe(a, body), seqno, extensions)
        self.assertEqual(problems, [], f"{impl} {scenario}")
        return a

    def test_growth_past_the_state_limit_is_consumed_not_replayed(self):
        # Masterchain at the genesis limit. Without the bound this request
        # reaches result 50: the mutation check drives exactly this fixture.
        for impl in self.wallets():
            with self.subTest(impl=impl):
                self.check_refused_once("addition", impl)

    def test_basechain_growth_past_the_state_limit_is_consumed_not_replayed(self):
        for impl in self.wallets():
            with self.subTest(impl=impl):
                self.check_refused_once("addition", impl, workchain=0)

    def test_removal_that_breaks_shared_subtrees_is_bounded(self):
        # Removing one key of a shared block replaces shared cells with new
        # ones: the dictionary grows although it holds fewer keys.
        for impl in self.wallets():
            with self.subTest(impl=impl, case="below the bound"):
                block = shared_block(key("block", 1) >> 3)
                a = Account(impl, extensions=dictionary_with(40, block))
                self.addCleanup(a.close)
                before = a.state_cells()
                a.send(
                    a.legacy_body(Cell().uint(0, 1).uint(1, 1).uint(3, 8).addr((-1, block[0]))),
                    ext=True,
                )
                self.assertGreater(a.state_cells(), before, "the fixture must grow on removal")
                self.assertLessEqual(a.state_cells(), state_bound(impl))
            with self.subTest(impl=impl, case="at the limit"):
                self.check_refused_once("removal", impl)

    def test_staging_at_the_state_limit_is_consumed_not_replayed(self):
        for impl in self.wallets():
            with self.subTest(impl=impl):
                self.check_refused_once("staging", impl)

    def test_extension_bound_boundary(self):
        # Exactly two cells below the bound, an addition lands on it; the next
        # is refused through every path that can add an extension.
        for impl in self.wallets():
            with self.subTest(impl=impl):
                bound = state_bound(impl)
                a = account_at(impl, bound - 2, required=[EXTENSION[1]])
                self.addCleanup(a.close)

                def add(n):
                    return Cell().uint(0, 1).uint(1, 1).uint(2, 8).addr((-1, key("edge", n)))

                result = a.send(a.legacy_body(add(1)), ext=True)
                self.assertEqual(a.state_cells(), bound)
                GAS[f"{impl}-state-bound-add"] = result["details"]["gas"]
                full = a.data.hash
                # A signed internal and an extension request revert whole.
                a.send(a.legacy_body(add(2), prefix=SIGNED_INTERNAL), sender=OTHER, expected=149)
                a.send(
                    Cell()
                    .uint(0x6578746E, 32)
                    .uint(0, 64)
                    .uint(0, 1)
                    .uint(1, 1)
                    .uint(2, 8)
                    .addr((-1, key("edge", 2))),
                    sender=EXTENSION,
                    expected=149,
                )
                self.assertEqual(a.data.hash, full)
                # A signed external is consumed: charged once, dead on replay.
                seqno, extensions = a.counters()[1], a.extensions().hash
                problems = refused_once_problems(
                    observe(a, a.legacy_body(add(2))), seqno, extensions
                )
                self.assertEqual(problems, [])
                self.assertEqual(a.state_cells(), bound)
                # Removing one makes room again.
                a.send(
                    a.legacy_body(
                        Cell().uint(0, 1).uint(1, 1).uint(3, 8).addr((-1, key("edge", 1)))
                    ),
                    ext=True,
                )
                a.send(a.legacy_body(add(2)), ext=True)
                self.assertEqual(a.state_cells(), bound)

    def test_wallet_above_the_bound_still_transacts(self):
        # Only an oversized StateInit can place a wallet above the bound.
        # Requests that do not grow it still pass, so it can spend and shrink.
        limits, fields = genesis_size_limits()
        limit = fields["max_mc_acc_state_cells"]
        for impl in self.wallets():
            with self.subTest(impl=impl):
                # An odd key: dictionary_with pairs only even keys.
                removable = next(k for k in (key("fill", i) for i in range(64)) if k & 1)
                a = account_at(impl, limit - 1, mode=1, limits=limits)
                self.addCleanup(a.close)
                result = a.send(a.legacy_body(), ext=True)
                self.assertEqual(len(outgoing(from_boc(result["transaction"]))), 1)
                a.send(
                    a.legacy_body(Cell().uint(0, 1).uint(1, 1).uint(3, 8).addr((-1, removable))),
                    ext=True,
                )
                self.assertEqual(a.state_cells(), limit - 3)
                # Staging again replaces the authentication cell in place.
                restage = Cell().uint(0, 1).uint(1, 1).uint(5, 8).uint(1, 64).addr(OTHER)
                a.send(a.legacy_body(restage), ext=True)
                self.assertEqual(a.auth()[:2], (1, 2))
                self.assertEqual(a.state_cells(), limit - 3)
                self.assertEqual(a.counters()[1], 3)
            with self.subTest(impl=impl, case="first staging grows the state"):
                # Without an authentication cell the first staging adds one;
                # above the bound that growth is refused even below the limit.
                b = account_at(impl, limit - 1, limits=limits)
                self.addCleanup(b.close)
                stage = Cell().uint(0, 1).uint(1, 1).uint(5, 8).uint(0, 64).addr(MODULE)
                b.send(b.legacy_body(stage), ext=True, expected=149, commits=True)
                self.assertEqual(b.auth(), (0, 0, 0, 0))

    def test_genesis_size_limits_leave_headroom_for_the_wallet(self):
        # The guard holds a wallet to code + data root + authentication cell +
        # 509 dictionary cells. Lowering ConfigParam 43 below that would let a
        # bounded wallet reach result 50 again.
        _, fields = genesis_size_limits()
        limit = min(fields["max_mc_acc_state_cells"], fields["max_acc_state_cells"])
        for impl in self.wallets():
            with self.subTest(impl=impl):
                self.assertEqual(beyond_code(impl), 1 + 1 + 509)
                self.assertLess(state_bound(impl), limit)

    def test_deploy_with_libraries_is_refused(self):
        # The bound counts code and data only. The executor counts libraries
        # too, so it must be impossible for a V5 account to hold any: the
        # wallet emits no library action, and a deploy that carries them is
        # refused before compute.
        library = Cell().uint(0xDEADBEEF, 32)
        libraries = make_dict(
            {int.from_bytes(library.hash, "big"): Cell().uint(0, 1).ref(library)}, 256
        )
        for impl in self.wallets():
            for carried in (None, libraries):
                with self.subTest(impl=impl, libraries=carried is not None):
                    a = Account(impl)
                    self.addCleanup(a.close)
                    data = account_data(a.shard)[0]
                    init = state_init(CODES[impl], data, carried)
                    address = (-1, int.from_bytes(init.hash, "big"))
                    body = a.legacy_body(Cell().uint(0, 1).uint(0, 1))
                    result = a.e.send(uninitialized_account(address), external(address, body, init))
                    if carried is None:
                        self.assertTrue(result["success"], result)
                        self.assertEqual(result["details"]["exit"], 0)
                    else:
                        self.assertFalse(result["success"], result)
                        self.assertTrue(result.get("external_not_accepted"), result)
                        # The refusal is the executor's library rule, which
                        # starts at global version 15: before it, the same
                        # deploy goes through.
                        old = Emulator(14)
                        self.addCleanup(old.close)
                        before = old.send(
                            uninitialized_account(address), external(address, body, init)
                        )
                        self.assertTrue(before["success"], before)
                        self.assertEqual(before["details"]["exit"], 0)

    def test_wallet_rejects_destruction_and_arbitrary_actions(self):
        for a in self.accounts(mode=2):
            if a.agent:
                continue
            for mode in [35, 7, 11, 195]:
                a.send(a.envelope(a.request(payload=a.execute_payload(mode=mode))), expected=1811)
            setcode = Cell().uint(0xAD4DE08E, 32).ref(Cell()).ref(Cell())
            # Invalid C5 prefix has a VM cell-underflow error; positive control
            # below proves the real action path is reached.
            a.send(a.envelope(a.request(payload=setcode)), expected=9)
            a.send(a.envelope(a.request()))


if __name__ == "__main__":
    import sys

    result = unittest.main(verbosity=2, exit=False)
    print("Measured native transaction gas:", GAS)
    sys.exit(0 if result.result.wasSuccessful() else 1)
