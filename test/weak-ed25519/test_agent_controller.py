#!/usr/bin/env python3
"""Stored controller keys, real native transactions, and admission gas.

Uses the repository's C++ transaction emulator with signature verification enabled.
All balances and deliberately malformed accounts are local fixtures. No network is
contacted. The shipped Rust BOC must equal freshly compiled FunC. A source mutation
restoring the old v2-only key guard must admit the same legacy forgery that the
shipped code rejects; a rejected undeployed account is not a passing control.
"""

# Repository-local imports need the explicit bootstrap below.
# ruff: noqa: E402

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc, make_dict, read_dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from native import (
    GLOBAL_ID,
    NOW,
    Emulator,
    account_data,
    compile_contract,
    config,
    external,
    internal,
    outgoing,
    state_init,
)

TASK, NATIVE, CANCEL, DEPLOY, V2 = range(0x41475003, 0x41475008)
OPERATIONS = {TASK: "task", NATIVE: "native", CANCEL: "cancel", DEPLOY: "deploy", V2: "v2"}
DOMAIN = int("ede715a9852fbba2c3c234ed0d27329ae34d6263a82cfb6215da87c91683b471", 16)
SECRET = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
OTHER_SECRET = Ed25519PrivateKey.from_private_bytes(bytes([0x43]) * 32)
PUBLIC = SECRET.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
IDENTITY = bytes.fromhex("01" + "00" * 31)
IDENTITY_ALIAS = bytes.fromhex("01" + "00" * 30 + "80")
ORDER2_ALIAS = bytes.fromhex("ec" + "ff" * 31)
FORGED = IDENTITY + bytes(32)
GROUP_ORDER = (1 << 252) + 27742317777372353535851937790883648493
VALUE = 100_000_000
FUNDING = 100_000_000_000
CREDIT = 10_000
GLOBAL_VERSION = 18
EVIDENCE = {"schema": "tos.agent-controller-key-regression.v1", "cases": [], "admission": []}


def weak_keys():
    """Existing on-chain policy: 8 torsion encodings, 2 sign aliases, 38 y aliases."""
    canonical = [
        IDENTITY.hex(),
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "00" * 31 + "80",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ec" + "ff" * 30 + "7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "00" * 32,
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "01" + "00" * 30 + "80",
        "ec" + "ff" * 31,
    ]
    keys = [bytes.fromhex(k) for k in canonical]
    keys.extend(
        bytes([first]) + bytes([255]) * 30 + bytes([last])
        for first in range(237, 256) for last in (127, 255)
    )
    assert len(keys) == len(set(keys)) == 48
    return keys


WEAK_KEYS = weak_keys()


def gas_config(credit=CREDIT):
    """Use the stricter 10,000 credit, even on basechain profiles allowing 20,000."""
    entries = read_dict(config(GLOBAL_VERSION), 32)
    for number in (20, 21):
        original = entries[number].refs[0]
        s = original.slice()
        tag = s.uint(8)
        if tag == 0xD1:
            s.uint(128)
            tag = s.uint(8)
        assert tag in (0xDD, 0xDE), "unexpected gas configuration constructor"
        s.uint(128)
        if tag == 0xDE:
            s.uint(64)
        offset = len(original.bits) - len(s.bits)
        s.uint(64)
        bits = original.bits[:offset] + format(credit, "064b") + s.bits
        entries[number] = Cell().ref(Cell(bits, original.refs))
    return make_dict(entries, 32)


def no_account():
    return Cell().uint(0, 256).uint(0, 64).ref(Cell().uint(0, 1))


def deployment(sender, address, init, value=FUNDING):
    return (
        Cell().uint(4, 4).addr(sender).addr(address).coins(value).uint(0, 1)
        .coins(0).coins(0).uint(0, 64).uint(NOW, 32)
        .uint(3, 2).ref(init).uint(1, 1).ref(Cell())
    )


def successful(result):
    assert result["success"], result
    d = result["details"]
    assert d["exit"] == 0 and d["compute_success"] and not d["aborted"], d
    assert d["action"] is None or (d["action"]["success"] and d["action"]["code"] == 0), d
    return from_boc(result["shard_account"])


def tx_fees(transaction):
    s = transaction.slice()
    assert s.uint(4) == 7
    s.uint(256 + 64 + 256 + 64 + 32)
    count = s.uint(15)
    s.uint(4)
    s.ref()
    fees = s.coins()
    assert s.maybe() is None
    return fees, count


def message_info(message):
    s = message.slice()
    assert s.uint(1) == 0
    flags = s.uint(3)
    sender, receiver = s.addr(), s.addr()
    value = s.coins()
    assert s.maybe() is None
    extra_flags, fwd_fee = s.coins(), s.coins()
    return {"sender": sender, "receiver": receiver, "value": value,
            "fwd_fee": fwd_fee, "flags": flags, "extra_flags": extra_flags}


class Agent:
    def __init__(self, code, receiver_code, key=PUBLIC, mode=None, wc=-1, metadata=False):
        self.owner, self.module, self.other = (wc, 17), (wc, 18), (wc, 19)
        self.receiver_code = receiver_code
        self.receiver_init = state_init(receiver_code, Cell().uint(0, 32))
        self.target = (wc, int.from_bytes(self.receiver_init.hash, "big"))
        policy = Cell().coins(5_000_000_000).coins(6_000_000_000).uint(3600, 64)
        for value in (0x1234, 0x5678):
            policy.uint(metadata, 1)
            if metadata:
                policy.uint(value, 256)
        data = (Cell().addr(self.owner).raw(key).uint(5, 256).uint(0, 64)
                .uint(0, 32).uint(0, 32).coins(0).ref(policy))
        if mode is not None:
            data.ref(Cell().uint(mode, 2).uint(1, 64).uint(0, 64).uint(self.module[1], 256))
        init = state_init(code, data)
        self.address = (wc, int.from_bytes(init.hash, "big"))
        self.e = Emulator.from_config(gas_config())
        self.shard = successful(self.e.send(no_account(), deployment(self.owner, self.address, init)))
        actual, balance = account_data(self.shard)
        assert actual.hash == data.hash and 0 < balance < FUNDING
        self.receiver = None

    def close(self):
        self.e.close()

    @property
    def data(self):
        return account_data(self.shard)[0]

    @property
    def balance(self):
        return account_data(self.shard)[1]

    def state(self):
        s = self.data.slice()
        owner, key, deployment_id = s.addr(), s.uint(256), s.uint(256)
        epoch, seq, day, spent = s.uint(64), s.uint(32), s.uint(32), s.coins()
        policy = s.ref()
        auth = s.ref().slice() if s.refs else None
        s.end()
        auth_tuple = (auth.uint(2), auth.uint(64), auth.uint(64), auth.uint(256)) if auth else (0, 0, 0, 0)
        if auth:
            auth.end()
        return {"owner": owner, "key": key, "deployment_id": deployment_id, "epoch": epoch,
                "seq": seq, "day": day, "spent": spent, "policy": policy.hash.hex(), "auth": auth_tuple}

    def payload(self, operation=NATIVE, value=VALUE, valid_until=NOW + 600):
        st = self.state()
        p = (Cell().uint(operation, 32).sint(GLOBAL_ID, 32).uint(st["epoch"], 64)
             .uint(st["seq"], 32).uint(valid_until, 32))
        if operation != CANCEL:
            p.addr(self.target).coins(value)
        if operation == DEPLOY:
            p.ref(self.receiver_init).ref(Cell().uint(123, 32))
        elif operation in (TASK, V2):
            if operation == V2:
                p.uint(3, 8)
            p.ref(Cell().uint(123, 32))
        return p

    def digest(self, payload):
        return (Cell().uint(DOMAIN, 256).sint(GLOBAL_ID, 32).sint(self.address[0], 8)
                .uint(self.address[1], 256).raw(payload.hash).hash)

    def signed(self, payload, secret=SECRET, forged=False):
        signature = FORGED if forged else secret.sign(self.digest(payload))
        return Cell(Cell().raw(signature).bits + payload.bits, payload.refs)

    def module_body(self, payload, secret=None, kind=0, nonce=None):
        _, epoch, current_nonce, _ = self.state()["auth"]
        req = (Cell().sint(GLOBAL_ID, 32).addr(self.address).uint(epoch, 64)
               .uint(current_nonce if nonce is None else nonce, 64).uint(NOW + 600, 32)
               .uint(kind, 8).ref(payload))
        co = None if secret is None else Cell().raw(secret.sign(Cell().uint(0x544F532D41555448, 64).ref(req).hash))
        return Cell().uint(0x41555448, 32).ref(req).maybe(co)

    def reject_external(self, body, exit_code):
        before = self.shard.hash
        state = self.state()
        balance = self.balance
        result = self.e.send(self.shard, external(self.address, body))
        assert not result["success"] and result.get("vm_exit_code") == exit_code, result
        assert "transaction" not in result and "shard_account" not in result, result
        assert self.shard.hash == before and self.state() == state and self.balance == balance
        return result

    def send_internal(self, body, sender=None, expected=0):
        before = self.data.hash
        result = self.e.send(self.shard, internal(sender or self.module, self.address, body))
        assert result["success"] and result["details"]["exit"] == expected, result
        self.shard = from_boc(result["shard_account"])
        if expected:
            assert result["details"]["aborted"] and self.data.hash == before, result
            assert not outgoing(from_boc(result["transaction"])), result
        else:
            successful(result)
        return result

    def prepare_receiver(self):
        self.receiver = successful(self.e.send(no_account(), deployment(self.owner, self.target, self.receiver_init)))
        assert account_data(self.receiver)[0].slice().uint(32) == 1

    def settle(self, result, sender_before, operation, inbound=0):
        """Deliver the actual emitted Message; account for every nanoTOS and fee."""
        self.shard = successful(result)
        tx = from_boc(result["transaction"])
        fees, count = tx_fees(tx)
        emitted = outgoing(tx)
        assert len(emitted) == count == (0 if operation == CANCEL else 1)
        summary = {"operation": OPERATIONS[operation], "sender_tx": tx.hash.hex(),
                   "sender_gas": result["details"]["gas"], "sender_fees": fees,
                   "sender_before": sender_before, "sender_after": self.balance}
        if operation == CANCEL:
            assert sender_before + inbound == self.balance + fees
            return summary
        message = emitted[0]
        info = message_info(message)
        assert info["sender"] == self.address and info["receiver"] == self.target, info
        assert info["value"] == VALUE, info
        assert sender_before + inbound == self.balance + VALUE + fees + info["fwd_fee"], summary
        before = account_data(self.receiver)[1] if self.receiver is not None else 0
        old_count = account_data(self.receiver)[0].slice().uint(32) if self.receiver else 0
        receipt = self.e.send(self.receiver if self.receiver is not None else no_account(), message)
        self.receiver = successful(receipt)
        receipt_tx = from_boc(receipt["transaction"])
        receipt_fees, receipt_count = tx_fees(receipt_tx)
        received_data, after = account_data(self.receiver)
        assert received_data.slice().uint(32) == old_count + 1
        assert not outgoing(receipt_tx) and receipt_count == 0
        assert before + VALUE == after + receipt_fees
        assert sender_before + before + inbound == self.balance + after + fees + receipt_fees + info["fwd_fee"]
        summary.update({"recipient_tx": receipt_tx.hash.hex(), "message": message.hash.hex(),
                        "recipient_before": before, "recipient_after": after,
                        "recipient_fees": receipt_fees, "forward_fee": info["fwd_fee"],
                        "transferred": VALUE, "conservation": True})
        return summary


class AgentControllerTests(unittest.TestCase):
    WORKCHAIN = -1

    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        work = Path(cls.work.name)
        cls.compiled = compile_contract("agent-account-code.fc", work / "agent.boc")
        rust = (ROOT / "tosctl/src/node-control/contracts/src/agent_account.rs").read_text()
        embeddings = re.findall(r'pub const AGENT_ACCOUNT_CODE_B64: &str =\s*"([^"]+)";', rust)
        assert len(embeddings) == 1
        cls.shipped = from_boc(base64.b64decode(embeddings[0]))
        assert cls.compiled.hash == cls.shipped.hash, "the shipped Rust BOC is stale"
        source = (ROOT / "crypto/smartcont/agent-account-code.fc").read_text()
        guard = "  ifnot (via_module) {\n    require_strong_controller_key(controller_pubkey);\n"
        assert source.count(guard) == 1, "stored-key signature guard must be unique"
        restored = ("  ifnot (via_module) {\n"
                    "    if (header_op == op::agent_checked_contract_call_v2) {\n"
                    "      require_strong_controller_key(controller_pubkey);\n    }\n")
        shutil.copy2(ROOT / "crypto/smartcont/auth-extension.fc", work)
        mutant = work / "agent-legacy-mutant.fc"
        mutant.write_text(source.replace(guard, restored))
        cls.mutant = compile_contract(str(mutant), work / "mutant.boc")
        receiver = work / "receiver.fc"
        receiver.write_text("() recv_internal() impure { slice s = get_data().begin_parse(); "
                            "int n = s~load_uint(32); s.end_parse(); "
                            "set_data(begin_cell().store_uint(n + 1, 32).end_cell()); }\n")
        cls.receiver = compile_contract(str(receiver), work / "receiver.boc")
        EVIDENCE.update({"shipped_code_hash": cls.shipped.hash.hex(),
                         "compiled_code_hash": cls.compiled.hash.hex(),
                         "legacy_mutant_code_hash": cls.mutant.hash.hex(),
                         "weak_encodings": len(WEAK_KEYS), "signature_checks_disabled": False,
                         "global_version": GLOBAL_VERSION, "gas_credit": CREDIT})

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def agent(self, **kwargs):
        a = Agent(kwargs.pop("code", self.shipped), self.receiver, wc=self.WORKCHAIN, **kwargs)
        self.addCleanup(a.close)
        return a

    def test_all_weak_encodings_reject_every_external_operation(self):
        for mode in (None, 1):
            for key in WEAK_KEYS:
                with self.subTest(mode=mode, key=key.hex()):
                    a = self.agent(key=key, mode=mode)
                    for op in OPERATIONS:
                        body = a.signed(a.payload(op), forged=True)
                        a.reject_external(body, 1720)
                        a.reject_external(body, 1720)
                        EVIDENCE["cases"].append({"kind": "weak-rejection", "workchain": self.WORKCHAIN,
                                                  "mode": mode or 0, "key": key.hex(),
                                                  "operation": OPERATIONS[op], "exit": 1720})

    def test_legacy_forgery_has_a_real_red_green_transfer(self):
        # The native verifier already rejects some canonical torsion encodings.
        # These accepted sign aliases prove that the contract guard is necessary.
        for key in (IDENTITY_ALIAS, ORDER2_ALIAS):
            for mode in (None, 1):
                for changed in (False, True):
                    with self.subTest(key=key.hex(), mode=mode, fixed=changed):
                        a = self.agent(code=self.shipped if changed else self.mutant, key=key, mode=mode)
                        a.prepare_receiver()
                        payload = a.payload(NATIVE)
                        if key == ORDER2_ALIAS:
                            # Bind the reduced challenge to this deployed account.
                            for expiry in range(NOW + 600, NOW + 1200):
                                payload = a.payload(NATIVE, valid_until=expiry)
                                challenge = int.from_bytes(hashlib.sha512(
                                    IDENTITY + key + a.digest(payload)).digest(), "little") % GROUP_ORDER
                                if challenge % 2 == 0:
                                    break
                            else:
                                self.fail("no deterministic order-2 challenge found")
                        a.reject_external(a.signed(a.payload(V2), forged=True), 1720)
                        body = a.signed(payload, forged=True)
                        if changed:
                            a.reject_external(body, 1720)
                        else:
                            before = a.balance
                            result = a.e.send(a.shard, external(a.address, body))
                            row = a.settle(result, before, NATIVE)
                            self.assertEqual((a.state()["seq"], a.state()["spent"]), (1, VALUE))
                            row.update({"kind": "legacy-only-mutant", "workchain": self.WORKCHAIN,
                                        "key": key.hex(), "mode": mode or 0})
                            EVIDENCE["cases"].append(row)

    def test_strong_keys_signatures_replay_and_real_action_phase(self):
        for mode in (None, 1):
            for op in OPERATIONS:
                with self.subTest(mode=mode, operation=OPERATIONS[op]):
                    a = self.agent(mode=mode, metadata=True)
                    if op not in (CANCEL, DEPLOY):
                        a.prepare_receiver()
                    payload = a.payload(op)
                    a.reject_external(a.signed(payload, secret=OTHER_SECRET), 1704)
                    before = a.balance
                    body = a.signed(payload)
                    row = a.settle(a.e.send(a.shard, external(a.address, body)), before, op)
                    self.assertEqual(a.state()["seq"], 1)
                    self.assertEqual(a.state()["spent"], 0 if op == CANCEL else VALUE)
                    a.reject_external(body, 1705)
                    row.update({"kind": "strong-action", "workchain": self.WORKCHAIN, "mode": mode or 0})
                    EVIDENCE["cases"].append(row)

    def test_owner_can_recover_every_weak_encoding_without_opening_rotation(self):
        for mode in (None, 1):
            for key in WEAK_KEYS:
                with self.subTest(mode=mode, key=key.hex()):
                    a = self.agent(key=key, mode=mode)
                    rotation = Cell().uint(0x41475002, 32).uint(0, 64).raw(PUBLIC)
                    a.send_internal(rotation, sender=a.other, expected=1702)
                    replacement = WEAK_KEYS[(WEAK_KEYS.index(key) + 1) % len(WEAK_KEYS)]
                    a.send_internal(Cell().uint(0x41475002, 32).uint(0, 64).raw(replacement),
                                    sender=a.owner, expected=1720)
                    before = a.state()
                    a.send_internal(rotation, sender=a.owner)
                    after = a.state()
                    self.assertEqual(after["key"], int.from_bytes(PUBLIC, "big"))
                    self.assertEqual((after["epoch"], after["seq"]), (1, 1))
                    for field in ("owner", "deployment_id", "day", "spent", "policy", "auth"):
                        self.assertEqual(after[field], before[field], field)
                    body = a.signed(a.payload(CANCEL))
                    a.shard = successful(a.e.send(a.shard, external(a.address, body)))
                    self.assertEqual(a.state()["seq"], 2)
                    EVIDENCE["cases"].append({"kind": "owner-recovery", "workchain": self.WORKCHAIN,
                                              "mode": mode or 0, "key": key.hex(), "epoch": 1, "seq": 2})

    def test_modules_keep_their_authority_and_hybrid_still_needs_both(self):
        for mode in (1, 2):
            for op in OPERATIONS:
                with self.subTest(mode=mode, operation=OPERATIONS[op]):
                    a = self.agent(key=IDENTITY, mode=mode)
                    a.reject_external(a.signed(a.payload(op), forged=True), 1720 if mode == 1 else 1807)
                    if op not in (CANCEL, DEPLOY):
                        a.prepare_receiver()
                    body = a.module_body(a.payload(op))
                    a.send_internal(body, sender=a.other, expected=1800)
                    before = a.balance
                    result = a.send_internal(body)
                    row = a.settle(result, before, op, inbound=1_000_000_000)
                    self.assertEqual((a.state()["seq"], a.state()["auth"][2]), (1, 1))
                    a.send_internal(body, expected=1804)
                    row.update({"kind": "module-action", "workchain": self.WORKCHAIN, "mode": mode})
                    EVIDENCE["cases"].append(row)
        for key in (IDENTITY, PUBLIC):
            a = self.agent(key=key, mode=3)
            a.reject_external(a.signed(a.payload(CANCEL), forged=key == IDENTITY), 1807)
            a.send_internal(a.module_body(a.payload(CANCEL)), expected=1808)
            a.send_internal(a.module_body(a.payload(CANCEL), secret=OTHER_SECRET), expected=1808)
            if key == PUBLIC:
                a.send_internal(a.module_body(a.payload(CANCEL), secret=SECRET))
                self.assertEqual((a.state()["seq"], a.state()["auth"][2]), (1, 1))
            else:
                a.send_internal(a.module_body(a.payload(CANCEL), secret=SECRET), expected=1808)
        a = self.agent(key=IDENTITY, mode=2)
        a.send_internal(a.module_body(Cell().uint(1, 2).addr(a.module), kind=1), expected=1806)
        a.send_internal(a.module_body(Cell().uint(3, 2).addr(a.module), kind=1), expected=1720)
        rotation = Cell().uint(0x41475002, 32).uint(0, 64).raw(PUBLIC)
        a.send_internal(rotation, sender=a.owner, expected=1807)
        a.send_internal(a.module_body(rotation, kind=2))
        self.assertEqual(a.state()["key"], int.from_bytes(PUBLIC, "big"))
        self.assertEqual((a.state()["epoch"], a.state()["seq"]), (1, 1))
        a.reject_external(a.signed(a.payload(CANCEL)), 1807)

    def test_admission_credit_with_full_policy_and_staged_auth(self):
        for mode in (None, 1):
            for op in OPERATIONS:
                with self.subTest(mode=mode, operation=OPERATIONS[op]):
                    a = self.agent(mode=mode, metadata=True)
                    message = external(a.address, a.signed(a.payload(op)))
                    def probe(credit):
                        e = Emulator.from_config(gas_config(credit))
                        try:
                            return e.send(a.shard, message)
                        finally:
                            e.close()
                    accepted = probe(CREDIT)
                    successful(accepted)
                    lo, hi = 0, CREDIT
                    while lo + 1 < hi:
                        mid = (lo + hi) // 2
                        result = probe(mid)
                        if result["success"]:
                            successful(result)
                            hi = mid
                        else:
                            self.assertIn(result.get("vm_exit_code"), (-14, 13), result)
                            lo = mid
                    successful(probe(hi))
                    self.assertFalse(probe(hi - 1)["success"])
                    row = {"workchain": self.WORKCHAIN, "mode": mode or 0,
                           "operation": OPERATIONS[op], "minimum_admission_credit": hi,
                           "supported_credit": CREDIT, "total_compute_gas": accepted["details"]["gas"]}
                    EVIDENCE["admission"].append(row)
                    print("ADMISSION", json.dumps(row, sort_keys=True))


class BasechainControllerTests(AgentControllerTests):
    WORKCHAIN = 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        for cls in (AgentControllerTests, BasechainControllerTests)
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    EVIDENCE.update({"tests_run": result.testsRun, "failures": len(result.failures),
                     "errors": len(result.errors), "success": result.wasSuccessful()})
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "results.json").write_text(json.dumps(EVIDENCE, indent=2) + "\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
