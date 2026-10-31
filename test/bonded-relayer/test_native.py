"""BR1 native transaction tests; real ML-DSA-44, compute and action phases.

Synthetic internal senders exercise the actor's authorization boundary; they are
not a claim that a synthetic address can sign a production wallet transaction.
Missing native dependencies are errors, never green skips.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/pq-contracts"))
import pqtest  # noqa: E402
from cells import Cell, from_boc  # noqa: E402
from native import (  # noqa: E402
    GLOBAL_ID, NOW, Emulator, account_data, active_account, internal, outgoing, state_init,
)

COIN = 10**9
OWNER, WORKER, REPORTER, OTHER = [(0, n) for n in (101, 102, 103, 104)]
ACTIVATE, STAKE, RETIRE, WITHDRAW, METADATA, SLASH = range(0x42520001, 0x42520007)
CONTEXT = b"TOS-BONDED-RELAYER-v1"
DELAY = 90000
CODE = None
SOURCE = Path(os.environ.get("RELAYER_SOURCE", ROOT / "crypto/smartcont/relayer-bond-code.fc"))


def initial(config, phase=0, principal=0):
    return (Cell().uint(phase, 3).coins(principal).uint(0, 32).uint(0, 32)
            .uint(0, 32).uint(0, 256).uint(0, 256).ref(config))


def header(op):
    return Cell().uint(op, 32).uint(0, 64)


def state(data):
    s = data.slice()
    return {"phase": s.uint(3), "principal": s.coins(), "activated": s.uint(32),
            "requested": s.uint(32), "after": s.uint(32), "metadata": s.uint(256),
            "evidence": s.uint(256)}


class Bond:
    def __init__(self, key=17, salt=1, network=GLOBAL_ID, phase=0, principal=0, balance=COIN,
                 delay=DELAY, minimum=10 * COIN, reserve=COIN):
        self.key = key
        identity = Cell().uint(0x111, 256).uint(0x222, 256).uint(0, 256)
        policy = Cell().coins(minimum).coins(reserve).uint(delay, 32)
        self.config = (Cell().sint(network, 32).uint(salt, 256).addr(OWNER).addr(WORKER)
                       .ref(pqtest.stored(pqtest.public_key(key))).ref(identity).ref(policy))
        data = initial(self.config, phase, principal)
        self.address = (0, int.from_bytes(state_init(CODE, data).hash, "big"))
        self.shard = active_account(self.address, CODE, data, balance=balance)
        self.e, self.now = Emulator(), NOW

    def close(self):
        self.e.close()

    @property
    def data(self):
        return account_data(self.shard)[0]

    @property
    def state(self):
        return state(self.data)

    def advance(self, seconds):
        self.now += seconds
        self.e.lib.transaction_emulator_set_unixtime(self.e.ptr, self.now)

    def digest(self, tag, payload=0, network=GLOBAL_ID, address=None):
        return (Cell().uint(tag, 32).sint(network, 32).addr(address or self.address)
                .uint(int.from_bytes(self.config.hash, "big"), 256).uint(payload, 256).hash)

    def signature(self, digest, key=None, context=CONTEXT):
        return pqtest.stored(pqtest.sign(self.key if key is None else key, digest, context))

    def activate(self, amount=10 * COIN, **kw):
        sig = self.signature(self.digest(0x42524150))
        return self.send(header(ACTIVATE).coins(amount).ref(sig), value=amount + 3 * COIN, **kw)

    def acceptance(self, slot=1, intent=123, issued=None, until=None, body_hash=234):
        issued = self.now if issued is None else issued
        until = issued + 300 if until is None else until
        return (Cell().uint(slot, 64).uint(issued, 32).uint(until, 32).uint(intent, 256)
                .ref(Cell().uint(body_hash, 256).uint(345, 256).uint(456, 256)))

    def proof(self, a, b, key_a=None, key_b=None, context=CONTEXT):
        sig_a = self.signature(self.digest(0x42524143, int.from_bytes(a.hash, "big")), key_a, context)
        sig_b = self.signature(self.digest(0x42524143, int.from_bytes(b.hash, "big")), key_b, context)
        return header(SLASH).ref(a).ref(sig_a).ref(b).ref(sig_b)

    def send(self, body, sender=OWNER, value=3 * COIN, expected=0, bounced=False):
        before = self.data.hash
        result = self.e.send(self.shard, internal(sender, self.address, body, value, bounced))
        details = pqtest.details_of(result)
        self.shard = from_boc(result["shard_account"])
        assert details["exit"] == expected, (
            f"expected {expected}, got {details}\n{result.get('vm_log', '')[-7000:]}"
        )
        messages = outgoing(from_boc(result["transaction"]))
        if expected:
            assert self.data.hash == before, "refusal changed state"
            assert not messages, "refusal emitted an outgoing message"
        else:
            assert not details["aborted"], details
            assert details["action"] is None or details["action"]["success"], details
        return messages, details


class BondTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CODE
        for key in ("FUNC_PATH", "FIFT_PATH", "EMULATOR_PATH", "PQ_TEST_SIGNER"):
            if not os.environ.get(key):
                raise RuntimeError(f"{key} required; native tests may not be skipped")
        cls.tmp = tempfile.TemporaryDirectory(prefix="bonded-relayer-")
        try:
            CODE = pqtest.compile_source(SOURCE, Path(cls.tmp.name) / "bond.boc")
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"compile failure: {exc.stderr!r}") from exc

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def bond(self, **kw):
        b = Bond(**kw)
        self.addCleanup(b.close)
        return b

    def test_permissionless_activation_requires_real_worker_possession(self):
        for salt, key in ((1, 17), (2, 18)):
            b = self.bond(salt=salt, key=key)
            _, details = b.activate()
            self.assertEqual(details["verifications"], 1)
            self.assertEqual(b.state["phase"], 1)
            self.assertEqual(b.state["principal"], 10 * COIN)

    def test_owner_authority(self):
        b = self.bond()
        b.activate(sender=OTHER, expected=2401)
        b.activate()
        for body in (header(STAKE).coins(COIN), header(RETIRE), header(METADATA).uint(9, 256)):
            b.send(body, sender=OTHER, expected=2401)

    def test_invalid_possession_signature(self):
        b = self.bond()
        signature = b.signature(b.digest(0x42524150), key=18)
        b.send(header(ACTIVATE).coins(10 * COIN).ref(signature), value=13 * COIN, expected=2406)

    def test_forged_initial_state_is_not_a_bond(self):
        b = self.bond(phase=1, principal=1000 * COIN, balance=2000 * COIN)
        b.send(header(RETIRE), expected=2405)

    def test_network_is_live_not_deployer_claim(self):
        b = self.bond(network=GLOBAL_ID + 1)
        b.activate(expected=2410)

    def test_policy_cannot_shorten_challenge_period(self):
        b = self.bond(delay=300)
        b.activate(expected=2404)

    def test_minimum_and_explicit_principal(self):
        b = self.bond()
        b.activate(amount=COIN, expected=2404)
        b.activate()
        b.send(header(STAKE).coins(COIN))
        self.assertEqual(b.state["principal"], 11 * COIN)
        b.send(Cell(), sender=OTHER, value=5 * COIN)
        self.assertEqual(b.state["principal"], 11 * COIN)

    def test_message_must_fund_principal_plus_compute(self):
        b = self.bond(balance=1000 * COIN)
        signature = b.signature(b.digest(0x42524150))
        b.send(header(ACTIVATE).coins(10 * COIN).ref(signature), value=10 * COIN, expected=2403)

    def test_early_exit_and_repeated_exit(self):
        b = self.bond()
        b.activate()
        b.send(header(WITHDRAW), expected=2402)
        b.send(header(RETIRE))
        b.send(header(WITHDRAW), expected=2408)
        b.send(header(RETIRE), expected=2402)
        b.send(header(STAKE).coins(COIN), expected=2402)
        b.advance(DELAY)
        messages, _ = b.send(header(WITHDRAW))
        self.assertEqual(len(messages), 1)
        self.assertEqual(b.state["phase"], 3)
        self.assertEqual(b.state["principal"], 0)
        b.send(header(WITHDRAW), expected=2402)
        b.activate(expected=2402)

    def test_real_equivocation_is_permissionlessly_slashed(self):
        b = self.bond()
        b.activate()
        a, c = b.acceptance(), b.acceptance(intent=124)
        messages, details = b.send(b.proof(a, c), sender=REPORTER)
        self.assertEqual(details["verifications"], 2)
        self.assertFalse(messages)
        self.assertEqual(b.state["phase"], 4)
        self.assertNotEqual(b.state["evidence"], 0)
        b.send(header(WITHDRAW), expected=2402)
        b.send(b.proof(a, c), sender=REPORTER, expected=2402)
        b.activate(expected=2402)

    def test_identical_statement_is_not_equivocation(self):
        b = self.bond()
        b.activate()
        a = b.acceptance()
        b.send(b.proof(a, a), sender=REPORTER, expected=2407)

    def test_different_slots_are_not_equivocation(self):
        b = self.bond()
        b.activate()
        b.send(b.proof(b.acceptance(), b.acceptance(slot=2, intent=124)),
               sender=REPORTER, expected=2407)

    def test_invalid_evidence_signature_and_context(self):
        b = self.bond()
        b.activate()
        a, c = b.acceptance(), b.acceptance(intent=124)
        for body in (b.proof(a, c, key_a=18), b.proof(a, c, key_b=18),
                     b.proof(a, c, context=b"not-the-acceptance-domain")):
            b.send(body, sender=REPORTER, expected=2406)

    def test_other_bond_evidence_cannot_be_replayed(self):
        a, b = self.bond(salt=1), self.bond(salt=2)
        a.activate()
        b.activate()
        proof = a.proof(a.acceptance(), a.acceptance(intent=124))
        b.send(proof, sender=REPORTER, expected=2406)

    def test_retirement_preserves_slash_liability(self):
        b = self.bond()
        b.activate()
        proof = b.proof(b.acceptance(), b.acceptance(intent=124))
        b.send(header(RETIRE))
        b.advance(1)
        b.send(proof, sender=REPORTER)
        self.assertEqual(b.state["phase"], 4)
        b.advance(DELAY)
        b.send(header(WITHDRAW), expected=2402)

    def test_future_pre_activation_and_expired_evidence(self):
        b = self.bond()
        b.activate()
        for issued in (b.now + 1, b.now - 1):
            b.send(b.proof(b.acceptance(issued=issued), b.acceptance(issued=issued, intent=124)),
                   sender=REPORTER, expected=2407)
        proof = b.proof(b.acceptance(), b.acceptance(intent=124))
        b.advance(86401)
        b.send(proof, sender=REPORTER, expected=2407)

    def test_acceptance_after_retirement_is_not_admitted(self):
        b = self.bond()
        b.activate()
        b.send(header(RETIRE))
        b.advance(1)
        b.send(b.proof(b.acceptance(), b.acceptance(intent=124)), sender=REPORTER, expected=2407)

    def test_metadata_cannot_replace_worker_or_erase_evidence(self):
        b = self.bond()
        b.activate()
        proof = b.proof(b.acceptance(), b.acceptance(intent=124))
        b.send(header(METADATA).uint(789, 256))
        b.send(proof, sender=REPORTER)
        b.send(header(METADATA).uint(0, 256), expected=2402)

    def test_bounced_messages_do_not_mutate(self):
        b = self.bond()
        b.activate()
        before = b.data.hash
        b.send(header(RETIRE), bounced=True)
        self.assertEqual(b.data.hash, before)

    def test_live_backing_not_nominal_record_controls_eligibility(self):
        b = self.bond()
        b.activate()
        code, values = pqtest.get_method(CODE, b.data, b.address, "get_relayer_bond", balance=2 * COIN)
        self.assertEqual(code, 0)
        self.assertEqual(values[1], 10 * COIN)
        self.assertEqual(values[2], COIN)
        self.assertEqual(values[3], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
