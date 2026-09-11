"""Account-level authentication tests against the native action-phase emulator.

No post-quantum algorithm is mocked or claimed: module-sender tests cover the
account authorization boundary. The separate relay test exercises an actual
signed module transaction and delivers its emitted message to the account.
"""
import os
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cells import Cell, from_boc, make_dict
from native import (ROOT, NOW, GLOBAL_ID, Emulator, compile_contract, state_init,
                    active_account, account_data, internal, external, outgoing)

SECRET = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
KEY = int.from_bytes(SECRET.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), 'big')
OTHER_SECRET = Ed25519PrivateKey.from_private_bytes(bytes([0x43]) * 32)
OWNER, MODULE, OTHER, TARGET = (-1, 17), (-1, 18), (-1, 19), (-1, 20)
AUTH = 0x41555448
DOMAIN = int('ede715a9852fbba2c3c234ed0d27329ae34d6263a82cfb6215da87c91683b471', 16)
CODES = {}
GAS = {}


def policy(maximum=5_000_000_000, daily=6_000_000_000):
    return Cell().coins(maximum).coins(daily).uint(3600, 64).uint(0, 2)


def auth_cell(mode, epoch=1, nonce=0, module=MODULE):
    return Cell().uint(mode, 2).uint(epoch, 64).uint(nonce, 64).uint(module[1], 256)


class Account:
    def __init__(self, impl, mode=None, nonce=0, epoch=1, seqno=0, module=MODULE, extensions=False, pubkey=KEY):
        self.impl, self.agent = impl, impl == 'agent'
        if self.agent:
            data = (Cell().addr(OWNER).uint(pubkey, 256).uint(5, 256).uint(0, 64)
                    .uint(seqno, 32).uint(0, 32).coins(0).ref(policy()))
        else:
            ext = make_dict({OTHER[1]: Cell().sint(-1, 1)}, 256) if extensions else None
            data = Cell().uint(1, 1).uint(seqno, 32).uint(0, 32).uint(pubkey, 256).maybe(ext)
        if mode is not None:
            data.ref(auth_cell(mode, epoch, nonce, module))
        self.address = (-1, int.from_bytes(state_init(CODES[impl], data).hash, 'big'))
        self.shard = active_account(self.address, CODES[impl], data)
        self.e = Emulator(14 if impl == 'wallet-tol' else 6)

    def close(self):
        self.e.close()

    @property
    def data(self):
        return account_data(self.shard)[0]

    def counters(self):
        s = self.data.slice()
        if self.agent:
            s.addr(); s.uint(256); s.uint(256)
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
            s.uint(321); s.maybe()
        if not s.refs:
            return 0, 0, 0, 0
        a = s.ref().slice()
        return a.uint(2), a.uint(64), a.uint(64), a.uint(256)

    def send(self, body, sender=MODULE, ext=False, expected=0, bounced=False):
        before = self.data.hash
        message = external(self.address, body) if ext else internal(sender, self.address, body, bounced=bounced)
        result = self.e.send(self.shard, message)
        if result['success']:
            details = result['details']
            actual = details['exit']
            self.shard = from_boc(result['shard_account'])
        else:
            actual = result.get('vm_exit_code')
            details = result
        assert actual == expected, f'{self.impl}: expected exit {expected}, got {details}\n{result.get("vm_log", "")[-7000:]}'
        if expected:
            assert self.data.hash == before, 'rejection must not commit authentication or account data'
        else:
            assert result['success'] and not details['aborted'], str(details)
            assert details['action'] is None or details['action']['success'], str(details)
        return result

    def request(self, kind=0, payload=None, **overrides):
        _, epoch, nonce, _ = self.auth()
        return (Cell().sint(overrides.get('global_id', GLOBAL_ID), 32)
                .addr(overrides.get('account', self.address)).uint(overrides.get('epoch', epoch), 64)
                .uint(overrides.get('nonce', nonce), 64).uint(overrides.get('valid_until', NOW + 600), 32)
                .uint(kind, 8).ref(payload if payload is not None else self.execute_payload()))

    def envelope(self, request, cosignature=None):
        return Cell().uint(AUTH, 32).ref(request).maybe(cosignature)

    def cosign(self, request, key=SECRET):
        digest = Cell().uint(0x544f532d41555448, 64).ref(request).hash
        return Cell().raw(key.sign(digest))

    def execute_payload(self, value=1_000_000_000, mode=3, operation=0x41475004):
        if self.agent:
            epoch, seq, _ = self.counters()
            payload = (Cell().uint(operation, 32).sint(GLOBAL_ID, 32).uint(epoch, 64)
                       .uint(seq, 32).uint(NOW + 600, 32))
            if operation != 0x41475005:
                payload.addr(TARGET).coins(value)
            if operation == 0x41475003:
                payload.ref(Cell().uint(123, 32))
            return payload
        message = internal(self.address, TARGET, Cell(), value)
        return Cell().uint(0x0ec3c86d, 32).uint(mode, 8).ref(Cell()).ref(message)

    def legacy_body(self, payload=None):
        if self.agent:
            payload = payload or self.execute_payload()
            digest = (Cell().uint(DOMAIN, 256).sint(GLOBAL_ID, 32).sint(self.address[0], 8)
                      .uint(self.address[1], 256).raw(payload.hash).hash)
            return Cell(''.join(f'{x:08b}' for x in SECRET.sign(digest)) + payload.bits, payload.refs)
        body = (Cell().uint(0x7369676e, 32).sint(GLOBAL_ID, 32).uint(0, 32)
                .uint(NOW+600, 32).uint(self.counters()[1], 32))
        if payload is None:
            body.maybe(self.execute_payload()).uint(0, 1)
        else:
            body.bits += payload.bits
            body.refs.extend(payload.refs)
        return Cell(body.bits + ''.join(f'{x:08b}' for x in SECRET.sign(body.hash)), body.refs)

    def configure(self, mode, module=MODULE, expected=0):
        req = self.request(1, Cell().uint(mode, 2).addr(module))
        co = self.cosign(req) if self.auth()[0] == 3 else None
        return self.send(self.envelope(req, co), expected=expected)


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        for impl, source in [('agent', 'agent-account-code.fc'), ('wallet-func', 'wallet-v5-code.fc'), ('wallet-tol', 'wallet-v5.tol')]:
            CODES[impl] = compile_contract(source, Path(cls.tmp.name) / f'{impl}.boc')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def accounts(self, **kwargs):
        for impl in CODES:
            a = Account(impl, **kwargs)
            self.addCleanup(a.close)
            yield a

    def test_legacy_success_and_real_signatures(self):
        for a in self.accounts():
            result = a.send(a.legacy_body(), ext=True)
            self.assertEqual(a.counters()[1], 1)
            self.assertEqual(len(outgoing(from_boc(result['transaction']))), 1)
            GAS[f'{a.impl}-legacy'] = result['details']['gas']
            bad = a.legacy_body()
            bad.bits = ('1' if bad.bits[0] == '0' else '0') + bad.bits[1:] if a.agent else bad.bits[:-1] + ('1' if bad.bits[-1] == '0' else '0')
            a.send(bad, ext=True, expected=1704 if a.agent else 135)

    def test_stage_and_module_confirmed_cutover(self):
        for a in self.accounts():
            if a.agent:
                body = Cell().uint(0x41475008, 32).uint(0, 64).sint(GLOBAL_ID, 32).uint(0, 64).addr(MODULE)
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
            self.assertEqual(len(outgoing(from_boc(result['transaction']))), 1)
            if a.agent:
                self.assertEqual(a.counters()[2], 1_000_000_000)
            a.send(a.envelope(request), expected=1804)
            GAS[f'{a.impl}-module'] = result['details']['gas']

    def test_each_binding_is_enforced(self):
        for a in self.accounts(mode=2):
            for field, value, error in [('global_id', 43, 1801), ('account', TARGET, 1802),
                                      ('epoch', 0, 1803), ('nonce', 1, 1804),
                                      ('valid_until', NOW, 1805), ('valid_until', NOW+3601, 1805)]:
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
            different = a.request(valid_until=NOW+601)
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
                p = policy(); body.bits += p.bits
                a.send(body, sender=OWNER, expected=1807)
                # The same management operation succeeds through the module.
                a.send(a.envelope(a.request(2, body)))
                self.assertEqual(a.auth()[2], 1)
            else:
                legacy = Cell().uint(0x6578746e, 32).uint(0, 64).uint(0, 1).uint(1, 1).uint(4, 8).uint(1, 1)
                a.send(legacy, sender=OTHER, expected=1807)
                signed = a.legacy_body()
                signed.bits = f'{0x73696e74:032b}' + signed.bits[32:]
                a.send(signed, sender=OWNER, expected=1807)
                a.configure(2)
                s = a.data.slice(); self.assertEqual(s.uint(1), 0); s.uint(320)
                self.assertIsNone(s.maybe(), 'strict mode removes old extensions')

    def test_hybrid_activation_rejects_weak_classical_keys(self):
        for key in [0, 1 << 248]:
            for a in self.accounts(mode=2, pubkey=key):
                a.configure(3, expected=1720 if a.agent else 1808)
                self.assertEqual(a.auth()[:3], (2, 1, 0))

    def test_counter_overflow_is_closed(self):
        for a in self.accounts(mode=2, nonce=(1 << 64)-1):
            a.send(a.envelope(a.request()), expected=1810)
        for a in self.accounts(mode=2, epoch=(1 << 64)-1):
            a.configure(2, expected=1810)
        for a in self.accounts(mode=2, seqno=(1 << 32)-1):
            a.send(a.envelope(a.request()), expected=1716 if a.agent else 1810)

    def test_agent_policy_still_applies(self):
        a = Account('agent', mode=2); self.addCleanup(a.close)
        a.send(a.envelope(a.request(payload=a.execute_payload(5_000_000_001))), expected=1707)
        a.send(a.envelope(a.request(payload=a.execute_payload(4_000_000_000))))
        a.send(a.envelope(a.request(payload=a.execute_payload(3_000_000_000))), expected=1707)
        a.send(a.envelope(a.request(payload=a.execute_payload(2_000_000_000))))
        self.assertEqual(a.counters()[2], 6_000_000_000)

    def test_real_module_transaction_and_hybrid_relay(self):
        module_code = compile_contract(str(ROOT / 'test/auth-extensions/test-module.fc'),
                                       Path(self.tmp.name) / 'test-module.boc')
        module_key = int.from_bytes(OTHER_SECRET.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), 'big')
        module_data = Cell().uint(module_key, 256).uint(0, 32)
        module_address = (-1, int.from_bytes(state_init(module_code, module_data).hash, 'big'))
        for a in self.accounts(mode=3, module=module_address):
            module_shard = active_account(module_address, module_code, module_data)
            request = a.request()
            envelope = a.envelope(request, a.cosign(request))
            signed = Cell().uint(0, 32).ref(envelope)
            proof = OTHER_SECRET.sign(signed.hash)
            message_body = Cell(''.join(f'{x:08b}' for x in proof) + signed.bits, signed.refs)
            invalid = Cell(''.join(f'{x:08b}' for x in SECRET.sign(signed.hash)) + signed.bits, signed.refs)
            bad = a.e.send(module_shard, external(module_address, invalid))
            self.assertFalse(bad['success'])
            self.assertEqual(bad['vm_exit_code'], 1900)
            result = a.e.send(module_shard, external(module_address, message_body))
            self.assertTrue(result['success'])
            self.assertEqual(result['details']['exit'], 0)
            self.assertFalse(result['details']['aborted'])
            emitted = outgoing(from_boc(result['transaction']))
            self.assertEqual(len(emitted), 1)
            # Deliver the exact message emitted by the module action phase;
            # do not fabricate the module's sender identity in this test.
            execution = a.e.send(a.shard, emitted[0])
            self.assertTrue(execution['success'])
            self.assertEqual(execution['details']['exit'], 0)
            self.assertFalse(execution['details']['aborted'])
            a.shard = from_boc(execution['shard_account'])
            self.assertEqual(a.auth()[2], 1)
            self.assertEqual(len(outgoing(from_boc(execution['transaction']))), 1)
            replay = a.e.send(from_boc(result['shard_account']), external(module_address, message_body))
            self.assertFalse(replay['success'])
            self.assertEqual(replay['vm_exit_code'], 1901)

    def test_agent_legacy_deploy_stays_inside_admission_credit(self):
        a = Account('agent'); self.addCleanup(a.close)
        # Minimal ordinary-cell deployment profile, matching the bounded path.
        init = state_init(Cell().uint(0, 8), Cell().uint(0, 32))
        target = (-1, int.from_bytes(init.hash, 'big'))
        payload = (Cell().uint(0x41475006, 32).sint(GLOBAL_ID, 32).uint(0, 64)
                   .uint(0, 32).uint(NOW+600, 32).addr(target).coins(1_000_000_000)
                   .ref(init).ref(Cell()))
        result = a.send(a.legacy_body(payload), ext=True)
        self.assertEqual(a.counters()[1], 1)
        self.assertEqual(len(outgoing(from_boc(result['transaction']))), 1)
        GAS['agent-legacy-deploy'] = result['details']['gas']

    def test_wallet_rejects_destruction_and_arbitrary_actions(self):
        for a in self.accounts(mode=2):
            if a.agent: continue
            for mode in [35, 7, 11, 195]:
                a.send(a.envelope(a.request(payload=a.execute_payload(mode=mode))), expected=1811)
            setcode = Cell().uint(0xad4de08e, 32).ref(Cell()).ref(Cell())
            # Invalid C5 prefix has a VM cell-underflow error; positive control
            # below proves the real action path is reached.
            a.send(a.envelope(a.request(payload=setcode)), expected=9)
            a.send(a.envelope(a.request()))


if __name__ == '__main__':
    import sys
    result = unittest.main(verbosity=2, exit=False)
    print('Measured native transaction gas:', GAS)
    sys.exit(0 if result.result.wasSuccessful() else 1)
