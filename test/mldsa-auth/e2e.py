#!/usr/bin/env python3
"""Actual v16 transactions: paid relayer -> ML-DSA module -> existing account.

No fabricated module sender, no replacement VM, no signature-ignore switch.
Normal cases change only the test config version; gas limits/prices
are left intact. One explicitly labeled destination-limit failure injection
exercises account commit semantics, not production calibration.
Public deterministic keys are TEST ONLY.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

from build_contracts import build_contracts
from protocol import (ROOT, Cell, from_boc, chain, clone, commitment, module_data,
                      submission, parse_message, Signer, CONTEXT, SUBMIT)
from native import (NOW, GLOBAL_ID, Emulator, active_account, account_data, state_init,
                    internal, external, outgoing)
import test_auth as framework

CODES = framework.CODES
MODULE_CODES = {}
SIGNER = None
MODULE_FILTER = None
EVENTS = []
TOTALS = []
FUNDING = 10_000_000_000
BALANCE = 100_000_000_000


def require_result(result, expected, before, shard, label, commits=False):
    details = result.get('details', result)
    actual = details.get('exit', result.get('vm_exit_code'))
    log = result.get('vm_log', '')[-5000:]
    if expected == 'failure':
        assert result['success'], f'{label}: expected a real rejected transaction, not an emulator error'
        assert actual != 0 and not details.get('compute_success', False), f'{label}: {details}'
    else:
        assert actual == expected, f'{label}: expected {expected}, got {details}\n{log}'
    after = account_data(shard)[0].hash
    if expected != 0 and not commits:
        assert before == after, f'{label}: rejected transaction changed persistent data'
    if expected != 0 and commits:
        assert before != after, f'{label}: committed refusal must consume account counters'
    if expected == 0:
        assert result['success'] and not details['aborted'], f'{label}: {details}'
        assert details['action'] is None or details['action']['success'], f'{label}: {details}'
    return details


def record(label, phase, result, shard):
    details = result.get('details', {})
    messages = outgoing(from_boc(result['transaction'])) if result['success'] else []
    EVENTS.append({'case': label, 'phase': phase, 'exit': details.get('exit', result.get('vm_exit_code')),
                   'gas': details.get('gas'), 'aborted': details.get('aborted'),
                   'action': details.get('action'), 'data_hash': account_data(shard)[0].hash.hex(),
                   'outgoing_hashes': [message.hash.hex() for message in messages]})


class Module:
    def __init__(self, language, workchain=-1, key=0, version=16):
        self.language, self.workchain, self.key = language, workchain, key
        self.code = MODULE_CODES[language]
        self.data = module_data(SIGNER.public_key(key), GLOBAL_ID)
        self.address = (workchain, int.from_bytes(state_init(self.code, self.data).hash, 'big'))
        self.shard = active_account(self.address, self.code, self.data, BALANCE)
        self.e = Emulator(version)

    def close(self):
        self.e.close()

    def set_version(self, version):
        last_lt = self.e.lt
        self.e.close()
        self.e = Emulator(version)
        self.e.lt = last_lt

    def signed(self, account, request=None, co=None, key=None, context=CONTEXT):
        request = request if request is not None else account.request()
        envelope = account.envelope(request, co)
        _, signature = SIGNER.sign(commitment(request), context, self.key if key is None else key)
        return submission(envelope, signature)

    def call(self, body, expected=0, value=FUNDING, label='', bounced=False, ext=False):
        before = account_data(self.shard)[0].hash
        msg = external(self.address, body) if ext else internal(
            (self.workchain, 17), self.address, body, value, bounced)
        result = self.e.send(self.shard, msg)
        if result['success']:
            self.shard = from_boc(result['shard_account'])
        require_result(result, expected, before, self.shard, label)
        assert account_data(self.shard)[0].hash == self.data.hash, 'module must remain immutable'
        record(label, 'module', result, self.shard)
        messages = outgoing(from_boc(result['transaction'])) if result['success'] else []
        if expected != 0:
            assert not messages, 'non-bouncing rejection must not emit AUTH or spend reserve'
        return result, messages


class Pair:
    def __init__(self, language, impl, workchain=-1, mode=2):
        self.module = Module(language, workchain)
        self.account = framework.Account(impl, mode=mode, module=self.module.address)
        a = self.account
        data = a.data
        a.e.close()
        a.e = Emulator(16)
        a.address = (workchain, int.from_bytes(state_init(CODES[impl], data).hash, 'big'))
        a.shard = active_account(a.address, CODES[impl], data, BALANCE)
        self.label = f'{language}/{impl}/wc{workchain}'
        self.limit_injection = False

    def close(self):
        self.module.close()
        self.account.close()

    def deliver(self, message, expected=0, label='', envelope=None, commits=False):
        a = self.account
        wire = parse_message(message)
        assert wire['destination'] == a.address
        assert wire['sender'] == self.module.address, 'VM must supply the actual module source'
        assert not wire['bounced'] and wire['bounce'] == 1
        assert 0 < wire['value'] < FUNDING
        if envelope is not None:
            assert wire['body'].hash == envelope.hash, 'relay must preserve the exact AUTH body'
        before = a.data.hash
        # Each instance must execute after the actual emitted message's LT.
        a.e.lt = max(a.e.lt, wire['created_lt'])
        # CRITICAL: deliver the exact message returned by the module action phase.
        result = a.e.send(a.shard, message)
        if result['success']:
            a.shard = from_boc(result['shard_account'])
        details = require_result(result, expected, before, a.shard, label, commits=commits)
        record(label, 'account', result, a.shard)
        if expected:
            for out in outgoing(from_boc(result['transaction'])):
                assert parse_message(out)['bounced'], 'rejection may bounce, but must not transfer assets'
        return result, details

    def execute(self, body, account_exit=0, label='', commits=False):
        module_before = account_data(self.module.shard)[1]
        mr, messages = self.module.call(body, label=label)
        assert len(messages) == 1, 'successful module must emit exactly one message'
        assert account_data(self.module.shard)[1] >= module_before, 'relay spent pre-existing reserve'
        ar, ad = self.deliver(messages[0], account_exit, label, body.refs[0], commits=commits)
        TOTALS.append({'case': label, 'module_gas': mr['details']['gas'], 'account_gas': ad['gas'],
                       'total_compute_gas': mr['details']['gas'] + ad['gas'],
                       'relay_value': parse_message(messages[0])['value'], 'funding': FUNDING,
                       'account_exit': account_exit, 'limit_injection': self.limit_injection})
        return mr, ar, messages[0]


class MldsaAuthTests(unittest.TestCase):
    def pairs(self, mode=2, workchains=(-1, 0)):
        for language in MODULE_CODES:
            if MODULE_FILTER and MODULE_FILTER != language:
                continue
            for impl in CODES:
                for wc in workchains:
                    p = Pair(language, impl, wc, mode)
                    self.addCleanup(p.close)
                    yield p

    def label(self, pair, suffix=''):
        return f'{self._testMethodName}/{pair.label}/{suffix}'

    def assert_transfer(self, pair, result):
        messages = outgoing(from_boc(result['transaction']))
        self.assertEqual(len(messages), 1)
        transfer = parse_message(messages[0])
        self.assertEqual(transfer['sender'], pair.account.address)
        self.assertEqual(transfer['destination'], framework.TARGET)
        self.assertEqual(transfer['value'], 1_000_000_000)
        self.assertFalse(transfer['bounced'])

    def test_valid_signature_and_exact_relay_then_account_replay(self):
        for p in self.pairs():
            a = p.account
            body = p.module.signed(a)
            _, result, _ = p.execute(body, label=self.label(p, 'accepted'))
            self.assert_transfer(p, result)
            self.assertEqual(a.auth()[2], 1)
            self.assertEqual(a.counters()[1], 1)
            if a.agent:
                self.assertEqual(a.counters()[2], 1_000_000_000)
            p.execute(body, 1804, self.label(p, 'replay'))
            self.assertEqual(a.auth()[2], 1)
            self.assertEqual(a.counters()[1], 1)

    def test_bad_pq_signatures_keys_context_and_encoding(self):
        for p in self.pairs():
            a, m = p.account, p.module
            req = a.request()
            good = m.signed(a, req)
            self.assertEqual(len(SIGNER.public_key()), 1312)
            _, sig = SIGNER.sign(commitment(req))
            damaged = bytearray(sig); damaged[len(sig) // 2] ^= 1
            cases = [
                ('bad-signature', submission(a.envelope(req), bytes(damaged)), 1808),
                ('wrong-key', m.signed(a, req, key=1), 1808),
                ('wrong-context', m.signed(a, req, context=b'wrong-context'), 1808),
                ('empty-signature', Cell().uint(SUBMIT, 32).uint(0, 64).ref(a.envelope(req)).ref(Cell()), 9),
                ('noncanonical-chain', Cell().uint(SUBMIT, 32).uint(0, 64).ref(a.envelope(req))
                 .ref(Cell().raw(sig[:126]).ref(chain(sig[126:]))), 9),
                ('trailing-body-bit', Cell(good.bits + '0', good.refs), 9),
            ]
            for name, body, expected in cases:
                m.call(body, expected, label=self.label(p, name))
                self.assertEqual(a.auth()[2], 0)
            p.execute(good, label=self.label(p, 'positive-control'))

    def test_every_request_field_and_payload_are_authenticated(self):
        for p in self.pairs():
            a, m = p.account, p.module
            request = a.request()
            _, sig = SIGNER.sign(commitment(request))
            changed_payload = clone(a.execute_payload())
            changed_payload.bits = changed_payload.bits[:-1] + ('0' if changed_payload.bits[-1] == '1' else '1')
            cases = [
                ('account', a.request(account=(m.workchain, 99)), 1808),
                ('epoch', a.request(epoch=2), 1808),
                ('nonce', a.request(nonce=1), 1808),
                ('expiry', a.request(valid_until=NOW + 601), 1808),
                ('kind', a.request(kind=2), 1808),
                ('payload', a.request(payload=changed_payload), 1808),
                ('network', a.request(global_id=GLOBAL_ID + 1), 1801),
            ]
            for name, changed, error in cases:
                m.call(submission(a.envelope(changed), sig), error, label=self.label(p, name))
            p.execute(m.signed(a), label=self.label(p, 'positive-control'))

    def test_signed_stale_epoch_nonce_and_expiry(self):
        for p in self.pairs():
            a, m = p.account, p.module
            for field, value, error in [('epoch', 0, 1803), ('nonce', 1, 1804)]:
                p.execute(m.signed(a, a.request(**{field: value})), error, self.label(p, field))
                self.assertEqual(a.auth()[2], 0)
            for target in (m.address, (0 if m.workchain == -1 else -1, 99)):
                m.call(m.signed(a, a.request(account=target)), 1809, label=self.label(p, 'invalid-target-' + str(target[0])))
            for until in (NOW, NOW + 3601):
                m.call(m.signed(a, a.request(valid_until=until)), 1805, label=self.label(p, str(until)))
            body = m.signed(a)
            _, messages = m.call(body, label=self.label(p, 'before-expiry'))
            self.assertEqual(len(messages), 1)
            a.e.lib.transaction_emulator_set_unixtime(a.e.ptr, NOW + 601)
            p.deliver(messages[0], 1805, self.label(p, 'expired-in-transit'))
            self.assertEqual(a.auth()[2], 0)

    def test_hybrid_requires_both_signatures_on_the_same_request(self):
        for p in self.pairs(mode=3):
            a, m = p.account, p.module
            req = a.request()
            for name, co in [('missing', None), ('wrong-key', a.cosign(req, framework.OTHER_SECRET)),
                             ('mixed-request', a.cosign(a.request(valid_until=NOW + 601)))]:
                p.execute(m.signed(a, req, co), 1808, self.label(p, name))
                self.assertEqual(a.auth()[2], 0)
            m.call(m.signed(a, req, a.cosign(req), key=1), 1808, label=self.label(p, 'valid-ed-bad-pq'))
            a.send(a.legacy_body(), ext=True, expected=1807)
            _, result, _ = p.execute(m.signed(a, req, a.cosign(req)), label=self.label(p, 'both-valid'))
            self.assert_transfer(p, result)
            self.assertEqual(a.auth()[2], 1)

    def test_authenticated_rotation_and_no_classical_downgrade(self):
        for p in self.pairs():
            a, old = p.account, p.module
            new = Module(old.language, old.workchain, key=1)
            self.addCleanup(new.close)
            stale = a.request()
            cfg = a.request(1, Cell().uint(2, 2).addr(new.address))
            p.execute(old.signed(a, cfg), label=self.label(p, 'rotate'))
            self.assertEqual(a.auth(), (2, 2, 0, new.address[1]))
            p.execute(old.signed(a, stale), 1800, self.label(p, 'old-module'))
            self.addCleanup(old.close)
            p.module = new
            p.execute(new.signed(a, stale), 1803, self.label(p, 'old-epoch-new-module'))
            downgrade = a.request(1, Cell().uint(1, 2).addr(new.address))
            p.execute(new.signed(a, downgrade), 1806, self.label(p, 'downgrade'))
            new.call(new.signed(a, key=0), 1808, label=self.label(p, 'old-key'))
            _, result, _ = p.execute(new.signed(a), label=self.label(p, 'new-key'))
            self.assert_transfer(p, result)
            self.assertEqual(a.auth()[:3], (2, 2, 1))
            a.send(a.legacy_body(), ext=True, expected=1807)

    def test_legacy_stage_then_pq_confirmed_strict_cutover(self):
        for p in self.pairs(mode=None, workchains=(-1,)):
            a, m = p.account, p.module
            if a.agent:
                stage = Cell().uint(0x41475008, 32).uint(0, 64).sint(GLOBAL_ID, 32).uint(0, 64).addr(m.address)
                a.send(stage, sender=framework.OWNER)
            else:
                actions = Cell().uint(0, 1).uint(1, 1).uint(5, 8).uint(0, 64).addr(m.address)
                a.send(a.legacy_body(actions), ext=True)
            self.assertEqual(a.auth()[:3], (1, 1, 0))
            cfg = a.request(1, Cell().uint(2, 2).addr(m.address))
            p.execute(m.signed(a, cfg), label=self.label(p, 'cutover'))
            self.assertEqual(a.auth()[:3], (2, 2, 0))
            a.send(a.legacy_body(), ext=True, expected=1807)
            _, result, _ = p.execute(m.signed(a), label=self.label(p, 'strict-execution'))
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
            p.execute(m.signed(a, bad), error, self.label(p, 'policy-refused'))
            self.assertEqual(a.auth()[2], 0)
            self.assertEqual(a.counters()[1], 0)
            self.assertEqual(a.counters()[2], 0)
            _, result, _ = p.execute(m.signed(a), label=self.label(p, 'allowed-transfer'))
            self.assert_transfer(p, result)

    def test_agent_post_accept_refusal_consumes_nonce_without_transfer(self):
        for language in MODULE_CODES:
            if MODULE_FILTER and MODULE_FILTER != language:
                continue
            for wc in (-1, 0):
                p = Pair(language, 'agent', wc)
                self.addCleanup(p.close)
                a, m = p.account, p.module
                # Destination-only failure injection, not calibration or network configuration.
                a.e.close()
                a.e = Emulator(16, max_msg_cells=0)
                p.limit_injection = True
                req = a.request(payload=a.execute_payload(operation=0x41475003))
                body = m.signed(a, req)
                _, result, _ = p.execute(body, 1713, self.label(p, 'committed-refusal'), commits=True)
                self.assertFalse(result['details']['aborted'])
                self.assertEqual(len(outgoing(from_boc(result['transaction']))), 0)
                self.assertEqual(a.counters()[2], 0)
                self.assertEqual(a.auth()[2], 1)
                self.assertEqual(a.counters()[1], 1)
                p.execute(body, 1804, self.label(p, 'consumed-replay'))

    def test_funding_bounce_and_version_gates(self):
        for p in self.pairs():
            m, a = p.module, p.account
            body = m.signed(a)
            m.call(body, 'failure', value=1000, label=self.label(p, 'underfunded'))
            _, out = m.call(body, bounced=True, label=self.label(p, 'bounce'))
            self.assertFalse(out)
            _, out = m.call(Cell(), label=self.label(p, 'top-up'))
            self.assertFalse(out)
            m.call(body, 1900, ext=True, label=self.label(p, 'external-rejected'))
            m.set_version(15)
            m.call(body, 6, label=self.label(p, 'v15-rejected'))
            m.set_version(16)
            p.execute(body, label=self.label(p, 'v16-positive-control'))


def main():
    global SIGNER, MODULE_FILTER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--signer', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--module', choices=('func', 'tol'))
    parser.add_argument('--case', choices=sorted(n for n in dir(MldsaAuthTests) if n.startswith('test_')))
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    MODULE_FILTER = args.module
    os.environ.update(FUNC_PATH=str(build / 'crypto/func'), FIFT_PATH=str(build / 'crypto/fift'),
                      TOL_PATH=str(build / 'tol/tol'), EMULATOR_PATH=str(build / 'emulator/libemulator.so'))
    build_contracts(build, out)
    SIGNER = Signer(args.signer)
    for impl in ('wallet-func', 'wallet-tol', 'agent'):
        CODES[impl] = from_boc((out / f'{impl}.boc').read_bytes())
    for language in ('func', 'tol'):
        MODULE_CODES[language] = from_boc((out / f'module-{language}.boc').read_bytes())
    suite = (unittest.TestSuite([MldsaAuthTests(args.case)]) if args.case
             else unittest.defaultTestLoader.loadTestsFromTestCase(MldsaAuthTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    (out / 'e2e.json').write_text(json.dumps({'success': result.wasSuccessful(), 'events': EVENTS},
                                           indent=2, sort_keys=True) + '\n')
    (out / 'gas.json').write_text(json.dumps({'units': 'gas; values are raw nanotomis',
                                           'network_activation': False, 'transactions': TOTALS},
                                          indent=2, sort_keys=True) + '\n')
    print('E2E_ASSERTION_FAILURE' if result.failures else 'E2E_NO_ASSERTION_FAILURE')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
