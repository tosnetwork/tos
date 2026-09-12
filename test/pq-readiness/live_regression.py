#!/usr/bin/env python3
"""Every account type and both authorization paths, on a chain that produces blocks.

`live_relay.py` drives the relayer lifecycle in depth on one shape: a FunC
wallet in PQ-only mode. This covers the other axis -- Wallet V5 and Agent
Account, classical and post-quantum -- so that a change to either contract, to
the module, or to the VM is caught on a real chain rather than only in the
emulator.

Four transfers must succeed and four refusals must hold. The refusals are not
decoration: a run where everything succeeds says nothing about whether a
signature is checked, so the same message is also sent with a signature that
should not be accepted, and the target must not move.

Opt-in. It needs a chain, started at a global version that has the instruction:

    TOS_GLOBAL_VERSION=16 uv run python scripts/localnet-jsonrpc.py --validators 1 \\
      --rpc 127.0.0.1:18545 --control 127.0.0.1:18745 --base-port 19000 \\
      --workdir test/integration/.localnet-reg

Every key it uses is public test material generated on the spot.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'test/tostester/src'), str(ROOT/'test/mldsa-auth'),
                str(ROOT/'test/auth-extensions'), str(ROOT/'test/pq-readiness')]

import nacl.signing
from pytosiq_core import Address, Builder, Cell, ExternalMsgInfo, MessageAny

from contract import (AgentAccount, AgentAccountBlueprint, AgentAccountState, AgentPolicy,
                      AuthState, Mldsa44ModuleBlueprint, NativeMldsa44Signer,
                      WalletV5, WalletV5Blueprint, WalletV5State)
from contract.agent_account import CONTROLLER_DOMAIN
from contract.pq_auth import network_id
from contract.pq_lite_transport import LiteClientTransport
from contract.pq_relayer import AttemptJournal, LOSS_ACK, PqRelayer
from live_chain import funded_payer, wait_for

VALUE = 1_000_000_000
# Fees come out of the message value, so the target receives slightly less.
TOLERANCE = 10_000_000
FUNDING_CAP = 3_000_000_000
KINDS = ('wallet-func', 'agent')


def source_commit() -> str:
    """Bind a report to the tree that produced it."""
    return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


class Tampered:
    """The same key and commitment, with one bit of the proof flipped."""

    def __init__(self, inner):
        self.inner = inner

    def public_key(self) -> bytes:
        return self.inner.public_key()

    def sign(self, commitment: bytes) -> bytes:
        broken = bytearray(self.inner.sign(commitment))
        broken[100] ^= 1
        return bytes(broken)


class Harness:
    def __init__(self, transport, network, payer, code, out):
        self.tr, self.net, self.payer, self.code, self.out = transport, network, payer, code, out
        self.results = []

    def record(self, case, ok, **detail):
        self.results.append(dict(case=case, ok=bool(ok), **detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {case}  {detail}", flush=True)

    # ---- account shapes --------------------------------------------------

    def blueprint(self, kind, key, auth=None):
        if kind == 'agent':
            return AgentAccountBlueprint(
                self.code['agent'], 0, self.net, self.payer.address, key.verify_key.encode(),
                os.urandom(32), AgentPolicy(2_000_000_000, 4_000_000_000), auth, key)
        return WalletV5Blueprint(self.code['wallet-func'], 0, self.net,
                                 key.verify_key.encode(), auth=auth, key=key)

    def view(self, kind, address, key):
        return (AgentAccount(None, address, self.net, key) if kind == 'agent'
                else WalletV5(None, address, self.net, key))

    def state(self, kind, address):
        cell = Cell.one_from_boc(self.tr.account_data(address).boc())
        return AgentAccountState.parse(cell) if kind == 'agent' else WalletV5State.parse(cell)

    def payload(self, kind, view, state, target, valid_until):
        return (view.transfer_payload(state, target, VALUE, valid_until) if kind == 'agent'
                else view.transfer_payload(target, VALUE))

    def deploy(self, kind, key, auth=None, value=8_000_000_000):
        blueprint = self.blueprint(kind, key, auth)
        asyncio.run(self.tr.deploy(blueprint, value))
        return blueprint

    # ---- classical -------------------------------------------------------

    def classical(self, kind, target):
        key = nacl.signing.SigningKey(os.urandom(32))
        blueprint = self.deploy(kind, key, value=6_000_000_000)
        state = self.state(kind, blueprint.address)
        view = self.view(kind, blueprint.address, key)
        before = self.tr.balance(target)
        _, now = self.tr.head()
        payload = self.payload(kind, view, state, target, now + 600)
        body = (view.sign(payload, state) if kind == 'agent'
                else view.sign(payload, state, now + 600))
        self.tr.broadcast_external(MessageAny(
            info=ExternalMsgInfo(None, blueprint.address, 0), init=None, body=body).serialize())
        moved = wait_for(lambda: (self.tr.balance(target) - before) or None,
                         f'{kind} classical transfer arrived')
        after = self.state(kind, blueprint.address)
        self.record(f'classical/{kind}',
                    VALUE - TOLERANCE <= moved <= VALUE and after.seqno == state.seqno + 1,
                    moved=moved, seqno=after.seqno)
        return blueprint, key, view

    def classical_wrong_key(self, kind, target):
        """A structurally perfect message signed by a key the account does not know.

        Rebuilding the exact signed preimage keeps the message well formed, so a
        refusal can only come from the signature check and never from a
        malformed file -- which is what a flipped byte in the BOC would produce.
        """
        key = nacl.signing.SigningKey(os.urandom(32))
        blueprint = self.deploy(kind, key, value=5_000_000_000)
        state = self.state(kind, blueprint.address)
        view = self.view(kind, blueprint.address, key)
        _, now = self.tr.head()
        payload = self.payload(kind, view, state, target, now + 600)
        wrong = nacl.signing.SigningKey(os.urandom(32))
        if kind == 'agent':
            digest = (Builder().store_bytes(CONTROLLER_DOMAIN)
                      .store_int(network_id(self.net), 32).store_int(blueprint.address.wc, 8)
                      .store_bytes(blueprint.address.hash_part)
                      .store_bytes(payload.hash).end_cell().hash)
            body = Builder().store_bytes(wrong.sign(digest).signature).store_cell(payload).end_cell()
        else:
            inner = (Builder().store_uint(0x7369676e, 32).store_int(network_id(self.net), 32)
                     .store_uint(state.wallet_id, 32).store_uint(now + 600, 32)
                     .store_uint(state.seqno, 32).store_maybe_ref(payload)
                     .store_uint(0, 1).end_cell())
            body = (Builder().store_cell(inner)
                    .store_bytes(wrong.sign(inner.hash).signature).end_cell())
        before = self.tr.balance(target)
        refused_at_node = False
        try:
            self.tr.broadcast_external(MessageAny(
                info=ExternalMsgInfo(None, blueprint.address, 0), init=None, body=body).serialize())
        except Exception:
            # The node runs the contract before accepting an external message,
            # so a rejected signature surfaces here rather than as a transaction.
            refused_at_node = True
        time.sleep(14)
        after = self.state(kind, blueprint.address)
        moved = self.tr.balance(target) - before
        self.record(f'classical-wrong-key/{kind}',
                    moved == 0 and after.seqno == state.seqno,
                    moved=moved, seqno_advanced=after.seqno - state.seqno,
                    refused_at_node=refused_at_node)

    # ---- post-quantum ----------------------------------------------------

    def post_quantum(self, kind, target, module, signer):
        key = nacl.signing.SigningKey(os.urandom(32))
        blueprint = self.deploy(kind, key, AuthState(2, 1, 0, module.address.hash_part))
        registered = self.tr.read_auth(blueprint.address)
        if registered.mode != 2 or registered.module_hash != module.address.hash_part:
            raise SystemExit(f'{kind} came up without the strict authentication root')
        state = self.state(kind, blueprint.address)
        view = self.view(kind, blueprint.address, key)
        _, now = self.tr.head()
        request = view.pq_request(state, self.payload(kind, view, state, target, now + 900), now + 900)
        relayer = PqRelayer(self.tr, AttemptJournal(self.out/f'{kind}.db'), FUNDING_CAP)

        # Refusal first. A tampered proof must be rejected on chain without the
        # target moving and without the nonce being spent, or "accepted" below
        # would mean nothing.
        before = self.tr.balance(target)
        bad = asyncio.run(relayer.submit(request, module.address, Tampered(signer), LOSS_ACK))
        rejection = wait_for(
            lambda: (lambda r: r if r.status == 'module_rejected' else None)(
                asyncio.run(relayer.reconcile(request, module.address, bad))),
            f'{kind} tampered proof rejected')
        stalled = self.tr.read_auth(blueprint.address).nonce
        self.record(f'pq-tampered/{kind}',
                    self.tr.balance(target) == before and stalled == registered.nonce,
                    moved=self.tr.balance(target) - before, nonce=stalled,
                    module_tx=rejection.module_transaction)
        # The module rejected it, so the nonce was never consumed and may be
        # authorized again -- but only through an explicit retire on a receipt.
        asyncio.run(relayer.retire(request, module.address, bad))

        broadcast = asyncio.run(relayer.submit(request, module.address, signer, LOSS_ACK))
        receipt = wait_for(
            lambda: (lambda r: r if r.status == 'executed' else None)(
                asyncio.run(relayer.reconcile(request, module.address, broadcast))),
            f'{kind} relayed request executed')
        moved = self.tr.balance(target) - before
        after = self.tr.read_auth(blueprint.address)
        self.record(f'pq/{kind}',
                    VALUE - TOLERANCE <= moved <= VALUE and after.nonce == registered.nonce + 1,
                    moved=moved, nonce=after.nonce, module_tx=receipt.module_transaction,
                    account_tx=receipt.account_transaction)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--lite-client', type=Path, required=True)
    parser.add_argument('--lite-config', type=Path, required=True)
    parser.add_argument('--key-tool', type=Path, required=True)
    parser.add_argument('--control', default='127.0.0.1:18745')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ.update(FUNC_PATH=str(build/'crypto/func'), FIFT_PATH=str(build/'crypto/fift'),
                      TOL_PATH=str(build/'tol/tol'))
    from build_contracts import build_contracts
    build_contracts(build, out)
    code = {n: Cell.one_from_boc((out/f'{n}.boc').read_bytes())
            for n in ('wallet-func', 'agent', 'module-func')}

    transport = LiteClientTransport(args.lite_client, args.lite_config,
                                    poll_seconds=2.0, attempts=45)
    network, version = transport.global_id(), transport.global_version()
    print(f'chain: global_id={network} global_version={version}', flush=True)
    if version < 16:
        raise SystemExit(f'the chain runs at version {version}; the instruction is not reachable')

    payer, _ = funded_payer(transport, args.control, code['wallet-func'], network)
    print(f'payer {payer.address.to_str(False)} balance={transport.balance(payer.address)}',
          flush=True)

    key_file = out/'PUBLIC-TEST-KEY'
    key_file.unlink(missing_ok=True)
    subprocess.run([str(args.key_tool.resolve()), 'keygen', str(key_file)],
                   check=True, capture_output=True)
    signer = NativeMldsa44Signer(args.key_tool.resolve(), key_file)

    harness = Harness(transport, network, payer, code, out)
    target = Address('0:' + '7e' * 32)

    for kind in KINDS:
        harness.classical(kind, target)
    for kind in KINDS:
        harness.classical_wrong_key(kind, target)

    module = Mldsa44ModuleBlueprint(code['module-func'], 0, network, signer.public_key())
    asyncio.run(transport.deploy(module, 4_000_000_000))
    if transport.read_module_key(module.address) != signer.public_key():
        raise SystemExit('the deployed module verifies against a different key')
    print(f'module {module.address.to_str(False)}', flush=True)

    for kind in KINDS:
        harness.post_quantum(kind, target, module, signer)

    cases = harness.results
    expected = {f'{p}/{k}' for k in KINDS
                for p in ('classical', 'classical-wrong-key', 'pq', 'pq-tampered')}
    missing = expected - {c['case'] for c in cases}
    if missing:
        raise SystemExit('cases never ran: ' + ', '.join(sorted(missing)))
    report = {'success': all(c['ok'] for c in cases), 'network': network,
              'global_version': version, 'scope': 'live-chain',
              'source_commit': source_commit(), 'cases': cases}
    (out/'live-regression.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    sys.exit(main())
