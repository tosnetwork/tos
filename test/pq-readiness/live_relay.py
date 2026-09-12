#!/usr/bin/env python3
"""Drive the whole PQ relay loop against a running chain.

Every other test in this directory runs against an emulator or a fake node. The
transport and the relayer were written to fail the way a relayer actually fails,
and until this ran, nothing had ever made them do it on a chain that produces
blocks. What is exercised here is the part no emulator can produce: real
wall-clock expiry, a real global id that messages are signed against, a wallet
whose seqno moves underneath the caller, funded deployment of a contract that
refuses external messages, and a receipt read back out of block storage.

Opt-in. It needs a chain:

    TOS_GLOBAL_VERSION=16 uv run python scripts/localnet-jsonrpc.py --validators 1 \\
      --rpc 127.0.0.1:18545 --control 127.0.0.1:18745 --base-port 19000 \\
      --workdir test/integration/.localnet-pq

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
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'test/tostester/src'), str(ROOT/'test/mldsa-auth'),
                str(ROOT/'test/auth-extensions'), str(ROOT/'test/pq-readiness')]

import nacl.signing
from pytosiq_core import Address, Cell, ExternalMsgInfo, MessageAny
from contract import (AuthState, Mldsa44ModuleBlueprint, NativeMldsa44Signer,
                      WalletV5, WalletV5Blueprint, WalletV5State)
from contract.pq_lite_transport import LiteClientTransport
from contract.pq_relayer import AttemptJournal, LOSS_ACK, PqRelayer
from live_chain import funded_payer, wait_for

TARGET_VALUE = 1_000_000_000
FUNDING_CAP = 2_000_000_000


def source_commit() -> str:
    """Bind a report to the tree that produced it, for the activation precheck."""
    return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


class TamperedSigner:
    """The same key and the same commitment, with one bit of the proof flipped."""

    def __init__(self, inner):
        self.inner = inner

    def public_key(self) -> bytes:
        return self.inner.public_key()

    def sign(self, commitment: bytes) -> bytes:
        broken = bytearray(self.inner.sign(commitment))
        broken[100] ^= 1
        return bytes(broken)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--lite-client', type=Path, required=True)
    parser.add_argument('--lite-config', type=Path, required=True)
    parser.add_argument('--control', default='127.0.0.1:18745')
    parser.add_argument('--key-tool', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ.update(FUNC_PATH=str(build/'crypto/func'), FIFT_PATH=str(build/'crypto/fift'),
                      TOL_PATH=str(build/'tol/tol'))
    from build_contracts import build_contracts
    build_contracts(build, out)
    codes = {name: Cell.one_from_boc((out/f'{name}.boc').read_bytes())
             for name in ('wallet-func', 'module-func')}

    transport = LiteClientTransport(args.lite_client, args.lite_config,
                                    poll_seconds=2.0, attempts=45)
    network = transport.global_id()
    version = transport.global_version()
    if version < 16:
        raise SystemExit(f'the chain runs at version {version}; the instruction is not reachable')
    _, chain_time = transport.head()
    events = []

    # ---- the funding wallet, which pays for everything that follows ---------
    payer, _ = funded_payer(transport, args.control, codes['wallet-func'], network, tos=30)
    events.append({'step': 'funding-wallet-deployed', 'address': payer.address.to_str(False),
                   'balance': transport.balance(payer.address)})

    # ---- the module, which refuses external messages and must be funded in --
    pq_key = out/'PUBLIC-TEST-KEY'
    pq_key.unlink(missing_ok=True)
    subprocess.run([str(args.key_tool.resolve()), 'keygen', str(pq_key)], check=True,
                   capture_output=True)
    pq_signer = NativeMldsa44Signer(args.key_tool.resolve(), pq_key)
    module = Mldsa44ModuleBlueprint(codes['module-func'], 0, network, pq_signer.public_key())
    asyncio.run(transport.deploy(module, 5_000_000_000))
    if transport.read_module_key(module.address) != pq_signer.public_key():
        raise SystemExit('the deployed module verifies against a different key')
    events.append({'step': 'module-deployed', 'address': module.address.to_str(False),
                   'key_confirmed_on_chain': True})

    # ---- the PQ-only account, which refuses classical authorization ---------
    account_key = nacl.signing.SigningKey(os.urandom(32))
    account = WalletV5Blueprint(codes['wallet-func'], 0, network,
                                account_key.verify_key.encode(),
                                auth=AuthState(2, 1, 0, module.address.hash_part))
    asyncio.run(transport.deploy(account, 8_000_000_000))
    live = transport.read_auth(account.address)
    if live.mode != 2 or live.module_hash != module.address.hash_part:
        raise SystemExit('the account came up without the strict authentication root')
    events.append({'step': 'pq-account-deployed', 'address': account.address.to_str(False),
                   'mode': live.mode, 'epoch': live.epoch, 'nonce': live.nonce})

    # ---- the relay itself ---------------------------------------------------
    target = Address('0:' + '5c' * 32)
    before = transport.balance(target)
    account_view = WalletV5(None, account.address, network, None)
    state = WalletV5State.parse(
        Cell.one_from_boc(transport.account_data(account.address).boc()))
    _, chain_time = transport.head()
    payload = account_view.transfer_payload(target, TARGET_VALUE)
    request = account_view.pq_request(state, payload, chain_time + 900)
    journal = AttemptJournal(out/'attempts.db')
    relayer = PqRelayer(transport, journal, FUNDING_CAP)

    # A run where every submission succeeds proves nothing about refusal. Send a
    # proof with one flipped bit first: the module must reject it on chain, the
    # target must not move, and the nonce must stay free to be authorized again.
    bad = asyncio.run(relayer.submit(request, module.address, TamperedSigner(pq_signer), LOSS_ACK))
    rejection = wait_for(
        lambda: (lambda r: r if r.status == 'module_rejected' else None)(
            asyncio.run(relayer.reconcile(request, module.address, bad))),
        'the module rejected the tampered proof')
    if transport.balance(target) != before:
        raise SystemExit('a tampered proof moved funds')
    if transport.read_auth(account.address).nonce != live.nonce:
        raise SystemExit('a rejected proof consumed the nonce')
    asyncio.run(relayer.retire(request, module.address, bad))
    events.append({'step': 'tampered-proof-rejected',
                   'module_transaction': rejection.module_transaction,
                   'target_moved': 0, 'nonce_still': live.nonce})

    broadcast = asyncio.run(relayer.submit(request, module.address, pq_signer, LOSS_ACK))
    events.append({'step': 'relayed', 'broadcast': broadcast,
                   'commitment': request.commitment.hex()})

    receipt = wait_for(
        lambda: (lambda r: r if r.status == 'executed' else None)(
            asyncio.run(relayer.reconcile(request, module.address, broadcast))),
        'the account executed the relayed request')
    after = transport.balance(target)
    moved = after - before
    # "Nonzero" would pass for a stray nanotomi. The target must receive what was
    # authorized, less only the forwarding fee taken out of the message value.
    if not TARGET_VALUE - 10_000_000 <= moved <= TARGET_VALUE:
        raise SystemExit(f'{target.to_str(False)} received {moved}, not the authorized '
                         f'{TARGET_VALUE}')
    final = transport.read_auth(account.address)
    if final.nonce != live.nonce + 1:
        raise SystemExit('the account executed without consuming the nonce')
    events.append({'step': 'executed', 'module_transaction': receipt.module_transaction,
                   'account_transaction': receipt.account_transaction,
                   'target_received': moved, 'nonce_after': final.nonce})

    # A replay of the very same authorization must now be refused, or the
    # nonce is decorative and the relay could be repeated by anyone watching.
    try:
        asyncio.run(relayer.submit(request, module.address, pq_signer, LOSS_ACK))
    except ValueError as refusal:
        events.append({'step': 'replay-refused', 'reason': str(refusal)})
    else:
        raise SystemExit('the same authorization was accepted twice')

    report = {'success': True, 'network': network, 'scope': 'live-chain',
              'source_commit': source_commit(), 'global_version': version,
              'target_received': moved, 'events': events}
    (out/'live-relay.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    journal.close()
    print(json.dumps({k: v for k, v in report.items() if k != 'events'}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
