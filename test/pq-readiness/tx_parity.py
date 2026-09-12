#!/usr/bin/env python3
"""Compare whole transactions, so the action phase is covered too.

The opcode driver stops after the compute phase; RAWRESERVE and SENDRAWMSG were
only ever compared as an action-list hash. Here the same account and the same
inbound message go through the native emulator and the Rust executor, and the
exit code, the action result, the emitted messages and the resulting account
must all agree.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'test/tostester/src'), str(ROOT/'test/mldsa-auth'),
                str(ROOT/'test/auth-extensions')]


def source_commit() -> str:
    """Bind a report to the tree that produced it, for the activation precheck."""
    return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def report(left, right):
    """Agreement between two builds is a property of the builds, not of a chain."""
    if len(left) != len(right) or len(left) < 4:
        raise ValueError('missing or truncated transaction evidence')
    rows = [line.split('\t') for line in left]
    if any(len(row) != 6 for row in rows):
        raise ValueError('malformed transaction row')
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError('duplicate transaction identifier')
    # Two VMs that reject everything agree perfectly. The transcript has to hold
    # a relay, a compute refusal and an action failure before agreement means
    # anything, because those are the three outcomes the module actually has.
    relayed = any(r[1] == '0' and r[2] == '0' and r[3] != '-' for r in rows)
    refused = any(r[1] != '0' for r in rows)
    action_failed = any(r[1] == '0' and r[2] != '0' for r in rows)
    if not (relayed and refused and action_failed):
        raise ValueError('transcript lacks a relay, a refusal or an action failure')
    differences = [(a, b) for a, b in zip(left, right) if a != b]
    return {'success': not differences, 'network': None, 'scope': 'network-independent',
            'source_commit': source_commit(), 'transactions': len(left),
            'differences': differences[:4],
            'compared': 'exit, action result, out messages, account'}


def account_state(cell):
    """Balance and contract storage: what the two runs must agree on."""
    if cell is None:
        return '0\t-'
    s = cell.slice()
    s.uint(1); s.addr(); s.varuint(7); s.varuint(7)
    if s.uint(3) == 1:
        s.uint(256)
    s.uint(32)
    if s.uint(1):
        s.coins()
    s.uint(64)
    balance = s.coins()
    data = cell.refs[-1].hash.hex() if cell.refs else '-'
    return f'{balance}\t{data}'


def transcript(name, details, transaction, account_cell):
    outgoing_hashes = [m.hash.hex() for m in outgoing(transaction)]
    return '\t'.join([
        name,
        str(details.get('exit')),
        str((details.get('action') or {}).get('code', 0)),
        ','.join(outgoing_hashes) if outgoing_hashes else '-',
        account_state(account_cell),
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--signer', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ.update(FUNC_PATH=str(build/'crypto/func'), FIFT_PATH=str(build/'crypto/fift'),
                      TOL_PATH=str(build/'tol/tol'))
    from protocol import emulator_library
    os.environ['EMULATOR_PATH'] = str(emulator_library(build))
    global outgoing
    from build_contracts import build_contracts
    from cells import Cell, from_boc
    from native import (NOW, GLOBAL_ID, Emulator, account_data, active_account, config,
                        internal, outgoing, state_init)
    from protocol import AUTH, CONTEXT, commitment, module_data, submission, Signer

    build_contracts(build, out)
    signer = Signer(args.signer)
    key = signer.public_key(0)
    wc = 0
    scenarios, rows = [], []

    module_code = from_boc((out/'module-func.boc').read_bytes())
    module_data_cell = module_data(key, GLOBAL_ID)
    module_init = state_init(module_code, module_data_cell)
    module = (wc, int.from_bytes(module_init.hash, 'big'))
    target = (wc, 0x9999999999999999999999999999999999999999999999999999999999999999)

    def request(valid_until=NOW + 600, kind=0, account=target):
        return (Cell().sint(GLOBAL_ID, 32).addr(account).uint(1, 64).uint(0, 64)
                .uint(valid_until, 32).uint(kind, 8).ref(Cell().uint(7, 32)))

    def submit(name, req, signature=None, value=10_000_000_000, balance=100_000_000_000):
        envelope = Cell().uint(AUTH, 32).ref(req).maybe(None)
        if signature is None:
            _, signature = signer.sign(commitment(req), CONTEXT, 0)
        body = submission(envelope, signature)
        shard = active_account(module, module_code, module_data_cell, balance)
        message = internal((wc, 17), module, body, value)
        scenarios.append((name, shard, message))

    good = request()
    submit('module-accepts-and-relays', good)
    tampered = bytearray(signer.sign(commitment(good), CONTEXT, 0)[1]); tampered[0] ^= 1
    submit('module-refuses-a-tampered-proof', good, bytes(tampered))
    submit('module-refuses-a-stale-request', request(valid_until=NOW - 1))
    # Enough to verify, too little to forward: the action phase is the one that
    # fails, and only a whole-transaction comparison can see the difference.
    submit('module-verifies-but-cannot-forward', good, value=66_000_000)

    emulator = Emulator(16)
    logical_times = []
    try:
        for name, shard, message in scenarios:
            result = emulator.send(shard, message)
            # The executor must be given the very logical time this used, or the
            # bookkeeping differs and every hash does too.
            logical_times.append(emulator.lt)
            assert result['success'], f'{name}: emulator error, not a transaction'
            details = result.get('details', result)
            after = from_boc(result['shard_account'])
            rows.append(transcript(name, details, from_boc(result['transaction']),
                                   after.refs[0] if after.refs else None))
    finally:
        emulator.close()
    (out/'emulator.tsv').write_text('\n'.join(rows) + '\n')

    # The Rust driver reads the Account cell inside the ShardAccount.
    (out/'scenarios.tsv').write_text('\n'.join(
        '\t'.join([name, str(NOW), str(lt), shard.refs[0].boc().hex(),
                   message.boc().hex(), '-'])
        for (name, shard, message), lt in zip(scenarios, logical_times)) + '\n')
    # ConfigParams is the address plus the dictionary; the emulator takes the
    # dictionary alone, so the same configuration is wrapped for the executor.
    fixture = from_boc((ROOT/'tosctl/src/executor/real_boc/default_config.boc').read_bytes())
    (out/'config.boc').write_bytes(
        Cell().uint(int(fixture.bits, 2), 256).ref(config(16)).boc())

    rust = subprocess.run([str(args.driver.resolve()), str(out/'config.boc'),
                           str(out/'scenarios.tsv')], capture_output=True, text=True)
    (out/'rust.tsv').write_text(rust.stdout)
    if rust.returncode != 0:
        raise SystemExit(f'rust driver failed: {rust.stderr.strip()[:400]}')

    left = (out/'emulator.tsv').read_text().splitlines()
    right = rust.stdout.splitlines()
    result = report(left, right)
    (out/'tx-parity.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if not result['success']:
        raise SystemExit('transaction divergence: ' + repr(result['differences']))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
