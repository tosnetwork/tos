#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""C ABI transaction binding, opaque skipped-send and fail-closed regressions."""
import ctypes
import hashlib
import json
import pathlib
import sys

library = ctypes.CDLL(sys.argv[1])
root = pathlib.Path(sys.argv[2])
manifest = json.loads((root / 'manifest.json').read_text())
verify = library.tos_proof_verify_wallet_transaction
verify.argtypes = [ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p,
                   ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                   ctypes.POINTER(ctypes.c_size_t)]
verify.restype = ctypes.c_int
LIMIT = 1 << 20


def call(tx, *, account=None, digest=None, lt=None, data=None, capacity=LIMIT, workchain=0):
    account = bytes.fromhex(manifest['account']) if account is None else account
    digest = bytes.fromhex(tx['hash']) if digest is None else digest
    data = (root / tx['file']).read_bytes() if data is None else data
    output = ctypes.create_string_buffer(b'x' * capacity, capacity)
    size = ctypes.c_size_t(123)
    status = verify(workchain, account, int(tx['lt']) if lt is None else lt, digest,
                    data, len(data), output, capacity, ctypes.byref(size))
    if status:
        assert size.value == 0, (status, size.value)
        assert output.raw == b'\0' * capacity, status
        return status, None
    assert 0 < size.value <= capacity
    return status, json.loads(output.raw[:size.value])


results = []
for i, tx in enumerate(manifest['transactions']):
    data = (root / tx['file']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == tx['sha256']
    code, result = call(tx)
    assert code == 0, (i, code)
    assert result['interface'] == 'tos-wallet-transaction/1'
    assert result['account'] == '0:' + manifest['account']
    assert result['hash'] == tx['hash'] and result['lt'] == tx['lt']
    assert result['compute'] == {'skipped': False, 'success': True, 'exit_code': 0}
    assert result['action']['success'] and result['action']['valid']
    assert result['action']['skipped_actions'] == tx['skipped_actions']
    assert result['action']['messages_created'] == len(tx['outgoing_amounts'])
    assert [m['value'] for m in result['out_msgs']] == tx['outgoing_amounts']
    assert not result['aborted'] and not result['destroyed']
    assert result['in_msg']['kind'] == 'external_in'
    assert 'paid' not in result and 'success' not in result
    results.append(result)
    print('WALLET_TRANSACTION_CASE', 'opaque-skipped-send' if i == 0 else f'actual-payment-{i}', 'PASS')

assert results[0]['hash'] == manifest['proven_head']
for newer, older in zip(results, results[1:]):
    assert newer['previous_hash'] == older['hash'] and newer['previous_lt'] == older['lt']
assert results[-1]['previous_lt'] == '0' and results[-1]['previous_hash'] == '00' * 32
print('WALLET_TRANSACTION_CASE authenticated-predecessor-chain PASS')

first = manifest['transactions'][0]
assert call(first, digest=b'\0' * 32)[0] == -2
print('WALLET_TRANSACTION_CASE wrong-hash PASS')
assert call(first, account=b'\0' * 32)[0] == -2
print('WALLET_TRANSACTION_CASE wrong-account PASS')
assert call(first, lt=int(first['lt']) + 1)[0] == -2
print('WALLET_TRANSACTION_CASE wrong-lt PASS')
for name, data in [('truncated', (root / first['file']).read_bytes()[:-1]),
                   ('trailing', (root / first['file']).read_bytes() + b'\0'),
                   ('garbage', b'not a boc'), ('byte-limit', b'\0' * (LIMIT + 1)),
                   ('empty', b'')]:
    assert call(first, data=data)[0] == (-1 if name in ('byte-limit', 'empty') else -2), name
    print('WALLET_TRANSACTION_CASE', name, 'PASS')
assert call(first, capacity=1)[0] == -3
assert call(first, capacity=0)[0] == -3
assert call(first, workchain=-1)[0] == -1
assert call(first, lt=0)[0] == -1
print('WALLET_TRANSACTION_CASE capacity-and-interface PASS')
