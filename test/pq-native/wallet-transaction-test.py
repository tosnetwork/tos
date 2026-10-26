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
assert call(first, digest=b'\0' * 32)[0] == -2, 'wrong-hash'
print('WALLET_TRANSACTION_CASE wrong-hash PASS')
assert call(first, account=b'\0' * 32)[0] == -2, 'wrong-account'
print('WALLET_TRANSACTION_CASE wrong-account PASS')
assert call(first, lt=int(first['lt']) + 1)[0] == -2, 'wrong-lt'
print('WALLET_TRANSACTION_CASE wrong-lt PASS')
for name, data in [('truncated', (root / first['file']).read_bytes()[:-1]),
                   ('trailing', (root / first['file']).read_bytes() + b'\0'),
                   ('garbage', b'not a boc'),
                   ('empty', b'')]:
    assert call(first, data=data)[0] == (-1 if name == 'empty' else -2), name
    print('WALLET_TRANSACTION_CASE', name, 'PASS')
assert call(first, capacity=1)[0] == -3
assert call(first, capacity=0)[0] == -3
assert call(first, workchain=-1)[0] == -1
assert call(first, lt=0)[0] == -1
print('WALLET_TRANSACTION_CASE capacity-and-interface PASS')

# Independent fixture-only cell builder: no SDK/native decoder supplies the
# expected root hash. Iterative traversal also tests depths beyond Python's
# ordinary recursion limit without changing interpreter limits.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'auth-extensions'))
from cells import Cell, from_boc  # noqa: E402


def serialize(cell, extras=()):
    ordered, seen = [], set()
    stack = [(cell, False)]
    while stack:
        item, done = stack.pop()
        if done:
            ordered.append(item)
        elif id(item) not in seen:
            seen.add(id(item))
            stack.append((item, True))
            stack.extend((ref, False) for ref in item.refs)
    depths, hashes = {}, {}
    for item in ordered:
        depth = 1 + max(depths[id(ref)] for ref in item.refs) if item.refs else 0
        depths[id(item)] = depth
        hashes[id(item)] = hashlib.sha256(item.prefix()
            + b''.join(depths[id(ref)].to_bytes(2, 'big') for ref in item.refs)
            + b''.join(hashes[id(ref)] for ref in item.refs)).digest()
    ordered.reverse()
    ordered.extend(extras)
    indices = {id(item): i for i, item in enumerate(ordered)}
    width = max(1, (len(ordered).bit_length() + 7) // 8)
    content = b''.join(item.prefix() + b''.join(indices[id(ref)].to_bytes(width, 'big')
                                                for ref in item.refs) for item in ordered)
    offset_width = max(1, (len(content).bit_length() + 7) // 8)
    encoded = (bytes.fromhex('b5ee9c72') + bytes([width, offset_width])
        + len(ordered).to_bytes(width, 'big') + (1).to_bytes(width, 'big') + bytes(width)
        + len(content).to_bytes(offset_width, 'big') + bytes(width) + content)
    return encoded, hashes[id(cell)], depths[id(cell)], len(ordered)


ordinary = from_boc((root / manifest['transactions'][-1]['file']).read_bytes())
# 64-bit unsigned logical time, 120-bit currency and opaque inline/ref bodies.
wide = Cell(ordinary.bits, ordinary.refs)
wide.bits = wide.bits[:260] + f'{(1 << 64) - 1:064b}' + wide.bits[324:]
fee_size = int(wide.bits[695:699], 2)
wide.bits = wide.bits[:695] + '1111' + '1' * 120 + wide.bits[699 + fee_size * 8:]
encoded, digest, _, _ = serialize(wide)
code, result = call(first, data=encoded, digest=digest, lt=(1 << 64) - 1)
assert code == 0 and result['lt'] == str((1 << 64) - 1) and result['fees'] == str((1 << 120) - 1)
print('WALLET_TRANSACTION_CASE uint64-and-120-bit-currency PASS')


def with_body(body):
    incoming = ordinary.refs[0].refs[0]
    messages = ordinary.refs[0]
    replaced_input = Cell(incoming.bits, [body])
    replaced_messages = Cell(messages.bits, [replaced_input] + messages.refs[1:])
    return Cell(ordinary.bits, [replaced_messages] + ordinary.refs[1:])


for target in (1023, 1024):
    body = Cell()
    # Transaction -> message collection -> message -> body contributes 3 edges.
    for _ in range(target - 3):
        body = Cell(refs=[body])
    encoded, digest, depth, _ = serialize(with_body(body))
    assert depth == target
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] == (0 if target == 1023 else -2), f'depth-{target}'
    print('WALLET_TRANSACTION_CASE', f'depth-{target}', 'PASS')

base = with_body(Cell())
_, _, _, base_count = serialize(base)
for target in (16384, 16385):
    # Disconnected cells are legal BOC data; the byte/cell preflight must bound
    # them too, rather than relying on reachable graph size after allocation.
    encoded, digest, _, count = serialize(base, [Cell().uint(i, 32) for i in range(target - base_count)])
    assert count == target and len(encoded) < LIMIT
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] == (0 if target == 16384 else -2), f'cell-count-{target}'
    print('WALLET_TRANSACTION_CASE', f'cell-count-{target}', 'PASS')

for mutation in ('previous-time-cycle', 'previous-zero-mismatch', 'trailing-root-bit'):
    malformed = Cell(ordinary.bits, ordinary.refs)
    if mutation == 'previous-time-cycle':
        malformed.bits = malformed.bits[:324] + '1' * 256 + f'{int(manifest["transactions"][-1]["lt"]):064b}' + malformed.bits[644:]
    elif mutation == 'previous-zero-mismatch':
        malformed.bits = malformed.bits[:580] + f'{1:064b}' + malformed.bits[644:]
    else:
        malformed.bits += '1'
    encoded, digest, _, _ = serialize(malformed)
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] == -2, mutation
    print('WALLET_TRANSACTION_CASE', mutation, 'PASS')


def hashmap(entries, remaining=15):
    assert entries
    keys = [f'{key:015b}'[-remaining:] if remaining else '' for key, _ in entries]
    prefix = 0
    while prefix < remaining and all(key[prefix] == keys[0][prefix] for key in keys):
        prefix += 1
    label = Cell('10').uint(prefix, remaining.bit_length())
    label.bits += keys[0][:prefix]
    tail = remaining - prefix
    if tail == 0:
        assert len(entries) == 1
        return label.ref(entries[0][1])
    left = [(key, value) for (key, value), bits in zip(entries, keys) if bits[prefix] == '0']
    right = [(key, value) for (key, value), bits in zip(entries, keys) if bits[prefix] == '1']
    return label.ref(hashmap(left, tail - 1)).ref(hashmap(right, tail - 1))


# An independent dictionary builder exercises the local message ceiling and
# rejects holes/count mismatches rather than silently truncating receipts.
message = ordinary.refs[0].refs[1].refs[0]
amount_size = int(message.bits[538:542], 2)
wide_message = Cell(message.bits[:538] + '1111' + '1' * 120 + message.bits[542 + amount_size * 8:], message.refs)
for count in (1, 256, 257):
    outputs = hashmap([(i, wide_message) for i in range(count)])
    messages = Cell('11', [ordinary.refs[0].refs[0], outputs])
    tx = Cell(ordinary.bits[:676] + f'{count:015b}' + ordinary.bits[691:], [messages] + ordinary.refs[1:])
    encoded, digest, _, _ = serialize(tx)
    code, result = call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))
    assert code == (0 if count <= 256 else -2), f'message-count-{count}'
    if code == 0:
        assert len(result['out_msgs']) == count
        assert all(m['value'] == str((1 << 120) - 1) for m in result['out_msgs'])
    print('WALLET_TRANSACTION_CASE', f'message-count-{count}', 'PASS')

for name, declared, keys in [('output-hole', 1, [2]), ('output-under-count', 0, [0]),
                              ('output-over-count', 2, [0])]:
    outputs = hashmap([(i, message) for i in keys])
    messages = Cell('11', [ordinary.refs[0].refs[0], outputs])
    tx = Cell(ordinary.bits[:676] + f'{declared:015b}' + ordinary.bits[691:], [messages] + ordinary.refs[1:])
    encoded, digest, _, _ = serialize(tx)
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] == -2, name
    print('WALLET_TRANSACTION_CASE', name, 'PASS')

for target in (LIMIT, LIMIT + 1):
    extras = [Cell() for _ in range(8200)]
    small, _, _, _ = serialize(base, extras)
    remaining = target - len(small) - (3 - small[5])
    for i in range(len(extras)):
        size = min(127, remaining)
        extras[i] = Cell('0' * (size * 8))
        remaining -= size
    assert remaining == 0
    encoded, digest, _, count = serialize(base, extras)
    assert len(encoded) == target and count <= 16384
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] == (0 if target == LIMIT else -1), f'byte-boundary-{target}'
    print('WALLET_TRANSACTION_CASE', f'byte-boundary-{target}', 'PASS')

output = ctypes.create_string_buffer(b'x' * 32, 32)
used = ctypes.c_size_t(123)
assert verify(0, None, 1, None, None, 0, output, 32, ctypes.byref(used)) == -1
assert used.value == 0 and output.raw == b'\0' * 32
used.value = 123
assert verify(0, None, 1, None, None, 0, output, LIMIT + 1, ctypes.byref(used)) == -1
assert used.value == 0
# Invalid oversized capacities are rejected before touching that pointer range.
assert output.raw == b'\0' * 32
print('WALLET_TRANSACTION_CASE null-input-and-invalid-capacity PASS')

# Matching hashes on malformed cells reach the TLB decoder, rather than being
# rejected by the outer hash guard first. Exercise both truncation and reference
# failures without accepting an abort/panic as successful rejection.
for cut in range(0, len(ordinary.bits), 17):
    malformed = Cell(ordinary.bits[:cut], ordinary.refs)
    encoded, digest, _, _ = serialize(malformed)
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] != 0
for refs in ([], ordinary.refs[:1], ordinary.refs[:2], ordinary.refs + [Cell()]):
    malformed = Cell(ordinary.bits, refs)
    encoded, digest, _, _ = serialize(malformed)
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] != 0
print('WALLET_TRANSACTION_CASE matching-hash-malformed-tlb PASS')

from concurrent.futures import ThreadPoolExecutor  # noqa: E402


def repeated(index):
    tx = manifest['transactions'][index % len(manifest['transactions'])]
    code, decoded = call(tx)
    assert code == 0 and decoded['hash'] == tx['hash']


with ThreadPoolExecutor(max_workers=4) as workers:
    list(workers.map(repeated, range(256)))
print('WALLET_TRANSACTION_CASE concurrent-independent-calls PASS')

for name, slot, replacement in [('malformed-state-update', 1, Cell()),
                                 ('trailing-state-update', 1, Cell(ordinary.refs[1].bits + '1')),
                                 ('malformed-other-description', 2, Cell('1')),
                                 ('empty-description', 2, Cell())]:
    refs = list(ordinary.refs)
    refs[slot] = replacement
    malformed = Cell(ordinary.bits, refs)
    encoded, digest, _, _ = serialize(malformed)
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] != 0, name
    print('WALLET_TRANSACTION_CASE', name, 'PASS')

# Opaque means an exotic leaf is not loaded as executable code or an ordinary
# cell, even when it is the directly referenced message body.
from cells import LibraryReference  # noqa: E402
encoded, digest, _, _ = serialize(with_body(LibraryReference(123)))
assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] == 0, 'direct-opaque-body'
print('WALLET_TRANSACTION_CASE direct-opaque-body PASS')

# Referenced typed fields must be structurally validated while Any contents
# remain opaque. These all have the correct independently computed root hash.
refs = list(ordinary.refs)
refs.insert(1, Cell())
bad_currency = Cell(ordinary.bits[:-1] + '1', refs)
leaf = ordinary.refs[0].refs[1]
bad_leaf = Cell(leaf.bits + '1', leaf.refs)
bad_messages = Cell(ordinary.refs[0].bits, [ordinary.refs[0].refs[0], bad_leaf])
bad_dictionary = Cell(ordinary.bits, [bad_messages] + ordinary.refs[1:])
incoming = ordinary.refs[0].refs[0]
bad_init = Cell(incoming.bits[:-2] + '111', [Cell()] + incoming.refs)
bad_init_messages = Cell(ordinary.refs[0].bits, [bad_init] + ordinary.refs[0].refs[1:])
bad_init_transaction = Cell(ordinary.bits, [bad_init_messages] + ordinary.refs[1:])
for name, malformed in [('malformed-extra-currency', bad_currency),
                        ('trailing-dictionary-leaf', bad_dictionary),
                        ('malformed-referenced-state-init', bad_init_transaction)]:
    encoded, digest, _, _ = serialize(malformed)
    assert call(first, data=encoded, digest=digest, lt=int(manifest['transactions'][-1]['lt']))[0] != 0, name
    print('WALLET_TRANSACTION_CASE', name, 'PASS')
