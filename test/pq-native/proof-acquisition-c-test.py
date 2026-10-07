#!/usr/bin/env python3
"""Exercise the C acquisition callback boundary with real public replies."""
import ctypes as c
from pathlib import Path
import sys

lib = c.CDLL(sys.argv[1])
root = Path(sys.argv[2])
Query = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t))
Emit = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_uint32, c.c_void_p, c.c_size_t)
acquire = lib.tos_proof_acquire
acquire.restype = c.c_int
acquire.argtypes = [c.c_char_p, c.c_size_t, c.c_char_p, c.c_size_t, c.c_char_p, c.c_size_t, Query, c.c_void_p, Emit, c.c_void_p]
anchor = (root / 'anchor.json').read_bytes()
request = (root / 'historical-request.json').read_bytes()
replies = [(root / 'historical' / name).read_bytes() for name in ['chain-0000.tl', 'config.tl', 'account.tl', 'exec-config.tl']]

def run(mode):
    collected, observed = [], []
    errors = []
    @Query
    def query(context, data, size, output, capacity, used):
        try:
            index = len(observed)
            observed.append(c.string_at(data, size))
            used[0] = 0
            if mode == 'transport-failure': return -1
            if mode == 'oversized': used[0] = capacity + 1; return 0
            if index >= len(replies): return -1
            reply = replies[index]
            assert len(reply) <= capacity
            c.memmove(output, reply, len(reply)); used[0] = len(reply)
            return 0
        except Exception as error:
            errors.append(str(error)); return -1
    @Emit
    def emit(context, kind, data, size):
        if mode == 'collector-failure': return -1
        collected.append((kind, c.string_at(data, size))); return 0
    status = acquire(anchor, len(anchor), request, len(request), None, 0, query, None, emit, None)
    assert not errors, errors
    return status, collected, observed

def check(name, condition):
    print('ACQUISITION_C_CASE', name, 'PASS' if condition else 'FAIL', flush=True)
    assert condition, name

status, collected, queries = run('valid')
check('real-callback-sequence', status == 0 and len(queries) == 4)
check('collected-real-material', [kind for kind, _ in collected] == [2, 4, 5, 6] and [data for _, data in collected] == replies)
for mode in ['transport-failure', 'oversized']:
    status, collected, queries = run(mode)
    check(mode + '-no-emission', status == -2 and not collected and len(queries) == 1)
check('collector-failure-refused', run('collector-failure')[0] == -3)
