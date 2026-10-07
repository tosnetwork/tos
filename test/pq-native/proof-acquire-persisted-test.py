#!/usr/bin/env python3
"""Real captured reply acquisition + verification + durable checkpoint test."""
import ctypes as c
import fcntl
import json
from pathlib import Path
import sys
import tempfile

lib = c.CDLL(sys.argv[1]); root = Path(sys.argv[2])
Query = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t))
function = lib.tos_proof_acquire_verify_live_persisted
function.restype = c.c_int
function.argtypes = [c.c_char_p, c.c_int, c.c_char_p, c.c_size_t, c.c_char_p, c.c_size_t, c.c_int64, Query, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
anchor = (root / 'anchor.json').read_bytes(); request = (root / 'live-request.json').read_bytes()

def call(directory, initialize=False, initial=False, failure=False, expired=False):
    replies = [(root / 'live/masterchain-info.tl').read_bytes(), (root / ('historical' if initial else 'live') / 'chain-0000.tl').read_bytes(), (root / 'live/config.tl').read_bytes()]
    observed, locks, errors = [], [], []
    @Query
    def query(context, data, size, output, capacity, used):
        try:
            with (directory / 'checkpoint.lock').open('r+') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locks.append(False)
                except BlockingIOError:
                    locks.append(True)
            index = len(observed); observed.append(c.string_at(data, size)); used[0] = 0
            if failure: return -1
            if index >= len(replies): return -1
            reply = replies[index]; assert len(reply) <= capacity
            c.memmove(output, reply, len(reply)); used[0] = len(reply); return 0
        except Exception as error:
            errors.append(str(error)); return -1
    output = c.create_string_buffer(b'x' * (1 << 20)); used = c.c_size_t(99)
    status = function(str(directory).encode(), int(initialize), anchor, len(anchor), request, len(request),
                      1791201231 if expired else 1791200932, query, None, output, 1 << 20, c.byref(used))
    assert not errors, errors
    if status: assert used.value == 0 and output.raw[:1 << 20] == b'\0' * (1 << 20)
    return status, output.raw[:used.value], observed, locks

def check(name, condition):
    print('ACQUIRE_PERSISTED_CASE', name, 'PASS' if condition else 'FAIL', flush=True)
    assert condition, name

with tempfile.TemporaryDirectory(prefix='tos-acquire-state-') as name:
    directory = Path(name)
    status, result, queries, locked = call(directory, initialize=True, initial=True)
    check('captured-live-acquisition-verifies', status == 0 and json.loads(result)['status'] == 'verified' and len(queries) == 3)
    check('lock-held-through-all-network-callbacks', len(locked) == 3 and all(locked))
    state = directory / 'checkpoint.json'; before = state.read_bytes()
    check('checkpoint-committed-before-return', json.loads(before)['head']['seqno'] == 636922)
    check('reopen-acquires-from-persisted-key-block', call(directory)[0] == 0)
    check('transport-failure-preserves-state', call(directory, failure=True)[0] == -2 and state.read_bytes() == before)
    check('expired-result-preserves-state', call(directory, expired=True)[0] == -2 and state.read_bytes() == before)
    state.unlink()
    status, result, queries, locked = call(directory, initialize=True, initial=True)
    check('lost-enrolled-state-refuses-before-query', status == -6 and not queries)
