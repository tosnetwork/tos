#!/usr/bin/env python3
"""Exercise durable live verification with real public chain material."""
import ctypes as c
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile

class Material(c.Structure):
    _fields_ = [('kind', c.c_uint32), ('data', c.c_void_p), ('size', c.c_size_t)]

library = c.CDLL(sys.argv[1])
root = Path(sys.argv[2])
verify = library.tos_proof_verify_live_persisted
verify.restype = c.c_int
verify.argtypes = [c.c_char_p, c.c_int, c.c_char_p, c.c_size_t, c.c_char_p, c.c_size_t,
                   c.c_int64, c.POINTER(Material), c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
anchor = (root / 'anchor.json').read_bytes()
request = (root / 'live-request.json').read_bytes()

def call(directory, initialize=0, initial=False, now=1791200932):
    files = [(1, root / 'live/masterchain-info.tl'), (4, root / 'live/config.tl')]
    chain = root / ('historical' if initial else 'live')
    files += [(2, p) for p in sorted(chain.glob('chain-*.tl'))]
    buffers = [c.create_string_buffer(p.read_bytes()) for _, p in files]
    parts = (Material * len(files))(*[Material(kind, c.cast(b, c.c_void_p), len(b.raw) - 1) for (kind, _), b in zip(files, buffers)])
    output = c.create_string_buffer(b'x' * (1 << 20))
    size = c.c_size_t(99)
    status = verify(str(directory).encode(), initialize, anchor, len(anchor), request, len(request), now,
                    parts, len(parts), output, 1 << 20, c.byref(size))
    if status:
        assert size.value == 0 and output.raw[:1 << 20] == b'\0' * (1 << 20), 'failure leaked output'
    return status, output.raw[:size.value]

def check(name, condition):
    print('PERSISTED_PROOF_CASE', name, 'PASS' if condition else 'FAIL', flush=True)
    assert condition, name

if '--sync-fault' in sys.argv:
    with tempfile.TemporaryDirectory(prefix='tos-proof-persisted-') as name:
        directory = Path(name).resolve()
        os.environ['PROOF_PERSIST_FAULT_DIR'] = str(directory)
        check('directory-sync-failure-refuses-result', call(directory, initialize=1, initial=True)[0] == -6)
        check('fault-reached-after-checkpoint-rename', (directory / 'checkpoint.json').is_file())
    sys.exit(0)

with tempfile.TemporaryDirectory(prefix='tos-proof-persisted-') as name:
    directory = Path(name)
    check('missing-unenrolled-refused', call(directory, initial=True)[0] == -6)
    status, result = call(directory, initialize=1, initial=True)
    check('explicit-first-use-verified', status == 0 and json.loads(result)['status'] == 'verified')
    state = directory / 'checkpoint.json'
    check('checkpoint-committed-before-result', state.is_file() and json.loads(state.read_text())['head']['seqno'] == 636922)
    before = state.read_bytes()
    check('reopen-verified', call(directory)[0] == 0)
    check('expired-refuses-without-state-change', call(directory, now=1791201231)[0] == -2 and state.read_bytes() == before)
    with (directory / 'checkpoint.lock').open('r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        check('competing-owner-refused', call(directory)[0] == -5)
    state.unlink()
    check('enrolled-missing-state-refused', call(directory, initialize=1, initial=True)[0] == -6)

with tempfile.TemporaryDirectory(prefix='tos-proof-persisted-') as name:
    directory = Path(name)
    (directory / 'checkpoint.tmp').mkdir()
    check('commit-failure-refuses-result', call(directory, initialize=1, initial=True)[0] == -6)
    check('interrupted-enrollment-cannot-reset', call(directory, initialize=1, initial=True)[0] == -6)

with tempfile.TemporaryDirectory(prefix='tos-proof-persisted-') as name:
    directory = Path(name)
    assert call(directory, initialize=1, initial=True)[0] == 0
    state = directory / 'checkpoint.json'
    contents = state.read_bytes()
    external = directory / 'saved.json'
    external.write_bytes(contents)
    external.chmod(0o600)
    state.unlink()
    state.symlink_to(external)
    check('symlink-state-refused', call(directory)[0] == -6)
    state.unlink()
    os.link(external, state)
    check('hardlink-state-refused', call(directory)[0] == -6)
    state.unlink()
    state.write_bytes(contents)
    state.chmod(0o644)
    check('public-state-refused', call(directory)[0] == -6)
    state.chmod(0o600)
    directory.chmod(0o755)
    check('public-directory-refused', call(directory)[0] == -6)
    directory.chmod(0o700)
    state.write_bytes(b'not a checkpoint')
    check('corrupt-state-refused', call(directory)[0] == -1)
