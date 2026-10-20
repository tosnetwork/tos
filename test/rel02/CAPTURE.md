# Capture and verification receipt

The durable source index is `capture-index.json`. It records every selected block
and every source block from which an original state-update cell was extracted:
full block ID, archive package/entry/range, payload SHA-256 and size, and the actual
independent `lookupBlock` replies from validator roles 1 and 3. `case: null` means
an extraction source, not an additional replay case. The original selected BOCs
and required cells are retained in `corpus/`; archive expiration does not remove
them from the test.

`capture-commands.json` retains the exact read-only remote programs and their
command/stdout/stderr hashes. The earlier 200-block capture used the recorded
entry-scan template on roles 1 and 3 and compared both payloads byte-for-byte.
The new capture read named immutable package files, at idle I/O/CPU priority,
then checked both full IDs. Historical `stop_at` deadlines are deliberately
preserved in this record; these are audit transcripts, not an instruction to
ignore a current read window. No live database was opened.

The archive retention is finite. A fresh acquisition can fail because a package
or RPC header is no longer served. That is a failure to reacquire, not evidence
that different bytes are valid. The committed BOCs, full-ID replies and hashes
preserve the original observation. The node endpoints/SSH credentials are supplied
by an authorized operator; they are not embedded in the repository.

## Reacquire one indexed entry

Run from the repository root, with `ARCHIVE_HOST` naming an authorized archive
holder and `OUT` a new coordinator scratch file. Under the original collection
limits use roles 1–2 for payloads, one SSH read at a time per node, at least two
seconds apart, and no reads during the excluded rotation windows or after the
approved deadline. Role 3 is used only for the independent RPC ID check.

This is the same archive-header/entry read as the recorded programs, scoped to
one named package and exact entry. It creates no remote file:

```sh
ARCHIVE_HOST="$AUTHORIZED_ARCHIVE_HOST" OUT="$SCRATCH_BLOCK" python3 - <<'PY'
import hashlib, json, os, subprocess, time
from pathlib import Path
index = json.loads(Path('test/rel02/capture-index.json').read_text())
item = next(x for x in index['blocks'] if x['case'] == 'blocks/-1-309465.boc')
source = next((s for s in item['sources'] if s['node'] in (1, 2)), item['sources'][0])
host = os.environ['ARCHIVE_HOST']
assert host and not host.startswith('-')
program = 'package=' + repr(source['archive_file']) + '\nentry=' + repr(source['entry']) + '\n' + r'''
import re, struct, sys
assert re.fullmatch(r'/var/lib/tos/validator/archive/packages/arch\d{4}/archive\.\d+(?:\.-?\d+[_:][0-9a-fA-F]+)?\.pack', package)
with open(package, 'rb') as f:
    assert f.read(4) == struct.pack('<I', 0xae8fdd01)
    while True:
        header = f.read(8)
        if not header:
            raise SystemExit('indexed entry is not served by this package')
        a, size = struct.unpack('<II', header)
        assert a & 65535 == 0x1e8b
        name = f.read(a >> 16).decode()
        if name == entry:
            assert size <= 8 * 1024 * 1024
            data = f.read(size)
            assert len(data) == size
            sys.stdout.buffer.write(data)
            break
        f.seek(size, 1)
'''
result = subprocess.run(['ssh', '-T', '-oBatchMode=yes', host,
    'ionice -c3 nice -n19 python3 -B -'], input=program.encode(),
    capture_output=True, timeout=180, check=True)
assert len(result.stdout) == item['size']
assert hashlib.sha256(result.stdout).hexdigest() == item['sha256']
with Path(os.environ['OUT']).open('xb') as f:
    f.write(result.stdout)
time.sleep(2)
PY
```

## Independently check the full IDs

With the existing Python codec dependencies installed, set `RPC_A` and `RPC_B`
to two distinct authorized validator endpoints (including `/jsonRPC`). On the
coordinator the recorded roles used ports 18381 and 18383. This sends only
`lookupBlock`, spaces each endpoint by at least 1.1 seconds, and independently
computes each committed block's root/file hashes:

```sh
RPC_A="$AUTHORIZED_RPC_A" RPC_B="$AUTHORIZED_RPC_B" python3 - <<'PY'
import base64, hashlib, json, os, sys, time, urllib.request
from pathlib import Path
sys.path.insert(0, 'test/tostester/src')
from pytosiq_core.boc import Cell
root = Path('test/rel02/corpus')
m = json.loads((root / 'manifest.json').read_text())
urls = [os.environ['RPC_A'], os.environ['RPC_B']]
assert len(set(urls)) == 2
last = {u: 0.0 for u in urls}
for entry in m['files']:
    if entry['kind'] != 'block':
        continue
    b = entry['source_block']
    data = (root / entry['path']).read_bytes()
    assert hashlib.sha256(data).hexdigest().upper() == b['file_hash']
    assert Cell.one_from_boc(data).get_hash(0).hex().upper() == b['root_hash']
    for url in urls:
        time.sleep(max(0, 1.1 - (time.monotonic() - last[url])))
        last[url] = time.monotonic()
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'lookupBlock', 'params': {
            'workchain': b['workchain'], 'shard': str(b['shard']), 'seqno': b['seqno']}}
        req = urllib.request.Request(url, json.dumps(request).encode(),
            {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as response:
            answer = json.load(response)
        assert 'error' not in answer, answer
        got = answer['result']
        if isinstance(got.get('id'), dict):
            got = got['id']
        normalized = {k: base64.b64decode(got[k]).hex().upper()
            if k in ('root_hash', 'file_hash') else int(got[k]) for k in b}
        assert normalized == b, (url, entry['path'], normalized, b)
print('all full IDs match two validators and the committed bytes')
PY
```

The exact original state-update extraction was:

```fift
"source-block.boc" file>B B>boc <s ref@+ drop ref@+ drop ref@
31 boc+>B "state-update.boc" B>file
```

Its root was checked against the original block's third reference before packing.
`check_oracle.py` independently checks every packed root's recorded hashes and
re-decodes the original transaction oracle. `run.py --controls` also performs the
actual empty-code execution control, in addition to the byte/expected-value
controls; receipts are uploaded with each architecture's CI result. The negative
operation shares the normal replay/emulation path and only replaces contract
code before the emulator call. Removing that replacement must make `--controls`
fail with `execution control did not change a consensus result`.
