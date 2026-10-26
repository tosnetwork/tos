# Capture and verification receipt

The corpus was captured offline, from local read-only copies. No host was
contacted, no node RPC was queried and no live database was opened. The inputs
were:

- `$ARCHIVE_DIR`: the archive packages of a throwaway full node that synced the
  epoch-5 public testnet (global id 2) from genesis to masterchain 242,333, with
  their `$ARCHIVE_SHA256SUMS` list. Every package was checked against that list
  before use.
- `$IDS_DIR`: full block ids from validators node-1 and node-3, captured with
  `lookupBlock` and `shards` per masterchain sequence number (TOK-01 117,700–117,950;
  ConfigParam 15 rounds 151,200–152,000, 161,000–161,250 and 194,800–195,800), and
  `named-supplement.json`, with node-1/node-3 `lookupBlock` replies for nine named
  blocks no `shards` reply covers. `$IDS_DIR/SHA256SUMS` lists every id file.
- `$CON01_RAW`: the rotation capture with node-1/node-3 `lookupBlock`, `shards` and
  `getMasterchainInfo` replies for masterchain 230,278–230,477.
- `$GENESIS_ZEROSTATE`: the published genesis zero state, bound by the initial
  block id: its root and file hashes equal the `init` id that node-1 and node-3
  return in the rotation capture's `getMasterchainInfo` replies.

`capture-index.json` is the durable source index. For every selected block and
every source of original cells it records the full block id, the package, entry
name, offset, size and SHA-256 of the archive entry, and the node-1 and node-3
replies (with the SHA-256 of each reply's canonical JSON). `case: null` marks a
cell source, not a replay case. `capture-commands.json` records the exact local
programs (text and SHA-256), the order they ran in, their exit codes and the
hashes of their inputs and outputs.

## Selection rule

A block is a replay case only when node-1 and node-3 each returned exactly one
full id for it and both equal the root hash and file hash of the archive bytes.
Masterchain ids come from `lookupBlock`; basechain ids come from the `shards`
reply of a masterchain block, which names only the newest basechain block it
registers, or from a named `lookupBlock` capture for the other basechain blocks.
A basechain block also needs its exact masterchain context in the corpus. A
planned block without such an id would be excluded and listed in the README;
none is.

## Original cells

A block's Merkle update carries only the cells its collation visited; the rest
are pruned. The configuration, the previous-block VM context and some account
cells read by the replay are therefore pruned in the selected blocks themselves.
The replay supplies them from other original chain data, matched only by
level-zero hash, so a supplied cell cannot change any value:

1. `build_index.py` indexes every full ordinary cell of every archived block (the
   old-state and new-state trees of its state update, and its other cells) by
   level-zero hash. Every cell of a later state was created by some block, whose
   new-state tree holds it in full; cells never rewritten since genesis exist only
   in the zero state.
2. `resolve.py` runs a diagnostic build of the replay (`epoch-replay.cpp` with the
   recorded `diagnostic.patch`, which only reports each pruned cell read, including
   in a shard block's masterchain context, and continues with the next block). For
   each reported hash it adds the archive block that holds the full cell: a block
   already selected, else one with a two-validator id, else the nearest. It repeats
   until no block fails. Only the parts it selects are given to the replay: the
   whole state-update cell of each source block, the block extra where a cell came
   from a key block's configuration, and the zero state.
3. `assemble.py write` packs exactly those roots into `corpus/state-parts.boc`. Each
   `supplement_roots` entry names its kind, its source block id and the SHA-256 of
   the archive entry it was taken from. Sources with node-1/node-3 ids carry
   `verified_rpc_nodes`; the others are bound by hash only.

The diagnostic build is used for this search only. Every result in
`VALIDATION.json` comes from the unmodified `emulator/test/epoch-replay.cpp`.

## Reproduce

Use a Python 3.14 environment with the codec dependencies of `test/tostester`
(`bitarray`, `pynacl`, `pycryptodome`). The programs are stored in
`capture-commands.json`; write every `scripts` entry, under its name, into one new
directory, replace `resolve.py` there with `test/rel02/capture/resolve.py`, and run
`capture.py` there with these variables set:

```sh
export REPO_DIR="$PWD" ARCHIVE_DIR=... ARCHIVE_SHA256SUMS=... IDS_DIR=... \
  CON01_RAW=... GENESIS_ZEROSTATE=... WORK_DIR=... REPLAY_DIAG=...
python3 capture.py
```

`REPLAY_DIAG` is the command that runs the diagnostic build (built from this tree
with `diagnostic.patch` applied, in the `Dockerfile.builder` environment).
`REPLAY_DIAG_TIMEOUT` optionally bounds each diagnostic run, in seconds (default 600).

`capture-commands.json` records what ran for the committed corpus, and its
`resolve.py` (SHA-256 `876718d71ff9e4d70d3083fdeeadde537d3921a7bdfcc939db5f61bea271f785`) is kept
as it ran. That program did not check the diagnostic child: a child that exited
non-zero, or exited 0 without replaying anything, read as "no failing blocks". For
any re-capture it is superseded by `test/rel02/capture/resolve.py` (SHA-256
`7ba1b888d30d866fbbcdbbf65827dc8595252da6be08b35a9c823039eac51ee8`), which refuses a diagnostic
run that exits non-zero, is killed or times out, and one that does not announce
every selected block in order or leaves a block with neither a block record nor a
reported failure. `test_run.py` exercises those refusals with stub children. The
committed corpus does not rest on the old program's result: `check_oracle.py` and
the unmodified replay check it independently.
`capture.py` writes `capture-log.json` in `$WORK_DIR`; its entries are the
`steps` of `capture-commands.json`.

## Check the full ids and the committed bytes

With only the committed files and the id captures:

```sh
IDS_DIR=... CON01_RAW=... python3 - <<'PY'
import base64, hashlib, json, os, sys
from pathlib import Path
sys.path.insert(0, 'test/tostester/src')
from pytosiq_core.boc import Cell
root = Path('test/rel02/corpus')
m = json.loads((root / 'manifest.json').read_text())
replies = {}
for path in sorted(Path(os.environ['IDS_DIR']).glob('*.json')):
    for node, per in json.loads(path.read_text()).items():
        for seq, rec in per.items():
            shards = rec['shards']['result']['shards'] if 'shards' in rec else []
            for r in [rec['lookup']['result']] + shards:
                replies.setdefault((r['workchain'], int(r['seqno'])), {}).setdefault(node, r)
con = json.loads(Path(os.environ['CON01_RAW']).read_text())
for node in ('node-1', 'node-3'):
    for seq, rec in con['nodes'][node]['lookup'].items():
        rs = [rec['response']['result']] + con['nodes'][node]['shards'][seq]['response']['result']['shards']
        for r in rs:
            replies.setdefault((r['workchain'], int(r['seqno'])), {}).setdefault(node, r)
for entry in m['files']:
    if entry['kind'] != 'block':
        continue
    b = entry['source_block']
    data = (root / entry['path']).read_bytes()
    assert hashlib.sha256(data).hexdigest().upper() == b['file_hash']
    assert Cell.one_from_boc(data).get_hash(0).hex().upper() == b['root_hash']
    got = replies[(b['workchain'], b['seqno'])]
    for node in ('node-1', 'node-3'):
        r = got[node]
        assert base64.b64decode(r['root_hash']).hex().upper() == b['root_hash'], (node, b)
        assert base64.b64decode(r['file_hash']).hex().upper() == b['file_hash'], (node, b)
print('every block equals the node-1 and node-3 full ids')
PY
```

`check_oracle.py` independently checks every packed root's recorded hashes and
re-decodes the original transaction oracle. `run.py --controls` performs the
corpus-byte, expected-state and empty-code execution controls; receipts are
uploaded with each architecture's CI result. The negative operation shares the
normal replay/emulation path and only replaces contract code before the emulator
call. Removing that replacement must make `--controls` fail with
`execution control did not change a consensus result`.
