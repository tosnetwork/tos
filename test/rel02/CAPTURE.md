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

## Staking capture

The `staking` case was added by a second capture of the whole selection, with the
same method and the same read-only inputs plus:

- node (b)'s archive packages: a second full node's packages for masterchain
  248,301–262,749 (basechain 249,421–263,978), checked against their own SHA-256
  list (`$ARCHIVE_B_SHA256SUMS`). `$ARCHIVE_DIR` is a read-only view of both
  archives, node (a)'s packages at their own paths and node (b)'s under `node-b/`,
  so the earlier archive locations keep their names. Neither archive covers
  masterchain 242,334–248,300.
- node-1/node-3 `lookupBlock` and `shards` captures for masterchain 172,796–172,908,
  177,942–178,387, 191,315–191,426, 212,786–213,221, 221,505–222,989,
  248,148–248,690 and 259,146–260,176, listed in the same `$IDS_DIR/SHA256SUMS`.

`plan.py` adds the 15 staking blocks named in the README (all masterchain, so
they need no masterchain context). `capture.py` adds the node (b) checksum step and
extends the cell index over both archives. All 15 have two-validator full ids
equal to their archive bytes, so none is excluded. The ids for 248,148–248,690
are verified but no block from them is planned: 248,148–248,300, which holds that
election's recovery, is in neither archive, and 248,301–248,690 holds no staking
transaction.

This was the first run of `test/rel02/capture/resolve.py` on real data. An
attempt in a separate work directory, whose diagnostic wrapper was not
executable, was refused (`diagnostic replay could not start: [Errno 13]
Permission denied`, exit 1, no `resolve.json`); the earlier program would have
read that as no failing blocks. The recorded run then accepted 124 diagnostic
runs over the 366 selected blocks: every child exited 0, announced every block
in order and left none without a block record or a reported failure. It ended
with no failing block, 1523 sources and 942 records. The resolver drew 119
masterchain sources and the extra of key block 250,344 from node (b)'s archive.

`capture-commands.json` keeps the first capture as it ran. Its `staking_capture`
entry holds the new `capture.py` and `plan.py`, `resolve.py` as committed in
`test/rel02/capture/`, the SHA-256 of each unchanged program, the diagnostic
build and the resolver receipt; the steps whose ids start with `staking-` were
appended to `steps`. To reproduce it, write the `scripts` entries into one new
directory, overwrite them with the `staking_capture` scripts, and run
`capture.py` with `ARCHIVE_B_SHA256SUMS` also set. Re-running the whole selection
rewrote `capture-index.json`, the manifest and `state-parts.boc`; the earlier
cases' block files and their 845 replay output records are unchanged.

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


## Account completeness supplement (2026-10-26)

The retained node-a manifest was verified before copying the archive packages.
A full-hash scan of masterchain block cells located the missing preimages in
blocks 53209 and 212648. Their original bytes are committed unchanged as
`corpus/account-preimages/-1-53209.boc` and `-1-212648.boc`. They are added to
`supplements`, not `blocks`, so the replay cases and on-chain oracle stay fixed.
The capture index records both source full IDs and exact package ranges;
`rpc_verification: []` means hash-bound source provenance, not a new independent
validator observation. The manifest's `complete_account_preimages` records
the original reference paths and complete subtree hashes/counts.

Reacquisition uses the same bounded package-entry read above, selecting the
source by block ID (these entries have `case: null`). Require the recorded
payload size/SHA-256 and decoded root hash before using a source. Retaining
only the 53209 state update is not the chosen receipt: its target candidate
still has a pruned child, while its block extra contains the full preimage.
Existing native hydration may recover that child from other supplements, but
the original full block makes the complete source directly auditable.
