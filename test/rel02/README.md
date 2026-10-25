# Cross-architecture epoch replay (REL-02)

This offline corpus contains 340 original public epoch-5 blocks (global id 2;
183 masterchain, 157 basechain) and the original cells needed to execute their
475 transactions. The manifest and all BOCs total about 4.51 MB, below the 20 MB
budget. No network, validator database, private key, or node service is needed to
run it. The corpus contains no generated positive chain fixtures.

## Coverage

Rows are disjoint. Block identifiers and input SHA-256 values are in
`corpus/manifest.json` (each block's `case` names its row); its expected records
come from decoding the original transaction/block BOCs, independently of the
native emulator.

| Cases | Blocks | Transactions | Coverage |
| --- | ---: | ---: | --- |
| `tok01`: consecutive masterchain 117753–117895 | 143 | 294 | Every masterchain block of the Token/NFT run: ticks/tocks, configuration and elector traffic |
| `tok01`: basechain 118260–118404 registered by those blocks | 140 | 42 | Collection deploy, mint 1000 and 100, transfer to an existing and to an undeployed wallet, transfer with payload notification, insufficient balance (exit 706, aborted, bounced), burn, admin change, NFT mint, NFT transfer, NFT transfer by a non-owner (exit 401, aborted, bounced); 128 empty blocks between them |
| `cp15`: masterchain 151331, 151410, 151706, 151780, 151828, 151876 | 6 | 28 | ConfigParam 15 critical proposal registration through the Config contract, a proposer-wallet transaction with no outgoing message, round-1 votes |
| `cp15`: masterchain 161046, 161094 | 2 | 10 | Round-2 votes |
| `cp15`: masterchain 194882–194884 | 3 | 6 | Validator rotation key block 194883 (ConfigParam 32/34) before round 3 |
| `cp15`: masterchain 195411, 195426, 195440, 195453–195455 | 6 | 24 | Round-3 votes and the adoption key block 195454 that installs the new ConfigParam 15 |
| `shard-exits`: basechain 152032, 152121, 152207, 152292, 152470, 152559 | 6 | 23 | Basechain service traffic during round 1 with contract-defined compute exits 1800, 1803 and 1808 (aborted) |
| `rotation`: masterchain 230373–230384 and basechain 231429–231440 | 23 | 25 | The first two-hour validator rotation: key block 230378 (ConfigParam 32/34) and the blocks around it |
| `context`: masterchain 117750, 117752, 151333, 151421, 151510, 151596, 151772, 151861, 230370–230372 | 11 | 23 | Exact masterchain contexts referenced by the selected basechain blocks |

Three selected blocks are key blocks (194883, 195454, 230378). Split/merge
blocks are not covered; the harness refuses them rather than guessing a
predecessor state.

Excluded, because no two-validator full id exists for them in the id captures:

- Basechain 118263, the token master deploy. A `shards` reply names only the
  newest basechain block a masterchain block registers, and masterchain 117756
  registers 118265; 118263 is reachable from it only through the hash links of
  118264 and 118265. Its contract code is used as an original cell source (bound
  by hash), not replayed.
- Empty basechain 118261, 118264, 118286, 118313 and 231435, and basechain
  152381 (service traffic), for the same reason.
- Masterchain 160950 and 160997, the first two round-2 votes: outside the
  captured range 161000–161250.

## What is checked

`test-epoch-replay` links the existing native codec, configuration reader,
Merkle-update implementation and transaction emulator. For every block it:

1. Parses and reserializes the BOC byte-for-byte, and round-trips the block TL-B
   record. It emits the original root/file hashes and serialization mode.
2. Validates and applies the authenticated Merkle state update to its original
   previous-state witness, requiring the declared new state hash.
3. Loads each account's authenticated previous state. It binds its hash to the
   original transaction's pre-state hash and executes every transaction with the
   original timestamp, logical time, random seed, configuration and libraries.
   Signature verification is enabled. It requires exact transaction and resulting
   account hashes, carrying the executed account between transactions.
4. Emits actual execution results: transaction description/hash, account hash,
   gas, compute/action exit codes, aborted status and outgoing-message hashes.

A shard replay requires its exact referenced masterchain block (root, file hash
and sequence number). That block's state supplies the configuration and previous
masterchain-block VM context. Missing context or a required pruned preimage is a
failure. Supplementary cells are combined only by their authenticated level-zero
hash, using the existing proof combiner; they cannot replace historical values.

This is authenticated state-update application plus transaction execution. It
does not regenerate a block with the collator or perform every block-validation
check. The manifest oracle and exact transaction hashes prevent the harness from
passing by merely printing recorded transaction summaries.

`run.py` pins every input's bytes, requires every output record to equal the
on-chain oracle, and writes canonical JSON lines. `--compare` additionally requires
byte-identical outputs from both architectures and names the first differing
item/field. A native failure cannot be reported as clean even if its emitted
prefix matches. The final workflow job also requires both matrix jobs to succeed.

## Provenance and files

Every replayed block's root and file hash equals the full block ids returned by
validators node-1 and node-3. [Capture commands and receipts](CAPTURE.md) describe
the local, read-only capture from the archive packages of a full node synced
from genesis; no host was contacted and no live database was opened.
`files` records each block's source ID and SHA-256. One native multi-root BOC,
`state-parts.boc`, packs the original supplemental cells, so the corpus has 341
inputs. Its file entry records SHA-256 and source block IDs; `supplement_roots`
records each of its 758 original roots with hashes and provenance:

- 756 `original_state_update` roots: the whole state-update cell of an archived
  block (751 masterchain blocks 3–230369 and basechain 105530, 118263, 150944,
  151779 and 152381). The configuration,
  previous-block VM context and account cells the replay reads but that a
  selected block's own Merkle update prunes come from these.
- One `original_block_extra` root: key block 154916's extra, whose configuration
  holds cells the elector and Config contract read.
- One `zero_state` root: the genesis zero state, for cells unchanged since
  genesis. Its hashes equal the initial block id node-1 and node-3 return.

292 roots come from blocks with node-1/node-3 ids (`verified_rpc_nodes`); the
others are bound by hash only, which is sufficient for their use: a cell is
accepted only where a verified block's state holds a pruned branch of the same
level-zero hash. Re-encoding the BOC container creates no new state values.

The files have separate purposes:

- `emulator/test/epoch-replay.cpp` is a small entry point into existing native
  execution libraries. Existing replay tools require node databases or complete
  validation environments; this entry point accepts bounded authenticated cells.
- `run.py` pins the corpus, checks the independent oracle and compares artifacts.
- `check_oracle.py` independently decodes original BOCs with the existing vendored
  Python codec. It checks oracle regeneration; it is not used to compute native
  execution results or required at replay runtime.
- `test_run.py` exercises failure reporting and refuses incomplete/malformed
  comparison results. It adds no synthetic positive chain fixtures.
- `corpus/manifest.json` records the oracle and provenance; the BOCs are its inputs.
- `CAPTURE.md`, `capture-index.json` and `capture-commands.json` retain the local
  capture programs, exact archive locations and the independent full-id replies.
  They remain auditable after the archive and the id captures are gone.
- `VALIDATION.json` records source/data hashes and the execution-control
  sensitivity receipt; hosted runs repeat the controls on both architectures.
- `.github/workflows/epoch-replay.yml` provides one bounded two-architecture
  matrix and a dependent artifact comparison, on pull requests and pushes to
  main. Existing architecture workflows do not compare these execution artifacts
  with each other. The block files are also inputs of `test-lite-proof-content`.

## Run

Use the repository's `Dockerfile.builder` environment (with its release
prerequisites). These are the effective epoch release arguments:

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
  -DTOS_ARCH=x86-64-v2 -DPORTABLE=x86-64-v2 -DTOS_USE_JEMALLOC=ON
cmake --build build --target test-epoch-replay --parallel 2
python3 test/rel02/test_run.py
python3 test/rel02/run.py --executable build/emulator/test-epoch-replay \
  --output result/outputs.jsonl --metrics result/metrics.json --controls
```

Use `armv8-a` for both architecture options on arm64. The hosted runners are
`ubuntu-24.04` and `ubuntu-24.04-arm`; the workflow pins action revisions and
uploads each architecture's outputs, metrics and mutation receipts.

`--controls` changes one corpus byte (must refuse its SHA-256), restores and
replays, then alters an expected new-state hash (must name that field), restores
and replays again. Each red/green result is written beside the output. The eight
comparison/provenance self-tests also exercise a semantic difference before a
missing tail,
missing fields/records, boolean-versus-number differences and a nonzero native
exit. The automated execution control replaces contract code with an empty cell
in the same native replay path and requires a changed actual account hash; normal replay
must then restore the identical baseline outputs. It runs in both hosted jobs.
`CAPTURE.md` records acquisition and mutation reproduction commands. The
architecture artifacts retain exact red/green statuses and mismatch values.

With the existing Python test dependencies installed, independently check the
recorded oracle:

```sh
python3 test/rel02/check_oracle.py
python3 test/rel02/run.py --compare x86/outputs.jsonl arm/outputs.jsonl
```
