# Cross-architecture epoch replay (REL-02)

This offline corpus contains 366 original public epoch-5 blocks (global id 2;
202 masterchain, 164 basechain) and the original cells needed to execute their
576 transactions. The manifest and all BOCs total about 7.61 MB, below the 20 MB
budget. No network, validator database, private key, or node service is needed to
run it. The corpus contains no generated positive chain fixtures.

## Complete account preimages

Two additional original archive blocks are retained under
`corpus/account-preimages/`: masterchain 53209 and 212648, totaling 19,476
bytes. They are supplemental cell sources, not additional replay cases.
Their complete ordinary subtrees replace the two distinct pruned hashes
that appeared in 147 input ShardAccounts. The manifest records full block
identities and reference paths in `complete_account_preimages`.

The source from 53209 must include its block extra: the same logical hash
also has a partial representation in its state update. The complete subtree
has 57 nodes; the second source's subtree has seven. The existing native
proof combiner handles matching representations without changing level-zero
hashes. All original 366 cases and 942 expected output records are unchanged.

Source bytes came from checksum-verified retained archive packages. The new
sources have no independent RPC ID capture; they are bound by their file/root
hashes and the matching preimages under existing authenticated account roots.
`capture-index.json` records package entries, byte ranges and this distinction.
The input-completeness probe checked all 576 accounts for pruned descendants,
compared every input logical root with the previous dump, and obtained zero
incomplete accounts. Removing these supplements restores 147 incomplete
accounts. This does not claim general instruction coverage. The continuous
Rust replay gate below consumes these complete inputs.

## Coverage

Rows are disjoint. Block identifiers and input SHA-256 values are in
`corpus/manifest.json` (each block's `case` names its row); its expected records
come from decoding the original transaction/block BOCs, independently of the
native emulator.

| Cases | Blocks | Transactions | Coverage |
| --- | ---: | ---: | --- |
| `tok01`: consecutive masterchain 117753–117895 | 143 | 294 | Every masterchain block of the Token/NFT run: ticks/tocks, configuration and elector traffic |
| `tok01`: basechain 118260–118404 registered by those blocks | 145 | 44 | Token master deploy, collection deploy, mint 1000 and 100, transfer to an existing and to an undeployed wallet, transfer with payload notification, insufficient balance (exit 706, aborted, bounced), burn, admin change, NFT mint, NFT transfer, NFT transfer by a non-owner (exit 401, aborted, bounced); 132 empty blocks between them |
| `cp15`: masterchain 151331, 151410, 151706, 151780, 151828, 151876 | 6 | 28 | ConfigParam 15 critical proposal registration through the Config contract, a proposer-wallet transaction with no outgoing message, round-1 votes |
| `cp15`: masterchain 160950, 160997, 161046, 161094 | 4 | 20 | Round-2 votes |
| `cp15`: masterchain 194882–194884 | 3 | 6 | Validator rotation key block 194883 (ConfigParam 32/34) before round 3 |
| `cp15`: masterchain 195411, 195426, 195440, 195453–195455 | 6 | 24 | Round-3 votes and the adoption key block 195454 that installs the new ConfigParam 15 |
| `shard-exits`: basechain 152032, 152121, 152207, 152292, 152381, 152470, 152559 | 7 | 26 | Basechain service traffic during round 1 with contract-defined compute exits 1800, 1803 and 1808 (aborted) |
| `rotation`: masterchain 230373–230384 and basechain 231429–231440 | 24 | 25 | The first two-hour validator rotation: key block 230378 (ConfigParam 32/34) and the blocks around it |
| `context`: masterchain 117750–117752, 151333, 151421, 151510, 151596, 151685, 151772, 151861, 230370–230372 | 13 | 27 | Exact masterchain contexts referenced by the selected basechain blocks |
| `staking`: masterchain 172824, 177967, 178028, 178083, 178145, 178206, 178267 | 7 | 36 | Elector stake refusals, each returned with op `0xee6f454c` and its reason: no election open (0, 172824); a bad signature, a wrong global id and a wrong `src_addr` (1, 177967, 178028, 178083); below `min_stake` (5, 178145); below 1/4096 of the total (2, 178206); a stake for another election (3, 178267). Each block holds the probe wallet's external message, its `new_stake`, the Elector's refusal and the wallet receiving the returned value |
| `staking`: masterchain 191343, 259207 | 2 | 11 | `recover_stake` with no credit, answered `0xfffffffe` (191343); a pool's `recover_stake`, sent on a wallet's request and answered `0xf96f7324` with 10,369.84 TOS of credit after the 13:00 UTC term (259207) |
| `staking`: masterchain 221616, 221669, 221688, 221689, 259307 | 5 | 30 | Accepted stakes: a wallet's stake request to its pool, the pool's `new_stake` to the Elector, the Elector's confirmation `0xf374484c` and the pool receiving it, for the four pools of the 12:00 UTC election and for the pool that recovered in 259207 staking again in the 16:15 UTC election |
| `staking`: masterchain 213016 | 1 | 5 | A single-nominator pool owner's withdrawal (op `0x1000`) of the pool's liquid balance, paid back to the owner wallet |

Three selected blocks are key blocks (194883, 195454, 230378). Split/merge
blocks are not covered; the harness refuses them rather than guessing a
predecessor state.

No planned block is excluded. Basechain blocks that are not the newest one a
masterchain block registers (among them the token master deploy 118263), and
masterchain 160950 and 160997 outside the captured ranges, carry ids from
separate node-1/node-3 `lookupBlock` captures.

### Staking coverage

The third-party review of the first epoch-5 corpus asked for stake submission,
stake recovery and failed-election cancellation/refund coverage. The `staking`
rows cover them as follows:

- **Stake submission: covered.** Five accepted stakes with the Elector's
  confirmation, and refusals with reasons 0, 1, 2, 3 and 5, each with the
  returned value arriving back at the sender.
- **Stake recovery: covered.** A recovery that returns credit (259207) and one
  with no credit (191343).
- **Failed-election cancellation/refund: partly covered.** The refusals above are
  the Elector's refund path. A failed election that is postponed is not covered:
  the postponed election whose ids were captured for masterchain
  248,148–248,690 is not in the archives. Node (a)'s archive ends at 242,333 and
  node (b)'s starts at 248,301, so its recovery block (about 248,24x) is in
  neither. In 248,301–248,690 node (b) holds only Elector ticks and empty-body
  Elector messages from the zero address: no `new_stake`, no message to the
  Config contract and no key block. No block from that capture is planned.

No planned staking block is excluded. Masterchain 259207 and 259307 come from
node (b)'s archive, the others from node (a)'s.

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
validators node-1 and node-3, from `lookupBlock` or from a masterchain block's
`shards` reply. [Capture commands and receipts](CAPTURE.md) describe
the local, read-only capture from the archive packages of a full node synced
from genesis, and of a second full node for masterchain 248,301–262,749; no
host was contacted and no live database was opened.
`files` records each block's source ID and SHA-256. One native multi-root BOC,
`state-parts.boc`, packs the original supplemental cells, so the corpus has 367
inputs. Its file entry records SHA-256 and source block IDs; `supplement_roots`
records each of its 1525 original roots with hashes and provenance:

- 1522 `original_state_update` roots: the whole state-update cell of an archived
  block (1518 masterchain blocks 3–259310 and basechain 105524, 105530, 150944
  and 151779). The configuration,
  previous-block VM context and account cells the replay reads but that a
  selected block's own Merkle update prunes come from these.
- Two `original_block_extra` roots: the extras of key blocks 154916 and 250344,
  whose configurations hold cells the elector and Config contract read. 250344 is
  in node (b)'s archive.
- One `zero_state` root: the published genesis zero state, for cells unchanged
  since genesis, bound by the initial block id node-1 and node-3 return.

506 roots come from blocks with node-1/node-3 ids (`verified_rpc_nodes`); the
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
  comparison results. It adds no synthetic positive chain fixtures. It also runs
  the capture resolver against stub diagnostic children, which must be refused
  when they fail, are killed, time out or replay only part of the selection.
- `corpus/manifest.json` records the oracle and provenance; the BOCs are its inputs.
- `CAPTURE.md`, `capture-index.json` and `capture-commands.json` retain the local
  capture programs, exact archive locations and the independent full-id replies.
  They remain auditable after the archive and the id captures are gone.
  `capture/resolve.py` supersedes the recorded `resolve.py` for re-captures.
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


## Continuous Rust execution

Build `test-epoch-replay` and the release `tos_executor` example `rel02-replay`,
then run on Linux:

```sh
python3 test/rel02/run_rust.py --native build/emulator/test-epoch-replay \
  --rust tosctl/src/target/release/examples/rel02-replay --output result/rust.json
python3 test/rel02/test_rust_artifacts.py --receipt result/rust.json \
  --output result/artifact-controls.json
```

Use fresh output paths. The orchestrator copies bounded, SHA-256-verified
corpus files, requires successful native execution and all 942 original oracle
records, and passes that exact versioned export plus its digest to Rust.
A caller-supplied dump/digest alone does not authenticate execution context.
All 576 raw account inputs must be complete before Rust executes any transaction.
The reviewed topology records 474 predecessor edges and 102 segment anchors
across 25 accounts; these sparse captures do not represent continuous history.
Actual Rust Account objects and storage-stat caches cross every present edge.
No mismatch resets state to the native input or permits a skipped transaction.

The nine-field Rust output contains index, type, LT, comparison labels,
diagnostic, actual transaction root, actual Account root and actual
ShardAccount root. `rust.roots.tsv` preserves these actual outputs and the
schema-3 receipt binds their digest. The comparator requires complete x86_64
and aarch64 artifacts and compares both to the oracle and each other. Receipt
counts without actual roots are insufficient. The #rel02-v2 native export has
18 fields; its final field is post-Account depth, emitted only after native
transaction and Account roots agree with the chain. The receipt also binds
`rust.native-depths.json`, ordered by index and original transaction hash.
Both Rust and Python independently derive each expected ShardAccount root from
that depth and the original transaction hash/start LT and output Account hash.
This checks every terminal segment too; equal errors on both architectures
cannot replace the per-row oracle. CI retains source/compiler/build
provenance and requires both matrix jobs to succeed.

The bounded offline processes use a 4 GiB address-space cap, 600-second CPU/wall
limits, 64 MiB per output file and 8 MiB parent diagnostic reads. Dump parsing
allows 64 MiB total, 1 MiB per row, at most 10,000 rows, and account traversal
at most 2,000,000 visits/depth 1,024. Refusal is an error, not a semantic mismatch
or a successful partial replay. Tests exercise process/output limits, timeout/cancellation
cleanup, invalid schema/identity and mutations of actual output artifacts.

The native `--check-dump-representations` control uses original block 53209's
complete and partial witnesses sharing a logical hash. It places both into one
copy traversal and requires the complete representation root to survive.
The production C++ VM and transaction semantics are unchanged.
