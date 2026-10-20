# Cross-architecture epoch replay (REL-02)

This offline corpus contains 248 original public epoch-4 blocks and the original
proof/account/state-update cells needed to execute their transactions. There are
564 transactions. The manifest and all BOCs total about 5.30 MB, below the 20 MB
budget. No network, validator database, private key, or node service is needed to
run it. The corpus contains no generated positive chain fixtures.

## Coverage

Rows are disjoint. Block identifiers and input SHA-256 values are in
`corpus/manifest.json`; its expected records come from decoding the original
transaction/block BOCs, independently of the native emulator.

| Cases | Blocks | Transactions | Coverage |
| --- | ---: | ---: | --- |
| Consecutive masterchain 269566–269765 | 200 | 429 | Real state transitions, special-contract ticks/tocks and ordinary transactions |
| Masterchain 309465 and 309734 | 2 | 10 | CP20/CP24 adoption, key blocks and configuration messages |
| Masterchain 317043/317044/317143/317144 | 4 | 28 | Operator, pool, controller and Elector; stake bid and recover/return paths, PQ verification |
| Masterchain 328605–328607 | 3 | 8 | Successful election result, configuration acknowledgement and subsequent tick |
| Masterchain 357884 and 387273 | 2 | 4 | October 20 insufficient-participant/postponed election attempts (three submitted stakes) |
| Masterchain 361394/361395/361424/390905/390906/390929 | 6 | 21 | Actual cancellation, fresh election window, and node-1 refund for both failed rounds |
| Masterchain 234331 | 1 | 8 | Real aborted transaction, nonzero compute exit and bounced message |
| Exact modern masterchain contexts | 6 | 12 | Contexts 431391–431396 referenced by the empty shard blocks |
| Exact load-test masterchain contexts | 8 | 17 | Contexts 356489/356491/356493/356494/356496/356497/356499/356501 |
| Shard 448307–448314 | 8 | 0 | Empty shard blocks, codec/state updates and exact masterchain binding |
| Busy shard blocks 363868/363872/363874/363875/363877/363878/363880/363882 | 8 | 27 | Actual wallet/relayer execution and plain internal transfers |

Three selected blocks are key blocks. The close-time cases are postponed
election attempts; the deadline/refund cases cover the later cancellation and
return, without inventing an elected set for a failed round. No real
Token/NFT transaction was located in the retained evidence used for this corpus;
those transaction types are **not covered**. Split/merge blocks are also not
covered; the harness refuses them rather than guessing a predecessor state.

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

Every original block's root and file hash was checked against full block IDs from
two validators. Existing coordinator captures were reused where available; new
archive reads used immutable package files only. No live database was opened.
`files` records each block's source ID and SHA-256. One native multi-root BOC,
`state-parts.boc`, packs the original supplemental cells, reducing the fixture
count to 249 inputs. Its file entry records SHA-256 and source block IDs;
`supplement_roots` records each original root's hashes and provenance. The 1,686
original roots were independently checked for identical hashes, bits and
referenced hashes after packing.

An `original_state_update` root is the original cell extracted from an acquired
block; `source_cell_hash` and `source_file_sha256` bind it to that block. Other
roots are original RPC proof or public account code/data cells. Re-encoding the
BOC container creates no new state values. Copied source/unit-test captures are
excluded; only known actual epoch captures supply account cells.

The new files have separate purposes:

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
- `.github/workflows/epoch-replay.yml` provides one bounded two-architecture
  matrix and a dependent artifact comparison. Existing architecture workflows
  do not compare these execution artifacts with each other.

## Run

Use the repository's `Dockerfile.builder` environment (with its release
prerequisites). These are the effective epoch release arguments; the ignored
`TOS_PRODUCTION_BUILD` option is deliberately absent:

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
comparison/provenance self-tests also exercise a semantic difference before a missing tail,
missing fields/records, boolean-versus-number differences and a nonzero native
exit. A separate implementation control replaced executed contract code with an
empty cell: actual account/transaction results changed and the gate failed;
restoring the source restored green. To repeat it in a disposable checkout,
insert `account.code = vm::CellBuilder{}.finalize();` immediately before the
`emulate_transaction` call, build and run the command above (must fail on
`account_hash`), then remove the line, rebuild and run again (must pass). No
mutation code remains in the harness.

With the existing Python test dependencies installed, independently check the
recorded oracle:

```sh
python3 test/rel02/check_oracle.py
python3 test/rel02/run.py --compare x86/outputs.jsonl arm/outputs.jsonl
```
