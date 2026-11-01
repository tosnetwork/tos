# Wallet-index replica capacity measurement

Run this on a separate, offline-installed copy of the real testnet data, using the
production binaries from the reviewed commit. The source node must be stopped.
The runner writes only a new output directory, samples loopback readiness, and
compares a metadata inventory of the source before and after. It never publishes
an endpoint or enables partial verification.

## Inputs and scope

The planned acceptance dataset is the EPOCH-6 STA-03 generation abbreviated
`f29d660a...581d`, at masterchain block 188992. Obtain the **complete** generation
manifest, content hashes and authenticated head from the operator's retained
artifact. The abbreviated name is not an integrity check. A different historical
benchmark dataset is a separate measurement and cannot close this acceptance.

- Path A starts with an absent index and builds from the retained window against
  the node's authenticated head. The source must have joined after block 1; a
  full replay from genesis is not counted as the intended Path A.
- Path B imports an untrusted snapshot, verifies the window and its history,
  derives ownership and drains outstanding work, then reaches Full verification.
- The conditional time targets are 6 hours for Path A and 2 hours for Path B,
  **including fresh-node preparation**, within the measured dataset and host
  envelope. Record source acquisition, transfer, offline verification/installation
  and node catch-up time separately; pass their measured total to the runner.
  Missing preparation time is unavailable, never assumed to be zero.
- Use the actual applied source tip as the target. A replay ceiling below the
  source tip never becomes caught up and does not exercise the full import gate.

Required files are the stopped native `state/`, `celldb/` and `archive/` store,
the full target masterchain block ID (seqno, root hash and file hash), the reviewed
release binaries, and for Path B the real snapshot. Retain the source manifest
and the binary build receipt. The runner records the binary hashes and the supplied
source-manifest hash; a user-supplied commit string or receipt alone does not
authenticate the data or binary build.

## Commands

Run each path separately with fresh output and the same frozen source. These
commands are templates; replace the full target and preparation time with actual
operator evidence. `SOURCE`, `BUILD`, `MANIFEST` and `SNAPSHOT` are ordinary task
variables referring to the prepared replica, reviewed build and retained files.

```sh
python3 scripts/wallet-index-replica-capacity.py \
  --mode path-b --dataset-kind real-replica \
  --build "$BUILD" --source-db "$SOURCE" --source-receipt "$MANIFEST" \
  --source-commit FULL_REVIEWED_COMMIT --snapshot "$SNAPSHOT" \
  --target-block-id 'FULL_MASTERCHAIN_BLOCK_ID' \
  --preparation-seconds MEASURED_SECONDS --root /srv/measurements/path-b

python3 scripts/wallet-index-replica-capacity.py \
  --mode path-a --dataset-kind real-replica \
  --build "$BUILD" --source-db "$SOURCE" --source-receipt "$MANIFEST" \
  --source-commit FULL_REVIEWED_COMMIT \
  --target-block-id 'FULL_MASTERCHAIN_BLOCK_ID' \
  --preparation-seconds MEASURED_SECONDS --root /srv/measurements/path-a
```

`--reference-index` optionally supplies an independently rebuilt, stopped index
at the identical head. Native canonical dumps must agree over the measured
index's **entire** served window; a narrower reference is refused. Without this
input, the receipt records the canonical digest and marks the independent
comparison unavailable. Run the second path with the first path's stopped index
to obtain a useful Path A/Path B comparison; label its provenance accurately.

`--block-times headers.json` accepts native block-header observations in this form:

```json
[
  {"block_id": "FULL_EARLIER_MASTERCHAIN_BLOCK_ID", "gen_utime": 1790000000},
  {"block_id": "FULL_LATER_MASTERCHAIN_BLOCK_ID", "gen_utime": 1790000100}
]
```

Use real headers from the same frozen chain and retain their extraction/proof
receipt. The runner hashes this input, checks ordering, and computes historical
chain growth from sequence/time differences. It compares that with advancing
replay-counter samples. No advancing samples, or no supplied header times, means
the comparison is unavailable. This is not a live-network soak: a positive
historical rate margin is evidence for this dataset, not a guarantee against
future traffic or different I/O contention.

## Evidence and interpretation

`receipt.json` records the exact target, binary and input hashes, source metadata
invariance, the final cursor, sampled verification phases, import duration, time to
Full/caught-up, per-stage peak RSS from Linux `wait4`, sampled anonymous memory and
disk use, final index size, canonical identity/digest, and optional comparisons.
Stage JSON, JSONL samples and logs remain beside it for inspection. A short stage
can have no anonymous-memory sample; its per-child peak RSS remains available.
Disk peaks are sampled every five seconds and may miss a shorter transient.
The metadata inventory is not a cryptographic hash of every archive file; retain
the original authenticated generation manifest as the source-content evidence.

Exit 0 means the measured path completed all functional checks and its supplied
total-time target; it is conditional on the recorded input/hardware envelope.
Exit 1 means a functional check or supplied limit failed. Exit 2 means the path
was measured but total-time acceptance is unavailable (for example preparation
time was not supplied). `--fixture-smoke` is not an option: use the explicit
`--dataset-kind fixture-smoke`; it always makes capacity acceptance unavailable.
Neither the harness's unit tests nor the small native lifecycle fixture is real
testnet capacity evidence. External security review remains a separate gate.

The default stage watchdog is six hours and can be changed with `--stage-timeout`.
`--max-total-seconds` records an explicit alternative time bound;
`--max-rss-mib` adds an optional measured process-memory ceiling. No production
memory ceiling is inferred from the old replay benchmark. Preserve CPU model,
RAM, disk model/filesystem, cache condition, available space and competing I/O in
the operator receipt when comparing runs. Store bulky run output outside Git;
commit only the command, exact inputs, concise result and retained artifact hashes.

## Local harness checks

```sh
python3 scripts/test_wallet_index_replica_capacity.py
```

These check the readiness, target-binding, time-accounting and measurement
controls. They do not need, create or substitute a real testnet replica.
