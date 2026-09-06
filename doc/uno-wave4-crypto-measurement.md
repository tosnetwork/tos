# Wave 4: semantic admission and real ABI measurement

## Scope and instrument

`test-uno-crypto-cost` is test-only, not a production engine, wire/profile,
ConfigParam 84 parser, or consensus-entry admission session. It first meters the
entire logical request list, then calls the real `uno_crypto_verify_v0` for each
occurrence. Pointer sharing does not discount proof calls, actions or bytes.

Its explicit counters are proof-call count, public Action count, and **ABI payload
bytes** (proof bytes + Action count × 884). This last metric excludes public
header fields and is not production canonical wire bytes, BoC size, input Cells,
or the engine-defined `wire_bytes`. It is not interchangeable with the three
frozen structural input limits. All counter multiplication/addition is checked.
The prototype rejects bad shape and over-budget work before any backend call.

Self-test command:

```
build/uno/crypto/test-uno-crypto-cost --self-test
```

The exact two-occurrence boundary is accepted; one proof/action/payload-byte
under that boundary invokes zero backend calls. Mutations independently removed
each of the three limit checks, bypassed proof shape, or discounted repeated
pointers: each made the backend invocation assertion fail with two calls.
Removing checked addition and multiplication separately also made the self-test
fail. Every mutation was restored. Logs are `build/wave4-cost-*-mutation.log`.

## Recorded workload

The measurement command (run only in the coordinated quiet interval) is:

```
RAYON_NUM_THREADS=48 build/uno/crypto/test-uno-crypto-cost --measure output-only.bin spend.bin
```

It emits raw JSONL with monotonic nanosecond measurements:

- One fresh-process key construction + full verification call (not isolated VK
  construction alone).
- Twenty warm single calls for each of the public funding/spending fixtures.
- Batch sizes 1/16/64/256/700, three samples per size and fixture, valid and with
  the last request's digest changed. The latter reaches authorization/signature
  failure after proof verification, per the inspected verifier ordering; the
  funding and spending paths are not collapsed into a claim about a particular
  real-spend signature. It is not an
  arbitrary “worst malicious bundle” claim.
- Twenty shape-rejection samples per fixture, with a 700-entry list whose first
  item has an empty proof. These measure earliest cheap rejection, not an O(700)
  last-item-invalid parsing worst case.

Each non-rejected sample separately reports the meter time and the actual loop
of complete ABI calls, with checked expected statuses. These are repeated calls,
not a multiplication of a single-call measurement. Fixture loading and pointer
list allocation occur outside timed stages. `process_hwm_rss_kib` is Linux
process-lifetime high-water RSS, **not** a per-phase or per-batch incremental
peak. It includes earlier workloads/key construction in the same process.

## Limits of interpretation

The fixtures each contain **two Actions and a 7264-byte proof**. They are real
public test proofs, but repeated occurrences reuse nullifiers and are not a valid
UNO block. This intentionally measures verifier pressure after bypassing global
state uniqueness, not successful multi-transfer execution or an admissible
production maximum. In particular, 700 × 9032 = 6,322,400 payload bytes already
exceeds a 4 MiB envelope before counting headers; it is a pressure sequence, not
evidence that a 4 MiB candidate contains 700 of these two-Action fixtures.
Every batch row reports actual proof calls, actions and payload bytes. Larger real bundles, distinct proof distributions, random
malicious points, final binding-signature failure, parallel verification,
proving, and global state verification are not covered here.

The meter offers a place to enforce logical work, not calibrated universal cost
weights. Two-Action data cannot fit independent per-action/per-proof weights or
show the cost of a production maximum structure budget. No host commitment,
canonical inbox, authenticated state acquisition, tree update, serialization,
CellDb commit, or committee path is in this measurement. Its wall time cannot be
called end-to-end validation time, and sanitizer measurements are not used as
performance data.

Production values remain pending D-3's complete workload envelope and the real
configured validation deadline. A measured maximum is not WCET; no coefficient,
safety factor, or proposed limit is silently installed by this test.

## Recorded run

Frozen public fixture inputs are committed as
`doc/measurements/uno-wave4-funding.bin.b64` and `uno-wave4-spend.bin.b64`.
Decode base64 to reproduce the exact test bytes; decoded SHA-256 values are:

- funding: `6db0ab8420cc9d30dc20db61e4a9cdcc0c0571e837ce16e9a4199d66f8170aa2`
- spend: `491cbbe26ed631047e8f83b1526714203d63c7908bac176392eae0494478a8a9`

These came from `real_bundle_requires_proof_and_signatures` exports at
`build/uno/crypto/fixtures/0c5be50e302c7406d822`. The generator uses `OsRng`;
no seed was recorded, so the generator cannot reproduce those bytes from a seed.
The frozen public artifacts provide byte-exact replay instead. They do not
contain spending keys or a real-value user transaction.

The coordinated run used instrument commit
`7039352500a7c025818b812d437b5303b5702db6` on 2026-09-06. The full wave's recorded
interval was 09:50:14–09:52:07 UTC; crypto ran as one process during that sequence,
not in parallel with the other measurement tools. Exact invocation:

```
RAYON_NUM_THREADS=48 build/uno/crypto/test-uno-crypto-cost --measure \
  build/uno-wave4-run-703935250/funding.bin \
  build/uno-wave4-run-703935250/spend.bin
```

Hardware: 192 logical CPUs, Intel Xeon Platinum 8455C, two sockets × 48 cores ×
two threads; dynamic frequency, not a pinned-frequency/isolated-core experiment.
Build: CMake Release `-O3 -DNDEBUG`, clang 21.1.8; Rust release 1.97.1
(`8bab26f4f`, 2026-07-14), no sanitizer. Wave-start load averages were
0.49/1.54/2.82, wave-end 4.70/3.37/3.38; this was a shared machine, not a claim
of zero external interference. Raw `crypto.jsonl` has 141 records in
`build/uno-wave4-run-703935250`, archived with the complete wave's raw evidence.
Fixture hashes match the frozen inputs above. All recorded expected ABI statuses
matched; there was no unexpected crypto test failure.

### Fresh and warm single calls

Times include semantic meter plus complete ABI call. Percentiles use nearest
rank (`ceil(p × n)`); with n=20, p95 is the nineteenth sorted observation.

| Workload | n | p50 ms | p95 ms | Max ms |
|---|---:|---:|---:|---:|
| Fresh process: key construction + funding verification | 1 | 1568.759319 | — | 1568.759319 |
| Warm funding | 20 | 8.296103 | 8.397586 | 8.403065 |
| Warm spend | 20 | 4.955083 | 5.171371 | 5.528226 |

The difference between contexts is not a fitted context weight: funding runs
first, CPU/cache/frequency conditions evolve, and only these two fixed proofs
were sampled. The first call is not isolated VK construction time.

### Actual serial batch loops

Each row has three samples. Times are measured total milliseconds, not single
call time multiplied by count. “Late failure” changes only the last request's
digest; all preceding requests must succeed and all intended calls are executed.

| Context | Outcome | Proof calls | Min ms | Median ms | Max ms |
|---|---|---:|---:|---:|---:|
| Funding | Valid | 1 | 8.268460 | 8.418850 | 8.442577 |
| Funding | Late failure | 1 | 6.946155 | 7.057550 | 7.182228 |
| Funding | Valid | 16 | 116.362767 | 123.211482 | 128.921663 |
| Funding | Late failure | 16 | 111.966631 | 113.357759 | 121.952241 |
| Funding | Valid | 64 | 362.899412 | 400.271118 | 410.129571 |
| Funding | Late failure | 64 | 358.837290 | 463.793383 | 511.565257 |
| Funding | Valid | 256 | 1391.971653 | 1420.091237 | 1763.833202 |
| Funding | Late failure | 256 | 1386.537242 | 1585.274696 | 1596.894457 |
| Funding | Valid | 700 | 3615.297305 | 3695.338383 | 3904.664632 |
| Funding | Late failure | 700 | 3619.633763 | 3629.942356 | 3644.821492 |
| Spend | Valid | 1 | 4.984579 | 5.074187 | 5.124782 |
| Spend | Late failure | 1 | 4.268144 | 4.290388 | 4.310606 |
| Spend | Valid | 16 | 78.876527 | 79.790155 | 80.429020 |
| Spend | Late failure | 16 | 77.014650 | 77.784965 | 84.942046 |
| Spend | Valid | 64 | 302.885641 | 320.249378 | 322.997392 |
| Spend | Late failure | 64 | 301.254916 | 305.918442 | 318.686393 |
| Spend | Valid | 256 | 1284.158622 | 1296.673051 | 1306.319309 |
| Spend | Late failure | 256 | 1294.503434 | 1325.623343 | 1559.700066 |
| Spend | Valid | 700 | 3362.443492 | 3716.038412 | 4328.444722 |
| Spend | Late failure | 700 | 3323.200871 | 3782.139213 | 3836.436350 |

Logical resource counts (the same in each context/outcome):

| Proof calls | Public Actions | ABI payload bytes |
|---:|---:|---:|
| 1 | 2 | 9,032 |
| 16 | 32 | 144,512 |
| 64 | 128 | 578,048 |
| 256 | 512 | 2,312,192 |
| 700 | 1,400 | 6,322,400 |

### Cheap rejection and memory

The meter's largest measured accepted-list duration was **3,308 ns**, for a
700-request list. The twenty earliest-shape-reject observations per context had
median 19 ns; funding p95/max 20/52 ns, spend p95/max 22/67 ns, with zero ABI calls.
These tiny measurements approach timer/compiler/loop overhead and do not establish
production wire parsing cost or a calibrated per-byte weight. They cover rejection
at the first entry, not maximum-length malicious parsing.

Every recorded process high-water mark was **10,752 KiB (10.5 MiB)**. This is the
lifetime RSS of this small-fixture sequential process, not a measured independent
peak for each stage, not parallel-worker memory, and not a production bound.

### Deadline comparison: diagnostic margin, not an admission limit

The current Simplex validator entry calls `validate_block_candidate` with
`td::Timestamp::in(60.0)` in `validator/consensus/block-validator.cpp:104`–`:105`.
That is a real current entry deadline, not the 400 ms target cadence. Its alarm
cannot interrupt a synchronous proof loop; it does not make arbitrary input safe.

The largest observed loop here was **4.328444722 s** (700 valid spend-fixture
verifications). An **illustrative, unapproved 2× margin** gives **8.656889444 s**,
14.43% of 60 s, leaving a numerical difference of 51.343110556 s. This is a
sensitivity comparison only: 2× is not measured WCET, the remaining difference
is not guaranteed available to other stages, and cold key construction was
measured separately at 1.568759319 s. Neither cache state nor future scheduling
is guaranteed by this run.

The result does **not** show that 700 proofs fit a valid block or its deadline:
this sequence already exceeds 4 MiB of payload, reuses spent identifiers, lacks
all host/state/commit paths, and has no maximum-Action or worst malformed-input
distribution. No three structural input values, universal semantic weights,
production schema or safe slot duration can be selected from these data alone.
