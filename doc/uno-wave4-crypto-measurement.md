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

## Planned recorded workload

The measurement command (run only in the coordinated quiet interval) is:

```
RAYON_NUM_THREADS=48 build/uno/crypto/test-uno-crypto-cost --measure output-only.bin spend.bin
```

It emits raw JSONL with monotonic nanosecond measurements:

- One fresh-process key construction + full verification call (not isolated VK
  construction alone).
- Twenty warm single calls for each of the public funding/spending fixtures.
- Batch sizes 1/16/64/256/700, three samples per size and fixture, valid and with
  the last request's digest changed. The latter passes proof verification and
  fails a spend signature, per the inspected verifier ordering; it is not an
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

Pending coordinated run after committing the instrument. The recorded result
must add the instrument commit, exact command/build/compiler/hardware, fixture
hashes and origin/seed limitations, raw sample file, failures and deadline margin.
Until those rows are present this document is an instrument description, not a
measurement result.
