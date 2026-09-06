# Public multi-shape measurement fixtures

`export_measurement_shapes` is a manually invoked measurement producer in
`uno/crypto/src/lib.rs`, not a default CI test or a production wire assignment.
Run from `uno/crypto` with a fresh existing output directory:

```sh
env UNO_SHAPE_FIXTURE_DIR=/absolute/fresh/directory CARGO_NET_OFFLINE=true \
  CARGO_TARGET_DIR=/home/tomi/tos/build/uno/crypto/cargo-target \
  RAYON_NUM_THREADS=48 cargo test --locked --offline --release -j48 \
  --lib export_measurement_shapes -- --ignored --nocapture
```

Explicit invocation without the directory variable fails rather than skipping.
Existing output files are never overwritten. The ignored marker keeps expensive
manual fixture production out of ordinary tests; it is not an activation gate.

The producer makes output-only bundles with 2, 4 and 8 Actions and constant
principal 5000 nanotomi. Output amounts use checked division and multiplication;
the resulting bundle balance must be exactly -5000. Seeds are respectively
32 repetitions of byte 2, 4 and 8 using the pinned `StdRng`. Keys and notes are
public test material, unsuitable for holding funds. Proof construction timing
excludes key construction, building/encryption, signatures, ABI checks and I/O.
One timing observation per shape is not a latency distribution.

Each bundle must pass the real ABI and fail with verification status 3 when its
authorization digest changes. The proof byte lengths are 7264, 11808 and 20896,
checked against the actual bundles. This does not establish valid ShieldClaim
authorization: no terminal Deposit, Reserve or chain context is supplied here.

## Measurement file only

`UNOABIT1` is eight ASCII bytes followed by Action count and proof byte count
as two unsigned 64-bit little-endian values. Remaining fields are the existing
T0 fixture layout: flags (one byte), signed balance (eight LE bytes), anchor
(32), binding signature (64), proof, then each Action's cv/nf/rk/cmx/epk
(32 each), encrypted ciphertext (580), outgoing ciphertext (80), spend signature
(64). This is not TL-B, ConfigParam 84, or a change to the exported ABI.
The previous `UNOABIT0` and its two-Action readers remain unchanged.

## Evidence and remaining work

`measurements/uno-d3-shape-generation.tar.gz` contains the producer source diff,
generation and restored logs, public binary fixtures, and a digest-binding
mutation patch/log. Replacing the real ABI's requested digest with the fixed
fixture digest makes the negative control receive status 0 instead of 3 and
fail before file creation. This is a behavioral status assertion, not an error
text assertion. The temporary ABI change is restored, not delivered.

No new error classification or consensus path is introduced. Test assertions
and output failures terminate this manual command; they do not classify blocks.
No new C++ exception boundary is present. Per the milestone review policy,
external review is pending the milestone, not claimed for this producer.

The C++ measurement reader does not yet consume T1. Diverse spend shapes,
independent seeded samples, full lifecycle workloads and stage/RSS measurements
remain outstanding. These fixtures alone do not determine verification weights,
input limits, a production partition schema, or a WCET envelope. D-3/B3-1 and
the capacity/claim-only feasibility gates remain open.
