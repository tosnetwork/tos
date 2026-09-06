# One-bit adaptive directory baseline

This is a test-only bulk layout baseline, not a production partition schema.
It closes no Y-1 or D-3 acceptance gate. Milestone review remains pending.

## Question and observation

Can variable-depth routing keep used-set leaves below a Cell control when keys
share a long prefix? In this model, yes, but the directory grows too. At 65536
keys and a 1024-Cell leaf control, uniform input needs 383 directory nodes;
input with a 128-bit common prefix needs 631, including 128 empty leaves.
The measured maximum leaf is 1023 Cells in both cases. A separate concentrated
1024-key run with only 128 directory nodes fails explicitly instead of growing
without a bound.

This distinguishes adaptive routing from the previous fixed-prefix baseline,
but does not demonstrate bounded deployed growth. The directory is a C++ vector,
not encoded Native accounts or coordinator data. Node counts are not encoded
Cell counts, bytes, or reference depth. Both occupied and empty key ranges have
canonical owners; no candidate-supplied page identifier is trusted by lookup.

## Experiment and evidence

Measured source: `4f52007d1` plus `adaptive-final-source.patch` in
`measurements/uno-adaptive-directory-pilot.tar.gz`. The final committed source
adds an explicit narrowing conversion after checked depth increment; the
preceding `depth < 256` guard proves the conversion safe. The matrix predates
that diagnostic-only change; the handoff build and CTests exercise it.

Release clang++-21, `-O3 -DNDEBUG`, Xeon Platinum 8455C. No CPU isolation or
cache eviction was established. The matrix uses seed 45, entries
1024/8192/65536, common-prefix bits 0/128, leaf Cells 1024/4096, directory nodes
4095, and three separate invocations per combination: 36 rows. Run:

```sh
build/measure-uno-adaptive-partition 65536 128 1024 4095 45
```

`ADAPTIVE_CSV` fields are entries, prefix bits, leaf Cell limit, directory node
limit, seed, nodes, leaves, empty leaves, maximum directory depth, maximum leaf
Cells, build milliseconds, and process high-water RSS KiB. The timer covers
bulk directory construction, including the initial whole used dictionary;
it excludes key generation and independent final validation. RSS is sampled
after validation and includes all fixture and transient allocations.

The registered `test-uno-adaptive-partition-self` is built by `all-tests`.
Two keys differing only at the last bit require exactly 513 nodes with a
one-Cell leaf control; 512 nodes fail. Tests also check empty-range ownership,
wrong-page rejection, duplicate rejection, checked-add overflow, complete key
preservation and independently recomputed leaf closures.

Four removed checks independently made CTest fail (exit 8): directory budget,
claimed-page equality, cached Cell-size correctness, and checked addition.
Restored adaptive and existing partition self-tests pass. Assertions test
structure, membership, arithmetic and outcomes, not error text alone. Patches,
build logs, negative logs, restored logs and raw measurements are archived.
These are manual historical mutations, not an automated mutation facility.

## What this does not measure

- Construction starts with the full used dictionary, potentially exceeding an
  admitted account's limit. This is not incremental splitting from legal pages.
- Payload is used-set only: no terminal owners, pending manifests, frontier,
  anchors, Note archive, accounting, Reserve or settlement reservations.
- No persisted directory, authenticated read/write evidence, participant
  records, coordinator encoding, host replay or database commit is exercised.
- Validation scans all leaves and original keys. No bounded authenticated hot
  access or cold import performance follows from this run.
- Neither the timing nor the process RSS is a whole-block bound or WCET.

The next decision experiment must start from bounded pages and replay continuous
growth with pending obligations, concentrated splits and terminal settlement.
It must budget directory, coordinator, evidence and staging separately and
retain old spent/owner evidence. Repeating this bulk matrix at more sizes is
not a substitute. Production thresholds, addresses and TL-B remain undecided.
