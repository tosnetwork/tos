# C09 parent-capacity correction (isolated candidate)

Base: reviewed query-only source `f43fb8ef638da62814c599df56960b9bda43fed3`.
This successor adds a test and this note only; it changes neither the running
query service nor business nodes.

The earlier 4096-parent progression test used a test-only 32 MiB
`EvidenceStore`. It did not establish a production failure: the production Q
store is 8 MiB and charges each derived row its serialized bytes plus 2048
bytes. The count-driven eviction added in `85936f516` was reverted in
`bd7f6db42`; no capacity was raised. The original parent count/8 MiB checks
and fixed-W refusal remain.

Focused production-profile measurements from the actual `project_process`
fixture (`production_process_parent_bound_is_below_query_resident_charge`):

| Accepted fixture | Serialized M parent | Charged Q projection |
| --- | ---: | ---: |
| Ordinary process | 1411 B | 3224 B |
| 128-byte epoch, 64 missing fields × 96 bytes | 8094 B | 9544 B |

These tested profiles do not prove every accepted source row. The parent byte
cap is separately enforced. If a valid original M row is larger than its
charged Q row and fills that bound first, it needs a focused byte-cap test and
fix, not count-only eviction. This is isolated development evidence, not
deployment, runtime availability, or 72-hour acceptance.

Restored locked `manager_query_source` target on this isolated base: 20 passed,
1 opt-in read-only cost witness ignored, exit 0. Removing only the test's
2048-byte production charge compiled and exited 101 at the intended
`parent_bytes < query_charge` assertion (`1411` versus `1176`), not at setup or
compilation. The charge was restored; test source SHA-256 is
`dac10d275aa51a65294d923c38d3a58c6d23f20dad4692a55bfe1b0e364214bf`.

The test and this note were selected into the current shared source without
the withdrawn count-driven eviction code. The combined locked
`manager_query_source` target passed 22 tests with one opt-in witness ignored;
the two fixture measurements remain examples, not a universal proof that the
production 8 MiB parent byte bound can never bind first.

The cursor's anchor is a **global M row**, not a process-row assertion. A
nonzero diagnostic-only prefix is accepted with its diagnostic boundary row
anchored. The tightened test then inserts an actual process row and tampers
the persisted cursor to skip it with paired NULL anchor columns; startup must
refuse. This is a test-only control, not a production cursor change or a
capacity progression claim. The isolated `3c4885703` removal mutant compiled
and failed at that startup-refusal assertion (exit 101); source-bound checks
for the shared successor: test source SHA-256
`dcea5c826fd2e261d63b081535ebd5d69917034659232e8a422e456aa30d81b0`,
unchanged `query_ledger.rs` SHA-256
`2152491e042fa50920f9b5d821e3884b8e0d338b301aabce6f2ad310d497b288`,
and fresh isolated-target test binary SHA-256
`8cd9e2e4db781137b4238ce92c4d25da45f6f3f157e3db433dbe778e7f0e7c46`.
The locked `manager_query_source` target on the shared successor exited 0:
22 passed, 1 opt-in local-M witness ignored, including the pre-existing
mixed-boundary rewrite test. The shared test binary was freshly compiled under
`/home/tomi/nhm-c09-shared-global-boundary-build`; a prior reused-target run
that executed tests absent from its source was discarded as invalid evidence.

The shared production validator already required `anchor.seq == watermark`
at `23429522d5`, so no production line from isolated `514d70c29` was copied.
The additional restored-ledger control forges `W=2` while retaining the valid
diagnostic row-1 hash as an older anchor. Startup must refuse this syntactically
valid but stale anchor, without requiring a process anchor for a genuinely
diagnostic-only boundary. This remains a cursor test, not an 8 MiB parent-cap
progression or 72-hour acceptance claim. The control first checks the durable
cursor decoder directly, then checks manager startup, so an independent M
reader guard cannot mask the cursor-validator sensitivity.

On this shared successor, `manager_query_source.rs` SHA-256 is
`197da5c50ad783264e6d27e728c3fe15030102ffe2e2409b8b753930b13f5048`,
unchanged `query_ledger.rs` SHA-256 is
`2152491e042fa50920f9b5d821e3884b8e0d338b301aabce6f2ad310d497b288`,
and the restored test binary SHA-256 is
`dcceeae8b8657698508eec92d632f0e5d6427b7d8107d9b6479fb3c1e2003233`.
In a detached worktree of this exact successor, changing only the ledger
validator from `anchor.seq != watermark` to the old `anchor.seq > watermark`
produced source SHA-256
`7657c9f3ae9321edea6470b78a8bf02add1f979b682b5b4e226453c1f683392b`.
It compiled and the exact target exited 101 at the intended direct decoder
assertion (`manager_query_source.rs:255`, `unwrap_err()` received `Ok`). After
restoration, the same target exited 0 and the ledger hash matched above. The
full locked `tos-health-services` package, fmt, strict Clippy and diff-check
also exited 0 on the final shared source; the `manager_query_source` file had
22 passed and 1 opt-in local-M witness ignored. No live service was changed.
