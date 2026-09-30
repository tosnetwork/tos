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
