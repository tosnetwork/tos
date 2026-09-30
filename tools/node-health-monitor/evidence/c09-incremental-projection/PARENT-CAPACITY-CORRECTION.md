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
