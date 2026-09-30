# C09 parent-capacity correction (isolated candidate)

The earlier 4096-parent progression test used a test-only 32 MiB `EvidenceStore`.
It did not establish a production failure: the production Q store is 8 MiB and
charges each derived row its serialized bytes plus 2048 bytes. The count-driven
eviction added in `85936f516` was reverted in `bd7f6db42`; no capacity was
raised. The original parent count/8 MiB checks and fixed-W refusal remain.

Focused production-profile measurements from the actual `project_process`
fixture (locked Rust test `production_process_parent_bound_is_below_query_resident_charge`):

| Accepted fixture | Serialized M parent | Charged Q projection |
| --- | ---: | ---: |
| Ordinary process | 1411 B | 3224 B |
| 128-byte epoch, 64 missing fields × 96 bytes | 8094 B | 9544 B |

These are tested profiles, not a proof for every possible accepted source row.
The parent byte cap remains a separately enforced bound. If a valid original M
row is demonstrably larger than the charged Q row and fills that bound first,
that case needs a focused byte-cap test and fix, not a count-only eviction.

At this source revision, the persisted cursor tamper control passes, and the
`pre_cursor_ledger_with_active_grant_catches_up_over_4096_history` control
requires `paused_for_grant == true`; it then verifies the old fixed-W grant
remains usable and cursor does not advance on the capacity pause. The full
`manager_query_source` suite passed 19 tests with two opt-in witnesses ignored.
This is isolated test evidence, not deployment or 72-hour acceptance.

The cursor's anchor is a **global M row**, not a process-row assertion. A
nonzero diagnostic-only prefix is accepted with its diagnostic boundary row
anchored. The test then inserts an actual process row and tampers the persisted
cursor to skip it with paired NULL anchor columns; startup refuses. Removing
the nonzero-watermark/global-anchor validation compiled but made that exact
negative test fail at its startup-refusal assertion (exit 101); restoring it
returned exit 0. This chose the global-row-anchor proof, rather than claiming
that every nonzero M prefix contains a process observation.

A further restored-ledger control forges `W=2` while retaining the valid
diagnostic row-1 hash as an older anchor. The cursor validator now requires
`anchor.seq == W`; the M reader also checks that hash against M's indexed
`store_seq=W` row. Replacing the equality check with the old `anchor.seq <= W`
behavior compiled, but failed the new startup-refusal assertion (exit 101).
The restored focused test and full relevant suite passed (19 passed, two
opt-in tests ignored). No claim is made that a nonzero W requires a *process*
anchor: the actual global W row may be diagnostic.
