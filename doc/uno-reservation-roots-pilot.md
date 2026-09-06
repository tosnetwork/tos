# Reservation and terminal-owner root measurement

The refund scenario in `measure-uno-partition-state` now measures all three
existing NullifierState roots, not only the used dictionary. This is a test
instrument extension, not the Native Reserve, Deposit/Withdrawal terminal
machine, a new account schema or a production encoding. External review is
pending at the milestone under AGENTS.md.

## Scope

The experiment starts with historical used keys, reserves two fresh keys under
one owner across their assigned in-memory pages, restores the pending state,
refunds it, and restores the refunded state. Each page's used, reserved and
owner/manifest roots are encoded as three separate BoCs, with an empty buffer
for an absent root. Framing and reachable Cells may be repeated across BoCs:
the sum is not a deduplicated full account size or physical persistent bytes.
It includes owner manifests and refunded tombstones. Paid-state restoration is
covered by the self-test, not by the performance matrix.

The four new phases are `serialize_pending_roots`,
`decode_validate_pending_roots`, `serialize_refunded_roots`, and
`decode_validate_refunded_roots`. Decode includes full `from_roots` consistency
validation, not just Cell construction. Pending phase rows report the original
used count; refunded phase rows report that count plus two. The stderr
`reservation_bytes` rows separately report used, reserved, owner and total
bytes, with checked summation. All three restored root hashes are compared,
and subsequent refund processing uses the restored pending state.

The original used-set-only serialization and Native envelope metrics remain
separate controls; those envelopes still do not contain reservation roots.
State is resident; no OS-cache eviction, persistent commit, authenticated
checkpoint, note-tree capacity reservation, receipt, amount or fee is measured.
There is only one owner per affected page, not a long history of terminal owners.

## Checks that can fail

The existing registered `test-uno-partition-measurement-self` now checks pending
keys cannot be consumed, refund consumes both keys permanently, Paid releases
the keys, and both terminal outcomes permanently prevent reusing the owner ID
with a different fresh key. Missing dependencies do not skip these checks.

A mutation omitting the owner root only when reservations are empty preserves
pending restoration and produces a structurally decodable refunded state. The
new owner-reuse assertion then fails; CTest exits 8. This tests behavior beyond
structural validation or error wording. Restoring the root restores success.

The executable now flushes and checks both output streams before successful
exit, in both self-test and measurement modes. With stdout directed to
`/dev/full`, the restored executable exits 1 and reports output failure.
Removing the stream-state check returns 0; the subprocess witness logs the
command and return code and fails its expected-exit assertion. A separate
measurement run with stderr directed to `/dev/full` also exits 1. Final normal
CTest passes. Mutation patches and nonempty witness logs are archived; these
are manual evidence, not automatic mutation CI. Existing exception boundaries
cover VM errors, virtualized state, VM budget, CellCreateError, CellWriteError
and standard exceptions; no new consensus error classification was introduced.

## Recorded run

Source base `8eee1613f` plus `refund-roots-restored-source.patch` in
`doc/measurements/uno-reservation-roots-pilot.tar.gz`. Build target:
`measure-uno-partition-state`, Release clang++-21, `-O3 -DNDEBUG`, same Xeon
Platinum 8455C host. Environment observations and build/test logs are archived.

```sh
for mode in single pages16; do
  for history in 0 1024 8192 32768 65536; do
    build/measure-uno-partition-state "$mode" refund "$history" 3 45 || exit 1
  done
done
```

Capture stdout CSV and stderr metrics separately. Ten serial invocations
passed: 480 phase rows, including 120 new all-root rows, plus 60 reservation
byte rows. Seed 45; three repetitions of each scenario share the same state,
not independent transaction histories. This is not a tail-percentile dataset.

For 65,536 used historical keys:

| Mode / cut | Used bytes | Reserved bytes | Owner bytes | Total bytes | Median encode ms | Median decode/full-validate ms |
| --- | --- | --- | --- | --- | --- | --- |
| single / pending | 2793805 | 152 | 93 | 2794050 | 29.3832 | 41.3412 |
| single / refunded | 2793889 | 0 | 93 | 2793982 | 24.5311 | 36.3953 |
| pages16 / pending | 2662897 | 158 | 104 | 2663159 | 24.6129 | 36.4172 |
| pages16 / refunded | 2662977 | 0 | 104 | 2663081 | 19.3706 | 42.7596 |

All three repetitions have identical byte breakdowns. Process high-water RSS
at these phases reached 99632 / 99608 KiB (single/pages16), including fixture,
prior samples, metrics and simultaneous BoC arenas, not isolated phase memory.
The large single dictionary remains above the known Native data-cell bound.

These numbers repair the missing-root measurement scope; they do not quantify
long-term owner accumulation or full settlement storage. They cannot select a
production schema, admission limit, cost coefficient or WCET margin. Y-1/D-3
and the authenticated obligation/claim-only feasibility gates remain open.
