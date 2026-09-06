# Existing note-component envelope measurement

This pilot measures the existing NoteTreeState, NullifierState, AnchorWindow,
NoteState and PrivateTransferState components together. It does **not** measure
a full UNO engine, Native account, participant transaction, Reserve or output
archive. No production state schema or admission limit changed. External
review remains pending at the milestone.

## Construction and checks

Historical nullifiers use seed 45, matching the dictionary pilots. The `owners`
profile creates one refunded single-key owner per historical key; `spent`
does not. Commitments are distinct small canonical field encodings consumed by
the actual pinned tree ABI, not a mock. They are not outputs of verified
proof-bearing transactions. The frontier is built to the same position as the
used count. A synthetic anchor history repeats that root to fill a window of
3 or 100; this is not a replayed or authenticated blockchain history.

The current event reserves two keys/leaves. Its refund consumes those keys,
appends two commitments, advances the anchor height and assembles a new
NoteState. Both pending and refunded states are wrapped in the existing
PrivateTransferState codec with zero accounting fields. This does not authorize
notes or establish backing, supply or the global accounting equation.

Each encoded component is serialized to BoC, decoded into a new arena and
restored through the actual component APIs. The test compares the full wrapper
hash, tree position, reserved-leaf count, mature anchor count, every old spent
key and terminal owner, and the two fresh keys' used/reserved status. The pending
source hash must remain unchanged. Native CellStorageStat counts the entire
PrivateTransferState closure, including its frontier/anchor/nullifier wrappers.

The tree component stores a bounded frontier, **not all historical notes or
ciphertexts**. Missing archive/availability storage cannot be inferred away from
its small size. Neither the Native Account envelope nor the future host's
coordinator, effects and read/write evidence is in these Cell counts.

## Instrument and negative evidence

The executable `measure-uno-note-component` is built under the existing
`TOS_UNO_CRYPTO_PROTOTYPE_TESTS` gate, uses the pinned offline Rust build, and is
a dependency of `all-tests`. A registered smoke runs 8 historical owners with
window 3. Missing environment controls fail (exit 1), not skip; a zero-test
filter is a CTest failure. Output to `/dev/full` also fails (exit 1).

Replacing the refunded tree with the unchanged prestate makes CTest exit 8:
the used count has advanced but the tree position has not. Removing checked-add
overflow detection independently makes CTest exit 8 at the max-plus-one test;
failure must leave its output unchanged. Both are state/value assertions, not
error-string-only evidence. The restored smoke and original `test-uno-tree-cell`
suite pass. Exact mutation patches and diagnostic logs are archived; mutations
are manual, not CI automation. No new production exception category is added.

## Reproduction and boundaries

Source base `9ff62cfd1` plus `note-component-final-source.patch` in
`doc/measurements/uno-note-component-envelope-pilot.tar.gz`. Configure with
`-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=ON`, build `measure-uno-note-component -j48`, then:

```sh
for count in 0 1024 13080 13106; do
  for window in 3 100; do
    for profile in spent owners; do
      for sample in 1 2 3; do
        env TOS_UNO_NOTE_KEYS="$count" TOS_UNO_NOTE_WINDOW="$window" \
          TOS_UNO_NOTE_HISTORY="$profile" build/uno/crypto/measure-uno-note-component \
          --filter ExistingComponentEnvelope || exit 1
      done
    done
  done
done
```

All 48 serial invocations passed, producing 96 component rows. Each cut's three
structural measurements agree. Release clang++-21, `-O3 -DNDEBUG`, Xeon Platinum
8455C; environment observations and full logs are archived. CPU/host isolation
and cold OS caches were not established.

Fields after `NOTE_COMPONENT_CSV`: history, seed, window, profile, cut, component
Cells, payload bits, depth, BoC bytes, diagnostic `cells <= 65536`, refund
transition ms, component encoding ms, BoC serialization ms, BoC decode plus
component restoration ms, process HWM KiB. The refund transition is timed once
and repeated on both cut rows: **do not sum it twice**. It includes refund,
tree append, anchor advancement and assembly, not historical construction,
proof checking, fees, persistence or inbox work. Cell scans and post-restore
membership assertions are outside these timers. HWM includes original and
restored state, fixture sets and Rust state, not phase-local memory.

## Structural results with historical owners

| History | Window | Pending Cells | Refunded Cells | Depth at both cuts | Pending / refunded BoC bytes | Cell control |
| --- | --- | --- | --- | --- | --- | --- |
| 13080 | 3 | 65422 | 65422 | 22 | 1569486 / 1569384 | both fit |
| 13080 | 100 | 65519 | 65519 | 102 | 1572978 / 1572876 | both fit |
| 13106 | 3 | 65551 | 65553 | 22 | 1638110 / 1638085 | both exceed |
| 13106 | 100 | 65648 | 65650 | 102 | 1641699 / 1641674 | both exceed |

The earlier raw-three-root pending cut at 13106 had exactly 65536 Cells. The
existing wrappers already take it over, before any Native account/engine
additions. A positive component control at 13080 is not a deployable limit:
the missing components and future operations still need headroom.

At 13106, median refund transitions were 6.58488 / 6.58619 ms for windows 3/100;
median pending BoC-plus-component restores were 48.9498 / 49.4963 ms. These are
three-sample component observations, not tail percentiles or WCET. Frontier
shape changes can alter the number of Cells across a refund independently of
the dictionary delta. No coefficient, production capacity, slot length or
deadline safety margin follows from this partial pipeline.

Y-1/D-3 remain open: complete coordinator/participant layout, authenticated
obligations, archive availability, Reserve fee isolation, persistent atomicity,
controlled cold/warm acquisition and migration feasibility are still missing.
