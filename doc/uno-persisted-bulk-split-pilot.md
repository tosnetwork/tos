# Persisted bulk repartition pilot

This is a storage-only comparison, not a production split schema, migration
protocol, participant record or claim-only feasibility proof. It extends
`uno-incremental-partition-pilot.md` and `uno-incremental-state-stages.md`.
External review remains pending at the milestone under AGENTS.md.

## Operation and independent checks

The same seed-91 fixture first persists and reopens one or sixteen synthetic
Native accounts. It inserts two fresh keys through the existing test path.
Then it unpacks every source account, validates each used dictionary and
enumerates its actual contents. It does not regenerate destination state from
the fixture seed. The single-account control rebuilds one dictionary; the
sixteen-page variant repartitions into 32 pages by the first five key bits.
Both preserve all historical spent markers, plus the two new keys.

Enumerated and rebuilt counts use checked additions and must equal the checked
sum of history and fresh-key counts. Source routing and canonical empty marker
values are checked. After committing, retaining both roots, reopening,
releasing the old root and reopening again, verification independently queries
every original fixture key at its expected destination. Both new keys must
reject a second insertion. The original key oracle is distinct from the
enumerated migration vectors. Whole-state BoC restoration still checks the
committed root hash. No production host, config or error classification changes.

The updated test accepts `TOS_UNO_STORAGE_SHAPE=split` or `split-prefix`.
The latter zeros the first 128 key bits: even the 32-page destination keeps
the entire history in page zero. This intentionally does not pretend that a
fixed extra routing bit solves concentrated growth.

The two new CTest smoke cases run both shapes at 1000 keys and 16 source pages;
the pre-existing `all-tests` dependency builds their binary. Missing controls
fail and the zero-test regex prevents an empty filter from passing.

## Measurement definitions

Use the existing serial matrix command with shapes `split split-prefix`, counts
`1000 8000 32000 65536`, pages `1 16`, and samples `1 2 3`. CSV page counts identify
the source layout. `INCREMENTAL_FOOTPRINT_CSV` adds, after history/seed/source
pages/shape: destination pages, baseline Cell record count/bytes, retained
two-root count/bytes, and final count/bytes after releasing the old root.

Footprints sum merged Cell key/value record sizes with the previously tested
checked counter. They are not SST allocation, WAL bytes, device traffic or the
transient memory peak of a write operation. The two-root observation is one
retention cut, not proof of the maximum footprint of a production migration.
Old and new state share one content-addressed database. Moving to another
database or instance could require copies not represented by these numbers.

The resolve/update timer now includes the two inserts, source validation,
enumeration, full rebuild and new account/shard packing. Other timers retain
their earlier definitions. Serialization follows full reads and commits;
OS caches are not evicted. Process HWM includes fixture generations, lazy Cells,
enumeration vectors, record maps and BoC arenas. It is not isolated node RSS.

## Recorded matrix

Source: `1912bfcae` plus the final patch in
`doc/measurements/uno-persisted-bulk-split-pilot.tar.gz`. All 48 serial processes
passed at approximately 13:36 UTC on 2026-09-06, with 48 stage, 48 footprint and
96 retain/release rows. All three samples in each scenario have identical
footprint counts and bytes. Release clang++-21, `-O3 -DNDEBUG`, Xeon Platinum
8455C, 192 logical CPUs, v2 extra_threads=0. Host isolation and cold physical
storage were not established; environment observations are archived.

At 65,536 historical keys, plus two inserts before rebuilding:

| Source → destination | Shape | Median resolve/update ms | Median serialize / decode ms | Maximum process HWM KiB |
| --- | --- | --- | --- | --- |
| 1 → 1 | uniform | 627.698 | 42.6641 / 24.9665 | 209336 |
| 16 → 32 | uniform | 525.826 | 45.7628 / 26.9072 | 211024 |
| 1 → 1 | concentrated | 901.231 | 42.9973 / 26.7885 | 196656 |
| 16 → 32 | concentrated | 605.350 | 42.0333 / 26.5041 | 194076 |

| Source → destination | Shape | Baseline records / bytes | Two-root records / bytes | Final records / bytes |
| --- | --- | --- | --- | --- |
| 1 → 1 | uniform | 131077 / 11707218 | 131116 / 11711377 | 131081 / 11707574 |
| 16 → 32 | uniform | 131107 / 11710804 | 131260 / 11728041 | 131143 / 11714984 |
| 1 → 1 | concentrated | 131077 / 10642739 | 131103 / 10645445 | 131081 / 10643036 |
| 16 → 32 | concentrated | 131123 / 10647982 | 131201 / 10656680 | 131175 / 10653831 |

The uniform 16→32 rebuild adds 153 records / 17237 bytes at the retention cut;
the concentrated case adds 78 / 8698. Shared immutable Cells explain why the
same-database retained footprint does not double. This does not bound an
independent successor's starting state, acquisition buffer or cutover peak.
The single-account controls and concentrated large pages exceed the Native
data-cell limit: these are deliberately non-admitted storage fixtures, not
successful production-capacity tests.

The observed maximum resolve/update time was 1042.76 ms; serialization and
decode maxima were 51.0649 and 31.2737 ms. Separate prepare/stage/write-batch
maxima were 1.42793 / 0.062093 / 4.52459 ms. These separate observations are not
one end-to-end sample or WCET and do not establish validation-deadline margin.

## Failure evidence and open requirements

Dropping the first enumerated key preserves the enumerated count but fails the
independent rebuilt count (1001 versus 1002) in both smoke cases. Routing every
key to page zero preserves counts but fails historical membership after
reopening in the uniform case. Both CTest commands exit 8; exact patches and
diagnostic logs are archived. Restored split, split-prefix, incremental and
partition-import smoke cases all pass. These are manual mutation runs, not
automatic mutation CI. The earlier output-stream failure guard is retained.

Y-1/D-3 remain open. There are no bounded coordinator records, participant
transaction chains, authenticated migration authorization, I13a-I13e host
atomicity, settlement obligations, full candidate/commitment/inbox/proof work,
or approved split/Reserve schema here. Claim-only feasibility and production
limit recommendations still require those missing measurements and decisions.
