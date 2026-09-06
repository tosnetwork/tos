# Native account envelope pilot

Source base `79f21a2ff` plus the run's archived source patch. Release Clang 21 on
the same 192-logical-CPU host. Serial run 2026-09-06 12:45:06–12:45:23 UTC,
one-minute load 2.30 to 1.99; no affinity or cache eviction. Seed 45, three samples
per invocation. Both modes ran insert/prefix at history 0, 8192, 32768 and 65536,
plus split at 65536: 18 invocations, 594 CSV phase rows and 54 envelope metric rows.
All commands exited successfully. Structural values matched across repetitions.

Storage-only account envelopes are defined in `uno-partition-measurement-method.md`.
They are not participant records or full UNO accounts. Selected history-65536
results (insert/prefix append two keys; split retains the original count):

| Mode / scenario | Accounts | Max data Cells | Max data bits | Max data depth | Data fits 65536 | Dictionary Cells | BoC bytes |
|---|---:|---:|---:|---:|---|---:|---:|
| single / insert | 1 | 131075 | 16486619 | 21 | no | 131078 | 2793998 |
| pages16 / insert | 16 | 8475 | 1065912 | 17 | yes | 131108 | 2795544 |
| single / prefix | 1 | 131075 | 8031739 | 21 | no | 131078 | 1729457 |
| pages16 / prefix | 16 | 131075 | 8031739 | 21 | no | 131124 | 1731124 |
| single / split | 1 | 131071 | 16486121 | 21 | no | 131074 | 2793914 |
| pages16 / split | 32 | 4275 | 537743 | 16 | yes | 131136 | 2797108 |

The 16-page prefix case concentrates all historical keys in one account; its
dictionary depth is 28 versus 24 in the other selected cases. The envelope does
not solve skew or total historical growth. A successful dictionary/BoC operation
does not override a failed per-data-closure bound. Conversely, the positive
uniform/split controls exclude all missing production overhead and reservations.

Median milliseconds over three samples, including full data scans in envelope
construction (not a throughput or tail estimate):

| Mode / scenario | Envelope construction | Whole dictionary BoC |
|---|---:|---:|
| single / insert | 18.3831 | 28.4040 |
| pages16 / insert | 13.8785 | 35.1170 |
| single / prefix | 22.4967 | 29.8032 |
| pages16 / prefix | 21.5017 | 28.9854 |
| single / split | 22.7540 | 35.3744 |
| pages16 / split | 12.9410 | 32.2360 |

Raw evidence is `measurements/uno-native-envelope-pilot.tar.gz`: all CSV/metrics,
source/build/environment metadata, mutation patches and logs. Disabling the
data-cell limit made the exact/over test fail; storing empty data instead of the
page made Native Account unpack-and-hash verification fail (both exit 1).
Restoration passed the one registered CTest. The archived `all-tests` dependency
query includes this instrument. Manual mutation evidence is not automated CI;
the self-test itself is now in the regular test graph. Milestone review pending.

No production schema, addressing, participant TL-B or admission limit is selected.
Pending work includes bounded coordinator/candidate/effects and reservations,
physical records, actual account storage metadata, independently reconstructed
state updates, new persistent bytes, atomic CellDb commit, authenticated cold
sync/GC/migration and the complete lifecycle timing envelope. This pilot supplies
one additional storage layer to the comparison, not the five-part design's
capacity acceptance or the claim-only composability proof.
