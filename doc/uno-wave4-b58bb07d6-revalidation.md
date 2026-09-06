# Component measurement rerun after instrument review

Source: `b58bb07d6`. UTC run: 2026-09-06 11:54:59–11:56:46. The existing
`scripts/measure-uno-audit-wave4.sh` serial matrix exited 0 after all stages.
The only dirty source path was unrelated prediction-market work, recorded in
the archive; UNO instrument sources were committed. The build invocation for all
four targets succeeded; this does not mean all four were recompiled. The storage
target was recompiled and relinked for this run. The crypto executable was linked
after the last `abi-cost.cpp` change; the input-admission and partition-state
executables were carried over from the 703935250 run, with their measurement
sources and `uno/core` unchanged between those revisions. No production schema
was selected.

Environment: same 192-logical-CPU host, Release clang++-21, `-O3 -DNDEBUG`,
offline pinned Rust build, `RAYON_NUM_THREADS=48` for real ABI calls. CPU and
kernel metadata are archived. One-minute load was 3.19 at start and 8.81 at end;
other workloads were not isolated. No CPU/NUMA affinity or OS-cache eviction was
used. Fresh-process/new-database experiments are not cold-device measurements.

Raw data: `measurements/uno-wave4-b58bb07d6.tar.gz`. It includes the full run
directory (source/build identity, seeds, public fixture hashes, raw records),
build log, and real output-failure experiment. Original methodology and limits
remain in `uno-wave4-crypto-measurement.md`, `uno-wave4-input-measurement.md`,
`uno-wave4-storage-measurement.md`, and `uno-partition-measurement-method.md`.

## Completeness and selected observations

Record counts checked: 141 crypto/shape JSON rows; 80 structural JSON rows;
1200 anchor rows; 60 partition CSVs containing 1620 phase rows; nine storage
CSV rows (three at each size). No partial run was combined with this run.

| Real ABI workload | Samples | Median total ms | Maximum total ms |
|---|---:|---:|---:|
| Funding warm single | 20 | 8.369972 | 9.665172 |
| Spend warm single | 20 | 4.998346 | 5.412460 |
| Funding 700 valid calls | 3 | 3726.494538 | 3821.683623 |
| Funding 700, last expected failure | 3 | 3686.478360 | 3698.032525 |
| Spend 700 valid calls | 3 | 3443.283811 | 3730.748125 |
| Spend 700, last expected failure | 3 | 3744.344111 | 3866.091348 |

First VK construction plus verification: 1.799706118 seconds, one observation.
Crypto-process high-water RSS: 10752 KiB. The two fixed two-Action public
fixtures are unchanged; repeated nullifiers are not a legal transaction batch.
700 calls contain 6,322,400 ABI payload bytes, already above 4 MiB without wire
overhead. These data cannot separate per-Action and per-proof cost weights.

| Structural Cells | Samples | Median detached admission ms | Maximum ms | HWM KiB |
|---|---:|---:|---:|---:|
| 1023 | 20 | 1.225910 | 1.386330 | 3072 |
| 8191 | 20 | 11.709050 | 12.374700 | 6144 |
| 32767 | 20 | 34.025150 | 58.840000 | 15360 |
| 65535 | 20 | 73.762350 | 124.293000 | 29184 |

At 65,536 historical keys, two-key insert, three samples, median microseconds:

| Phase | Single dictionary | 16 page roots |
|---|---:|---:|
| Full load | 17550.5 | 19019.5 |
| Incremental absence | 4.643 | 4.324 |
| Update two | 16.844 | 16.735 |
| Serialize changed pages | 27310.5 | 2761.14 |
| Serialize all pages | 29271.6 | 26104.7 |

Page roots are an in-memory vector, not Native participant accounts. The large
single dictionary is not a consensus-admissible executor. These are storage
primitive comparisons, not multi-account atomicity or production capacity proof.
The table selects uniform-key insertion. At the same size, changed-page
serialization medians reverse in the archived `prefix` scenario (single
30080.5 vs pages16 41539.6 microseconds) and `split` scenario (1.956 vs 19431.4).
The advantage is scenario-dependent, not a general property of partitioning.

Storage import-request maximum / process HWM maximum across three samples:
1000 keys: 40.6751 ms / 29184 KiB; 8000: 171.298 ms / 41324 KiB;
32000: 634.729 ms / 87120 KiB. The real host wrapper capacity check and CellDb
actor are exercised, but the state is synthetic rather than a full UNO pool;
there is no new authenticated network or committee evidence here.

## Failure control and remaining gates

The rebuilt real `--measure` executable, using the same public fixtures and
48 threads, wrote to `/dev/full`. It printed `measurement output write failed`
and exited 2. This confirms the real invocation rejects an output failure, not
just an injected stream in self-test. It is not a disk/database outage test.
The archived log records the diagnostic and exit code, but not the command line;
the fixture paths, thread setting and sink are operator-recorded context rather
than independently reconstructable from that log.

The maximum observed ABI loop in this run was 3.866091348 seconds; the earlier
703935250 run recorded 4.328444722 seconds. No safety multiplier or
production limit is inferred: this is not the full parse/inbox/state/proof/
execution/serialization/commit envelope, and it is not a WCET bound against the
non-preemptive validation deadline. Clock-floor calibration, diverse real proof
shapes, production participant schema, migration capacity and the joint claim-only
feasibility evidence remain open. D-3, Y-1 and activation gates remain deferred.

## Review disposition

Claude Code independently recomputed the archived counts and table values.
Accepted corrections distinguish incremental build success from recompilation,
state the scenario dependence of the partition table, scope the maximum to this
run, and name the partition methodology document. No new regression test or
mutation experiment is claimed by this report. The review transcript is working
material at `~/memo/reviews/uno-wave4-b58bb07d6-revalidation-review.txt`.
