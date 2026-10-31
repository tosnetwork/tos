# Decision-log allocator accounting check

Baseline: `0939b8a19d32b6694f14e4e3018659055c7ec28b`.

The scale executable links jemalloc in the native CI configuration. Reading
glibc's `mallinfo2()` there measured zero for a live 64 MiB allocation and failed
the existing positive control. The `retained` mode used the same incorrect
counter.

## Repair and scope

The test target selects its counter together with its allocator link. Jemalloc
builds refresh `epoch` for every sample and read process-wide `stats.allocated`;
glibc builds retain `mallinfo2().uordblks + hblkhd`. A failed statistics operation
or an unexpected result size fails the test. These are allocated-heap figures,
not resident memory or reserved pages; actor-thread caches can make jemalloc's
figures approximate. Peak RSS is reported separately.

The existing strict-build job builds with `TOS_USE_JEMALLOC=ON`. Its exact test
inventory now requires and runs all four `decision-log-scale-*` modes. A missing
registration fails the inventory check. The large/small allocation controls,
resource limits, and timing thresholds are unchanged. Production consensus code
and state lifetimes are unchanged.

## Local checks

Native Linux x86-64, GCC 13, jemalloc 5.3.0: a focused build linked the actual
scale test, signing ledger, actor and utility sources against system OpenSSL and
zlib. It used generated utility configuration, with no source replacements or
filesystem adapters. This is not a full repository CMake build.

| Check | Result |
| --- | --- |
| Baseline scale executable with jemalloc | Exit 1 at the 64 MiB allocation control |
| Repaired executable, glibc | All four modes passed |
| Repaired executable, jemalloc | All four modes passed |
| Jemalloc memory mode with `MALLOC_CONF=tcache:false` | Passed |
| Statistics refresh/read failures and incorrect result size, in a focused helper harness | Each failed at its intended diagnostic |
| Suppressed epoch refresh | Failed at the unchanged 64 MiB control |
| Original strict-build inventory | Selected none of the four scale modes |
| Updated inventory; remove each scale registration in turn | Selects all four; each missing registration is rejected |

The final jemalloc full-size restart loaded in 1.57 s and reconciled in 1.54 s.
The retained-session case measured 317,530,272 allocated bytes for 1,024 sessions
of 2,032 records. One exploratory scaling run exceeded the unchanged ratio limit
(9.09 versus 8); the final run was 6.44, and three sequential checks were 5.59,
6.05 and 6.28. This timing sensitivity is recorded rather than counted as an
unbroken pass. The configured Linux CI gate remains the integration check.

## Supported build commands

```sh
cmake -S . -B build -DTOS_USE_JEMALLOC=ON
cmake --build build --target test-decision-log-scale
ctest --test-dir build --output-on-failure --no-tests=error -R '^decision-log-scale-'
```

The strict-build workflow's inventory-checked selection is reproduced by:

```sh
regex="$(python3 scripts/check-ctest-inventory.py --build-dir build --expected-file scripts/strict-build-targeted-tests.txt --print-regex)"
ctest --test-dir build --output-on-failure --no-tests=error -R "$regex"
```

Checklist: TE-4, TE-6, BC-5, RB-13. The non-author source review and focused
fault controls found no remaining blocking finding in this repair.
