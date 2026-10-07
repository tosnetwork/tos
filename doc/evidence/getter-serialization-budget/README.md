# Getter result serialization budget — measurement

Evidence for `doc/elector-participant-list-read.md` §2 and Appendix A.

- Revision: `main` at `6da705c8a`. `crypto/vm` and `validator/impl/liteserver.cpp` are
  unchanged between the build the probe was linked against and this revision.
- What it measures: the operations the lite server's result-stack serialization
  (`vm::FakeVmStateLimits fstate(1000)`, `validator/impl/liteserver.cpp:1556`) spends
  on the exact result shapes of `participant_list_extended` and `list_proposals`,
  and the largest list that fits the budget. It runs the production sequence
  `Stack::serialize` → `finalize_to` → `std_boc_serialize`.

## Build and run

From the repository root, with a configured release build in `build/`:

```sh
LIBS=$(find build/crypto build/tdactor build/tddb build/tdutils build/third-party \
            build/common build/keys build/tl build/tl-utils -name '*.a' | grep -v -E 'test|fuzz')
for B in 1000 1000000000; do
  clang++-21 -std=c++20 -O1 -DBUDGET=$B \
    -Icrypto -Itdutils -Ibuild/tdutils -Itdactor -Itddb -Icommon -I. -Ithird-party/abseil-cpp \
    doc/evidence/getter-serialization-budget/probe.cpp -o /tmp/probe_$B \
    -Wl,--start-group $LIBS -Wl,--end-group -ldl -lpthread -lz
  /tmp/probe_$B | grep -v '^ n='
done
```

## Result

| Budget | Participants that fit | Proposals that fit (no voters) |
| ---: | ---: | ---: |
| 1,000 (production) | 76 (77 → 1,009 ops) | 49 (50 → 1,002 ops) |
| 10^9 | 300 (probe cap) | 300 (probe cap) |

Operation counts (both budgets): participants 13N + 8; proposals 20P + 3V + 2
(V = voter entries); one proposal with 21 voters costs 85; at most 12 proposals with
21 voters each fit in 1,000. `std_boc_serialize` adds no operations. A tuple costs 2
operations, a scalar or null 1, the stack root 1.

- `probe.cpp` SHA-256 prefix `bdf80af674b2b9ca`; captured output SHA-256 prefix
  `082a9c72670f0ec3` (not committed; regenerate with the commands above).
