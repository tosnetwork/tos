# Mac Release build blockers (OPEN)

An independent clean Apple Silicon Release build of exact tree
`463f44bea31e04da48abf5fa8b01c2b04426c8d3` configured successfully but
failed at build step 1318/1676. The original logs, checksums and platform
details are archived in `memo/pq-native/N6-MACBOOK-PARALLEL-TEST-01-RESULT-20260924.md`
and its `-DATA/` directory at memo commit `fde096ce`. These are three
source-level **pre-merge repair items**, not a Mac consensus-test verdict:

| ID | Build defect | Required closure |
| --- | --- | --- |
| A | `test/pq-native/n6-microbench.cpp:492-509` unconditionally uses Linux `cpu_set_t`/`sched_getaffinity` while CMake registers the target on Mac. | Portable implementation or explicit platform scope; clean Mac Release target build. |
| B | `crypto/vm/db/DynamicBagOfCellsDbV2.cpp:20-26` uses Apple `weak_import` for `mallctl`; with default `TOS_USE_JEMALLOC=OFF`, Apple ld cannot resolve it and `tos_db` consumers fail to link. | Link correctly or exclude the call without jemalloc; clean Mac Release consumer links. |
| C | `crypto/pq/consensus-key-tool.cpp:15` includes `openssl/crypto.h` directly, but its target receives OpenSSL only through the signer's PRIVATE link. Mac has no system header; Linux may compile against system headers while linking vendored OpenSSL. | Give `tos-pq-consensus-key` the matching explicit OpenSSL include/link dependency; compile and link on Mac and check Linux header/library provenance. |

The branch's current CI runs these paths on Linux only. The Mac CTest list has
54 registered tests, eight disabled, but **zero were run** in that full-build
attempt. A separately commissioned run of 45 already-built tests is
diagnostic partial evidence only: even if green, it cannot close A/B/C or
establish full Mac Release acceptance. Fixes and a clean fixed-tree Mac build
are required before treating this platform as merge-ready. This note does not
modify the independent Mac test tree or claim its later results.
