# Self-pay simulation context component (WIP)

Implementation: `c02537b8370dcb69cebdcb92ee30062a9d62a42c`, based on `d3470f0a83ca124ef4bf93726e9688d2c9fa5861`.

This is the first component of the pending native simulation implementation. It derives an estimated time and distinct block/transaction logical times from observations that the future basechain entry point must authenticate. It does not authenticate those observations, execute a message, estimate fees or expose a new C ABI. The complete feature must consume this component from the proof-bound simulation path before publication; this helper alone is not a deliverable simulation feature.

## Author self-check

- Callers: the declaration and definition are used by the new native unit test. Production integration is still pending in this same WIP branch. Existing proof/transaction C entry points and their callers are unchanged.
- Rules: version16 minimum; nonzero uint32 time; account start<=end<=shard end; absent accounts have zero transaction history; estimated time includes shard, masterchain and local clocks. Strict upward alignment uses `Config::get_lt_align()`. The quotient bound reserves one transaction LT before increment/multiplication, avoiding wrap before adding1. The future entry point must additionally enforce basechain/native-version support, same-target proofs and input ownership.
- Evidence: actual implementation and test compiled with `-DNDEBUG`;20 named checks passed. Ten separately compiled variants each remove one bound or rule and fail the designated named assertion: shard/masterchain time and LT, strict alignment, transaction+1, account consistency, LT overflow, clock range and version. The source file remains unchanged; the original binary passes20 again. The test uses explicit failure counting rather than NDEBUG-sensitive assert.
- Build boundary: direct compilation used the current C++ sources plus the existing f2d generated include paths/tdutils archive. The first two manual compile attempts lacked dependency include flags; after using the recorded compilation database's include/define flags, compilation and execution pass. This is not a complete fresh native/CMake build. The new target is registered as `self-pay-simulation-context`; actual CMake target build and CI invocation remain part of complete feature acceptance.
- Upstream: arithmetic constraints are checked against the current block validator/collator and emulator alignment behavior; the narrow self-pay calculation API is local. No consensus rule changes.
- Resources/order: scalar observations/results, fixed-size arithmetic and bounded literal error messages; temporary Result errors are destroyed by the caller. No cache, queue, timer, process, persistent handle or I/O is added. Inputs are checked before arithmetic; errors carry fixed codes and no wallet data.
- Areas: UP, AP, TE, BC, DC, RH. No network traffic, phone custody, fee policy, live transaction or device performance acceptance is claimed. The CMake registration does not by itself claim a hosted CI pass.

Raw commands, build/test logs, ten modified-source copies and binaries are retained under `${HOME}/validation/mobile-quantum-handoff`, prefix `r02-simulation-context-`; the memo index records sizes/hashes. Keep them through independent acceptance and complete wallet delivery. The shared generated headers/archive remain attributed to their original build.

Next in this WIP branch: complete configuration graph/Account proof binding, explicit execution inputs, the exact signed-message adapter and its resource/result ownership limits, then source-built target/platform validation and the full transaction/negative-control matrix. Do not merge or describe this component as working fee estimation before those steps.

## CI registration follow-up

The existing `python-and-pq-chain` workflow now builds `test-self-pay-simulation-context` and selects its CTest name with `--no-tests=error`. The workflow runs on every PR without path filters. Local YAML parsing and command-selection inspection pass; hosted execution and a fresh full CMake build have not run for this WIP branch. This registration does not change the twenty-check/ten-mutation local evidence or the pending production integration.
