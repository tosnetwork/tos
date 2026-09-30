# C09 native raw monotonic hook candidate

Scope: isolated `nhm/c09-raw-monotonic` branch. This is a compiled native
primitive and test, not a deployed validator hook or a C09 performance pass.
The earlier external RTT capture and soak audit files are unchanged.

## Source-backed design

- R4 §16.1 requires common raw monotonic start/end points, population,
  resolution, loss and instrument cost before a 3% p99 decision. Existing
  `validator/measurement/measurement-contract.cpp::sample_clocks` emits
  independent JSONL trace points through a synchronously flushed sink. Its
  points lack a process token and cannot safely be paired across processes.
- New `validator/measurement/c09-raw-monotonic.h` is a Linux-only, opt-in
  fixed-capacity primitive. Each start/finish point carries PID, random
  process nonce, fixed `CLOCK_MONOTONIC_RAW` domain and a finite stage enum.
  `finish` samples the end clock before validation or try-lock. It rejects a
  different PID/nonce/domain, future/backward point, span over one hour or
  unknown stage/outcome. Forked children cannot reuse inherited points.
- Capacity is at most 1,024 records per `Capture`; `sizeof(Capture<1024>)`
  compiled to 57,480 bytes. No dynamic record allocation, file/network write
  or blocking lock occurs on `start`/`finish`; full/contended records are
  dropped and counted. Counter saturation/failed finite CAS sets
  `complete=false`. A caller-provided span receives a snapshot outside the
  hot path. Construction obtains a nonce once; failure disables capture.
- The primitive is intentionally **not wired** into `simplex/pool.cpp`,
  `block-producer.cpp`, storage or QueryService. It has no production stage
  population, operation-key deduplication, binary/config profile binding,
  clock calibration or instrument-overhead measurement. Those fields remain
  `not_run`/unsupported. Real hook placement and exact stage semantics need
  source review before a native build/restart. No existing business binary
  uses this file.

Lighthouse owns Rust QueryService projection/ledger work in the shared branch.
This candidate adds only the new C++ header, standalone test and receipt; it
does not alter those files or C07/C08 code. A later integration must review
the exact call sites and preserve the business journal order.

## Exact validation

Compiler: `c++ (Ubuntu 15.2.0-15ubuntu1~22~ppa2) 15.2.0`.

```sh
c++ -std=c++20 -O2 -Wall -Wextra -Werror -pedantic -pthread -I. \
  test/pq-native/c09-raw-monotonic-test.cpp \
  -o /tmp/c09-raw-monotonic-starbridge-test
/tmp/c09-raw-monotonic-starbridge-test
```

Natural exit 0:
`C09_NATIVE_RAW_OK retained=2 full=1 identity=3 time=1 resident_bytes=57480`.
The test exercises a real same-process span, wrong PID, wrong nonce, wrong
domain, future point, inherited point after `fork`, capacity loss and counters.
An isolated temporary header copy replaced only the domain guard with `false`:
the mutant compiled with exit 0 and the unchanged test exited 6 at its
wrong-domain assertion. The original header was not edited by the mutation.

| Artifact | SHA-256 |
|---|---|
| `validator/measurement/c09-raw-monotonic.h` | `a214ad18ed59e74b8f7ddf80044f22ca17f51b8062025ea8c699245f068af8a6` |
| `test/pq-native/c09-raw-monotonic-test.cpp` | `da04fbccb1b769d568c11b072388c588d813f301133a19decd635015e1dbaefe` |
| compiled temporary test binary | `a63c7da5e3f622ae360fbb0e3392ad215eb32bf321eaa77c5654cc40ce7818aa` |

No broad rebuild, live node test, restart, deploy or model API call occurred.
The next step that needs actual native call-site coverage would edit consensus
or storage source and replace live binaries; this task stops before that step.
