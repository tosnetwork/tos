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
  dropped and counted, and either drop sets `complete=false` for the entire
  timing population. Counter saturation/failed finite CAS also sets
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
`C09_NATIVE_RAW_OK retained=2 full=1 identity=3 time=1 complete=0 resident_bytes=57480`.
The test exercises a real same-process span, wrong PID, wrong nonce, wrong
domain, future point, inherited point after `fork`, capacity loss and counters.
It also checks a no-loss population remains complete; exactly
`INT64_MAX` nanoseconds converts, while one nanosecond more and the next
whole second are rejected without signed overflow.
An isolated temporary header copy replaced only the domain guard with `false`:
the mutant compiled with exit 0 and the unchanged test exited 6 at its
wrong-domain assertion. The original header was not edited by the mutation.

The feedback corrections were verified with two further isolated compiled
mutants against the final test: replacing the shared full/contention drop
helper's `complete=false` with `true` exited 13; removing the equality-case
nanosecond remainder check compiled and exited 15. Both original paths
compiled and exited 0. `raw_now` now delegates its conversion to the tested
checked function, so the boundary assertion exercises production conversion.

| Artifact | SHA-256 |
|---|---|
| `validator/measurement/c09-raw-monotonic.h` | `23a05e2c83d9f8a43b0f3adbb7130d7d59fca591fba758342e00f6182d4b18af` |
| `test/pq-native/c09-raw-monotonic-test.cpp` | `281c80ca527efa89ebc03972af1e0c7fb710a787e078c237331164c1d914d500` |
| compiled temporary test binary | `97de751b0e8151f638358e6307838c67016c5e046aa52f09fe70e17a5eec2661` |

No broad rebuild, live node test, restart, deploy or model API call occurred.
The next step that needs actual native call-site coverage would edit consensus
or storage source and replace live binaries; this task stops before that step.
