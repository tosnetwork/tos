# R4 continuation validation

Design fetched from memo/main: R4 blob
`b6ee93b81ad3794eecff3b6c8ed2faf28072120c`; work-order blob
`f7cd3371c8023bb61409d5e77fd96a3741f0cddd`.
TOS starting HEAD: `86db5fe9e93fe0a04c324dc0aa58dcfe88ce4b9f`.
The consensus/persistence anchors remain unchanged relative to the design's
`1620db717cb4ec4c0521fb9742338962eec1a5bd` baseline; the earlier branch adds
metrics/PQ hooks and exporter/QUIC collection protection.

## Commands and evidence

```sh
python3 tools/node-health-monitor/scripts/check-contracts.py
cargo fmt --manifest-path tools/node-health-monitor/Cargo.toml --all -- --check
cargo clippy --manifest-path tools/node-health-monitor/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path tools/node-health-monitor/Cargo.toml --locked --workspace
cargo build --manifest-path tools/node-health-monitor/Cargo.toml --locked
python3 tools/node-health-monitor/tests/process-smoke.py
python3 tools/node-health-monitor/tests/mutations.py
python3 tools/node-health-monitor/tests/native-mutations.py
python3 tools/node-health-monitor/tests/r4-mutations.py
```

67 Rust tests pass: 30 existing core, 16 R4 core, 10 HTTP, 6 SQLite and 5 native
cache tests. Contract validation covers 20 closed schemas, six tool request/error
response fixtures, unknown nested fields, exact u64 and UTCZ. It also compiles
and executes the standalone C++ codec; its bytes match Python and the Rust test.
The process smoke starts actual edge/query executables, imports a process sample,
queries with the authorized grant and confirms that revocation returns 401.

Mutations: 10 existing Rust + 6 existing C++ + 15 new Rust + 1 new C++.
An initial epoch-change mutation survived because the test used a smaller new
generation, which independently triggered the stale-generation check. The test
now uses a larger generation in the new epoch and fails when epoch reset is
removed. The repaired mutation is included in the final passing mutation run.

The new tests exercise production Rust library functions, actual SQLite files,
a real loopback HTTP source and real router requests. The vote stage model is
explicitly only a contract fixture; it is not a native consensus integration test.

## Limits and not-run gates

- No full validator build was needed for this round's standalone codec-only C++
  addition. The codec was compiled and run, including its mutation. Earlier native
  hooks were not extended by this round.
- The R4 output schemas are contract artifacts; existing handlers have not yet
  migrated to all those data shapes. Schema validation does not prove runtime
  DTO parity or all source adapters.
- SQLite tests establish the local component contracts, not wiring into the HTTP
  service, a complete inventory/rule engine, long-reader behavior or all disk faults.
- Native storms establish zero additional local requests for cached GETs, not
  production mTLS authorization, host isolation, all RPC sources or AI/MCP storms.
- No actual Prometheus/Alertmanager version tests, AURA/MCP sessions, model egress,
  witness proof validation, approved hardware performance measurements or 72h soak.
- No production deployment, restart, protocol change, durability change or real
  notification was performed. Production readiness remains blocked explicitly.
