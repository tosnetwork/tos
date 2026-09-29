# Node health monitor implementation

**Status: partial implementation, not production accepted.** The normative
specification is [R4, 2026-09-29](https://github.com/tosnetwork/memo/blob/main/node-health-monitor/TOS-NODE-HEALTH-MONITOR-DESIGN-20260929.md),
blob `b6ee93b81ad3794eecff3b6c8ed2faf28072120c`. This branch starts from
`tos/main@b2c500dc6f26eb1530dac9679385b6f330b3d008`.

## R4 continuation

See [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md) for C00–C09 status and
[VALIDATION-R4.md](VALIDATION-R4.md) for this round's concrete evidence.
No complete work order or production capability is marked accepted.

Added strict schemas and contract checks, cross-language diagnostic framing,
monotonic cache freshness, multisource incident recovery, isolated SQLite
control/evidence components and optional fixed native collection in health-edge.
The storage components are not yet connected to the existing HTTP query process.

```sh
python3 tools/node-health-monitor/scripts/check-contracts.py
bash tools/node-health-monitor/scripts/run-contract-tests.sh
python3 tools/node-health-monitor/tests/r4-mutations.py
```

Optional local native sampling: append `127.0.0.1:PORT` to the existing
`health-edge NODE PID LOOPBACK_LISTEN TOKEN_FILE` command. Consumers use the
edge's authenticated `/metrics` cache. This development interface does not
supply the required production mTLS ingress or revoke old direct scrape owners.

## Implemented boundaries

- Native exporter: one actual collection at a time, 15-second start interval,
  no HTTP waiters, 30-second cache maximum age, 2-second publication budget,
  bounded publication, explicit cold/stale 503, cached generation/source time.
- Async collector aggregation: batches of eight, single flight, and completion
  only after every child in a started batch finishes, including error paths.
  Registries reject incomplete collection after capacity is exceeded.
- QUIC native metrics use a summary-only path that avoids constructing per-connection
  and per-path maps. The separate diagnostic stats API retains its old detail.
- Opt-in `validator-engine --health-core-metrics`: fixed process-wide production
  consensus PQ sign/verify counters and fixed-bucket durations. Disabled sources
  are absent. These are not per-session/per-scope duty accounting.
- Fixed diagnostic ring primitive, with single-attempt admission, no waiting,
  visible drops and no file fallback. It is **not wired to TraceCollector/IPC**.
- Rust deterministic contracts: source freshness and actual-work ownership,
  duty cohort accounting primitive, guard hysteresis, independent observer
  identity comparison, dead-man replay protection, incident missing-evidence
  state, bounded broker queue/cancellation, evidence identity/watermark,
  scoped run grants, six cache-query handlers, and diagnosis output validation.
- Executables: `health-edge`, `health-collector`, `tos-observability`,
  `health-watchdog`, and `health-contract-check`.
- Rust input contracts, behavior/HTTP tests, compiled mutation tests and CI.

## Run tests

Use the repository-pinned Rust toolchain (1.97.1):

```sh
scripts/install-rust-toolchain.sh
cargo fmt --manifest-path tools/node-health-monitor/Cargo.toml --all -- --check
cargo clippy --manifest-path tools/node-health-monitor/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path tools/node-health-monitor/Cargo.toml --locked
python3 tools/node-health-monitor/tests/mutations.py
python3 tools/node-health-monitor/tests/native-mutations.py
```

The mutation runners first require the named baseline test to pass, edit one
production guard, compile it, require its named behavioral assertion to fail,
and restore the original file in `finally`. Run them without other builds
using the same checkout. A compilation failure is not a killed mutation.

Native actor/signature integration tests use the repository build:

```sh
cmake --build build --target test-health-collector-completion test-health-pq-signer test-metrics-label-bound -j2
build/test-health-collector-completion
build/test-health-pq-signer
build/test-metrics-label-bound
```

## Executables and current limits

Build with `cargo build --release --manifest-path tools/node-health-monitor/Cargo.toml`.
Each executable prints its exact positional usage on invalid arguments.

| Executable | Current behavior | Boundary still missing |
|---|---|---|
| `health-edge` | Fixed Linux process fields, epoch/PID-reuse check, scheduled cache, authenticated/rate-limited loopback HTTP | Core/admin/getStats adapters, host/cgroup collection and effective resource validation |
| `health-collector` | Sequential mTLS HTTPS cache poll and bounded ingest, skips missed ticks, deduplicates source identity | Complete inventory scheduler, HA fencing, durable evidence/metrics quality pipeline |
| `tos-observability` | Typed cache-only HTTP queries, separate operator/ingest/service credentials, 200s scoped grants and immediate revocation | MCP SDK transport, persistent ledger/store, opaque pagination, all aggregation modes, ancestor traversal |
| `health-watchdog` | Fixed HTTPS heartbeat and independent bounded receiver attempts | Witness chain adapters, rule-chain dead-man source, confirmed delivery receipts |
| `health-contract-check` | Fail-closed arithmetic and declared acceptance checks | Actual host/network/cgroup/notification verification |

There is **no production enablement claim**. Defaults fail the declaration
checker. It does not manufacture hardware evidence from booleans. The monitor
cache is currently memory-only (bounded accounting); optional JSONL import is
for already-collected fixtures. It does not meet the retention requirements.
Grant control routes are for a protected monitoring-host control plane and
must not be exposed through a remote query ingress.

Metric summary and ancestor queries return `CAPABILITY_UNSUPPORTED`. Nonempty
cursors return `CURSOR_MISMATCH`; overflowing an unpaginated result returns an
explicit limit error. No cache miss contacts a node. There is no `/mcp`, model
provider or AURA session implementation yet. AI must remain disabled.

## Remaining release gates

See [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md). In particular, complete
H1b/H2 evidence, source-contiguous-work budgets, real cancellation/fault tests,
mTLS/ACL deployment, production resource profiles, A/B/C/D/E performance
measurements and the 72-hour soak have not passed. Do not install this branch
on production validators as an accepted monitor.
