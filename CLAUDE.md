# CLAUDE.md

## Test Concurrency

This repository can run very CPU-heavy Rust tests, especially under
`uno/plonky3-ffi` and `tosctl/uno`.

**Default command (measured fastest)**:

```bash
cargo test --release -j 64
```

Use `-j 64` as the normal Cargo job count. This is approximately one
third of the available logical CPUs on the current host. Each test
binary spawns its own Rayon pool inside, and letting the default
test-threads policy (one per CPU) run them in parallel lets the
machine saturate without oversubscription hurting per-test latency.

**Measured 2026-04-22 on this host, uno/plonky3-ffi lib (390 tests)**:

| Config | Wall time |
|---|---:|
| `cargo test --release -j 64` (default parallel test-threads) | **~290 s (5 min)** |
| `RAYON_NUM_THREADS=128 cargo test --release -j 128 -- --test-threads=1` | 4 271 s (71 min) — 15× slower |

So `--test-threads=1` serializes the 390-test suite and every heavy
STARK prove/verify stacks on top of the next — throughput collapses.
Do NOT cap `--test-threads=1` for the full lib suite.

**Single-test isolation** (when debugging one specific heavy test —
NOT the full suite):

```bash
RAYON_NUM_THREADS=64 cargo test --release -j 64 SPECIFIC_TEST -- --test-threads=1
```

Only use this recipe when the one test actually needs the whole
Rayon pool to itself (e.g. profiling a prove path, chasing a data
race). Never for a green/red full-suite check.

**Summary-only view** (when only the final test-result lines matter):

```bash
cargo test --release -j 64 2>&1 | grep -E "^test result" | tail -5
```

If a test fails under the summary-only form, rerun without `grep` so
the full failure output is visible.
