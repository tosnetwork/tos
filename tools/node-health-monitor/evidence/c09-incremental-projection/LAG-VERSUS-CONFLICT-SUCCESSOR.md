# C09 fixed-W continuity under bounded projection lag

**Superseded for error classification by `SAFE-LAG-CLASSIFICATION-SUCCESSOR.md`.**
The trigger-based SQLite faults below use `RAISE(FAIL)`, a constraint failure;
they do not demonstrate a transient busy/full storage condition. The compiled
all-revoke mutants below therefore do not justify treating unknown errors as
recoverable. The bounded active-W capacity result remains a valid control.

Starting HEAD: `85ceebb4f9f3c61d7e2dd7824cf1e266cc2aeb7a`. This is an isolated candidate; no live QueryService, Manager, Edge, collector, business node or model process was changed.

The old importer treated every Q insertion or cursor-commit error as a Manager source conflict and revoked every active run. That was incorrect for a fixed-W evidence eviction boundary, the bounded M parent index, and transient Q SQLite failures. The successor separates explicit projection/source identity violations (still latch conflict and revoke) from capacity or Q-write/cursor-commit availability errors. On the latter it leaves the durable M cursor unchanged, sets `manager_caught_up=false`, refuses new grants, and preserves already-fixed runs. If a page was durably inserted before the cursor commit failed, the old cursor causes an idempotent replay; it does not make later evidence visible under an old run's W. Startup tolerates this lag state but not a latched source conflict.

The actual control-router test creates an active grant at W=1, adds two M rows, and separately injects a mid-page Q insert failure and a cursor-commit failure. Under each fault it requires: old run query HTTP 200; new grant HTTP 503; no source-conflict latch; cursor remains at M seq 1. After removing the trigger, the same process catches up to seq 3, a new grant succeeds, and a restart retains the original fixed run. The 4097-row migration control is tightened to **require**, rather than conditionally skip, an actual active-W eviction pause; it checks the old query remains 200, the cursor cannot advance on repeated new-grant attempts, then explicit revoke permits catch-up. Source mismatch/quarantine refusal tests remain in the affected suite.

Restored source SHA-256 (paths under `tools/node-health-monitor/crates/health-services/`): `src/observability.rs` `a0450772c7bfd07e430251d9d778d3f2e94f4e5238dd5d1bc768955dfe00496f`; `src/query_ledger.rs` `386fb2ef55ec0e6484ef407452f6dab9a3ea11980da21229e5dd3d75aca7f0e2`; `tests/manager_query_source.rs` `67d525e9340a34c280ab440a53645720c9ad56a107ed30a4e2e0fe057a4847d9`.

| Raw log under `/home/tomi/nhm-c08-mcp-evidence/` | SHA-256 | Natural result |
| --- | --- | --- |
| `c09-lag-preserve-baseline.log` | `ee778ac31834cc90c55e7e47226ded37df59c4bd15c63f05fdfc7067c7f057d7` | Real-router fault baseline exit 0 |
| `c09-lag-insert-revoke-mutant.log` | `848585c5f43818aafd1c4626804538815764786e20f82a5518e1fd3520cd8b71` | Compiled mutation restoring all-insert-error revocation, exit 101 at intended `!manager_conflicted` assertion in insert mode |
| `c09-lag-cursor-revoke-mutant.log` | `83f327c31919e9d52fce6562edc681ae07ff7e4af09156198c8beed7ed86d754` | Compiled mutation restoring all-cursor-error revocation, exit 101 at intended assertion in cursor mode |
| `c09-lag-preserve-restored-suite.log` | `01cc407c01588bd82cfda691e4fbb77d58bd5acd48ddab2d50424dbb6099e2b8` | Restored locked fmt, Clippy with warnings denied, full workspace suite exit 0; affected projection suite 17 passed/1 opt-in ignored |

The mutant builds emitted dead-code warnings because the respective classifier was bypassed, but **compiled and executed** the real assertion; neither red is a compiler failure. Raw mutant logs are historical and the source was restored before the final suite. The candidate still has no concurrent live broker latency, rollback-drill or 72-hour production acceptance. The running local query binary remains the supervisor's `14bb30d0` source, without this successor.
