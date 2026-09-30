# Validator health judgement: what is live on the local development network (2026-09-30)

Goal restated by the owner: **the monitor (AURA) must reliably judge validator
health**. This note records what was implemented for that goal, what runs on
this host now, the fault exercise that shows the judgement moving, and what
still needs an owner decision. Nothing here is production acceptance.

## The path, end to end

```
validator-engine (native-core-v3 typed snapshot: consensus actions/phases/
failures, sessions, slot progress, PQ sign/verify, chain anchors)
  -> health-edge (fixed 15 s sampler, mTLS cache)
  -> health-collector (archives the snapshot into M, exact parent hash)
  -> health-native-poll (derives the fixed rule facts, posts a FactFrame)
  -> health-state / M (rule engine: 8 rules per validator, 6 per observer)
  -> tos-observability / Q (six tools: process, consensus, chain, storage
     components + read-only verdict copy, fixed watermark, grants)
  -> judge-validator-health.py (deterministic verdict per node from M rule
     incidents + archived native evidence; optional model explanation that
     can never upgrade a verdict)
```

## Changes landed on `node-health-monitor` today

| Commit | What |
| --- | --- |
| `217a3ce59` | Workspace test build compiled again (missing `NativeV3` match arm). |
| `7a7c41839` | `health-core::native_facts`: deterministic derivation of chain progress age, local action failures, oldest pending action, PQ failures, storage ack failures/usability and session stop pending from a v2/v3 native record; `health-native-poll` posts them; manager admits the five extra native rule adapters; v3 snapshots may be complete with an anchor; rule manifest marks six adapters implemented. Tests on real validator1/observer5 loopback samples drive the rule engine through stall, signing failure, unusable journal and incomplete cases. |
| `00a487511`, `bbd3d2cfa` | v3 native snapshot unit test with a published chain anchor; the anchored body was **unparseable JSON** (missing quote after `applied_advanced_unix_seconds`) — fixed and covered with `td::json_decode`. |
| `7fec4fc14`, `5ace1f181`, `599f72199` | `scripts/judge-validator-health.py` + tests: verdict per node (healthy / degraded / unhealthy / unknown) from M incidents and the latest archived native row (parent hash recomputed), incidents active while `open`, `suspended_unknown` or `recovering`, an edge-reachable node whose process and native sources are silent for 180 s is judged unhealthy (`node_process_unobservable`), and a model answer is validated against the diagnosis contract and delivered evidence. |
| `49124b420` | Merge of `cc/c07-c08` (native rows projected into Q, snapshot consensus/chain/storage components, verdict copy, fixed package v2, gated provider adapter; 262 tests). |
| `3b8464170` | Native poll names every skipped tick; separate manager-ingest identity (edge reader role cannot ingest). |
| `d5e5d399f` | Ingress request budget configurable per listener (defaults unchanged 1/s burst 4); `scripts/sample-validator-health-tools.py` reads one node through the six tools over the private MCP socket. |

Gates at `599f72199`: `cargo fmt --check` OK, strict clippy (`--features mcp`)
exit 0, `cargo test --workspace --features mcp` 269 passed / 0 failed / 4
ignored, `check-contracts.py` 24 schemas OK, `pytest tests/test_judge_validator_health.py` 7 passed.

## What happened to the local network (recorded honestly)

1. Rolling the v3 binary onto the six nodes restarted the four validators
   within a few minutes of each other. Each restart replayed state and was
   **OOM-killed at the installed `MemoryMax=4G`** (validator cold start needs
   8–13 GiB after a day of chain growth; the same binary's observers used
   ~200 MiB). The runtime ceiling was raised to 24 GiB and the crash loop
   stopped, but the chain had halted at masterchain seqno 172,664.
2. The validators had **no persistent state** (`archive/states` held only the
   zerostate; the protocol saves one every 2^17 s ≈ 36 h) and replayed from
   genesis at ~3.7 blocks/s, i.e. ~12 h to the head, with any further restart
   starting over. The owner chose to rebuild the development network.
3. Rebuild: monitoring lanes stopped first, runtime drop-ins removed,
   `setup-testnet.sh --clean` from the main checkout (no backup, owner
   decision), then `zz-nhm-cc-runtime.conf` drop-ins with
   `--health-native-core-v3` and the JSON-fixed engine
   (`validator-engine-nhm-cc-2821eae2401fc82f`), `MemoryMax=16G` validators /
   `8G` observers (runtime properties), edges recreated on the new PIDs, all
   `network_id` bindings rewritten to zerostate root `3bd997b3…6c50e`, M
   control/evidence and Q ledger started empty (old databases archived under
   `runtime-archive-*`). Receipt: `runtime/rebind-20260930T105437Z.json`.
4. Two defects surfaced only on the live network and were fixed the same
   hour: the native poll used the edge-reader identity for manager ingest
   (403), and the manager ingress' fixed 1 req/s budget refused a third of
   18 lanes' requests (429).

## Live result

At 11:05–11:08 UTC all six nodes evaluated **healthy**: eight native rules
good per validator, six per observer, native sample age ≤ 30 s, zero
refusals. `nhm-local-judge.timer` now writes one verdict line per minute to
a private journal.

Six-tool read of validator1 through the private MCP socket
(`sample-validator-health-tools.py`): `tools/list` = exactly six tools;
`tos_get_node_snapshot` returned `partial` with **process, consensus, chain
and storage** components, three evidence ids, and the coverage list naming
only the by-design gaps (`local_duties`, `queue_state`, `storage_state`,
host pressure fields). The query projection reports `caught_up` and
`verdict_source_configured: true`.

## Fault exercise (validator4 stopped for 3 minutes, then restarted)

Timeline (judge journal, UTC; validator4 `systemctl stop` at 11:08:30,
`start` at 11:11:30, edge recreated on the new PID at 11:12:15):

| Time | validator4 verdict | Why |
| --- | --- | --- |
| 11:08:30 | healthy | baseline, all eight rules good |
| 11:09:30 | unknown | native rule inputs unknown (no fresh sample), edge still reachable |
| 11:10:30 | degraded | `telemetry_unavailable` opened (warning) after its 45 s pending |
| 11:11:30 | unknown → (after fix) degraded | the incident had moved to `suspended_unknown`; the judge counted only `open`, corrected in `599f72199` so retained severity keeps the node degraded |
| 11:13–11:16 | degraded | node back, native samples fresh, but its rule facts stayed unusable: the restarted engine latched `observation_gap` (an early metrics scrape before registration) and the fact derivation treated that as counter corruption |

Other five nodes stayed healthy throughout; consensus continued (3 of 4).

Two corrections came out of the exercise: incidents in `suspended_unknown`
/ `recovering` stay active with retained severity, and an edge-reachable
node whose process and native sources are silent for 180 s is judged
`unhealthy` (`node_process_unobservable`) instead of unknown. A third:
`observation_gap` is a coverage gap of the bounded publisher, not evidence
that cumulative counters were dropped, so it no longer blocks the facts
(`CounterSaturation`, `CasExhaustion`, capacity and contention reasons still
do).

Recovery: the restart itself had been done in the wrong order (node first,
edge 45 s later), so the old edge and the new edge both sampled the new
process epoch and M quarantined it as a source conflict (`SOURCE_CONFLICT`),
which fail-closed the query broker (`projection_status: conflict`) and kept
validator4 `unknown: native_source_quarantined` — exactly what the design
asks for. A second restart in the correct order (stop the node's edge, restart
the node, wait for its v3 snapshot, recreate the edge on the new PID) produced
a clean epoch; the query cache was archived and re-projected from M without
conflict. At 11:22:56 UTC all six nodes were **healthy** again (validator4
native age 10 s, eight rules good).

Operational rule recorded for this stack: **always stop a node's edge before
restarting the node**; never let two edges sample one process epoch.

## Still open

- **Model explanation**: the AURA step needs a Codex login inside a private
  `CODEX_HOME` (the spawned app-server answers 401) or an approved
  chat-completions endpoint. Not done on my own; the deterministic verdict
  does not depend on it and the validator refuses any answer that upgrades a
  verdict or cites undelivered evidence.
- Persistent state cadence (36 h) means a validator restart before the first
  boundary (~2026-10-01 00:02 UTC) replays from genesis; cheap on a young
  chain, hours on an old one. This is a node property, recorded here for
  operators.
- The health-state verdict copy is imported into the query cache (210 rows in
  the first hour, source `health_state`, component `health`); the six-tool
  sample in this note requested process/consensus/chain/storage and did not
  ask for that component, so its delivery through `tos_get_node_snapshot` is
  not shown here.
- `memory_growth_unexplained` still has no adapter; the cgroup pressure that
  caused today's OOM would have been caught by it.
