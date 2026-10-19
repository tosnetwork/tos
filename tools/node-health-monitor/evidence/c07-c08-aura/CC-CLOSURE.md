# C07/C08 closure matrix and native evidence path (2026-09-30)

Branch `cc/c07-c08` from `origin/node-health-monitor@217a3ce59`. Scope was
re-ordered mid-task by the owner to "AURA can reliably judge validator
health": (a) project archived native rows and serve real consensus/chain/
storage components and catalog metrics, (b) expose M's health-state verdict
read-only, (c) put both into the fixed package, (d) a small gated provider
adapter; the C08 rejection matrix dropped to last. This document records
what is implemented and tested, what is not, and the exact commands.

Commits (all pushed to `origin/cc/c07-c08`, none to `node-health-monitor`
or `main`):

| Commit | Content |
| --- | --- |
| `41f8750b3` | Native consensus rows projected into the query cache; snapshot consensus/chain/storage components; verdict copy; native metric catalog; schemas regenerated; RESULT_TOO_LARGE; multi_source coverage; control-DB argument |
| `df7e855dc` | Fixed package v2 (native + verdicts, deterministic truncation); diagnosis validator hardening; broker-owned publication record |
| (this commit) | Chat-completions provider adapter behind a config gate with owned-mock tests; this closure document and status rows |

## Gates (each commit)

```sh
cd tools/node-health-monitor
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features mcp --locked -j64 -- -D warnings
cargo test --workspace --locked -j64 --features mcp --no-fail-fast
```

Results: baseline (`217a3ce59`) tests 247 passed / 0 failed; baseline strict
clippy was already **red** at `native.rs:186` (`NativeRecord`) and
`edge_snapshot.rs:43` (`EdgeSource`) with `large_enum_variant` (verified on a
clean `git archive HEAD` export, exit 101) and is now green with documented
`allow`s. After `41f8750b3`: fmt OK, clippy exit 0, tests 251 passed / 0
failed / 4 ignored (host-only diagnostics). After `df7e855dc`: fmt OK,
clippy exit 0, tests 257 / 0 / 4. For this commit: fmt OK, clippy exit 0,
tests 262 passed / 0 failed / 4 ignored (`--no-fail-fast`); a lint-only
scoping change in `tests/provider.rs` followed, after which fmt, clippy and
the provider binary (5/5) were re-run green. `scripts/check-contracts.py`
passes (24 closed schemas) and the
runtime snapshot outputs `tos_get_node_snapshot.native.json` (consensus,
chain, storage; 11 805 bytes) and `tos_get_node_snapshot.verdict.json`
(consensus with health; 11 568 bytes) validate against the regenerated
`tos_get_node_snapshot.output.schema.json`.

One pre-existing test changed meaning: `tests/ingress.rs` archived a full
edge snapshot (native + process) and asserted the projection yields exactly
one row under the old process-only rule; it now counts process rows
explicitly (the native row is the intended second projection).

## Fixture

`crates/health-services/tests/fixtures/native_core_v2_validator1.json` is one
real `native-core-v2` sample from the validator1 loopback publisher
(`generation 3620`, `2026-09-30T09:40:38Z`, content hash verified). It
contains no key material. v3 rows in tests are derived from it with
synthetic chain anchors and recomputed content hashes.

## Coverage matrix

Legend: **IT** implemented and tested by an isolated test on this host;
**IU** implemented, not covered by a dedicated test; **M** missing;
**U** unsupported by design (documented); **not_run** needs owner input.

### Owner priority items

| # | Predicate | Status | Where |
| --- | --- | --- | --- |
| a1 | Archived `native_core` v1/v2/v3 rows projected with retained-parent/W discipline | IT | `manager_query_source.rs::project_native`, `tests/native_projection.rs::native_rows_project_deterministically_and_skip_fact_frames` (parent ≤ query charge, pure function of parent, tamper refused) |
| a2 | Collector fact frames with the same source id are never projected | IT | same test; SQL `ELIGIBLE_SOURCE` selects on the archived component tag; mutant M2 |
| a3 | `tos_get_node_snapshot` `consensus` from native rows: sessions, contexts (slots, lifecycle), per-action phases/outcomes/failures/pending/oldest age, pq_sign/pq_verify, incomplete reasons | IT | `snapshot_serves_consensus_chain_storage_and_catalog_metrics_from_native_rows` |
| a4 | `chain` component from v3 anchors (applied/served seqno, applied age, served gap); v2-only window is an explicit `CACHE_MISS` | IT | same test |
| a5 | `storage` component (storage_commit_ack capability, durable-finality reason, storage/journal failure sums) | IT | same test |
| a6 | `tos_get_metric_window` fixed catalog (24 ids), derived from consecutive delivered samples, honest population/gaps/resets, no PromQL | IT | `health-core/src/native_metrics.rs`; same test (gauge, delta with `no prior sample` gap, null points for absent field) |
| a7 | `max_points_per_series` smaller than result is explicit `SERIES_LIMIT`, not trimming | IT | same test; mutant M1 |
| a8 | 4096-point and 32-series limits | IU / U | guards present in `query.rs`; 32 series unreachable through the input contract (4 nodes × 6 ids = 24); 4096 points unreachable within the 8 MiB resident cap |
| b1 | Health-state verdict exposed read-only in the consensus component (active incidents, rule ids, severity, episode, evaluation sequence) | IT | `health_verdict_copy_attaches_to_consensus_component_read_only`, `fresh_native_sample_and_verdict_share_one_snapshot`; control DB opened read-only, unchanged after the run |
| b2 | Verdict `since` | U (documented) | M's `HealthState` has no wall-clock incident time; the copy exposes `observed_at` = query import time with `since_basis: query_import`. A true `since` needs a field in health-state (other agent's file). |
| b3 | Stale verdict copy is reported missing, never shown | IT | stale row (hours old) → `health: null` + `missing_evidence[health_state]` |
| b4 | Verdict read failure never revokes grants | IT | `with_manager_control` on a foreign-network control DB fails at startup; runtime failures set `verdict_import_error` (exposed on projection-health) |
| c1 | Fixed package v2 carries native components and verdicts per node at fixed W | IT | `package_v2_fixes_native_and_verdicts_and_truncates_deterministically` |
| c2 | ≤ 16 KiB with deterministic truncation and explicit listing | IT | same test; four v3 nodes ≈ 18 KiB → all chain/storage views then the last node's consensus dropped, verdicts kept; mutant M4 |
| c3 | Validator accepts `analysis` citing package ids; refuses M parent ids and undelivered ids | IT | same test |
| d1 | Chat-completions profile behind `enabled`/profile/egress gate | IT | `tests/provider.rs` |
| d2 | private_only egress: public IP, DNS name, IPv6 global, credentials in URL, wrong scheme refused with zero requests | IT | `disabled_and_non_private_endpoints_never_send_a_request` |
| d3 | Redirect refused, target never contacted | IT | `redirect_is_refused_and_the_target_is_never_contacted`; mutant M5 |
| d4 | SSE error, refusal (JSON and content_filter), incomplete (length, empty, `[DONE]` without content, stream without `[DONE]`), HTTP 200 non-JSON, HTTP 4xx/5xx → rules-only, one request, no retry | IT | `every_provider_failure_is_rules_only_without_retry` |
| d5 | Exactly one format repair, then `InvalidJson`; second reply valid → accepted | IT | `invalid_diagnosis_is_repaired_exactly_once` |
| d6 | Package is the only user content; no tools offered | IT | `streamed_valid_diagnosis_is_accepted_and_package_is_the_only_user_content` |
| d7 | Real model/provider run | not_run | owner has not chosen a model/provider; no external host is configured or contacted |

### C07 predicates (design §15, work order C07)

| # | Predicate | Status | Where |
| --- | --- | --- | --- |
| 1 | observed finding cites ≥ 1 delivered evidence id | IT | `diagnosis.rs` tests, `contracts.rs` |
| 2 | ids must be from this run's delivered set (not other run / undelivered page / expired) | IT | `evidence_must_come_from_this_runs_delivered_set`; package test (M parent id refused) |
| 3 | hypothesis requires `missing_evidence` | IT | `diagnosis.rs`, `contracts.rs` |
| 4 | multiple JSON objects, trailing instructions, leading prose, BOM, array wrapper, truncation, > 16 KiB refused | IT | `multiple_objects_trailing_text_truncation_and_prefix_are_refused` |
| 5 | unknown fields at any depth refused | IT | `model_cannot_supply_severity_or_remediation_fields` |
| 6 | repeated JSON keys refused | IT | `duplicate_keys_at_any_depth_are_refused`; mutant M3 |
| 7 | model cannot change severity or claim remediation | IT (structural) | closed schema has no such fields; `PublishedDiagnosis` carries broker severity/coverage and constant `remediation: not_executed` |
| 8 | broker adds schema/prompt/model/config versions, input/ledger hashes, elapsed/usage | IT | `Provenance` in `PublishedDiagnosis::publish` |
| 9 | token accounting with a real tokenizer, 8192 context / 1536 output | M | not implemented; the model is unchosen so any tokenizer would be approximate. The 16 KiB package byte bound is the only enforced input bound. |
| 10 | retention cleanup of `query_packages` and revoked grants | IU / M | `QueryLedger::compact_terminal` already reclaims expired runs (packages, attempts, bindings) under an explicit cutoff and is tested; revoked-but-unexpired grants and quota-driven reclamation are not implemented |
| 11 | AI stop/timeout/schema error do not affect basic alerting | IT (structural) | query/broker layer has no path into health-state; control DB opened read-only |

### C08 predicates (design §14, work order C08)

| # | Predicate | Status | Where |
| --- | --- | --- | --- |
| 1 | six exact tools, `tools/list` exactly six | IT | `tests/mcp.rs`, `tos-observability` bin test |
| 2 | HTTP and MCP share one implementation | IT | `mcp_bridge.rs` invokes the HTTP router |
| 3 | cross-run access | IT | `tests/http.rs` (401, cursor `CURSOR_MISMATCH`) |
| 4 | cross-scope / cross-node access | IT | `tests/http.rs` (`OUT_OF_SCOPE`) |
| 5 | unknown fields incl. `force_refresh` | IT (force_refresh) / IU (`live`, `priority`, `sample_interval` — same `deny_unknown_fields` path, no dedicated test) | `tests/http.rs` |
| 6 | cache miss non-retryable, no re-collection | IT | `retryable=false` asserted; `manager_projection_reads` counter unchanged under queries (`tests/native_projection.rs`, `tests/manager_query_source.rs` 1000-request storm) |
| 7 | oversize input 16 KiB / response 32 KiB / run 128 KiB incl. MCP duplicate bytes | IT | `tests/http.rs` 413; `mcp_bridge.rs` unit tests; bin test; `tests/query_ledger.rs` |
| 8 | 16 total calls incl. failures, 2 concurrent, 180 s run, 200 s grant, 5 s tool timeout | IT | ledger and bridge tests, storm test |
| 9 | duplicate page replay | IU | stable-read by construction; no dedicated replay-twice test |
| 10 | expired cursor / cursor parameter mismatch / tampered / wrong tool | IT | `query.rs` unit test, `tests/http.rs` |
| 11 | two sources at the same observed time | IT (changes, store order) / IU (events from two sources) | `tests/http.rs` |
| 12 | late-arriving records after W fixed | IT | `tests/http.rs`, `tests/query_ledger.rs` |
| 13 | token crossover between two concurrent connections | IU | single-connection replay and second-connection refusal tested in the bin; no two-run interleaving test |
| 14 | redirect refusal | IT (provider, adapter non-success refusal) | `tests/provider.rs`, `tests/aura_stdio.rs` |
| 15 | prompt-injection text in evidence stays data | IU | single charged JSON text block by construction; no dedicated test |
| 16 | MCP annotations are not authorization | IU | annotations fixed `readOnlyHint=true`; revoked grants refused regardless; no dedicated test |
| 17 | cancel revokes grant and observes real child termination | IU / M | adapter child death and reap tested (`aura_stdio.rs`); broker-owned cancel→revoke→wait sequence at process level not implemented (`Broker` has only `cancel`/`confirm_stopped` state) |
| 18 | no second model task while prior unconfirmed | IT (state) / M (process) | `contracts.rs` broker tests |
| 19 | zero unplanned V/O/Prometheus requests under tool storm + cache miss + ancestor_depth | IT (M reads) / U (V/O) | QueryService has no upstream client; M-read counter asserted; no owned fake V/O upstream counter test |
| 20 | broker cannot write health-state severity/resolution | IT (structural) | control DB read-only; publication severity is broker input |

Counts: IT 43, IU 9, M 3 (token accounting, quota/revoked retention, process-level cancel), U 3 (32-series bound, verdict `since`, V/O counter), not_run 1 (real model).

## Compiled mutation checks (all restored to green afterwards)

| Mutant | Guard removed | Killed by |
| --- | --- | --- |
| M1 `query.rs` | `count > max_points_per_series → SERIES_LIMIT` deleted (silent trimming) | `snapshot_serves_...` `native_projection.rs:450` — got 200, expected 429 |
| M2 `manager_query_source.rs` | `ELIGIBLE_SOURCE` component tag check replaced by `1=1` | `snapshot_serves_...` :287 and `health_verdict_copy_...` :517 — import refuses the now-eligible fact frame |
| M3 `diagnosis.rs` | `reject_duplicate_keys` call deleted | `duplicate_keys_at_any_depth_are_refused` `diagnosis.rs:346` — `invalid diagnosis JSON` instead of `duplicate JSON object key` |
| M4 `fixed_package.rs` | drop order swapped to chain before storage | `package_v2_fixes_...` `native_projection.rs:796` — first drop not `validator4/storage` |
| M5 `provider.rs` | redirect policy `none` → `limited(2)` | `redirect_is_refused_...` `provider.rs:164` — `HttpStatus(405)` (target contacted) instead of 302 |

Baseline and restored runs: `tos-health-core --lib` 8/8, `native_projection`
5/5, `provider` 5/5 after reverting every mutant.

## Retention and budget notes (honest limits)

- Derived native rows are ~10–13 KiB resident charge (compact typed payload,
  chain/storage views and the exact origin payload so the M-parent retention
  cap can never bind first). At 6 nodes × 15 s this is roughly 25–30 min of
  history in the 8 MiB resident cache; metric windows beyond that are partial
  with explicit gaps. Longer history needs a larger cap (owner decision).
- While any grant is active, eviction of rows at or before its W is refused
  (pre-existing policy); with native rows the cache fills sooner, so imports
  pause (`caught_up=false`, new grants 503) until active grants expire.
- The verdict copy is refreshed only when M's evaluation sequence moves or
  the copy is older than two minutes; it is fresh relative to the response
  clock (bounded by `max_age_seconds`) because the broker fixes the window at
  or before grant creation, which is when the copy is stamped.
- A 4-node package cannot hold four full v3 samples in 16 KiB; three full
  samples plus all four verdicts are kept and the fourth consensus is listed
  as dropped. Two-node grants keep everything.

## Items needing owner input (`not_run`, never pass)

1. Choice of model/provider endpoint (private_only) and its real egress test.
2. Real tokenizer for context accounting once the model is known.
3. Whether the 8 MiB resident/parent caps should grow for native history.
4. A wall-clock incident time in M's health state (other agent's file) so the
   verdict `since` can be authoritative rather than `query_import`.

## Requests to the other agent (files not edited here)

- `crates/health-core/src/health_state.rs` / control outbox: add an
  authoritative incident open time so `HealthDto.since_basis` can become
  `health_state`.
- `native.rs` / `edge_snapshot.rs`: two `#[allow(clippy::large_enum_variant)]`
  attributes were added with comments to restore the strict gate; keep or
  replace by boxing the v3 variants in your consumers.
- `tests/ingress.rs:528`: assertion now counts process rows explicitly.
