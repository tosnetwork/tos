# Workchain-0 consensus standstill — investigation handoff (2026-07-28)

## Current status (2026-07-29)

**Resolved and live-validated.** The initial handoff below correctly captured
PR #15 and PR #16, but its remaining `start_generation()` staleness hypothesis
was not the final root cause. Commit `1c137fa44` (`Fix Simplex recovery across
long empty candidate chains`) fixed the remaining cold-restart liveness bug.
Node3 restarted at 00:06 UTC on current `main` containing PR #15, PR #16, and
`1c137fa44`. After historical replay settled:

- `Standstill detected` occurred zero times in the 00:36-00:46 UTC window;
- workchain 0 resumed collation, including
  `Generating an empty block for slot 193410` for
  shard `(0,8000000000000000)`;
- StateResolver remained exactly bounded at `state_cache=1024/1024` and
  `finalized_cache=4096/4096`, with both in-flight counts at zero;
- `BufferAllocator` live bytes stayed between 590.6 and 591.2 MB over a
  nine-minute steady window;
- a 21-minute differential heap profile showed only 37.2 MB net growth,
  entirely in normal RocksDB MemTable/SkipList/Arena write allocation.

There is no current evidence of a continuing standstill or an independent
unbounded anonymous-memory leak. The rest of this document preserves the
investigation sequence and explains the final third fix.

## Background

Repository `/home/tomi/tos` (a TON fork, TOS blockchain). A local 3-node
private test network runs via systemd services `tos-validator@{1,2,3}.service`,
with data directories under `test/integration/.network/node{1,2,3}`.
Masterchain (shard `-1`) is validated jointly by all 3 nodes. Workchain 0
(shard `0`) has a validator committee of **exactly one validator: node3**
(`shard_validators=1`, a legitimate genesis-config choice — the project's own
`test/integration/test_simplex2_release.py` explicitly supports this
configuration, it is not a misconfiguration). node1/node2 are observers only
on workchain 0.

## Problems already found and fixed

### Problem 1: unbounded in-flight growth in `state-resolver.cpp` (fixed, PR #15, branch `fix/simplex-state-resolver-inflight-admission-control`)

In `validator/consensus/simplex/state-resolver.cpp`,
`StateResolverImpl::resolve_state()` / `finalize_blocks()` bound their
`CompletedLru` (`completed-lru.h`) caches only for **completed** entries —
in-flight (started, not yet resolved) entries have no bound at all. In
production (node3) this was observed as `state_cache` repeatedly spiking to
37138/1024 (configured cap is 1024), then collapsing back to ~0 almost
instantly, in a roughly 60-90 second cycle.

Fix: added `InflightAdmission` (`completed-lru.h`), which gates admission of
a **new** entry once a configurable concurrent cap is reached (default 4096,
tunable via `TOS_SIMPLEX_STATE_INFLIGHT_MAX` /
`TOS_SIMPLEX_FINALIZED_INFLIGHT_MAX`), rejecting overflow with
`ErrorCode::notready`. Already-known entries are unaffected. Verified in
production: after deploying this fix, `state_cache` stayed bounded
(oscillating between 0 and ~2145) and eventually drained to 0, instead of
growing without bound.

### Problem 2: `resolve_state_inner()` unconditionally takes the network resolution path for skip-certified slots (fixed, PR #16, branch `fix/simplex-skip-certified-resolution-shortcircuit`)

Root cause chain:
1. `consensus.cpp`'s `alarm()` (around lines 147-160) only ever broadcasts
   `BroadcastVote<SkipVote>` once a slot times out — it never broadcasts any
   candidate placeholder (not even an empty one) for that slot.
2. `state-resolver.cpp`'s `resolve_state_inner()` (around lines 228-260,
   pre-fix) unconditionally called
   `co_await owning_bus().publish<ResolveCandidate>(*id)` for **every**
   ancestor id, before ever checking whether that slot had already been
   skip-certified, and only checked `candidate->is_empty()` after the
   response came back.
3. A slot that timed out purely via the skip mechanism has **no** `Candidate`
   object anywhere in the network. `candidate-resolver.cpp`'s
   `resolve_candidate_inner()` (around lines 593-666) retries its peer-query
   `while (!complete)` loop **with no overall deadline** — only a capped
   per-attempt timeout that grows multiplicatively — so it retries forever
   against something that structurally cannot exist.
4. This is self-reinforcing: `consensus.cpp`'s `start_generation()` (around
   lines 211-226) calls `resolve_state(base)` as its first step; if that
   never completes, `OurLeaderWindowStarted` is never published, so every
   slot in that leader window lapses into a fresh skip vote, extending the
   phantom ancestor chain further and making the next attempt even slower.

Fix:
- Added `QuerySlotSkipped` (`bus.h` / `bus.cpp` / `pool.cpp`), a purely local
  (no network/DB round trip) Bus query that reads `PoolImpl`'s already
  tracked per-slot state directly (`SlotState::is_skipped()` /
  `available_base`; `available_base` is already correctly propagated past
  entire skip runs by `handle_typed_saved_certificate(SkipCertRef)`).
  `resolve_state_inner()` now asks this **before** ever calling
  `ResolveCandidate`; a positive answer jumps straight to the real ancestor
  in one hop.
- Added an overall attempt cap to `candidate-resolver.cpp`'s retry loop
  (`TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS`, default 16), returning
  `ErrorCode::notready` once exhausted, as defense-in-depth for any other
  reason a candidate can't be found.

Verified: full `test-consensus` suite passes (17/17, including
loss/restart/partition/adaptive-byzantine/state-resolver-catch-up
scenarios), clean build under `-Werror`. Deployed live to node3: `state_cache`
was confirmed to drain fully to 0 (no longer stuck growing) — but see below.

## Problem 3: recursive recovery across a long empty-candidate chain (fixed by `1c137fa44`)

The PR #15 + PR #16 deployment still showed no workchain-0 collation in its
first observation window. The initial hypothesis was that
`start_generation()` completed state resolution too late and discarded every
attempt through its leader-window staleness check. Further investigation
ruled that out as the root cause.

The actual failure was deterministic after a sufficiently long quiet-chain
history:

1. Empty candidates are real `Candidate` objects whose parent points to the
   previous candidate. They are distinct from skip-certified slots, for which
   PR #16's `QuerySlotSkipped` can jump directly to `available_base`.
2. The old `resolve_state_inner()` recursively called
   `resolve_state(candidate->parent_id)` for every empty candidate.
3. Each recursive step entered `resolve_state()` as an independently admitted
   cache/in-flight operation. A cold restart behind more than the production
   4,096-entry admission limit therefore failed before reaching a usable
   finalized or genesis anchor.
4. Retrying restarted the same long ancestor walk. This prevented
   `start_generation()` from obtaining its base state, so new leader windows
   produced more empty/skip history and the standstill became
   self-reinforcing.
5. A finalized anchor could also be temporarily absent from the manager's
   block/state indexes during cold-start replay. Treating that
   timeout/not-ready result as a reason to restart the whole 4,096+ ancestor
   walk amplified the failure.

Commit `1c137fa44` makes the ancestor traversal iterative inside one admitted
operation:

- skip-certified runs still jump through `QuerySlotSkipped`;
- empty candidates only advance the local ancestor cursor and therefore use
  constant additional memory regardless of chain length;
- only full candidates that must be replayed are retained, then applied
  oldest-to-newest once a cached, finalized, or genesis state anchor is found;
- an already cached ancestor state is reused directly;
- if a finalized anchor is temporarily unavailable from the manager with
  `timeout` or `notready`, the resolver reconstructs it from its already
  validated candidate data instead of restarting the entire walk.

The deterministic regression
`test-consensus-simplex2-empty-chain-restart` constructs more than 4,096
consecutive empty candidates, cold-restarts the node, forces the
missing-manager-anchor fallback, and requires consensus to resume. This test
and the full consensus suite pass.

The live evidence in "Current status" confirms the production symptom is
gone. The earlier `current_window_` staleness theory and validator-index
concern are retained only as ruled-out investigation hypotheses; neither
required a code change.

## Files involved

- `validator/consensus/simplex/state-resolver.cpp` (modified by PR #15/#16
  and `1c137fa44`; iterative long-empty-chain recovery)
- `validator/consensus/simplex/candidate-resolver.cpp` (modified, PR #16)
- `validator/consensus/simplex/completed-lru.h` (modified, PR #15)
- `validator/consensus/simplex/bus.h` / `bus.cpp` (modified, PR #16, added `QuerySlotSkipped`)
- `validator/consensus/simplex/pool.cpp` (modified, PR #16)
- `validator/consensus/simplex/consensus.cpp` (investigated; the
  leader-window staleness check was not the final root cause)
- `validator/consensus/simplex/collator-schedule.cpp` (investigated; no issue)
- `validator/consensus/block-producer.cpp` (investigated; no issue)

## How to reproduce / observe

Local services: `tos-validator@{1,2,3}.service`
(`sudo systemctl restart|status tos-validator@N.service`).
Logs: `sudo journalctl -u tos-validator@3.service -f -o cat`.
The historical failure was stuck at finalized slot **81094**. Current `main`
has recovered and workchain 0 is producing blocks. Key regression markers to
monitor are `Standstill detected`,
`MEMORY_DIAGNOSTICS simplex-state-resolver`,
`Generating an empty block for slot`, and
`Collator for shard (0,8000000000000000`.
