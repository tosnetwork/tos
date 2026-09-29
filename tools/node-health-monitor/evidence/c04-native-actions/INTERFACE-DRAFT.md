# C04 native interface draft — review required

Baseline: `a884b0ca735736fd5a81306c26bdc65a5bd967df`.
This is a proposal. The native-core-v1 publisher and Rust consumer remain unchanged.

## Logical accounting and bounded storage

Four actions: `proposal`, `notarize_vote`, `finalize_vote`, `skip_vote`.
Public origin: `live`, `replay`. Replay has the finite discriminator
`signed_record` or `intent_only`; live has discriminator `null`.

One reservation belongs to an existing bus/session, with separate actor-confined
vote and proposal lanes. The process has eight context reservations, sixteen
ledger banks, 512 keys per bank (8192 total keys), and 1024 shared pending age
rows. Ledger keys contain action, origin/discriminator, slot and a 32-byte
candidate hash. Bus ownership supplies the session and shard identity; the
publisher supplies the process epoch and network identity. Skip has zero bytes
in its internal candidate key and public candidate_id=null. Proposal uses the
slot opportunity before its candidate exists, so first-block retries share the
same logical key. Candidate publication can subsequently supply its identity.

The banks occupy less than 512KiB; counters and pending rows less than 40KiB.
Context records must stay below 16KiB. The entire proposed extension is below
568KiB, leaving the remainder of the 4MiB core budget for C01 and publication.
No bank is replicated per actor. Reservation uses at most eight CAS attempts
over contexts; action lookup compares at most 512 scalar keys; pending admission
tests at most 1024 fixed rows. Publication may scan those 1024 rows once per
generation, never coroutine state. All paths have fixed bounds and retain no
business object, actor, bus, state, signature or key reference.

Terminal keys remain until their bus dies. There is no eviction: a full bank
declines new tracking and latches incomplete. This is an explicit limitation for
long-lived sessions, rather than a claim of exact lifetime deduplication after
discarding history. An alternative bounded retention policy needs a proven
protocol rejection boundary before approval. Pending capacity, context capacity,
counter saturation and bounded CAS exhaustion similarly latch incomplete and
leave business work untouched. Oldest age is an approximate concurrent view,
computed from admitted rows; absent/full observations never imply an exact zero.

The first admitted logical key contributes one requested phase, one pending
increment and one terminal decrement. Repeated calls contribute only a separate
repeated-request counter. They still run all original business logic and may
invoke the signer again. PQ counters remain the existing production leaf counts.
Each logical phase is emitted once. Live requested = pending + sum(live outcomes)
when accounting is complete at a quiescent read; concurrent reads are approximate.
Replay phases and pending are separate and never enter live outcome totals.

## Exact metric tuples proposed

`tos_consensus_actions_total{action,phase,origin}` permits:

- proposal/live: requested, signed, candidate_published.
- each vote/live: requested, intent_committed, signed, signed_committed,
  local_applied, broadcast_enqueued.
- each vote/replay: requested, restored_signed, signed, signed_committed,
  local_applied. restored_signed is only signed-record replay; signing and signed
  commit are only intent-only replay.

`tos_consensus_action_outcomes_total{action,outcome}`: four actions times
enqueued/failed/cancelled/suppressed/unknown (20 tuples).
`tos_consensus_action_pending{action}` and oldest_age_seconds: four tuples each,
live population. Replay pending is a distinct native snapshot field.
`tos_consensus_action_accounting_complete{action}`: four tuples.
Failure tuples are sparse:

- all actions: missing_signer, sign_backend, finality_behind, superseded, cancelled.
- votes only: intent_storage, signed_storage, journal_unusable, duplicate_or_stale.

Proposal first-block retry and empty-candidate totals each have one fixed tuple.
Session state gauges: active, stopping. Started/stopping_started/stopped counters
are process-lifetime scalar totals. No session/hash/slot is a metric label.
The authoritative series calculation is 3 proposal/live + 18 vote/live + 15 vote/replay =
36 phase series; 20 outcome + 8 pending/age + 4 completeness + 32 failure +
2 proposal + 5 session = 107 series. Final manifest must compute and verify this
count and the union with all C01/PQ series before approval.

## Branch mapping

- pool::cast_our_vote intent await error: failed/intent_storage, except cancelled
  status: cancelled/unknown cancellation cause. No signing or later phases.
- no signer: failed/missing_signer; backend failure: failed/sign_backend.
- signed commit await error: failed/signed_storage, except cancelled status:
  cancelled. No applied/enqueued phase.
- pool::apply_own_vote handle_vote=false: suppressed/duplicate_or_stale. This
  conservative classification makes no claim of storage failure.
- actual live OutgoingProtocolMessage publication: enqueued, meaning local enqueue.
- replay signed record: restored_signed and possibly local_applied; no new sign,
  no live enqueue/outcome. Intent replay signs and commits once through original
  production code, still no live enqueue/outcome.
- producer::generate_candidates successful CandidateGenerated publication:
  proposal/enqueued. Signed alone or CollateFinished is not completion.
- finality/journal early returns: suppressed with their finite cause.
- superseded generation: cancelled/superseded. Coroutine destruction while
  unfinished: cancelled. No invented operational or protocol deadlines.

## Canonical payload proposal

Successor source_version=`native-core-v2`. Retain existing native_core fields
and SourceEnvelope. Add `consensus` (null when disabled). Keys are canonical
lexical order; every u64 counter, age and sequence is a decimal string.
The proposed `consensus` object has exactly:

```
actions: array <=4, sorted proposal/notarize_vote/finalize_vote/skip_vote
capabilities: fixed object of supported/unsupported flags and finite reasons
contexts: array <=8, deterministic registration order
instrumentation_complete: boolean
repeated_requests: decimal_u64
sessions: {active, started, stop_started, stopped, stopping}: decimal_u64
```

An action row has exactly action, accounting_complete, live, replay.
`live` has exactly outcomes (five fixed named counters), pending,
oldest_age_ns (decimal_u64|null), phases (action-specific exact named counters),
failures (action-specific exact named counters). `replay` is null for proposal;
votes have signed_record and intent_only subrows, each with exact phases,
pending and oldest_age_ns. Impossible stages are absent by an exact schema,
not arbitrary dynamic keys or silently zero-filled fields.

Each context has network_id (hex64), scope (workchain i32/shard decimal_u64;
approved scope alias or null), session_id (hex64), current_slot u32|null,
last_finalized_slot u32|null, lifecycle=active|stopping,
stop_started_monotonic_ns decimal_u64|null. These are consensus identities.
Block anchors and StorageAck objects remain separately typed and cannot be
inferred from these slots. Context lifetime publication needs a bounded safe
snapshot mechanism; this draft does not authorize reading actor-owned memory.

Fixed unsupported capabilities: assigned vote denominator, vote protocol
deadline, network observation/inclusion, exact cohort success rate, PQ queue,
hardware durable_finality. Storage acknowledgements mean commit_acknowledged.
No zero substitutes for unsupported. Timeliness remains unknown without a
frozen deadline and not_applicable for replay.

## Remaining review decisions

Native labels need the C01 CoreRegistry to support fixed approved tuples (the
existing 64 unlabelled production slots have an empty allowlist). Proposed
extension is prebound finite tuple handles with enough bounded slots, retaining
its saturating updates and no hot-path registration. This needs a frozen metric
manifest; the alternative independent inherited scalar array is preparation only.

Bus destruction is currently an ownership-release observation. Before naming
it actual stopped, demonstrate the existing SpawnsWith actor lifetime and real
drain boundary, including pending coroutine and stop-event delivery fixtures.
Stopping must begin at the bridge's actual StopRequested publication, with no
new owning references. C03/Rust integration, publisher generation coupling,
canonical hashes and the exact successor schemas belong to coordinated review.
