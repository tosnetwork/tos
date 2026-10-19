# C04 native-core-v2 shared wire review — proposed freeze, not implementation

Baseline: TOS `2060cc1a1c7a36fe7214789a254cc36017c9f3a0` (accepted C03).
Producer proposal: Starbridge `evidence/c04-native-actions/INTERFACE-DRAFT.md`
in its isolated tree, inspected 2026-09-29 UTC. This document does not approve
or change either publisher or Rust wire. Supervisor must freeze one exact
successor before either side changes the published format.

Starbridge subsequently supplied closed Draft 2020-12
`consensus-schema.draft.json` (SHA-256
`97c06fafcd395d3261a3ed03e0e9f7d603cfc4ba362fe2e2d9681b6d6f92a0e0`)
and synthetic `consensus-canonical.draft.json` (SHA-256
`950037142424d05ff5231bbcf61ad7b62545e07d4ce30b85e627b943202b9f78`).
The pinned C00 Python environment with jsonschema 4.25.1 accepted the schema
and its sample (Draft202012Validator.check_schema and iter_errors, zero errors).
That is a shape check, not a native producer-byte or semantic validation.
Three in-memory negative probes are also **accepted by that draft schema**:
`sessions.started="18446744073709551616"`, unsupported `vote_assigned` with
`enabled=true`, and proposal `accounting_complete=false` without a reason.
These are concrete remaining semantic contract gaps, not native test failures.

## Version and immutable pairing

- Preserve `native-core-v1` validation and fixtures unchanged. `native-core-v2`
  is a separate strict payload variant, selected by the literal `source_version`;
  no untagged/deserialization fallback to v1 or arbitrary JSON. Envelope
  `schema_version=1` can remain only if the envelope fields/meaning are unchanged.
- V2 retains the v1 required fields and adds required-nullable `consensus`.
  `consensus=null` means C04 disabled/unsupported, **not** complete with zero
  actions. Once C04 is expected, v1/null is unavailable for C04 facts.
- All objects are closed (`additionalProperties=false` / `deny_unknown_fields`),
  including nested replay/capability/context rows. Each u64 is canonical
  decimal text: `0` or nonzero without leading zero, bounded by `u64::MAX`.
  IDs/hashes are lowercase 64-digit hex. Explicit null is distinct from a
  missing required-nullable key.
- Envelope `generation` equals payload `generation`; `source_epoch` equals
  `process_epoch`; the exact returned OpenMetrics body, including EOF, matches
  payload `bytes` and SHA-256 `openmetrics_hash`; canonical JSON payload matches
  `content_hash`. Preserve the 2 MiB body limit and 30 s source-age gate.
  A failed invariant refuses the entire native pair, never a partial C04 fact.
- `quality.instrumentation_complete` must not claim more than both existing PQ
  leaves and consensus accounting. V2's source coverage remains partial for
  other unimplemented sources. Freeze a distinct V2 sampling-policy literal
  describing concurrent generation approximation; do not claim atomic actor
  state. Counters are process-epoch cumulative; pending/ages/contexts are
  generation-time concurrent snapshots. A cross-generation delta is valid only
  within identical process/source epoch, action and context identity.

## Closed C04 payload shape proposed for supervisor freeze

`consensus` non-null is an object with exactly `actions`, `capabilities`,
`contexts`, `instrumentation_complete`, `incomplete_reasons`,
`repeated_requests`, and `sessions`. `actions` is exactly four unique rows in
this canonical order: proposal, notarize_vote, finalize_vote, skip_vote. The
producer's current `<=4` permits omitted actions to masquerade as zero; either
require all four or add explicit per-action unavailable entries. This proposal
requires all four with `accounting_complete=false` when their source is not
fully instrumented. `contexts` is at most eight, unique by
`(network_id,scope_id,session_id)` and in stable registration order; a duplicate
identity or a context network different from payload `network_id` is refused.
`repeated_requests` is an exact process-wide counter separate from per-action
phase counters and from actual PQ leaf invocation counts. The supervisor's
incremental ruling permits ledger retirement only for **terminal** keys with
`slot <` a monotonic finalization floor obtained from the owner's actual
Finalization event. Pending keys are never retired. A request for a retired
terminal key must not reopen logical requested/outcome counting; a genuinely
new later phase is observed once but latches accounting incomplete. The
producer must test asynchronous mailbox/floor ordering and must not pool
unrelated actors into a plain shared bank. This bounded-retention rule
supersedes the producer draft's no-eviction proposal, subject to exact native
implementation review.

An action row has exactly `action`, `accounting_complete`,
`incomplete_reasons`, `live`, and `replay`. `incomplete_reasons` is a sorted,
unique finite list, nonempty iff `accounting_complete=false` when C04 is
enabled. Proposed finite values: `context_capacity`, `ledger_capacity`,
`pending_capacity`, `counter_saturation`, `cas_exhaustion`,
`observation_gap`, `session_lifecycle_unverified`. The global list is the
sorted union of per-action and session/producer reasons. A full 512-key bank,
1024 pending rows, eight contexts, or exhausted bounded CAS must latch an
appropriate reason for the affected action; no pending eviction, zero-fill,
or new business failure. Post-retirement new-phase ambiguity also latches
`observation_gap`, without altering historical requested/outcome counts.
`instrumentation_complete` is true only when all action
accounting and lifecycle measurements claimed by this payload are complete.

`live` has exactly `phases`, `outcomes`, `failures`, `pending`, and
`oldest_age_ns`. Proposal phases are `requested`, `signed`,
`candidate_published`; each vote phase is `requested`, `intent_committed`,
`signed`, `signed_committed`, `local_applied`, `broadcast_enqueued`.
`outcomes` has exactly `enqueued`, `failed`, `cancelled`, `suppressed`,
`unknown`. Proposal failures have exactly `missing_signer`, `sign_backend`,
`finality_behind`, `superseded`, `cancelled`; each vote adds `intent_storage`,
`signed_storage`, `journal_unusable`, `duplicate_or_stale`. All counters and
`pending` are decimal u64. `oldest_age_ns` is decimal u64 **or null**;
it is null when there is no admitted pending row or tracking/age is incomplete,
and never fabricated as zero. Outcome values mean local terminal observation,
with `enqueued` only at actual CandidateGenerated/OutgoingProtocolMessage
publication, not network receipt. A single logical key has at most one live
requested phase and terminal outcome. Retry may still invoke PQ signing again.

Proposal `replay=null`; each vote `replay` has exactly `signed_record` and
`intent_only`. Each subrow has `phases`, `pending`, `oldest_age_ns` and (subject
to the replay-failure decision below) a finite terminal/error accounting
field. Signed-record phases are exactly `requested`, `restored_signed`,
`local_applied`; intent-only phases exactly `requested`, `signed`,
`signed_committed`, `local_applied`. Impossible phases are absent, not zero
under a generic map. Replay never contributes live outcomes/enqueue, but a
real intent-only signer invocation still contributes to the existing PQ leaf.

Proposed context exact fields: `network_id`, `scope`, `session_id`,
`current_slot`, `last_finalized_slot`, `lifecycle`,
`stop_started_monotonic_ns`. Freeze `scope` as a closed object
`{scope_id: alias, workchain: i32, shard: decimal_u64}`, or null if the native
owner cannot establish that mapping. Null scope makes scoped C04 facts
unavailable; it must not be silently interpreted as envelope `scope_id=node`.
Slots are u32 or null and never block seqno. Lifecycle is `active|stopping`.
If stop-start time is present, lifecycle must be `stopping`; if active, it is
null. No actor-owned memory may be read without a bounded safe snapshot.

Capabilities must be a closed fixed set, not arbitrary labels. Proposed keys:
`assigned_duty_denominator`, `protocol_deadline`, `network_inclusion`,
`exact_cohort_success`, `pq_queue`, `durable_finality`, plus positive
`local_action_accounting` and `storage_commit_acknowledged` if evidenced.
Each key is `{status: supported|unsupported, reason: finite literal|null}`;
unsupported requires a reason and never a numeric zero. The positive storage
capability means only actual commit acknowledgement, not crash-safe hardware
durability. Timeliness without a frozen deadline is `unknown`; replay is
`not_applicable`. No generic success-rate or missed-duty denominator is derived.

Sessions proposed exact fields: `active`, `started`, `stop_started`,
`stopped`, `stopping`, all decimal u64 **only after** a real actor drain
boundary is demonstrated. Until then, `stopped` must be required-nullable
with an explicit unsupported capability/reason (not `0`), and no stop-duration
fact may be emitted. `stop_started` must correspond to actual StopRequested
publication, not a destructor. Session gauges are concurrent observations;
process-lifetime totals do not fall when retired sessions disappear.

## Metric and resource gate

Producer proposes 107 finite new series (36 phase + 20 outcome + 8
pending/age + 4 completeness + 32 failure + 2 proposal + 5 session), making
the provisional C01 union 214. This exceeds C01's **profile cap 128** despite
remaining below R4's global 2048. The existing fixed CoreRegistry has 64
reserved slots and an empty production approved-name list. Freeze a revised
manifest with exact tuples, HELP/TYPE, 214-or-recomputed series, explicit
profile cap, fixed tuple handles and bounded memory before metrics are enabled.
No hot-path registration/dynamic labels. The <568 KiB native extension is a
proposal subject to static size assertions and bounded work evidence; it is
not a measured whole-process 4 MiB or 1%/3% result.

## Decisions needed before freeze

1. **Replay terminal loss:** current proposed replay rows have phases/pending
   only. A failed/cancelled replay must either have exact finite terminal/error
   accounting or latch incomplete; it cannot disappear as a successful replay.
2. **Lifecycle:** prove SpawnsWith actor drain/stop-event boundary in native
   tests, or publish `stopped=null` with explicit reason. Bus destruction alone
   is insufficient. Decide whether contexts may be removed before a verified
   stop while retaining process-lifetime totals.
3. **Scope and capabilities:** approve the exact scope mapping and finite
   capability status/reason literals, including what is genuinely supported
   by this native candidate. No Rust consumer should infer it from loose text.
4. **Incomplete and concurrency:** approve per-action/global reason propagation,
   null oldest-age rules, and fixed V2 sampling policy. Validate that a full
   bank, dropped tracking or post-retirement phase cannot yield complete/green.
5. **Metric gate:** approve the revised fixed tuple allowlist/profile cap and
   bounded registry implementation; no inherited scalar array masquerading
   as a registered C01 metric.

## Reconciliation against Starbridge's exact draft

The new schema correctly fixes four action rows by tuple position, closed
nested phase maps, replay signed-record/intent-only stage sets, fixed finite
capability names/reasons, required-nullable oldest ages, and at most eight
contexts. It also introduces `post_terminal_progress` and
`retired_requests`, both exact process-wide u64 counters, matching the
supervisor's bounded-retirement ruling. The synthetic all-zero sample is
legitimate as a shape fixture only, not proof of real hooks or draining.

Remaining exact mismatches to settle in the freeze:

- The draft has no per-action/global `incomplete_reasons`. A false boolean
  cannot distinguish ledger exhaustion, pending age loss, context failure or
  retirement ambiguity. Add the bounded finite reason lists above or freeze
  an equivalently closed reason-bearing quality structure; define whether
  `post_terminal_progress>0` forces the affected action incomplete.
- Replay subrows still have only phases/pending/age. A replay that errors or
  cancels after `requested` needs a truthful terminal/error population or an
  explicit incomplete latch. The present schema alone cannot distinguish it
  from a still-pending or silently disappeared operation.
- The draft requires numeric `sessions.stopped` and advertises supported
  `session_lifecycle`; this is contingent on actual actor drain proof. Until
  then use null/unsupported, not a synthetic zero. `scope` currently always
  has workchain/shard but permits `scope_id:null`; define that as an explicit
  unscoped observation, or make the entire scope null. Never treat it as
  masterchain or node-scoped consensus evidence.
- The draft allows arbitrary booleans for `enabled`, `contract_valid` and
  `performance_gate` even when `supported=false`, and its synthetic positive
  capabilities are `supported=true,enabled=true,contract_valid=false` with
  `reason=null`. Freeze the truth table: an unsupported or invalid capability
  must not become a usable C04 rule input. A successful syntactic schema check
  does not establish `contract_valid=true` or production performance.
- The schema's decimal pattern/maxLength permits values greater than
  `u64::MAX` and its context shard does likewise. Require exact checked u64
  decoding in Rust and native tests for `18446744073709551615` accepted and
  `18446744073709551616` refused; canonical leading-zero negatives too.
- Schema shape does not bind context network to payload network, uniqueness
  of `(network,scope,session)`, active/stopping timestamp relation, or global
  versus per-action completeness. Enforce these semantic relations in the
  strict DTO validator and test actual producer pairs after freeze.

After freeze, Rust tests should consume **actual producer bytes** and exercise
positive pairs plus unknown/extra fields, invalid enum/phase/context,
noncanonical/overflow u64, hash/EOF/generation mismatch, capacity exhaustion,
incomplete accounting, disabled/null, v1 coexistence and epoch switch. No
publisher or Rust wire changes have been made for this review.
