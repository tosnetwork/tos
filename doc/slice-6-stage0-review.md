# Slice 6 Stage 0 Review Verification

**Date:** 2026-05-01  
**Branch:** actor-layer  
**Reviewed commit:** ff44b4153  
**Scope:** `doc/tos-slice-6-policy.md`, `doc/tos-delivery-sla-policy.md`, `doc/tos-time-policy.md`, `doc/tos-supervision-policy.md`, `doc/tos-capability-policy.md`, `doc/roadmap.md`, `doc/tos-message-policy.md`

## Verdict

**APPROVE.**

All 18 findings from the first Slice 6 Stage 0 design review are addressed in commit `ff44b4153`. The five companion RFCs are ready for Stage 1 implementation planning. The residual risks below remain operational design concerns for later stages, but they are not blockers for Stage 1.

## Closure Table

| Finding | Severity | Disposition |
|---|---|---|
| F-001 delivery_id | BLOCKER | Closed. `delivery_id_input_v1#d601` is now consensus-normative in `tos-delivery-sla-policy.md` §3, including scheduling transaction identity and recipient-visible value semantics. |
| F-002 BackPressure payload | BLOCKER | Closed. `back_pressure_advice_v1#b601` is now defined in §2 with bucket, scope, `min_retry_after_blocks`, and `advice_valid_until`. |
| F-008 dead-letter sink | BLOCKER | Closed. §5 defines sink bounds, sender-funded records, full-sink behavior, and `dropped_count`; §6 defines force-expiry on escrow depletion. |
| F-009 queue-pressure buckets | BLOCKER | Closed. §7 defines bucket thresholds, route-bucket granularity, `BackPressureAdvice` delivery channel, and rejecting behavior. |
| F-003 bit 3 conditionality | HIGH | Closed. Supervision baseline does not activate `extra_flags` bit 3; `tos-message-policy.md` §3.4 now treats it as reserved but invalid until a later amendment. |
| F-004 time base | HIGH | Closed. `tos-time-policy.md` §2 selects masterchain seqno and documents timestamp MEV rationale. |
| F-005 deleted cancel_authority | HIGH | Closed. `tos-time-policy.md` §5/§6 specify missing/deleted cancel authority behavior and no automatic inheritance by dead-letter address. |
| F-006 non-atomic supervision recovery | HIGH | Closed. `tos-supervision-policy.md` §6 states `one_for_all` and `rest_for_one` are best-effort non-atomic sequences, with registry location and partial-failure escalation. |
| F-007 constraints_hash encoding | HIGH | Closed. `tos-capability-policy.md` §4 defines `capability_constraints_v1#c601`, includes selector in the hash, and defines wallet display minimums. |
| F-010 handle reorg stability | MEDIUM | Closed. `tos-time-policy.md` §8 defines handle as the scheduled delivery `delivery_id` and specifies orphaned/unknown/delivered/expired cancellation behavior. |
| F-011 OP_MONITOR_DOWN | MEDIUM | Closed. `OP_MONITOR_DOWN = 0x00000010` is allocated and recorded in `tos-supervision-policy.md` and `tos-message-policy.md`. |
| F-012 revocation storage | MEDIUM | Closed. `tos-capability-policy.md` §5 now requires bounded revocation storage and reject-on-over-budget semantics. |
| F-013 open questions unresolved | MEDIUM | Closed. `tos-slice-6-policy.md` §7 is now `Stage 0 review decisions` and answers all five questions. |
| F-014 deliver_by vs expire_after | LOW | Closed. `expire_after_blocks` is the wire field; `deliver_by_mc_seqno` is computed. |
| F-015 notification vs OP_ERROR | LOW | Closed. Supervision RFC says monitor notifications are not `OP_ERROR`. |
| F-016 Stage 1 exit criterion | LOW | Closed. Umbrella Stage 1 exit criterion now includes delivery id, dead-letter retention, queue-pressure channel, and BackPressure payload/deferral. |
| F-017 Undeliverable | NIT | Closed. Delivery-SLA §2 adds `Undeliverable` and maps it to `ErrorClass.Permanent` plus reason code until schema bump. |
| F-018 ConfigParam wording | NIT | Closed. Umbrella constraint 10 now references `tos-message-policy.md` §3.4 synchronized-constant procedure. |

## Residual Risks

- Validator timing influence still exists through the delivery fairness window, even with masterchain seqno scheduling. Financial contracts must document this in release and audit material.
- OTP strategy names can mislead authors unless stdlib docs keep emphasizing TOS recovery is non-atomic and message-based.
- Capability constraint encoding needs explicit version discipline in future schema changes so old grants remain interpretable.
- Queue-pressure information-leak review remains a production gate for active BackPressure emission.
- Dead-letter record timing can leak coarse cross-shard latency and should stay part of the Stage 1 threat model.
