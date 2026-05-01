# TOS Supervision Policy RFC

## 0. Status and scope

**Status.** Draft v0.2, 2026-05-01. Companion RFC for Slice 6 Stage 0
after the first design-review fix pass.

This document defines the on-chain supervision model for `actor.md`
sections 5.1, 6.3, 6.4, and 6.6. It depends on the delivery-SLA and
time RFCs for failure records, dead letters, and retry timing.

## 1. First principles

Erlang can restart a process inside one runtime. TOS cannot do that
silently. A smart contract failure is a consensus event, and any
recovery is another consensus-visible message.

Therefore TOS supervision means:

- a child declares who may observe or supervise it;
- failures produce bounded structured notifications;
- a supervisor may send funded recovery messages according to a
  declared strategy;
- restart intensity and circuit breakers stop repeated failure from
  becoming message amplification.

## 2. Failure sources

Supervision may observe:

- compute-phase exception;
- action-phase failure when surfaced by delivery/bounce rules;
- frozen account;
- rent-expired account;
- deleted account;
- delivery-SLA permanent failure;
- scheduled-message expiry when the scheduled message names a monitor or
  supervisor callback.

Ordinary application-level rejection does not automatically become a
supervision failure unless the child or sender declares it as such.

## 3. Monitors versus links

A **monitor** is one-way observation. The observer receives a bounded
DOWN-style notification when the observed actor fails. The observed
actor does not fail because the observer fails.

A **link** is a declared failure relationship. Failure may escalate or
trigger supervisor strategy. Link registration is more expensive than a
monitor.

A **supervisor relationship** is a link plus a child spec, restart
policy, budget, and recovery target.

Stage 4 does **not** activate `extra_flags` bit 3 by default. The
initial link/monitor surface uses explicit registration state and the
notification opcode below. `extra_flags` bit 3 remains reserved for a
future fast-path link tag only if a later amendment specifies the exact
bit semantics, validator behavior, mask widening, stdlib constants, and
conformance fixture changes in `doc/tos-message-policy.md` section 3.4.

## 4. Notification body

Minimum failure notification fields:

```
op: uint32 = OP_MONITOR_DOWN
query_id: uint64
observed: address
failure_class: uint8
failure_code: uint16
phase: uint8
original_message_hash: uint256?
created_at: uint64
diagnostic: Cell?
```

`OP_MONITOR_DOWN` is allocated from the protocol-defined system opcode
range in `doc/tos-message-policy.md` section 3.2. The Stage 0 draft
allocation is:

```
OP_MONITOR_DOWN = 0x00000010
```

The notification is not encoded as `OP_ERROR`. `failure_class` uses the
same numeric values as `ErrorClass` where possible, while
`failure_code` is the protocol/supervision reason code. This keeps
ordinary request/reply errors separate from observer notifications.
Diagnostics are optional and gas-charged. The notification must remain
useful without them.

## 5. Funding

Registration must name who pays for:

- monitor/link storage;
- failure notification forwarding;
- diagnostic cell inclusion;
- supervisor recovery messages;
- retry/cooldown scheduled messages.

The protocol must not generate unfunded notifications. If funding is
missing, it emits the smallest available audit record and drops optional
delivery.

## 6. Restart strategies

Supported strategies:

- `one_for_one`: recover only the failed child;
- `one_for_all`: recover all children in the supervisor group;
- `rest_for_one`: recover the failed child and later siblings in the
  declared order;
- `dynamic`: children share one child-spec template but have independent
  ids and budgets.

On-chain restart is not state mutation by validators. It is a supervisor
message such as "reinitialize", "replace code", "deploy replacement", or
"mark failed", chosen by contract code and manifests.

Unlike OTP, `one_for_all` and `rest_for_one` are **best-effort
non-atomic recovery sequences** on TOS. Each child recovery is a separate
transaction and may fail independently, especially across shards. The
supervisor's child registry is stored in supervisor contract state for
the Stage 5 baseline; a later child-registry contract requires a separate
manifest and gas/rent budget. `rest_for_one` ordering is the explicit
order of that registry, not address sort order.

If partial recovery fails, the supervisor must stop the sequence once
the failed recovery exhausts its per-child retry budget, record which
children were recovered, and emit the configured escalation/dead-letter
record. It must not continue blindly through the remaining children
after an unrecoverable intermediate failure.

## 7. Restart intensity and circuit breakers

Every supervised child spec must define:

- max restarts;
- restart window;
- cooldown;
- max recovery gas;
- max recovery value;
- escalation target;
- final failure state.

When intensity is exceeded, the supervisor must stop retrying and emit a
bounded escalation/dead-letter record. Infinite restart loops are a
protocol bug.

## 8. Tol and stdlib surface

Expected stdlib:

- `@stdlib/supervision`
- child spec structs;
- monitor/link registration helpers;
- failure notification parsers;
- restart-intensity counters;
- circuit-breaker helpers.

Expected manifest checks:

- every supervised child has an explicit budget;
- every recovery path is idempotent or has replay protection;
- every restart strategy has an escalation path;
- every failure notification handler is unknown-opcode safe.

## 9. Non-goals

- No automatic validator-side state reset.
- No global supervisor for all contracts.
- No unbounded failure logs in account state.
- No supervision of legacy contracts unless they opt in or a wrapper
  contract accepts the monitoring cost.

## 10. Exit criteria

- A monitor can receive a bounded notification under emulator tests.
- A supervisor example recovers one failed child and stops under a
  restart storm.
- `extra_flags` mask widening, if used, lands with conformance fixtures.
- If `extra_flags` bit 3 is not used, `doc/tos-message-policy.md`
  remains in the reserved-but-invalid state and monitor/link tests use
  `OP_MONITOR_DOWN`.
- Existing Slice 1-5 contracts remain valid and unchanged.
