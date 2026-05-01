# TOS Delivery SLA and Dead-Letter Policy RFC

## 0. Status and scope

**Status.** Draft v0.1, 2026-05-01. Companion RFC for Slice 6 Stage 0.

This document defines the delivery-failure substrate required before
scheduled messages, supervision, monitor notifications, or active
`ErrorClass.BackPressure` semantics can safely ship.

## 1. First principles

TOS already has message delivery, bounces, and application-level
`OP_ERROR`. What it does not have is a consensus-visible answer to:
"this message could not be delivered within the promised resource and
time budget; who is told, who pays, and what may retry?"

The answer must be protocol-level because delivery can fail before the
destination contract executes. A stdlib cannot observe every cross-shard
import delay, frozen recipient, deleted account, or expired scheduled
message.

## 2. Failure classes

Delivery failure records must map into the existing `ErrorClass`
taxonomy without overloading application errors:

| Class | Meaning | Retry |
|---|---|---|
| `Transient` | temporary import delay, temporary shard queue pressure | yes, with backoff |
| `Permanent` | destination deleted without bounce path, invalid address, permanently frozen target | no |
| `Protocol` | malformed envelope or protocol-level rejection | no |
| `BackPressure` | delivery accepted but current queue/resource pressure says sender should slow down | yes, with explicit backoff |

`BackPressure` remains reserved until this RFC is approved and the
implementation can prove that senders receive bounded retry advice
instead of a vague "try again later" signal.

## 3. Delivery identity

Every tracked delivery attempt needs a stable identity:

```
delivery_id = hash(src, dest, created_lt, value, body_hash, mode, extra_flags)
```

The exact hash input is an implementation detail for Stage 1, but it
must include enough data to distinguish two equal bodies sent in the
same block and must not require parsing application payloads.

## 4. Deadline model

The protocol should define two windows:

- `not_before`: earliest point at which delivery is valid. Ordinary
  messages have `not_before = created_at`.
- `deliver_by`: latest point at which the delivery attempt may remain
  pending before a failure record is produced.

For ordinary messages, `deliver_by` is derived from config defaults and
possibly sender-provided mode bits once those are defined. For scheduled
messages, `deliver_by` is derived from `not_before + fairness_window`.

No contract should be promised exact delivery at a specific timestamp.

## 5. Dead-letter routing

On expiry or permanent delivery failure, the protocol routes a bounded
record to one of:

1. the sender's bounce path, if the sender still exists and escrow covers
   delivery;
2. a sender-declared dead-letter address, if declared and funded;
3. a workchain-local system dead-letter sink.

The system sink is for auditability and bounded retention, not for
application recovery. Application recovery requires an explicit bounce or
dead-letter handler.

## 6. Funding rules

The original sender funds:

- delivery attempt forwarding fee;
- bounce or dead-letter forwarding fee;
- scheduled-message storage rent, if applicable;
- diagnostic-cell storage only when explicitly requested.

If escrow is insufficient, the protocol emits the smallest possible
system-level audit record and drops optional diagnostics. It must not
mint a free failure message.

## 7. Queue-pressure metrics

Queue-pressure exposure is useful only if it cannot become a congestion
oracle for attackers. Stage 1 may expose coarse, bucketed values:

- `normal`
- `delayed`
- `congested`
- `rejecting`

It must not expose precise queue length or per-shard scheduling internals
until an information-leak review approves them.

## 8. Interaction with existing bounces

Existing Slice 1 rich bounces remain valid. Delivery-SLA failure is an
additional protocol failure path for messages that cannot reach normal
compute. If destination compute runs and throws, ordinary bounce rules
apply.

## 9. Stage 1 exit criteria

- A conformance fixture proves old contracts are unchanged when they do
  not request delivery-SLA handling.
- A delivery failure record is canonical and bounded.
- `ErrorClass.BackPressure` has a precise activation condition or stays
  reserved.
- Dead-letter routing has a named payer and bounded retention.

