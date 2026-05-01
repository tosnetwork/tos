# TOS Delivery SLA and Dead-Letter Policy RFC

## 0. Status and scope

**Status.** Draft v0.2, 2026-05-01. Companion RFC for Slice 6 Stage 0
after the first design-review fix pass.

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
| `Permanent` | invalid address, code rejected, or another delivery failure that cannot be retried by changing timing | no |
| `Undeliverable` | destination deleted, permanently frozen, or otherwise unavailable after the delivery window | no, unless application has an alternate target |
| `Protocol` | malformed envelope or protocol-level rejection | no |
| `BackPressure` | delivery accepted but current queue/resource pressure says sender should slow down | yes, with explicit backoff |

`Undeliverable` is represented as `ErrorClass.Permanent` plus a
delivery-failure reason code until a future schema bump adds a distinct
application-visible enum value. The name is kept here because
`actor.md` section 5.7 uses it for the protocol condition.

`BackPressure` remains reserved until senders receive this bounded retry
advice payload, either in a bounce/dead-letter diagnostic cell or in the
corresponding delivery-failure record:

```
back_pressure_advice_v1#b601
  delivery_id:uint256
  bucket:uint8              // 0 normal, 1 delayed, 2 congested, 3 rejecting
  scope:uint8               // 0 workchain-pair, 1 shard-route bucket
  min_retry_after_blocks:uint32
  advice_valid_until:uint32 // masterchain seqno
  route_hash:uint256        // hash of the coarse route bucket, not raw queue id
= BackPressureAdvice;
```

`min_retry_after_blocks` is mandatory and nonzero for buckets
`congested` and `rejecting`. A sender that retries earlier must not
receive stronger delivery guarantees than a fresh message.

The Stage 1 stdlib keeps production construction behind a runtime gate:
`slice6BackPressureAdvice(...)` throws while `BACK_PRESSURE_ACTIVATION_GATE`
is false. Tests may still validate the struct shape by constructing
`Slice6BackPressureAdviceV1` and calling `requireValid()`, but production
helpers must not emit it until the activation review flips the gate.

## 3. Delivery identity

Every tracked delivery attempt needs a stable identity:

```
delivery_id = cell_hash(delivery_id_input_v1)
```

The hash input is consensus-normative, not an implementation detail. It
is explicitly ref-packed because the full field list cannot fit in one
1023-bit TVM cell once two `MsgAddressInt` values,
`CurrencyCollection`, and several `uint256` hashes are present:

```
delivery_origin_v1$_
  origin_tx_lt:uint64
  origin_tx_hash:uint256
  origin_action_index:uint16
  attempt_kind:uint8        // 0 immediate, 1 scheduled, 2 retry,
                            // 3 monitor notification, 4 supervisor recovery
  attempt_seq:uint16        // initial attempt is 0
= DeliveryOriginV1;

delivery_route_v1$_
  src:MsgAddressInt
  dest:MsgAddressInt
  send_mode:uint16
  extra_flags:uint16
= DeliveryRouteV1;

delivery_payload_v1$_
  value:CurrencyCollection
  state_init_hash:(Maybe uint256)
  body_hash:uint256
  not_before_mc_seqno:uint32
  expire_after_blocks:uint32
= DeliveryPayloadV1;

delivery_id_input_v1#d601
  origin:^DeliveryOriginV1
  route:^DeliveryRouteV1
  payload:^DeliveryPayloadV1
= DeliveryIdInputV1;
```

`origin_tx_lt` and `origin_tx_hash` identify the transaction that
created the delivery attempt. For a scheduled message, this is the
scheduling transaction, not the later delivery transaction. `value` is
the recipient-visible `CurrencyCollection` after send-mode resolution
and before forwarding, scheduler-rent, dead-letter, or diagnostic fees
are deducted. `body_hash` is the TVM cell hash of the exact body cell
that would be delivered; no application payload parsing is required.
`state_init_hash` is `null` when no StateInit is attached.

## 4. Deadline model

The protocol should define two windows:

- `not_before`: earliest point at which delivery is valid. Ordinary
  messages have `not_before_mc_seqno` equal to the masterchain seqno
  that contains the origin transaction.
- `deliver_by`: computed latest point at which the delivery attempt may remain
  pending before a failure record is produced.

For ordinary messages, `deliver_by` is derived from config defaults and
possibly sender-provided mode bits once those are defined. For scheduled
messages, the wire/storage field is `expire_after_blocks`, and
`deliver_by_mc_seqno = not_before_mc_seqno + expire_after_blocks`.
Overflow is invalid at scheduling time.

No contract should be promised exact delivery at a specific timestamp.
Slice 6 uses masterchain seqno, not validator-provided timestamp, as the
scheduler time base; see `doc/tos-time-policy.md` section 2.

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

The workchain-local system dead-letter sink is the Slice 6 concrete
form of the "system-level dead-letter actor" named in `actor.md`
section 5.7. It is scoped per workchain so retention, rent, and full-sink
behavior can be configured without coupling all workchains to one global
queue.

The system sink is workchain-local and bounded by config:

- `max_dead_letter_records`;
- `dead_letter_retention_blocks`;
- `max_dead_letter_record_bits`;
- `max_dead_letter_record_refs`.

Every persistent sink record is paid from sender escrow. The stdlib
insertion API takes the concrete escrow coin amount and rejects records
below `min_record_escrow_coins`; a boolean "funded" flag is not a valid
storage-cost proof, and `min_record_escrow_coins = 0` is an invalid
budget. Diagnostic cells are depth-checked before any `calculateSize`
traversal; a diagnostic already at or above the configured record depth
cannot fit once wrapped in the dead-letter record value. The measured
record bit/ref counts must fit the declared storage fields before any
narrowing cast; oversize records are rejected as too large, not wrapped
into a smaller apparent budget. If escrow is insufficient, no persistent
system-sink record is created; validators may include only a
non-persistent block-local counter for observability. If the sink is
full, the protocol first removes expired records. If no slot is
available after expiry cleanup, the new persistent record is dropped and
the sink's bounded `dropped_count` is incremented. The protocol must not
evict an unexpired paid record to store a new attacker-funded record.

## 6. Funding rules

The original sender funds:

- delivery attempt forwarding fee;
- bounce or dead-letter forwarding fee;
- scheduled-message storage rent, if applicable;
- diagnostic-cell storage only when explicitly requested.

If escrow is insufficient, the protocol emits the smallest possible
system-level audit record and drops optional diagnostics. It must not
mint a free failure message.

If escrow is depleted before `deliver_by_mc_seqno`, the delivery attempt
is force-expired on the next scheduler/dead-letter sweep. It may produce
only the records/messages still covered by remaining escrow; otherwise it
is accounted through the bounded non-persistent dropped counter described
in section 5.

## 7. Queue-pressure metrics

Queue-pressure exposure is useful only if it cannot become a congestion
oracle for attackers. Stage 1 may expose coarse, bucketed values:

- `normal`: route delay is below `pressure_delayed_blocks`.
- `delayed`: route delay is at least `pressure_delayed_blocks`.
- `congested`: route delay is at least `pressure_congested_blocks` or
  the coarse route bucket is above `pressure_congested_fill_ratio`.
- `rejecting`: the route bucket is above `pressure_rejecting_fill_ratio`
  and new delivery attempts for that bucket are rejected or converted to
  a funded delivery-failure record.

The metric is computed over a coarse route bucket:
`(src_workchain, dest_workchain, route_bucket_id)`, where
`route_bucket_id` is a config-sized hash bucket, not an exact shard
queue id. The delivery channel is `BackPressureAdvice` in a funded
bounce/dead-letter diagnostic or delivery-failure record. `rejecting`
must never silently drop a funded attempt: it either rejects
synchronously before accepting escrow, or emits a funded delivery-failure
record after acceptance.

The information exposed is limited to the bucket enum and the minimum
retry delay. Precise queue length, exact shard id, and validator-local
scheduler internals remain hidden until a separate information-leak
review approves stronger observability. Even bucketed dead-letter timing
can leak coarse cross-shard latency; Stage 1 security review must treat
that timing side channel explicitly before production activation.

## 8. Interaction with existing bounces

Existing Slice 1 rich bounces remain valid. Delivery-SLA failure is an
additional protocol failure path for messages that cannot reach normal
compute. If destination compute runs and throws, ordinary bounce rules
apply.

## 9. Stage 1 exit criteria

- A conformance fixture proves old contracts are unchanged when they do
  not request delivery-SLA handling.
- A delivery failure record is canonical and bounded.
- `delivery_id_input_v1` is implemented exactly as the ref-packed shape
  specified in section 3, including stable scheduled-message ids.
- `ErrorClass.BackPressure` emits only with `BackPressureAdvice` from
  section 2, or stays reserved behind an explicit gate.
- Dead-letter routing has a named payer and bounded retention.
- Queue-pressure bucket thresholds, route-bucket granularity, and
  information-leak review are recorded before production activation.
