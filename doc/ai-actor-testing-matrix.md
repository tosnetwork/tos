# AI Actor Testing Matrix

This document defines the minimum test matrix for AI actor primitives.

## Unit Tests

Agent account:

- owner updates controller
- non-owner cannot update controller
- controller can accept allowed task
- controller cannot exceed spending limit
- expired delegation fails

Task escrow:

- create task with budget
- accept open task
- reject duplicate accept
- submit result from assigned agent
- reject result from unassigned agent
- settle accepted result
- reject duplicate settlement
- cancel open task
- timeout overdue task
- dispute submitted result

Service actor:

- quote service price
- authorize service call
- reject unauthorized service call
- reject over-budget charge
- bind result hash to request hash

Verifier actor:

- submit accept decision
- submit reject decision
- reject unauthorized verifier
- bind decision to task id and result hash

## Integration Tests

- user creates task, agent accepts, agent submits result, user settles
- user creates task, agent accepts, deadline expires, task times out
- agent calls service actor, service result is referenced by task result
- verifier reviews result, task settles according to verifier decision
- indexer reconstructs workflow from transaction history

AI Edge Computing Terminal integration, when a Service Actor is backed by a
terminal:

- bind terminal quote, payment authorization, invocation, receipt, and
  settlement to one request identity
- reject a quote for an expired model/service revision
- reject work before payment or local admission
- preserve owner-reserved capacity
- cancel and release queue, RAM, VRAM, KV cache, and temporary files
- normalize adapter crash, OOM, timeout, and disconnect paths
- restart without duplicate execution or lost refund/settlement state
- rotate runtime key, model, endpoint, and price without changing active
  quotes
- distinguish declared claims from benchmarked, audited, or attested claims
- demonstrate bounded memory, disk, queues, watchers, caches, and journal
  growth under anonymous-load and fault-injection soak

The complete off-chain matrix belongs to the
[AI Edge Computing Terminal architecture](ai-edge-computing-terminal-architecture.md)
and `tos-ai` conformance suite. These tests supplement rather than replace
native contract tests.

### Site-bound physical terminal

Real-time priority and safety:

- emergency and safety work preempts every lower priority
- external saturation cannot cause a control or perception deadline miss
- OOM, thermal pressure, model download, telemetry, and compaction reject or
  pause lower-priority work first
- TOS networking and settlement are absent from the hard real-time loop
- public APIs expose no raw CAN, GPIO, serial, fieldbus, camera
  administration, container socket, or accelerator handle
- a valid network capability cannot bypass an independent safety interlock
- semantic actuator requests enforce state/rate/deadline/value constraints,
  idempotency, and local audit

Offline and reconnect:

- approved local inference continues without TOS connectivity
- operations requiring fresh chain state fail closed
- cached offline authority enforces value, quantity, age, and expiry
- journal bytes, entries, age, receipts, retries, and compaction stay bounded
- reconnect observes key/policy/model/terminal revocation before new admission
- event, action, voucher, receipt, and settlement reconciliation is idempotent
- expired queued requests and acknowledged journal segments are removed with
  bounded work

Model, runtime, firmware, and policy updates:

- reject wrong signer, hash, target, dependency, compatibility, authority, and
  security revision
- reject truncated, oversized, replayed, and rollback-incompatible packages
- power loss at download, verification, staging, activation, health check, and
  commit preserves an active or known-good slot
- lab/canary/cohort rollout advances only after explicit health gates
- crash, deadline, memory, thermal, and accuracy gates pause and roll back
- active quotes and receipts preserve the selected model/runtime/policy
  revision
- staging bytes, retained versions, logs, retry work, and history stay bounded

Fleet:

- enroll and revoke one terminal without affecting peer authority
- site administrator cannot escalate to fleet owner
- runtime, update, model, payment, and actuator keys are non-interchangeable
- groups, pagination, fan-out, retries, watchers, offline records, and history
  remain bounded at fleet scale
- permanently offline terminals expire from active health
- aggregate discovery/health does not expose prohibited site topology or
  personal/sensor data
- mixed-version fleet can pause, drain, roll back, and retire safely

The normative use case is
[Site-Bound Physical AI Edge Terminal](physical-ai-edge-terminal-use-case.md).

## Local Testnet Tests

- deploy task and agent contracts on wc=0
- run workflow through validator JSON-RPC
- restart one validator during task lifecycle
- stop one validator long enough to catch up
- verify transaction history after catch-up
- verify no additional execution domains are registered
- bind a physical terminal to raw ADNL and optionally `name.tos`
- complete online event/subscription payment and receipt
- disconnect the terminal while local work continues
- reconnect and settle a bounded offline journal exactly once
- rotate runtime/update authority and reject the old authority
- restart validators without affecting local safety execution

## Negative Tests

- malformed opcode
- malformed body
- wrong `query_id`
- replayed message
- wrong sender
- wrong task id
- insufficient value
- expired capability
- service charge above maximum
- settlement without result

## Release Gates

Before Level 2 support:

- all unit tests pass
- local testnet workflow passes
- restart and catch-up test passes
- security review complete
- message catalog updated
- operator runbook updated
- physical-terminal releases additionally pass disconnected soak, power-loss
  update recovery, real-time saturation, actuator-interlock, and fleet-scale
  bounded-state gates
