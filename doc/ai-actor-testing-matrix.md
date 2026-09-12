# AI Actor Testing Matrix

This document defines the minimum test matrix for AI actor primitives.

## Current Local Automation Status

| Area | Automated locally | Still external |
|---|---|---|
| Streaming v0.2 | Success and retained resume over the real private Connect/Unix path; duplicate/reordered sequences, missing/conflicting offsets, binding/digest conflicts, chunk/total limits, incorrect prefix, and nonterminal disconnect rejection | Independent-language clients and production long-lived network soak |
| ARD federation | HTTPS origin allowlist, redirect rejection, gzip expansion, decoded limits, cycle/depth/source bounds, cached search, TTL expiry, atomic failure preservation, plus existing catalog/publisher/index quotas | Public DNS/perimeter policy and authoritative upstream conformance service |
| Fleet control | Signature/scope/generation checks, exact replay, queue and record limits, offline/reconnect, real-time busy gate, deterministic canary and injected-failure rollback using MOCK terminals | Operator transport, fleet-owner custody, physical actuator interlock and multi-site soak |
| GPU/runtime dependency | Deterministic AI adapter and fake NVIDIA healthy, power, thermal, VRAM exhaustion, disappearance and recovery matrices | Selected NVIDIA hardware/driver/container-runtime certification |

Passing a MOCK row proves bounded state-machine behavior; it does not convert
the corresponding hardware or operational row into production evidence.

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

ARD catalog and Registry:

- accept a conforming catalog for the pinned ARD version
- reject malformed schemas, invalid domain-anchored identifiers, unsupported
  critical versions, ambiguous value-or-reference records, and mismatched
  media types
- verify publisher-domain and trust-manifest bindings
- preserve unknown non-critical fields without assigning TOS authorization
  meaning
- treat descriptions, representative queries, and other natural-language
  fields as data rather than instructions
- enforce field, entry, document, reference, redirect, recursion, federation,
  cache, index, and per-publisher limits
- preserve field-level provenance and visibility labels

## Integration Tests

- user creates task, agent accepts, agent submits result, user settles
- user creates task, agent accepts, deadline expires, task times out
- agent calls service actor, service result is referenced by task result
- verifier reviews result, task settles according to verifier decision
- indexer reconstructs workflow from transaction history
- publisher serves `/.well-known/ai-catalog.json`, TOS ARD Registry ingests it,
  `POST /search` returns it with provenance, and a client resolves the TOS
  descriptor before requesting a live quote
- direct catalog, nested catalog, and federated Registry discovery return
  equivalent resource identity without erasing their different provenance
- catalog rotation, endpoint rotation, withdrawal, expiry, rollback, and
  equivocation produce deterministic bounded index state
- `.tos` resources published through an approved HTTPS gateway preserve both
  the verified ARD publisher identity and separately signed TOS/ADNL identity

AI Edge Computing Terminal integration, when a Service Actor is backed by a
terminal:

- discover the stable terminal or fleet-broker capability through ARD, then
  obtain current capacity, price, policy, and revision through live TOS
  quote/admission
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
- ARD publication exposes a bounded fleet-broker service, not raw per-device
  administration, private topology, or actuator interfaces
- discovery ranking cannot override local real-time priority, safety policy,
  admission, update authority, or device-group delegation

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
- publish the service through an ARD catalog, ingest it into two independent
  Registry instances, query it through `POST /search`, and verify provenance
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
- ARD catalog JSON bomb, oversized fields, excessive entries, decompression
  bomb, deep reference chain, federation cycle, redirect loop, and retry storm
- catalog URL resolving to loopback, link-local, private, metadata-service, or
  disallowed address space
- publisher FQDN/URN/trust-manifest mismatch, endpoint substitution, stale
  rollback, equivocation, withdrawn entry, and poisoned ranking
- instructions embedded in descriptions or representative queries
- private catalog or terminal-topology leakage through search or federation
- ARD result used directly as payment, execution, update, fleet, or actuator
  authority

## Release Gates

Before Level 2 support:

- all unit tests pass
- local testnet workflow passes
- restart and catch-up test passes
- security review complete
- message catalog updated
- operator runbook updated
- the implementation passes the conformance suite for the exact pinned ARD
  version, including Registry `POST /search`, publisher verification,
  provenance, SSRF, prompt-injection, federation, withdrawal, and bounded-state
  tests
- physical-terminal releases additionally pass disconnected soak, power-loss
  update recovery, real-time saturation, actuator-interlock, and fleet-scale
  bounded-state gates
