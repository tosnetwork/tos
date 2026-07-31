# AI Actor Operations Runbook

This runbook describes the minimum operational posture for running AI actor infrastructure on TOS.

It covers off-chain agent runners, model or tool service operators,
[AI Edge Computing Terminal](ai-edge-computing-terminal-architecture.md)
operators, verifier operators, and task workflow backends.
It also covers operators of TOS ARD Registry instances and catalog gateways
defined by [tos-ard-compatibility.md](tos-ard-compatibility.md).

The operational target is an Agent Wallet stack: Agent Account contracts,
controller keys, off-chain runners, Service Actors and Verifier Actors. An AI
terminal is a separately deployed service runtime; it is not a validator and
must use a revocable runtime key rather than the owner or unrestricted wallet
key.

## Node Access

Recommended trust tiers:

- use a local full node for agents that control material funds
- use proof-backed reads for lightweight agents where available
- use trusted RPC only for low-value automation or development
- use indexed data for discovery and dashboards, not authority

ARD search results are indexed discovery data. Before payment or invocation,
clients revalidate the publisher, current TOS descriptor, endpoint
authorization, chain commitments, live quote, admission, and payment
destination.

## Key Separation

Operators should keep these keys separate:

- validator keys
- node control keys
- agent owner keys
- agent controller keys
- service signing keys
- verifier decision keys
- terminal runtime keys
- fleet/site administration keys
- update and model-package signing keys
- local actuator/safety authority
- API credentials for off-chain services

Agent or service workers must not run with validator keyring access.
Terminal runtime, update, fleet, payment, and actuator keys must not be
interchangeable.

## Monitoring

Monitor:

- task acceptance latency
- result submission latency
- settlement failures
- service charge rejection rate
- verifier decision rate
- timeout and cancellation rate
- delivery failures and back-pressure records
- agent balance and spend-limit utilization
- terminal real-time deadline misses and priority preemption
- offline journal size, age, and reconnect backlog
- active/known-good model and software revisions
- update rollout ring, health gates, pause, and rollback status
- fleet enrollment, revocation, and permanently offline records
- actuator rejection, deduplication, and safety-interlock events
- ARD catalog crawl success, publisher verification, expiry, withdrawal,
  equivocation, redirect and content-size rejection
- Registry search latency, index size, per-publisher quota, stale-result age,
  federation hops/cycles, cache/queue/retry bounds, and provenance coverage
- denied SSRF targets, private-catalog access, prompt-injection indicators,
  and visibility-policy violations

## ARD Registry Operation

Run an ARD Registry as a separate least-privilege service, not inside
`validator-engine` and not with validator, owner, terminal, payment, update,
fleet, or actuator keys.

An operator should:

1. pin the exact supported ARD version and publish its compatibility status
2. allowlist schemes, ports, redirect behavior and reachable address classes
   and recheck resolved targets against DNS rebinding
3. configure hard limits for catalog bytes, decompression, entries, fields,
   references, recursion, federation hops, cycles, response time, retries,
   cache, index size, retention, and each publisher
4. keep public, private and tenant catalogs in separately authorized
   visibility domains
5. preserve field-level publisher, chain, observation, attestation, and
   derived-ranking provenance
6. support bounded expiry, withdrawal, revalidation, rollback and equivocation
   handling
7. back up configuration and rebuildable source state without treating the
   derived search index as settlement authority
8. test graceful restart, corrupt-index recovery, upstream outage and
   federation isolation

The Registry may be unavailable without stopping admitted terminal work,
physical safety functions, blockchain consensus, or settlement of already
identified operations.

## Incident Response

If an agent behaves unexpectedly:

1. revoke or rotate the controller key
2. stop the off-chain worker
3. inspect recent task and service messages
4. check outstanding escrow exposure
5. settle, cancel, or dispute affected tasks according to policy
6. publish an operator note if public users are affected

If a service actor overcharges or emits bad results:

1. disable the service endpoint off-chain
2. rotate service signing keys if needed
3. reject pending charges that exceed policy
4. dispute affected tasks
5. update service metadata or registry status

If a site-bound physical terminal or update behaves unexpectedly:

1. preserve local safety and control; do not depend on chain connectivity
2. disable external admission without stopping required local workloads
3. engage the independent safety controller or site emergency procedure
4. pause the fleet rollout and prevent further activation
5. roll back to the known-good model/runtime/policy slot
6. revoke the affected terminal/runtime/update authority at the narrowest scope
7. preserve bounded signed audit and offline-journal evidence
8. reconcile payment only after reconnect state and revocation are verified

If an ARD catalog, gateway, or Registry is compromised:

1. stop new crawling and federation without interrupting admitted work
2. quarantine the publisher, peer, tenant, or affected provenance class
3. withdraw or mark affected results stale rather than silently rewriting
   their origin
4. rotate Registry/gateway credentials that are actually affected; do not
   rotate unrelated TOS owner or validator keys
5. rebuild the derived index from verified catalogs and bounded source state
6. require clients to refresh descriptors, quotes and payment bindings
7. publish the affected time, scope, identities and remediation

## Deployment Checklist

- local testnet run completed
- task escrow tests passed
- agent account tests passed
- service actor tests passed, if applicable
- verifier actor tests passed, if applicable
- transaction history reconstruction tested
- key backup and rotation procedure documented
- emergency stop or revoke path tested
- ARD publisher and Registry releases pass pinned-version conformance,
  provenance, withdrawal, SSRF/DNS-rebinding, prompt-injection, federation,
  private-visibility, restart and bounded-state tests
- physical-terminal releases test disconnected local operation, bounded
  reconnect, signed update rollback under power loss, real-time priority,
  actuator isolation, and fleet-scale bounded state
