# AI Actor Operations Runbook

This runbook describes the minimum operational posture for running AI actor infrastructure on TOS.

It covers off-chain agent runners, model or tool service operators,
[AI Edge Computing Terminal](ai-edge-computing-terminal-architecture.md)
operators, verifier operators, and task workflow backends.

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

## Deployment Checklist

- local testnet run completed
- task escrow tests passed
- agent account tests passed
- service actor tests passed, if applicable
- verifier actor tests passed, if applicable
- transaction history reconstruction tested
- key backup and rotation procedure documented
- emergency stop or revoke path tested
- physical-terminal releases test disconnected local operation, bounded
  reconnect, signed update rollback under power loss, real-time priority,
  actuator isolation, and fleet-scale bounded state
