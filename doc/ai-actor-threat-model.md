# AI Actor Threat Model

This document defines the baseline threat model for AI actor workflows on TOS.

It applies to agent accounts, task actors, service actors, verifier actors, workflow indexers, and off-chain agent runners that interact with native TVM contracts.

## Assets

- task escrow balances
- agent account balances
- service actor payment streams
- owner and controller keys
- delegated agent permissions
- task state and settlement decisions
- result metadata and evidence references
- verifier decisions and reputation inputs

## Trust Boundaries

- Chain state is authoritative for balances, permissions, task status, deadlines, and settlement.
- Off-chain agent runners are not trusted by default.
- Service endpoints are not trusted by default.
- Indexers and workflow dashboards provide derived views only.
- Evidence references are claims until verified by a verifier actor, proof adapter, signature check, or trusted policy.

## Primary Threats

### Permission Escalation

An agent, session, or service gains owner-equivalent authority without an explicit grant.

Required controls:

- bounded delegation
- explicit spending limits
- separate owner, controller, fee payer, service, and verifier roles
- inspectable permission state

### Owner and Controller Key Confusion

An off-chain agent runtime obtains the Agent Wallet owner key, or an operator mistakes a
controller-authorized action for an unrestricted owner-authorized wallet transfer.

Required controls:

- keep the Agent Wallet owner key in the operator-controlled vault and never export it to the
  agent runtime
- use the controller key only through Agent Account messages that enforce sequence numbers,
  expiry, per-action limits, and daily limits on-chain
- require `tosctl agent wallet send` to use the owner key and explicit operator confirmation
- do not allow `tosctl agent wallet send` to accept controller signatures or runtime manifests
- reserve owner-authorized transfers for manual treasury maintenance, refunds, emergency
  withdrawals, and agent retirement
- route automated task and service spending through the policy-enforced Agent Account path

### Escrow Theft

A task actor releases funds to the wrong party or releases funds before the required result or verification state exists.

Required controls:

- explicit task state machine
- sender checks on settlement messages
- deterministic timeout behavior
- payout amounts derived from escrow state

### Replay and Cross-Domain Confusion

A valid message or capability grant is replayed against another task, deployment, chain, or service actor.

Required controls:

- `query_id` correlation
- task id in lifecycle messages
- replay domain in capability constraints
- global id and address binding in signed payloads where applicable

### Service Overcharging

A service actor charges without an authorized request or charges more than the task budget allows.

Required controls:

- service-call authorization tied to task state
- max-value constraints
- signed or hash-referenced service responses
- settlement checks against verified chain state

### Fake Results or Evidence

An agent submits a result hash, transcript, or evidence reference that is not connected to the requested task.

Required controls:

- result metadata hash bound to task id
- optional verifier actor decision
- evidence reference hash
- result acceptance rules visible from contract state

### Indexer Authority Drift

Clients treat derived workflow timelines or reputation data as authoritative for spending or settlement.

Required controls:

- trust-tier labeling
- node-verified checks for balances and permissions
- clear distinction between indexed views and contract state

### Message Amplification

Retries, supervision, scheduled messages, or back-pressure responses create unbounded traffic.

Required controls:

- funded retries
- bounded scheduled-message queues
- restart intensity limits
- delivery-SLA failure records
- explicit backoff guidance

## Minimum Review Before Production

Every production AI actor primitive should receive review for:

- authorization and role separation
- replay domains
- escrow accounting
- timeout and cancellation paths
- service-call payment limits
- evidence and verifier semantics
- indexer trust boundaries
- denial-of-service and message amplification
- local testnet restart and catch-up behavior
