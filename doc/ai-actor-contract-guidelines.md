# AI Actor Contract Guidelines

This document gives implementation guidance for the first native TVM AI actor contracts.

The initial target is not a full marketplace. The target is a minimal, testable loop: create task, accept task, submit result, settle payment, and inspect history.

## Agent Account

An agent account is the contract foundation for an AI robot wallet. It should start with:

- owner key or owner address
- controller key or controller address
- maximum spend per task
- maximum spend per time window, if supported
- capability metadata hash
- endpoint metadata hash
- allowed task categories hash
- replay domain

Required checks:

- owner-only update for controller and policy
- controller-limited execution for task actions
- no controller path to owner-equivalent authority
- all outbound value sends bounded by policy

## AI Robot Wallet Surface

The first wallet surface should be machine-facing:

- inspect current controller and owner
- inspect spend limits and remaining budget
- inspect active task ids
- inspect service-call policy
- inspect verifier policy
- build signed task and service messages

Consumer mobile features such as contacts, QR-code UX, push notifications, app-store packaging, or fiat on-ramp flows are out of scope for the first agent wallet implementation.

## Task Escrow

A task escrow contract should start with:

- creator
- assigned agent, optional until accepted
- budget
- escrow balance
- deadline policy
- result metadata hash
- evidence hash
- status enum
- settlement policy hash

Required checks:

- only open tasks can be accepted
- only assigned agent can submit a normal result
- only creator, verifier, or policy authority can settle
- payout cannot exceed escrow balance
- cancellation cannot bypass accepted work unless policy allows it
- timeout path is deterministic

## Service Actor

A service actor should start with:

- owner
- service metadata hash
- price policy hash
- accepted payment target
- public response verification key, if used
- rate-limit policy hash

Required checks:

- service call must be authorized by task or agent policy
- charge must not exceed the authorized maximum
- result hash must bind to request hash
- service metadata updates are owner-controlled and visible

## Verifier Actor

A verifier actor should start with:

- owner or committee authority
- verifier metadata hash
- supported evidence types
- decision policy hash
- optional stake or bond reference

Required checks:

- decisions bind to task id and result hash
- decision values are typed and machine-readable
- verifier authority is inspectable
- disputed decisions remain reconstructible from transaction history

## Storage Rules

- Store hashes and compact references, not large model outputs.
- Store role addresses explicitly.
- Store status as a small enum.
- Store enough data to reconstruct settlement.
- Do not depend on off-chain service availability for contract safety.

## Testing Rules

Every contract should have positive and negative tests for:

- malformed body
- unauthorized sender
- replayed message
- expired message
- out-of-phase lifecycle message
- insufficient value
- over-budget service charge
- duplicate settlement
