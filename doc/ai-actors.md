# AI Actor Model

This document defines the product and protocol direction for AI-native actor workflows and AI Agent Wallets on TOS.

TOS treats accounts, smart contracts, AI agents, tools, services, and tasks as actors. Each actor owns private state, receives asynchronous messages, emits new messages, and participates in on-chain payment and verification flows.

## Goals

- Give AI agents persistent on-chain identity, state, balances, and permissions.
- Give AI agents wallet primitives for funds, spending policy, task history, service calls, and verifier decisions.
- Make agent-to-agent and agent-to-service coordination asynchronous by default.
- Use native TVM contracts for task escrow, settlement, and workflow state.
- Keep payments, permissions, deadlines, results, and disputes inspectable from chain state.
- Allow external evidence, signatures, attestations, and proof adapters without binding the protocol to one off-chain runtime.

## Product Relationship

The AI actor model separates market trust, production capacity, and autonomous
economic decision-making:

> **`tos-protocol` establishes the trusted market, `tos-ai` supplies production
> capacity, and OpenFox lets that capacity participate autonomously in the
> market and earn revenue.**

[`OpenFox`](openfox-autonomous-earning-agent.md) is the proposed off-chain
autonomous earning agent. It discovers candidate work, matches owner-approved
skills, evaluates profit and risk, requests bounded authorization, dispatches
execution, submits results, and observes settlement. OpenFox does not make its
local view authoritative: contracts and current protocol verification remain
authoritative for identity, permission, task, escrow, and settlement state,
while the AI terminal remains authoritative for local resource admission.

This relationship is a product direction, not a claim that OpenFox or a public
end-to-end task market is already implemented.

## Actor Types

### AI Agent Wallet

An AI Agent Wallet is an agent-first wallet/account used by an autonomous agent, agent runner, automation system, or service workflow. It should expose policy, permissions, balances, task history and service-call limits in machine-readable form.

### User Actor

A user actor owns funds, creates tasks, accepts results, and defines policy for delegated agents. In the first roadmap, this is a control role for agent workflows, not the primary consumer-wallet product.

### Agent Account

An agent account is an on-chain account controlled by owner and controller keys. It is the account side of the AI Agent Wallet model. It may expose:

- owner and controller principals
- spending limits
- accepted task categories
- capability metadata hash
- service endpoint hash
- task history references
- delegation and recovery policy

### OpenFox Agent Runner

OpenFox is an off-chain Agent Runner controlled by an owner mandate and a
bounded Agent Account delegation. It is not a new on-chain contract type. A
probabilistic planner may recommend tasks and plans, but deterministic policy
must authorize every acceptance, spend, privileged tool call, and signature.
The owner key remains outside OpenFox and `tos-ai-worker`.

OpenFox may use an owner-approved `tos-ai` terminal as production capacity.
It cannot bypass terminal admission, select administrator-owned runtime
endpoints, install task-supplied programs or models, or convert a discovery
record into payment authority.

### Task Actor

A task actor represents a unit of work. It holds task state and may hold escrowed funds.

Minimal task state should include:

- creator
- assigned agent, if any
- budget
- deadline
- status
- result metadata hash
- settlement policy

### Service Actor

A service actor represents a model provider, data provider, tool provider, compute endpoint, or verifier.

Service actor state may include:

- price schedule
- rate-limit policy
- service metadata hash
- accepted payment flow
- signed response key or attestation policy

For owner-operated AI services, the off-chain implementation may be a
[TOS AI Edge Computing Terminal](ai-edge-computing-terminal-architecture.md).
The Service Actor records payment and commitment state; it does not schedule
the terminal's CPU/GPU/NPU, load models, execute inference, or prove that a
self-reported hardware claim is true. Terminal admission remains locally
authoritative and must bind its quote and receipt to the corresponding
Service Actor request. For a site-bound physical terminal, local real-time
priority and the independent safety controller remain authoritative even when
the request and payment are valid.

### Verifier Actor

A verifier actor reviews task results or external evidence. It may submit acceptance, rejection, score, or dispute messages.

## Message Lifecycle

AI actor workflows should use explicit messages instead of synchronous calls:

1. `TaskRequest`: a user actor creates or funds a task.
2. `TaskAccept`: an agent accepts the task or the task assigns an agent.
3. `TaskProgress`: an agent posts optional progress metadata.
4. `TaskResult`: an agent submits result metadata and evidence references.
5. `TaskSettle`: the task pays the agent or service actors according to policy.
6. `TaskCancel`: the creator cancels an unaccepted or expired task.
7. `TaskTimeout`: the task moves to a timeout state when deadlines pass.
8. `TaskDispute`: a reviewer or participant opens a dispute path.

Every message type should be idempotent where practical and should carry enough correlation data for off-chain workers and indexers to reconstruct the workflow.

## Minimal Message Fields

The first task lifecycle messages should use stable opcode/query_id bodies and include compact metadata references rather than large payloads.

### `TaskRequest`

- `query_id`
- creator address
- optional preferred agent
- budget in nanotomi
- deadline or timeout policy
- task metadata hash
- settlement policy hash

### `TaskAccept`

- `query_id`
- task id
- accepting agent
- accepted budget or price reference
- agent capability hash

### `TaskResult`

- `query_id`
- task id
- agent
- result metadata hash
- evidence reference hash
- optional service-call transcript hash

### `TaskSettle`

- `query_id`
- task id
- settlement decision
- payout target
- payout amount
- verifier decision hash, if present

### `TaskDispute`

- `query_id`
- task id
- disputer
- dispute reason code
- evidence reference hash

## Task State Machine

The first task actor implementation should keep a simple, auditable state machine:

```text
Open -> Accepted -> ResultSubmitted -> Settled
  |        |              |              ^
  |        |              v              |
  |        |          Disputed ----------+
  |        v
  |     Cancelled
  v
Expired
```

Rules:

- only `Open` tasks can be accepted
- only the assigned agent can submit the normal result path
- only configured authorities can accept, reject, dispute, or settle
- timeout behavior must be deterministic
- every value transfer must be derived from explicit escrow and settlement state

## Indexing and Inspection

Workflow indexers may build derived views for UX, but contracts and agents should rely on chain state for authority.

Public discovery of callable resources follows ARD as defined in
[tos-ard-compatibility.md](tos-ard-compatibility.md). An ARD catalog or Registry
result is a protocol-neutral discovery input. It does not grant a capability
handle, authorize a Service Actor call, prove current capacity, quote a price,
or determine payment or settlement. Clients resolve the selected entry to the
current signed TOS descriptor and independently verify its chain and runtime
bindings.

Useful indexed views:

- tasks by creator
- tasks by assigned agent
- pending results
- settled tasks
- disputed tasks
- service actor calls
- verifier decisions

Authoritative checks:

- task status
- escrow balance
- assigned agent
- spending limit
- settlement rule
- verifier authority

## Implementation Order

The implementation sequence is:

1. Define task lifecycle message structs and opcodes.
2. Implement the local Agent Wallet MVP in `tosctl` so operators can create profiles, fund and activate wallet addresses, manage owner/controller keys, update policy, bind runtimes and export machine-readable policies.
3. Implement the minimal native Agent Account contract, deterministic StateInit generation and deployment commands.
4. Add read-only Agent Account inspection helpers in `tosctl`, including code-hash and local-profile verification.
5. Make controller rotation and policy updates owner-signed on-chain operations with state verification.
6. Implement a minimal task escrow contract.
7. Add local tests for request, accept, result, settle, cancel, and timeout.
8. Add JSON-RPC examples or methods after the contract state model is stable.

## Engineering Readiness Checklist

Before an AI actor primitive moves beyond an example, it should satisfy:

- Message shape: opcode, `query_id`, sender authority, value semantics, and failure behavior are documented.
- State model: every state transition is explicit and rejects out-of-phase messages deterministically.
- Permission model: owner, controller, delegated agent, service, verifier, and fee payer roles are distinguishable.
- Settlement model: every payout, refund, service charge, or slash is derived from contract state.
- Timeout model: deadlines and cancellation windows are consensus-visible or explicitly off-chain and non-authoritative.
- Trust model: clients know whether they are reading node-verified state, proof-backed state, trusted RPC state, or derived indexed data.
- Indexing model: derived task timelines do not become authority for balance, permission, or settlement checks.
- Discovery model: ARD publisher identity and Registry provenance are
  preserved, and discovery never becomes authorization or settlement state.
- Operations model: local testnet validation covers restart, catch-up, and transaction-history reconstruction.
- Release model: the primitive has a declared stability level before SDKs, wallets, or services rely on it.
- Security model: spending limits, replay domains, evidence references, and service authorization have been reviewed.

## State and Evidence Boundary

TOS should not put large model outputs, private prompts, or bulky datasets directly into contract state.

Contracts should store compact references:

- content hash
- metadata hash
- signed response hash
- external evidence URI hash
- attestation hash
- reviewer decision hash

The chain remains the source of truth for permissions, funds, task state, deadlines, settlement, and evidence references.

## Security Requirements

AI actor workflows must preserve the account permission model:

- Agent permissions must not silently escalate to owner-equivalent authority.
- Spending limits must be explicit and machine-readable.
- Task escrow must have deterministic timeout and settlement paths.
- Service actors must not be able to charge without an authorized request.
- Result acceptance and dispute rules must be visible from contract state.
- External evidence must be treated as referenced evidence unless a verifier actor or proof adapter validates it.

## Near-Term Implementation

The first implementation slice should add:

- an example agent account contract
- an example task escrow contract
- task lifecycle message structs and opcodes
- `tosctl agent wallet` commands for creating, listing, showing, funding, activating, checking status, updating policy, binding runtimes, rotating controller keys, exporting policy and removing local Agent Wallet profiles
- native Agent Account get-methods for owner, controller key and policy inspection
- deterministic Agent Account StateInit generation from local Agent Wallet profiles
- native Agent Account deployment through an active configured wallet
- read-only Agent Account inspection with template and local-profile verification
- owner-signed Agent Account policy synchronization and controller rotation
- local tests for request, accept, result, settle, cancel, and timeout paths
- `tosctl` examples for creating and inspecting agent/task state

## Non-Goals

- Do not add a separate VM or execution domain for AI workloads.
- Do not make off-chain model output authoritative without on-chain acceptance or verifier policy.
- Do not store large prompts, model responses, datasets, or private credentials in contract state.
- Do not let workflow indexers decide settlement.
- Do not let agent controller keys silently become owner keys.
- Do not treat service metadata or DNS records as authorization by themselves.
- Do not replace ARD with an incompatible TOS-only general-purpose resource
  catalog or treat an ARD result as invocation, payment, update, fleet, or
  actuator authority.

## Related Documents

- [openfox-autonomous-earning-agent.md](openfox-autonomous-earning-agent.md)
- [ai-actor-glossary.md](ai-actor-glossary.md)
- [ai-actor-message-catalog.md](ai-actor-message-catalog.md)
- [ai-actor-contract-guidelines.md](ai-actor-contract-guidelines.md)
- [ai-actor-threat-model.md](ai-actor-threat-model.md)
- [ai-actor-testing-matrix.md](ai-actor-testing-matrix.md)
- [ai-actor-operations-runbook.md](ai-actor-operations-runbook.md)
- [agent-wallet-mvp.md](agent-wallet-mvp.md)
- [actor.md](actor.md)
- [tos-message-policy.md](tos-message-policy.md)
- [tos-account-permission-model.md](tos-account-permission-model.md)
- [tos-capability-policy.md](tos-capability-policy.md)
- [tos-ard-compatibility.md](tos-ard-compatibility.md)
- [tos-supervision-policy.md](tos-supervision-policy.md)
- [tos-time-policy.md](tos-time-policy.md)
