# TOS Roadmap

## Vision

The Open System (TOS) is an actor-model blockchain for autonomous AI agents and agent-first wallets.

TOS treats accounts, smart contracts, AI agents, tools, services and tasks as independent actors. Each actor owns private state, receives asynchronous messages, emits new messages, and participates in native on-chain payment and verification flows.

The goal is to make TOS a practical execution and coordination layer for AI-native applications:

- AI Agent Wallets that hold funds, permissions, task history and service-call policy
- independent agents with persistent on-chain identity and state
- asynchronous agent-to-agent and agent-to-service workflows
- verifiable task execution, settlement and reputation
- native payments for model calls, data access, tools and compute
- scalable coordination through message-driven execution and sharding

## Design Principles

- Agent-wallet first: wallet primitives should serve autonomous agents and automation systems before consumer mobile wallet UX.
- Actor first: every account, agent, task and service should map naturally to an independent actor.
- Asynchronous by default: workflows should use messages, callbacks, retries and timeouts instead of synchronous blocking calls.
- Native execution focus: the core protocol should stay centered on the native TVM execution layer.
- Verifiable coordination: tasks, results, payments, disputes and reputation should be auditable.
- Agent economy ready: agents should be able to hold funds, pay for services, receive rewards and operate under explicit spending policies.
- Modular proof support: the protocol should allow external evidence, signatures, attestations and other proof adapters without hard-coding one verification backend.

## Architecture Direction

### Agent Accounts

Introduce an agent-oriented wallet/account model on top of native contracts.

Agent wallets should be able to express:

- owner and controller keys
- spending limits and execution policies
- capability metadata
- service endpoints or off-chain worker references
- task history and reputation references
- recoverability and delegation rules

### Agent Messaging

Standardize message formats for AI workflows.

The protocol should support:

- task request messages
- task acceptance and rejection
- partial progress updates
- result submission
- callback messages
- timeout and cancellation messages
- settlement and dispute messages

### Task Contracts

Build native task contracts for agent work.

Initial task contracts should support:

- task creation with budget and deadline
- agent assignment or open bidding
- escrowed payment
- result submission
- acceptance, rejection and dispute windows
- payout and slashing hooks

### Capability Registry

Create an on-chain registry for agent and service capabilities.

The registry should track:

- agent identity
- supported task categories
- pricing model
- service-level metadata
- staking or bond requirements
- reputation references
- verification methods

### Service Actors

Represent model providers, data providers, tools, or compute services as actors.

Service actors should provide:

- pricing and rate limits
- access policy
- payment settlement
- signed response metadata
- optional proof or attestation references

### Verifiable Workflows

Support workflows where multiple actors coordinate around a result.

Examples:

- one user actor delegates a task to a planner agent
- the planner splits work across specialized agents
- agents call model, data and tool service actors
- validators or reviewers submit verification messages
- the task contract settles payment based on policy

## Phases

### Phase 1: Native AI Actor Positioning

- Keep the node focused on native TVM execution.
- Document the actor-model execution semantics for AI use cases.
- Define base terminology for agent accounts, task actors, service actors and workflow messages.
- Provide example contracts that model simple agent tasks and escrowed payments.
- Keep README, BUILD and operator docs aligned with the AI actor direction.

### Phase 2: Agent Account and Task Primitives

- Implement reusable smart-contract templates for agent wallets and agent accounts.
- Ship the first `tosctl agent wallet` MVP for local profile creation, funding, activation, controller keys, runtime binding, policy updates, removal and policy inspection.
- Add the first native Agent Account contract template with owner/controller/policy state.
- Implement task escrow contracts with deadlines, result submission and settlement.
- Add SDK helpers for creating agent accounts and task contracts.
- Add JSON-RPC flows for task discovery, task state and agent account inspection.
- Add integration tests for agent-to-agent task messages.

### Phase 3: Agent Registry and Service Marketplace

- Add a capability registry contract.
- Support agent registration, metadata updates, staking and reputation references.
- Add service actor templates for model, data and tool providers.
- Add native payment flows for per-call or per-task settlement.
- Provide `tosctl` commands for registering agents, posting tasks and inspecting service actors.

### Phase 4: Verifiable AI Workflows

- Add proof adapter interfaces for signed results, attestations and external evidence.
- Support reviewer or verifier actors for task acceptance policies.
- Add dispute contracts for contested results.
- Add workflow examples that compose planner, worker, service and verifier actors.
- Publish reference schemas for result metadata and evidence bundles.

### Phase 5: Scalable Agent Economy

- Optimize message throughput for high-volume agent workflows.
- Improve shard-aware task routing and actor placement.
- Add reputation aggregation and risk scoring primitives.
- Add monitoring and analytics for agent activity, task settlement and service usage.
- Prepare long-running agent operations with robust retry, timeout and recovery patterns.

## Near-Term Engineering Tasks

- Add `doc/ai-actors.md` to describe the actor-model architecture for AI agents.
- Add `doc/agent-wallet-mvp.md` to define the first local Agent Wallet slice.
- Add example task and Agent Account contracts under the native smart-contract tree.
- Extend `tosctl` from local Agent Wallet profiles toward deploy and task commands.
- Add JSON-RPC endpoints or examples for querying agent and task state.
- Add tests that cover asynchronous task lifecycle messages.
- Keep scans in CI to prevent removed execution domains from reappearing.

## Non-Goals

- TOS should not become a collection of unrelated virtual machines.
- TOS should not depend on synchronous request-response execution for core agent workflows.
- TOS should not hard-code one model provider, proof system, oracle or off-chain runtime.
- TOS should not make AI execution opaque; task state, payments and verification metadata should remain inspectable.
- TOS should not optimize its first wallet roadmap around ordinary consumer Android or iOS wallets.
