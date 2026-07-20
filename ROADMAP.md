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
- Add `tosctl agent account build-state` for deterministic Agent Account StateInit generation.
- Add `tosctl agent account deploy` to deploy deterministic Agent Account state through a configured funding wallet.
- Add `tosctl agent account show/status` for get-method inspection and local-profile verification.
- Add owner-signed Agent Account policy updates and controller rotation with post-transaction verification.
- Add `tosctl agent wallet send` for owner-authorized transfers from the underlying Agent Wallet;
  automated agent spending must continue through Agent Account policy enforcement.
- Implement task escrow contracts with deadlines, result submission and settlement.
- Add SDK helpers for creating agent accounts and task contracts: the `contracts`
  crate (`tosctl/src/node-control/contracts`) is a transport-agnostic Rust SDK --
  deterministic StateInit/deploy-data construction, operation-message builders and
  get-method decoding for every native AI-actor contract, usable independent of the
  `tosctl` CLI. See its crate-level docs and
  `examples/agent_sdk_walkthrough.rs` (`cargo run --example agent_sdk_walkthrough -p
  contracts`) for an end-to-end construction walkthrough with no CLI or network
  dependency.
- Add JSON-RPC flows for task discovery, task state and agent account inspection.
- Add integration tests for agent-to-agent task messages.
- Add authenticated HTTP query endpoints (`GET /agents/{address}`, `GET /tasks/{address}`,
  `GET /tasks`) to `tosctld` for inspecting Agent Account and Task Escrow state, with
  status/creator/agent/deadline filters, bounded-concurrency chain reads, per-query timeouts,
  and a stable structured error taxonomy (`invalid_request`, `not_found`, `rpc_unavailable`,
  `invalid_contract_state`, `timeout`). `GET /tasks` enumerates tasks registered in the
  querying node's local `tosctld` configuration only — it is not a chain-wide contract index;
  that requires the Phase 3 capability registry / indexer below.

### Phase 3: Agent Registry and Service Marketplace

- Add a capability registry contract: one deployed instance per registered agent/service
  (the same per-actor pattern as Agent Account and Task Escrow), tracking owner, an optional
  verifier role, task-category/pricing/metadata/verification-method hashes, a stakeable bond,
  and an accumulating signed reputation score, with an active/inactive lifecycle.
- Support agent registration, metadata updates, staking and reputation references: owner-signed
  metadata updates and verifier rotation, permissionless staking, owner-gated bond withdrawal,
  verifier-gated reputation deltas, deactivate (refunds the bond) and reactivate.
- Provide `tosctl agent registry deploy/ls/show/send/build-state` commands for registering
  agents and inspecting registry entries (`send --operation` covers update-metadata,
  update-verifier, stake, withdraw-bond, update-reputation, deactivate, reactivate).
- Add service actor templates for model, data and tool providers: one deployed instance per
  service (same per-actor pattern), tracking owner, an access policy (open or a single
  authorized caller), price-per-call, a daily rate limit, accumulated revenue, signed
  response-hash commitments, and an optional proof/attestation-scheme reference, with the
  same active/inactive lifecycle as the capability registry.
- Add native payment flows for per-call settlement: `call` requires the message value to
  cover `price_per_call` and credits it to on-chain revenue; the owner commits a response
  hash via `respond` and withdraws accumulated revenue via `withdraw-revenue`. Per-task
  settlement already exists via Task Escrow (Phase 2).
- Provide `tosctl agent service deploy/ls/show/send/build-state` commands for registering
  services and inspecting them (`send --operation` covers call, respond, update-policy,
  withdraw-revenue, deactivate, reactivate).
- `GET /tasks`'s "local registry only" limitation (see Phase 2) is not yet resolved by an
  indexer; the capability registry and service actor above are per-agent/per-service
  lookups, not a chain-wide index either.

### Phase 4: Verifiable AI Workflows

- Add dispute contracts for contested results: a standalone reviewer/arbitrator actor (one
  deployed instance per case, same per-actor pattern as the other native contracts),
  independent of Task Escrow's existing built-in single-verifier resolve path. Records a
  subject reference, claimant/respondent evidence hashes, and a reviewer ruling (claimant,
  respondent, or a basis-point split), with `tosctl agent dispute deploy/ls/show/send`. It is
  a pure adjudication ledger -- it does not hold or move funds; the subject contract's own
  settlement logic must act on the ruling.
- Support reviewer or verifier actors for task acceptance policies: the Dispute contract's
  reviewer role above covers this for contested results; Task Escrow's existing verifier role
  (Phase 2) already covers uncontested settlement authority.
- Add proof adapter interfaces for signed results, attestations and external evidence: a
  standalone Proof Attestation contract (one deployed instance per signer/subject, same
  per-actor pattern) verifying ed25519 signatures natively on-chain (`CHKSIGNU`) over an
  attested hash. `attest` is permissionless -- any sender may relay a valid signature from
  the registered key -- while `rotate-key` and `revoke` are owner-gated, with
  `tosctl agent attestation deploy/ls/show/send`. This is a concrete, narrowly-scoped
  instance of a proof adapter (ed25519 signature verification); Task Escrow/Dispute still
  carry generic evidence/ruling *hashes* rather than consuming this adapter directly, so a
  broader pluggable verification-backend interface across contracts remains open.
  Task Escrow now optionally consumes this signature scheme directly: a task deployed
  with an `attestor_pubkey` requires `settle` to carry a valid ed25519 signature over
  the submitted `result_hash`, verified inline (`CHKSIGNU`) by Task Escrow itself --
  additive on top of, never a replacement for, the existing creator/verifier sender
  authorization. `tosctl agent task create/build-state` accept `--attestor-pubkey` or
  `--signer-vault-key`; `tosctl agent task send --operation settle` accepts
  `--attestation-signature` or `--signer-vault-key`. This is deliberately inline
  verification (no cross-contract messaging) -- see the session's design discussion
  for why: it avoids a novel cross-contract trust/message pattern in a fund-moving
  path, at the cost of not consuming a separately-deployed Proof Attestation
  contract's own revocation/rotation state.
- Add workflow examples that compose planner, worker, service and verifier actors: see
  [`doc/ai-agent-workflow-example.md`](doc/ai-agent-workflow-example.md), which walks a
  planner posting a Task Escrow, a worker (Agent Account) accepting it and paying a Service
  Actor mid-task, a verifier settling the happy path, and a reviewer (Dispute contract)
  resolving a contested one.
- Publish reference schemas for result metadata and evidence bundles: see
  [`doc/ai-workflow-schemas.md`](doc/ai-workflow-schemas.md) -- a canonical-JSON-plus-SHA-256
  hashing convention and JSON shapes for every `*_hash` field across Task Escrow, Capability
  Registry, Service Actor, Dispute and Agent Account.

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
- Extend `tosctl` from Agent Account policy operations toward task commands.
- Add JSON-RPC endpoints or examples for querying agent and task state.
- Add tests that cover asynchronous task lifecycle messages.
- Keep scans in CI to prevent removed execution domains from reappearing: see
  [`scripts/check-no-removed-execution-domains.sh`](scripts/check-no-removed-execution-domains.sh),
  wired into CI via
  [`.github/workflows/no-removed-execution-domains-scan.yml`](.github/workflows/no-removed-execution-domains-scan.yml).

## Non-Goals

- TOS should not become a collection of unrelated virtual machines.
- TOS should not depend on synchronous request-response execution for core agent workflows.
- TOS should not hard-code one model provider, proof system, oracle or off-chain runtime.
- TOS should not make AI execution opaque; task state, payments and verification metadata should remain inspectable.
- TOS should not optimize its first wallet roadmap around ordinary consumer Android or iOS wallets.
