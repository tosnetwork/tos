# TOS 12-Month Roadmap

Version: v1.0

## Purpose

This document turns the TOS North Star into an execution roadmap for the next 12 months.

It is not a protocol spec and not a full backlog.
It is a sequencing document for product and engineering priorities.

The goal is to answer:

> What should TOS do first, what should it defer, and how should success be measured quarter by quarter?

This roadmap assumes the strategic priorities defined in [tos-north-star.md](doc/tos-north-star.md).

## Roadmap Rule

TOS should not optimize for the largest number of visible features delivered.
It should optimize for the largest reduction in ecosystem friction.

That means the first year should focus on:

- closing canonical workflows
- reducing integration ambiguity
- publishing and enforcing stable standards
- making the operator and wallet paths reliable
- making the trust model and data model explicit

## Primary Audiences for the Next 12 Months

The roadmap is ordered around these audiences:

1. infrastructure operators and validators
2. wallet and backend integrators
3. contract teams building reusable applications and services

This order should drive tradeoffs.
If a feature helps a lower-priority audience but weakens the canonical path for a higher-priority audience, it should usually wait.

## Product Surfaces That Must Become Canonical

By the end of this roadmap window, TOS should have one obvious answer for:

- how to run and operate a node
- how to read chain state
- how to estimate, send, and track a transaction
- how to inspect historical and indexed data
- how to build and deploy a contract
- how to reason about trust assumptions for each client type

## Quarter 1: Close Core Operator and RPC Loops

### Goals

- make the node the stable primary service boundary
- make the operator path reliable enough for repeated use
- remove obvious inconsistencies from public RPC behavior

### Must-Ship Outcomes

- embedded JSON-RPC reaches stable read, send, and fee-estimation coverage
- health, readiness, and metrics are consistent and machine-consumable
- `tosctl` becomes the default operator entry point for core node workflows
- configuration, control-plane operations, and service inspection avoid text scraping
- canonical workflows are documented truthfully, with partial workflows labeled explicitly

### Key Deliverables

- validator-engine embedded JSON-RPC stabilization
- structured node status and operator diagnostics
- `tosctl` command convergence for config, service, key, node, and basic wallet flows
- compatibility cleanup for public RPC method names, error semantics, and response shapes
- operator docs aligned with actual implementation

### Exit Criteria

- a healthy node can be installed, configured, started, inspected, and stopped through one primary operator path
- major JSON-RPC read and send flows pass compatibility and regression checks
- docs no longer overclaim incomplete workflows

## Quarter 2: Standardize Wallet, Data, and Trust Surfaces

### Goals

- make wallet integration predictable
- publish the first stable data model for serious integrations
- define trust tiers as product policy, not hidden architecture

### Must-Ship Outcomes

- one canonical wallet integration model from estimate to send to tracking
- one explicit model for balances, transaction identifiers, outcomes, and historical lookup
- published trust tiers and recommended defaults by product type
- early account and permission model decisions documented and enforced in public surfaces

### Key Deliverables

- wallet-facing RPC semantics hardening
- transaction history and indexed data contracts
- public documentation for trust tiers
- first version of account, signing, and delegated-permission standards
- indexer and explorer guidance based on explicit data contracts

### Exit Criteria

- a wallet integrator can support the canonical send-and-track flow from one main API surface
- an explorer or indexer can build from documented historical and indexed data expectations
- trust assumptions are explicit for wallets, browser clients, mobile clients, and infrastructure

## Quarter 3: Standardize Application Interfaces and Upgrade Discipline

### Goals

- reduce application-layer fragmentation
- make upgrade and governance coordination legible
- make ecosystem standards ownership explicit

### Must-Ship Outcomes

- published conventions for token behavior, contract metadata, indexed outputs, and SDK expectations
- defined ownership and change authority for protocol, RPC, wallet-facing, indexing, and account-model standards
- documented upgrade proposal, staging, compatibility-window, and rollback expectations

### Key Deliverables

- application-facing standards package
- deprecation and compatibility policy
- governance and upgrade process documentation
- release discipline that distinguishes stable, experimental, and deferred surfaces

### Exit Criteria

- application teams can rely on published conventions instead of ad hoc chain-specific behavior
- operators and integrators can predict upgrade impact before rollout
- ecosystem participants know where canonical standards are defined and maintained

## Quarter 4: Ecosystem Hardening and Strategic Reassessment

### Goals

- test whether TOS is actually reducing ecosystem friction
- cut or defer surfaces that did not converge
- convert the first year of work into durable release discipline

### Must-Ship Outcomes

- hard-metric review against north-star success criteria
- quantitative review of rethink triggers
- clear go-forward decision on which surfaces are stable, which remain experimental, and which should be deprioritized
- roadmap update for the following 12 months based on measured outcomes

### Key Deliverables

- north-star metric review
- canonical workflow audit
- standards compliance review
- operator time-to-success review
- wallet integration friction review
- indexed-data and trust-model adoption review

### Exit Criteria

- TOS can demonstrate measurable reduction in operator and integrator friction
- the roadmap for the next year is shaped by evidence instead of aspiration
- underperforming or fragmenting surfaces are clearly downgraded, deferred, or removed from the canonical path

## Repository-Level Ownership

### `~/tos`

Owns:

- node-native APIs
- embedded JSON-RPC
- health, readiness, metrics
- structured control-plane capabilities
- trust and verification primitives
- protocol-facing and node-facing implementation work

### `~/tos/tosctl`

Owns:

- operator workflows
- CLI structure and UX
- config orchestration
- service and automation ergonomics
- operator docs and workflow closure

### Shared Responsibility

Requires coordination across both repos:

- wallet-facing send-and-track semantics
- fee-estimation workflow consistency
- data model and historical query expectations
- account and permission model rollout
- standards documentation and compatibility discipline

## Non-Goals for the Next 12 Months

TOS should not prioritize:

- a large number of secondary CLIs or sidecar tools
- many overlapping public API surfaces
- premature expansion into every application vertical
- undocumented convenience shortcuts that bypass trust-model clarity
- major feature growth that does not improve operator, wallet, or integration coherence

## Quarterly Metrics

Each quarter should report at least:

- median time from zero to healthy node
- JSON-RPC compatibility and regression pass rate
- number of canonical workflows that are fully automatable
- number of critical workflows still requiring expert-only manual intervention
- number of primary API surfaces required for wallet integration
- number of undocumented or unofficial paths still needed by serious operators

## Final Rule

The first year should not be judged by how much TOS adds.
It should be judged by how much ambiguity, fragmentation, and hidden operational cost TOS removes.
