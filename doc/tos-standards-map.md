# TOS Standards Map

Version: v1.0

## Purpose

This document defines the major public standards surfaces for TOS.
The AI Actor Model in [ai-actors.md](ai-actors.md) is the current product direction for these standards.

It is not a protocol spec and not a complete API reference.
It is a map of the surfaces that must become stable enough for ecosystem participants to rely on.

The goal is to answer:

> Which parts of TOS must behave like standards, who depends on them, and what kind of stability is required?

## Standards Rule

TOS should distinguish clearly between:

- implementation details
- supported product surfaces
- formal ecosystem standards

Not every implementation detail needs standardization.
But every surface that serious wallets, operators, applications, explorers, indexers, or infrastructure providers depend on must have a clear stability policy.

## Stability Levels

Each standard surface should be classified into one of these levels:

### Level 1. Canonical Standard

Required for broad ecosystem compatibility.
Changes require documentation, compatibility review, and deprecation discipline.

### Level 2. Supported Surface

Supported for serious use, but still evolving.
Changes must be documented, but the compatibility burden is lower than Level 1.

### Level 3. Experimental Surface

Available for testing and iteration.
Not yet safe to build broad ecosystem dependencies around.

## Standard Families

The TOS standards map is organized into these families:

1. RPC standards
2. wallet standards
3. indexing and data standards
4. account and permission standards
5. operator standards
6. contract and application standards
7. trust and verification standards
8. AI actor workflow standards

## 1. RPC Standards

### Scope

**Status: ✅ Implementation complete, OpenAPI 3.1 spec published (doc/openapi.yaml)**

RPC standards define how machine clients interact with chain state and transaction workflows.

### Surfaces

- public JSON-RPC method names
- request and response envelope shape
- field naming conventions
- numeric and string encoding conventions
- error object semantics
- health and readiness endpoints
- fee-estimation request and response shape
- send-and-track transaction semantics

### Required Stability

Core read, estimate, send, and tracking methods should be treated as Level 1.
Optional or niche methods may remain Level 2 until ecosystem dependency is real.

### Required Guarantees

- one canonical meaning for each public method
- no silent behavior drift behind unchanged method names
- explicit not-implemented behavior
- explicit deprecation windows for breaking changes
- published distinction between stable and experimental endpoints

### Primary Consumers

- wallets
- backend services
- explorers
- dashboards
- automation and CI
- SDKs

## 2. Wallet Standards

### Scope

**Status: ✅ Send-track spec published (doc/tos-wallet-send-track.md)**

Wallet standards define the stable user-facing and machine-facing transaction lifecycle.

### Surfaces

- address normalization and canonical display rules
- wallet type detection rules
- transaction estimation semantics
- transaction submission semantics
- transaction tracking semantics
- status and outcome interpretation
- failure classification relevant to wallets
- signing payload conventions

### Required Stability

The canonical wallet flow from estimate to send to tracking should be Level 1.
Wallet convenience helpers that do not affect interoperability may remain Level 2.

### Required Guarantees

- wallets do not need multiple incompatible primary APIs for normal send flows
- transaction identifiers are stable and documented
- transaction outcomes are interpretable without reverse engineering
- failure reasons are structured enough for wallet UX
- wallet-facing RPC methods preserve meaning across releases

### Primary Consumers

- wallet applications
- custodial systems
- payment processors
- merchant tooling
- embedded finance products

## 3. Indexing and Data Standards

### Scope

**Status: ✅ Transaction history spec published (doc/tos-transaction-history.md)**

Indexing and data standards define how integrators obtain historical, derived, and searchable views of chain activity.

### Surfaces

- transaction history model
- block and transaction identifiers
- historical account state expectations
- receipts or equivalent execution outcomes
- event-like indexed outputs
- archival query boundaries
- proof boundaries for verifiable responses
- reproducibility expectations for indexed views

### Required Stability

Core historical and indexed data contracts should become Level 1 once explorers, wallets, and analytics systems rely on them.
Experimental derived views may remain Level 2 or Level 3 until stabilized.

### Required Guarantees

- a documented model for transaction history
- a documented model for outcomes and execution results
- a documented boundary between node-native data, archival data, and indexer-derived data
- explicit trust assumptions for indexed views
- consistent identifiers across RPC, indexing, and explorer surfaces

### Primary Consumers

- explorers
- indexers
- wallet backends
- analytics systems
- compliance and monitoring systems

## 4. Account and Permission Standards

### Scope

**Status: ❌ Not started**

Account and permission standards define how authority works in TOS.

### Surfaces

- account behavior model
- signing and submission semantics
- authorization model
- delegated permission model
- session permission model
- agent permission model
- sponsorship or fee-payer semantics where relevant
- smart account compatibility expectations

### Required Stability

Core authorization and signing semantics should be Level 1 once published.
More advanced permission features may begin as Level 2, but should not be left ambiguous.

### Required Guarantees

- account behavior is documented clearly enough for wallets and applications
- signing meaning is stable across toolchains
- delegated permissions do not rely on undocumented wallet-specific behavior
- session and agent permissions are explicit, bounded, and machine-readable
- sponsorship semantics are either supported intentionally or clearly out of scope

### Primary Consumers

- wallets
- applications
- automation agents
- embedded transaction systems
- account abstraction tooling

## 5. Operator Standards

### Scope

**Status: ✅ Implementation complete, formal spec pending**

Operator standards define the canonical path for node and validator operations.

### Surfaces

- canonical CLI command groups
- config structure and persistence rules
- structured node status model
- health and readiness semantics
- key-management workflow expectations
- backup and recovery workflow expectations
- upgrade and deprecation signaling
- governance participation workflow semantics

### Required Stability

Core operator workflows should be Level 1 once the canonical path is declared.
Guided or partially automated flows should remain Level 2 until truly closed.

### Required Guarantees

- one primary operator path for common workflows
- no dependence on text scraping for critical paths
- truthful workflow labeling
- explicit partial, guided, stable, or experimental status
- compatibility discipline for config and automation surfaces

### Primary Consumers

- validators
- infrastructure operators
- DevOps teams
- SRE teams
- managed service providers

## 6. Contract and Application Standards

### Scope

**Status: ✅ TOS TEP token standards published (doc/tos-tep-token-standards.md)**

Contract and application standards define how reusable application-layer components compose.

### Surfaces

- token behavior conventions
- contract metadata conventions
- ABI or interface description conventions
- deployment and upgrade expectations
- indexed output and event conventions
- SDK abstractions for common application patterns

### Required Stability

Widely reused application-facing conventions should become Level 1 only after they are explicit and tested.
Newer conventions may remain Level 2 while adoption is forming.

### Required Guarantees

- reusable contract types have documented expectations
- metadata is stable enough for wallets, explorers, and tooling
- event-like outputs can be interpreted consistently
- SDKs do not invent incompatible meanings for common application concepts

### Primary Consumers

- contract teams
- SDK authors
- wallets
- explorers
- application platforms

## 7. Trust and Verification Standards

### Scope

**Status: ✅ Trust tiers spec published (doc/tos-trust-tiers.md)**

Trust and verification standards define what clients can verify, what they must trust, and what proofs are available.

### Surfaces

- full-node verification expectations
- light-client verification expectations
- proof-backed remote verification semantics
- trusted convenience API classification
- proof format and verification boundaries where applicable
- recommended trust defaults by product type

### Required Stability

Trust-tier definitions and terminology should be Level 1 once published.
Concrete proof transport details may remain Level 2 while implementation matures.

### Required Guarantees

- each major client type has a documented recommended trust tier
- trust assumptions are not hidden behind convenience APIs
- proof-backed verification claims are precise about scope
- integrators can distinguish verified data from trusted derived data

### Primary Consumers

- Agent Wallets
- agent runners
- automation clients
- SDKs
- explorers
- infrastructure providers

## 8. AI Actor Workflow Standards

### Scope

**Status: draft direction published (doc/ai-actors.md)**

AI actor workflow standards define how user actors, agent accounts, task actors, service actors, and verifier actors coordinate through asynchronous messages.
The primary wallet standard in this family is the Agent Wallet: a machine-facing wallet/account for AI agents and automation.

Companion draft documents:

- [ai-actor-message-catalog.md](ai-actor-message-catalog.md)
- [ai-actor-contract-guidelines.md](ai-actor-contract-guidelines.md)
- [ai-actor-threat-model.md](ai-actor-threat-model.md)
- [ai-actor-testing-matrix.md](ai-actor-testing-matrix.md)
- [ai-actor-operations-runbook.md](ai-actor-operations-runbook.md)

### Surfaces

- agent account metadata and permission expectations
- Agent Wallet policy, balance, task-history and service-call inspection
- task lifecycle messages
- task escrow and settlement semantics
- service actor pricing and authorization metadata
- verifier actor result-review messages
- evidence reference and result metadata conventions
- workflow indexing and inspection expectations

### Required Stability

The first agent and task primitives may begin as Level 3 while examples and tests mature. Message names, settlement semantics, and account permission boundaries should move toward Level 2 before SDKs depend on them.

### Required Guarantees

- agent permissions are explicit and bounded
- task state is inspectable from chain state
- service actors cannot charge without authorized requests
- result references and verification metadata are machine-readable
- workflows remain asynchronous and do not depend on synchronous cross-contract calls
- threat model, message catalog, and test matrix are updated before a primitive is promoted

### Primary Consumers

- AI agent developers
- Agent Wallet implementers
- wallet and account teams
- model and tool service providers
- workflow builders
- verifier and reputation systems

## Standards Ownership

TOS should assign clear ownership for each standards family:

- RPC standards
- wallet standards
- indexing and data standards
- account and permission standards
- operator standards
- contract and application standards
- trust and verification standards
- AI actor workflow standards

Ownership must answer:

- who proposes changes
- who reviews compatibility impact
- who approves changes
- where the canonical definition lives
- how changes are announced

If ownership is ambiguous, the standard is not mature.

## Change Policy

Every Level 1 surface should have:

- a canonical document or spec location
- explicit versioning or compatibility policy
- deprecation rules
- migration guidance for downstream integrators

Every Level 2 surface should have:

- a documented status marker
- known open questions
- an explicit path either toward stabilization or removal

Every Level 3 surface should have:

- explicit experimental labeling
- no implied long-term compatibility promise

## Standards Audit Questions

When deciding whether a surface is ready to be treated as a standard, ask:

1. Do multiple serious ecosystem participants already depend on it?
2. Is its behavior documented clearly enough to implement independently?
3. Are identifiers, field names, and failure modes stable?
4. Is the trust model explicit?
5. Is ownership clear?
6. Is there a deprecation path for future change?
7. Would fragmentation here force wallets, operators, or applications to build custom glue?

If the answer is mostly no, the surface should not yet be treated as a Level 1 standard.

## Near-Term Standardization Order

For the next 12 months, TOS should standardize in this order:

1. RPC standards
2. wallet standards
3. operator standards
4. indexing and data standards
5. trust and verification standards
6. account and permission standards
7. contract and application standards

This order follows the first-year priority of reducing operator and integrator friction before expanding higher-level abstraction surfaces.

## Final Rule

TOS should not let standards emerge accidentally from whichever implementation happens to exist first.

The ecosystem should make standards explicit early enough that:

- operators can automate confidently
- wallets can integrate once
- indexers can build once
- applications can compose without reinventing the chain
