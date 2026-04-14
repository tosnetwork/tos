# TOS Convergence Implementation Plan

Version: v1.0

## Purpose

This document turns the TOS architecture and standards documents into an implementation-oriented convergence plan.

It answers:

> How should TOS move from a fragmented tooling model toward one canonical node-facing path, one canonical operator path, and a stable set of public standards?

This document complements:

- [tos-north-star.md](tos-north-star.md)
- [tos-roadmap-12m.md](tos-roadmap-12m.md)
- [tos-standards-map.md](tos-standards-map.md)
- [tos-release-policy.md](tos-release-policy.md)
- [tos-vs-fragmented-architecture.md](tos-vs-fragmented-architecture.md)

## Convergence Goal

TOS should converge around:

- one canonical node-native service boundary
- one canonical operator path
- one explicit set of public standards
- one disciplined release model for ecosystem-facing surfaces

This does not mean every low-level tool disappears.
It means low-level tools stop being the default path for normal operators, wallets, applications, and data consumers.

## Target Architectural Split

### `~/tos`

Should become the canonical source of:

- embedded JSON-RPC and related public machine-facing APIs
- health, readiness, and metrics endpoints
- structured node and validator status surfaces
- structured control-plane capability
- node-native trust and verification primitives
- protocol-facing and data-facing primitives required by canonical public surfaces

### `~/tos/tosctl`

Should become the canonical source of:

- operator workflows
- node and validator lifecycle UX
- config orchestration
- machine-usable and human-usable operational commands
- migration guidance for operator workflows
- honest labeling of stable, guided, partial, and experimental workflows

### Secondary Tools

Low-level binaries and migration shims may continue to exist, but should be categorized as:

- internal building blocks
- expert debugging tools
- temporary compatibility aids
- development-only helpers

They should not remain the documented default for common workflows.

## Public Surface Categories

The convergence work should treat these categories as first-class:

1. node-native RPC surfaces
2. wallet-facing transaction lifecycle surfaces
3. indexing and historical data contracts
4. account and permission semantics
5. operator control and automation surfaces
6. release and compatibility policy for all of the above

## Repository Mapping

### Work That Belongs in `~/tos`

Typical examples:

- adding or stabilizing embedded JSON-RPC methods
- exposing structured health, readiness, metrics, and node status
- exposing structured control-plane capabilities that operators should not obtain through text scraping
- implementing fee estimation and transaction lifecycle primitives
- defining explicit trust-tier or proof-related primitives
- providing canonical historical or indexed data primitives where the node must own them

### Work That Belongs in `~/tos/tosctl`

Typical examples:

- adding or refining canonical command groups
- making workflows automatable and scriptable
- converging config UX and config schema usage
- replacing guidance-only flows with closed operator workflows
- labeling workflows accurately according to maturity
- documenting canonical operator paths

### Work That Requires Coordination Across Both Repos

Typical examples:

- wallet-facing send, estimate, and tracking semantics
- governance participation workflows
- account and permission model rollout
- historical and indexed data expectations
- release-status labeling for operator and API surfaces

## Migration Pattern

Each fragmented workflow should be migrated in this order:

1. identify the real canonical user need
2. identify the current layers involved
3. decide which part must become node-native
4. decide which part must become operator-CLI-native
5. explicitly downgrade or demote the remaining layers
6. publish the new canonical path
7. deprecate the legacy path honestly

This pattern should be applied repeatedly instead of treating each tool as a separate one-off decision.

## Convergence Workstreams

### Workstream 1. Canonical Node Service Boundary

Goal:

- make `validator-engine` the primary service core for public machine-facing interaction

Implementation themes:

- embedded JSON-RPC expansion and stabilization
- health, readiness, and metrics standardization
- structured status and control primitives
- compatibility cleanup for canonical read, estimate, send, and tracking methods

Primary repository:

- `~/tos`

Dependent repository:

- `~/tos/tosctl`

### Workstream 2. Canonical Operator Path

Goal:

- make `tosctl` the primary operational interface

Implementation themes:

- command convergence
- config convergence
- lifecycle convergence
- automation-safe output and error handling
- reduction of operator dependence on low-level expert tools

Primary repository:

- `~/tos/tosctl`

Dependent repository:

- `~/tos`

### Workstream 3. Canonical Wallet and Transaction Flow

Goal:

- provide one coherent path for estimate, send, and track

Implementation themes:

- stable RPC semantics
- clear transaction identifiers and outcomes
- stable wallet-facing failure classification
- explicit account and signing semantics

Primary repositories:

- `~/tos`
- `~/tos/tosctl` for operator-facing workflows and diagnostics

### Workstream 4. Canonical Data Contracts

Goal:

- make historical and indexed data expectations explicit

Implementation themes:

- transaction history model
- outcome and receipt model
- event-like indexed output conventions
- archival query boundaries
- trust and proof boundaries

Primary repository:

- `~/tos`

Supporting artifacts:

- docs and standards definitions

### Workstream 5. Standards and Release Discipline

Goal:

- keep convergence from collapsing back into fragmentation

Implementation themes:

- standards ownership
- stability levels
- compatibility windows
- deprecation rules
- experimental-surface discipline
- truthful workflow labeling

Primary repositories:

- documentation across `~/tos`
- implementation labeling in both `~/tos` and `~/tos/tosctl`

## Milestone Plan

### Milestone A. Close Core Node and Operator Loops

Target outcomes:

- embedded JSON-RPC covers the canonical read, estimate, send, and tracking path
- `tosctl` covers the canonical node and validator operator path
- health, readiness, and structured diagnostics are consistent

Expected changes in `~/tos`:

- JSON-RPC coverage and compatibility hardening
- health/readiness/metrics stabilization
- structured node status exposure

Expected changes in `~/tos/tosctl`:

- canonical command-group cleanup
- config-path correctness
- automation-friendly outputs
- removal of misleading completion claims

### Milestone B. Standardize Wallet, Data, and Trust Surfaces

Target outcomes:

- one canonical wallet integration flow
- one documented historical and indexed data model
- published trust-tier guidance

Expected changes in `~/tos`:

- transaction and history semantics stabilization
- trust-model and proof-boundary clarification

Expected changes in `~/tos/tosctl`:

- diagnostics and operator tooling aligned with wallet/data standards where needed

### Milestone C. Standardize Account, Permission, and Application Interfaces

Target outcomes:

- documented account and permission semantics
- documented application-layer interface conventions
- reduced application-layer fragmentation

Expected changes in `~/tos`:

- RPC or protocol-facing support for canonical account and permission semantics

Expected changes in `~/tos/tosctl`:

- operator workflows for account- or governance-related operations where needed

### Milestone D. Enforce Release and Standards Discipline

Target outcomes:

- all significant public surfaces carry clear stability status
- compatibility windows and deprecation behavior are consistent
- experimental surfaces are labeled and reviewed honestly

Expected changes in `~/tos`:

- release-note and stability labeling discipline for node-facing surfaces

Expected changes in `~/tos/tosctl`:

- release-note and stability labeling discipline for operator-facing surfaces

## What Should Be Demoted

The convergence plan assumes that some existing surfaces will be retained but demoted.

These typically include:

- low-level query binaries used mainly for debugging
- raw expert control tools
- migration wrappers that only exist because the canonical path is not yet complete
- compatibility shims that are still needed temporarily

Demotion does not mean deletion.
It means:

- not the primary documented path
- not the first recommended integration path
- not the basis for ecosystem standards

## Decision Matrix for Existing Tools

Each existing tool or surface should be classified as one of:

- canonical
- supported secondary
- expert-only
- compatibility shim
- deprecated
- removal candidate

The classification should depend on:

- whether it is needed for normal workflows
- whether it has unique capability not yet present in the canonical path
- whether downstream integrators depend on it
- whether it reduces or increases ecosystem fragmentation

## Implementation Ownership Questions

Before starting work on any convergence task, answer:

1. Is this capability supposed to be node-native, operator-native, or secondary?
2. Which repository owns the long-term canonical version?
3. Is the current implementation a real canonical path or only a transition path?
4. What existing surface becomes demoted if this succeeds?
5. What standards surface does this affect?
6. What release-policy obligations does it create?

If these questions are unanswered, implementation will likely drift back toward fragmentation.

## Success Criteria

The convergence plan is working when:

- downstream users stop needing multiple overlapping primary entry points
- more workflows move onto the canonical node and operator path each quarter
- fewer private wrappers are required in wallets, explorers, and operator automation
- standards and release labels become more accurate over time, not less
- legacy tools remain available where needed, but are no longer the default answer

## Final Rule

Convergence is not complete when TOS has many tools.
Convergence is complete when serious ecosystem participants no longer need to guess which tool, API, or workflow is the real one.
