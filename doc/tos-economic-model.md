# TOS Economic Model

Version: v0.2-draft

## Purpose

This document defines the economic model that should make TOS worth:

- using
- operating
- integrating
- building on

It is not a token-marketing document.
It is the product and protocol economics companion to:

- `doc/tos-north-star.md`
- `doc/tos-standards-map.md`
- `doc/tos-release-policy.md`

The goal is to answer a simple question:

> What economic loops must exist for TOS to become durable rather than merely usable?

## Scope

This document should eventually define:

- the role of the native asset
- fee mechanics
- validator economics
- operator and infrastructure economics
- developer and application incentives
- long-term sustainability constraints

This document should not try to optimize for:

- speculative narratives without product utility
- token complexity without ecosystem leverage
- short-term activity that does not compound network value

## First-Principles Questions

The final model must answer these questions clearly:

1. Why do users need the asset?
2. Why do validators keep operating?
3. Why do infrastructure providers recover cost?
4. Why do developers keep building?
5. Why do applications stay instead of extracting value and leaving?
6. How do fees reinforce useful activity rather than accidental complexity?
7. What economic behaviors should TOS discourage?

## Design Goals

The economic model should produce:

- simple and legible fee semantics
- durable validator participation
- rational operator economics
- low-friction wallet and application integration
- incentives that reward useful network activity
- economics that align with actual product workflows

## Recommended Baseline Direction

The baseline direction for TOS should be conservative:

- one native asset should secure the network and pay protocol fees
- fee mechanics should remain simple enough for wallet estimation and operator reasoning
- validator economics should reward steady participation rather than exotic strategy
- infrastructure economics should assume that some services are market-provided rather than protocol-subsidized
- developer incentives should favor durable ecosystem growth over short-lived extraction

This baseline should remain the default unless a stronger alternative proves it improves:

- operator reliability
- wallet UX
- integration cost
- network sustainability

## Non-Goals

The economic model should not optimize for:

- maximum mechanism complexity
- rapid token experimentation without operational need
- governance complexity without ecosystem benefit
- multiple overlapping fee systems unless clearly justified

## Core Design Areas

### 1. Native Asset Role

This section should define:

- whether the native asset is required for all fees
- whether the asset is also used for staking
- whether it plays a governance role
- whether it is needed for security deposits, rent, or execution guarantees

Open questions:

- Is one asset sufficient for all roles?
- Which roles are mandatory at launch and which are optional later?
- What product workflows depend directly on the asset?

Decisions:

- `TBD`

Recommended options:

- Option A: one native asset for fees + staking + governance signaling
- Option B: one native asset for fees + staking, governance handled separately

Recommended direction:

- Prefer Option B in the near term unless governance-token separation introduces more clarity than complexity.

### 2. Fee Model

This section should define:

- transaction fee components
- execution fee components
- storage fee components
- forwarding / message-delivery fees
- fee estimation expectations for wallets and SDKs

Open questions:

- Which fee components are surfaced publicly?
- Which fee components are predictable enough for wallet UX?
- How are fees exposed to operators and developers?

Decisions:

- `TBD`

Recommended options:

- Option A: explicit fee decomposition surfaced publicly
  - execution
  - storage
  - forwarding
  - any import / ingress fee
- Option B: user-facing total fee only, internal components mostly hidden

Recommended direction:

- Prefer Option A.
- Wallets and operators need stable, machine-readable decomposition even if most users only see a total.

### 3. Validator Economics

This section should define:

- validator revenue sources
- validator operating cost assumptions
- stake requirements
- slashing or equivalent penalty model, if any
- economic expectations for healthy validator participation

Open questions:

- What level of validator profitability is considered sustainable?
- Which costs are borne by validators directly?
- How should idle or harmful validator behavior be discouraged?

Decisions:

- `TBD`

Recommended options:

- Option A: validators are rewarded primarily through protocol fees and staking yield
- Option B: validators rely heavily on inflationary subsidy independent of useful activity

Recommended direction:

- Prefer Option A with conservative subsidy assumptions.
- The system should not depend on indefinite emissions that are disconnected from real usage.

### 4. Operator and Infrastructure Economics

This section should define:

- economics for node operators beyond validators
- archival / indexing / RPC infra sustainability
- whether the protocol directly rewards any supporting infrastructure roles
- whether the ecosystem expects application-layer monetization instead

Open questions:

- Which infrastructure roles are protocol-critical?
- Which roles are expected to be market-provided?
- What cost structures need to be acknowledged in public standards?

Decisions:

- `TBD`

Recommended options:

- Option A: validators are protocol-critical; indexing / archival / RPC are mostly market services
- Option B: protocol attempts to directly subsidize most ecosystem infrastructure roles

Recommended direction:

- Prefer Option A.
- TOS should clearly distinguish protocol-critical roles from ecosystem service roles.

### 5. Developer and Application Incentives

This section should define:

- why application teams build on TOS
- whether grants, protocol incentives, or fee-sharing exist
- whether developer incentives are protocol-native or ecosystem-layer
- how TOS avoids attracting purely extractive activity

Open questions:

- What makes application retention rational?
- How does TOS reward ecosystem value creation without creating distortion?
- What metrics indicate real ecosystem compounding?

Decisions:

- `TBD`

Recommended options:

- Option A: prioritize low integration cost, stable standards, and ecosystem support over protocol-native rewards
- Option B: rely heavily on token incentives, liquidity mining, or direct application subsidy

Recommended direction:

- Prefer Option A as the baseline.
- If explicit incentives are added, they should reinforce real usage rather than synthetic activity.

### 6. Economic Security and Abuse Resistance

This section should define:

- what spam or abusive behaviors the economic model must price against
- how low-value activity is discouraged
- how protocol resources are protected
- how fee design interacts with network reliability

Open questions:

- Which attacks should be handled economically rather than technically?
- Which resources need explicit scarcity pricing?
- What behavior should become uneconomical by design?

Decisions:

- `TBD`

Recommended options:

- Option A: use simple and visible fee pressure to price scarce resources
- Option B: rely on a growing set of special-case anti-abuse mechanisms

Recommended direction:

- Prefer Option A wherever possible.
- Resource pricing should be legible before it becomes clever.

### 7. Governance and Economic Change

This section should define:

- who can propose economic changes
- how such changes are reviewed
- what compatibility and notice windows apply
- how ecosystem participants evaluate economic-impact changes

Open questions:

- Which economic parameters are stable?
- Which are adjustable?
- What change process is required for each class?

Decisions:

- `TBD`

Recommended options:

- Option A: economic parameter classes with explicit change authority and notice windows
- Option B: broad governance power with weak categorization of changes

Recommended direction:

- Prefer Option A.
- TOS should classify which parameters are:
  - stable by default
  - adjustable with deprecation / notice
  - emergency-only

## Product-Surface Implications

The economic model must feed directly into:

- wallet fee estimation
- transaction-building UX
- validator operation workflows
- public RPC and data contracts
- operator dashboards and observability
- release and governance policy

This section should map each economic decision to concrete product surfaces.

Initial mapping:

- wallet UX depends on stable fee decomposition and fee predictability
- operator UX depends on validator cost/reward legibility
- public RPC depends on explicit fee and execution-result semantics
- indexers and explorers depend on stable transaction outcome and fee reporting
- governance tooling depends on explicit parameter classes and change windows

## Metrics

The final version of this document should define metrics such as:

- validator participation health
- validator/operator cost recovery assumptions
- average fee predictability for wallet flows
- infrastructure cost pressure for read-heavy integrations
- developer and application retention signals

Metrics:

- `TBD`

## Open Decisions

This section should become the short list of unresolved questions that require product and protocol leadership input.

Initial open decisions:

1. Should governance power be tied directly to the staking asset, or treated as a separate coordination layer?
2. Which fee components must be stable public fields from the first public standards release?
3. What validator return profile is considered minimally sustainable?
4. Which infrastructure roles are protocol-critical versus market-provided?
5. Do developer incentives start as ecosystem programs only, or is protocol-native support required later?
6. Which economic parameters are adjustable, and which should be effectively frozen?

## Draft Decision Checklist

Before moving this document to v1.0, TOS leadership should explicitly decide:

- native asset roles
- fee decomposition and public reporting model
- validator reward and cost-recovery model
- infra role boundaries
- developer incentive posture
- economic governance boundaries

## Acceptance Criteria

This document reaches v1.0 when:

- the native asset role is explicit
- the fee model is explicit
- validator and infrastructure incentives are explicit
- developer/application incentives are explicit
- governance rules for economic changes are explicit
- the resulting model can be mapped to wallet, operator, and API surfaces without ambiguity
