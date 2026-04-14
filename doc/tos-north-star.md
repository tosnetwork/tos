# TOS North Star

Version: v1.2

## Purpose

This document defines the long-term product and engineering compass for TOS.

It is not a protocol spec, and it is not an implementation checklist.
It is the answer to a simpler question:

> What kind of ecosystem are we trying to build, and what must be true for it to win?

The goal is to keep TOS aligned on first principles when making decisions about protocol work, node software, tooling, APIs, wallets, contracts, and ecosystem support.

## First Principles

### 1. A blockchain succeeds only if real users can reliably do real work

Consensus, throughput, proofs, and protocol elegance matter.
But they matter only insofar as they enable stable user actions:

- create an account
- send value
- deploy a contract
- call a contract
- observe state
- operate a validator
- recover from failure

If these workflows are fragile, fragmented, or poorly documented, the chain is not ready regardless of protocol quality.

### 2. The ecosystem must have one obvious path for every important job

Every high-frequency workflow must have a clear canonical path:

- one canonical node runtime
- one canonical machine-facing API surface
- one canonical operator CLI
- one canonical wallet flow
- one canonical contract deployment flow

Multiple internal layers may exist.
But external users, operators, and developers must not be forced to choose between overlapping, partially compatible entry points.

### 3. Simplicity at the edge is more important than flexibility in the middle

Internal architecture may be modular.
External product surfaces must be opinionated.

It is acceptable to have many internal components.
It is not acceptable to expose every internal component as a primary user-facing tool.

### 4. The winning default is boring reliability

The ecosystem should optimize for:

- deterministic behavior
- stable interfaces
- clear failure modes
- low operational surprise
- easy upgrade paths

Novelty is valuable only when it reduces cost or increases capability without raising operator risk.

### 5. Tooling is part of the protocol product

For TOS, the node, the RPC API, the operator CLI, the wallet abstractions, and the contract toolchain are not separate concerns.
They are one product surface.

If the protocol is powerful but the tooling is fragmented, the actual product is fragmented.

## The TOS Goal

TOS should become a chain where:

- a node can be deployed and operated through one primary control surface
- chain state can be read through one stable RPC surface
- transactions can be built, estimated, sent, and tracked through one consistent client model
- contract development has one supported path from source to deployment to debugging
- validator operations do not require tribal knowledge or text scraping
- ecosystem contributors can build against stable interfaces instead of reverse-engineering runtime behavior

This implies a product goal:

> TOS should feel integrated, not assembled.

This is not only a tooling goal.
It is also a market-design goal:

> TOS should be worth building on, worth operating, and worth integrating.

## Target Users and First Winning Use Cases

TOS should not try to win every category at once.
In the next 12 to 24 months, it should optimize first for:

- serious infrastructure operators who need reliable node and validator workflows
- wallet and backend integrators who need stable read, estimate, send, and track semantics
- contract teams who need one coherent path from source to deployment and observability

The first winning use cases should be the ones where operational coherence and API coherence matter most:

- running validators and related infrastructure without tribal knowledge
- integrating wallet send flows from one stable public surface
- deploying and operating contract-based applications with predictable tooling
- building explorers, dashboards, and indexers on top of explicit data contracts

This means TOS should not measure progress by the number of features it exposes.
It should measure progress by whether these audiences can complete their most important jobs faster, more safely, and with less chain-specific glue.

## Why TOS Wins

TOS should not try to win by being merely comparable.
It should win where coherence creates compounding advantage.

The ecosystem should aim to be meaningfully better in a small number of areas:

- operator workflows that are dramatically simpler and more automatable
- public API surfaces that are dramatically more stable and easier to integrate
- contract and wallet flows that are dramatically more coherent from estimate to send to observe

TOS does not need to dominate every category.
It does need to be obviously better where it chooses to compete.

That also means TOS should be explicit about what it is not trying to be in the near term.
Strategic focus is part of product quality.

## Priority Order Across Target Users

When tradeoffs appear, TOS should prioritize audiences in this order:

1. infrastructure operators and validators
2. wallet and backend integrators
3. contract teams building reusable applications and services

This ordering is intentional.
If the operator path is fragile, the rest of the ecosystem inherits instability.
If wallet and backend integrations remain expensive, user-facing adoption remains shallow.
If those two layers are strong, contract teams inherit a more reliable foundation.

This priority order should influence staffing, roadmap sequencing, and release criteria.

## What TOS Must Be

### 1. A node-first ecosystem

**Status: ✅ Done**

The node is the root of truth.
Important capabilities should live in the node or be directly derived from it:

- read APIs
- send APIs
- health and readiness
- metrics
- structured control-plane operations

Critical workflows should not depend on sidecar glue unless the sidecar is intentionally part of the supported product.

### 2. An API-first ecosystem

**Status: ✅ Done**

Every important chain action should have a stable machine-facing interface.

That means:

- structured JSON-RPC for read and send flows
- predictable request and response shapes
- explicit error semantics
- health and readiness endpoints
- compatibility discipline for public method names

Humans may use CLIs.
Ecosystems scale through APIs.

### 3. A standards-first ecosystem, not a single-implementation ecosystem

**Status: ⚠️ OpenAPI 3.1 spec published, formal standard families pending**

TOS should standardize interfaces aggressively without requiring ecosystem monoculture.

That means separating:

- canonical protocol rules
- canonical public interface standards
- interchangeable compliant implementations where practical

One primary reference implementation is acceptable.
One mandatory implementation for every layer is not the goal.

TOS should be strict about interface compatibility and loose about implementation diversity wherever diversity does not fragment the product.

### 4. An operator-first ecosystem

**Status: ✅ Done**

Validators and infrastructure operators are not a secondary audience.
If operations are painful, the ecosystem slows down everywhere else.

The operator product must support:

- install
- configure
- bind roles
- inspect node health
- inspect validator state
- manage keys
- manage pools
- perform governance actions
- recover and back up state

These must be intentional workflows, not emergent combinations of unrelated tools.

### 5. A wallet-first ecosystem

**Status: ✅ Core APIs + in_msg_hash tracking + send-track spec published (doc/tos-wallet-send-track.md)**

A chain does not become widely usable until wallet flows are stable and predictable.

Wallet-facing primitives must be first-class:

- address normalization
- balance and state inspection
- wallet detection
- fee estimation
- send flow
- transaction tracking

Wallet integration should not depend on bespoke chain-specific guesswork.

### 6. A contract-first ecosystem

**Status: ⚠️ Toolchain exists, unified workflow pending**

Contracts are the application layer.
Developers must be able to:

- build contracts
- test them
- inspect execution
- estimate fees
- deploy and upgrade safely
- reason about contract state

The contract toolchain must be coherent across compiler, runtime, API, and operator tooling.

### 7. A data-availability and indexing-friendly ecosystem

**Status: ✅ Transaction history spec published (doc/tos-transaction-history.md)**

Applications and infrastructure do not scale on recent state alone.
TOS must make it clear how the ecosystem accesses:

- recent state
- historical state
- transaction history
- receipts or equivalent execution outcomes
- contract-generated events or event-equivalent indexed outputs
- proofs where verification matters

The product boundary between node, archival service, and indexing service must be explicit.
If every explorer, wallet backend, and analytics system must invent its own history model, TOS will remain expensive to integrate.

### 8. An application-composability ecosystem

**Status: ✅ TOS TEP token standards published (doc/tos-tep-token-standards.md)**

The ecosystem should not only make contracts possible.
It should make applications easy to compose with each other.

That requires stable conventions for:

- common token interfaces
- wallet interaction patterns
- permission and signing expectations
- contract metadata
- event and indexing conventions
- SDK abstractions

Applications should build on shared standards first and custom glue second.

### 9. A sustainable economic ecosystem

**Status: ❌ Not started**

Technical coherence is necessary but not sufficient.
TOS must also be economically coherent.

The ecosystem should make it easy to answer:

- why users hold and spend the asset
- why validators keep operating
- why developers keep building
- why infrastructure providers can recover cost
- how fee mechanics reinforce real network utility instead of accidental complexity

If the stack is technically elegant but economically hollow, adoption will remain shallow.

### 10. A clear trust-model ecosystem

**Status: ✅ Trust tiers spec published (doc/tos-trust-tiers.md)**

Not every user should need the same verification model.
But every product surface should make its trust assumptions explicit.

TOS should support clear tiers such as:

- full verification
- light verification
- proof-backed verification for constrained clients
- indexer-backed convenience for products that accept more trust

The ecosystem should define which guarantees belong to each tier.
Wallets, mobile clients, browser clients, operators, and analytics systems should not have to infer trust boundaries from implementation quirks.

### 11. An account-and-permission model that compounds ecosystem value

**Status: ❌ Not started**

Application growth depends heavily on the account model.
TOS should treat this as a strategic layer, not a wallet implementation detail.

The ecosystem should make deliberate choices about:

- account abstraction boundaries
- signing and submission semantics
- delegated permissions
- session and agent permissions
- sponsored transaction or fee-payer semantics where relevant

These decisions shape wallet UX, application automation, embedded payments, and smart account composition.

## What TOS Must Avoid

### 1. Fragmented primary interfaces

TOS should avoid having multiple overlapping "main" tools for the same task.

Bad pattern:

- one tool for reading
- another tool for sending
- another tool for operator actions
- another tool for ad hoc node control
- another tool for deployment

Good pattern:

- one primary API surface
- one primary operator CLI
- lower-level tools retained as implementation details or expert interfaces

### 2. Text-oriented operations where structure is required

If an operator tool must parse human-readable output from another tool, the architecture is wrong.

Important operational paths must use:

- typed RPCs
- typed control-plane calls
- structured JSON
- explicit status objects

### 3. Feature growth without path convergence

New features should reduce fragmentation, not add another top-level path.

Whenever a new capability is added, the first question should be:

> Does this strengthen the canonical path, or create another parallel path?

If it creates another path, the burden of proof is high.

### 4. Documentation that outruns implementation

TOS should not claim parity, completion, or production readiness before the workflows are truly closed.

A partially automated workflow is acceptable.
A partially automated workflow documented as complete is harmful.

### 5. Hidden operator state

Operational behavior should not depend on opaque local databases, undocumented caches, or implicit side effects.

Configuration and live state should be explicit, inspectable, and reproducible.

### 6. Interface lock-in disguised as ecosystem coherence

TOS should not confuse "one canonical path" with "one permanently mandatory implementation."

Ecosystem coherence should come from strong standards and stable interfaces.
It should not depend on forbidding alternative compliant implementations at every layer.

### 7. Growth without economic alignment

TOS should avoid features that increase protocol or product complexity without improving:

- user utility
- builder leverage
- validator incentives
- infrastructure sustainability
- network demand

If a feature does not improve at least one of these meaningfully, its long-term value is suspect.

## Strategic Product Directions

### Direction 1. Make the node the canonical service boundary

**Status: ✅ Done**

The validator engine should expose the primary embedded service surface for:

- JSON-RPC
- health
- readiness
- metrics
- structured node capability access

This reduces dependency on external compatibility shims and makes the node the stable product core.

### Direction 2. Define public standards separately from implementation ownership

**Status: ⚠️ OpenAPI 3.1 spec published, formal standard families pending**

TOS should document and stabilize public standards at distinct layers:

- protocol behavior
- RPC behavior
- wallet-facing transaction semantics
- contract interface conventions
- indexing and archival guarantees

These standards should remain stable even when the underlying implementation evolves.
This is how TOS can remain coherent without becoming closed.

TOS should also define who owns change authority for each class of standard:

- protocol standards
- public RPC standards
- wallet-facing standards
- indexing and archival standards
- account and permission standards

Ownership should be explicit enough that ecosystem participants know where canonical decisions come from and how they can be challenged, reviewed, and updated.

### Direction 3. Make `tosctl` the canonical operator shell

**Status: ✅ Done**

`tosctl` should become the default answer to operator questions such as:

- How do I set this up?
- How do I inspect the validator?
- How do I manage wallet and pool workflows?
- How do I participate in governance?
- How do I check alerts, metrics, and backups?

The target is not a large command tree for its own sake.
The target is one obvious operator path.

### Direction 4. Treat indexed data as a first-class product surface

**Status: ✅ Transaction history spec published (doc/tos-transaction-history.md)**

Recent chain state is not enough.
TOS should intentionally define how serious integrations obtain:

- transaction history
- execution outcomes
- event-like outputs
- archival reads
- reproducible indexed views of state transitions

If this is left implicit, every explorer, wallet backend, compliance system, and analytics stack will rebuild the same fragile layer differently.

### Direction 5. Keep low-level binaries, but demote them

**Status: ✅ Done**

Expert tools may still exist.
That is fine.

But they should be treated as:

- internal building blocks
- expert escape hatches
- debugging tools

They should not remain the default operational path for normal workflows.

### Direction 6. Make application standards part of ecosystem policy

**Status: ✅ TOS TEP token standards published (doc/tos-tep-token-standards.md)**

TOS should publish and protect shared conventions for:

- token behavior
- signing flows
- wallet interaction
- contract metadata
- indexed outputs and event conventions
- fee estimation and send-flow semantics

The goal is to let applications compose by default instead of discovering each other through reverse engineering.

### Direction 7. Treat compatibility as a migration tool, not a permanent excuse

**Status: ✅ Done**

Compatibility with existing public API shapes is strategically useful because it lowers adoption cost.
But compatibility should feed into a coherent TOS-native product, not freeze fragmentation forever.

The correct sequence is:

1. match the interfaces that users already expect
2. stabilize TOS-native implementations behind them
3. converge ecosystem usage onto the canonical TOS path

### Direction 8. Keep economic design tied to product reality

**Status: ❌ Not started**

TOS should evaluate fee markets, validator economics, developer incentives, and infrastructure incentives against actual product behavior.

Economic design is not an abstract appendix.
It must reinforce:

- useful transaction volume
- durable validator participation
- rational infrastructure investment
- application growth that compounds instead of churning

### Direction 9. Make governance and upgrade coordination a product surface

**Status: ✅ Upgrade process spec published (doc/tos-upgrade-process.md)**

Protocol governance is not separate from product quality.
If upgrade coordination is fragile, interface stability will also be fragile.

TOS should define and publish expectations for:

- upgrade proposal flow
- implementation and review flow
- staging and testnet expectations
- compatibility windows
- deprecation policy
- emergency coordination and rollback expectations

This should be explicit enough that ecosystem participants can predict how change happens before a crisis forces ad hoc coordination.

### Direction 10. Define verification tiers as part of public architecture

**Status: ✅ Published doc/tos-trust-tiers.md with 4 tiers and 9 product-type defaults**

TOS should publish a clear model for how different clients interact with trust and verification:

- node-native full verification
- light-client verification
- proof-backed remote verification
- trusted convenience APIs

This allows wallets, SDKs, browsers, and infrastructure providers to choose the right trust-cost tradeoff without ambiguity.

TOS should also publish recommended defaults by product type:

- validators and critical infrastructure should prefer full verification
- wallets should prefer light verification or proof-backed remote verification where feasible
- browser and mobile clients should use the lightest model that still keeps trust assumptions explicit
- explorers, dashboards, and analytics systems may use trusted indexed views, but should document that trust model clearly

### Direction 11. Make the account and permission model an ecosystem standard

**Status: ❌ Not started**

TOS should not leave signing, delegation, and permission semantics to fragmented wallet behavior.

The ecosystem should converge on clear standards for:

- account behavior
- authorization flow
- session permissions
- agent permissions
- submission and sponsorship patterns

This is one of the highest-leverage areas for application UX and automation.

## Execution Priorities

### Priority 1. Close the critical workflow loops

**Status: ✅ Done**

The following loops must be complete and reliable:

- node startup to healthy serving state
- JSON-RPC read path
- transaction send path
- fee estimation path
- wallet activation and send flow
- validator inspection and governance participation

If these loops are broken, partial feature expansion is noise.

### Priority 2. Standardize the data model for serious integrations

**Status: ✅ Transaction history spec published (doc/tos-transaction-history.md)**

TOS should define stable expectations for:

- account history
- transaction identifiers
- receipts or equivalent execution outcomes
- event-like indexed outputs
- archival query boundaries
- proof boundaries

Without this, application teams and infrastructure teams will keep rebuilding incompatible history layers.

### Priority 3. Eliminate fragmented control surfaces

**Status: ✅ Done**

TOS should keep collapsing scattered capabilities into:

- node-native APIs in the validator engine
- structured commands in `tosctl`

This is higher value than adding many new secondary tools.

### Priority 4. Standardize response shapes and error semantics

**Status: ✅ Done**

A healthy ecosystem depends on predictability.

For public APIs, TOS should maintain:

- stable field names
- stable method names
- consistent numeric/string conventions
- explicit not-implemented behavior
- typed error messages instead of generic internal failures

### Priority 5. Define and enforce application-facing standards

**Status: ✅ TOS TEP token standards published (doc/tos-tep-token-standards.md)**

TOS should standardize the surfaces that applications and wallets depend on most:

- token interfaces
- signing and submission rules
- contract metadata conventions
- indexing and event conventions
- SDK surface expectations

This is necessary if TOS wants applications to compose instead of fork their own conventions.

### Priority 6. Build for automation, not only for interactive use

**Status: ✅ Done**

Every important operational workflow should be usable by:

- a human at the terminal
- CI
- scripts
- dashboards
- wallet and backend services

If a workflow only works interactively, it is unfinished.

### Priority 7. Keep safety visible

**Status: ✅ Done**

For upgrades, backups, alerts, and destructive actions:

- defaults must be conservative
- risk must be obvious
- manual guidance is acceptable when automation is not mature
- unsafe shortcuts must not be presented as production-grade workflows

### Priority 8. Measure ecosystem success with hard metrics

**Status: ⚠️ JSON-RPC Prometheus metrics implemented (per-method request/error counters, cache, uptime); higher-level ecosystem metrics pending**

TOS should track concrete indicators such as:

- time from zero to healthy node
- number of commands or API calls required for a wallet send flow
- number of steps from contract source to deploy
- percentage of operator workflows that are fully automatable
- JSON-RPC compatibility pass rate
- time for an integrator to achieve correct balance and transaction history reads
- validator recovery time after common failures
- number of critical workflows that still require expert-only manual intervention

### Priority 9. Reduce ambiguity about governance and change management

**Status: ✅ Upgrade process spec published (doc/tos-upgrade-process.md)**

TOS should make protocol and interface evolution legible to the ecosystem.

At minimum, operators and integrators should be able to answer:

- what changes are coming
- which surfaces are stable
- how long compatibility will be preserved
- how to prepare for upgrades
- what happens during emergency rollback or incident response

### Priority 10. Standardize trust tiers and permission semantics

**Status: ⚠️ Trust tiers published (doc/tos-trust-tiers.md); permission semantics pending**

TOS should not postpone these decisions until wallets and applications have already fragmented.

The ecosystem should define early:

- trust models for major client types
- account and signing semantics
- delegated permission expectations
- session and agent access patterns
- sponsorship and relayer expectations where relevant

## Product Tests for Every Major Decision

Before adopting a new tool, endpoint, or workflow, ask:

1. Does this reduce the number of primary ways to do the job?
2. Does this make the common workflow shorter or more reliable?
3. Can this be used both by humans and by automation?
4. Does it remove text scraping, implicit state, or undocumented glue?
5. Is the failure mode clear?
6. Can we document this as the canonical path without misleading users?
7. Does it strengthen composability for wallets, applications, and infrastructure?
8. Does it improve or harm long-term incentive alignment?
9. Does it make the trust model clearer instead of more implicit?
10. Does it reinforce or fragment the account and permission model?

If the answer is mostly no, the change is likely not aligned with the TOS direction.

## TOS Success Criteria

TOS is on the right path when the following become true:

- new operators can bring up a node without private tribal knowledge
- wallets can integrate against one clear RPC surface
- infrastructure teams can automate node operations through one CLI and one API
- contract developers can estimate, deploy, and inspect without switching between fragmented tools
- docs describe the real path, not an aspirational path
- new features usually remove complexity at the edge instead of adding it

TOS is meaningfully succeeding when these become measurable:

- a competent operator can go from zero to a healthy node in hours, not weeks
- a wallet integrator can support send-and-track flows from one public API surface
- an explorer or indexer can build against stable historical and indexed data contracts
- an application developer can build on standardized interfaces instead of chain-specific ad hoc conventions
- validators, builders, and infrastructure providers can all identify a rational economic reason to keep participating

TOS should also measure whether its chosen differentiators are becoming real:

- operator workflows become substantially shorter and more automatable release over release
- major wallet and backend integrations can complete against one canonical API surface
- core product surfaces become more coherent rather than more feature-fragmented

## Non-Goals and Rethink Triggers

For the near term, TOS should explicitly avoid optimizing for:

- maximum surface-area growth without workflow closure
- many overlapping primary tools for the same job
- premature expansion into every application category
- complex governance machinery without clear operational value
- convenience APIs whose trust assumptions are undocumented

TOS should also define signals that require a strategic rethink, such as:

- the canonical operator path still requiring expert tribal knowledge
- wallet integrators still needing multiple incompatible API surfaces
- indexers and explorers still rebuilding incompatible data models
- application teams repeatedly inventing custom account, signing, or event conventions
- operators and integrators being unable to predict upgrade impact or compatibility windows
- core participant groups lacking a rational economic reason to stay

Where possible, these should be made quantitative. For example:

- the median time from zero to a healthy node remains above one day for competent operators for two consecutive quarters
- a mainstream wallet integration still requires more than one primary API surface after a published convergence milestone
- automation coverage for critical operator workflows remains below an agreed threshold after a roadmap cycle dedicated to operator maturity
- compatibility-breaking changes to canonical public surfaces occur more than once without a documented deprecation window
- major ecosystem participants cannot identify a clear owner for standards or upgrade decisions during active change

## Final Rule

TOS should not aim to be the most complicated system with the most features.
It should aim to be the most coherent system for users, operators, developers, and integrators.

That is the compass:

> Fewer primary paths. More complete workflows. Stable interfaces. Honest documentation. Reliable operations.
