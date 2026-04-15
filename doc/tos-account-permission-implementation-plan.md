# TOS Account and Permission Implementation Plan

Version: v0.1

## Purpose

This document turns:

- `doc/tos-account-permission-model.md`
- `doc/tos-account-permission-api-draft.md`

into an implementation plan that is concrete enough for engineering work.

The goal is to answer:

> Which parts can be implemented now, where should they live, what are their data sources, and which parts must remain deferred until protocol or product decisions are finalized?

This document is intended to be actionable for coding work in:

- `~/tos`
- `~/tos/tosctl`

## Scope

This plan covers the first implementation wave for account and permission surfaces:

- account capability discovery
- authorization role modeling
- transaction intent / signing / submission flow separation
- preparatory interfaces for delegation, session, and agent permissions

This plan does not attempt to fully implement:

- protocol-native sponsorship
- a complete smart-account framework
- protocol-native delegation/session storage if the chain does not yet expose it

## Implementation Principles

1. Do not invent fake on-chain semantics where the protocol does not yet have them.
2. Prefer explicit inspection surfaces over hidden wallet logic.
3. Prefer node-native or node-derived truth over sidecar-only truth.
4. Separate:
   - persisted protocol/account state
   - node/API-derived views
   - transaction-scoped temporary objects
5. Defer features that require protocol-level semantics not yet frozen.

## Object Classification

The five proposed objects do not all have the same implementation shape.

### 1. `account.capability`

Classification:

- node/API-derived view

Meaning:

- current machine-readable description of what an account supports

Primary source candidates:

- account state
- code hash / account model detection
- known account-standard registry or capability rules

Should it be persisted directly on chain?

- not required for v1

### 2. `account.authorizationRoles`

Classification:

- transaction-scoped temporary object

Meaning:

- description of who signs, who submits, and who pays for a particular action

Primary source candidates:

- transaction intent object
- submission request object

Should it be persisted directly on chain?

- no

### 3. `account.delegationGrant`

Classification:

- deferred persisted state model unless a standard source already exists

Meaning:

- explicit delegation record

Primary source candidates:

- future protocol/account standard
- future smart-account standard
- future indexer-backed standardized view

Should it be implemented now?

- inspection scaffolding may be implemented
- real semantics should be deferred unless a concrete standard state source exists

### 4. `account.sessionCapability`

Classification:

- persisted `account_standard` state model where a standard source exists; otherwise deferred or indexed

Meaning:

- short-lived delegated authority

Primary source candidates:

- future account standard
- future session authorization standard

Should it be implemented now?

- yes, where a concrete `account_standard` source exists
- otherwise stable inspection/error behavior only

### 5. `account.agentCapability`

Classification:

- persisted `account_standard` state model where a standard source exists; otherwise deferred or indexed

Meaning:

- automation-oriented delegated authority

Primary source candidates:

- future account / permission standard
- future indexed view

Should it be implemented now?

- yes, where a concrete `account_standard` source exists
- otherwise stable inspection/error behavior only

## Implementation Decision

The first implementation wave should implement only the objects and methods that have defensible data sources now.

### Implement now

- ✅ `account.capability`
- ✅ `account.authorizationRoles` as an embedded typed sub-object inside transaction-building and submission surfaces
- ✅ `buildTransactionIntent`
- ✅ `getSigningPayload` as a wrapper over an already-defined canonical signed-message representation
- ✅ `submitSignedTransaction` as a wrapper over the existing signed-message submission path

### Implement partially now

- ✅ RPC surfaces added with source-aware structured responses for:
  - `getAccountDelegations`
  - `getAccountSessions`
  - `getAccountAgents`
- ✅ `getAccountAgents` has a first real `account_standard` implementation for `advanced.wallet.multisig`
  - source tier: `account_standard`
  - object family: `account.agentCapability`
  - semantics: multisig owners are exposed as bounded `agent_execution` principals with threshold constraints
- ✅ `getAccountDelegations` has a first real `account_standard` implementation for `advanced.wallet.restricted`
  - source tier: `account_standard`
  - object family: `account.delegationGrant`
  - semantics: the restricted wallet vesting schedule is exposed as a `bounded_transfer` delegation with time-based value constraints
- ✅ `getAccountDelegations` has a second real `account_standard` implementation for `contract.pool.nominator`
  - source tier: `account_standard`
  - object family: `account.delegationGrant`
  - semantics: nominators are exposed as `bounded_transfer` delegators with stake-based constraints; withdraw requests materialize as `revoked` status
- ✅ documentation and SDK type placeholders

### Defer full implementation

- broader real state-backed `getAccountDelegations` coverage beyond `advanced.wallet.restricted` and `contract.pool.nominator`
- broader real state-backed `getAccountAgents` coverage beyond `advanced.wallet.multisig`

Reason:

- implementing broader delegation/agent coverage requires additional account standards

### Later standards-and-implementation stage

The following work is intentionally outside the current implementation baseline and should be treated as future-standard work:

- additional `account_standard` permission-read models for more account families
- a mutable session account standard with real `grantAccountSession` / `revokeAccountSession` semantics
- a mutable agent account standard with real `grantAccountAgent` / `revokeAccountAgent` semantics
- broader post-mutation lifecycle UX beyond the current preview/result contract

This later stage is expected to require:

- new or revised smart-contract/account standards
- corresponding node-side account-model detection and inspection handlers
- lifecycle mutation semantics implemented at the account-standard layer
- fixture, smoke, and operator-path coverage for each new supported model

Important boundary:

- these items are not blocked by the current RPC shape
- they are blocked by the absence of mutable account-standard semantics in the underlying contracts
- therefore they MUST be tracked as future standards work, not as unfinished baseline implementation debt

Additional rule:

- The initial transaction surfaces MUST NOT introduce a second independent transaction encoding or submission pipeline
- The initial signing and submission methods MUST reuse existing canonical signed-message / message-BOC semantics where possible

## Repository Ownership

### `~/tos`

Owns:

- JSON-RPC methods
- node-native or node-derived capability discovery
- transaction intent and signing-payload RPC surfaces
- signed submission RPC surface
- any account-capability detection logic

### `~/tos/tosctl`

Owns:

- operator and developer CLI wrappers around these APIs
- human-facing inspection commands
- JSON output and automation UX

### Not yet owned by either implementation

- final delegation/session/agent protocol semantics
- final sponsorship semantics

These require further model/spec decisions first.

## Initial Transaction-Surface Targets

### Target A. `getAccountCapability`

Status:

- ✅ implemented

Purpose:

- expose a stable machine-readable capability descriptor for an account

Implementation location:

- `~/tos/validator-engine`

Suggested method:

- JSON-RPC: `getAccountCapability`

Suggested REST path:

- `GET /getAccountCapability`
- `POST /getAccountCapability`

Input:

- `address`
- optional `seqno`

Output shape:

- `account.capability`

Minimum fields for v1:

- `@type`
- `address`
- `account_model`
- `authorization_version`
- `supports_delegation`
- `supports_sessions`
- `supports_agents`
- `account_state`
- `revision`

Optional / experimental field:

- `supports_sponsorship`

Initial data-source strategy:

- parse account address and state
- inspect code hash and known account-model signatures
- derive support flags conservatively

v1 rules:

- unsupported capabilities MUST default to `false`
- unknown advanced account models MUST be surfaced explicitly rather than guessed
- the API MUST avoid claiming support for delegation/session/agent unless that support is actually known
- sponsorship support MUST NOT be claimed as a stable v1 capability unless a later standard revision defines it concretely

Initial implementation note:

- this method is primarily a derived inspection method, not a protocol mutation

### Target B. `buildTransactionIntent`

Status:

- ✅ implemented

Purpose:

- create a canonical machine-readable transaction intent before signing

Implementation location:

- `~/tos/validator-engine`

Suggested method:

- JSON-RPC: `buildTransactionIntent`

Suggested REST path:

- `POST /buildTransactionIntent`

Input:

- `from`
- action or payload fields
- fee intent fields
- optional capability/account-model hint

Output shape:

- `transaction.intent`

Minimum fields for v1:

- `@type`
- `from`
- `account_model`
- `authorization_version`
- `action`
- `authorization_roles`
- `fee_intent`
- `replay_protection`

Initial data-source strategy:

- use request data + account capability discovery + chain context
- do not require protocol-native delegation/session state for the base version

v1 rules:

- signer / submitter / fee payer fields must be explicit in the intent object
- the default intent may set them all equal when no advanced flow is requested
- the object must be sufficient to derive a deterministic signing payload

### Target C. `getSigningPayload`

Status:

- ✅ implemented

Purpose:

- return the canonical payload that a wallet or SDK should sign for a transaction intent

Implementation location:

- `~/tos/validator-engine`

Suggested method:

- JSON-RPC: `getSigningPayload`

Suggested REST path:

- `POST /getSigningPayload`

Input:

- `transaction.intent` object or equivalent fields

Output shape:

- `transaction.signingPayload`

Minimum fields for v1:

- `@type`
- `payload_version`
- `payload_encoding`
- `payload`
- `chain_id`
- `replay_protection`

Initial data-source strategy:

- pure derivation from the canonical intent object
- the resulting payload MUST map onto an already-defined signed-message representation accepted by the existing node send path

v1 rules:

- identical logical intents MUST yield identical signing payload semantics
- the payload MUST bind chain identity and replay protection
- the method MUST be usable for offline signing flows
- the method MUST NOT invent a new transaction binary format in the initial implementation
- the payload format exposed in the initial implementation MUST be explicitly documented as mapping to the existing canonical signed-message / message-BOC representation

### Target D. `submitSignedTransaction`

Status:

- ✅ implemented

Purpose:

- submit a signed transaction using the canonical submission surface

Implementation location:

- `~/tos/validator-engine`

Suggested method:

- JSON-RPC: `submitSignedTransaction`

Suggested REST path:

- `POST /submitSignedTransaction`

Input:

- signed payload that corresponds to the initial canonical signed-message representation
- optional submitter metadata

Output shape:

- `transaction.submissionResult`

Minimum fields for v1:

- `@type`
- `accepted`
- `transaction_hash` or equivalent tracking reference
- `submission_id` or equivalent request trace id
- `authorization_roles`

Initial data-source strategy:

- reuse or wrap existing send path where possible
- do not duplicate low-level send implementation unnecessarily

v1 rules:

- this method should be the standard signed-submission surface
- it should not force signer and submitter to be implicitly identical in the model
- it MUST submit through the existing canonical send path rather than introducing a second transaction-ingestion pipeline
- if the signed artifact cannot be mapped to the existing canonical send path, the method MUST fail with a structured error rather than guessing a translation

## Remaining Permission-Semantics Work

After the initial account-capability and transaction intent/signing/submission surfaces are stable, the next implementation wave adds real, inspectable, revocable permission semantics for:

- delegations
- sessions
- agents

This work is inspired by the direction of Ethereum account-abstraction ecosystems:

- explicit account abstraction roles rather than implicit wallet behavior
- explicit delegation and permission objects rather than hidden app-specific state
- modular or extensible account capability discovery

But TOS MUST preserve one important architectural rule:

- TOS MUST continue using one canonical transaction submission path rather than introducing a second independent mempool or submission pipeline

### Detailed Design Goals

1. Make delegation/session/agent state real and inspectable rather than deferred placeholders.
2. Keep permission semantics machine-readable and portable across wallets, SDKs, and applications.
3. Preserve the transaction-model separation of:
   - signer
   - submitter
   - fee payer
4. Avoid wallet-specific hidden permission state.
5. Extend the canonical transaction model instead of replacing it.

### Normative Direction

The full implementation plan SHOULD follow these design choices:

- `account.delegationGrant` becomes a real standard object, not just a draft schema
- `account.sessionCapability` is a constrained delegation class
- `account.agentCapability` is a constrained delegation class intended for automation
- all three MUST remain inspectable through public APIs
- all three MUST support bounded scope, `expires_at` or equivalent bounded-validity semantics, and revocation
- all three MUST fit the same canonical transaction authorization model already introduced by the initial transaction surfaces

### Permission Model

#### 1. Delegation

`account.delegationGrant` should become the canonical persisted or canonically indexed authorization object.

Minimum semantics:

- `id`
- `grantor`
- `grantee`
- `scope`
- `constraints`
- `created_at`
- `expires_at`
- `revoked_at`
- `revocable`
- `revocation_reference`
- `status`

Frozen canonical scope vocabulary:

- `submit_only`
- `bounded_transfer`
- `bounded_contract_call`
- `session_issuance`
- `agent_execution`

Frozen canonical constraints:

- `target_allowlist`
- `max_value`
- `max_uses`
- `not_before`
- `expires_at`

Extension rule:

- When an `account_standard` source exposes semantics beyond the canonical constraints, those details MUST be placed in a `constraints_extensions` sibling field, not mixed into `constraints`.
- `constraints` MUST contain only canonical vocabulary fields.
- `constraints_extensions` SHOULD include an `account_model` field.

Rules:

- delegation MUST be explicit
- delegation MUST be bounded
- delegation MUST be revocable
- delegation MUST fail closed when expired or malformed

#### 2. Sessions

`account.sessionCapability` should become a short-lived constrained delegation object.

Minimum semantics:

- tied to a principal or session key
- explicitly scoped
- constraints-aware
- `created_at`
- explicitly expiring
- `revoked_at`
- revocable
- inspectable through public APIs

Recommended initial session scopes:

- `bounded_transfer` with tight constraints
- `bounded_contract_call` with tight constraints
- `submit_only` within a bounded interaction window

Rules:

- session permissions MUST NOT silently become owner-equivalent authority
- wallets SHOULD display session scope and `expires_at` or equivalent bounded-validity semantics clearly

#### 3. Agents

`account.agentCapability` should become an automation-oriented constrained delegation object.

Minimum semantics:

- bound to a named or typed agent principal
- bound to explicit scopes and constraints
- `created_at`
- `revoked_at`
- revocable
- inspectable

Recommended initial agent constraints:

- target allowlist
- action class allowlist
- value or rate limits
- `expires_at`

Rules:

- agent permissions MUST remain bounded
- agent permissions MUST be auditable enough for wallets and operators to inspect
- agent permissions MUST NOT silently escalate to owner-equivalent authority

### Additional API Surfaces

The following methods should move from deferred placeholders to real implementations:

- `getAccountDelegations`
- `getAccountSessions`
- `getAccountAgents`

Read-only query contract:

- these methods MUST be inspection-only
- these methods MUST NOT mutate permission state
- these methods MUST return machine-readable objects whose shape matches the frozen object model
- these methods MUST distinguish:
  - supported semantics with zero results
  - unsupported semantics for the account model
  - deferred semantics with no frozen source tier

Lifecycle methods SHOULD be introduced only after the underlying persisted semantics are frozen:

- `grantAccountDelegation`
- `revokeAccountDelegation`
- `grantAccountSession`
- `revokeAccountSession`
- `grantAccountAgent`
- `revokeAccountAgent`

These lifecycle methods MUST NOT be implemented before the underlying state and signing semantics are standardized.

### Frozen State Strategy

The permission-state source is now frozen for implementation.

Canonical source tiers, in descending preference:

1. `protocol`
2. `account_standard`
3. `indexed`
4. `deferred`

Rules:

- real permission inspection methods MUST only return stable permission objects when the source tier is `protocol`, `account_standard`, or `indexed`
- implementations MUST NOT rely on wallet-private hidden state as canonical truth
- if `indexed` is used, the node implementation MUST document freshness and trust assumptions
- if a given account model does not expose permissions through a frozen source tier, capability discovery MUST surface `*_source = "deferred"` and inspection methods MUST fail honestly

### Capability Discovery Extensions

`getAccountCapability` should later expand to report not only support flags, but also the source and maturity of permission semantics.

Recommended additional fields:

- `delegation_source`
- `session_source`
- `agent_source`
- `capability_maturity`

Where:

- source indicates whether semantics come from protocol state, standardized smart-account state, or indexed derived state
- maturity indicates whether the capability is stable, supported, or experimental

Required capability behavior for real permission inspection:

- if `delegation_source = "deferred"`, `getAccountDelegations` MUST fail with a structured unavailable/deferred error
- if `session_source = "deferred"`, `getAccountSessions` MUST fail with a structured unavailable/deferred error
- if `agent_source = "deferred"`, `getAccountAgents` MUST fail with a structured unavailable/deferred error
- if the source is `protocol`, `account_standard`, or `indexed`, the corresponding method MUST return a real list, including an empty list when the feature is supported but no live objects exist

### Transaction Semantics Extensions

Permission-bearing semantics MUST extend the initial transaction model rather than replace it.

That means:

- `buildTransactionIntent` MAY accept delegation/session/agent references once those references have real semantics
- `getSigningPayload` MUST continue producing one canonical signing representation for the same logical transaction family
- `submitSignedTransaction` MUST continue using the canonical send path

The implementation plan MUST NOT adopt a separate submission pipeline analogous to a second public mempool just for account abstraction.

### Permission-Bearing Transaction Reference Design

When real permission inspection exists for an account model, `buildTransactionIntent` MAY accept optional permission references:

- `delegation_ref` — stable identifier of a delegation grant to authorize the transaction
- `session_ref` — stable identifier of a session capability
- `agent_ref` — stable identifier of an agent capability

#### Validation Rules

When a permission reference is provided:

1. The RPC layer MUST resolve the referenced permission using the corresponding inspection method.
2. The resolved permission MUST have `status = "active"`.
3. The resolved permission's `scope` MUST cover the requested action.
4. The resolved permission's `constraints` MUST not be violated by the transaction parameters.
5. If validation fails, the method MUST fail with a structured permission error (`DELEGATION_EXPIRED`, `AGENT_SCOPE_VIOLATION`, etc.).

#### Current Implementation Status

In the initial implementation, all permission references are rejected with `FEATURE_DEFERRED`. This is correct per the plan's MAY rule. Permission-bearing transaction support will be enabled incrementally as lifecycle and validation paths mature.

### Permission Error Model

In addition to the initial transaction-surface error codes, implementations should reserve structured errors for:

- `DELEGATION_UNAVAILABLE`
- `DELEGATION_EXPIRED`
- `DELEGATION_REVOKED`
- `SESSION_UNAVAILABLE`
- `SESSION_EXPIRED`
- `AGENT_UNAVAILABLE`
- `AGENT_SCOPE_VIOLATION`
- `PERMISSION_SOURCE_DEFERRED`
- `PERMISSION_SOURCE_UNSUPPORTED`
- `INDEXED_STATE_STALE`

### Frozen Revocation and Status Rules

The following rules are frozen for implementation:

- every permission object MUST have a stable identifier
- every permission object MUST evaluate to exactly one status:
  - `active`
  - `expired`
  - `revoked`
  - `unknown`
- status precedence MUST be:
  1. `revoked`
  2. `expired`
  3. `active`
  4. `unknown`
- `unknown` MUST fail closed for authorization decisions
- `revoked_at` MUST be populated when explicit revocation evidence exists
- `revocation_reference` SHOULD carry the canonical revocation or supersession reference when available

### Permission-Semantics Acceptance Criteria

This part of the implementation plan is complete when:

- ✅ `account.delegationGrant` has real semantics and a real state source (`advanced.wallet.restricted` via `account_standard`)
- ✅ `account.sessionCapability` has either:
  - real semantics and bounded authority for at least one supported account model, or
  - ✅ an explicitly documented deferred status with stable inspection/error behavior until such a source exists
- ✅ `account.agentCapability` has real semantics and bounded authority (`advanced.wallet.multisig` via `account_standard`)
- ✅ `getAccountDelegations` and `getAccountAgents` return real inspectable state where a frozen source exists
- ✅ `getAccountSessions` either returns real inspectable state where a frozen source exists or ✅ returns structured deferred/unsupported results according to the frozen source-tier rules
- ✅ wallets and SDKs can inspect delegation/session/agent state without wallet-specific heuristics (canonical constraints use frozen vocabulary; model-specific details in `constraints_extensions`)
- ✅ permission-bearing transactions still use the same canonical submission path introduced by the initial transaction surfaces

### Read-Only Inspection Method Design

The first real implementations of `getAccountDelegations`, `getAccountSessions`, and `getAccountAgents` MUST follow one shared design.

Required input shape:

- `address`
- optional `include_inactive`
- optional canonical status filter
- optional source-tier override only for debugging or operator inspection, never for default wallet flows

Required output shape:

- top-level list of the corresponding canonical object type
- each returned object MUST include:
  - stable identifier
  - canonical scope
  - canonical constraints
  - bounded-validity fields
  - revocation fields where available
  - canonical status

Required result semantics:

- supported + no objects => empty successful list
- supported + some objects => non-empty successful list
- unsupported for the detected account model => structured `PERMISSION_SOURCE_UNSUPPORTED`
- semantics still deferred => structured `PERMISSION_SOURCE_DEFERRED`
- indexed source unavailable or stale beyond documented freshness window => structured `INDEXED_STATE_STALE`

The methods MUST NOT collapse these cases into one another.

### Source-Tier to Behavior Mapping

#### `protocol`

- read directly from protocol-native or protocol-standardized account state
- returned objects SHOULD be treated as highest-confidence permission truth

#### `account_standard`

- read from standardized account-linked contract/query semantics
- returned objects are canonical if the account model is recognized and the query semantics are frozen

#### `indexed`

- read from a canonically indexed node-derived projection
- implementations MUST document:
  - freshness window
  - lag/staleness behavior
  - whether revocation and expiry can be observed immediately or only after indexing catches up

#### `deferred`

- no real inspection result may be returned
- the corresponding query MUST fail with a structured deferred/unavailable error

### Indexed Freshness Rules

If a permission surface is backed by `indexed` state:

- the node MUST expose or internally enforce a freshness threshold
- stale indexed results MUST NOT be silently returned as if they were current canonical truth
- when freshness cannot be guaranteed, the query MUST fail with `INDEXED_STATE_STALE`
- generic wallets SHOULD avoid treating stale indexed permission state as safely authorizing action

### Query-to-Validation Relationship

Once real permission inspection exists:

- `buildTransactionIntent` MUST use the same frozen scope and status semantics as the inspection methods
- `getSigningPayload` MUST reject references to permissions whose status is:
  - `expired`
  - `revoked`
  - `unknown`
- `submitSignedTransaction` MUST reject signed artifacts that rely on permissions no longer valid under the same semantics

This keeps inspection, intent building, signing, and submission aligned to one authority model.

## Full Implementation Order

Recommended order:

1. Implement the frozen minimum schema for:
   - `account.delegationGrant`
   - `account.sessionCapability`
   - `account.agentCapability`
2. Extend `getAccountCapability` to report permission-source and maturity metadata.
3. Implement read-only inspection methods with full result discrimination:
   - `getAccountDelegations`
   - `getAccountSessions`
   - `getAccountAgents`
4. Add source-tier freshness and staleness handling for any `indexed` implementation path.
5. Add validation and error semantics for permission-bearing references in:
   - `buildTransactionIntent`
   - `getSigningPayload`
   - `submitSignedTransaction`
6. Only after the underlying state model is stable in code, add lifecycle mutation methods:
   - `grant*`
   - `revoke*`
7. Add `tosctl` wrappers and JSON output once the node-side surfaces are stable.

## Repository Ownership for Remaining Permission Semantics

### `~/tos`

Owns:

- persisted or canonically indexed permission-state exposure
- `getAccountDelegations`
- `getAccountSessions`
- `getAccountAgents`
- permission-aware capability discovery
- permission-aware validation in transaction intent / signing / submission flow
- future lifecycle mutation RPCs if standardized

### `~/tos/tosctl`

Owns:

- operator and developer inspection commands for delegations/sessions/agents
- machine-readable CLI output
- guided workflows around grant/revoke only after node-side APIs are stable

### Shared prerequisite

The following inputs are now frozen for implementation:

- canonical source tiers
- canonical scope vocabulary
- canonical constraint vocabulary
- revocation model
- bounded-validity/status model
- permission error semantics

## Suggested File Ownership in `~/tos` for Remaining Permission Semantics

Likely implementation areas:

- `validator-engine/json-rpc-server-accounts.cpp`
  - `getAccountCapability` capability-source and maturity extensions
  - `getAccountDelegations`
  - `getAccountSessions`
  - `getAccountAgents`
- `validator-engine/json-rpc-server-send.cpp`
  - permission-aware `buildTransactionIntent`
  - permission-aware `getSigningPayload`
  - permission-aware `submitSignedTransaction`
- shared helper files
  - permission-source detection
  - delegation/session/agent JSON formatting
  - scope and constraint validation

## Suggested File Ownership in `~/tos/tosctl` for Remaining Permission Semantics

Likely follow-up surfaces:

- `tosctl account delegations`
- `tosctl account sessions`
- `tosctl account agents`
- future:
  - `tosctl account delegation grant`
  - `tosctl account delegation revoke`
  - `tosctl account session grant`
  - `tosctl account session revoke`
  - `tosctl account agent grant`
  - `tosctl account agent revoke`

These mutation wrappers MUST NOT be implemented ahead of the node-side lifecycle APIs.

## Remaining Permission-Semantics Patch Checklist

The following checklist is intended to be concrete enough for coding tasks.

### Step 1. State-source implementation

- ✅ implement capability reporting using one frozen source tier:
  - ✅ `protocol` — returns `PERMISSION_SOURCE_UNSUPPORTED` (no protocol-native permission state exists)
  - ✅ `account_standard` — real implementations for `advanced.wallet.multisig` (agents), `advanced.wallet.restricted` (delegations), and `contract.pool.nominator` (delegations with real status materialization)
  - ✅ `indexed` — returns `INDEXED_STATE_STALE` (no canonical indexed source is configured)
  - ✅ `deferred` — returns `PERMISSION_SOURCE_DEFERRED`
- ✅ document freshness and trust guarantees when `indexed` is used (inline code documentation in `json-rpc-server-account-capability.cpp`)

### Step 2. Shared types

- ✅ add stable JSON builders / structs for:
  - ✅ `account.delegationGrant` — `build_delegation_grant_json()`
  - ✅ `account.sessionCapability` — `build_session_capability_json()` (defined as shared type; no handler invokes it yet because no account model exposes sessions)
  - ✅ `account.agentCapability` — `build_agent_capability_json()`
- ✅ add `capability_maturity` and `*_source` fields to `account.capability`
- ✅ include:
  - ✅ stable id
  - ✅ canonical scope (from frozen vocabulary)
  - ✅ canonical constraints (from frozen vocabulary; model-specific details in `constraints_extensions`)
  - ✅ created/expiry-equivalent/revocation fields (`created_at`, `expires_at`, `revoked_at`)
  - ✅ canonical status

### Step 3. Read-only inspection RPCs

- ✅ implement:
  - ✅ `getAccountDelegations` — real for `advanced.wallet.restricted` and `contract.pool.nominator`, honest error for others
  - ✅ `getAccountSessions` — honest error for all models (no session source exists)
  - ✅ `getAccountAgents` — real for `advanced.wallet.multisig`, honest error for others
- ✅ ensure unsupported account models fail honestly (`PERMISSION_SOURCE_UNSUPPORTED`)
- ✅ ensure empty results are distinguishable from unsupported semantics (empty `[]` vs structured error)
- ✅ ensure `unknown` status is not treated as usable authority
- ✅ ensure deferred source tiers return `PERMISSION_SOURCE_DEFERRED`
- ✅ ensure stale indexed state returns `INDEXED_STATE_STALE`

Status materialization note:

- `advanced.wallet.multisig` can only materialize `status="active"`. It has no on-chain revocation or expiration evidence.
- `advanced.wallet.restricted` can materialize `status="active"` and `status="expired"`. When the vesting reserve reaches 0 (full balance released), the restriction no longer applies and the delegation status becomes `"expired"`.
- `contract.pool.nominator` can materialize `status="active"` and `status="revoked"`. When a nominator has submitted a withdraw request, the delegation status is `"revoked"` (real on-chain revocation evidence).

### Step 4. Freshness and source-tier handling

- ✅ if a permission surface is backed by `indexed`, implement freshness checks — currently all indexed-tier requests fail with `INDEXED_STATE_STALE` (no canonical indexed source is configured)
- ✅ fail closed when freshness guarantees cannot be met
- ✅ surface source-tier metadata through `getAccountCapability` (`delegation_source`, `session_source`, `agent_source`, `capability_maturity`)

### Step 5. Intent/signing/submission validation

- ✅ allow delegation/session/agent references only when backed by real semantics — currently all permission references are rejected with `FEATURE_DEFERRED` (the plan's line 659 says this is MAY, not MUST, for the initial implementation)
- ✅ validate and reject:
  - ✅ permission-bearing requests rejected with `FEATURE_DEFERRED`
  - ✅ distinct `fee_payer` rejected with `FEATURE_DEFERRED`
  - ✅ invalid BOC rejected with `SIGNED_ARTIFACT_INVALID`
  - ✅ unsupported payload encoding rejected with `SIGNED_ARTIFACT_UNSUPPORTED`
- ✅ reject permission-bearing requests that exceed allowed scope — all permission references rejected in initial implementation

### Step 6. Error and testing coverage

- ✅ add structured errors for permission failures — all 15 error codes defined and documented in code
- ✅ add positive-path tests for supported permission-bearing flows (multisig agents, restricted delegations)
- ✅ add explicit negative tests for:
  - ✅ expired permission — `advanced.wallet.restricted` materializes `expired` when vesting reserve reaches 0 (full balance released)
  - ✅ revoked inspection path — `contract.pool.nominator` materializes `revoked` status when on-chain `withdraw_requests` state is present; positive tests validate this from a pre-seeded withdraw fixture
  - ✅ deferred source tier
  - ✅ stale indexed state
  - ✅ unsupported account model
  - ✅ scope violation — `buildTransactionIntent` validates `delegation_ref` against real delegation state; tests cover `DELEGATION_EXPIRED`, `DELEGATION_REVOKED`, `DELEGATION_UNAVAILABLE`, and `DELEGATION_SCOPE_VIOLATION`
- ✅ additional test coverage:
  - ✅ error code prefix format validation
  - ✅ source-tier override behavior
  - ✅ canonical vs. extension constraint separation
  - ✅ schema compliance for frozen fields
  - ✅ nominator pool capability and delegation inspection

### Lifecycle Mutation Method Design

The following design applies to lifecycle mutation RPCs when they are implemented.

#### RPC Surfaces

Six lifecycle methods are planned:

- `grantAccountDelegation` — create a new delegation grant
- `revokeAccountDelegation` — revoke an existing delegation
- `grantAccountSession` — create a new session capability
- `revokeAccountSession` — revoke an existing session
- `grantAccountAgent` — register a new agent capability
- `revokeAccountAgent` — revoke an existing agent

#### Request Shape (grant)

Common fields for all grant methods:

- `address` — the account granting the permission
- `grantee` — the principal receiving the permission
- `scope` — one of the frozen canonical scope values
- `constraints` — canonical constraint fields only
- `expires_at` — optional bounded-validity
- `revocable` — whether the grant supports later revocation

#### Request Shape (revoke)

Common fields for all revoke methods:

- `address` — the account that owns the permission
- `permission_id` — the stable identifier of the permission to revoke

#### Response Shape

All lifecycle methods MUST return the affected permission object in its canonical form (the same shape returned by the corresponding inspection method).

#### State Ownership

Lifecycle mutations do NOT create node-managed state. Instead:

- The RPC layer constructs a transaction message that the target account's smart contract will interpret.
- The contract is the authority for state persistence and validation.
- The RPC layer MUST submit through the existing canonical send path (`liteServer.sendMessage`).
- The RPC layer MAY pre-validate the request (e.g., reject impossible operations for a known account model) but MUST NOT be the source of truth for permission state.

#### Authorization Model

- Only the account owner (or an entity with sufficient authority under the account model) may grant permissions.
- Revocation requires either the original grantor's authority or account-owner-level authority.
- The smart contract enforces these rules; the RPC layer does not independently authorize.

#### Per-Model Lifecycle Capabilities

| Account Model | Agent Lifecycle | Delegation Lifecycle | Session Lifecycle |
| --- | --- | --- | --- |
| `default.wallet.v1` | not supported | not supported | not supported |
| `advanced.wallet.multisig` | **immutable** — owner set is fixed at deployment | not supported | not supported |
| `advanced.wallet.restricted` | not supported | **immutable** — vesting is fixed at deployment | not supported |
| `contract.pool.nominator` | not supported | **deposit/withdraw** — nominators can deposit (grant) and request withdrawal (revoke) | not supported |

When a lifecycle method is called against an account model that does not support it, the method MUST fail with `FEATURE_DEFERRED` or `PERMISSION_SOURCE_UNSUPPORTED`.

When a lifecycle method is called against a model with immutable permissions, the method MUST fail with a structured error explaining that the account model does not support runtime permission changes.

### Step 7. Mutation methods, only if ready

- ✅ design finalized — RPC shapes, authorization model, state ownership, and per-model lifecycle capabilities are documented in the "Lifecycle Mutation Method Design" section above
- ✅ RPC surfaces implemented — 6 lifecycle handlers with real account-model detection (`grantAccountDelegation`, `revokeAccountDelegation`, `grantAccountSession`, `revokeAccountSession`, `grantAccountAgent`, `revokeAccountAgent`)
- ✅ frozen request-shape enforcement — grant handlers validate `address`, `grantee` (`MISSING_GRANTEE`), `scope` (`INVALID_SCOPE` for non-canonical values), `constraints` (`INVALID_CONSTRAINTS` for non-canonical fields), `expires_at`, `revocable`; revoke handlers validate `address`, `permission_id` (`MISSING_PERMISSION_ID`); request validation runs before account-model dispatch
- ✅ response-shape refinement — supported mutation handlers return `lifecycle.mutationResult` with `mutation_intent` and `affected_object_preview` in canonical inspection shape (e.g., `account.delegationGrant` for delegation grant/revoke)
- ✅ `contract.pool.nominator` returns full `lifecycle.mutationResult` with deposit ("d") / withdraw ("w") intent and delegation preview
- ✅ immutable models (`advanced.wallet.multisig`, `advanced.wallet.restricted`) return `LIFECYCLE_IMMUTABLE`
- ✅ unsupported models return `PERMISSION_SOURCE_UNSUPPORTED`
- only after contract-level mutation interfaces are standardized for more models, expand:
  - delegation grant/revoke
  - session grant/revoke
  - agent grant/revoke
- mutation APIs must use the same canonical transaction model and submission path as the initial transaction surfaces

## Required Supporting Types

The first implementation wave should introduce draft type definitions for:

- `account.capability`
- `account.authorizationRoles`
- `transaction.intent`
- `transaction.signingPayload`
- `transaction.submissionResult`

These may begin as:

- internal C++ JSON builder helpers in `~/tos`
- optional client-side typed wrappers in `~/tos/tosctl`

`account.authorizationRoles` MUST NOT be treated as a standalone persisted object or a standalone inspection RPC in the initial implementation.
It exists initially only as a machine-readable nested object inside:

- `transaction.intent`
- `transaction.submissionResult`

## Initial Backend Mapping

To avoid accidental invention of a second transaction model, initial implementations MUST follow this mapping:

### 1. `buildTransactionIntent`

- constructs a canonical machine-readable intent object only
- derives fields from request data, account capability discovery, and current chain context
- MUST NOT introduce new execution semantics beyond what the existing send path already supports

### 2. `getSigningPayload`

- derives a canonical signing payload from `transaction.intent`
- MUST map that payload to the already-supported canonical signed-message / message-BOC representation used by the current node send path
- MUST document which intent fields are represented directly, which are normalized, and which are rejected in the initial implementation

### 3. `submitSignedTransaction`

- accepts only signed artifacts that correspond to the initial canonical signed-message representation
- MUST submit through the existing canonical send path
- MUST reject signed artifacts that imply unsupported advanced account, delegation, session, agent, or sponsorship semantics

### 4. Advanced / later features

- delegation/session/agent references MAY appear only as rejected or explicitly unsupported fields in the initial implementation unless a later standard promotes them
- sponsorship MUST remain out of the base submission model in the initial implementation

## Initial Backend Mapping Table

| Surface | Input basis | Existing backend dependency | Output | Must fail when |
| --- | --- | --- | --- | --- |
| `getAccountCapability` | address, optional seqno | existing account-state lookup + account-model detection | `account.capability` | account model cannot be classified conservatively |
| `buildTransactionIntent` | request fields + chain context + capability discovery | existing chain/account context only | `transaction.intent` | requested semantics exceed current canonical send path |
| `getSigningPayload` | `transaction.intent` | canonical initial intent-to-message mapping | `transaction.signingPayload` | payload cannot be deterministically derived or mapped to current signed-message representation |
| `submitSignedTransaction` | signed artifact + optional submitter metadata | existing canonical send path | `transaction.submissionResult` | signed artifact is invalid or not representable in the current canonical send path |
| `getAccountDelegations` | address, optional filters | frozen permission source tier for delegations | list of `account.delegationGrant` | no frozen source exists for the account model, or indexed state is stale |
| `getAccountSessions` | address, optional filters | frozen permission source tier for sessions | list of `account.sessionCapability` | no frozen source exists for the account model, or indexed state is stale |
| `getAccountAgents` | address, optional filters | frozen permission source tier for agents | list of `account.agentCapability` | no frozen source exists for the account model, or indexed state is stale |

## Suggested File Ownership in `~/tos`

Likely implementation area:

- `validator-engine/json-rpc-server-accounts.cpp`
  - `getAccountCapability`
- `validator-engine/json-rpc-server-send.cpp`
  - `buildTransactionIntent`
  - `getSigningPayload`
  - `submitSignedTransaction`
- shared helper files
  - account model detection
  - authorization-role JSON formatting
  - signing-payload formatting

This is a guidance boundary, not a hard mandate.

## Suggested File Ownership in `~/tos/tosctl`

Likely follow-up surfaces:

- account inspection commands
- JSON output support for account capability
- developer/operator wrappers around intent/signing/submission flow

Examples:

- `tosctl account capability`
- `tosctl tx build-intent`
- `tosctl tx signing-payload`
- `tosctl tx submit-signed`

These are follow-up tasks, not phase-1 blockers.

## Error Policy

For all new methods:

- unsupported semantics MUST return structured errors
- unknown account models MUST be surfaced honestly
- deferred delegation/session/agent methods MUST NOT fabricate empty success as if the feature were implemented

Recommended error cases:

- unsupported account model
- capability unknown
- signing payload cannot be derived
- signed submission invalid
- signed artifact does not match the canonical initial signed-message representation
- feature deferred / not yet available

### Recommended Initial Error Codes

- `ACCOUNT_MODEL_UNSUPPORTED`
- `ACCOUNT_CAPABILITY_UNKNOWN`
- `TRANSACTION_INTENT_UNSUPPORTED`
- `SIGNING_PAYLOAD_UNAVAILABLE`
- `SIGNED_ARTIFACT_INVALID`
- `SIGNED_ARTIFACT_UNSUPPORTED`
- `FEATURE_DEFERRED`

These codes are provisional but SHOULD be used consistently across the initial implementation if new structured errors are introduced.

## Testing Requirements

The initial implementation should include:

- ✅ positive-path tests for `getAccountCapability`
- ✅ positive-path tests for `buildTransactionIntent`
- ✅ positive-path tests for `getSigningPayload`
- ✅ positive-path tests for `submitSignedTransaction`
- ✅ invalid-input coverage
- ✅ stable JSON-shape assertions
- ✅ explicit tests that deferred methods fail honestly if wired

## Delivery Order

Recommended order:

1. ✅ add shared type/JSON builders
2. ✅ implement `getAccountCapability`
3. ✅ implement `buildTransactionIntent`
4. ✅ document the exact initial mapping from intent -> signing payload -> existing canonical signed-message representation
5. ✅ implement `getSigningPayload`
6. ✅ implement `submitSignedTransaction` as a wrapper over the existing send path
7. ✅ add deferred placeholders or explicit non-implementation policy for delegation/session/agent methods
8. ✅ add `tosctl` wrappers (`tosctl tx build-intent`, `tosctl tx signing-payload`, `tosctl tx submit-signed`, `tosctl account capability/delegations/sessions/agents`)

## Acceptance Criteria

The initial transaction surfaces are complete when:

- ✅ `getAccountCapability` returns stable machine-readable capability objects
- ✅ a canonical transaction intent object exists
- ✅ a canonical signing payload can be derived from that intent without inventing a second transaction format
- ✅ a canonical signed-submission surface exists as a wrapper over the existing send path
- ✅ signer / submitter / fee payer roles are explicit in the public model
- ✅ delegation/session/agent methods are either honestly deferred or backed by real semantics
