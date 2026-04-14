# TOS Account and Permission Model

Version: v0.4-spec-draft

## Purpose

This document defines the account, signing, delegation, and permission model for TOS.

It exists because wallet UX, application composability, automation, and safe operator workflows all depend on a clear answer to this question:

> Who is allowed to do what, using which keys, under which rules, and with which user-visible guarantees?

This document is a strategic model document.
It is now written as a standards-oriented draft.
It is not yet a frozen protocol spec, but it is intended to be specific enough to guide:

- RPC design
- wallet design
- SDK type design
- future protocol and account-surface standardization

## Terminology

The following terms are used normatively in this document:

- **Account**: the canonical user-facing authority container recognized by wallets, SDKs, and applications.
- **Default Account Model**: the primary account model that mainstream wallets and SDKs MUST support.
- **Signer**: the authority that approves a transaction or delegated action.
- **Submitter**: the actor that broadcasts a signed transaction.
- **Fee Payer**: the actor whose balance funds execution.
- **Delegation**: a bounded grant of authority from one principal to another.
- **Session Permission**: a short-lived delegated authority intended for limited interaction.
- **Agent Permission**: a delegated authority intended for automation or programmatic action.
- **Capability Discovery**: the machine-readable way to determine which account behaviors and permission features are supported.

## Normative Language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as normative requirements for future TOS standards and implementations.

## Scope

This document should eventually define:

- account model boundaries
- signing and submission semantics
- delegated permission semantics
- session and agent permission semantics
- sponsorship / fee-payer semantics if supported
- how these decisions surface in wallets, SDKs, RPCs, and contracts

## First-Principles Questions

The final model must answer:

1. What is an account in TOS?
2. Which actions require owner authorization?
3. Which actions can be delegated?
4. How are session or temporary permissions represented?
5. How do automated agents act safely on behalf of users?
6. Can one actor pay fees for another, and if so under what rules?
7. Which guarantees must be stable across wallets, SDKs, and applications?

## Design Goals

The account and permission model should produce:

- predictable wallet behavior
- safe delegation
- low-friction automation
- explicit permission boundaries
- composable application standards
- machine-readable semantics for signing and submission

## Recommended Baseline Direction

The baseline direction for TOS should be:

- one canonical account and signing model for mainstream integrations
- explicit delegated permissions instead of wallet-specific hidden behavior
- session and agent permissions treated as first-class standards, not ad hoc app conventions
- machine-readable signing, submission, and authorization semantics
- conservative defaults for sponsorship and delegation

TOS should prefer one strong default path over many loosely compatible patterns.

## Proposed Baseline Model

The proposed baseline model for TOS is:

- one canonical default externally owned account model for mainstream wallets
- one canonical transaction signing payload model
- one canonical submission model that distinguishes:
  - signer
  - submitter
  - fee payer
- one standard delegation model with explicit scope, expiry, and revocation
- one standard session / agent model for limited automation
- sponsorship deferred until the base account model is stable

This baseline is intended to optimize for:

- wallet portability
- SDK portability
- low ambiguity in public RPCs
- safe application automation
- predictable user-facing authorization semantics

## v1 Normative Decisions

Unless superseded by a later approved revision, the v1 baseline for TOS is:

1. TOS MUST define one canonical Default Account Model for mainstream user wallets and SDKs.
2. TOS MUST define one canonical signing payload model for mainstream transaction authorization.
3. TOS MUST distinguish signer, submitter, and fee payer as separate logical roles in public standards, even when the common case collapses them into one actor.
4. TOS MUST define delegation as an explicit, inspectable, bounded authorization object.
5. TOS MUST define session and agent permissions as constrained forms of delegation rather than unrelated wallet-specific mechanisms.
6. Sponsorship and distinct fee-payer semantics MUST be treated as deferred from the base v1 standard unless a later revision explicitly promotes them.

These decisions are the baseline assumptions for:

- public RPC surfaces
- wallet and SDK standards
- account capability discovery
- future contract and application standards

## Non-Goals

The model should not optimize for:

- wallet-specific hidden behavior
- ad hoc permission semantics per application
- invisible delegation rules
- complex smart-account behavior without a standard surface

## Core Design Areas

### 1. Account Model

This section should define:

- whether accounts are basic, programmable, or both
- the relationship between account identity and executable logic
- whether account abstraction is native, layered, or deferred

Open questions:

- Is there one default account model or multiple classes?
- Which behaviors are protocol-level versus wallet-level?
- How much account behavior is standardized?

Decisions:

- `TBD`

Recommended options:

- Option A: one canonical default account model, with room for advanced programmable variants later
- Option B: multiple equally primary account models from the start

Recommended direction:

- Prefer Option A.
- The ecosystem should converge around one mainstream account model before expanding variants.

Proposed baseline:

- TOS should define one canonical default account model for mainstream user wallets.
- That model should support:
  - deterministic ownership semantics
  - replay-safe transaction authorization
  - explicit nonce / seqno or equivalent freshness semantics
  - future compatibility with delegated and session permissions

Implications:

- wallets should not need to detect multiple equally-primary user account standards
- public RPCs should assume one default account model unless a request explicitly targets an advanced variant
- advanced account variants may exist later, but they should be additive rather than foundational

Normative baseline:

- The Default Account Model MUST be the only account model required for mainstream wallet compatibility.
- Advanced account models MAY exist, but they MUST NOT replace or fragment the default user-facing path.
- Capability discovery MUST make the difference between default and advanced account models explicit.

### 2. Signing Model

This section should define:

- what exactly is signed
- how signatures bind to chain, account, nonce, and fee semantics
- how wallets expose signing to users and integrators
- how offline signing should work

Open questions:

- What are the canonical signing payloads?
- How do signatures bind to replay protection?
- Which signature schemes are standard user-facing schemes?

Decisions:

- `TBD`

Recommended options:

- Option A: one canonical signing payload model with explicit replay protection and chain binding
- Option B: multiple signing payload conventions depending on wallet or app type

Recommended direction:

- Prefer Option A.
- Wallet and SDK fragmentation starts here if this is left loose.

Proposed baseline:

- TOS should standardize one canonical signing payload format for normal user transactions.
- The signing payload should bind at minimum:
  - chain identity
  - account identity
  - authorization scope
  - freshness / replay protection field
  - fee or fee intent where relevant

Minimum rule:

- two compliant wallets signing the same logical transaction should produce signatures over the same canonical payload semantics, even if internal UX differs.

Implications:

- JSON-RPC transaction-building methods should expose enough structure for offline signing and deterministic signing verification
- SDKs should not invent wallet-specific payload encodings

Normative baseline:

- A canonical signing payload model MUST exist for standard transactions.
- The signing payload MUST bind:
  - chain identity
  - account identity
  - replay-protection / freshness field
  - authorization intent
- Wallets and SDKs MUST NOT silently substitute incompatible signing semantics for the same logical transaction type.

### 3. Submission Model

This section should define:

- who submits transactions
- whether signer and submitter may differ
- how transactions are tracked from estimate to send to confirmation
- what semantics wallets and SDKs can rely on

Open questions:

- Does submission require the same actor that signed?
- How should relayed or delegated submission behave?
- Which submission states must be observable via public APIs?

Decisions:

- `TBD`

Recommended options:

- Option A: explicitly separate signer, submitter, and fee payer roles in the public model
- Option B: treat submission implicitly as “the signer sends”

Recommended direction:

- Prefer Option A in the standard, even if the common case collapses the roles into one actor.

Proposed baseline:

- TOS should explicitly separate:
  - signer: the authority approving the action
  - submitter: the actor broadcasting the transaction
  - fee payer: the actor funding execution, if different

Default case:

- in the default wallet flow, signer and submitter will usually be the same entity, and fee payer will usually be the same account

But the model should remain explicit so that:

- relaying
- queued submission
- delegated broadcasting
- future sponsorship

can be represented without redefining transaction semantics.

Normative baseline:

- Public standards MUST model signer, submitter, and fee payer as distinct roles.
- The default wallet flow MAY use the same actor for all three roles.
- Public APIs SHOULD expose enough structure that relayed or delegated submission does not require redefining the transaction model.

### 4. Delegated Permissions

This section should define:

- what permissions can be delegated
- how delegation scope is represented
- how delegation is revoked
- how delegated actions are exposed to users and applications

Open questions:

- Can delegation be amount-limited, target-limited, or time-limited?
- Which delegated actions are safe enough for common use?
- What minimum metadata must be visible in wallets and SDKs?

Decisions:

- `TBD`

Recommended options:

- Option A: standard delegation objects with explicit scope, expiry, and revocation
- Option B: application-defined delegation semantics with no canonical model

Recommended direction:

- Prefer Option A.
- Delegation should be portable across wallets and SDKs where possible.

Proposed baseline:

- delegation should be an explicit authorization object with:
  - subject
  - scope
  - optional target restrictions
  - optional amount or rate limits
  - expiry
  - revocation capability

Recommended minimum delegation scopes:

- submit-only
- spend within bounded limit
- call-contract within bounded scope
- session-limited interaction permission

Rules:

- delegation must be inspectable
- delegation must be revocable
- delegation must not be implicit side state hidden inside one wallet implementation

Normative baseline:

- Delegation MUST be explicit.
- Delegation MUST have bounded scope.
- Delegation MUST support expiry or an equivalent bounded-validity mechanism.
- Delegation MUST support revocation.
- Delegation semantics MUST be machine-readable enough for wallets and SDKs to inspect and display meaningfully.

### 5. Session and Agent Permissions

This section should define:

- temporary session permissions
- automated agent permissions
- expiration and revocation
- UI and API expectations around limited authority

Open questions:

- Are sessions first-class protocol objects or application-level conventions?
- How are session scopes encoded?
- How are agent permissions audited or displayed?

Decisions:

- `TBD`

Recommended options:

- Option A: explicit session / agent permission classes in the standard model
- Option B: leave sessions to wallet-specific or app-specific conventions

Recommended direction:

- Prefer Option A.
- This is too central to automation and embedded UX to leave fragmented.

Proposed baseline:

- session and agent permissions should be standardized as limited delegations rather than entirely separate authorization universes

Recommended model:

- a session is a short-lived delegated capability
- an agent is a named or typed delegated capability intended for automation

Both should support:

- explicit scope
- expiry
- revocation
- bounded authority

Recommended v1 boundary:

- standardize the model and public semantics first
- keep the number of authority classes small
- avoid trying to solve every automation use case in v1

Normative baseline:

- Session permissions MUST be modeled as constrained delegations.
- Agent permissions MUST be modeled as constrained delegations.
- Session and agent permissions MUST NOT silently escalate to owner-equivalent authority.
- Wallets and SDKs SHOULD expose bounded authority, expiry, and revocation clearly when these permissions exist.

### 6. Sponsorship and Fee Payer Semantics

This section should define:

- whether a fee payer may differ from the logical actor
- whether sponsored transactions exist
- how sponsored flows are represented in wallets and APIs
- how abuse is controlled

Open questions:

- Is fee sponsorship part of the base model or a later extension?
- What user guarantees are required if sponsorship exists?
- Which trust assumptions must be explicit?

Decisions:

- `TBD`

Recommended options:

- Option A: sponsorship is part of the standard model from the start
- Option B: sponsorship is explicitly deferred and only introduced after the base model is stable

Recommended direction:

- Prefer Option B unless there is an immediate product need that cannot be met otherwise.

Proposed baseline:

- sponsorship should be explicitly out of the base v1 account model
- the standard should reserve vocabulary for a future distinct fee payer
- the default public transaction semantics should assume self-paid execution

Reason:

- sponsorship adds trust, abuse, UX, and API complexity
- it should be introduced only after the base account, signing, and delegation semantics are stable

Normative baseline:

- Sponsorship is out of scope for the base v1 account standard.
- Public transaction semantics MUST remain valid without a distinct fee payer.
- Future sponsorship support, if added, MUST preserve backward-compatible interpretation of signer and submitter roles.

### 7. Smart Account and Contract Integration

This section should define:

- how programmable account behavior interacts with the permission model
- which wallet behaviors are standardized
- how contracts can depend on account semantics safely

Open questions:

- What minimum smart-account conventions should be standardized?
- How should applications discover account capabilities?
- Which account features must be visible through RPC and SDK surfaces?

Decisions:

- `TBD`

Recommended options:

- Option A: standardize a minimum smart-account capability surface
- Option B: let every contract and wallet define account capability semantics independently

Recommended direction:

- Prefer Option A.
- Applications need a discoverable minimum contract for account behavior.

Proposed baseline:

- TOS should standardize a minimum capability surface for programmable accounts or smart accounts

Minimum discovery goals:

- whether the account is standard-default or advanced
- whether delegated permissions are supported
- whether session permissions are supported
- which signing / authorization version applies

This discovery surface should be available through stable APIs rather than application-specific heuristics.

Normative baseline:

- Account capability discovery MUST exist for public integrations.
- Capability discovery MUST distinguish, at minimum:
  - default versus advanced account model
  - delegation support
  - session support
  - authorization/signing version

## Product-Surface Implications

The final model must map directly to:

- wallet send and signing UX
- JSON-RPC request shapes
- transaction tracking semantics
- SDK abstractions
- contract interface standards
- account inspection APIs

This section should eventually provide that mapping.

Initial mapping:

- wallets need canonical signing and authorization flows
- JSON-RPC needs canonical transaction-build and submission semantics
- SDKs need stable abstractions for signer, submitter, session, and delegation
- applications need a portable expectation for account capability discovery
- operator and governance tooling need explicit authority semantics

Concrete implications:

- wallets need one canonical send / sign / submit flow for mainstream accounts
- RPC needs stable request fields for:
  - transaction construction
  - signature attachment
  - submission
  - tracking
- SDKs need a portable representation of:
  - account type
  - signing payload
  - delegation object
  - session capability
- explorers and operator tools need inspectable account authority metadata where relevant

## Normative Object Model

The following conceptual objects SHOULD become the basis for future API and SDK schemas.

### AccountCapability

Minimum fields:

- `account_model`
- `authorization_version`
- `supports_delegation`
- `supports_sessions`
- `supports_agents`
- `supports_sponsorship`

### DelegationGrant

Minimum fields:

- `grantor`
- `grantee`
- `scope`
- `constraints`
- `expiry`
- `revocation_reference`

### SessionCapability

Minimum fields:

- `session_id`
- `principal`
- `scope`
- `expiry`
- `revocable`

### AgentCapability

Minimum fields:

- `agent_id`
- `principal`
- `scope`
- `constraints`
- `expiry`
- `revocable`

These names are conceptual and MAY evolve, but their semantics SHOULD remain stable once standardized.

## Security Requirements

The final model should explicitly define:

- replay protection expectations
- revocation semantics
- expiration semantics
- failure handling for delegated actions
- what must be verifiable by wallets and applications

Security requirements:

- `TBD`

Minimum expected guarantees:

- replay protection must be explicit and standard
- delegation must be scope-limited and revocable
- session permissions must be time-bounded or otherwise safely constrained
- agent permissions must be inspectable
- sponsorship must never obscure who is authorizing versus who is paying

Recommended additional guarantees:

- delegated permissions must fail closed when expired or malformed
- session permissions must be visibly bounded in APIs and wallet UX
- agent permissions must not silently escalate into owner-equivalent authority

Normative baseline:

- Expired permissions MUST be invalid.
- Malformed permissions MUST fail closed.
- Revoked permissions MUST NOT remain usable through client-side ambiguity.
- Public APIs SHOULD make authority boundaries inspectable enough for wallets and operators to reason about them safely.

## Standardization Boundaries

This section should define which parts are:

- protocol-level standards
- wallet-facing standards
- SDK-facing standards
- recommended conventions rather than mandatory behavior

Boundaries:

- Protocol-level standards SHOULD define:
  - role semantics
  - signing semantics
  - replay-protection semantics
  - minimum delegation semantics
- Wallet-facing standards SHOULD define:
  - user-visible capability interpretation
  - display and confirmation expectations
- SDK-facing standards SHOULD define:
  - type shapes
  - field semantics
  - portability guarantees
- Application conventions MAY extend the model, but they MUST NOT redefine canonical baseline semantics for default wallets and SDKs.

## Metrics

The final version should define metrics such as:

- number of account models a wallet integrator must support
- number of signing flows required for mainstream integration
- degree of delegation/session portability across wallets and SDKs
- percentage of application use cases covered by standardized permission semantics

Metrics:

- `TBD`

Recommended initial metrics:

- one default account model required for mainstream integration
- one canonical signing payload model per mainstream transaction family
- zero wallet-specific hidden delegation semantics in canonical public flows
- explicit capability discovery available through at least one stable public API surface

## Open Decisions

Initial open decisions:

1. Which exact replay-protection primitive becomes the canonical freshness field?
2. Which delegated scopes are mandatory in v1 versus optional later?
3. How much of session and agent semantics are protocol-native versus standard-convention-native?
4. Which APIs expose account capability discovery?
5. When sponsorship is added later, how is the fee payer represented without breaking the v1 signing model?

## Draft Decision Checklist

Before moving this document to v1.0, TOS leadership should explicitly decide:

- default account model
- signing and replay model
- submission role model
- delegation scope model
- session and agent permission model
- sponsorship posture

## v1 Non-Goals

The v1 account and permission standard explicitly does not attempt to solve:

- every advanced smart-account model
- every possible agent workflow
- protocol-native sponsorship in the base release
- application-specific policy languages
- wallet-specific convenience behaviors masquerading as standards

## Proposed v1 Decisions

Unless later review rejects them, the proposed v1 decisions are:

1. One canonical default account model
2. One canonical signing payload model
3. Explicit signer / submitter distinction in standards
4. Explicit delegation objects with expiry and revocation
5. Session and agent permissions defined as constrained delegation classes
6. Sponsorship deferred from the base v1 standard

## Implementation Consequences

If this baseline is adopted, future engineering work should include:

- wallet-facing RPC surface updates to reflect signer / submitter / fee semantics clearly
- SDK type definitions for delegation and session capabilities
- account-capability discovery fields in public API surfaces
- operator and explorer support for inspecting delegation-relevant state
- future standards documents that freeze:
  - account type identifiers
  - signing payload format
  - delegation schema
  - session / agent schema

## Open Implementation Hooks

The next engineering-facing documents should derive from this draft and define:

- canonical RPC schema for account capability discovery
- canonical RPC schema for signing / submission role separation
- SDK type definitions for DelegationGrant, SessionCapability, and AgentCapability
- wallet-facing signing payload serialization rules
- explorer / operator inspection rules for permission-relevant state

## Acceptance Criteria

This document reaches v1.0 when:

- the default account model is explicit
- signing and submission semantics are explicit
- delegated, session, and agent permission semantics are explicit
- sponsorship semantics are explicit or explicitly out of scope
- wallet, RPC, and SDK implications are mapped clearly
- ecosystem participants can build against one canonical permission model instead of inventing their own
