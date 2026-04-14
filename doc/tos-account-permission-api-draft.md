# TOS Account and Permission API Draft

Version: v0.1-spec-draft

## Purpose

This document translates:

- `doc/tos-account-permission-model.md`

into a machine-facing API draft that can guide:

- JSON-RPC evolution
- wallet integration
- SDK type design
- explorer and operator inspection support

It is not yet a frozen RPC spec.
It is the first implementation-oriented draft of the public account and permission surface.

## Scope

This draft defines candidate public surfaces for:

- account capability discovery
- signer / submitter / fee-payer role modeling
- delegation inspection
- session / agent capability inspection
- transaction build / sign / submit flow separation

This draft does not yet define:

- full sponsorship support
- protocol-level binary encoding details
- smart-account execution internals

## Normative Intent

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** indicate intended requirements for future TOS public standards.

## Public Surface Goals

The public API surface should make these questions answerable without wallet-specific guesswork:

1. What kind of account is this?
2. Which permission features does it support?
3. Who is authorizing this action?
4. Who is submitting it?
5. Who is paying for it?
6. Which delegated/session/agent permissions are in effect?

## Proposed API Objects

### 1. `account.capability`

This object SHOULD be the canonical machine-readable capability descriptor for an account.

Proposed fields:

- `@type`: `account.capability`
- `address`
- `account_model`
- `authorization_version`
- `supports_delegation`
- `supports_sessions`
- `supports_agents`
- `supports_sponsorship`
- `account_state`
- `revision`

Example:

```json
{
  "@type": "account.capability",
  "address": "0:...",
  "account_model": "default.v1",
  "authorization_version": "auth.v1",
  "supports_delegation": true,
  "supports_sessions": true,
  "supports_agents": false,
  "supports_sponsorship": false,
  "account_state": "active",
  "revision": 1
}
```

### 2. `account.authorizationRoles`

This object SHOULD describe the role model used for a transaction or authorization flow.

Proposed fields:

- `@type`: `account.authorizationRoles`
- `signer`
- `submitter`
- `fee_payer`
- `is_self_submitted`
- `is_self_paid`

Example:

```json
{
  "@type": "account.authorizationRoles",
  "signer": "0:...",
  "submitter": "0:...",
  "fee_payer": "0:...",
  "is_self_submitted": true,
  "is_self_paid": true
}
```

### 3. `account.delegationGrant`

This object SHOULD describe a single explicit delegation.

Proposed fields:

- `@type`: `account.delegationGrant`
- `grantor`
- `grantee`
- `scope`
- `constraints`
- `expiry`
- `revocable`
- `revocation_reference`
- `status`

Example:

```json
{
  "@type": "account.delegationGrant",
  "grantor": "0:owner",
  "grantee": "0:delegate",
  "scope": "submit_only",
  "constraints": {
    "target_allowlist": [],
    "max_value": null
  },
  "expiry": 1777000000,
  "revocable": true,
  "revocation_reference": "del_01",
  "status": "active"
}
```

### 4. `account.sessionCapability`

This object SHOULD describe a short-lived delegated permission.

Proposed fields:

- `@type`: `account.sessionCapability`
- `session_id`
- `principal`
- `scope`
- `expiry`
- `revocable`
- `status`

### 5. `account.agentCapability`

This object SHOULD describe an automation-oriented delegated permission.

Proposed fields:

- `@type`: `account.agentCapability`
- `agent_id`
- `principal`
- `scope`
- `constraints`
- `expiry`
- `revocable`
- `status`

## Proposed RPC Methods

These method names are draft candidates, not yet frozen.

### 1. `getAccountCapability`

Purpose:

- return the canonical capability descriptor for an account

Input:

- `address`

Output:

- `account.capability`

### 2. `getAccountDelegations`

Purpose:

- return active and optionally inactive delegations associated with an account

Input:

- `address`
- optional `include_inactive`

Output:

- list of `account.delegationGrant`

### 3. `getAccountSessions`

Purpose:

- return known session capabilities for an account

Input:

- `address`
- optional filters

Output:

- list of `account.sessionCapability`

### 4. `getAccountAgents`

Purpose:

- return known automation / agent capabilities for an account

Input:

- `address`
- optional filters

Output:

- list of `account.agentCapability`

### 5. `buildTransactionIntent`

Purpose:

- create a canonical machine-readable transaction intent before signing

Input:

- `from`
- action payload
- fee intent or fee parameters
- optional delegation/session reference

Output:

- canonical intent object suitable for deterministic signing

### 6. `getSigningPayload`

Purpose:

- return the canonical signing payload for a transaction intent

Input:

- transaction intent or intent reference

Output:

- chain-bound, replay-safe signing payload

### 7. `submitSignedTransaction`

Purpose:

- submit an already signed transaction using the canonical submission surface

Input:

- signed payload
- optional submitter metadata

Output:

- submission result and tracking identifiers

## Proposed Wallet / SDK Mapping

Wallets and SDKs SHOULD expose the following concepts directly:

- account capability
- authorization roles
- transaction intent
- signing payload
- delegation grant
- session capability
- agent capability

Wallets SHOULD NOT require integrators to infer these concepts from:

- opaque wallet metadata
- custom app-specific conventions
- undocumented serialization quirks

## Proposed v1 Boundaries

The following SHOULD be included in the first standards wave:

- `account.capability`
- signer / submitter / fee-payer role modeling
- transaction intent and signing-payload separation
- delegation inspection surface
- session capability inspection surface

The following SHOULD be deferred unless implementation pressure makes them unavoidable:

- sponsorship
- complex programmable account capability negotiation
- advanced policy-language surfaces
- multi-party authorization orchestration

## Security Expectations

The API draft SHOULD satisfy these properties:

- clients can identify the authorization model without reverse engineering
- delegated authority is inspectable
- session / agent authority is visibly bounded
- signing payloads are canonical and replay-safe
- submitter and fee-payer roles are explicit when they differ from the signer

## Open Questions

1. Which of these surfaces belong in the base JSON-RPC standard versus SDK-only schema?
2. Should capability discovery be one method or part of existing account-information methods?
3. Should delegation/session/agent inspection be node-native, indexer-backed, or hybrid?
4. What is the minimum canonical transaction-intent schema?
5. Which surfaces need chain-proof or proof-backed verification in later phases?

## Next Implementation Steps

If this draft is adopted, the next engineering documents should define:

1. exact JSON field names and types
2. exact RPC request / response schemas
3. error semantics
4. SDK types
5. storage / indexing requirements for delegation and session inspection

