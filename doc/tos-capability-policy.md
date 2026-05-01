# TOS Capability Handle Policy RFC

## 0. Status and scope

**Status.** Draft v0.1, 2026-05-01. Companion RFC for Slice 6 Stage 0.

This document opens the public design required by `actor.md` section
5.4. It does not approve protocol-level capability admission control.

## 1. First principles

TOS account addresses are public and content-derived. That cannot be
undone without breaking the account model. Capability addressing can
therefore only add an authorization plane on top of public addresses.

The core security question is not "can we make an address unguessable?"
The answer is no. The real question is: can a target contract verify
that this caller has a bounded grant to invoke this entry point under
these constraints?

## 2. Rejected baseline: reusable public bearer token

A reusable bearer token placed in an internal message body is visible on
chain. Once observed, it can be replayed unless every use is single-use,
sender-bound, signature-bound, encrypted, or checked against mutable
state.

Therefore reusable public bearer handles are rejected for Slice 6.

## 3. Preferred model: public grant with bounded proof

The initial capability handle is a public grant:

```
issuer: address
target: address
grantee: address?
grantee_pubkey: uint256?
selector: uint32
constraints_hash: uint256
valid_from: uint64
expires_at: uint64
nonce: uint64
revocation_epoch: uint64
```

The handle id is `hash(grant_cell)`. The handle id is not secret. A call
is authorized only when the target verifies one of:

- `in.senderAddress == grantee`;
- a signature from `grantee_pubkey` over the call context;
- a contract-local grant registry entry that is active and not revoked;
- a single-use nonce that is consumed during the call.

## 4. Constraints

Constraints may include:

- max value;
- allowed opcode or receive selector;
- argument bounds;
- valid time window;
- max uses;
- required counterparty;
- required workchain;
- replay domain;
- delegated depth.

Constraints must be hashed in the grant and exposed in manifests. A
wallet or SDK must not display an opaque capability as "safe" unless it
can decode the constraint vocabulary.

## 5. Revocation

Every non-single-use grant needs a revocation path:

- issuer increments a revocation epoch;
- target stores revoked handle ids;
- target stores minimum active epoch per issuer/grantee pair;
- grant expires naturally.

The design may choose one or more paths, but it must document storage
cost and lookup cost. Revocation cannot be an off-chain promise only.

## 6. Relationship to account permissions

`doc/tos-account-permission-model.md` already defines account
capability discovery, sessions, agents, and delegations for wallets and
RPC. Slice 6 capability handles must not fork that vocabulary.

The bridge is:

- account permissions decide who may sign or submit;
- capability handles decide what a target contract will accept;
- capability discovery tells wallets and SDKs which model is supported.

## 7. Tol and stdlib surface

Stage 6 should start with a stdlib and manifest shape:

- `@stdlib/capability`
- `CapabilityGrant`
- `CapabilityConstraints`
- `requireCapability(...)`
- manifest-declared selectors and constraints;
- release checker validation that grants are sender-bound,
  signature-bound, stateful, or single-use.

Protocol admission control is deferred until the stdlib model passes
external review.

## 8. Threat model

The design must explicitly handle:

- replay on the same target;
- replay on a different target;
- replay across workchains;
- token leakage through public message bodies;
- phishing grants with misleading constraints;
- delegated grant chains;
- revocation race;
- expired grant race;
- griefing through large grant registries;
- wallet display ambiguity.

## 9. Non-goals

- No hidden account addresses.
- No reusable secret in a public body.
- No universal permission model for every legacy contract.
- No protocol-level admission control before stdlib, wallet, and RPC
  semantics are reviewed together.

## 10. Exit criteria for Slice 6

- A public capability grant can be represented in a manifest.
- A Tol example verifies a sender-bound or signature-bound grant.
- Replay and revocation tests exist.
- Wallet/RPC capability discovery can report whether a contract uses the
  standard capability surface.
- Security review accepts or explicitly defers protocol-level admission
  control.

