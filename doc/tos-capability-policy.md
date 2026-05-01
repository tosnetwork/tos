# TOS Capability Handle Policy RFC

## 0. Status and scope

**Status.** Draft v0.2, 2026-05-01. Companion RFC for Slice 6 Stage 0
after the first design-review fix pass.

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
version: uint8 = 1
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

The handle id is `cell_hash(CapabilityGrantV1)`. The handle id is not
secret. A call is authorized only when the target verifies one of:

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

Constraints are encoded canonically before hashing:

```
capability_constraints_v1#c601
  selector:uint32
  max_value:(Maybe Grams)
  valid_from_mc_seqno:uint32
  expires_at_mc_seqno:uint32
  max_uses:(Maybe uint32)
  required_counterparty:(Maybe MsgAddressInt)
  required_workchain:(Maybe int32)
  replay_domain:uint256
  delegated_depth:uint8
  argument_bounds:(HashmapE 16 CapabilityArgumentBound)
= CapabilityConstraintsV1;
```

`constraints_hash = cell_hash(CapabilityConstraintsV1)`. `selector` is
part of the hashed constraints even though it is also copied into the
grant header for cheap dispatch. If the two values differ, the grant is
invalid. Future constraint encodings must use a new `version` and a
different constructor tag; wallets must display the version they decode.

A conforming wallet or SDK must decode and display at least:

- target;
- selector / allowed opcode;
- max value;
- validity window;
- max uses;
- grantee or signer;
- required counterparty;
- delegated depth.

If any of those fields are present but undecodable, the wallet must show
the grant as unknown/high-risk and must not summarize it as a safe
bounded permission. Opaque extension fields may exist only under a
manifest-declared extension id.

## 5. Revocation

Every non-single-use grant needs a revocation path:

- issuer increments a revocation epoch;
- target stores revoked handle ids;
- target stores minimum active epoch per issuer/grantee pair;
- grant expires naturally.

The design may choose one or more paths, but it must document storage
cost and lookup cost. Revocation cannot be an off-chain promise only.
The stdlib full check is named `requireHandleAndEpochNotRevoked` to make
clear that it checks handle-id revocation and revocation epoch only; it is
not a standalone grant authorization check.

Revocation storage is bounded by manifest and config:

- max revoked handle ids per target;
- max epoch map entries per issuer/grantee pair;
- rent payer for each entry;
- expiry or compaction rule for old entries;
- full-set behavior.

The Stage 6 baseline rejects a revocation write that would exceed its
declared budget unless the caller pays to compact expired entries first.
It must not silently drop the oldest unexpired revocation, because that
would reactivate a previously revoked grant.

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
- Canonical `CapabilityConstraintsV1` hashing, wallet display minimums,
  revocation storage bounds, and full-set behavior are specified and
  tested.
- Security review accepts or explicitly defers protocol-level admission
  control.
