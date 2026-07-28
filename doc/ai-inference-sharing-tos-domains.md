# Shared AI Inference Services over TOS Domains (Design Note, 2026-07-28)

## Motivation

Individual TOS users who already run a local language model (no shared GPU
infrastructure, no model hosting by TOS itself) should be able to expose that
model as a paid, discoverable API compatible with common chat-completion
client shapes (the ChatGPT/Kimi-style request/response pattern), without
operating any TOS-specific server infrastructure beyond what the protocol
already provides.

The three requirements this note captures:

1. A user can run a local inference backend and make it reachable as an AI
   service, billed in TOS.
2. Callers pay per call or by subscription, in TOS.
3. The service is reached through a human-readable `name.tos` domain that is
   publicly resolvable on the TOS network, not a raw ADNL address or IP.

This is a design note, not an implementation. It records the scope decisions
made so far so that contract and gateway design can proceed from a fixed
starting point.

## Phase 1 Scope

- The operator's gateway performs pure request forwarding to a local model
  backend already running on the operator's machine. It does not host,
  fine-tune, or manage a model.
- No GPU provisioning, model packaging, or compute scheduling is part of this
  phase.
- Billing enforcement (call accounting, subscription validity, payment
  verification) and request forwarding are gateway-side concerns; only the
  payment/settlement primitives are expected to be on-chain.

## How the Three Requirements Map to Existing TOS Infrastructure

| Requirement | Existing TOS primitive | Status |
|---|---|---|
| Discoverable domain name | TOS DNS (`ConfigParam 4` root resolver, `dns-manual-code.fc` / `dns-auto-code.fc`) | Already ported from TON; protocol-level, unchanged |
| Reaching a node's HTTP service without a public TCP origin | TOS Sites / `rldp-http-proxy` (see [TosSites.md](TosSites.md)) | Already ported from TON |
| Per-call or subscription billing in TOS, tied to an on-chain-auditable service | AI Actor Model `Service Actor` (see [ai-actors.md](ai-actors.md)) | Design exists; billing/subscription messages for this use case are new work |
| Registering `name.tos` itself | A domain-registry contract minting ownership as an NFT (TON's `.ton` model) | **Not present in this repository.** TON's DNS Collection/auction contract is a separate ecosystem application built on top of TON, not part of the core protocol this repo cloned. This is new application-level contract work, described below. |

The only genuinely new engineering surface is the domain-registry contract
and the billing/gateway integration; DNS resolution, resolver chaining, and
TOS Sites transport require no protocol changes.

## Domain Registry Design

Product decisions locked in for this phase:

- **Pricing**: a single fixed price for all `name.tos` registrations,
  regardless of name length. No auction.
- **Term**: 1 year validity per registration, with a grace period (default
  30 days, tunable) during which only the current owner may renew. After the
  grace period elapses, the name becomes registrable by anyone.
- **Reserved names**: none in phase 1. Any name that passes the character/
  length validation is registrable by whoever claims it first.

### Contracts

**`TosDomainCollection`** (root contract; its address is published in the
network's root-resolver config slot)

- Holds the fixed price, the `TosDomainItem` code, and the registration/grace
  period constants.
- Stateless factory and router: it does not track which names are taken. It
  validates the label's character set, computes the deterministic target
  address, and forwards the registration message (with StateInit on first
  registration, without StateInit on re-registration of an existing address)
  along with the attached payment, refunding any excess.

**`TosDomainItem`** (one instance per registered name)

- Implements the standard NFT interface (ownership is transferable) and the
  `dnsresolve` get-method interface so it participates in normal TOS DNS
  resolution and chaining, exactly like any other DNS resolver in the
  existing chain.
- Holds `owner`, `expires_at`, and the DNS record dictionary (wallet address,
  contract address, ADNL address for a TOS Site, Storage bag id,
  next-resolver for subdomains).
- Is the sole authority on whether a given `Register`-style message should be
  accepted as a first claim, a renewal, or a post-expiry re-claim — it must
  re-check its own expiry/grace state at the moment the message is actually
  processed rather than trusting any pre-check performed by the Collection,
  since messages are asynchronous and a pre-check could be stale by the time
  it lands.

### Addressing

The address of a `TosDomainItem` is deterministic from
`sha256(normalized_label)`, where `normalized_label` is the single DNS label
being registered at this resolver level — not the full dotted name, and not
namespaced by TLD. This mirrors TON's DNS Collection precedent and composes
correctly with resolver chaining: a subdomain registrar (e.g. one an owner of
`alice.tos` might run for `*.alice.tos`) hashes only its own label the same
way, independent of how many levels deep it sits. Supporting an additional
TLD in the future means deploying another root Collection contract, not
changing the hash function.

Character-set validation (lowercase ASCII letters, digits, hyphen — standard
DNS label rules) happens at registration time so that case or charset
collisions cannot occur; no runtime case-folding is performed inside the
contract.

### Expiry and Re-registration

An expired `TosDomainItem` is never destroyed and redeployed. Its code never
changes across its lifetime; only its persistent data does. When a
post-grace-period registration message arrives, the same contract instance
overwrites `owner`, resets `expires_at`, and **clears its DNS record
dictionary** (the previous owner's records must not leak to the new owner).
This avoids the complexity and race exposure of a destroy/redeploy cycle and
preserves the property that a name's contract address never changes once
first claimed.

### State Machine (`TosDomainItem`)

```text
Unregistered --Register(pay)--> Active(expires_at)
Active --Renew(pay), owner only--> Active(new expires_at)
Active --now > expires_at--> Grace(expires_at + grace_period)
Grace --Renew(pay), owner only--> Active(new expires_at)
Grace --now > expires_at + grace_period--> Unregistered  (anyone may Register)
```

## Relationship to Billing (AI Actor Model)

Once a service is reachable at `name.tos`, charging for calls is a
[Service Actor](ai-actors.md#service-actor) concern, not a DNS concern: the
domain record should point at a service endpoint whose price schedule,
rate-limit policy, and accepted payment flow are inspectable on-chain, per
the existing AI Actor Model conventions. DNS records are discovery hints, not
authorization — the gateway and any billing contract must independently
verify payment/subscription state rather than trusting that resolving the
domain implies the caller is authorized (this repeats the existing AI Actor
Model security requirement that "service metadata or DNS records" are not by
themselves authorization).

Per-call vs. subscription billing mechanics, and whether accounting happens
per-call on-chain or is batched off-chain by the gateway and settled
periodically, are open design questions left for the Service Actor billing
work, not resolved by this note.

## Non-Goals (Phase 1)

- No model hosting, fine-tuning, or GPU provisioning by TOS or the registry.
- No auction-based pricing or premium-name tiers.
- No reserved/blocklisted name handling.
- No multi-TLD support.
- No destroy/redeploy lifecycle for domain contracts.
- Resolving a domain does not itself authorize a paid call; billing state is
  verified independently.

## Open Items Before Implementation

- Fixed registration price and grace-period length (numeric values).
- Where registration/renewal payments are routed (burn, treasury, validator
  share).
- Per-call vs. subscription billing message shapes for the AI service
  Service Actor.
- Target network for initial deployment (private/local network needs no
  registry coordination at all, per [DNS.md](DNS.md); a shared testnet or
  mainnet deployment requires a config-level decision about which
  `TosDomainCollection` address is authoritative).
- Security review of payment custody, re-registration race conditions, and
  record-clearing correctness before any shared-network deployment, at the
  same rigor as the existing AI-actor task escrow contracts.

## Related Docs

- [DNS.md](DNS.md)
- [TosSites.md](TosSites.md)
- [ai-actors.md](ai-actors.md)
- [ai-actor-contract-guidelines.md](ai-actor-contract-guidelines.md)
- [ai-actor-threat-model.md](ai-actor-threat-model.md)
