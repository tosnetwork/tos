# Shared AI Edge Inference Services over TOS Domains

## Status

- Document type: domain binding and Phase 1 inference design note
- Status: proposed, non-normative
- Date: 2026-07-30
- Terminal architecture:
  [TOS AI Edge Computing Terminal](ai-edge-computing-terminal-architecture.md)
- Main plan:
  [The TOS Protocol Implementation Plan](the-tos-protocol-implementation-plan.md)

## Motivation

Individual TOS users who run a local model should be able to turn selected
hardware into a TOS AI Edge Computing Terminal and expose one or more paid,
discoverable inference services compatible with common client shapes. TOS
does not host the model or take control of the device. The operator installs a
standalone terminal product, not a validator.

The three requirements this note captures:

1. A user can run a local inference backend and make it reachable as an AI
   service, billed in TOS.
2. Callers pay per call or by subscription, in TOS.
3. The recommended public identity is a human-readable `name.tos` domain that
   resolves through the TOS network to the terminal's current ADNL endpoint.

Raw ADNL access remains valid when a domain is unavailable. The purpose of
this note is the additional stable-name path, not a requirement that every
terminal own a domain.

This is a design note, not an implementation. It records the scope decisions
made so far so that contract and gateway design can proceed from a fixed
starting point.

## Phase 1 Terminal Scope

- The operator runs a Tier 1 managed-inference terminal on supported
  Linux/NVIDIA hardware.
- The operator approves exact local model artifacts and runtime adapters.
- `tos-edge-core` and `tos-edge-ai` enforce authentication, quote/payment
  binding, input limits, bounded admission, cancellation, metering, receipts,
  and cleanup.
- Consumers call provider-approved service profiles. They do not receive a
  shell, Docker socket, raw accelerator access, or permission to execute an
  arbitrary container.
- The terminal may use OpenAI-compatible, Ollama, llama.cpp, or vLLM adapters.
- Billing enforcement and request execution happen off-chain; generic
  identity, commitment, payment, escrow, and settlement remain on-chain.
- Resource claims and benchmarks carry explicit declared, observed,
  benchmarked, audited, or attested evidence levels.

## How the Three Requirements Map to Existing TOS Infrastructure

| Requirement | Existing TOS primitive | Status |
|---|---|---|
| Discoverable domain name | TOS DNS (`ConfigParam 4` root resolver, `dns-manual-code.fc` / `dns-auto-code.fc`) | Already ported from TON; protocol-level, unchanged |
| Reaching a node's HTTP service without a public TCP origin | TOS Sites / `rldp-http-proxy` (see [TosSites.md](TosSites.md)) | Already ported from TON |
| Per-call or subscription billing in TOS, tied to an on-chain-auditable service | AI Actor Model `Service Actor` (see [ai-actors.md](ai-actors.md)) | Design exists; billing/subscription messages for this use case are new work |
| Registering `name.tos` itself | A domain-registry contract minting ownership as an NFT (TON's `.ton` model) | **Not present in this repository.** TON's DNS Collection/auction contract is a separate ecosystem application built on top of TON, not part of the core protocol this repo cloned. This is new application-level contract work, described below. |
| Terminal and resource identity | Edge Core plus signed terminal/resource manifest | **To build in `tos-protocol`.** This is not a validator identity. |
| Hardware/runtime detection and measured compatibility | AI terminal probes and benchmark profiles | **To build in `tos-ai`.** Self-report is not attestation. |
| Managed model execution | Model manager, runtime adapters, and bounded scheduler | **To build in `tos-ai`.** Existing runtimes are reused rather than reimplemented. |
| Home-network reachability | Public ADNL path or owner-selected relay/reverse tunnel | TOS transport exists; a complete ordinary-user relay product remains new work. |

DNS resolution, resolver chaining, ADNL/RLDP, and TOS Sites transport require
no consensus change. The missing work is nevertheless broader than the
registrar: the terminal, base protocol, runtime adapters, scheduler, discovery,
relay, billing integration, and conformance suite are all product work.

## Domain-to-Terminal Binding

```text
name.tos
  -> TOS DNS site record
  -> current ADNL identity
  -> RLDP/TOS Sites ingress or authorized relay
  -> tos-edge-ai
  -> authenticated and paid terminal session
  -> bounded task admission
  -> approved runtime adapter and model
```

The domain represents a persistent owner-controlled service identity. The
terminal host, IP address, accelerator, runtime key, model revision, and relay
may rotate without transferring the domain. Active quotes remain bound to
their original service and model revisions.

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

- No model hosting, fine-tuning, or GPU provisioning by TOS core or the
  registrar.
- No arbitrary consumer containers, public shell, raw accelerator rental, or
  automatic advertisement of all detected host capacity.
- No promise of universal GPU, NPU, mobile, or edge-device compatibility.
- No assumption that a domain, payment, benchmark, or receipt proves the
  physical hardware, exact runtime, semantic correctness, or confidentiality.
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
- Canonical terminal/resource manifest, workload benchmarks, evidence levels,
  and freshness rules.
- Runtime adapter ABI, model artifact commitments, and bounded scheduler
  semantics.
- Phase 1 public-ADNL requirement or minimally trusted relay product.
- Target network for initial deployment (private/local network needs no
  registry coordination at all, per [DNS.md](DNS.md); a shared testnet or
  mainnet deployment requires a config-level decision about which
  `TosDomainCollection` address is authoritative).
- Security review of payment custody, re-registration race conditions, and
  record-clearing correctness before any shared-network deployment, at the
  same rigor as the existing AI-actor task escrow contracts.

## Related Docs

- [TOS AI Edge Computing Terminal Architecture](ai-edge-computing-terminal-architecture.md)
- [The TOS Protocol Implementation Plan](the-tos-protocol-implementation-plan.md)
- [Managed AI Services on Local GPU Hardware](local-gpu-sharing-use-case.md)
- [Site-Bound Physical AI Edge Terminal](physical-ai-edge-terminal-use-case.md)
- [Locally Hosted Open-Weight Model Sharing](local-open-weight-model-sharing-use-case.md)
- [DNS.md](DNS.md)
- [TosSites.md](TosSites.md)
- [ai-actors.md](ai-actors.md)
- [ai-actor-contract-guidelines.md](ai-actor-contract-guidelines.md)
- [ai-actor-threat-model.md](ai-actor-threat-model.md)
