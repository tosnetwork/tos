# TOS Trust and Verification Tiers

Version: v1.0

## Purpose

This document defines the trust and verification tiers for TOS clients.

It is not an implementation guide and not a protocol spec.
It is the policy that governs how different client types should reason about trust, verification, and the guarantees they receive from the TOS network.

The goal is to answer:

> What trust assumptions does each kind of TOS client make, what verification does it perform, and which tier should each product type use?

This document complements:

- [tos-standards-map.md](tos-standards-map.md) (Standard Family 7: trust and verification standards)
- [tos-release-policy.md](tos-release-policy.md) (stability levels referenced in Section 6)
- [ai-actors.md](ai-actors.md) (AI actor workflow direction)

## Policy Rule

Different clients need different verification levels.
A validator must verify everything locally.
An AI robot wallet can use proof-backed remote verification when it cannot run a full node.
A dashboard may accept trusted API responses.

But every client should know which tier it operates at, what guarantees that tier provides, and what risks it accepts.

If a client cannot answer those questions, the integration is not yet well-defined.

## AI Actor Trust Rule

AI agents that spend funds, accept tasks, settle escrow, or submit verifier decisions should use the strongest practical trust tier:

- Tier 1 for agents or services that control material funds
- Tier 2 for AI robot wallets and lightweight agents that need proof-backed reads
- Tier 3 only for convenience reads where the client understands the trusted endpoint
- Tier 4 only for analytics, discovery, reputation previews, or non-authoritative workflow dashboards

An agent must not treat indexed or transformed data as authority for spending limits, task settlement, or permission checks unless the relevant contract state is also verified.

Before an AI actor client is released, it should document:

- which tier it uses for task state
- which tier it uses for balance and permission checks
- which tier it uses for workflow history
- whether service and verifier evidence is verified locally or trusted

## Trust Tiers

TOS defines four trust tiers, ordered from strongest verification to weakest.

### Tier 1: Full Verification (Node-Native)

**How it works**

The client runs a full validator node.
All blocks, transactions, and state transitions are locally validated against protocol rules.

**Verification**

Complete.
Every block is verified.
Every transaction is executed locally.
Every state transition is validated.

**Trust assumption**

The client trusts only the protocol rules and the validator set (consensus).
It does not trust any external operator, RPC endpoint, or data provider.

**Latency**

Minimal.
Data is local.
No network round-trip is required for reads.

**Cost**

High.
Full node storage, bandwidth, and compute are required.
The client must keep up with the chain in real time.

**Recommended for**

- Validators
- Critical infrastructure
- Archival nodes
- Compliance systems
- Infrastructure operators running their own nodes

**TOS API surface**

Direct access to validator-manager internals.
The embedded JSON-RPC server is a convenience layer over fully-verified local state.
All responses reflect the node's own verified view of the chain.

### Tier 2: Light Verification (Proof-Backed)

**How it works**

The client validates block proofs and state proofs without storing full chain history.
It obtains proof data from a remote node and verifies it locally.

**Verification**

Block headers are verified against the validator set.
Individual account states and transactions are verified via Merkle proofs rooted in verified block headers.
The client does not re-execute all transactions, but can independently confirm that specific state claims are consistent with the verified chain.

**Trust assumption**

The client trusts the validator set (consensus) but does NOT trust the RPC endpoint operator.
A malicious endpoint cannot forge proofs that pass local verification.
It can only withhold data (denial of service), not fabricate it.

**Latency**

Moderate.
Requires proof retrieval and local proof verification.
Faster than running a full node; slower than a plain API call.

**Cost**

Low to medium.
No full chain storage.
Proof verification requires modest computation.
Bandwidth is limited to proofs and the specific data requested.

**Recommended for**

- AI robot wallets that cannot run a full node
- lightweight agent runners
- automation clients that need proof-backed reads
- Embedded payment systems
- Any client that needs trustless verification without full-node cost

**TOS API surface**

`getShardBlockProof` and `getMasterchainBlockSignatures` provide the core proof primitives.
Account state proofs are embedded in liteserver responses.
Light clients can retrieve these proofs via any liteserver endpoint and verify them independently.

**Current status**

Proof primitives exist in the API, but no dedicated light-client verification library is published yet.
This tier is architecturally supported by the protocol; client-side tooling is the remaining gap.

### Tier 3: Trusted Remote (API-Backed)

**How it works**

The client calls a trusted JSON-RPC endpoint and accepts responses without cryptographic verification.
The client treats the endpoint operator as honest.

**Verification**

None beyond HTTPS transport security.
The client does not verify block proofs, state proofs, or validator signatures.
It accepts the JSON response at face value.

**Trust assumption**

The client trusts the RPC endpoint operator to return correct, complete, and timely data.
If the endpoint is compromised or malicious, the client has no way to detect incorrect responses.

**Latency**

Low.
Simple HTTP request and response.
No local proof computation.

**Cost**

Minimal.
No local computation beyond JSON parsing.
No local storage.

**Recommended for**

- Explorers and block viewers (self-operated endpoint)
- Dashboards and monitoring
- Development and testing
- Backend services behind private infrastructure
- Custodial wallet backends querying their own full node

**TOS API surface**

All JSON-RPC methods.
The `ok` field indicates request success.
The `error` field provides structured error details.
No proof data is required or consumed.

**Risk**

A malicious or compromised endpoint can return incorrect balances, fake transactions, or omit data.
This tier is only safe when the endpoint is self-operated or operated by a trusted party over a secure channel.

Tier 3 should not be the sole data source for balance verification in production wallets that send user funds, unless the endpoint is self-operated against the operator's own full node.

### Tier 4: Indexed/Derived (Third-Party)

**How it works**

The client queries an indexer, explorer API, or analytics service that processes and transforms chain data.
The data may be aggregated, filtered, enriched, or delayed relative to the live chain.

**Verification**

None.
Data may be delayed, incomplete, or transformed.
The client has no way to verify correctness against the chain.

**Trust assumption**

The client trusts the indexer or explorer operator AND their data pipeline correctness.
This is the weakest trust model: the client depends on both the operator's honesty and their engineering quality.

**Latency**

Variable.
Depends on indexer ingestion lag, query complexity, and service availability.
May range from sub-second to minutes behind the live chain.

**Cost**

Minimal for the client.
The indexer operator bears the cost of running infrastructure and maintaining the data pipeline.

**Recommended for**

- Historical analytics
- Compliance reporting
- Portfolio tracking
- Non-critical UI displays
- Research and data science

**TOS API surface**

Not directly TOS-operated.
Third-party services build on Tier 1 or Tier 3 data.
TOS does not define or guarantee the API surface of third-party indexers.

**Risk**

Highest trust assumption of any tier.
Data may be stale, incomplete, or incorrectly derived.
Should never be used for transaction submission or balance verification in production wallets.
Should never be treated as authoritative without cross-referencing against a higher tier.

## Recommended Defaults by Product Type

| Product Type | Recommended Tier | Notes |
|---|---|---|
| Validator node | Tier 1 | Must use full verification |
| Infrastructure operator | Tier 1 | Runs own nodes |
| AI robot wallet / agent runner | Tier 1 or Tier 2 | Use Tier 1 when controlling material funds; Tier 2 for proof-backed lightweight operation |
| Service actor backend | Tier 1 or Tier 3 (self-operated) | Self-operated JSON-RPC against own full node |
| Consumer wallet prototype | Tier 2 or Tier 3 | Out of scope for the first product roadmap |
| Explorer / block viewer | Tier 3 (self-operated) | Operates own full node with JSON-RPC |
| Analytics / compliance | Tier 4 (acceptable) | Must document data freshness guarantees |
| Development / testing | Tier 3 | Acceptable for non-production use |
| CI / automation | Tier 3 | Use dedicated testnet endpoints |

These defaults represent the minimum recommended tier for each product type.
Using a stronger tier is always acceptable.
Using a weaker tier than recommended requires explicit documentation of the trust tradeoff.

## Security Implications

### Trustless tiers (Tier 1 and Tier 2)

The client can independently verify correctness.
No external party can fabricate data that the client would accept.
The only attack surface is data withholding (denial of service), not data fabrication.

### Trusted tiers (Tier 3 and Tier 4)

The client depends on the operator's honesty and competence.
A compromised or malicious operator can return incorrect data without detection.
Clients at these tiers should apply defense-in-depth measures:

- use HTTPS with certificate validation
- pin or restrict the set of trusted endpoints
- cross-reference critical data against a second source when practical
- never treat Tier 3/4 data as a sole source of truth for high-value operations

### Mixing tiers within one application

Mixing tiers within a single application is acceptable and often advisable.

Example: a wallet may use Tier 3 for fast UI state display, but verify critical balances via Tier 2 proof verification before submitting a send transaction.

Example: a backend service may use Tier 4 indexed data for analytics dashboards, but query its own Tier 1 node for balance checks before processing withdrawals.

### Production wallet send flows

Production wallet send flows should NOT rely solely on Tier 3 or Tier 4 for balance verification.
At minimum, the balance check before sending should use Tier 2 proof verification or Tier 1 local state.

If Tier 2 tooling is not yet available, a custodial wallet backend should use Tier 3 against its own self-operated full node (which is effectively Tier 1 at the infrastructure level).

## API Endpoints by Trust Tier

This table summarizes how key JSON-RPC methods relate to each trust tier.

| Endpoint | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---|---|---|---|
| getMasterchainInfo | Local state | Verify block proofs | Accept response | -- |
| getAddressInformation | Local state | Verify state proof | Accept response | -- |
| getMasterchainBlockSignatures | Local state | Verify validator signatures | Accept response | -- |
| getShardBlockProof | -- | Core proof primitive | Accept response | -- |
| sendBocReturnHash | Local submission | Submit via trusted node | Accept response | -- |
| getTransactions | Local state | Verify against block | Accept response | Via indexer |

Notes:

- Tier 1 accesses all data from locally verified state. Proof-specific endpoints like `getShardBlockProof` are not needed because the node already has full verification.
- Tier 2 uses proof endpoints as its primary verification mechanism. The client retrieves proofs and validates them locally.
- Tier 3 uses all endpoints without verification. Trust is in the endpoint operator.
- Tier 4 typically does not call TOS JSON-RPC directly. Data comes from third-party indexer APIs built on top of Tier 1 or Tier 3 infrastructure.

## Stability Level

This section classifies the stability of the trust tier specification itself, using the levels defined in [tos-release-policy.md](tos-release-policy.md) and [tos-standards-map.md](tos-standards-map.md).

| Component | Stability Level | Rationale |
|---|---|---|
| Trust tier definitions (Tiers 1-4) | Level 1 (Canonical Standard) | Core architectural classification; should not change without deprecation |
| Recommended defaults by product type | Level 2 (Supported) | May evolve as light-client tooling matures and Tier 2 becomes more practical |
| Proof format and transport details | Level 3 (Experimental) | Subject to protocol changes; not yet stable enough for strong compatibility guarantees |

## Open Questions

The following questions are known but not yet resolved.
They should be addressed as trust tier tooling matures.

1. **Light-client library**: When will a published verification library make Tier 2 practical for AI robot wallet and agent-runner integrators?

2. **Proof freshness**: What is the maximum acceptable age of a block proof before a Tier 2 client should consider it stale? This affects both UX and security.

3. **Validator set bootstrapping**: How does a Tier 2 client obtain and verify the initial validator set? This is the trust root for all proof verification.

4. **Tier 3 endpoint authentication**: Should TOS define a standard for authenticating JSON-RPC endpoints beyond HTTPS? API keys, JWTs, and mTLS are common patterns but not yet standardized for TOS.

5. **Indexer data contracts**: Should TOS publish minimum quality expectations for Tier 4 data providers (freshness, completeness, accuracy)? This would reduce the risk of the weakest trust tier.

## Final Rule

Every TOS client should know which trust tier it operates at.
Every product surface should make its trust assumptions explicit.

If a user cannot determine whether their client verifies data or merely trusts someone else's claim, the integration documentation is incomplete.

Trust tiers are not a hierarchy of quality.
They are a hierarchy of verification.
The right tier depends on the client's operational context, cost constraints, and security requirements.
The wrong tier is the one the client does not know it is using.
