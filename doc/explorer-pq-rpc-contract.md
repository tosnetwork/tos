# Explorer post-quantum RPC parity contract

Status: **detailed design proposed for external review; not an implemented API or release approval**.

See [the detailed interface design](explorer-pq-rpc-design.md) for wire types,
request/result schemas, error semantics, proof verification, resource budgets and
review decisions.

Source reviewed: `d41eae93dbbcb2af730b4ff5015458794ef04cb1`.
Author-reported explorer integration (not independently verified): `b000d3ce99c19910585241779d226bcbd99ec9e7`.
Author-reported observations: 2026-10-14, three-validator ML-DSA networks at VM 16 and VM 18. Receipts and deployment fixtures were unavailable for this audit; these are unverified historical reports, not reproduced evidence.

## Problem and intended result

The explorer can display blocks and PQ validator membership, but cannot retrieve
PQ block signatures through the existing signature endpoint. PQ account capability
responses also lack the public authorization metadata needed to distinguish daily,
rescue and stateful fee authority. The frontend currently decodes a finite set of
source-pinned contracts and raw configuration cells itself.

Complete the existing read-only RPC contracts so clients can query consensus
signature evidence, account authorization and chain-committed policy at a specified
block. Preserve classical clients, reject malformed evidence, and distinguish
verified state, raw proof material, unsupported decoding and absent data.

This request does not change consensus rules, enable an algorithm, approve a
candidate contract, expose signer material, or add signing/execution endpoints.

## Scope inventory

The explorer's node methods are already dispatched: `getMasterchainInfo`,
`getConsensusBlock`, `lookupBlock`, `shards`, `getBlockHeader`,
`getBlockTransactions`, `getBlockTransactionsExt`, `getTransactions`,
`getMasterchainBlockSignatures`, `getConfigParam`, `getAddressInformation`,
`getAccountCapability`, `getAccountAgents`, `getAccountEvents`,
`getAccountJettons`, `getAccountNfts`, and `getTokenData`.

The gaps below concern missing result support, decoded metadata and transport
parity, rather than a missing registration for every explorer feature.

| Request | Existing interface | Current gap | Priority |
| --- | --- | --- | --- |
| R1: PQ consensus signatures and signer evidence | `getMasterchainBlockSignatures` | Explicitly rejects `liteServer.signatureSet.simplexPq` | P0 |
| R2: PQ account capability and public authority | `getAccountCapability`, `getWalletInformation` | PQ code families are not classified; public authorization state is unavailable as typed metadata | P1 |
| R3: Proof acquisition transport parity | `getProofQuery` | Available through JSON-RPC dispatch, absent from named REST routing | P1 for REST proof clients |
| R4: Typed protocol policy | `getConfigParam` | Only validator-set parameters have decoded fields; clients decode policy/limits cells independently | P1 convenience and shared correctness |

Indexed validator history, search, address labels, contract build attestations,
asset history and AI-economy query pages belong to the existing explorer/Query
service. Do not duplicate these database-backed services in the validator RPC.
Likewise, a missing optional configuration parameter is not a missing endpoint.

## R1 — Complete `getMasterchainBlockSignatures`

### Evidence

`validator-engine/json-rpc-server-parse.cpp`,
`render_masterchain_block_signatures_json`, returns:

```json
{
  "ok": false,
  "error": "post-quantum block signatures are not supported by JSON-RPC yet",
  "code": -32603
}
```

The author reported that the local VM 16 network returned HTTP 500 at masterchain seqno 7516; the VM 18
candidate returned it at seqno 5591. These observations were not independently reproduced. Config 34 returned actual PQ members with
`algorithm_id: 1`, non-null `validator_id`, `key_id`, `pq_public_key`, and
`public_key: null`. The reported payload is not an independently retained live-RPC receipt.

The native schema already carries the data in
`tl/generate/scheme/lite_api.tl`:

```text
liteServer.pqSignature validator_id:int256 algorithm_id:int signature:bytes
liteServer.signatureSet.simplexPq
  cc_seqno:int validator_set_hash:int signatures:(vector liteServer.pqSignature)
  session_id:int256 slot:int candidate:bytes
```

### Required response

Keep the request `{ "seqno": N }` and the existing top-level `id` and
`signatures` fields. Add a distinct PQ carrier discriminator, for example
`blocks.blockSignatures.simplexPq`. Return:

- The complete signed masterchain block ID: workchain, shard, seqno, root/file hashes.
- Carrier metadata: `cc_seqno`, `validator_set_hash`, `session_id`, `slot`, and
  the exact serialized candidate bytes.
- Each signature's exact stable `validator_id`, `algorithm_id` and signature bytes.
- The proof-link/configuration evidence needed to identify the effective signer
  set and signing preimage, through an optional proof response or existing R3
  acquisition. Document the actual signing domain and how the candidate bytes
  reconstruct it; a signature array alone is insufficient for independent verification.

Use base64 for binary fields, consistent with the current API. Do not manufacture
`node_id_short` from a PQ validator ID. Do not rename a stable validator ID to
`public_key`. Classical ordinary/simplex records retain their existing shapes;
new classical metadata must be additive. Specify integer signedness consistently
with the native schema; fields wider than JavaScript's exact range use decimal strings.

A PQ record has no `key_id` field in the native carrier. If the JSON response adds
`key_id`, public key, validator index or weight, derive it from the effective,
proof-bound descriptor. Otherwise return it as unavailable; do not guess from
latest Config 34 or ADNL. Membership at the current head is not necessarily the
set that signed a historical block, especially across set transitions.

### Fail-closed rules

The handler in `json-rpc-server-blocks.cpp` currently selects a forward proof link
by destination seqno and renders a null carrier as an empty ordinary set. Require
an exact full target block-ID match and reject missing, mismatched or ambiguous
links for a signed block. Genesis remains explicitly unsigned.

Malformed carriers, invalid suite/length combinations, duplicate or unknown signer
identities, excessive record counts and invalid proof/signature evidence must not
become a successful empty array. Serialization is not cryptographic verification:
only advertise verification that was actually performed. Keep arbitrary binary
values bounded before allocation/JSON encoding. Unknown future carriers return a
stable unsupported response.

### Acceptance

- Ordinary and classical simplex compatibility vectors remain green.
- Real PQ records round-trip all identity, signature and simplex metadata fields.
- A pinned historical block returns its own signature carrier, not a later block's.
- Negative controls cover wrong root/file hash at the same seqno, missing link,
  truncated signature, unsupported suite, duplicate signer, wrong effective set,
  altered candidate/session/slot and oversized records.
- A valid proof and its exact signing preimage verify with the existing native PQ
  verifier; tampering fails its intended assertion.
- Replace the current `JsonRpcParse.pq_block_signatures_fail_loudly` expectation
  with positive PQ support and targeted malformed-carrier coverage.
- Both JSON-RPC and REST routes succeed on the three-validator localnet.

## R2 — PQ account capability and public authorization state

### Evidence

Source-derived projections for an unclassified Quantum candidate are shown
separately below. They describe selected fields, not a captured live response.
The author's earlier HTTP 200 observation lacks retained receipts and remains
unverified.

`getAccountCapability` projection:

```json
{
  "account_model": "advanced.unknown",
  "authorization_version": "unknown"
}
```

`getWalletInformation` projection:

```json
{
  "wallet_type": null,
  "seqno": null
}
```

This is an honest unknown result, but insufficient structured information for the
explorer. `json-rpc-account-model.cpp` does not classify these PQ families.
`detect_authorization_version` in `json-rpc-server-account-capability.cpp` assigns
Ed25519 to every nonempty wallet type; extend that decision before registering a
PQ wallet type.

### Required metadata

Extend existing responses additively with a versioned public authorization view,
using exact compiled code identity and bounded canonical state decoding:

| Code family | Public metadata |
| --- | --- |
| PQ highload wallet | ML-DSA-44 suite, public key/key identity, subwallet ID, replay-window cleanup time and timeout; do not invent a seqno |
| ML-DSA authorization module | Suite, global ID and canonical 1312-byte public key |
| Falcon padded authorization module | Suite/profile version, global ID and canonical 897-byte public key; VM availability is reported separately |
| Complete Quantum wallet | Wallet ID/seqno, AUTH schema/mode, retirement flags, authority epoch, primary/rescue nonces, module StateInit identity and public fee metadata |
| Quantum module | Global ID, network namespace, daily ML-DSA key, SLH-DSA rescue key and rescue policy |
| Quantum fee vault | HSS/LMS public profile, configuration commitment, bound module, epoch start and next consumed/available leaf counter |

Include the observed masterchain/shard IDs, code hash, decoding schema and
recognition status. Pin account state to the requested masterchain observation.
Distinguish unrecognized code, recognized-but-malformed state, absent/frozen
accounts and valid public metadata. Keep counters exact as decimal strings where
needed. Preserve existing classical capability fields and permission-source behavior.

Use the existing native codecs or a source-generated registry, rather than a
second unchecked list of code hashes. Different compiler outputs/candidate bundles
require explicit recognition; matching storage shape alone cannot identify code.

The Quantum wallet's V5-shaped 256-bit field is required to be zero and inert. It
must never be advertised as an Ed25519 signing authority. Daily, rescue and fee
roles have distinct suites and lifecycle rules. The fee-tree ID is public metadata,
not a secret or a public-key digest. A leaf counter does not prove that an offline
signer has avoided leaf reuse. Code recognition does not prove deployment approval,
key possession, signature validity or network admission.

### Acceptance

Run live read-only capability requests against canonical highload/module/Quantum
fixtures and legacy wallets. Negative controls cover unknown code with plausible
storage, malformed/exotic/deep cells, wrong public-key length, wrong module witness,
nonzero inert legacy key, unsupported profile and integer truncation. Require
public-state responses to contain no seed, private key, signer state or local file path.
Candidate status and decoded state must not be conflated with production approval.

## R3 — Reuse the existing bounded proof transport

`getProofQuery` is already dispatched as JSON-RPC. Its handler accepts a base64
native query and returns `{ "reply": "<base64 native reply>" }`.
`lite-client/proof-verify/readonly-query.h` allows masterchain info, block proof,
config, account-state and library proof queries; it rejects execution and nested
queries. Its existing limits are 16 KiB decoded query, 64 config parameters,
16 library IDs and 64 MiB reply.

Add the named REST route `/getProofQuery` through the same handler and policy,
with transport parity tests. Preserve all allowlist, parser, size and response
limits, authentication and rate limiting. Do not create an unrestricted liteserver
proxy or a duplicate masterchain-proof endpoint merely for the explorer.

Document a reproducible acquisition sequence from a trusted anchor, effective
validator configuration and raw account/config proofs to native verification.
Returned raw proof bytes are acquisition material, not an assertion that a client
has independently verified them. Existing `getConfigParam(with_proof=true)`
already returns the block ID and proofs it checked; preserve that capability.

## R4 — Add typed policy views to `getConfigParam`

Preserve `config.bytes`, optional proofs and existing validator-set fields. Add
schema-versioned decoded fields for:

- Config 8: committed VM version and exact capability bits.
- Config 43: the message/state limits relevant to large PQ payloads; expose only
  actual source-defined fields, not a guessed security or fee estimate.
- Config 47: the bounded validator-controller code allowlist.
- Config 48: network tag, policy sequence, retired-suite flags, primary deadline
  and frozen specification hash.

Return decoded fields and proof/block metadata from the same cell observation.
Missing optional policy on a legacy chain remains distinguishable from malformed
policy or transport failure. Config 48 is mandatory at VM 17 and later. Compute
retirement status, if provided, using authenticated chain time at that observation,
not wall-clock time. Validate the exact frozen AUTH profile and controller limits.

Verifier availability, network admission and account authorization are separate.
ML-DSA/SLH-DSA/HSS-LMS verifier gates start at VM 16, fee-hash admission at VM 17,
and the Falcon candidate verifier at VM 19 in the reviewed source. A VM gate alone
must not be described as an account using that algorithm or a production release.

Negative controls cover unknown policy tags/specification hashes, unsupported
flags/deadline keys, excessive allowlist entries, malformed cells, missing mandatory
policy, inconsistent block observations and uint64 precision loss.

## Implementation and review gates

Implement R1 first to remove the observed signature-query failure. R2 supplies the
missing account metadata; R3 and R4 remove transport and client-decoding gaps.
Keep each boundary independently reviewable and backward compatible.

For every implemented boundary, commit the smallest reproducible test/fixture and
an evidence index with exact source pins, commands and exit status. Remove the
specific guard/support branch and require the intended test to fail before claiming
coverage. Run the repository's two-build static-analysis gate for C/C++ changes.
Map relevant CI to the affected native codec, RPC transport and live integration
boundaries. Do not mark a request complete merely because a renderer compiles.

This document changes no executable code. Current node gaps remain until these
implementation and validation requirements are fulfilled.

## Reproducing evidence

For each future live observation retain the source commit, executable hash,
network/global ID, VM version, deployment code/state hashes, sanitized exact
request, full block ID and response/status. Save bounded public fixtures with
SHA-256 and an accessible artifact location. Run each endpoint independently;
do not combine projections into a purported single reply. Never retain private
keys or wallet secrets. Source-derived behavior and synthetic schema tests do
not replace these runtime receipts.
