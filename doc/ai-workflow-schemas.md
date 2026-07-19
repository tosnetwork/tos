# Reference Schemas for Result Metadata and Evidence Bundles

Every native AI-actor contract commits to off-chain data by storing a 32-byte hash rather
than the data itself (see the design principle in [`ROADMAP.md`](../ROADMAP.md): "TOS
should not make AI execution opaque; task state, payments and verification metadata should
remain inspectable" combined with "Modular proof support ... without hard-coding one
verification backend"). The chain never validates the *content* behind these hashes; it only
proves that whoever produced the hash committed to one specific document, and lets any
holder of that document verify it against the on-chain commitment.

Two parties who don't share a hash pre-image cannot verify each other's commitments unless
they agree on (a) what fields the pre-image contains and (b) how it is canonicalized before
hashing. This document is that agreement. It does not change any contract; it only specifies
the off-chain JSON shape and hashing rule the existing `*_hash` fields already expect.

## Hashing convention

Every bundle below is:

1. Serialized as UTF-8 JSON with object keys sorted lexicographically (byte order) and no
   insignificant whitespace -- i.e. [RFC 8785 JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785).
2. Hashed with SHA-256.
3. Stored on-chain as the resulting 32 bytes (hex-encoded at the `tosctl` CLI boundary, raw
   `uint256` in contract storage and get-methods).

A verifier who receives a bundle re-serializes it under the same rule, hashes it, and
compares the result to the on-chain hash field. Any two implementations that both follow
this convention produce byte-identical input to the hash, and therefore agree on the digest,
without needing a shared library -- this is what "modular proof support" means in practice:
the chain only needs the digest; the bundle format and verification logic live entirely
off-chain and can evolve independently per `bundle_version`.

Every bundle below carries a `bundle_version` field precisely so a verifier can tell which
revision of the schema to parse against; adding a field must bump `bundle_version` and
existing on-chain hashes remain valid against their original version.

## Task Escrow: `result_hash` / `evidence_hash`

Committed by the assigned agent via `tosctl agent task send --operation result`
([`crypto/smartcont/task-escrow-code.fc`](../crypto/smartcont/task-escrow-code.fc)).

`TaskResultBundle` (hashed to `result_hash`):

```json
{
  "bundle_version": 1,
  "task_address": "0:<task-escrow-account-id>",
  "agent_address": "0:<agent-account-or-wallet-id>",
  "completed_at": 1790000000,
  "summary": "human-readable one-line result summary",
  "output_uri": "ipfs://... | https://... | null",
  "output_hash": "<64-hex-sha256-of-the-raw-output-artifact>"
}
```

`TaskEvidenceBundle` (hashed to `evidence_hash`) is a separate document precisely so a large
evidence trail (logs, intermediate steps, tool-call transcripts) can be published or
withheld independently of the compact result summary above:

```json
{
  "bundle_version": 1,
  "task_address": "0:<task-escrow-account-id>",
  "steps": [
    { "kind": "service_call", "service_address": "0:<service-actor-id>", "request_hash": "<64-hex>", "response_hash": "<64-hex>" },
    { "kind": "tool_call", "tool": "web-search", "query": "...", "result_uri": "..." }
  ],
  "verification_method_hash": "<64-hex, see Capability Registry below, or all-zero if none>"
}
```

## Dispute: `claimant_evidence_hash` / `respondent_evidence_hash` / `ruling_hash`

Committed via `tosctl agent dispute deploy` and `send --operation submit-respondent-evidence
/ rule` ([`crypto/smartcont/dispute-code.fc`](../crypto/smartcont/dispute-code.fc)). Both
evidence bundles share one shape; the ruling is a separate, reviewer-authored document.

`DisputeEvidenceBundle` (hashed to `claimant_evidence_hash` or `respondent_evidence_hash`):

```json
{
  "bundle_version": 1,
  "dispute_address": "0:<dispute-account-id>",
  "submitted_by": "claimant | respondent",
  "narrative": "why the task result should/should not be accepted",
  "references": [
    { "kind": "task_evidence", "hash": "<64-hex, references a TaskEvidenceBundle above>" },
    { "kind": "external", "uri": "https://...", "sha256": "<64-hex>" }
  ]
}
```

`DisputeRulingBundle` (hashed to `ruling_hash`):

```json
{
  "bundle_version": 1,
  "dispute_address": "0:<dispute-account-id>",
  "ruling": "claimant | respondent | split",
  "split_bps": 6500,
  "rationale": "human-readable ruling rationale",
  "considered_evidence_hashes": ["<64-hex>", "<64-hex>"]
}
```

`ruling`/`split_bps` here must match the values the reviewer separately submits as typed
`rule` message arguments on-chain -- the bundle is the rationale behind that ruling, not a
substitute for it; the chain never parses this JSON.

## Capability Registry: `task_categories_hash` / `pricing_hash` / `metadata_hash` / `verification_method_hash`

Committed via `tosctl agent registry deploy` / `send --operation update-metadata`
([`crypto/smartcont/capability-registry-code.fc`](../crypto/smartcont/capability-registry-code.fc)).
Each hash is a separate document so any one facet (pricing, say) can change without
re-publishing the others:

```json
// task_categories_hash -> TaskCategoriesBundle
{ "bundle_version": 1, "categories": ["research", "code-review", "data-labeling"] }

// pricing_hash -> PricingBundle
{ "bundle_version": 1, "model": "per_call", "price_nanotos": 50000000, "currency": "TOS" }

// metadata_hash -> AgentCapabilityMetadataBundle
{ "bundle_version": 1, "display_name": "...", "description": "...", "contact": "..." }

// verification_method_hash -> VerificationMethodBundle
{
  "bundle_version": 1,
  "method": "ed25519_signature | tee_attestation | merkle_inclusion | none",
  "params": { "public_key": "<hex, if ed25519_signature>" }
}
```

`VerificationMethodBundle.method` is an open string, not an enum enforced on-chain --
consistent with the "no hard-coded verification backend" principle. Verifiers that don't
recognize a `method` value should treat the registry entry as unverifiable rather than
rejecting the whole record.

## Service Actor: `metadata_hash` / `proof_scheme_hash` / per-call `request_hash` / `response_hash`

Committed via `tosctl agent service deploy` / `send --operation update-policy` (metadata,
proof scheme) and `send --operation call` / `respond` (per-call request/response)
([`crypto/smartcont/service-actor-code.fc`](../crypto/smartcont/service-actor-code.fc)).
`metadata_hash` and `proof_scheme_hash` follow `AgentCapabilityMetadataBundle` and
`VerificationMethodBundle` above (a Service Actor is a specialization of the same capability
concept, scoped to one callable endpoint). Per call:

```json
// request_hash -> ServiceCallRequestBundle
{
  "bundle_version": 1,
  "service_address": "0:<service-actor-id>",
  "caller_address": "0:<agent-account-or-wallet-id>",
  "input_hash": "<64-hex-sha256-of-the-raw-request-payload>",
  "requested_at": 1790000000
}

// response_hash -> ServiceCallResponseBundle
{
  "bundle_version": 1,
  "service_address": "0:<service-actor-id>",
  "request_hash": "<64-hex, must match the on-chain last_request_hash it answers>",
  "output_hash": "<64-hex-sha256-of-the-raw-response-payload>",
  "responded_at": 1790000000,
  "proof": { "method": "...", "value": "..." }
}
```

Raw request/response payloads (prompts, model outputs) are deliberately *not* part of the
bundle and are never expected on-chain; only their hashes are, so a counterparty holding the
raw payload can prove it matches what the Service Actor recorded.

## Agent Account: `metadata_hash` / `service_endpoint_hash`

Committed via `tosctl agent wallet update-policy` / `agent account update-policy`
([`crypto/smartcont/agent-account-code.fc`](../crypto/smartcont/agent-account-code.fc)).
`metadata_hash` follows `AgentCapabilityMetadataBundle` above. `service_endpoint_hash`:

```json
{
  "bundle_version": 1,
  "endpoint": "https://agent.example/runtime",
  "runner_id": "runner-sfo-1",
  "attestation_hash": "<64-hex, optional runtime attestation reference>"
}
```

This mirrors the `runtime` object `tosctl agent wallet bind-runtime` already stores locally
(see [`doc/agent-wallet-mvp.md`](agent-wallet-mvp.md)) -- `bind-runtime` is the local-profile
side of this commitment; publishing the hash on-chain via `update-policy` is what makes it
independently verifiable.
