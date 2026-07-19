# AI Actor Message Catalog

This document defines the initial message catalog for AI actor workflows.

The catalog is intentionally small. Each message should use an explicit opcode, a `query_id`, and enough fields to reconstruct the workflow from transaction history.

The primary sender and receiver model is AI robot wallets and agent accounts, not ordinary mobile wallets.

## Conventions

- Field names are written in snake_case for documentation.
- Numeric values are placeholders until contract implementation allocates constants.
- Large payloads should be represented by hashes or evidence references.
- Messages that move funds must include task id, sender authority, and value semantics.
- Unknown messages should fail closed unless a contract explicitly documents a silent-drop path.

## Task Lifecycle Messages

| Message | Direction | Purpose |
|---|---|---|
| `TaskRequest` | user actor -> task actor | Create or fund a task |
| `TaskAccept` | agent account -> task actor | Accept an open task |
| `TaskProgress` | agent account -> task actor | Publish optional progress metadata |
| `TaskResult` | agent account -> task actor | Submit result and evidence references |
| `TaskSettle` | creator/verifier/task policy -> task actor | Release payout, refund, or slash |
| `TaskCancel` | creator/cancel authority -> task actor | Cancel an open or expired task |
| `TaskTimeout` | scheduler/task policy -> task actor | Move an overdue task to timeout handling |
| `TaskDispute` | creator/agent/verifier -> task actor | Open a dispute path |

## Service Messages

| Message | Direction | Purpose |
|---|---|---|
| `ServiceQuote` | agent/task -> service actor | Request price and capability metadata |
| `ServiceCall` | agent/task -> service actor | Authorize a model, data, tool, or compute call |
| `ServiceResult` | service actor -> task/agent | Return result metadata and response hash |
| `ServiceCharge` | service actor -> task actor | Request settlement for an authorized call |

## Verifier Messages

| Message | Direction | Purpose |
|---|---|---|
| `VerifyRequest` | task actor -> verifier actor | Ask for result or evidence review |
| `VerifyDecision` | verifier actor -> task actor | Accept, reject, score, or dispute result |
| `VerifierStakeUpdate` | verifier actor -> registry/task | Publish verifier bond or policy state |

## Required Fields By Category

### Lifecycle

- `query_id`
- `task_id`
- `sender`
- `created_at` or consensus time reference where needed

### Payment

- `amount`
- `currency`
- `max_charge`
- `refund_target`
- `payout_target`

### Authorization

- `capability_hash`
- `delegation_ref`
- `replay_domain`
- `expires_at`

### Evidence

- `metadata_hash`
- `evidence_hash`
- `transcript_hash`
- `signature`
- `verifier_id`

## Failure Semantics

- malformed messages: reject with protocol or decode error
- unauthorized messages: reject with authorization error
- out-of-phase messages: reject or postpone according to the task ABI
- insufficient escrow: reject before state transition
- expired authority: reject and preserve task state
