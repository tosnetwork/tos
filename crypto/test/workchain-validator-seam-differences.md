# Validator versus collator account-binding seams

Read-only inventory against commit
`a3a4438bdaeb9946d43794346fe7bcd40df40990`; both production files are unchanged
from integrated commit `6e089de558a587f674abf943e98a670c3cb25164`.
This is preparation for the coordinator's reviewed first collator seam, not an
alternative implementation or authorization to modify validator code.

## The six sites and their different jobs

| Job | Collator site | Validator site | Difference relevant to the reviewed pattern |
| --- | --- | --- | --- |
| Configuration/custom execution flag | `validator/impl/collator.cpp:2275`, visitor at 2303 | `validator/impl/validate-query.cpp:1067`, visitor at 1142 | Both visitors return `Result<bool>` controlling `custom_workchain_block_seqno`; this is configuration classification, not an engine invocation. Collator uses `FetchConfigParams` and the proposed block sequence number; validator builds phase configurations here and uses the candidate's sequence number. Replacing refusal with a chosen Boolean needs the reviewed account-binding meaning, not a default copied from another variant. |
| Shard/configuration readiness | `collator.cpp:1582`, visitor at 1597 | `validate-query.cpp:1276`, visitor at 1292 | Collator actually binds/destroys the configured adapter and records configuration ownership before/during/after. Validator's branch has no equivalent adapter or observations yet. Other validator shard checks reject incompatible candidate context; resolver/config failures are local failures. |
| Execution versus replay selection | `collator.cpp:2443`, visitor at 2458 | `validate-query.cpp:6510`, visitor at 6520 | Both currently return a singleton `ResolvedWorkchainBlockExecution*`. Collator consumes an externally supplied candidate and constructs transactions; validator consumes candidate AccountBlocks/imports and replays against authenticated previous state plus candidate next state. A multi-account binding cannot become either a singleton pointer or an ordinary-account null pointer. |

## Order is not symmetric

Collator calls shard readiness at `collator.cpp:1786`, before
`do_collate_inner` calls `fetch_config_params` at 2446. Validator calls
`fetch_config_params` at `validate-query.cpp:1043`, then shard readiness at 1046.
The validator configuration visitor is therefore an earlier refusal than its
readiness visitor. Success at the reviewed collator readiness seam alone cannot
establish reachability of the analogous validator seam.

Validator transaction replay is later still: stage 1 calls `check_transactions`
at 7870, after AccountBlock prechecks (7795), message/queue/processed-info checks,
and input-queue checks. It does not start with the collator's blank dictionaries.
Candidate InMsgDescr and AccountBlocks are unpacked at 2915–2918. `state_root_`
is derived by validating/applying the candidate Merkle update to authenticated
previous state at 1480–1497; it is an object to verify, not a locally committed
publication outcome or trusted engine-reported result.

## Singleton assumptions that must stay confined to the singleton alternative

In validator `check_transactions`:

- The selected type is a singleton block-engine pointer (6518). Null means the
  ordinary per-account loop (6603 onward), which can spawn parallel account actors.
  Returning null for a multi-account binding would silently choose that loop.
- Candidate imports are streamed through the singleton wire cap (6536–6551).
  Its limit and framing must not be relabeled as the multi-account admission bound.
- Replay context contains authenticated previous/config/masterchain roots and the
  candidate-derived inbox (6560–6563); replay compares against `state_root_`.
- The `found` flag and executor-address comparison (6564–6572) enforce exactly one
  AccountBlock; absence is rejected at 6601. These are the legacy singleton rule,
  not I13a's one logical batch across multiple AccountBlocks.
- `replay_resolved_workchain_account_block` (6574) is singleton replay. After it,
  each transaction's outbound messages are independently checked (6583–6598), with
  message metadata and saved account-validation context. A new branch must account
  for these validation obligations; replay success alone cannot bypass them.

Collator's corresponding legacy branch also has singleton-specific assumptions:
`batch_executor_address_`, unsplit-state requirements and queue import collection
at 2510–2525; `create_workchain_batch_transaction` at 3476 creates one executor
account, commits it at 3544, and registers outgoing messages at 3553. These facts
explain why the new account-binding shape must be explicit on both sides. This
inventory does not decide which structural restrictions a new protocol needs.

## Failure provenance and terminal observation

At all six current binding refusals, LocalUnavailable means "not connected".
It is not a reusable classification for the candidate-dependent execution/replay
that will replace them. Existing singleton validator replay already distinguishes
local-failure categories from candidate failures at 6553–6558 and 6577–6581.
Its candidate-only import exception boundary deliberately captures only the
candidate dictionary; it must not expand to cover authenticated local state while
retaining candidate classification. Missing local authenticated data and forbidden
candidate-supplied structures remain different sources even if both throw
`VmVirtError`.

Validator has distinct terminal outcomes: `reject_query` constructs
`CandidateReject` (`validate-query.cpp:145–160`); `fatal_error(Status)` resolves the
promise with an error (206–226). A parent Boolean caller may subsequently log a
generic rejection after an inner fatal failure (for example 7870–7871), while
`main_promise` has already been consumed. Tests must observe the terminal typed
result and original status, not infer classification from the last log line or
Boolean return. Collator's construction-error path is not a replacement for this
validator distinction.

## Observations and shared reverse control

The existing adapter lifetime/ownership statistics occur only in the collator
readiness visitor (`collator.cpp:1603–1612`), not in validator's three branches.
The reviewed pattern must distinguish resolution, adapter binding, proof admission,
actual metered engine entry, replay comparison, and successful completion; one
"adapter bound" event does not imply execution. Per-account actor counts and work
timers on validator's ordinary loop likewise do not count a logical batch.
Independent validator replay uses a separate I13b execution scope; it is not a
retry of the collator's publication transaction.

Both sides must consume the shared activation helper. The current validator
resolver wrappers include `cannot execute configured workchain: ` (1130),
`cannot resolve configured workchain execution: ` (1138),
`cannot validate configured workchain: ` (1289), and
`cannot resolve transaction execution scope: ` (6515). They are not the exact
collator prefix supported by the current helper's `collator` boundary. Do not
strip arbitrary prefixes or add a B classifier. The first reviewed pattern must
identify the actual observed boundary and, if necessary, have the shared helper
owner add an explicit supported form with its own real-input calibration.

No validator file is changed by this inventory. Phase two remains gated on the
coordinator's review of A's first collator seam. Batch identity/count checking,
execution ledger, actual reader routing, and final commit authority are not
implemented or declared satisfied here.
