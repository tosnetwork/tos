# Inbound creation-time boundary (B2-5)

Read-only investigation, 2026-09-06, baseline `b00c408a0` plus the current
second-wave worktree. No timestamp guard, import policy, or queue rule changed.

## Disposition

**Disputed for ordinary cross-shard wall-clock skew; deferred for a complete
adversarial reachability test.** The inspected normal send/import path imposes
an authenticated causal time bound. A receiver's slower local clock is not by
itself a way to supply `created_at > transaction.now` to batch settlement.
This does not prove every possible initialized state or privileged migration
obeys the bound. Retain the guard; neither deletion nor skipping a queued message
follows from this investigation.

For a normally produced message, let S be its source block, Q the selected
neighbor queue block (possibly later or after transit), M the receiver's
reference masterchain state, and U the receiving UNO block. The inspected path
supports:

`message.created_at = S.utime <= Q.utime <= M.utime <= U.utime = transaction.now`

The equalities/inequalities depend on the already-validated history and normal
message creation rules, not on synchronized wall clocks.

## Evidence for each link

1. `crypto/block/transaction.cpp:3424` overwrites ordinary outgoing `created_at`
   with transaction `now`, regardless of the sender's proposed field. Bounce
   construction does the same at `:4110`. `ValidateQuery::precheck_one_transaction`
   requires transaction `now` equal block time (`validate-query.cpp:3232`). Normal
   transaction execution is recreated at `:6153`, compared by transaction hash
   and output messages at `:6250`/`:6277`, rather than trusting a message's header.

2. Previous-state time is monotonic in `check_utime_lt`
   (`validate-query.cpp:2475`). Transit only rewraps the same message reference in
   a new envelope (`collator.cpp:4035`); it does not advance its original
   `created_at`. Deferred dispatch likewise preserves an older message, with
   separate emitted logical time. This is an induction over a normally validated
   queue history, not an assertion about arbitrary queue bytes.

3. Non-masterchain collator neighbors come from a copy of reference-MC shard
   configuration (`collator.cpp:880`, `:971`), using its exact top block IDs
   (`:981`, `:1052`). Validator non-MC `new_shard_conf_` is likewise a copy of
   the reference configuration (`validate-query.cpp:1004`), not an independently
   newer neighbor tip. Queue requests use those IDs at `:1691` and `:1743`.
   Queue proof loading binds its virtual state hash to the requested block's
   state proof (`out-msg-queue-proof.cpp:194`–`:198`). Full-collated-data loading
   follows the requested block hash through its state update to the state root
   (`validate-query.cpp:7637`). Caches or prefetched queues therefore do not grant
   permission to select a future unregistered neighbor tip.

4. Masterchain collation skips a newly imported shard descriptor generated after
   MC block time (`collator.cpp:1922`). Import validation independently rejects
   that condition (`validate-query.cpp:2092`), and compares descriptor information
   with the block-header-derived descriptor (`:2106`). New zerostate descriptors
   also have a time bound (`:2015`); unchanged descriptors must retain their
   previous information (`:2039`). Thus a faster source cannot normally be made
   visible through an earlier-time MC cut.

5. Receiving collation clamps block time to at least both the reference-MC and
   previous-state times (`collator.cpp:2178`–`:2181`). Validation separately
   enforces both lower bounds (`validate-query.cpp:2475`, `:2480`), including
   configurations allowing equal timestamps. The local future-time tolerance
   (`:2520`) is an additional local voting check, not permission to reverse those
   causal lower bounds. Native batch settlement uses that block time.

Masterchain-origin ordinary sends have a shorter version of the same argument:
their queue is selected from the referenced MC state (`validate-query.cpp:1711`).
Special system messages constructed here also use current time (`collator.cpp:3319`,
validated at `validate-query.cpp:6776`). This is not a complete audit of every
privileged message producer or future host extension.

## Tests actually run, and what they do not show

The existing real transaction/settlement tests were rerun without rebuilding or
changing them:

```
build/test-workchain-block --filter BatchNativeMessageSettlement
build/test-workchain-block --filter NativeBatchCreditIsAtomicAndReplayable
```

Both ran one named test and passed. The first exercises the actual native send
settlement and asserts output `created_at == 10` for transaction time 10. The
second exercises native credit and replay, but its synthetic envelope helper
sets `created_at` to 1. Its “late” cases concern logical/emitted logical time,
**not** `created_at`. They must not be cited as a future-wall-time test. Logs:
`build/wave2-inbound-time-send.log` and `build/wave2-inbound-time-credit.log`.

No new test was added, no shared build was run, and no end-to-end network clock
skew experiment was performed. In particular, this is not a mutation-tested
proof of the complete causal chain above.

## Remaining cases

- A deliberately initialized queue can contain future-dated bytes not created
  through `try_action_send_msg`. A state hash authenticates those bytes, not
  their lawful historical creation. Other-shard seqno-zero neighbors are skipped
  during neighbor selection; that alone does not prove a bad queued item cannot
  persist into a later shard block. A test genesis/privileged state replacement
  must therefore be treated separately from normal skew.
- Privileged upgrades, externally installed checkpoints, hardfork state edits,
  and future message-creation engines require their own admissibility review.
  This investigation neither blesses such states nor establishes a safe
  automatic queue-deletion rule.
- A real adversarial experiment should force source time ahead, attempt its
  registration in an earlier MC block, and show rejection there; then advance
  the MC cut and show the receiving block clamps time and credits normally.
  That experiment has not been performed here. A helper that injects a future
  envelope directly into `stage_workchain_credit` would reproduce its rejection
  but would not establish the claimed normal-network reachability.

Until that broader evidence exists, preserve the deterministic guard and record
the narrower disputed premise rather than converting an unproven scenario into
a consensus behavior change.
