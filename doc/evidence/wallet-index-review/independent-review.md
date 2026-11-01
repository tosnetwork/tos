# Independent review — PR #373 wallet-index fixes

## Scope and conclusion

**No remaining blocking findings within the reviewed scope at source commit `f7535841bd860eaacd1e0f268a3571a235bf24b0`**, tree `90be29b58c66a1959e53fd964ec5dbdefa1c1b24`.

This review covers the production fixes, regression and sensitivity controls, native fixtures and scenarios, CI wiring, and relevant operational documentation introduced after `f81afead6d2ba2c2fcc96da4b29c210531dc8b3f`. The principal implementation commit is `cf905789bd5a6a06184329060fd220bb8179c28a`, tree `d53a7d7572ef50ec58957e06256feaf85396d82a`. The follow-up `f7535841…24b0` changes only the lifecycle absence predicate and its two tests; production C++, compiled test sources, and the compiled-control runner are unchanged.

This is a **non-author agent review of the production, test, and CI changes**, not a GitHub third-party approval. The reviewer contributed the English runbook update; its consistency was checked, but that contribution is not represented as an independent review of another author's documentation. Repository-required third-party approval and required CI remain separate merge gates. No merge was performed.

Final source review used committed objects. Runtime review read receipts, logs, transaction BOCs, and exported snapshots; it did not open or mutate node/index databases.

## Review checklist and source findings

- **State, persistence, and trust boundaries:** Restored retention recovery is restricted to `Full` verification. A candidate must be applied, expired, below the replay checkpoint, and authenticated by full block identity against the checked applied head's state. Base, base record, and checkpoint publish atomically. Quarantined/partial indexes cannot use this shortcut. Missing history may retain extra data without authorizing younger pruning.
- **Parsing and ownership verification:** Malformed getter ABI results are contained as negative ownership verdicts; virtualization errors remain indeterminate. Valid absent optional account data uses the VM's empty-data semantics consistently in loading, classification, and retries. Regressions include genuine token/NFT ownership and stale-row removal.
- **Resource bounds and cancellation:** Retention search performs at most 32 probes, validates the bounded shard-tip record, honors cancellation, and adds no persistent cache. Lifecycle evidence is capped at 32 transactions, each at most 64 KiB. Mutation logs have a 512 KiB per-log cap.
- **Tests and sensitivity:** Controls require the named native test to execute and its expected semantic failure to accompany an abort. Build failures, timeouts, setup failures, and unrelated signals do not count as red results. Restoration handles all owned files while preserving conflicting external edits. Timeout cleanup kills the command group even if its leader has exited.
- **CI and provenance:** All 13 native scenarios run by default without scenario narrowing. CI supplies the checked-out source commit, propagates pipeline failure, requires success markers, and retains allowlisted receipts, lifecycle BOCs, and control logs for 14 days.
- **Operations and documentation:** The runbook accurately describes trusted versus untrusted restore, retention recovery across old archive gaps, optional-data behavior, and the verification work required. It does not present fixture measurements as production capacity evidence.

The reviewed fixes address the two ownership failures and the trusted-restore retention stall. The generalized ancestor helper also preserves the block-1/head-1 case.

## Compiled regression-control evidence

Inspected receipt: `/tmp/pr373-review-controls-cf905789/receipt.json`.

SHA-256: `018abba40e19806f24045a7336e7c3ccfd591e373d32413cd44a2db11c2adc77`.

The receipt pins `cf905789…c28a` and records **27 accepted executions: 9 baseline passes, 9 expected failures across five mutations, and 9 restored passes**. I checked all 27 raw test logs for their exact execution marker; all nine red logs contain their expected semantic diagnostic and `Signal: 6`. Source/test hashes match that committed source, restored hashes match baseline, and tests remained unchanged. The largest retained log is 308,151 bytes, below the cap.

I independently ran the exact committed control-helper revision in an isolated temporary tree: **12/12 passed**. Earlier focused fixture/snapshot helpers passed 19 tests, and CI guard tests passed 15 tests with `BRANCH_CHAIN_PYTHON_CI_OK`. Committed diff whitespace checks passed. The two absence regressions have inspected semantic red logs for the old zero-balance predicate and a removed code-empty guard; the author reported restored green results and zero type errors. Unchanged C++ suites were not rerun by this reviewer.

## Native image and lifecycle evidence

The completed image is `/tmp/pr373-native-image-f7535841`. Its receipt reports init block **399**, donor checkpoint **464**, frontier **467**, zero zero-state files, and no supplied static state. The raw producer log contains `NATIVE_WALLET_INDEX_IMAGE_OK`.

I decoded all **12 lifecycle BOCs**, totaling **5,941 bytes**, and checked each recorded file SHA-256, transaction hash, account, LT, previous LT, status, successful computation/action, and available previous-transaction hash link. All twelve hashes also occur in the honest checkpoint-464 snapshot.

Both destruction transactions are `active → nonexist`, have `destroyed=true`, and have compute/action result 0. I independently verified their owner Ed25519 signatures and decoded send mode **160**. Deployment and redeployment of the recreated account contain byte-identical StateInit whose hash equals its account address; redeployment starts with previous LT 0 and previous hash zero.

Successful completion passes both post-destruction absence gates and the final destroyed-account check using the corrected exact `balance == -1` predicate with empty code, data, frozen hash, and extra currencies. Native client code independently confirms that this sentinel represents a proof-validated absent root; zero is a valid balance of an existing account.

## All 13 scenarios and the six requested cases

Inspected aggregate receipt: `/tmp/pr373-native-verify-f7535841/receipt.json` (27,945 bytes).

SHA-256: `c9142e2d8706c2e91dd6edc3ea0ba76ab66425e5242ed648560c5b90961962f3`.

It pins `f7535841…24b0`, records all three native tool hashes, and reports `sources_unchanged=true`. Every individual receipt agrees with the aggregate. The raw runner log contains `NATIVE_WALLET_INDEX_VERIFY_OK`.

| Requested case | Independently checked evidence and result |
| --- | --- |
| Path A | Empty-index window build reaches Full at head 467, base 400; canonical stream matches the reference at the same head/window; exit 0. |
| Injected history | Exactly one row is added under the dormant account at LT 441000001, newer than its actual last LT 9000001; other records are unchanged. Exit 2 with `rows are newer than the account's last transaction`; never observed ready. |
| Stale snapshot | Snapshot bytes are identical to the full-source export at checkpoint 10, preceding init 399. Exit 2 with `snapshot older than this node's history`; never observed ready. |
| Forged ownership | Exactly five claim keys change: three additions and two tombstone replacements. All five disappear in the quarantined re-export while history is preserved. Full verification and canonical equality follow; exit 0. |
| Destroyed-account omission | Exactly the destroyed account's three history rows are removed. Exit 2 with `the snapshot omits the account's history in the window`; never observed ready. |
| Recreated-account omission | Exactly three old-incarnation rows are removed; the two new-incarnation rows remain. Exit 2 with `the window's blocks hold a transaction at 460000001 the snapshot does not match`; never observed ready. |

The four positive scenarios—reference, Path A, Path B, forged ownership—exit 0 and reach Full at head 467. All nine negative scenarios exit 2 with their intended refusal in the raw service log and were never observed ready. Edited snapshot hashes match their receipts.

For Path A, Path B, and forged ownership, I compared both raw canonical streams and independently recomputed their SHA-256. All six streams have the same digest:

`c3d2a2e50f02f38cdde8592a0e6b811e84d6e9edcc98502b83a654226775cc94`.

Each includes exactly the 11 expected in-window lifecycle events and no ownership rows. The separately printed anchor annotation is outside the canonical digest.

## Evidence limits

- `absent_at` is a masterchain tip observed after the account query reported absence. It is not the account proof's recorded block ID. `shard_block` separately records transaction-location evidence. Neither label should be presented as an independently retained proof of absence at that exact masterchain block.
- Transaction BOCs permit structural, signature, hash-chain, and execution-result inspection; they are not standalone ledger-inclusion proofs.
- “Never observed ready” describes sampled HTTP evidence. The separately reviewed serving gate provides the implementation guarantee.
- Native genuine ownership is empty; positive token/NFT derivation is covered by C++ regressions.
- Quick negative-run RSS samples can precede startup and are unsuitable for capacity/performance claims. This review makes no production-scale throughput claim.
- Main-branch compatibility and consolidated final CTest runs are reported separately by the parent; they were not independently rerun here. This review does not replace required CI or third-party approval.
