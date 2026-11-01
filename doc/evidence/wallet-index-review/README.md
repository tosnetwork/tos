# Wallet-index ownership, retention, and native acceptance evidence

This records the follow-up to the review of PR #373. The two ownership P1 findings and the trusted-restore retention P2 finding are repaired. The acceptance runner implements the six previously missing scenarios, and branch CI requires all thirteen scenarios.

## Reviewed source and scope

- Original reviewed head: `f81afead6d2ba2c2fcc96da4b29c210531dc8b3f`.
- Production fixes, regression tests, native scenarios, and mandatory CI: `cf905789bd5a6a06184329060fd220bb8179c28a`.
- Native lifecycle fixture correction: `f7535841bd860eaacd1e0f268a3571a235bf24b0`.
- Native acceptance source: **f7535841bd860eaacd1e0f268a3571a235bf24b0**.
- Main used for the merge compatibility check: `084e4315899cc3a5bf64cc434ee327e1db487173`.

The production C++ files and their compiled regression tests are byte-identical between the two follow-up source commits. The second commit fixes the harness's interpretation of the native account API, with two additional regression tests. Native execution is pinned to `f7535841`, and the compiled mutation controls are pinned to `cf905789`.

The evidence publication also formats four Python CI/control scripts after GitHub's Lint job reported formatting failures. Their normalized Python ASTs are identical before and after formatting; the prospective merge's 33 Ruff-included Python files then pass the repository-pinned Ruff checks and formatting gate, and the 12 control helpers, 15 CI guard helpers, and full CI coverage guard pass again. [format-equivalence.json](format-equivalence.json) records the exact files and hashes. Production C++, native fixture and acceptance runner bytes remain unchanged. This publication does not claim a new native execution at its own commit.

## Findings and fixes

### P1: malformed getter output could terminate ownership derivation

The token-wallet verifier consumed getter stack fields without containing `vm::VmError`. The ownership sweep called that verifier directly, so a successful getter returning the wrong stack types could escape the worker and terminate the process.

The exception boundary now covers account loading, wallet getter decoding, and master resolution. Every wallet ABI field is consumed using its required type. Malformed output produces a definite negative verdict; virtualization failures remain indeterminate. NFT collection decoding follows the same rule. Rejected claims remove stale ownership instead of leaving permanently retried work.

The regressions execute the actual getter VM and production ownership sweep/drain. They check all four wallet fields, malformed master and NFT collection resolvers, stale-row deletion, an empty retry backlog, and eventual Full verification.

### P1: valid absent account data could prevent Full verification indefinitely

`StateInit.data` is optional. A valid active account with code and absent data was classified as undecodable, then its retries repeated the same classification against the pinned head. Because Full requires an empty parked backlog, this could hold replay and readiness indefinitely.

The loader now preserves the absent data reference and lets the VM supply its normal empty-data cell. Initial classification and queued retries agree. The tests prove positive token/NFT ownership as well as stale ownership removal and eventual Full; they cannot pass merely by skipping the accounts. The old malformed-state fixture was replaced with a genuinely malformed encoding.

### P2: a trusted restore could retain expired history indefinitely

A trusted snapshot can have a window base older than the receiving node's available history while its checkpoint remains readable. The original time scan repeatedly asked for the missing successor of that base and never resumed pruning.

Full replay can now find a retained candidate below the current replay checkpoint and strictly older than the seven-day cutoff. It authenticates the candidate's complete block identity against the checked applied head's ancestor dictionary before committing the candidate's shard-tip record, the base, and the replay checkpoint together. Quarantined and Partial indexes cannot take this shortcut. Young history remains retained; missing or unverifiable evidence cannot authorize pruning.

The search makes at most 32 probes and retains one bounded candidate record. It adds one constant-size observed-head identity to the replay loop, with no growing cache or queue. Existing record validation caps the candidate at 4,096 shard tips. Local cells and temporary records are released on completion, error, and cancellation.

Tests exercise actual trusted snapshot export/restore, the cutoff boundary, Full-only behavior, invalid/unapplied/foreign candidates, ancestor mismatch, read failures, sparse history, maximum valid sequence numbers, and cancellation. Separate real-state tests cover arbitrary ancestor lookup, head-state binding, full root/file identities, and the first-block/head-1 compatibility case.

## Native acceptance

The complete default registry passed: **13/13 scenarios, exit 0**, with `NATIVE_WALLET_INDEX_VERIFY_OK` and `sources_unchanged=true`. The separately generated image completed with `NATIVE_WALLET_INDEX_IMAGE_OK`. See [the original aggregate receipt](native-receipt.json), [image receipt](image-receipt.json), [actual service output](native-service-output.txt), and [canonical command output](canonical-views.txt).

The joined source starts at init block **399**. The honest donor snapshot is at **C=464**; all successful acceptance paths finish at **H=467**, with the imported/built canonical window based at **B=400**. Each comparison uses the import's entire stored window and a full-source reference at exactly the same head. The reference's own base is 0, so it covers the compared window.

| Scenario | Actual result | Evidence |
| --- | --- | --- |
| Reference | Full; exit 0 | Full replay reaches H=467; 467 masterchain blocks applied. |
| Path B: honest untrusted import | Full; exit 0 | Same H, B, and canonical digest as the full replay reference. |
| **Path A: no snapshot** | **Full; exit 0** | Native source reports no block 1; builds the window, derives ownership, and matches the reference. |
| Tampered transaction | Refused; exit 2 | `not the account's last transaction` |
| Missing middle transaction | Refused; exit 2 | `not hash-linked` |
| Truncated oldest history | Refused; exit 2 | `truncated inside the window` |
| Wrong checkpoint identity | Refused; exit 2 | `not this node's masterchain block` |
| Wrong first-block anchor | Refused; exit 2 | `anchor is not this node's first block` |
| **Injected history** | **Refused; exit 2** | Exactly one injected dormant-account row at LT 441000001 exceeds its actual last LT 9000001; `rows are newer than the account's last transaction`. |
| **Stale snapshot** | **Refused; exit 2** | Genuine full-source snapshot C=10 precedes init=399; `snapshot older than this node's history`. |
| **Forged ownership** | **Full after claims discarded; exit 0** | Exactly five claim keys changed (three additions, two tombstone replacements); none survives quarantined import; rederived view matches the reference. |
| **Destroyed-account omission** | **Refused; exit 2** | Exactly three real rows removed, including destruction at LT 450000001; `the snapshot omits the account's history in the window`. |
| **Recreated-account omission** | **Refused; exit 2** | Old LTs 454000001, 458000001, 460000001 removed; new LTs 464000001 and 468000001 preserved; block pass reports the missing transaction at 460000001. |

The six bold scenarios supply the previously missing evidence. Every negative exits for its named semantic refusal and was **never observed ready**. Sampling is not itself a proof about every instant. The separate serving-gate regressions cover readiness and refusal during verification. Positive acceptance paths require Full verification. The negative controls explicitly pass `--allow-partial-verification` and still never become ready because verification is held or refused.

Path A, Path B, and rederived forged ownership produce the same canonical SHA-256:

```text
c3d2a2e50f02f38cdde8592a0e6b811e84d6e9edcc98502b83a654226775cc94
```

The streams contain exactly 11 in-window lifecycle events and no ownership rows. The canonical digest binds schema, complete checkpoint identity, window base and its block identity, and the canonical rows. The separate `anchor_verified` diagnostic annotation is outside the canonical digest; equality is not a claim that this annotation is identical.

The four positive service runs lasted 3.110 s (reference), 1.683 s (Path B), 0.535 s (Path A), and 1.621 s (forged ownership); sampled VmHWM values were 41,188, 35,500, 34,488, and 34,892 KiB respectively. These short fixture measurements are provenance only. They do not establish production performance, memory growth, or testnet capacity; fast negative-run RSS samples can occur before startup.


The image uses four real native validators and an empty observer that downloads a nonzero persistent state. It supplies no Genesis files to that observer. The fixture commits ordinary wallet transactions, destroys accounts using their own signatures and send mode 160, observes absence through the proof-checking native account API, and redeploys the identical StateInit to prove recreation under the same address.

The first runtime image exposed a harness error after a successful destruction transaction: the native raw account API uses balance `-1` for an absent authenticated account root, while the fixture waited for zero. The shared absence predicate now requires the exact sentinel and empty code/data/frozen/extra-currency fields. Existing zero-balance accounts remain distinct. Both the old-sentinel behavior and removal of the code-empty guard were observed red before the corrected tests passed. The complete image and acceptance run were then regenerated at the source commit above.

The native image contains ordinary wallets. Its ownership case proves removal of forged token/NFT claims and derivation of the correct empty ownership population. The compiled ownership regressions provide the positive genuine-token/NFT coverage.

## Compiled sensitivity evidence

At `cf905789bd5a6a06184329060fd220bb8179c28a`, the dedicated control runner completed 27 accepted executions: nine baseline passes, nine intended failures across five removed rules, and nine restored passes. Every red result contains its exact test-start marker, the named semantic diagnostic, and abort evidence. Timeouts, setup failures, unrelated signals, and tests that never start do not count.

| Removed rule | Expected failures observed |
| --- | ---: |
| Getter decoding errors stay inside the ownership verdict | 3 |
| Valid absent data remains runnable | 2 |
| Full trusted restores can resume expired retention across a source gap | 2 |
| Ancestor lookup uses the requested sequence number | 1 |
| The first block can authenticate its own head-1 anchor | 1 |

The runner restored source bytes and hashes exactly, left test sources unchanged, and left the Git checkout clean. Its cleanup controls also prove that it restores owned mutations despite a concurrent edit to another file and terminates child processes after timeout even when their parent has exited.

## Other validation

- Native core target: 146 cases passed, including 15 snapshot cases.
- Native source/verification target: 75 cases passed.
- Final exact-source CTest run: all seven relevant gates passed in 97.72 s, covering the two native targets plus apply, JSON-RPC transport, snapshot CLI, verification gate, and canonical-dump CLI.
- Native runner/snapshot-record/lifecycle helpers: 21 passed, including two lifecycle API tests with reason-specific negative controls.
- Control-runner helpers: 12 passed.
- CI guard helpers: 15 passed; the complete branch CI coverage guard passed.
- Changed C++ lines pass Clang-format 21; changed Python files pass Ruff checks/formatting and type checks; whitespace checks pass.

An independent non-author agent reviewed the exact source commits and inspected the compiled mutation receipt and raw failure logs. Its control-cleanup, execution-marker, and evidence-retention findings were resolved; the runtime-discovered absence-sentinel correction was separately reviewed. It also inspected every final scenario and independently decoded the saved lifecycle transactions and canonical streams. This source review does not replace the repository's required third-party review.

## Reproduction and retained evidence

[validation.json](validation.json) records the exact local commands, source identities, binary-build receipt, final CTest and Python results, host details, merge simulation, and artifact hashes. This was a native Ubuntu 24.04.3 host run with Clang 21.1.8, Release, jemalloc enabled, an eight-CPU quota and an 8 GiB memory limit. It was not a replay inside the repository CI builder container.

For a fresh reproduction, check out the source commit above, install the pinned dependencies and configure/build the targets from `.github/workflows/branch-chain-python.yml`, generate the Python API, then run the following from the checkout. Use new output directories and a free base-port range:

```sh
uv sync --frozen
.venv/bin/python test/tostester/generate_tl.py
.venv/bin/python -u test/integration/node_sync_init_block.py \
  --root /tmp/wallet-index-image --build build \
  --wallet-index-only --base-port 48400
.venv/bin/python -u test/integration/wallet_index_verify_native.py \
  --init-root /tmp/wallet-index-image --build build \
  --root /tmp/wallet-index-verify \
  --source-commit f7535841bd860eaacd1e0f268a3571a235bf24b0
python3 scripts/test-wallet-index-review-controls.py \
  --build-dir build --jobs 4 --output-dir /tmp/wallet-index-controls
ctest --test-dir build --output-on-failure --no-tests=error \
  -R '^(test-wallet-index|test-wallet-index-source|test-wallet-index-apply|test-json-rpc-transport|wallet-index-snapshot-cli|wallet-index-verification-gate|wallet-index-dump-cli)$'
```

The local producer's `--wallet-index-only` mode still runs four real validators, transaction traffic, and persistent-state download/join. It omits the unrelated Rust publisher capture/refusal checks. CI uses the original producer mode plus `--wallet-index-fixtures`, and preserves its existing native image consumers before wallet-index acceptance. A local wallet-only success is not a claim that those omitted publisher checks ran locally.


CI runs the complete thirteen-scenario registry without a narrowing `--scenarios` argument and requires `NATIVE_WALLET_INDEX_VERIFY_OK`. It runs the compiled control runner and requires `WALLET_INDEX_REVIEW_CONTROLS_OK`. Both pipelines propagate failures. Native acceptance reuses the init image after its existing consumers, preserving those checks.

CI retains the fixture JSON, transaction BOCs, scenario receipts, and bounded control logs for 14 days. Fixture BOCs are capped at 32 files of at most 64 KiB each. Control logs are capped at 512 KiB each. Full node databases, indexes, and bulk build logs are excluded from the committed evidence.

The durable artifacts are:

| Artifact | Purpose |
| --- | --- |
| [native-receipt.json](native-receipt.json), [image-receipt.json](image-receipt.json) | Original native results, exact source/tool hashes, lifecycle metadata and all 13 outcomes. |
| [native-service-output.txt](native-service-output.txt), [canonical-views.txt](canonical-views.txt), [native-completion.txt](native-completion.txt) | Actual small service outputs, canonical streams, and completion markers. |
| [wallet-traffic](wallet-traffic) | All 12 real public transaction BOCs, 5,941 decoded bytes total, stored as base64 text. Decode with `base64 --decode`; decoded SHA-256 values are in the receipt. |
| [compiled-controls.json](compiled-controls.json), [compiled-control-excerpts.txt](compiled-control-excerpts.txt) | All 27 compiled outcomes, source restoration and byte-equivalence checks, exact named red failures and pass markers. |
| [helper-sensitivity.txt](helper-sensitivity.txt), [ctest-summary.txt](ctest-summary.txt) | Targeted helper sensitivity failures, restored helper gates, and the final seven CTests. |
| [independent-review.md](independent-review.md) | Source-pinned independent non-author agent review and artifact checks. |
| [validation.json](validation.json), [SHA256SUMS](SHA256SUMS) | Commands, environment, provenance, limitations and integrity index. |
| [format-equivalence.json](format-equivalence.json) | The four formatting-only follow-ups to CI, their unchanged ASTs, and successful replacement gates. |

The full local producer/build/mutation logs and databases are temporary; the bounded outputs necessary to inspect the claims are committed here. Original paths and hashes provide traceability, not a substitute for accessible raw evidence. The 14-day CI retention applies to the separate CI execution, not to an assumed upload of these local files.

`absent_at` in the original fixture receipt means the masterchain tip observed after the native account API returned absence. It is not the block ID from that account-state proof. The separately recorded `shard_block` is the destruction transaction's observed location. Saved BOCs support structural, signature, hash-chain and StateInit checks; they are not standalone ledger-inclusion proofs. The independent review decoded both successful destruction actions, verified the wallet signatures and send mode 160, and checked byte-identical deployment/redeployment StateInit at the same address.


## Merge and capacity limits

The reviewed implementation merges without a textual conflict into main `084e4315899cc3a5bf64cc434ee327e1db487173`: `git merge-tree --write-tree` exits 0 and produces tree `ea27be0c2b879f591a5f391927248a2b114bce61`. This is a merge simulation; it is not a native build/test of the integrated tree, an approval, or an actual merge.

The two P1 defects, the P2 retention defect, and the six requested native evidence gaps are closed within this review's scope. Required current-head CI and the repository's third-party review remain merge gates. The PR remains Draft and has not been merged. Live CI status is tracked in the PR; successful local host runs are not represented as GitHub Actions success.


These local measurements characterize the disposable fixture. They do not establish throughput or memory/disk capacity on a replica of testnet data. That capacity measurement remains the existing issue #316 acceptance item; this change does not claim to close it.
