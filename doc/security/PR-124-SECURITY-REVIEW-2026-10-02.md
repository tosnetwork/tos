# PR #124 security review — 2026-10-02

## Status and exact scope

Initial reviewed head: `924cf0970532b5794fcee635e8ff67755c326041`.
Head branch: `tol-stdlib-audited-patterns`.

**One confirmed fee-accounting defect has a source fix and six new regression vectors. The original review did not execute the patch; native follow-up verification is recorded in the last section. A separate, conditional signer-configuration risk was unresolved at review time; its resolution is recorded in the last section. This is not a security approval or a claim that every path in the PR is safe.**

Changes made directly on the PR branch:

- `1699b87e522743daacc2bfda5b5be371252618e4`: include proposer dictionary traversal in multisig update pricing.
- `0c80b5e20edf2c89eaa71706d71f4d5f7e4d2f7b`: add `crypto/func/auto-tests/tests/lib-multisig-wallet-members.fc`.

This was a source-led review of the multisig parent/order authorization and fee paths, highload external acceptance/commit/send handling, replay guard, ordered-delivery bookkeeping, quorum verification, and Jetton transfer/mint/burn/bounce paths. Selected FunC/Tol counterparts and existing regression/fee fixtures were inspected. The TOS action executor was inspected where action-failure behavior mattered. This was not an exhaustive independent cross-language equivalence proof, full build, fuzzing campaign, deployment test, or audit of every changed documentation/build/test line.

## F-01 — P2 / Medium: proposer updates were omitted from the compute quote

### Evidence

In `crypto/smartcont/multisig-wallet-code.fc`, `validate_actions` visits both dictionaries for every `action::update`:

```func
signer_count = count_members(cs~load_ref());
count_members(cs~load_dict());
multisig_order::require_valid_threshold(threshold, signer_count);
installed += signer_count;
```

The second traversal validates the proposer set, but its count was discarded. `installed` feeds `require_new_order_value` and `get_order_estimate`. In `crypto/smartcont/multisig-order.fc`, `required_value_for_sizes` uses that count to price member-validation work in both parent compute phases.

An update installing one signer and 255 proposers therefore passed a member count of **1**, although it visits **256** entries. Repeated updates compound the omission. Sharing the same dictionary cells between updates does not eliminate the repeated validation work.

### Impact and preconditions

A legitimate proposer/signer can obtain a quote that omits a variable component of the proposal and execute computation. Depending on fee settings, available value, action shape and existing headroom, execution may exhaust its gas/value budget. The parent validates actions before `accept_message`, so the parent's existing balance is not a substitute for correctly funding that validation step. If the order has already fired, a failed parent execution can leave the intended actions unperformed.

The missing cost term is established from source. A full TVM transaction reproducing an out-of-gas failure at exactly the old quote was **not** executed in this review. This is an underpricing/liveness finding, not a demonstrated asset-theft exploit.

### Applied fix

```func
signer_count = count_members(cs~load_ref());
int proposer_count = count_members(cs~load_dict());
multisig_order::require_valid_threshold(threshold, signer_count);
installed += signer_count + proposer_count;
```

The running cost counter now includes every visited signer and proposer in every update. The final `signer_count` and threshold are unchanged: proposers do **not** become approvers. The legacy fee-profile field name `parent_gas_per_updated_signer` is retained, but this caller supplies the total member visits to the same `count_members` implementation. No opcode, storage layout, address derivation, approval format or signature format changes were made.

### Regression vectors added

The new FunC file imports the production wallet rather than reimplementing its validator. The existing `crypto/func/auto-tests/run_tests.py` discovers all `.fc` files in its tests directory, so no separate registration change is required.

| Vector | Required result |
| --- | --- |
| One signer, 255 proposers | 256 priced visits; final signer count remains 1 |
| Three signers, no proposers | 3 priced visits; existing signer-only behavior retained |
| Two updates: (1,255), then (3,2) | 261 visits, not just the last update's count |
| Same 2-signer / 7-proposer dictionaries reused twice | 18 visits, not 9 |
| 255 signers and 255 proposers | 510 visits |
| Threshold 2, one signer, 255 proposers | `invalid_config`; proposer count cannot satisfy quorum |

As first committed, the file did not assemble: it included the wallet, whose `recv_internal` is method 0, and also defined `main`, so Fift stopped with `procedure already defined` and none of the six cases ran. The follow-up removed `main`; the results are in the last section.

## F-02 — P2 / conditional configuration risk: indexed approvals do not enforce unique signer addresses

### Evidence and minimal trace

`multisig_order::approve` and Tol `MultisigOrder.approve` authorize `sender` against the address at a supplied index, then deduplicate approvals using a bit for that **index**. `multisig_order::signer_count`, Tol `multisigOrderSignerCount`, and the parent's `count_members` count dictionary entries; they do not reject duplicate address values.

For a stored signer configuration:

```text
index 0 -> Alice
index 1 -> Alice
index 2 -> Bob
threshold = 2
```

Alice's approval at index 0 sets bit 0 and increments the count to 1. Alice's approval at index 1 passes the same sender check, sets a different bit and increments the count to 2. The order fires without Bob.

This is a source-level trace, not a native sandbox reproduction performed here.

### Important qualification

The trace requires a duplicate-address signer configuration at deployment, or an update installing such a configuration that was itself approved by the existing quorum. It is **not** an outsider bypass of a correctly configured unique-address multisig. If repeated indices intentionally represent signer weights, that must be an explicit API/security contract rather than being described as independent M-of-N signers.

### Unresolved in this patch

No runtime uniqueness change was pushed. Closing the unique-address interpretation requires a coordinated change, not merely changing the entry count:

1. Validate exact canonical address values and uniqueness of signer identities at signer-set construction/update boundaries. Preserve sparse uint8 indices and permit index 255; a set may have at most 255 entries.
2. Apply equivalent rules to FunC and Tol constructors and document the trusted-input precondition of the `new_with_count` fast path. A count supplied by a caller is not proof of uniqueness.
3. Ensure deployment tooling validates the initial signer configuration; the wallet's update validator is not an initial-storage validator.
4. Re-measure gas and message/state-size profiles for any runtime implementation change. Naively scanning the whole signer set on every approval would invalidate the current constant-cost approval/init assumptions.
5. Add duplicate-address, malformed-address, sparse-index, maximum-size and normal-flow tests. Duplicate configurations must be rejected before they can authorize an order, or explicit weighted semantics must be documented and tested.

This item was open at review time; see "F-02 resolution" below.

## Action-phase observations: do not import an upstream conclusion blindly

The highload wallet forces `IGNORE_ERRORS` and commits replay state before outbound parsing. Whether a particular action failure preserves the state depends on the actual TOS executor/configuration, not just on `COMMIT` appearing in the source.

At the reviewed revision, `Transaction::try_action_send_msg` in `crypto/block/transaction.cpp` routes invalid send-mode combinations through `check_skip_invalid` at global version 13 and later. Consequently, an upstream-style claim that an invalid mode alone defeats this wallet's forced `+2` at the fixture's version 14 was not accepted as a confirmed finding. The existing fixture's signed mode is fixed to 1, so broader mode/configuration coverage would still strengthen the test evidence.

No universal guarantee covering every global version, state-size limit, malformed cell or action list is made by this review.

## Verification performed and not performed

Performed:

- Read live PR metadata, changed-file list, relevant source and selected test fixtures through GitHub.
- Pinned the initial review to the exact head above and read back the modified source after writing.
- Verified the local copy of the original wallet against Git's blob hash `492c9a51256002b4fb4b18b8a59e0e0b9832a5b8` and the patched copy against `5643663dbe578139576dc81f50c9b38a325900ce`.
- Checked the new file's six-case test manifest, delimiter balance and whitespace. These checks are not a compiler.
- Independently checked the arithmetic of all 65,280 valid single-update signer/proposer count pairs and the multi-update vectors. Four of the five positive vectors distinguish the old counter from the fixed counter. This is a mathematical model, not execution of the contract or mutation testing of compiled bytecode.

Not performed:

- FunC/Fift compilation or execution of the new tests.
- TOS C++ TVM/emulator execution, fresh fee-profile measurement, complete Rust sandboxes, or complete Tol regression suite.
- Exhaustive independent equivalence, fuzzing or formal verification.

The working environment did not have `func`, `fift`, `test-emulator` or `cargo`. The PR description's previously reported test totals belong to an earlier revision and are not evidence that these new commits passed.

## Required native follow-through before sign-off

Run the normal `test-func` target (including the new file), `test-emulator` fee-profile tests, and the multisig sandbox suite on the final branch head. For focused FunC execution, the existing runner accepts the tests directory:

```sh
FUNC_EXECUTABLE=/absolute/path/to/func \
FIFT_EXECUTABLE=/absolute/path/to/fift \
python3 crypto/func/auto-tests/run_tests.py crypto/func/auto-tests/tests
```

Extend the native multisig fee fixture's `actions` helper/case matrix to construct nonempty proposer dictionaries and include at least (one updated signer, 255 proposers), (255 signers, 255 proposers), and repeated updates sharing proposer dictionaries. Verify the actual quote covers the measured path; also execute the quote-funded transaction path rather than relying only on the fixture's generous balance. Do not invent newly measured profile constants.

Resolve F-02's signer-identity semantics and close its corresponding tests before calling the multisig a unique-address M-of-N implementation. No merge or approval was performed as part of this review.

## Native follow-up verification

Run on the branch head after the review commits, with the follow-up changes below.

Follow-up changes:

- `lib-multisig-wallet-members.fc`: removed the duplicate `main` that kept the file from assembling.
- `emulator/test/multisig-fee-profile-fixture.cpp`:
  - The quote coverage matrix now builds nonempty proposer dictionaries. It adds (1 signer, 255 proposers), (255 signers, 255 proposers) for both a 3-signer and a 255-signer wallet, and two updates sharing the same (1, 255) dictionaries.
  - A wallet of 255 signers with 200 actions and an update installing both full sets exceeds the order's 1024-cell action limit and is refused with `order_too_large`. The largest in-limit combination is used instead.
  - New test `QuoteFundedOrdersExecuteWithoutWalletSubsidy`. For every case it runs the whole path as complete transactions on the C++ executor, funding the proposal with exactly `get_order_estimate`: proposal, order deployment, two approvals, execution. Every transaction must succeed in both the compute and action phases, and every action payment must arrive. The wallet's balance must not fall by more than the actions themselves pay, which is their values plus the forward fees of their messages (send mode 1).

Results:

- `run_tests.py` (FunC): 35 files pass, including the six new cases.
- `test-emulator`: all tests pass, including the extended quote matrix and the quote-funded path for nine cases.
- `multisig_wallet_sandbox.rs` (15 tests) and `highload_wallet_v3_sandbox.rs` (11 tests) pass.

Sensitivity of F-01. With the counter reverted to `installed += signer_count`, three tests fail:

- the new FunC file fails;
- the quote matrix fails at (1 signer, 255 proposers): quote 129,679,583 against an actual path cost of about 296,959,069;
- the quote-funded path fails at the same case, because a transaction on the path does not complete.

This reproduces F-01's effect on the executor: an order funded with the old quote did not reach execution.

The actions' own forward fees are not part of the quote. With 255 send actions, the wallet pays about 102,000,000 in forward fees for its outbound messages. The quote prices the path that takes an order to execution. The actions are payments the signers approved, with a send mode the action chose, so their fees are counted with their values.

F-02 was not addressed by this follow-up; see "F-02 resolution" below.

## F-02 resolution

Signer sets now give each address exactly one vote.

Rule: a signer set lists each signer as a plain `addr_std` (267 bits, no references), in strictly increasing address order by index: workchain first, then account id. Indices may be sparse and may reach 255. Equal addresses can never both satisfy a strict order, so one comparison with the previous entry detects a duplicate.

Where the rule is enforced:

- `multisig_order::next_signer_key` and Tol `multisigOrderNextSignerKey` check one entry against the previous one. `multisig_order::signer_count` and `multisigOrderSignerCount`, and so `new` and `multisigOrderNew`, apply the rule to the whole set.
- `new_with_count` and `multisigOrderNewWithCount` keep their fast path. They document that they trust their caller to supply a set satisfying the rule, because a count alone does not show the addresses are distinct.
- The wallet applies the rule to every signer set an update installs, at proposal and again at execution. Proposer sets keep the previous rules, because proposers open orders but never vote.
- The new getter `get_checked_signer_count` applies the rule to the current set. The wallet's initial set is the deployer's input, and no code runs on it. It is checked by calling this getter before deploying or joining a wallet.

Rejected alternative: checking the current set on every proposal. It was implemented and measured: a proposal on a 255-signer wallet went from 69,565 to 455,962 gas, and the largest valid combination no longer fit the gas limit of the estimate getter. The deployer can also write any initial state, so a per-proposal check cannot replace checking before deployment.

Cost: the per-installed-member gas in the fee profile rose from 866 measured (profile 960) to 1,881 measured (profile 2,070), because every installed signer is now checked. Installed proposers are charged at the same rate although they cost less. This overcharge is conservative, and the excess stays with the wallet.

Tests:

- Library, with identical vectors in `lib-multisig-order.fc` and `stdlib-multisig-order-positive.tol` (case 116).
  - Accepted: a sparse ordered set up to index 255, and an ordering decided by workchain before account id.
  - Refused: one address at two indices; a descending order by account id; a descending order by workchain; a trailing bit; `addr_none`; the anycast form; an entry with a reference; and `new` over a duplicate set.
- Wallet, in `lib-multisig-wallet-members.fc`, through the production validator:
  - duplicate and unordered signer sets are refused, including when a later update in the chain installs them;
  - proposer sets are not subject to the rule;
  - the getter counts a valid stored set and refuses a duplicate one.
- Sandbox, in `multisig_wallet_sandbox.rs`:
  - `an_update_cannot_list_one_signer_twice`: a proposal installing alice twice, or an unordered set, is refused before any order exists.
  - The fixture now orders its signers and asserts `get_checked_signer_count` on every deployed wallet.

Sensitivity: each of these mutations makes a test fail.

- the order comparison, the length and reference check, and the `addr_std` tag check, removed in FunC and in Tol separately;
- the wallet skipping the rule for installed signers;
- the getter returning the stored count unchecked.

Full runs after the change: FunC 35 files; `test-emulator` 99 tests, including the quote matrix and the quote-funded path; tol-tester 674; Rust sandboxes 16 + 11.

## Remaining follow-up items

Deployment tooling for the initial signer set:

- `crypto/smartcont/new-multisig-wallet.fif` builds a wallet's initial state from signer and proposer addresses given in any order and in any address form.
  - It assigns signer indices in increasing address order.
  - It refuses an address given twice, including the same address written in two forms.
  - It refuses a threshold outside 1..signers.
  - It then runs the wallet's own `get_checked_signer_count` on the state and refuses it unless the count matches. It saves the StateInit and the address.
- `crypto/CMakeLists.txt` generates the wallet and order code it includes.
- `crypto/smartcont/tests/test-new-multisig-wallet.py` (CTest `test-new-multisig-wallet`):
  - runs the accepted case and reads the saved StateInit back through the wallet code: signer count, threshold, address;
  - runs six refused cases;
  - runs a copy of the script that lists signers in reverse order, which the wallet's check must refuse.
- Sensitivity: removing the script's duplicate check, or its call to the wallet's check, makes the test fail.

Wider coverage for the high-volume wallet:

- `EveryModeAndMessageConsumesItsId` signs requests with send modes 0, 1, 3, 16, 17, 32, 64, 128, 160, 192 (the invalid 128 + 64) and 255.
  - It runs them for an ordinary message, a message to `addr_none` and one with malformed extra currencies.
  - It runs everything at global versions 14 (genesis) and 15, as whole transactions on the C++ executor.
  - Every request without +32 consumes its query id.

That coverage found an issue: a request could send with +32 (destroy if zero).

- An account deleted that way can be deployed again at the same address from its public StateInit, with empty replay dictionaries.
- Once funded again, every request it had accepted that was still fresh could run a second time.
- The wallet now refuses +32 before acceptance (throw code 39), so the request costs nothing and its query id stays unused.
- An `internal_transfer` batch is checked too: an action list holding a send with +32 is refused before it is installed.
- `NoRequestCanDestroyTheWallet` covers both paths, and checks that a batch without the flag still runs and keeps the account and its replay state.
- Removing either check makes it fail.

Full runs after these items:

- `test-emulator`: 101 tests
- FunC: 35 files
- tol-tester: 674
- Rust sandboxes: 16 + 11
- CTest `test-new-multisig-wallet`
