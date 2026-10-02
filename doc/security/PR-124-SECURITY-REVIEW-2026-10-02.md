# PR #124 security review — 2026-10-02

## Status and exact scope

Initial reviewed head: `924cf0970532b5794fcee635e8ff67755c326041`.
Head branch: `tol-stdlib-audited-patterns`.

**One confirmed fee-accounting defect has a source fix and six new regression vectors. Native execution of the patch has NOT been verified in this review. A separate, conditional signer-configuration risk remains unresolved. This is not a security approval or a claim that every path in the PR is safe.**

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

These are added regression cases, **not six tests reported as passed**. Native compilation/execution remains required.

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

This item remains open. The limited fee-counter fix above must not be represented as closing it.

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
