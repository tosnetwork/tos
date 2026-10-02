# PR #124 security re-review — 2026-10-02

## Scope and status

Reviewed head: `56cf7c71231a8cae43680212d40f5c7f68226560` on `tol-stdlib-audited-patterns`.
Previous review head: `6417ea4a5874612cc3a7668c7bb863fa475e8631`.
The comparison contains four follow-up commits and seventeen changed paths.

This re-review examined the follow-up signer-identity implementation in FunC and Tol, the multisig parent and deployment/preflight boundaries, the updated quote-funded executor fixture, and highload destroy/replay handling and its new action-phase tests. Unchanged PR components were not independently re-audited in full. The generated language-reference PDF was not part of this source-code review.

**Two additional boundary defects are source-fixed below. Native compilation/execution of these new commits and fresh fee-profile checks remain outstanding. This is not an approval or a statement that the whole PR is vulnerability-free.**

## Previous findings and follow-up

### F-01 — proposer traversal omitted from pricing

The production validator still accumulates `signer_count + proposer_count` on every update. The follow-up fixture now includes nonempty proposer sets, repeated updates sharing dictionaries, full signer/proposer sets, and a complete transaction-executor path funded with exactly the quote. This addresses the previous source-level defect and the previously missing test shapes.

The follow-up also removed the `main()` declaration from the original review's regression file: it conflicted with the imported wallet's `recv_internal` at method 0. That was a real defect in the earlier uncompiled test addition. This re-review preserves the correction and adds no second method-0 entry point.

The previous report records native runs and mutation results by the implementation author. Those are existing reported results, not independent native runs performed in this re-review and not evidence for the new commits below.

### F-02 — duplicate signer addresses at different indices

`multisig_order::next_signer_key` and `multisigOrderNextSignerKey` now require a 267-bit, reference-free, plain standard address and strict ascending `(signed workchain, unsigned account id)` order as dictionary indices increase. Strict ordering excludes duplicate addresses while retaining sparse indices, including index 255. Both constructors that count the set enforce the rule; the fast `new_with_count` variants explicitly trust a caller-validated set. The parent applies the rule to installed signer sets, and the Fift deployment script sorts signers and rejects duplicates.

This closes the original duplicate-address trace for configurations built/checked through those boundaries. It deliberately does not scan the entire current signer set on every proposal. Clients using custom initial state must still perform deployment preflight and verify the intended code/state; the signer getter is not a general authenticity certificate. A remaining scalar preflight gap was found and fixed as R2-02 below.

### Highload destroy protection

The external request rejects send mode `+32` before acceptance. The self-message batch scans send actions for the same bit before installing c5; code restoration is retained. The new executor fixture checks the relevant direct and batch paths. No additional confirmed defect in these changes was found in this source review.

Coverage qualification: `EveryModeAndMessageConsumesItsId` currently enumerates eleven selected modes and three message shapes at two global versions. Its name is not evidence of exhaustive coverage of all 256 mode bytes, all cell encodings, all replay-dictionary sizes, or all executor limits.

## R2-01 — P2 / Medium: unsupported parent workchains could use a basechain-only quote

### Evidence and impact

At the reviewed head:

- `new-multisig-wallet.fif` accepted a `workchain-id`, advertised deployment in that workchain, and used it when emitting the wallet address. It did not restrict the parent to workchain 0.
- `multisig_order::address` always derives an order in workchain 0.
- `multisig_order::required_value_for_sizes` prices all four compute phases, both message forwards, and order storage with the basechain fee selector.
- Neither `recv_internal`'s `new_order` branch nor `get_order_estimate` rejected a masterchain parent.
- The native quote-funded fixture deploys its parent as `block::StdAddress wallet(0, ...)`; it does not demonstrate a masterchain quote.

For a parent deployed in workchain -1, the basechain-only price composition is not the composition of its actual parent/order path. Where masterchain tariffs are higher, the estimate can underfund that path. The exact shortfall and resulting transaction failure depend on configuration and available value. This review did not execute a loss or exact-quote failure reproduction on a masterchain deployment.

This is an unsupported-deployment/underpricing finding, not an outsider authorization bypass. Restricting the parent location is preferable here to silently inventing a cross-workchain fee model and calibration that have never been tested.

### Applied fix

`multisig-wallet-code.fc` now defines:

```func
const int error::unsupported_workchain = 0x1a13;

() require_supported_workchain() impure inline {
  (int workchain, _) = parse_std_addr(my_address());
  throw_unless(error::unsupported_workchain, workchain == multisig_order::basechain);
}
```

Both `new_order` admission and `get_order_estimate` call this guard. The proposal check precedes action traversal, seqno allocation and sends. The Fift script also refuses any parent workchain other than 0 before it writes address/StateInit files, and its usage text states the restriction.

Signer/proposer addresses are not restricted to workchain 0 by this change. A basechain wallet can still have a signer in the masterchain; that is distinct from deploying the parent there. Custom deployments must respect the supported location. The guard does not make unsupported deployments usable or guarantee recovery of funds sent to such an address.

### Added regression coverage

In the existing production-importing FunC test file:

- Case 111 accepts parent workchain 0 and requires `unsupported_workchain` for every other int8 workchain value.
- Case 112 invokes the actual quote getter and receiver under a masterchain MYADDR, checks their rejection code, and checks persistent data is unchanged.

The deployment-script test adds refused parent workchains -1 and 1 and verifies no `.addr` or `.init.boc` is written. Its existing accepted case retains cross-workchain signers.

## R2-02 — P2 / conditional deployment risk: preflight ignored cached count and threshold

### Evidence and minimal trace

The old getter was:

```func
int get_checked_signer_count() method_id {
  (_, _, _, cell signers, _, _) = load_data();
  return multisig_order::signer_count(signers);
}
```

It validated the signer dictionary but ignored the two scalar fields passed to each order: the cached `signer_count` and `threshold`.

Consider custom initial data with two distinct, correctly ordered signers, cached count 3, and threshold 3. The old getter returned 2 successfully. A client relying on success from the recommended preflight could miss that the configuration is unusable: `new_with_count` sees threshold 3 and count 3 as valid, but only two signer identities can approve, so no order can reach its threshold. With cached count 2 and threshold 0 or 3, the getter also succeeded although order initialization rejects the configuration.

This requires malformed/custom initial state. The unmodified official script already derives a correct count and checks its command-line threshold; ordinary valid script inputs are not alleged to produce these states. The finding concerns the public getter used to inspect deployed/custom state and the strength of the script's independent serialized-state check. It is a liveness/fund-locking configuration risk, not a demonstrated theft from a correctly configured wallet.

### Applied fix

```func
(_, int threshold, int stored_count, cell signers, _, _) = load_data();
int actual_count = multisig_order::signer_count(signers);
throw_unless(multisig_order::error::invalid_config, stored_count == actual_count);
multisig_order::require_valid_threshold(threshold, actual_count);
return actual_count;
```

The getter now validates dictionary identity rules, cached count consistency, and an achievable positive threshold together. It continues to require only c4, so the script can invoke it on initial data before constructing the wallet address. Workchain admission is checked separately by the script and transaction/quote entry points.

There is no new signer-dictionary traversal in the normal proposal, approval or execution path. This change adds scalar checks only to the existing preflight traversal.

### Added regression coverage

- FunC case 110 rejects six bad `(threshold, cached count)` combinations over a valid two-signer dictionary, including `(3,3)`, and accepts the valid `(2,2)` boundary.
- The Python/Fift deployment test mutates only the serialized count/threshold fields while preserving valid CLI inputs and a valid dictionary. Six variants must fail at the wallet's own preflight, before any deployment files are saved. These cases are designed to distinguish a real serialized-state check from merely trusting CLI validation.

## Commits and compatibility

Changes were pushed directly to the existing PR branch, without merging or rewriting history:

| Commit | Change |
| --- | --- |
| `ff8bd0101b2064c66372d7a8705bbf60778be627` | Parent workchain guards and complete signer scalar preflight |
| `d9d913ddc5b3940456425f6321408e68f3ca3309` | Three added FunC test cases, making twelve entries in the existing file |
| `04639020bb318ddfc97ff6e5d775f30d5f30db6f` | Basechain-only deployment guard and usage/preflight documentation |
| `12bce1c528685c1f072782b5ec1c17fd72729e06` | Two deployment workchain refusals and six serialized-state mutation scenarios |

Existing message opcodes, wire formats, storage layouts, threshold voting semantics and address-derivation algorithms were not changed. The new rejection code is wallet-local `0x1a13`. Recompiling changed wallet code naturally changes its code hash and therefore newly generated wallet StateInit addresses; no bytecode/hash identity is claimed.

The library's fee arithmetic and measured constants were not modified. The parent admission guard adds constant work, not a new signer-dependent cost. This does NOT establish that the old fee profile still meets its measurement bounds: code must be rebuilt and the existing profile and quote-funded executor tests must be rerun on the final head.

## Verification actually performed

- Read live PR metadata, the four-commit comparison, relevant exact-head source, follow-up report and test fixtures via the GitHub connection.
- Checked the branch was still at `56cf7c71231a8cae43680212d40f5c7f68226560` immediately before publishing the patch series.
- Reconstructed the four edited files locally and verified every original file against its Git blob SHA before editing.
- Checked the patch diffs, whitespace, final newlines, FunC delimiter balance, unique method IDs and twelve-entry test manifest, and absence of a second method-0 `main`.
- Parsed the modified Python test with Python's AST parser. This is a Python syntax check, not execution of its Fift subprocesses.
- Verified all four GitHub write responses match the locally computed patched blob hashes; read back the updated getter/quote source.

Patched blob SHAs:

```text
multisig-wallet-code.fc          988a782b8eb7d864314590d96ce687fa6ffbfbc0
lib-multisig-wallet-members.fc   081bd22af8142a4953feb819e9fbc531e057892e
new-multisig-wallet.fif          c0b98881538cddaa5fcbb0ad810b5be0f252d345
test-new-multisig-wallet.py      b657ba34a98e816d979ca66dc724b73e81ca8380
```

The container has no available `func`, `fift`, `test-emulator` or `cargo` command, and direct Git transport could not resolve github.com. Repository reads/writes succeeded through the connected GitHub tools. No native build, FunC/Fift execution, TVM transaction run, fee measurement, complete Rust sandbox run, or complete Tol suite was performed in this re-review. No new native test pass count or compiled-bytecode mutation result is claimed.

The inspected old-head sandbox workflow run `36985980529` was cancelled during toolchain build; its sandbox steps were skipped. It is not a successful validation of either head. Fresh final-head CI/native results remain required.

## Before merge

Rebuild the wallet and both forms of generated code used by the emulator and Fift deployment script, then run the existing targets on the final branch head:

1. `test-func`, including all twelve cases in `lib-multisig-wallet-members.fc`.
2. CTest `test-new-multisig-wallet`, including the new no-output-on-refusal and serialized-scalar mutations.
3. `test-emulator`, especially `MultisigFeeProfile.ProfileMatchesThisBuild`, `QuoteCoversTheLargestWalletsAndOrders` and `QuoteFundedOrdersExecuteWithoutWalletSubsidy`.
4. The multisig and highload Rust sandbox suites, and the existing FunC/Tol equivalence regressions.

If a native profile gate fails, use its actual measurements to adjust the profile; do not fabricate constants or weaken the bound. Also confirm the new workchain guard is enforced in a whole masterchain transaction, not just a direct receiver test, before claiming native end-to-end closure of R2-01.

**Review disposition: the two identified new source issues have patches and regression coverage committed; native verification remains open. No approval, merge or deployment was performed.**
