# M5 encoding handoff

Branch: `agent/uno-m5-encoding`, worktree `/home/tomi/tos-m2`.
Specification: memo main `01a82572`, SHA256 prefix `aaac1f54cce57364`.
The newer user messages, especially the D69 corrections, supersede older prose.
A owns host integration and ABI inventory; B owns TL-B and encoding. Never hash
or import A's WIP. A's committed `0f799c88e` was merged as `66505f935`.

## Preserved work and evidence

- `48dca2c42`: D64 review, proof tests and the original frozen symbolic prediction.
- `0e8fbbc12`: D66 applicability addendum and earlier interface proposal.
- `76a317394`: initial Withdrawal wire/context/record codec. Its free Attempt
  sequence was wrong and is superseded by the next commit.
- `ccc24052e`: one Attempt per Withdrawal, no attempt sequence/counter; bounded
  control envelope, ID Add semantics, independent created_lt uniqueness,
  enumerated count and nonempty control closure check. Six codec tests passed;
  isolated LT/count/closure check removals each exited 1. The existing three
  M3 wallet vectors passed their unchanged field and candidate-hash assertions.
- `475214710`, `9be4f9c67`: frozen D68 shortfall prediction and English-reference
  correction. Do not rewrite these or the older prediction to fit observations.
- `fc55a5590`: WIP D69 origin codec, V2 primitive ABI and complete schema-3
  account-envelope codec. No node call site is installed by this commit.

Executed on the fc55a5590 contents:

    cargo test --locked --offline --lib system_encryption
    # cwd uno/crypto: 7 passed, 0 failed (debug)
    cmake --build /home/tomi/uno-m3-refund-assert-build --target test-workchain-withdrawal-codec -j2
    ctest --test-dir /home/tomi/uno-m3-refund-assert-build -R '^test-workchain-withdrawal-codec$' --output-on-failure
    # 1 CTest target passed; direct executable: 9 tests passed

The tests cover all three origin roundtrips, zero/truncated sequence rejection,
actual C++ canonical origin bytes consumed by Rust V2, unchanged D33 fixed
ciphertext, distinct new-member transcripts, schema-3 full-root roundtrip,
4-root-reference framing, old/new decoder rejection without implicit migration,
account binding and malformed control. Two identical sweep attributions with
sequences 41/42 produce different receipt IDs AND different commitment/handle;
old ciphertext verification under the second request returns VERIFY=3.
These are codec/primitive results, not successful host issuance/settlement.

Local logs: `/tmp/d69-rust-tests.log`, `/tmp/d69-codec-build.log`.
Logs are convenient, not required inputs to reproduce the committed tests.

## Callable APIs and representation

`crypto/block/workchain-system-origin.h`:

- `WorkchainSystemOrigin` variant: Deposit, Settlement, Sweep; tags 0/1/2.
- `encode/decode_workchain_system_origin` and `derive_workchain_system_receipt_id`.
- `encode_workchain_system_origin_transcript`: exact canonical bytes, 41/115.
- `encode/decode_workchain_system_receipt`: new tagged receipt; old receipt
  constructors and Deposit identity derivation remain unchanged.
- Sweep attribution stores type 2, src workchain/address, account_id, uint256
  value and return_failed. Host must enforce D62 eligibility, not trust encoding.

`crypto/block/workchain-withdrawal-account.h`:

- `encode/decode_workchain_withdrawal_account(value/root, authenticated_limit)`.
- `WorkchainWithdrawalAccount` holds `account`, authenticated `control`, and
  `origin_pending`. The legacy system receipts in `account.system_pending` and
  new `origin_pending` share ONE capacity of four and ONE Add-only dictionary.
- `account.schema_version` is 3. Component validation reuses an internal schema-2
  projection that is never installed; input decoding accepts only the new root.
- Both account and control expose lifecycle; their encodings must agree.
- Existing generic account/ReplayInput decoders have NOT been expanded. A must
  dispatch the new tags to their dedicated APIs and perform explicit migration.

Rust `SystemEncryptionRequestV2` / generated C header: abi_version 2, domain,
receipt_id, recipient, amount, origin[115], origin_bytes. Tail bytes zero.
`uno_crypto_system_encrypt_v2` / `uno_crypto_system_verify_v2` are additive;
Deposit delegates to unchanged v1 transcript. New source labels differ. See
`uno/crypto/ABI.md` for exact byte order and host provenance obligations.
The ABI does not independently parse/authenticate TL-B attribution or its ID.

## Exact next steps

1. COMPLETED after the handoff commit: run
   `python3 crypto/test/workchain-d69-sequence-controls.py --repo /home/tomi/tos-m2 --build /home/tomi/uno-m3-refund-assert-build`.
   Deposit, Settlement and Sweep each exited 1 at `missing.is_error()` after
   removing only the required-sequence check. The initial ccache argument-order
   tool failure was corrected; it was not counted as a mutation result.
2. Add/run removal controls for the new complete-account combined system count,
   account binding and dictionary Add checks as appropriate. Do not claim the
   nine passing tests alone prove these checks detect their targeted changes.
3. COMPLETED after fc55a5590: rebuild `test-workchain-confidential-execution`,
   run its `--filter M3WalletRequests`. FormalVectorFields passed (one named
   test covers all three existing vectors). No vectors or expectations changed.
4. Give A the committed interfaces above. A must add the V2 metering entry and
   register changed Rust files/new ABI test call sites in its owned
   `crypto/test/workchain-crypto-abi-boundary.json` BEFORE any node caller is wired.
   B has not changed that file or claimed the guard green.
5. A must wire the schema-3 root/control into actual host account access, closure,
   COLLECT (both system views) and Failed custody dispatch. The standalone
   nonempty-control predicate is not evidence that the node calls it.
6. Coordinate replacement of the expired M3 no-obligation guard with the
   authenticated-set check. Do not merely delete/update the guard to turn green.
   State-loader inventory also needs an explicit review of the new codec paths;
   source-aware error classification remains the caller's responsibility.
7. Continue D62/D63 real host behavior controls and cross-check actual accounting
   against frozen predictions only after predictions have been committed.

## Boundaries and traps

- No full regression, new host activation, custody Failed acceptance, counter
  installation, no-pending host behavior or complete closure integration is
  claimed by fc55a5590. The source set is WIP despite focused tests passing.
- Deposit transcript and existing vectors MUST NOT be regenerated to fit code.
- Do not weaken coordinator `info.bounced` rejection. Failed/late bounce belongs
  to a separate custody authenticated entry. Use actual incoming envelope.msg
  CellRepr hash, never payout hash or original created_lt as message identity.
- Shared deposit_sequence uses checked increment and same-batch staged state.
  Failed issuance or no-receipt dust MUST NOT install increment. Two constructors
  reading the same batch-old value do not establish sequencing. Pending ID
  collision checks remain mandatory even with a counter and domain separation.
- consumed_return_cost is actual reserve SPENT, capped by original_reserve,
  not total actual return loss c when c>b. Shortfall is an event-derived amount,
  not a persistent payable claim or an operating-budget subsidy.
- K_withdrawal, return reserve and settlement window have no local defaults.
  The latter is not a delivery/safety bound. D68 freezing conditions still apply.
- Do not read A's expected accounting outputs before freezing new predictions.
  Independence is behavioral; coordinator-relayed outputs are not B observations.
- Communication to A repeatedly fails at localhost:42881. Do not retry the same
  message. Coordinator relays; `/tmp/uno-m5-codec-handoff.txt` is only a local
  convenience and older than this committed handoff until explicitly updated.

## Ordered queue item 1: complete account codec delivery

The full-root API was already committed in fc55a5590; it is not awaiting
implementation. `block/workchain-withdrawal-account.h` exports
`encode_workchain_withdrawal_account(value, authenticated_limit)` and
`decode_workchain_withdrawal_account(root, authenticated_limit)`, returning
`WorkchainWithdrawalAccount { account, control, origin_pending }`.
Generic old-account decoding is intentionally not widened. Host dispatch,
explicit migration authorization and calling the closure check remain A's work.

The focused account test now simultaneously installs user, legacy Deposit and
new-origin receipts into the same root. It passes and checks that the retained
legacy Deposit cell hash is unchanged. Combined legacy/new system capacity is
four. Isolated removal of the combined-capacity check and record-account binding
check each exits 1 at the corresponding assertion. Reproduce with:

    python3 crypto/test/workchain-withdrawal-account-controls.py --repo /home/tomi/tos-m2 --build /home/tomi/uno-m3-refund-assert-build

These complete the two new-account checks previously listed under next step 2;
they do not replace the already committed control ID/LT/count/closure checks or
claim actual node invocation of the full-root decoder.
