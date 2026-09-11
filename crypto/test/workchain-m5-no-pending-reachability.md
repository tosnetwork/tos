# Withdrawal pending installation: current reachability boundary

Normative basis: memo `01a82572`, specification SHA-256 prefix
`aaac1f54cce57364`. Source inspected at `2353777c7`.

## Observation, not a completed host check

`5f628635d` introduced `uno/crypto/src/withdrawal_statement.rs`, not a Native
prepare transaction. `WithdrawalStatement::new` returns an owned statement
containing a domain, fee, context bytes and ten points. Its inputs contain no
mutable account state, account dictionary, pending installer or effects sink.
Its accessors return immutable references; `verify` returns `Result<(), AbiStatus>`.
Neither operation emits an authenticated account root or a payout.

Consequently, installing a pending receipt through this particular interface is
currently unrepresentable. This is a source/interface reachability observation,
not a successful behavioral test of a node rejecting an illicit receipt. No
synthetic installer was added to manufacture a red control.

The Native `WorkchainReplayInput` dispatch in
`crypto/block/workchain-confidential-input.h` still handles transfer,
registration and closure. The dedicated Withdrawal codec does not by itself
install a prepare execution branch. The test-only `withdrawal_pending` predicate
in `crypto/test/workchain-m5-accounting-assertions.h` explicitly leaves its
authenticated-state adapter unimplemented; its map comparisons are not evidence
that such a node adapter exists.

## Activation point and required control

The violation becomes reachable when a Native Withdrawal prepare branch can
publish account updates and a payout. It need not wait for Failed settlement:
accidentally reusing the ordinary SEND pending installer in prepare is already
enough. Failed receipt issuance is a separate, intentionally permitted operation
and must not be used as a substitute for testing this prepare boundary.

Before enabling that prepare branch, install a read-only comparison over the
complete authenticated account-to-pending cut before and after the isolated
operation: user entries, system entries, pending_count and system_pending_count.
Do not compare only proposed effects or only the withdrawing account. Mutation
controls must install a receipt in the source account and in another account,
commit the resulting account artifacts, and reach the named host rejection.
The unchanged authenticated cut must pass. The metered entry must precede its
host caller; do not create an unmetered path to expedite this test.

No production code or guard criteria changed for this finding. No host
no-pending enforcement, mutation-control success, live Withdrawal execution or
completed D34 review is claimed. The item remains an explicit integration gate,
not a completed minting-safety check.
