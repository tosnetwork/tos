# Authenticated host debit checkpoint — not complete prepare

Norm: memo `6f440f8d`, SHA-256 prefix `edd8b81c68ecba44`.
Scope follows the owner's narrowed criterion: one real host account debit
observable in the authenticated successor. W creation and payout are absent.

## Executed observation

Command: `python3 test/uno-m3-live.py --build /tmp/uno-merge-6ea2fbf80-tL5Uih --m5-debit`.
Fresh test chain `/tmp/uno-m3-live-nrzfu_lk`: register A/B, real Native Deposit,
COLLECT, then the debit-only checkpoint. No confidential test funding was used.
The registered C++ engine verifies the D64 proof through the metered ABI before
returning account writes; the existing Native host materializes them. Actual
collator and validator actors run; this is not a multi-node network claim.

The final actor outputs were `collate 0`, `validate accept`. Reading the accepted
state (derived from the exported candidate's state update) and decrypting with
the test key gave:

- available: `1000000000 -> 999999603`;
- available revision: `1 -> 2`; nonce successor equality also asserted;
- debit: `100 + 17 + 23 + 257 = 397`;
- explicit test fee: state `250`, compute `2 * 1`, sender tip `5`;
- precharged proof work: collator `3632`, validator `3632` (not billing units).

The authenticated block ID was
`(2,8000000000000000,5):5ECC1994F0F648DA7D60F7084312F0A89B314183ACB405B42B68FDF1F87857F4:238C18BF189E3C528FFE1ED38FB8DF9167DD83090DF762EDD0609725E394B42C`.
Artifacts saved **before** the later test failure:

- `debit-authenticated-state.boc`, SHA-256 `63e1d50d8852b5b1e3849fa9fe9254e017396a914adbd13057aead1e8eef9ddd`;
- `debit-authenticated-block.boc`, SHA-256 `238c18bf189e3c528ffe1ed38fb8df9167dd83090df762edd0609725e394b42c`.

OFF reported `collate -7201`, phase 3, recorded delivery, zero transactions;
the existing driver also checked zero engine execution and no candidate export.
Original production gate strings/defaults were not edited. This is not the
complete nine-item ON/OFF/oracle contract or a pre-edit isolated rollback claim.

## Exact stopping point and limits

After the real debit observation, the existing test-side accounting/replay
decoder rejected the new checkpoint wrapper with `-7200: unknown confidential
replay tag`; the parent driver aborted. **The whole script is not green.** This
is not a demonstrated value-flow rejection and is not a validator rejection:
the validator had already accepted. Existing backing assertions were retained.

The checkpoint uses a distinct test wrapper around the real Withdrawal wire
and its real proof, only in the existing D59 test engine. It is not a completed
production Withdrawal operation. Outward fee and reserve are proof-bound test
inputs here, not yet reconstructed Native prices. No W/P, enqueue, phase-0
evidence or payout is claimed. The temporary debit-only route must not be used
as a completed prepare or left as a substitute for that route.

B's nine prepare contract tests remain **0/9 ready**: debit, overflow,
no-pending, record, cap, fee-admission, enqueue, onoff, oracle-control are not
registered as completed tests. In particular the full all-account pending-cut
mutation/oracle controls are outstanding. Neither existing guard is retired.
Unknown-provenance counter: **not installed / unmeasured, not zero**.
Error classification is not closed; this commit is not wiring acceptance.

Production library changes: `workchain-proof-work.h` adds a metered request
overload; `workchain-proof-backend.cpp` adds its dedicated ABI call. The profile
counts the existing extra constructor `relation::prepare` as well as verify's
prepare. No claim of independent backend trace verification is made here.
The new debit branch itself is test-owned in `workchain-m3-node-engine.h`.
