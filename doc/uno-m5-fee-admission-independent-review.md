# Withdrawal fee admission: independent matching-proof control

B, 2026-09-11. Follow-up to `69df994b9` and the D76 anchor table.
Specification: memo `8b96aa66`, SHA256 prefix `24291053f8c289fe`.
Implementation under review: `65b819639` / unchanged relevant paths in
`7f23ceb79`. No production or A-owned source was changed.

**The missing independent negative control is now executed at the actual
registered test engine's prepare entry.** The coordinator accepted the `fee-admission` item as green (memo `319c1003`,
SHA256 prefix `21e3852817331916`). This is not a new live block run or completion
of the entire WITHDRAWAL-PREPARE contract. Default CTest registration remains
a separate integration step; the fail-closed runner has not been weakened.

## Inputs and independent observations

The archived live fixture provides the configuration, previous accounts, and
permanent accepted Block -> AccountBlock -> Transaction -> entry.input. The
probe extracts that actual host input, resolves configuration through the
original `M3NodeEngine::validate_and_resolve_config`, and constructs its account
read view from the archived predecessor. It changes the candidate's fee, matching
new available ciphertext, operation-data-bound context and authorization.
It does not substitute a newly invented fee-only host function.

The decoded authenticated tariff has **base=2, state_fee=250**, hence the
independently checked floor is **252**. The two fees are 252 and 251, with checked
subtraction for the latter. The old fixture's f=257 is not used as the floor.
Principal=137, q=100 and b=23 remain identical. Explicit fixture values are not
protocol defaults or proposed frozen values.

For **each** fee, the existing `uno/prover` m3-scenario tool generates separate
matching points and a proof after the operation context has been rebuilt.
The probe then invokes `execute_m5_test_debit` with a fresh real verifier to
verify the proof independently of fee admission. Only afterwards does it invoke
`M3NodeEngine::execute_metered_accounts` with another fresh verifier.

| Case | Separate real kernel verification | Actual engine result |
|---|---|---|
| f=252 | OK, 3636 proof-work units | OK; prepare effects produced; S=250, C=2, tip=0 checked |
| f=251 | OK, 3636 proof-work units | -7200, exact message `Withdrawal public fee below authenticated fee floor`; engine verifier consumed 0 units |

The low case is therefore not green because of a mismatching proof. The exact
fee rejection occurs at `workchain-operation-fees.h:38–39`, reached by
`workchain-m3-node-engine.h:247–248`, before this engine invocation's proof call.
A separate kernel invocation already established that its proof was valid.

## Removal control and restoration

Only the isolated shadow helper's floor rejection was removed:

```
(void)__builtin_sub_overflow(claimed_fee, floor, &tip);
```

The normal code rejects when that builtin reports underflow. The mutation keeps
the builtin but ignores its result. It does not alter the fees, config, proof,
context, node-engine entry or test expectation. Patch is included in the evidence.
This deliberately faulty path may produce nonsensical later fee components;
**no claim is made that a full settlement/block would accept those components**.
The observed property is the required admission rejection at this entry.

With the same f=251 proof:

1. Independent kernel verification still passes, 3636 units.
2. The engine returns effects instead of the required fee rejection.
3. The probe fails specifically at `CHECK(result.is_error())`, line 55.
   Its process terminates with **SIGABRT** (Python returncode **-6**), not exit 1.
4. Restoring the original helper restores both outcomes in the table, exit 0
   for each checking invocation. No new proof was needed for restoration.

An additional backend sanity control changes one response byte in the otherwise
matching proof. The real verifier returns the specific -7200
`Withdrawal cryptographic proof rejected`, with positive consumed units. This
rules out treating a successful stub backend as proof-validity evidence.

## Observation and execution boundaries

- **Observation:** real kernel status/consumed work, actual engine return status,
  exact fee error and returned S/C/T effects. No claim of Native publication,
  collator import, accepted new account roots or D32 physical settlement.
- **Execution:** actual configuration resolver, test-only proof precheck, and
  original registered `M3NodeEngine::execute_metered_accounts` prepare branch.
  Full outer registry admission/materialized-arena construction is not rerun;
  this standalone probe reconstructs the read view from the archived fixture.
- `WorkchainProofTestAccess` supplies an explicit test budget of 100000, not a
  production resource-policy default. The backend is compiled with
  `TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED` and linked to the real Rust library.
- Account/config artifacts originated in A's accepted run. Generation and
  verification of these two new authorizations, engine calls, and removal /
  restoration observations were performed independently by B.
- This is post-implementation review, not a prediction. No frozen prediction was
  edited, no guard retired, and no default CTest selector was silently marked ready.

## Evidence and replay notes

[Evidence directory](measurements/uno-m5-fee-admission-independent/) contains
probe source, both requests/points/proofs, original fixture inputs, exact mutation
patch, result logs, and hashes. `probe.cpp` retains the paths of the actual run:
fixture `/tmp/uno-m3-live-grcv32yz`; output directories were
`/tmp/b-fee-admission/high` and `/tmp/b-fee-admission/low`.

Commands per side were `probe init OUT high|low`, then
`m3-scenario withdrawal-points OUT/request.txt OUT/points.txt`,
`probe context OUT high|low`,
`m3-scenario withdrawal-prove OUT/request.txt OUT/proof.txt`,
and `probe check OUT high|low`. `probe badproof OUT low` is the backend sanity
control. The bundled fixture can be copied to the stated temporary path in a
fresh environment; do not overwrite another worker's live fixture.

The shadow build exported `65b819639` crypto/block and crypto/test headers,
compiled this standalone probe and that commit's real proof-backend.cpp, and
linked existing native libraries. The standalone main replaced test-td-main;
no test-workchain-block backend stubs were linked. Real Rust library and prover
binary hashes are recorded. This is not a hermetic rebuild of all dependencies.

Build setup initially found the ordinary native build lacked the Withdrawal Rust
symbol; the actual live build's real Rust library was then explicitly selected.
That link failure was a tool/dependency mismatch, not a fee-admission failure.
An initial control wrapper incorrectly expected exit 1 from CHECK; the observed
termination was SIGABRT. The result and the restored runs above retain its real
classification rather than rewriting it as exit 1.
