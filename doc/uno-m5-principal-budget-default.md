# Principal-only Native pricing budget: default CTest integration

This supersedes only the integration-status limitation in
`uno-m5-d76-independent-review.md`; its historical evidence is unchanged.
The integration follows merge `d96d75d98` of A's committed `09a94d798`.
No production implementation was changed for this test integration.

`test-workchain-payout-principal-budget` is unconditionally registered beside
`test-workchain-block`. The included test also runs in that existing full target.
A required success marker prevents an unmatched selector from passing silently.

Observation: Native pair success/refusal and exact legacy refusal code/message.
Execution: real `native_payout_exact_fee_fixture` pricing and pair construction.
Principal-only ceilings 0 and 99 must fail like legacy; ceiling 100 succeeds.
With exact q=100, ceiling 0 succeeds. This does not observe a live queue or
prove all Withdrawal prepare acceptance requirements.

Validation: repository CMake configuration generated the actual default CTest
registration; discovery found exactly one selected test. The current test
translation unit and transaction implementation were freshly compiled against
this tree, linking existing Native dependency libraries. This is not a full
clean rebuild or full-suite result. Initial auxiliary build attempts had a
path collision and mixed-header redefinitions; corrected source include paths
resolved these tool/setup failures before the recorded runs.

Normal CTest: 1/1, exit 0. Isolated mutation changes only
`exact_outward_fee ? custody.balance.tomis : fee_budget` to
`(exact_outward_fee || exact_principal) ? custody.balance.tomis : fee_budget`.
The same test fails at `principal_only.is_error()` (CTest exit 8), before the
success marker. Restoring the original implementation gives 1/1, exit 0.
The mutation was confined to /tmp; no A files or shared production source were
modified. Raw logs are in `measurements/uno-m5-principal-budget-default/`.

The CMake registration is the continuous check; the isolated mutation evidence
establishes that its assertion can fail. This does not retire any handoff guard.
