# C3 host-side preflight contract (not C3 closure)

## Authorized boundary

This is the host half of the post-M1 resource-cap work. M1 already closed at
`dd2327c90`, with the gate closed. The prerequisite for concrete C3 closure is
**an identified production preflight implementation**; that prerequisite is
currently not satisfied. Existing `proof_work` implementations found in the
tree are test substitutes; the configured production adapter only forwards.

This host helper neither implements that engine nor replaces the existing
`ProofAdmittedBatchInput::admit()` call. That call still invokes `proof_work`
before comparing its returned verification-work declaration with
`max_proof_units`. There is no production call site for the new helper. The
four refusal branches remain collator 1 / validator 3, unchanged.

## Default expiry check

`test-workchain-preflight-expiry` is registered in `crypto/CMakeLists.txt`,
independently of the opt-in native module. When a production implementation
appears, connect this budget contract as its sole budget entry, delete the
expiry guard, remove the private-only qualification and retarget controls to
the actual production call site. This does not prove that the engine charges
every operation: that remains the concrete-engine unit's obligation.

The guard inventories every `proof_work` identifier in Git-visible first-party
C/C++ sources (tracked and nonignored untracked additions). It excludes test,
documentation and vendored directories, not all files except two known paths.
Its five exact token identities in two production files cover two abstract
declarations, the existing admission call, and the adapter body/forwarded call.
There is no whole-file exemption. Additional occurrences and changes to those
recorded tokens fail closed; preceding return types, enclosing class names and
call receivers are not fingerprinted. Comments and whitespace cannot authorize a new body.
This is a lexical lifecycle guard, not semantic C++ analysis: generated or
token-pasted identifiers and code outside that source inventory are not claimed
covered. Native private budget tests remain separately opt-in.

Consequently C2 alone is a bound with a preflight-sized hole, **not a complete
per-block resource bound**. The closed gate is the reason this incomplete
state is acceptable. Completing these mechanisms does not authorize moving it.

## Contract and interface to C2

`WorkchainPreflightRunner::run(reservations, allowance, inspector)` reserves
the whole explicitly supplied nonzero allowance before it invokes the inspector.
Zero allowances remain representable inputs but fail as InvalidAllowance before
reservation or callback entry; no codec acceptance is implied. A nonzero
reservation is never refunded even for an empty inspector body.
`WorkchainPreflightReservations` is an interface, not an accumulator:
collator accumulation and validator independent recomputation must implement
their own logic. The private test's accumulator is neither production logic.
The helper does not authenticate its scalar allowance or select policy defaults.
The integration must supply a pre-inspection bound from authenticated policy
and bounded input admission, not from the result of that inspection.

`WorkchainPreflightMeter::perform(units, operation)` checks and charges before
calling the operation. It is noncopyable/nonmovable, its constructor is private,
and no reset/refund is exposed. Refusal is sticky even if the inspector ignores
the boolean result. Zero-priced operations are rejected; genuinely empty
inspection can perform no operations. The return value declaring verification
work is kept distinct from consumed preflight work. Tests deliberately use
different numbers for the two.

The unit is an explicitly supplied profile operation count, **not time or
money**. This helper assigns no wire version, no weights, no production
numerical values, and no implicit relationship between preflight and backend
operation units. B owns the authenticated policy encoding. Binding to those
fields and an approved profile identity remains a separate integration step;
synthetic test numbers are not approved configuration.

Reservation failure prevents callback entry. Inspection failure, including an
exception, leaves the successful reservation in place. The result reports
failure nature, preserving the original `td::Result` or exception payload;
it does not infer candidate/local provenance from message text or exception
class. Dispatch on the primary reason before reading a callback result:
a meter refusal dominates success or a secondary exception. Original exception
payloads must be consumed in the synchronous owner's lifetime.

## Correspondence to the existing base-workchain limit path

The reference is `ParamLimits` and `BlockLimitStatus` in
`crypto/block/block.h`, block cumulative gas use in collator, independent
`total_gas_used_` in validator, and pre-operation gas deduction in
`crypto/vm/vm.h`. B's encoding reuses the existing limit shape; this helper
does not duplicate its codec or three thresholds.

Do **not** copy the validator's `hard + single-transaction gas allowance`
comparison into preflight. Here the entire invocation allowance must be known
and reserved before beginning, so no last-call grace is needed. That conclusion
is conditional on C3's advance allowance and complete operation coverage;
the existing unmetered `proof_work` path does not meet those conditions. Its
returned declaration is not the cost of producing the declaration.

## What is not enforced by this helper

Native C++ is not sandboxed. An inspector can perform work outside `perform`,
or supply an incorrect operation weight. The host helper cannot preempt that
work and cannot discover omitted verification or a wrongly constructed
statement. The concrete engine must establish operation coverage and its
input-size bound, including repeated DAG traversal, decoding, allocations,
and successful/failed branches, with independent actual-operation controls.
Auxiliary memory bounds likewise require that concrete implementation; this
work counter is not an allocator or a memory proof. Those obligations are not
discharged by private fixtures or by returning a small number.

## Private execution

Explicitly include `crypto/test/workchain-preflight-budget.cmake` with
`CMAKE_PROJECT_TOS_INCLUDE`, build `test-workchain-preflight-budget -j32`, then
run `ctest -R '^test-workchain-preflight-budget-gates$' --output-on-failure`.
The module registers the Python driver with TIMEOUT and RESOURCE_LOCK. Default
build/registration and the six private I13 checks are unchanged: this is a
separate `private;workchain;c3` label, not an I13 acceptance claim.

The driver pins nine named cases, verifies them against the native dispatch
table's `--list`, and checks the completed-case marker, actual exit and stderr
for each, so an empty or shortened test selection cannot pass. Cases cover
positive operation/declaration separation, reservation before body, charge
before operation, multiple individually allowed calls exceeding a synthetic
block bound, exact capacity, sticky refusal, failure without refund, original
exception preservation, secondary-exception precedence, unavailable/unknown
reservation results, unsigned overflow, zero-allowance and zero-charge rejection.
The meter is a borrowed synchronous object; storing its pointer beyond `run`
or across a suspension is prohibited and not made safe by noncopyability.
