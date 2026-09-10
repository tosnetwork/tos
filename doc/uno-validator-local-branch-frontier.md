# Validator local branches and their earlier readiness barrier

Baseline: `ba6e289716ab35a54a2f2b6dff1a666fb22829f7`.
The accompanying patch changes only the two AccountBinding visitor arms in
`validator/impl/validate-query.cpp`. It is an unaccepted draft, compiled as the
actual `tos_validator` target. No collator implementation was consulted or
copied to derive these choices.

The first arm controls `ComputePhaseConfig::custom_workchain_block_seqno`.
Its consumer is the legacy `WorkchainComputeContext` passed to `run_compute`
(transaction.cpp:2211 onward). Account batches do not execute through that
per-account interface. The proposed value is false, as for the block execution
family, not a generic claim that UNO is a native engine.

The second arm follows successful authenticated scoped resolution within
`check_this_shard_mc_info()`. Its proposed OK permits the remaining shard
metadata checks; it does not establish admission, replay, or I13a-e. Neither
arm consumes candidate/declarations roots, and neither should derive an I13
verdict. No additional transport carrier or shared collator verdict is added.

| Input/source | Existing terminal handling retained |
| --- | --- |
| Resolver failure from local engine availability or authenticated configuration processing | `fatal_error(Status)` resolves the final promise as an error: local failure |
| Candidate requests an absent, disabled or not-yet-enabled workchain | `reject_query` resolves CandidateReject |
| Candidate shard/predecessor conflicts with authenticated shard metadata | Existing CandidateReject checks remain |
| Successful binding at either local visitor | Continues local configuration processing; not final candidate acceptance |

## Earlier call-chain barrier requiring a scheduling decision

At baseline lines 1043 and 1046, `try_unpack_mc_state()` calls
`fetch_config_params()` before `check_this_shard_mc_info()`.
Inside `fetch_config_params()`, lines 1126-1134 add the candidate workchain to
the required local roles and call `validate_required_workchains()` before the
first visitor. Therefore the registry readiness check is also invoked on the
per-block validation path, not exclusively on node startup.

`workchain-execution-dispatch.cpp:809-814` rejects AccountBinding in that
required-role check. Lines 817-819 propagate LocalUnavailable. This precedes
both local visitor arms under the real wc=2 validation call chain, even with
registration, activation and configuration parsing satisfied.

Changing the two visitor arms cannot supply real per-block call-site evidence
while that barrier remains. Until its role in per-block validation is adjudicated
and the real path is exercised with mutation controls, neither arm may be counted
as an accepted live seam. No registry bypass, synthetic success result, or
singleton substitution was introduced to manufacture reachability.

The existing final account execution refusal (baseline line 6527) remains
untouched. The shared AccountCandidate carrier remains the sole transport API
when that later stage is implemented. Build success is not behavioral evidence.

## Local-expression controls prepared, not yet run

The opt-in `crypto/test/workchain-validator-local-visitors.cmake` registers a
local-expression CTest. Its extractor copies the two complete production visitor
statements verbatim and records their source hash and offsets. A configuration-only
fixture engine is resolved against the archived production-created masterchain
zero state. The fixture provides no execution capability and no candidate carrier.

The expected failures are 1311 when custom is incorrectly true, 1310 when the
custom arm is restored to local refusal, and 1320 when the local binding arm is
restored to refusal. The mutation driver uses a detached source copy, explicitly
rebuilds the generated-expression test target after every mutation and restoration,
and records byte restoration and reapplication hashes. It never mutates the
production source tree. These prepared controls have not been built or run yet.

These controls cannot establish that either production caller reaches its visitor.
They intentionally do not compile or run a modified ValidateQuery with an earlier
check bypassed. The actual validator library build recorded above predates this
new test module and is not compilation evidence for the new test executable.
The new tests must turn red under their specified mutations after the test window
is released before their local-expression results may be relied on.
