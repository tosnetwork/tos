# Deterministic verification operations (profile 4)

This is C1 work, not C2 block aggregation, C3 inspection complexity, live
execution authorization, or an I13 acceptance claim. The live refusal gates
remain in place.

## Profile identity

Profile 4 explicitly authorizes (1) the tagged fee-settlement constructor and
(2) deterministic proof-operation counting with precharged backend calls.
Profiles 2 and 3 retain their previous meanings. A binary already exists which
recognizes profile 3 without this meter. Adding the meter to profile 3 would
give the same authenticated value different semantics on those two binaries.
This is the concrete reason for a new identity, not a capability ladder.
Fee permission is exactly `3 || 4`; metering is exactly `4`. Unknown versions
gain neither permission. An unsupported authenticated profile is a local
inability to execute, not evidence against a candidate. Installation must reject
unsupported profiles. Activation requires auditable deployment readiness, an
explicit first effective block, and a dry-run with profile 4 installed before
support is widespread. A global-version log warning does not enforce deployment.

## Operation unit

Let `E` be Sigma equations, `W` shared witnesses, `Q` encoded public points,
`m` padded range objects, `N = 64m`, and `L = log2(N)`.
SEND uses `(Q,E,W,m)=(10,8,6,8)`; COLLECT uses
`(3k+6,2k+5,2k+4,next_pow2(2k+4))`. The current backend is a 64-bit range
backend even when the authenticated monetary maximum is narrower.

The unit is the unweighted sum of these separately observable components:

| Operation boundary | Full-path reservation |
| --- | ---: |
| Scalar-point terms supplied to MSM | `EW + (2N+2L+4) + (m+4)` |
| Standalone scalar-point multiplications | `E+3` |
| Generated points | `2N+2` |
| Decoded points | `Q+E+2L+4+m` |
| Encoded range commitments | `m` |
| Inner-product challenge rounds | `L` |
| Sigma equation checks | `E` |
| Shared canonical Sigma response scalars | `W` |
| Variable context bytes supplied to transcript absorption | `context_bytes` |

The two range MSMs are independent; their terms must both be reserved. Dense
Sigma rows still pass identity coefficients to MSM. There is no sparsity
discount. Fresh G/H generation and both constructions of the Pedersen blinding
base count; a future cached-generator implementation must not silently change
this profile's unit. These are algorithm-interface counts, not instruction
counts, nanoseconds, weighted performance estimates, or fee units. They do not
claim a WCET or replace the separate admitted input/state and C3 memory/work
obligations. In particular, a round count is not a count of all field operations
inside that round.

The complete valid path has exactly these counts. A malformed proof can exit
earlier. Every admitted call reserves the complete path anyway: invalid proofs,
local backend failures, and unavailable backends receive no refund. A second
attempt cannot restore the allowance; a failed verifier stays failed. The
returned effects usage is not consulted for this decision.

## Enforcement and provenance

Proof admission retains the actual declaration, not merely the authenticated
maximum. The runner creates a synchronous, noncopyable verifier and hands it to
the explicit metered engine entry. Unsupported implementations fail locally;
the default never invokes their old unmetered entry. The configured adapter
passes that same verifier with its immutable authenticated parameters.

The wrapper derives the reservation from the actual ABI request shape. It
checks and deducts before its private backend entry, then consumes the typed
backend verdict. A declaration below the derived reservation is a local engine
contract failure: inspection and request construction should describe the same
candidate. It is not a reason to blame that candidate. Invalid cryptography is
separately classified from ABI contract failures and unavailable backends. The
runner checks sticky meter failure even when an engine ignores a returned error.

The ABI's borrowed allocation validity and synchronous lifetime requirements
remain unchanged. This layer does not make arbitrary pointers safe. Default
node builds do not acquire a cryptographic backend or enable an engine. The
real-kernel test links its own explicit backend independently of node activation.

## Evidence status

The dedicated boundary fixture tests precharge and typed failures; it cannot
establish correspondence with cryptographic work. The real-kernel test uses the
unchanged frozen SEND and COLLECT k=1..8 corpus and a link-time raw-call counter.
The diagnostic trace script copies the verifier into an isolated temporary
directory, instruments actual iterator consumption and operation sites, and
checks each component separately. That instrumented copy is never deployed,
does not pass the source manifest gate by construction, and does not replace
the ordinary kernel regression. Its extra observation exports are excluded from
cbindgen output only in that disposable copy; the production ABI is untouched.

The wrapper rejects local policy/context contradictions before calling the ABI;
otherwise DECODE mixes local faults with bad point/scalar encodings. KEY is
reserved but not emitted by this relation path, so it is not prospectively
classified as a candidate verdict. The trace is a separate CTest and uses
standard git for mechanical edits of its disposable copy, not an agent tool.

The manual compiled controls and raw logs are in
`measurements/uno-v2-c1-operation-controls/restore-audit.json`. All sixteen
mutants are reconstructed from the restored source; their hashes equal the
recorded mutant hashes. Baseline and restored executable hashes also match.
The low-formula control omits the second range MSM reservation: the actual
backend observes 1106 terms while the formula reserves 1094. This fails the
per-component numerical comparison, not the wrapper's own cap calculation.
The trace checks SEND and every COLLECT k=1..8 against the unchanged corpus.
These diagnostic observations do not prove arbitrary future backend code has
the same complexity; a backend change must preserve or explicitly revise this
profile and its observation coverage.

Six separately injected source-gate violations were rejected and restored:
a raw host ABI call, inclusion of the test capability helper, redefinition of
the named test friend without that include, interval-based fee permission,
and raw-call/friend injections specifically in the node executable directory.
The source gate is a checked trusted-code discipline, not an adversarial C++
sandbox. It does not make forged pointer allocations or dynamically loaded
unreviewed code safe. Production statement construction and authentication of
its context remain engine obligations; the meter only establishes the checked
request contract and operation reservation.

The seven related CTests pass on the final source. Ordinary tests and the
real-operation trace are registered for repeat execution. Runtime source
mutations and static injection controls are manual evidence, not automatically
rerun mutations in CI. The trace requires the Native Ninja build and its locked
offline Rust dependencies. It builds only a disposable instrumented copy.

The token's minting helper is private to the runner. The verifier cannot be
copied or moved, and the configured adapter forwards the same instance. A new
runner invocation still creates a new allowance: cross-invocation and
cross-batch aggregation are C2, deliberately not claimed here. C3 inspection
complexity, live registration, refusal-gate movement and I13 acceptance remain
open. This cut is not a completed D31 or M1 acceptance report.

### Registration and build boundaries

The shared CI registration assertion requires the five existing kernel gates
and the two real proof tests (seven in total). Independently suppressing each
new registration leaves CMake configuration successful but makes the actual CI
assertion fail with six tests; restoring the registration returns seven. This
is a registration control, not a compiled cryptographic mutation.

The host source gate covers `crypto/block`, `validator`, `validator-engine` and
the active kernel/engine tree, with explicit test-source exclusions. New host
source roots must be added to this gate before they can carry an engine; the
gate is not a transitive include-graph verifier. The dedicated real test image
contains one backend definition and one raw ABI definition. The default disk
collator image contains no raw ABI definition. Archive test substitution relies
on keeping the backend translation unit dedicated to that boundary; adding
another exported dependency requires revisiting its link layout.

Python3 is now a required configure dependency for the unconditional offline
host gate. The instrumentation driver supports the Native Ninja build, not
every CMake generator. Its registration is deliberately not silently skipped
on other generators: those configurations cannot claim this evidence until a
driver port is supplied. The 600-second test timeout is not a measured CI
hardware bound; CI-runner provisioning and timing remain to be measured. Local
passes are not proof of that deployment property.

The real-test `--wrap=uno_crypto_verify_v2` is an observation and status-injection
hook, not the production precharge mechanism. Production precharge is in
`WorkchainProofVerifier::verify`, before its private `run_backend` call. Removing
only that linker option from the real test still links on this build, but the
unchanged test fails its numerical `backend_calls == before + 1` assertion after
the valid frozen proof returned successfully. Restoring the option restores
both success and the exact binary hash. Thus a missing observer does not produce
a silent green test. This is a link-option runtime control, recorded separately
from the sixteen source mutations; it does not prove all possible build modes.

The three owner-approved build integration exceptions match exact strings at
their specified paths, never line numbers or whole files. They affect only the
Uno path rule, not the retired-symbol rule. An injected `MineUno` inside an
otherwise allowed CMake option line is rejected solely by the latter rule,
demonstrating that path-rule rejection is not masking the retired-symbol check.

### Obligations on a future metered engine

`execute_metered_accounts` must reject malformed candidate shapes as candidate
data before assembling the ABI request, bind the request to that candidate and
the authenticated configuration, and derive context bytes identically on all
nodes. The host shape gate reports an inconsistent *assembled request* as a
local contract failure; blindly forwarding unchecked candidate counts into it
would create an abstention attack. The future engine needs a direct control for
that boundary. A well-formed request built from the wrong statement can be
metered correctly and still be wrong. Zero verification calls also satisfy a
work cap: this meter does not establish verification completeness. Neither
obligation can be accepted from a fixture with no production engine registered.
