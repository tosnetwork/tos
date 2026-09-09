# Wallet prover review disposition

Scope: independently built cryptographic SEND/COLLECT generation, not a wallet
transaction builder, live host, or M2 acceptance. The first independent review
ran both Rust suites and the kernel gate. Follow-up review passed with no new
blockers, independently rerunning both Rust suites, both source gates and the
five node CTests. This is a reviewed implementation unit, not M2 acceptance.

| Finding | Disposition |
|---|---|
| Generator state outlives erased masks | Fixed: concrete ChaCha12 generator with the zeroize feature, a production `ZeroizeOnDrop` bound, and an explicitly zeroizing input seed buffer. Removing the feature fails compilation at the production call. The wrapper previously used did not itself implement the marker trait; the concrete generator does. |
| Manually enumerated first-party entropy scan | Fixed: discover every Rust source under `src`, excluding only the exact test fixture module. Adding an unlisted module with a forbidden token fails the gate. |
| Ineffective cbindgen exclusion | Removed. The existing generated-header byte comparison is the ABI guard. |
| Unexercised statement/backend outcomes | Statement policy and encoding failures are tested before entropy acquisition. The pinned backend's parameter errors are unreachable under checked shapes; that dependency is recorded at the call. Generated-proof failure is exercised by the response mutation. |
| ABI-status payload might be mistaken for a consensus verdict | Clarified, not remapped. A primitive status is not a network verdict; provenance is supplied by the wallet-local enclosing outcome. There is no host/candidate callback here. |
| Post-generation opening mismatch called a witness error | Fixed: it is now a backend inconsistency. The caller's openings were already checked before generation. |

An additional local inspection found four variable-time MSM calls constructing
inner-product L/R points from non-public vectors. The review's checks of the
new AND code and the bit-commitment path did not cover these calls. All four now
use constant-time MSM. Public-challenge generator folding and public verification
remain variable-time. The vendored source manifest and provenance delta were
updated. Frozen proof bytes remain identical. This is not a proof of complete
side-channel resistance or erasure of all process memory and compiler temporaries.

Evidence: `measurements/uno-v2-wallet-prover-controls.md`,
`measurements/uno-v2-wallet-prover-erasure-control.md`, and
`measurements/uno-v2-wallet-statement-control.md`. These are manual mutation
records, not a claim that CI reruns mutations. Wallet tests remain standalone;
the existing five node-kernel CTests also pass with the adapted source.

The wallet and verifier have separate workspaces. All external source identities
in the wallet lock are covered by the verifier lock's source-integrity audit;
their runtime feature graphs deliberately differ. This does not inherit a
security audit of newly exercised prover code from the verifier audit.

Remaining obligations from follow-up: automate the wallet source gate separately
from node linkage; retain the seed-copy residual warning; review the concrete
generator's drop implementations on refresh. `RangeProver` intentionally merges
the two currently unreachable backend-error conditions; it does not distinguish
parameter rejection from post-generation opening disagreement. The unused
vendored linear prover still uses variable-time secret MSM and is not an approved
wallet consumer. The source manifest records local byte identity, not an automated
diff against pristine upstream; refreshing the dependency still needs that review.
