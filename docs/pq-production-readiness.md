# PQ production readiness

This change develops the remaining execution, operational and client integration
above the immutable ML-DSA authentication modules. It does not activate a network,
change ConfigParam 8, or approve a relayer funding-loss policy.

## Implementation boundaries

- Rust VM: implement the native verifier's version, cell decoding, return/error
  semantics and gas contract; compare real execution against the C++ VM.
- Validator load: provide reproducible measurement and evidence validation.
  Hosted CI results are not production-hardware certification.
- Activation: prepare and validate an explicit rollout plan. No automatic live
  configuration writes, invented quorum, activation height or validator approval.
- SDK and relayer: exact commitment/signing, state-bound submissions, budget
  limits and honest asynchronous result classification.
- tostester: Wallet V5 and Agent Account deployment/signing helpers with native
  transaction tests, retaining Wallet V1 compatibility.

## Validation status

Implementation is in progress on this draft branch. A source-reproduction artifact
is archived at the exact head so local and hosted reviews can share the same
inputs. No green source-archive job is claimed as functional validation. The final
PR description must list executed tests separately from deployment prerequisites.
