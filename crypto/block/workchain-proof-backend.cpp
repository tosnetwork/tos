#include "block/workchain-proof-work.h"

namespace block {

namespace {
WorkchainProofVerdict classify_backend_status(unsigned status) {
  switch (status) {
    case UNO_CRYPTO_OK: return WorkchainProofVerdict::Valid;
    case UNO_CRYPTO_DECODE:
    case UNO_CRYPTO_VERIFY: return WorkchainProofVerdict::InvalidProof;
    default: return WorkchainProofVerdict::LocalContractFailure;
  }
}
}

WorkchainProofVerdict WorkchainProofVerifier::run_backend(const UnoCryptoKeyPossessionRequestV2& request) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  return classify_backend_status(uno_crypto_verify_key_possession_v2(&request));
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

WorkchainProofVerdict WorkchainProofVerifier::run_backend(const UnoCryptoClosurePossessionRequestV2& request) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  return classify_backend_status(uno_crypto_verify_closure_possession_v2(&request));
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

WorkchainProofVerdict WorkchainProofVerifier::run_backend(const UnoCryptoVerifyRequestV2& request) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  // This is the sole host-side raw relation ABI invocation. The engine must
  // use WorkchainProofVerifier, which charges before reaching this boundary.
  switch (uno_crypto_verify_v2(&request)) {
    case UNO_CRYPTO_OK: return WorkchainProofVerdict::Valid;
    case UNO_CRYPTO_DECODE:
    case UNO_CRYPTO_VERIFY: return WorkchainProofVerdict::InvalidProof;
    // No current relation path returns KEY. Do not pre-authorize a future
    // meaning as candidate-invalid merely because the ABI reserved the name.
    case UNO_CRYPTO_KEY:
    case UNO_CRYPTO_ARGUMENTS:
    case UNO_CRYPTO_PANIC: return WorkchainProofVerdict::LocalContractFailure;
    default: return WorkchainProofVerdict::LocalContractFailure;
  }
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

}  // namespace block
