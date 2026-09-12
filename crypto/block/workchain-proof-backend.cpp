#include "block/workchain-proof-work.h"

namespace block {

WorkchainProofVerdict WorkchainProofVerifier::run_system_backend(
    const UnoCryptoSystemEncryptionRequestV2& request, UnoCryptoSystemCiphertext& output) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  return uno_crypto_system_encrypt_v2(&request, &output) == UNO_CRYPTO_OK
             ? WorkchainProofVerdict::Valid : WorkchainProofVerdict::LocalContractFailure;
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

WorkchainProofVerdict WorkchainProofVerifier::run_system_verify_backend(
    const UnoCryptoSystemEncryptionRequestV2& request, const UnoCryptoSystemCiphertext& supplied) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  switch (uno_crypto_system_verify_v2(&request, &supplied)) {
    case UNO_CRYPTO_OK: return WorkchainProofVerdict::Valid;
    case UNO_CRYPTO_VERIFY: return WorkchainProofVerdict::InvalidProof;
    default: return WorkchainProofVerdict::LocalContractFailure;
  }
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

WorkchainProofVerdict WorkchainProofVerifier::run_system_backend(
    const UnoCryptoSystemEncryptionRequest& request, UnoCryptoSystemCiphertext& output) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  // No candidate ciphertext is consumed here. DECODE means authenticated-input
  // reconstruction failed (including a zero derived scalar), not an invalid proof.
  return uno_crypto_system_encrypt_v1(&request, &output) == UNO_CRYPTO_OK
             ? WorkchainProofVerdict::Valid : WorkchainProofVerdict::LocalContractFailure;
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

WorkchainProofVerdict WorkchainProofVerifier::run_system_verify_backend(
    const UnoCryptoSystemEncryptionRequest& request, const UnoCryptoSystemCiphertext& supplied) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  switch (uno_crypto_system_verify_v1(&request, &supplied)) {
    case UNO_CRYPTO_OK: return WorkchainProofVerdict::Valid;
    // Only VERIFY identifies disagreement with the candidate's ciphertext.
    // DECODE concerns reconstruction from the host's authenticated inputs.
    case UNO_CRYPTO_VERIFY: return WorkchainProofVerdict::InvalidProof;
    default: return WorkchainProofVerdict::LocalContractFailure;
  }
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

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

WorkchainProofVerdict WorkchainProofVerifier::run_backend(const UnoCryptoWithdrawalVerifyRequestV2& request) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  return classify_backend_status(uno_crypto_verify_withdrawal_v2(&request));
#else
  return WorkchainProofVerdict::BackendUnavailable;
#endif
}

}  // namespace block
