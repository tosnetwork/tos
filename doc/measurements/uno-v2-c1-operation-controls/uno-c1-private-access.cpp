#include "block/workchain-account-engine.h"
void allowed(block::WorkchainProofVerifier& meter) {
  (void)meter.consumed();
}
#ifdef ATTEMPT_CONSTRUCTION
void forbidden() { block::WorkchainProofVerifier meter(100); }
#endif
#ifdef ATTEMPT_MINT
void forbidden(const block::ProofAdmittedBatchInput& token) { (void)token.make_verifier(); }
#endif
#ifdef ATTEMPT_RAW_BACKEND
void forbidden(const UnoCryptoVerifyRequestV2& request) { (void)block::WorkchainProofVerifier::run_backend(request); }
#endif
