#include "block/workchain-proof-work.h"
#include "workchain-proof-test-access.h"
#include "block/workchain-resource-policy.h"
#include "td/utils/tests.h"

namespace {
std::uint64_t backend_calls = 0;
block::WorkchainProofVerdict verdict = block::WorkchainProofVerdict::Valid;
UnoCryptoVerifyRequestV2 send_request() {
  UnoCryptoVerifyRequestV2 request{};
  request.abi_version = UNO_BALANCE_ABI_VERSION;
  request.relation = UNO_RELATION_SEND;
  request.limits = {100, 100, 8, 1024, 4096};
  request.context_bytes = 1;
  request.point_count = 10;
  request.commitment_count = 8;
  request.response_count = 6;
  request.proof_bytes = 864;
  return request;
}
}

// Dedicated boundary fixture, not a substitute for the separate real-kernel
// correspondence test. It makes precharge order observable without crypto CPU.
namespace block {
WorkchainProofVerdict WorkchainProofVerifier::run_system_backend(
    const UnoCryptoSystemEncryptionRequestV2&, UnoCryptoSystemCiphertext&) {
  ++backend_calls;
  return verdict;
}
WorkchainProofVerdict WorkchainProofVerifier::run_system_verify_backend(
    const UnoCryptoSystemEncryptionRequestV2&, const UnoCryptoSystemCiphertext&) {
  ++backend_calls;
  return verdict;
}
WorkchainProofVerdict WorkchainProofVerifier::run_backend(const UnoCryptoVerifyRequestV2&) {
  ++backend_calls;
  return verdict;
}
WorkchainProofVerdict WorkchainProofVerifier::run_system_backend(
    const UnoCryptoSystemEncryptionRequest&, UnoCryptoSystemCiphertext&) {
  ++backend_calls;
  return verdict;
}
WorkchainProofVerdict WorkchainProofVerifier::run_system_verify_backend(
    const UnoCryptoSystemEncryptionRequest&, const UnoCryptoSystemCiphertext&) {
  ++backend_calls;
  return verdict;
}
}

TEST(WorkchainProofWork, SystemPairChargesBeforeEitherBackend) {
  UnoCryptoSystemEncryptionRequest request{};
  request.abi_version = UNO_CRYPTO_ABI_VERSION;
  request.amount = 1;
  UnoCryptoSystemCiphertext ciphertext{};
  backend_calls = 0;
  verdict = block::WorkchainProofVerdict::Valid;
  auto generation = block::WorkchainProofTestAccess::create(6);
  auto verification = block::WorkchainProofTestAccess::create(6);
  ASSERT_TRUE(generation.system_encrypt(request).is_error());
  ASSERT_TRUE(verification.verify(request, ciphertext).is_error());
  ASSERT_EQ(backend_calls, 0u);
  auto proposer = block::WorkchainProofTestAccess::create(7);
  auto validator = block::WorkchainProofTestAccess::create(7);
  ASSERT_TRUE(proposer.system_encrypt(request).is_ok());
  ASSERT_TRUE(validator.verify(request, ciphertext).is_ok());
  ASSERT_EQ(backend_calls, 2u);
  ASSERT_EQ(proposer.consumed(), 7u);
  ASSERT_EQ(validator.consumed(), proposer.consumed());
}

TEST(WorkchainProofWork, OriginPairPrechargeAndStickyFailure) {
  for (auto width : {41u, 115u}) {
    UnoCryptoSystemEncryptionRequestV2 request{};
    request.abi_version = 2; request.amount = 1; request.origin_bytes = width;
    UnoCryptoSystemCiphertext ciphertext{};
    backend_calls = 0;
    verdict = block::WorkchainProofVerdict::Valid;
    auto short_a = block::WorkchainProofTestAccess::create(6);
    auto short_b = block::WorkchainProofTestAccess::create(6);
    ASSERT_TRUE(short_a.system_encrypt(request).is_error());
    ASSERT_TRUE(short_b.verify(request, ciphertext).is_error());
    ASSERT_EQ(backend_calls, 0u);
    auto a = block::WorkchainProofTestAccess::create(14);
    auto b = block::WorkchainProofTestAccess::create(14);
    ASSERT_TRUE(a.system_encrypt(request).is_ok());
    ASSERT_TRUE(b.verify(request, ciphertext).is_ok());
    ASSERT_EQ(a.consumed(), 7u); ASSERT_EQ(a.consumed(), b.consumed());
    verdict = block::WorkchainProofVerdict::LocalContractFailure;
    ASSERT_TRUE(a.system_encrypt(request).is_error());
    ASSERT_TRUE(b.verify(request, ciphertext).is_error());
    ASSERT_EQ(a.consumed(), 14u); ASSERT_EQ(a.consumed(), b.consumed());
    ASSERT_EQ(backend_calls, 4u);
    verdict = block::WorkchainProofVerdict::Valid;
    ASSERT_TRUE(a.system_encrypt(request).is_error());
    ASSERT_TRUE(b.verify(request, ciphertext).is_error());
    ASSERT_EQ(backend_calls, 4u);
  }
}

TEST(WorkchainProofWork, ExactSendComponents) {
  auto operations = block::workchain_proof_operations_v4(send_request()).move_as_ok();
  ASSERT_EQ(operations.msm_terms, 1106u);
  ASSERT_EQ(operations.scalar_multiplications, 11u);
  ASSERT_EQ(operations.generated_points, 1026u);
  ASSERT_EQ(operations.decoded_points, 48u);
  ASSERT_EQ(operations.encoded_points, 8u);
  ASSERT_EQ(operations.range_rounds, 9u);
  ASSERT_EQ(operations.sigma_equations, 8u);
  ASSERT_EQ(operations.sigma_witnesses, 6u);
  ASSERT_EQ(operations.context_bytes, 1u);
  ASSERT_EQ(operations.total().move_as_ok(), 2223u);
}

TEST(WorkchainProofWork, PrechargeAndStickyFailure) {
  auto request = send_request();
  backend_calls = 0;
  verdict = block::WorkchainProofVerdict::Valid;
  auto insufficient = block::WorkchainProofTestAccess::create(2222);
  auto rejected = insufficient.verify(request);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
  ASSERT_EQ(backend_calls, 0u);
  ASSERT_EQ(insufficient.consumed(), 0u);
  auto exact = block::WorkchainProofTestAccess::create(2223);
  ASSERT_TRUE(exact.verify(request).is_ok());
  ASSERT_EQ(backend_calls, 1u);
  ASSERT_EQ(exact.consumed(), 2223u);
  ASSERT_TRUE(exact.verify(request).is_error());
  ASSERT_EQ(backend_calls, 1u);
  ASSERT_EQ(exact.consumed(), 2223u);

  for (auto result : {block::WorkchainProofVerdict::InvalidProof,
                     block::WorkchainProofVerdict::LocalContractFailure,
                     block::WorkchainProofVerdict::BackendUnavailable}) {
    verdict = result;
    const auto before = backend_calls;
    auto failed = block::WorkchainProofTestAccess::create(4446);
    auto error = failed.verify(request);
    ASSERT_TRUE(error.is_error());
    ASSERT_EQ(error.code(), static_cast<int>(result == block::WorkchainProofVerdict::InvalidProof
        ? block::WorkchainExecutionFailure::CandidateInvalid
        : block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(backend_calls, before + 1);
    ASSERT_EQ(failed.consumed(), 2223u);
    ASSERT_TRUE(failed.status().is_error());
    ASSERT_TRUE(failed.verify(request).is_error());
    ASSERT_EQ(backend_calls, before + 1);
    ASSERT_EQ(failed.consumed(), 2223u);
  }
}

TEST(WorkchainProofWork, ShapeRefusalBeforeBackend) {
  const auto before = backend_calls;
  for (unsigned fault = 0; fault < 7; ++fault) {
    auto request = send_request();
    if (fault == 0) request.abi_version = 0;
    if (fault == 1) request.relation = UINT32_MAX;
    if (fault == 2) request.receipt_count = 65;
    if (fault == 3) ++request.point_count;
    if (fault == 4) ++request.commitment_count;
    if (fault == 5) ++request.response_count;
    if (fault == 6) ++request.proof_bytes;
    auto meter = block::WorkchainProofTestAccess::create(UINT64_MAX);
    auto result = meter.verify(request);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(meter.consumed(), 0u);
    ASSERT_EQ(backend_calls, before);
  }
}

TEST(WorkchainProofWork, ExplicitProfileSet) {
  ASSERT_TRUE(block::workchain_batch_admission_version_supported(2));
  ASSERT_TRUE(block::workchain_batch_admission_version_supported(3));
  ASSERT_TRUE(block::workchain_batch_admission_version_supported(4));
  ASSERT_TRUE(!block::workchain_batch_admission_version_supported(5));
  ASSERT_TRUE(!block::workchain_batch_admission_version_supported(0x10004));
}

TEST(WorkchainProofWork, LocalLimitsAndContext) {
  ASSERT_TRUE(block::proof_count_product(UINT64_MAX, 2).is_error());
  ASSERT_EQ(block::proof_count_product(0, UINT64_MAX).move_as_ok(), 0u);
  ASSERT_EQ(block::proof_count_product(UINT64_MAX, 1).move_as_ok(), UINT64_MAX);
  for (unsigned fault = 0; fault < 10; ++fault) {
    auto request = send_request();
    if (fault == 0) request.limits.max_value = 0;
    if (fault == 1) request.limits.max_balance = 99;
    if (fault == 2) request.limits.max_collect = 0;
    if (fault == 3) request.limits.max_collect = 65;
    if (fault == 4) request.limits.max_context_bytes = 0;
    if (fault == 5) request.limits.max_proof_bytes = 0;
    if (fault == 6) request.context_bytes = 0;
    if (fault == 7) request.context_bytes = 1025;
    if (fault == 8) request.limits.max_proof_bytes = 863;
    if (fault == 9) {
      request.relation = UNO_RELATION_COLLECT;
      request.receipt_count = 9;
      request.point_count = 33;
      request.commitment_count = 23;
      request.response_count = 22;
      request.proof_bytes = 992;
    }
    const auto before = backend_calls;
    auto meter = block::WorkchainProofTestAccess::create(UINT64_MAX);
    auto result = meter.verify(request);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(backend_calls, before);
    ASSERT_EQ(meter.consumed(), 0u);
  }
  auto request = send_request();
  request.context_bytes = 1024;
  ASSERT_EQ(block::workchain_proof_operations_v4(request).move_as_ok().total().move_as_ok(), 3246u);
  request.context_bytes = request.limits.max_context_bytes = SIZE_MAX;
  auto operations = block::workchain_proof_operations_v4(request).move_as_ok();
  ASSERT_TRUE(operations.total().is_error());
}
