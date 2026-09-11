// Reuse the frozen-vector reader without changing the kernel-owned fixtures.
#define main retained_abi_fixture_main
#include "../../uno/crypto/tests/balance-abi.cpp"
#undef main
#include "block/workchain-proof-work.h"
#include "workchain-proof-test-access.h"
#include "workchain-deposit-transition-test.h"

static std::uint64_t backend_calls = 0;
static std::uint32_t forced_status = UINT32_MAX;
extern "C" uint32_t __real_uno_crypto_verify_v2(const UnoCryptoVerifyRequestV2*);
extern "C" uint32_t __wrap_uno_crypto_verify_v2(const UnoCryptoVerifyRequestV2* request) {
  ++backend_calls;
  if (forced_status != UINT32_MAX) return forced_status;
  return __real_uno_crypto_verify_v2(request);
}

#ifdef WORKCHAIN_PROOF_OPERATION_TRACE
extern "C" std::uint64_t workchain_proof_trace_read(std::size_t index);
extern "C" void workchain_proof_trace_reset();
#endif

int main(int argc, char** argv) {
  try {
    require(argc == 2, "expected the frozen vector corpus");
    auto fixtures = load(argv[1]);
    test_metered_deposit_transition();
    UnoCryptoSystemEncryptionRequest system{};
    system.abi_version = UNO_CRYPTO_ABI_VERSION;
    system.amount = 123;
    auto recipient = bytes("b6ec3baa39a7357ab9ca16c61373385f7cfb04ab10c4bc20c8bd3cc6db9a6100");
    std::memcpy(system.recipient, recipient.data(), 32);
    auto generation = block::WorkchainProofTestAccess::create(7);
    auto ciphertext = generation.system_encrypt(system);
    require(ciphertext.is_ok() && generation.consumed() == 7, "system generation was not charged");
    auto verification = block::WorkchainProofTestAccess::create(7);
    require(verification.verify(system, ciphertext.ok()).is_ok() && verification.consumed() == 7,
            "system reconstruction was not charged");
    require(generation.consumed() == verification.consumed(),
            "proposer generation and validator reconstruction charges differ");
    auto short_generation = block::WorkchainProofTestAccess::create(6);
    require(short_generation.system_encrypt(system).is_error() && short_generation.consumed() == 0,
            "underfunded system generation succeeded");
    auto short_verification = block::WorkchainProofTestAccess::create(6);
    require(short_verification.verify(system, ciphertext.ok()).is_error() && short_verification.consumed() == 0,
            "underfunded system verification succeeded");
    auto altered = ciphertext.ok();
    altered.handle[0] ^= 1;
    auto mismatch = block::WorkchainProofTestAccess::create(14);
    auto rejected = mismatch.verify(system, altered);
    require(rejected.is_error() && rejected.code() == -7200 && mismatch.consumed() == 7,
            "candidate system ciphertext mismatch misclassified or refunded");
    require(mismatch.verify(system, ciphertext.ok()).is_error() && mismatch.consumed() == 7,
            "system mismatch was not sticky");
    std::memset(system.recipient, 0, 32);
    auto malformed = block::WorkchainProofTestAccess::create(14);
    auto unavailable = malformed.system_encrypt(system);
    require(unavailable.is_error() && unavailable.error().code() == -7201 && malformed.consumed() == 7,
            "invalid authenticated system recipient became candidate-invalid or refunded");
    require(malformed.system_encrypt(system).is_error() && malformed.consumed() == 7,
            "system generation failure was not sticky");
    std::cout << "system generation/reconstruction: 7 units each; exact, short, mismatch, sticky failure passed\n";
    for (auto& fixture : fixtures) {
      const auto request = fixture.request();
      auto ops_result = block::workchain_proof_operations_v4(request);
      require(ops_result.is_ok(), "valid frozen request shape rejected");
      auto ops = ops_result.move_as_ok();
      const auto units = ops.total().move_as_ok();
      require(units > 0, "nonempty verifier operation plan");
      auto before = backend_calls;
auto short_budget = block::WorkchainProofTestAccess::create(units - 1);
      auto short_result = short_budget.verify(request);
      require(short_result.is_error() && short_result.code() == -7201, "undercount is a local contract failure");
      require(backend_calls == before, "undercount entered the real backend");
#ifdef WORKCHAIN_PROOF_OPERATION_TRACE
      workchain_proof_trace_reset();
#endif
      auto exact = block::WorkchainProofTestAccess::create(units);
      require(exact.verify(request).is_ok(), "real kernel rejected a frozen proof");
      require(backend_calls == before + 1, "real backend positive witness missing");
      require(exact.consumed() == units, "real kernel call was not precharged");
#ifdef WORKCHAIN_PROOF_OPERATION_TRACE
      const std::uint64_t expected[] = {ops.msm_terms, ops.scalar_multiplications, ops.generated_points,
          ops.decoded_points, ops.encoded_points, ops.range_rounds, ops.sigma_equations, ops.sigma_witnesses,
          ops.context_bytes};
      for (std::size_t i = 0; i < 9; ++i) {
        std::cout << "kind=" << request.relation << " k=" << request.receipt_count
                  << " component=" << i << " actual=" << workchain_proof_trace_read(i)
                  << " reserved=" << expected[i] << '\n';
        require(workchain_proof_trace_read(i) == expected[i], "backend operations differ from the profile formula");
      }
#endif
      auto invalid = fixture;
      invalid.proof.back() ^= 1;
      auto failed = block::WorkchainProofTestAccess::create(units);
      auto result = failed.verify(invalid.request());
      require(result.is_error() && result.code() == -7200, "invalid proof lost its candidate classification");
      require(backend_calls == before + 2, "invalid proof never reached the real kernel");
      require(failed.consumed() == units, "failed proof reservation was refunded");
      require(failed.verify(request).is_error(), "ignored failed proof was erased");
      require(backend_calls == before + 2, "sticky failure retried the backend");
    }
    const auto request = fixtures.front().request();
    const auto units = block::workchain_proof_operations_v4(request).move_as_ok().total().move_as_ok();
    for (std::uint32_t status : std::array<std::uint32_t, 4>{UNO_CRYPTO_ARGUMENTS, UNO_CRYPTO_PANIC, UNO_CRYPTO_KEY, 99u}) {
      forced_status = status;
      const auto before = backend_calls;
      auto meter = block::WorkchainProofTestAccess::create(units);
      auto error = meter.verify(request);
      require(error.is_error() && error.code() == -7201, "non-candidate ABI status became a candidate verdict");
      require(backend_calls == before + 1, "forced ABI status was not observed at the call boundary");
      require(meter.consumed() == units, "local backend failure refunded attempted work");
    }
    forced_status = UINT32_MAX;
    std::cout << "verified SEND and COLLECT k=1..8: " << fixtures.size() << " fixtures\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
