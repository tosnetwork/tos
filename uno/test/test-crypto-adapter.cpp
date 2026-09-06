#include "uno/core/crypto-verifier.h"
#include "td/utils/tests.h"

using namespace uno_workchain;

namespace {
uint32_t result_code = UNO_CRYPTO_OK;
unsigned calls = 0;
UnoCryptoVerifyRequest observed{};
}

extern "C" uint32_t uno_crypto_verify_v0(const UnoCryptoVerifyRequest* request) {
  ++calls;
  observed = *request;
  return result_code;
}

TEST(UnoCryptoAdapter, ContextMappingAndFailureClasses) {
  CryptoBundle bundle;
  bundle.actions.resize(1);
  bundle.proof.resize(4992);
  std::array<td::uint8, 32> digest{};
  digest[0] = 42;
  for (auto kind : {BundleContext::Transfer, BundleContext::Unshield, BundleContext::ShieldClaim,
                    BundleContext::WithdrawalRefund, BundleContext::Genesis, BundleContext::PrivateFeeDistribution}) {
    bool spending = kind == BundleContext::Transfer || kind == BundleContext::Unshield;
    bundle.flags = spending ? 3 : 2;
    bundle.value_balance = spending ? 100 : -100;
    auto principal = Amount::from_nanotomi(kind == BundleContext::Transfer ? 0 : 100);
    auto fee = Amount::from_nanotomi(kind == BundleContext::Transfer ? 100 : 0);
    uint32_t expected = kind == BundleContext::Transfer ? UNO_TRANSFER :
      kind == BundleContext::Unshield ? UNO_UNSHIELD :
      kind == BundleContext::ShieldClaim ? UNO_SHIELD_CLAIM :
      kind == BundleContext::WithdrawalRefund ? UNO_WITHDRAWAL_REFUND :
      kind == BundleContext::Genesis ? UNO_GENESIS : UNO_PRIVATE_FEE_DISTRIBUTION;
    for (uint32_t status : {0u, 1u, 2u, 3u, 4u, 5u, 255u}) {
      calls = 0;
      result_code = status;
      auto result = verify_crypto_bundle(bundle, kind, principal, fee, digest, {1, 4992});
      ASSERT_EQ(calls, 1u);
      ASSERT_EQ(observed.context, expected);
      ASSERT_EQ(observed.sighash[0], 42);
      ASSERT_EQ(observed.principal_lo, principal.low());
      ASSERT_EQ(observed.fee_lo, fee.low());
      if (status == 0 || status == 2 || status == 3) {
        ASSERT_TRUE(result.is_ok());
        ASSERT_EQ(result.ok(), status == 0);
      } else {
        ASSERT_TRUE(result.is_error());
      }
    }
  }
}

TEST(UnoCryptoAdapter, InvalidPublicInputsNeverInvokeBackend) {
  CryptoBundle bundle;
  bundle.flags = 3;
  bundle.value_balance = 100;
  bundle.actions.resize(1);
  bundle.proof.resize(4992);
  result_code = UNO_CRYPTO_VERIFY;
  calls = 0;
  auto wrong_fee = verify_crypto_bundle(bundle, BundleContext::Transfer, {}, Amount::from_nanotomi(101), {}, {1, 4992});
  ASSERT_TRUE(wrong_fee.is_ok());
  ASSERT_TRUE(!wrong_fee.ok());
  ASSERT_EQ(calls, 0u);
  bundle.proof.pop_back();
  auto short_proof = verify_crypto_bundle(bundle, BundleContext::Transfer, {}, Amount::from_nanotomi(100), {}, {1, 4992});
  ASSERT_TRUE(short_proof.is_ok());
  ASSERT_TRUE(!short_proof.ok());
  ASSERT_EQ(calls, 0u);
  auto unconfigured = verify_crypto_bundle(bundle, BundleContext::Transfer, {}, {}, {}, {});
  ASSERT_TRUE(unconfigured.is_error());
  ASSERT_EQ(calls, 0u);
}

TEST(UnoCryptoAdapter, ShapeBoundariesWithoutAllocation) {
  ASSERT_TRUE(crypto_bundle_shape_valid(1, 4992, {1, 4992}));
  ASSERT_TRUE(!crypto_bundle_shape_valid(0, 2720, {1, 4992}));
  ASSERT_TRUE(!crypto_bundle_shape_valid(2, 7264, {1, 7264}));
  ASSERT_TRUE(!crypto_bundle_shape_valid(1, 4991, {1, 4992}));
  ASSERT_TRUE(!crypto_bundle_shape_valid(1, 4993, {1, 4993}));
  ASSERT_TRUE(!crypto_bundle_shape_valid(1, 4992, {1, 4991}));
  const auto max = std::numeric_limits<std::size_t>::max();
  const auto overflow_count = (max - 2720) / 2272 + 1;
  // Intentionally wrapped resource length exposes a missing pre-multiplication bound.
  const auto wrapped_bytes = overflow_count * 2272 + 2720;
  ASSERT_TRUE(!crypto_bundle_shape_valid(overflow_count, wrapped_bytes, {max, max}));
}

TEST(UnoCryptoAdapter, EmptyAndOversizedShapesNeverInvokeBackend) {
  CryptoBundle valid;
  valid.flags = 3;
  valid.value_balance = 100;
  valid.actions.resize(1);
  valid.proof.resize(4992);
  result_code = UNO_CRYPTO_OK;
  for (unsigned kind = 0; kind < 3; ++kind) {
    auto bundle = valid;
    if (kind == 0) bundle.actions.clear();
    if (kind == 1) bundle.proof.clear();
    if (kind == 2) {
      bundle.actions.resize(2);
      bundle.proof.resize(7264);
    }
    calls = 0;
    auto result = verify_crypto_bundle(bundle, BundleContext::Transfer, {},
                                      Amount::from_nanotomi(100), {}, {1, 7264});
    ASSERT_TRUE(result.is_ok());
    ASSERT_TRUE(!result.ok());
    ASSERT_EQ(calls, 0u);
  }
  calls = 0;
  auto accepted = verify_crypto_bundle(valid, BundleContext::Transfer, {},
                                      Amount::from_nanotomi(100), {}, {1, 7264});
  ASSERT_TRUE(accepted.is_ok());
  ASSERT_TRUE(accepted.ok());
  ASSERT_EQ(calls, 1u);
}
