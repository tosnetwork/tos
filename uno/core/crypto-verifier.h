#pragma once

#include <algorithm>
#include <array>
#include <vector>

#include "uno/core/bundle-context.h"
#include "uno/crypto/include/uno_crypto.h"

namespace uno_workchain {

struct CryptoBundle {
  td::uint8 flags = 0;
  td::int64 value_balance = 0;
  std::array<td::uint8, 32> anchor{};
  std::array<td::uint8, 64> binding_signature{};
  std::vector<UnoCryptoAction> actions;
  std::vector<td::uint8> proof;
};

struct CryptoLimits {
  std::size_t max_actions = 0;
  std::size_t max_proof_bytes = 0;
};

inline bool crypto_bundle_shape_valid(std::size_t count, std::size_t proof_bytes, CryptoLimits limits) {
  if (count == 0 || count > limits.max_actions ||
      count > (std::numeric_limits<std::size_t>::max() - 2720) / 2272) {
    return false;
  }
  // Resource-size arithmetic, bounded above before multiplication; no monetary scaling.
  const auto expected_proof_bytes = count * 2272 + 2720;
  return proof_bytes == expected_proof_bytes && expected_proof_bytes <= limits.max_proof_bytes;
}

// Result errors are local/ABI failures, not evidence that a transaction is invalid.
// A true result still requires authenticated settlement and host-state checks.
inline td::Result<bool> verify_crypto_bundle(const CryptoBundle& bundle, BundleContext context,
                                            const Amount& principal, const Amount& fee,
                                            const std::array<td::uint8, 32>& sighash,
                                            CryptoLimits limits) {
  if (limits.max_actions == 0 || limits.max_proof_bytes == 0) {
    return td::Status::Error("UNO verifier limits are not configured");
  }
  uint32_t abi_context;
  switch (context) {
    case BundleContext::Transfer: abi_context = UNO_TRANSFER; break;
    case BundleContext::Unshield: abi_context = UNO_UNSHIELD; break;
    case BundleContext::ShieldClaim: abi_context = UNO_SHIELD_CLAIM; break;
    case BundleContext::WithdrawalRefund: abi_context = UNO_WITHDRAWAL_REFUND; break;
    case BundleContext::Genesis: abi_context = UNO_GENESIS; break;
    case BundleContext::PrivateFeeDistribution: abi_context = UNO_PRIVATE_FEE_DISTRIBUTION; break;
    default: return td::Status::Error("unknown UNO verifier context");
  }
  if (validate_bundle_context(context, bundle.value_balance, (bundle.flags & 1) != 0,
                              (bundle.flags & 2) != 0, principal, fee).is_error()) {
    return false;
  }
  const auto count = bundle.actions.size();
  if (!crypto_bundle_shape_valid(count, bundle.proof.size(), limits)) {
    return false;
  }
  UnoCryptoVerifyRequest request{};
  request.abi_version = UNO_CRYPTO_ABI_VERSION;
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.context = abi_context;
  request.flags = bundle.flags;
  request.value_balance = bundle.value_balance;
  request.principal_hi = principal.high();
  request.principal_lo = principal.low();
  request.fee_hi = fee.high();
  request.fee_lo = fee.low();
  std::copy(bundle.anchor.begin(), bundle.anchor.end(), request.anchor);
  std::copy(sighash.begin(), sighash.end(), request.sighash);
  std::copy(bundle.binding_signature.begin(), bundle.binding_signature.end(), request.binding_signature);
  request.actions = bundle.actions.data();
  request.action_count = count;
  request.proof = bundle.proof.data();
  request.proof_bytes = bundle.proof.size();
  request.max_actions = limits.max_actions;
  request.max_proof_bytes = limits.max_proof_bytes;
  switch (uno_crypto_verify_v0(&request)) {
    case UNO_CRYPTO_OK: return true;
    case UNO_CRYPTO_DECODE:
    case UNO_CRYPTO_VERIFY: return false;
    case UNO_CRYPTO_ARGUMENTS: return td::Status::Error("UNO verifier ABI rejected host arguments");
    case UNO_CRYPTO_KEY: return td::Status::Error("UNO verifier key construction failed");
    case UNO_CRYPTO_PANIC: return td::Status::Error("UNO verifier reported an internal panic");
    default: return td::Status::Error("unknown UNO verifier status");
  }
}

}  // namespace uno_workchain
