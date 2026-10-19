/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstdio>
#include <vector>

#include "mldsa44.h"
#include "slhdsa128s.h"
#include "wallet-pq-signer-c.h"
#include "wallet-pq-signer.h"
namespace {
unsigned calls = 0;
}
// Test-only replacement verdicts. Signing still uses the real algorithms.
namespace tos::pq {
VerifyResult verify_mldsa44(std::string_view, std::string_view, std::string_view, std::string_view) noexcept {
  ++calls;
  return VerifyResult::invalid;
}
VerifyResult verify_slhdsa128s(std::string_view, std::string_view, std::string_view, std::string_view) noexcept {
  ++calls;
  return VerifyResult::backend_error;
}
}  // namespace tos::pq
int main() {
  using namespace tos::pq;
  for (auto role : {WalletPQRole::primary, WalletPQRole::rescue}) {
    auto key = WalletPQSigner::from_seed(role, std::string(role == WalletPQRole::primary ? 32 : 48, 'x'));
    if (!key)
      return 2;
    if (key->sign(WalletPQPurpose::auth, std::string(32, 'd'))) {
      std::fputs("accepted rejected wallet signature\n", stderr);
      return 1;
    }
    const int bound_role = role == WalletPQRole::primary ? 1 : 2;
    const std::string seed(role == WalletPQRole::primary ? 32 : 48, 'x');
    auto handle = tos_wallet_pq_import(bound_role, reinterpret_cast<const uint8_t*>(seed.data()), seed.size());
    if (!handle)
      return 4;
    std::vector<uint8_t> output(bound_role == 1 ? 2420 : 7856, 0xa5);
    const std::string digest(32, 'd');
    const int result = tos_wallet_pq_sign(handle, bound_role, TOS_WALLET_PQ_AUTH,
                                          reinterpret_cast<const uint8_t*>(key->public_key().data()),
                                          key->public_key().size(), reinterpret_cast<const uint8_t*>(digest.data()),
                                          digest.size(), output.data(), output.size());
    tos_wallet_pq_destroy(handle);
    if (result || !std::all_of(output.begin(), output.end(), [](uint8_t b) { return b == 0xa5; })) {
      std::fputs("C ABI exported rejected wallet signature\n", stderr);
      return 5;
    }
  }
  if (calls != 4)
    return 3;
  std::puts("wallet signer refuses invalid and backend-error verification verdicts");
}
