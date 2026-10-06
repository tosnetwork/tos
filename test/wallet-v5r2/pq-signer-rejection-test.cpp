/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>

#include "mldsa44.h"
#include "slhdsa128s.h"
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
  }
  if (calls != 2)
    return 3;
  std::puts("wallet signer refuses invalid and backend-error verification verdicts");
}
