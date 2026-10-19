/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstdio>
#include <vector>

#include "wallet-pq-signer-c.h"
#include "wallet-pq-signer.h"
namespace {
unsigned calls = 0;
}
// Test executable only: simulate the private random source failing closed.
extern "C" int RAND_priv_bytes(unsigned char*, int) {
  ++calls;
  return 0;
}
int main() {
  using namespace tos::pq;
  for (auto role : {WalletPQRole::primary, WalletPQRole::rescue}) {
    if (WalletPQSigner::generate(role)) {
      std::fputs("generated wallet key after random source failure\n", stderr);
      return 1;
    }
    auto key = WalletPQSigner::from_seed(role, std::string(role == WalletPQRole::primary ? 32 : 48, 'x'));
    if (!key)
      return 2;
    if (key->sign(WalletPQPurpose::auth, std::string(32, 'd'))) {
      std::fputs("exported wallet signature after random source failure\n", stderr);
      return 3;
    }
    const int bound_role = role == WalletPQRole::primary ? 1 : 2;
    if (tos_wallet_pq_generate(bound_role))
      return 5;
    const std::string seed(role == WalletPQRole::primary ? 32 : 48, 'x');
    auto handle = tos_wallet_pq_import(bound_role, reinterpret_cast<const uint8_t*>(seed.data()), seed.size());
    if (!handle)
      return 6;
    std::vector<uint8_t> output(bound_role == 1 ? 2420 : 7856, 0xa5);
    const std::string digest(32, 'd');
    const int result = tos_wallet_pq_sign(handle, bound_role, TOS_WALLET_PQ_AUTH,
                                          reinterpret_cast<const uint8_t*>(key->public_key().data()),
                                          key->public_key().size(), reinterpret_cast<const uint8_t*>(digest.data()),
                                          digest.size(), output.data(), output.size());
    tos_wallet_pq_destroy(handle);
    if (result || !std::all_of(output.begin(), output.end(), [](uint8_t b) { return b == 0xa5; })) {
      std::fputs("C ABI exported signature after random failure\n", stderr);
      return 7;
    }
  }
  if (calls != 8)
    return 4;
  std::puts("wallet signer refuses key generation and signing on random source failure");
}
