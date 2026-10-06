/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>

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
  }
  if (calls != 4)
    return 4;
  std::puts("wallet signer refuses key generation and signing on random source failure");
}
