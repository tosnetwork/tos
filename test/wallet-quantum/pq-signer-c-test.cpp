/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string_view>
#include <vector>

#include "mldsa44.h"
#include "slhdsa128s.h"
#include "wallet-pq-signer-c.h"

extern "C" int wallet_pq_c_header_test(void);
static void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "C_SIGNER_FAILURE: " << message << '\n';
    std::exit(1);
  }
}
static std::string_view view(const std::vector<uint8_t>& data) {
  return {reinterpret_cast<const char*>(data.data()), data.size()};
}

int main() {
  require(wallet_pq_c_header_test(), "C header linkage");
  for (int role : {TOS_WALLET_PQ_PRIMARY, TOS_WALLET_PQ_RESCUE}) {
    const bool primary = role == TOS_WALLET_PQ_PRIMARY;
    const std::vector<uint8_t> seed(primary ? 32 : 48, 0x11);  // Public fixture only.
    using Handle = std::unique_ptr<tos_wallet_pq_signer, decltype(&tos_wallet_pq_destroy)>;
    Handle signer(tos_wallet_pq_import(role, seed.data(), seed.size()), tos_wallet_pq_destroy);
    require(bool(signer), "import");
    require(!tos_wallet_pq_import(role, seed.data(), seed.size() - 1), "seed width");
    std::vector<uint8_t> key(primary ? 1312 : 32), signature(primary ? 2420 : 7856, 0xa5);
    const std::vector<uint8_t> digest(32, 0x22);
    require(tos_wallet_pq_public_key(signer.get(), key.data(), key.size()) == 1, "public key");
    const auto original_key = key;
    require(!tos_wallet_pq_public_key(signer.get(), key.data(), key.size() - 1), "key output width");
    require(key == original_key, "key output touched on failure");
    auto sign = [&](int expected_role, int purpose, const std::vector<uint8_t>& expected_key, size_t digest_size,
                    size_t output_size) {
      return tos_wallet_pq_sign(signer.get(), expected_role, purpose, expected_key.data(), expected_key.size(),
                                digest.data(), digest_size, signature.data(), output_size);
    };
    auto wrong_key = key;
    wrong_key[0] ^= 1;
    require(!sign(role, TOS_WALLET_PQ_AUTH, wrong_key, 32, signature.size()), "wrong key accepted");
    require(!sign(primary ? 2 : 1, TOS_WALLET_PQ_AUTH, key, 32, signature.size()), "wrong role accepted");
    require(!sign(role, 99, key, 32, signature.size()), "unknown purpose accepted");
    require(!sign(role, TOS_WALLET_PQ_AUTH, key, 31, signature.size()), "digest width accepted");
    require(!sign(role, TOS_WALLET_PQ_AUTH, key, 32, signature.size() - 1), "output width accepted");
    require(!tos_wallet_pq_sign(nullptr, role, 1, key.data(), key.size(), digest.data(), 32, signature.data(),
                                signature.size()),
            "null handle accepted");
    require(std::all_of(signature.begin(), signature.end(), [](uint8_t b) { return b == 0xa5; }),
            "signature output touched on failure");
    for (int purpose : {TOS_WALLET_PQ_AUTH, TOS_WALLET_PQ_POP, TOS_WALLET_PQ_PREPARATION}) {
      if (primary && purpose == TOS_WALLET_PQ_PREPARATION) {
        const auto previous = signature;
        require(!sign(role, purpose, key, 32, signature.size()), "primary preparation accepted");
        require(signature == previous, "forbidden purpose changed output");
        continue;
      }
      require(sign(role, purpose, key, 32, signature.size()) == 1, "valid bound signing");
      const std::string_view context = purpose == TOS_WALLET_PQ_POP           ? "TOS-RESCUE-POP-v1"
                                       : purpose == TOS_WALLET_PQ_PREPARATION ? "TOS-RESCUE-FEE-PREP-v1"
                                       : primary                              ? "TOS-AUTH-V2-ML-DSA-44-v1"
                                                                              : "TOS-AUTH-SLH-DSA-SHA2-128S-v1";
      const auto result = primary ? tos::pq::verify_mldsa44(view(digest), context, view(signature), view(key))
                                  : tos::pq::verify_slhdsa128s(view(digest), context, view(signature), view(key));
      require(result == tos::pq::VerifyResult::valid, "signature verification");
    }
  }
  std::cout << "Bound C signing and C header linkage pass\n";
}
