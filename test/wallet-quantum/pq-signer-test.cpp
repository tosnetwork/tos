/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <type_traits>

#include "mldsa44.h"
#include "slhdsa128s.h"
#include "wallet-pq-signer.h"
using namespace tos::pq;

int main() {
  static_assert(!std::is_copy_constructible_v<WalletPQSigner>);
  static_assert(!std::is_copy_assignable_v<WalletPQSigner>);
  assert(!WalletPQSigner::from_seed(static_cast<WalletPQRole>(99), std::string(48, 'x')));
  assert(!WalletPQSigner::generate(static_cast<WalletPQRole>(99)));
  for (auto role : {WalletPQRole::primary, WalletPQRole::rescue}) {
    const std::size_t seed_size = role == WalletPQRole::primary ? 32 : 48;
    assert(!WalletPQSigner::from_seed(role, std::string(seed_size - 1, 'x')));
    assert(!WalletPQSigner::from_seed(role, std::string(seed_size + 1, 'x')));
    // Public fixture seed only. No generated private material is printed/stored.
    auto key = WalletPQSigner::from_seed(role, std::string(seed_size, 'x'));
    auto same = WalletPQSigner::from_seed(role, std::string(seed_size, 'x'));
    assert(key && same && key->public_key() == same->public_key());
    auto fresh = WalletPQSigner::generate(role);
    assert(fresh && fresh->public_key() != key->public_key());
    assert(key->role() == role);
    assert(key->public_key().size() == (role == WalletPQRole::primary ? 1312 : 32));
    assert(!key->sign(WalletPQPurpose::auth, std::string(31, 'd')));
    assert(!key->sign(WalletPQPurpose::auth, std::string(33, 'd')));
    assert(!key->sign(static_cast<WalletPQPurpose>(99), std::string(32, 'd')));
    for (auto purpose : {WalletPQPurpose::auth, WalletPQPurpose::pop, WalletPQPurpose::preparation}) {
      const std::string digest(32, 'd');
      auto sig = key->sign(purpose, digest);
      if (role == WalletPQRole::primary && purpose == WalletPQPurpose::preparation) {
        assert(!sig);
        continue;
      }
      assert(sig);
      const std::string context = purpose == WalletPQPurpose::pop           ? "TOS-RESCUE-POP-v1"
                                  : purpose == WalletPQPurpose::preparation ? "TOS-RESCUE-FEE-PREP-v1"
                                  : role == WalletPQRole::primary           ? "TOS-AUTH-V2-ML-DSA-44-v1"
                                                                            : "TOS-AUTH-SLH-DSA-SHA2-128S-v1";
      auto verify = [&](std::string_view msg, std::string_view ctx, std::string_view signature, std::string_view pk) {
        return role == WalletPQRole::primary ? verify_mldsa44(msg, ctx, signature, pk)
                                             : verify_slhdsa128s(msg, ctx, signature, pk);
      };
      assert(sig->size() == (role == WalletPQRole::primary ? 2420 : 7856));
      assert(verify(digest, context, *sig, key->public_key()) == VerifyResult::valid);
      assert(verify(std::string(32, 'e'), context, *sig, key->public_key()) == VerifyResult::invalid);
      assert(verify(digest, "wrong-domain", *sig, key->public_key()) == VerifyResult::invalid);
      assert(verify(digest, context, *sig, fresh->public_key()) == VerifyResult::invalid);
      auto repeated = key->sign(purpose, digest);
      assert(repeated && *repeated != *sig);
      (*sig)[0] ^= 1;
      assert(verify(digest, context, *sig, key->public_key()) == VerifyResult::invalid);
    }
    auto moved = std::move(*key);
    assert(!key->sign(WalletPQPurpose::auth, std::string(32, 'd')));
    assert(moved.public_key() == same->public_key());
  }
  std::puts("wallet PQ signer: both suites, five domains, randomized signatures and refusal boundaries pass");
}
