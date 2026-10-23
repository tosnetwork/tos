/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The one routine that signs a validator's stake, exercised directly.
//
// A review's standing objection was that the operator tool was tested while the node's
// control query -- the path a real validator's first stake actually takes -- was not, so
// the two could drift and a bug could live only in the untested one. They now call a
// single routine, sign_stake_authorization, and this pins that routine: it must derive
// the key identity from the signer (not copy it by a Bits256's bit-count, the overflow
// that once crashed both call sites), sign the exact stake preimage under the election
// domain and no other, bind that signature to the sending account and the transport
// address, and refuse a zero address, a zero sender, or a weight factor below one.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-elector.h"
#include "crypto/pq/pq-stake-authorization.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

}  // namespace

int main() {
  // A deterministic consensus key, so the assertions are reproducible.
  std::string seed(32, '\0');
  for (int i = 0; i < 32; ++i) {
    seed[i] = static_cast<char>(i * 7 + 1);
  }
  auto maybe_store = tos::pq::ValidatorPQKeyStore::from_seed(seed);
  assert(maybe_store.has_value() && "a 32-byte seed yields a consensus key");
  const auto& store = *maybe_store;

  const std::int32_t global_id = -239;
  const std::uint32_t election = 1789434000u;
  const std::uint32_t max_factor = 0x30000;  // three, comfortably above the floor
  const auto src_addr = fill(0xa1);
  const auto adnl = fill(0xb2);

  auto auth = tos::pq::sign_stake_authorization(store, global_id, election, max_factor, src_addr, adnl);
  assert(auth.has_value() && "a well-formed stake is signable");
  assert(auth->signature.algorithm_id == tos::pq::PQAlgorithmId::mldsa44);
  assert(auth->signature.signature.size() == tos::pq::mldsa44_signature_bytes && "a full ML-DSA-44 signature");

  // The key identity is the signer's, derived once. A copy that read the destination
  // Bits256's size would have written 256 bytes here; this asserts the 32 that belong.
  assert(std::memcmp(auth->key_id.data(), store.consensus_key().key_id.data(), 32) == 0 &&
         "the authorised key id is the consensus key's own");

  // The signature verifies over the exact preimage the elector will rebuild, under the
  // election context and no other. verify_mldsa44 takes the raw message and the context
  // separately, exactly as the contract's on-chain verify does.
  const std::string public_key = store.consensus_key().public_key;
  assert(public_key.size() == tos::pq::mldsa44_public_key_bytes);
  const auto preimage = tos::pq::stake_preimage(global_id, election, max_factor, src_addr, adnl);
  assert(tos::pq::verify_mldsa44(preimage, tos::pq::validator_election_context, auth->signature.signature,
                                 public_key) == tos::pq::VerifyResult::valid &&
         "the stake signature verifies over its own preimage under the election domain");

  // Domain separation: the same signature must not verify under a neighbouring authority's
  // context. This is what stops a stake being replayed as a configuration vote.
  assert(tos::pq::verify_mldsa44(preimage, tos::pq::validator_config_vote_context, auth->signature.signature,
                                 public_key) != tos::pq::VerifyResult::valid &&
         "a stake verifies under the configuration-vote domain");

  // The signature is bound to the account that sends the stake: another sender cannot
  // present it, which is what makes the elector's reading of the sender meaningful.
  const auto other_sender_preimage = tos::pq::stake_preimage(global_id, election, max_factor, fill(0xa2), adnl);
  assert(tos::pq::verify_mldsa44(other_sender_preimage, tos::pq::validator_election_context,
                                 auth->signature.signature, public_key) != tos::pq::VerifyResult::valid &&
         "a stake signature verifies with the sender changed");

  // And to the transport address it states.
  const auto other_address_preimage = tos::pq::stake_preimage(global_id, election, max_factor, src_addr, fill(0xb3));
  assert(tos::pq::verify_mldsa44(other_address_preimage, tos::pq::validator_election_context,
                                 auth->signature.signature, public_key) != tos::pq::VerifyResult::valid &&
         "a stake signature verifies with the transport address changed");

  // Preconditions, enforced once for both call sites. Each must refuse, returning nothing.
  assert(!tos::pq::sign_stake_authorization(store, global_id, election, max_factor, src_addr, fill(0x00))
              .has_value() &&
         "a zero transport address is refused");
  assert(!tos::pq::sign_stake_authorization(store, global_id, election, max_factor, fill(0x00), adnl)
              .has_value() &&
         "a zero sender is refused");
  assert(!tos::pq::sign_stake_authorization(store, global_id, election, 0xffff, src_addr, adnl).has_value() &&
         "a weight factor below one is refused");

  // The floor itself is admitted: exactly one is 0x10000.
  assert(tos::pq::sign_stake_authorization(store, global_id, election, 0x10000, src_addr, adnl).has_value() &&
         "a weight factor of exactly one is admitted");

  std::printf("STAKE_AUTHORISATION_OK signature=%zu bytes key_id derived, sender- and address-bound\n",
              auth->signature.signature.size());
  return 0;
}
