/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The consensus context the Simplex fuzz target verifies against, shared with the seed
// generator so the committed seeds carry signatures this context accepts: three
// validators of equal weight with post-quantum consensus keys from fixed public seeds,
// never operational key material.

#pragma once

#include <cstring>
#include <string>
#include <vector>

#include "crypto/pq/consensus-pq-signer.h"
#include "tos/quorum.h"
#include "validator/consensus/bus.h"

namespace tos::fuzz {

inline td::Bits256 filled(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

struct SimplexFixture {
  struct FirstLeader final : tos::validator::consensus::CollatorSchedule {
    tos::validator::consensus::PeerValidatorId expected_collator_for(td::uint32) const override {
      return tos::validator::consensus::PeerValidatorId{0};
    }
  };

  static constexpr std::size_t kValidators = 3;

  tos::validator::consensus::Bus bus;
  std::vector<tos::pq::ValidatorPQKeyStore> stores;

  // False when a key could not be derived; the caller must not use the fixture then.
  bool ok = true;

  SimplexFixture() {
    namespace c = tos::validator::consensus;
    bus.session_id = filled(0x42);
    bus.shard = tos::ShardIdFull{tos::masterchainId};
    bus.cc_seqno = 11;
    bus.total_weight = 0;
    bus.collator_schedule = td::make_ref<FirstLeader>();
    for (std::size_t i = 0; i < kValidators; ++i) {
      auto store = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, static_cast<char>(0x40 + i)));
      if (!store.has_value()) {
        ok = false;
        return;
      }
      stores.push_back(std::move(*store));
      auto adnl = tos::adnl::AdnlNodeIdShort{filled(static_cast<unsigned char>(0x90 + i))};
      bus.validator_set.push_back(c::PeerValidator{
          .validator_id = tos::ValidatorId{filled(static_cast<unsigned char>(0x70 + i))},
          .idx = c::PeerValidatorId{i},
          .consensus_key = stores.back().consensus_key(),
          .transport_key_id = adnl.pubkey_hash(),
          .adnl_id = adnl,
          .weight = 1,
      });
      if (!tos::checked_add_validator_weight(bus.total_weight, 1)) {
        ok = false;
        return;
      }
    }
  }
};

// Input kinds of the Simplex target: the first input byte selects one, the second the
// validator a vote or candidate arrives from, and the rest is the message.
enum class SimplexInput : std::uint8_t { vote = 0, certificate = 1, candidate = 2 };

}  // namespace tos::fuzz
