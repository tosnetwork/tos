/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// A validator group must only be created when this build fully understands the
// workchain's consensus configuration. Anything else -- the parameter absent,
// the cell malformed, the per-workchain entry missing, reserved flag bits set,
// or a protocol version newer than this build supports -- has to fail closed:
// running a group anyway would either select a different consensus
// implementation (splitting the network between binary versions) or abort in
// the bridge's version check.
//
// These tests drive real ConfigParam 30 cells through the real parser
// (block::Config::get_new_consensus_config) into the admission predicate that
// ValidatorManagerImpl uses for both validator and observer groups, so they
// cover the whole decision path rather than a hand-built struct.

#include "block/mc-config.h"
#include "td/utils/tests.h"
#include "tos/tos-types.h"
#include "vm/cells.h"
#include "vm/dict.h"

namespace {

// simplex_config_v2#22 flags:(## 5) protocol_version:(## 2) use_quic:Bool
//   slots_per_leader_window:(## 32) noncritical_params:(HashmapE 8 uint32)
td::Ref<vm::Cell> make_simplex_v2(unsigned flags, unsigned protocol_version) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0x22, 8));
  CHECK(cb.store_long_bool(flags, 5));
  CHECK(cb.store_long_bool(protocol_version, 2));
  CHECK(cb.store_long_bool(0, 1));   // use_quic
  CHECK(cb.store_long_bool(4, 32));  // slots_per_leader_window (>= 1)
  CHECK(cb.store_long_bool(0, 1));   // empty HashmapE
  return cb.finalize();
}

// simplex_config#21 flags:(## 7) use_quic:Bool target_rate_ms:uint32
//   slots_per_leader_window:(## 32) first_block_timeout_ms:uint32
//   max_leader_window_desync:uint32
td::Ref<vm::Cell> make_simplex_v1(unsigned flags) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0x21, 8));
  CHECK(cb.store_long_bool(flags, 7));
  CHECK(cb.store_long_bool(0, 1));     // use_quic
  CHECK(cb.store_long_bool(400, 32));  // target_rate_ms
  CHECK(cb.store_long_bool(4, 32));    // slots_per_leader_window (>= 1)
  CHECK(cb.store_long_bool(2000, 32));  // first_block_timeout_ms
  CHECK(cb.store_long_bool(250, 32));   // max_leader_window_desync
  return cb.finalize();
}

// new_consensus_config_all#10 mc:(Maybe ^NewConsensusConfig)
//   shard:(Maybe ^NewConsensusConfig)
td::Ref<vm::Cell> make_param30(td::Ref<vm::Cell> mc, td::Ref<vm::Cell> shard) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0x10, 8));
  if (mc.not_null()) {
    CHECK(cb.store_long_bool(1, 1) && cb.store_ref_bool(std::move(mc)));
  } else {
    CHECK(cb.store_long_bool(0, 1));
  }
  if (shard.not_null()) {
    CHECK(cb.store_long_bool(1, 1) && cb.store_ref_bool(std::move(shard)));
  } else {
    CHECK(cb.store_long_bool(0, 1));
  }
  return cb.finalize();
}

// A configuration dictionary holding only ConfigParam 30 (when given) plus a
// filler so the root is never null. ConfigParam 29 is deliberately absent:
// get_consensus_config() falls back to defaults, which is what a node without
// an explicit consensus config sees.
std::unique_ptr<block::Config> make_config(td::Ref<vm::Cell> param30) {
  vm::Dictionary cfg{32};
  if (param30.not_null()) {
    td::BitArray<32> key;
    key.store_ulong(30);
    CHECK(cfg.set_ref(key.cbits(), 32, std::move(param30)));
  }
  td::BitArray<32> param0;
  param0.store_ulong(0);
  vm::CellBuilder addr;
  addr.store_zeroes(256);
  CHECK(cfg.set_ref(param0.cbits(), 32, addr.finalize()));
  auto r_config = block::Config::unpack_config(cfg.get_root_cell());
  CHECK(r_config.is_ok());
  return r_config.move_as_ok();
}

bool admissible(const std::unique_ptr<block::Config>& config, tos::WorkchainId wc) {
  return tos::consensus_group_admissible(config->get_new_consensus_config(wc));
}

}  // namespace

TEST(ConsensusConfigAdmission, supported_version_is_admissible) {
  // The baseline: a well-formed v2 entry at the highest version this build
  // supports must be accepted for both the masterchain and a basechain.
  auto config = make_config(make_param30(
      make_simplex_v2(0, tos::NewConsensusConfig::MAX_SUPPORTED_PROTOCOL_VERSION),
      make_simplex_v2(0, tos::NewConsensusConfig::MAX_SUPPORTED_PROTOCOL_VERSION)));
  ASSERT_TRUE(admissible(config, tos::masterchainId));
  ASSERT_TRUE(admissible(config, tos::basechainId));
}

TEST(ConsensusConfigAdmission, legacy_v1_entry_is_admissible) {
  auto config = make_config(make_param30(make_simplex_v1(0), make_simplex_v1(0)));
  ASSERT_TRUE(admissible(config, tos::masterchainId));
  ASSERT_TRUE(admissible(config, tos::basechainId));
}

TEST(ConsensusConfigAdmission, missing_parameter_fails_closed) {
  // The case that used to fall back to the abandoned consensus stack.
  auto config = make_config({});
  ASSERT_TRUE(!admissible(config, tos::masterchainId));
  ASSERT_TRUE(!admissible(config, tos::basechainId));
}

TEST(ConsensusConfigAdmission, missing_workchain_entry_fails_closed) {
  // Present parameter, but the side this node validates is `nothing`.
  auto only_shard = make_config(make_param30({}, make_simplex_v2(0, 2)));
  ASSERT_TRUE(!admissible(only_shard, tos::masterchainId));
  ASSERT_TRUE(admissible(only_shard, tos::basechainId));

  auto only_mc = make_config(make_param30(make_simplex_v2(0, 2), {}));
  ASSERT_TRUE(admissible(only_mc, tos::masterchainId));
  ASSERT_TRUE(!admissible(only_mc, tos::basechainId));
}

TEST(ConsensusConfigAdmission, newer_protocol_version_fails_closed) {
  // The load-bearing case: governance activates a version this build does not
  // implement. protocol_version is a 2-bit field, so MAX_SUPPORTED + 1 is a
  // value that really can appear on chain. It must not reach the bridge, whose
  // version check aborts the process.
  constexpr unsigned future = tos::NewConsensusConfig::MAX_SUPPORTED_PROTOCOL_VERSION + 1;
  static_assert(future <= 3, "protocol_version is a 2-bit field");
  auto config = make_config(make_param30(make_simplex_v2(0, future), make_simplex_v2(0, future)));
  ASSERT_TRUE(!admissible(config, tos::masterchainId));
  ASSERT_TRUE(!admissible(config, tos::basechainId));
}

TEST(ConsensusConfigAdmission, reserved_flag_bits_fail_closed) {
  // Reserved bits carry no meaning in any supported implementation, so a
  // configuration that sets them is one this build cannot claim to run.
  for (unsigned bit = 0; bit < 5; ++bit) {
    auto config = make_config(make_param30(make_simplex_v2(1u << bit, 2), make_simplex_v2(1u << bit, 2)));
    ASSERT_TRUE(!admissible(config, tos::masterchainId));
    ASSERT_TRUE(!admissible(config, tos::basechainId));
  }
  for (unsigned bit = 0; bit < 7; ++bit) {
    auto config = make_config(make_param30(make_simplex_v1(1u << bit), make_simplex_v1(1u << bit)));
    ASSERT_TRUE(!admissible(config, tos::masterchainId));
    ASSERT_TRUE(!admissible(config, tos::basechainId));
  }
}

TEST(ConsensusConfigAdmission, malformed_parameter_fails_closed) {
  // An unknown constructor tag: the parameter is present but unparseable.
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0xff, 8));
  cb.store_zeroes(64);
  auto config = make_config(cb.finalize());
  ASSERT_TRUE(!admissible(config, tos::masterchainId));
  ASSERT_TRUE(!admissible(config, tos::basechainId));
}

TEST(ConsensusConfigAdmission, unknown_inner_constructor_fails_closed) {
  // Well-formed outer wrapper, unparseable per-workchain entry.
  vm::CellBuilder inner;
  CHECK(inner.store_long_bool(0x2f, 8));
  inner.store_zeroes(64);
  auto entry = inner.finalize();
  auto config = make_config(make_param30(entry, entry));
  ASSERT_TRUE(!admissible(config, tos::masterchainId));
  ASSERT_TRUE(!admissible(config, tos::basechainId));
}
