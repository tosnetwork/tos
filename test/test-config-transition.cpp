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

// block::valid_config_transition() is the one predicate both the collator
// (before installing a new configuration) and the validator (in
// check_config_update) apply to an old -> new configuration pair. These
// tests pin what it accepts and rejects on real ConfigParam 12 cells, and
// pin the external-message size default that applies whenever ConfigParam 43
// is absent from the configuration.

#include "block/block.h"
#include "block/mc-config.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/dict.h"

namespace {

struct WorkchainSpec {
  td::int32 id = 0;
  td::uint32 version = 1;
  td::int32 vm_version = -1;
  td::uint64 vm_mode = 0;
  bool active = true;
  td::Bits256 zerostate_root_hash = td::Bits256::zero();
};

// workchain#a6 enabled_since:uint32 monitor_min_split:(## 8) min_split:(## 8)
//   max_split:(## 8) basic:(## 1) active:Bool accept_msgs:Bool flags:(## 13)
//   zerostate_root_hash:bits256 zerostate_file_hash:bits256 version:uint32
//   format:(WorkchainFormat basic) = WorkchainDescr;
// wfmt_basic#1 vm_version:int32 vm_mode:uint64 = WorkchainFormat 1;
td::Ref<vm::Cell> make_workchain_descr(const WorkchainSpec& spec) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0xa6, 8));
  CHECK(cb.store_long_bool(0, 32));  // enabled_since
  CHECK(cb.store_long_bool(0, 8));   // monitor_min_split
  CHECK(cb.store_long_bool(0, 8));   // min_split
  CHECK(cb.store_long_bool(4, 8));   // max_split
  CHECK(cb.store_long_bool(1, 1));   // basic
  CHECK(cb.store_long_bool(spec.active ? 1 : 0, 1));
  CHECK(cb.store_long_bool(1, 1));   // accept_msgs
  CHECK(cb.store_long_bool(0, 13));  // flags
  CHECK(cb.store_bits_bool(spec.zerostate_root_hash.cbits(), 256));
  cb.store_zeroes(256);              // zerostate_file_hash
  CHECK(cb.store_long_bool(spec.version, 32));
  CHECK(cb.store_long_bool(1, 4));   // wfmt_basic#1
  CHECK(cb.store_long_bool(spec.vm_version, 32));
  CHECK(cb.store_long_bool(static_cast<long long>(spec.vm_mode), 64));
  return cb.finalize();
}

// Builds a full configuration dictionary holding only ConfigParam 12.
td::Ref<vm::Cell> make_config(const std::vector<WorkchainSpec>& workchains) {
  vm::Dictionary wc_dict{32};
  for (const auto& spec : workchains) {
    td::BitArray<32> key;
    key.store_ulong(static_cast<td::uint32>(spec.id));
    CHECK(wc_dict.set(key.cbits(), 32, vm::load_cell_slice_ref(make_workchain_descr(spec))));
  }
  vm::Dictionary cfg{32};
  td::BitArray<32> param12;
  param12.store_ulong(12);
  // _ workchains:(HashmapE 32 WorkchainDescr) = ConfigParam 12;
  // HashmapE is a presence bit followed by a reference to the dictionary root.
  vm::CellBuilder cb;
  auto root = wc_dict.get_root_cell();
  if (root.not_null()) {
    CHECK(cb.store_long_bool(1, 1) && cb.store_ref_bool(std::move(root)));
  } else {
    CHECK(cb.store_long_bool(0, 1));
  }
  CHECK(cfg.set_ref(param12.cbits(), 32, cb.finalize()));
  // Something else must be present so that the configuration root is not null.
  td::BitArray<32> param0;
  param0.store_ulong(0);
  vm::CellBuilder addr;
  addr.store_zeroes(256);
  CHECK(cfg.set_ref(param0.cbits(), 32, addr.finalize()));
  return cfg.get_root_cell();
}

void expect_ok(const td::Status& status) {
  if (status.is_error()) {
    LOG(ERROR) << "unexpected rejection: " << status;
  }
  ASSERT_TRUE(status.is_ok());
}

}  // namespace

TEST(ConfigTransition, unchanged_configuration_is_accepted) {
  auto cfg = make_config({WorkchainSpec{}});
  expect_ok(block::valid_config_transition(cfg, cfg));
}

TEST(ConfigTransition, adding_a_workchain_is_accepted) {
  auto old_cfg = make_config({WorkchainSpec{}});
  WorkchainSpec extra;
  extra.id = 1;
  auto new_cfg = make_config({WorkchainSpec{}, extra});
  expect_ok(block::valid_config_transition(old_cfg, new_cfg));
}

TEST(ConfigTransition, changing_a_flag_that_is_not_part_of_the_rule_is_accepted) {
  auto old_cfg = make_config({WorkchainSpec{}});
  WorkchainSpec inactive;
  inactive.active = false;
  auto new_cfg = make_config({inactive});
  expect_ok(block::valid_config_transition(old_cfg, new_cfg));
}

TEST(ConfigTransition, version_bump_is_rejected) {
  auto old_cfg = make_config({WorkchainSpec{}});
  WorkchainSpec bumped;
  bumped.version = 2;
  auto new_cfg = make_config({bumped});
  auto status = block::valid_config_transition(old_cfg, new_cfg);
  ASSERT_TRUE(status.is_error());
  ASSERT_TRUE(status.message().str().find("WorkchainDescr version") != std::string::npos);
}

TEST(ConfigTransition, vm_version_change_is_rejected) {
  auto old_cfg = make_config({WorkchainSpec{}});
  WorkchainSpec changed;
  changed.vm_version = 5;
  auto new_cfg = make_config({changed});
  ASSERT_TRUE(block::valid_config_transition(old_cfg, new_cfg).is_error());
}

TEST(ConfigTransition, vm_mode_change_is_rejected) {
  auto old_cfg = make_config({WorkchainSpec{}});
  WorkchainSpec changed;
  changed.vm_mode = 1;
  auto new_cfg = make_config({changed});
  ASSERT_TRUE(block::valid_config_transition(old_cfg, new_cfg).is_error());
}

TEST(ConfigTransition, zerostate_hash_change_is_rejected) {
  auto old_cfg = make_config({WorkchainSpec{}});
  WorkchainSpec changed;
  changed.zerostate_root_hash = td::Bits256::ones();
  auto new_cfg = make_config({changed});
  ASSERT_TRUE(block::valid_config_transition(old_cfg, new_cfg).is_error());
}

TEST(ConfigTransition, removing_a_workchain_is_rejected) {
  auto old_cfg = make_config({WorkchainSpec{}});
  auto new_cfg = make_config({});
  ASSERT_TRUE(block::valid_config_transition(old_cfg, new_cfg).is_error());
}

TEST(ConfigTransition, missing_configuration_root_is_rejected) {
  auto cfg = make_config({WorkchainSpec{}});
  ASSERT_TRUE(block::valid_config_transition({}, cfg).is_error());
  ASSERT_TRUE(block::valid_config_transition(cfg, {}).is_error());
}

TEST(ConfigTransition, malformed_param12_is_an_error_not_an_exception) {
  vm::Dictionary cfg{32};
  td::BitArray<32> param12;
  param12.store_ulong(12);
  vm::CellBuilder garbage;
  garbage.store_ones(64);
  CHECK(cfg.set_ref(param12.cbits(), 32, garbage.finalize()));
  auto good = make_config({WorkchainSpec{}});
  ASSERT_TRUE(block::valid_config_transition(good, cfg.get_root_cell()).is_error());
  ASSERT_TRUE(block::valid_config_transition(cfg.get_root_cell(), good).is_error());
}

TEST(ConfigTransition, external_message_size_default_is_64k) {
  // Applied whenever ConfigParam 43 is absent; every validator parses and
  // broadcasts external messages up to this size before any gas is paid.
  block::SizeLimitsConfig::ExtMsgLimits limits;
  ASSERT_EQ(65535u, limits.max_size);
}

TEST(ConfigTransition, ingress_destination_continuity) {
  auto base = make_config({WorkchainSpec{}});
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address.set_zero();
  policy.engine_configuration = vm::CellBuilder().finalize();
  auto with_policies = [&](std::vector<block::WorkchainNativeIngressPolicy> policies) {
    vm::Dictionary config(base, 32);
    auto encoded = block::encode_workchain_native_ingress_table(policies).move_as_ok();
    ASSERT_TRUE(config.set_ref(td::BitArray<32>{block::kWorkchainNativeIngressConfigParam}, encoded));
    return config.get_root_cell();
  };
  auto original = with_policies({policy});
  auto hash = original->get_hash();
  expect_ok(block::valid_config_transition(original, original));
  ASSERT_TRUE(block::valid_config_transition(original, base).is_error());
  ASSERT_TRUE(block::valid_config_transition(original, with_policies({})).is_error());
  auto changed = policy;
  changed.executor_address = td::Bits256::ones();
  ASSERT_TRUE(block::valid_config_transition(original, with_policies({changed})).is_error());
  // Entry order or unrelated entries cannot authorize changing an existing destination.
  auto extra = policy;
  extra.workchain_id = 3;
  expect_ok(block::valid_config_transition(original, with_policies({extra, policy})));
  ASSERT_TRUE(block::valid_config_transition(original, with_policies({extra, changed})).is_error());
  ASSERT_TRUE(original->get_hash() == hash);
}
