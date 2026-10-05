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

#include <filesystem>

#include "block/auth-policy.h"
#include "block/block-auto.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "validator/auth-policy-admission.h"
#include "vm/boc.h"
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
  cb.store_zeroes(256);  // zerostate_file_hash
  CHECK(cb.store_long_bool(spec.version, 32));
  CHECK(cb.store_long_bool(1, 4));  // wfmt_basic#1
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

namespace {
td::Ref<vm::Cell> auth_policy_cell(td::uint64 sequence = 0, int retired = 0, td::uint32 deadline = 0,
                                   int network = 123) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(0xa1, 8));
  cb.store_zeroes(224);
  CHECK(cb.store_long_bool(network, 32));
  CHECK(cb.store_long_bool(static_cast<long long>(sequence), 64));
  CHECK(cb.store_long_bool(retired, 16));
  if (deadline) {
    vm::Dictionary schedule{8};
    vm::CellBuilder entry;
    CHECK(entry.store_long_bool(deadline, 32));
    CHECK(schedule.set(td::BitArray<8>{1}, vm::load_cell_slice_ref(entry.finalize())));
    CHECK(cb.store_long_bool(1, 1) && cb.store_ref_bool(schedule.get_root_cell()));
  } else {
    CHECK(cb.store_long_bool(0, 1));
  }
  td::Bits256 spec;
  td::sha256(block::auth_policy_profile, spec.as_slice());
  CHECK(cb.store_bits_bool(spec.cbits(), 256));
  return cb.finalize();
}

td::Ref<vm::Cell> auth_config(td::Ref<vm::Cell> policy, int version = 17, bool mandatory = true, bool critical = true) {
  vm::Dictionary cfg{make_config({WorkchainSpec{}}), 32};
  vm::CellBuilder ver;
  CHECK(ver.store_long_bool(0xc4, 8) && ver.store_long_bool(version, 32) && ver.store_long_bool(0, 64));
  CHECK(cfg.set_ref(td::BitArray<32>{8}, ver.finalize()));
  if (policy.not_null()) {
    CHECK(cfg.set_ref(td::BitArray<32>{48}, policy));
  }
  vm::Dictionary membership{32};
  CHECK(membership.set(td::BitArray<32>{48}, vm::load_cell_slice_ref(vm::CellBuilder{}.finalize())));
  if (mandatory) {
    CHECK(cfg.set_ref(td::BitArray<32>{9}, membership.get_root_cell()));
  }
  if (critical) {
    CHECK(cfg.set_ref(td::BitArray<32>{10}, membership.get_root_cell()));
  }
  return cfg.get_root_cell();
}
}  // namespace

TEST(AuthPolicy, mandatory_version_and_membership) {
  ASSERT_TRUE(block::validate_auth_policy_config(auth_config({}, 16)).is_ok());
  ASSERT_TRUE(block::validate_auth_policy_config(auth_config({}, 17)).is_error());
  ASSERT_TRUE(block::validate_auth_policy_config(auth_config(auth_policy_cell())).is_ok());
  ASSERT_TRUE(block::validate_auth_policy_config(auth_config(auth_policy_cell(), 17, false)).is_error());
  ASSERT_TRUE(block::validate_auth_policy_config(auth_config(auth_policy_cell(), 16, false)).is_error());
  ASSERT_TRUE(block::validate_auth_policy_config(auth_config(auth_policy_cell(), 17, true, false)).is_error());
}

TEST(AuthPolicy, absorbing_retirement_and_sequence) {
  auto initial = auth_config(auth_policy_cell());
  auto retired = auth_config(auth_policy_cell(1, 2));
  expect_ok(block::valid_config_transition(initial, initial));
  expect_ok(block::valid_config_transition(initial, retired));
  ASSERT_TRUE(block::valid_config_transition(retired, auth_config(auth_policy_cell(2))).is_error());
  ASSERT_TRUE(block::valid_config_transition(retired, auth_config(auth_policy_cell(1, 2, 100))).is_error());
  ASSERT_TRUE(block::valid_config_transition(retired, auth_config(auth_policy_cell(0, 2))).is_error());
  ASSERT_TRUE(block::valid_config_transition(retired, auth_config({})).is_error());
  ASSERT_TRUE(block::valid_config_transition(retired, auth_config({}, 16)).is_error());
  ASSERT_TRUE(block::valid_config_transition(initial, auth_config(auth_policy_cell(1, 0, 0, 124))).is_error());
}

TEST(AuthPolicy, deadlines_cannot_disappear_or_move_later) {
  auto initial = auth_config(auth_policy_cell());
  auto scheduled = auth_config(auth_policy_cell(1, 0, 100));
  expect_ok(block::valid_config_transition(initial, scheduled));
  expect_ok(block::valid_config_transition(scheduled, auth_config(auth_policy_cell(2, 0, 100))));
  expect_ok(block::valid_config_transition(scheduled, auth_config(auth_policy_cell(2, 0, 99))));
  ASSERT_TRUE(block::valid_config_transition(scheduled, auth_config(auth_policy_cell(2, 0, 101))).is_error());
  ASSERT_TRUE(block::valid_config_transition(scheduled, auth_config(auth_policy_cell(2))).is_error());
  ASSERT_TRUE(block::valid_config_transition(scheduled, auth_config(auth_policy_cell(2, 2))).is_error());
}

TEST(AuthPolicy, strict_shape_and_initial_sequence) {
  ASSERT_TRUE(block::unpack_auth_policy(auth_policy_cell(0, 4)).is_error());
  ASSERT_TRUE(block::unpack_auth_policy(vm::CellBuilder{}.finalize()).is_error());
  auto legacy = auth_config({}, 16);
  expect_ok(block::valid_config_transition(legacy, auth_config(auth_policy_cell())));
  ASSERT_TRUE(block::valid_config_transition(legacy, auth_config(auth_policy_cell(1))).is_error());
  auto high = auth_config(auth_policy_cell(~td::uint64{0}, 2));
  ASSERT_TRUE(block::valid_config_transition(high, auth_config(auth_policy_cell(0, 2))).is_error());
}

TEST(AuthPolicy, schema_admits_the_frozen_record) {
  ASSERT_TRUE(block::gen::ConfigParam{48}.validate_ref(1024, auth_policy_cell()));
  ASSERT_TRUE(block::gen::ConfigParam{48}.validate_ref(1024, auth_policy_cell(1, 2, 123)));
  ASSERT_TRUE(!block::gen::ConfigParam{48}.validate_ref(1024, vm::CellBuilder{}.finalize()));
}

TEST(AuthPolicy, full_configuration_installation) {
  auto path =
      std::filesystem::path(__FILE__).parent_path().parent_path() / "tosctl/src/executor/real_boc/default_config.boc";
  auto file = td::read_file(path.string());
  ASSERT_TRUE(file.is_ok());
  auto decoded = vm::std_boc_deserialize(file.move_as_ok());
  ASSERT_TRUE(decoded.is_ok());
  auto wrapper = vm::load_cell_slice(decoded.move_as_ok());
  td::Bits256 address;
  ASSERT_TRUE(wrapper.fetch_bits_to(address));
  vm::Dictionary configuration{wrapper.fetch_ref(), 32};
  vm::CellBuilder addr;
  addr.store_bits(address.cbits(), 256);
  td::BitArray<32> zero_key;
  zero_key.store_ulong(0);
  CHECK(configuration.set_ref(zero_key, addr.finalize()));
  // The emulator fixture omits block-production fields; supply valid canonical
  // values so this test exercises full configuration admission, not omissions.
  vm::CellBuilder limits;
  CHECK(limits.store_long_bool(0x5d, 8));
  for (int i = 0; i < 3; ++i) {
    CHECK(limits.store_long_bool(0xc3, 8) && limits.store_long_bool(1, 32) && limits.store_long_bool(2, 32) &&
          limits.store_long_bool(3, 32));
  }
  auto block_limits = limits.finalize();
  CHECK(configuration.set_ref(td::BitArray<32>{22}, block_limits));
  CHECK(configuration.set_ref(td::BitArray<32>{23}, block_limits));
  vm::CellBuilder catchain;
  CHECK(catchain.store_long_bool(0xc1, 8));
  for (int i = 0; i < 4; ++i) {
    CHECK(catchain.store_long_bool(1, 32));
  }
  CHECK(configuration.set_ref(td::BitArray<32>{28}, catchain.finalize()));
  vm::CellBuilder validator;
  CHECK(validator.store_long_bool(0x53, 8) && validator.store_long_bool(0x8e81278a, 32));
  validator.store_zeroes(256);
  CHECK(validator.store_long_bool(1, 64));
  vm::Dictionary validators{16};
  td::BitArray<16> validator_index;
  validator_index.store_ulong(0);
  CHECK(validators.set(validator_index, vm::load_cell_slice_ref(validator.finalize())));
  vm::CellBuilder set;
  CHECK(set.store_long_bool(0x12, 8) && set.store_long_bool(1, 32) && set.store_long_bool(2, 32) &&
        set.store_long_bool(1, 16) && set.store_long_bool(1, 16) && set.store_long_bool(1, 64) &&
        set.store_long_bool(1, 1) && set.store_ref_bool(validators.get_root_cell()));
  CHECK(configuration.set_ref(td::BitArray<32>{34}, set.finalize()));
  ASSERT_TRUE(block::valid_config_data(configuration.get_root_cell(), address));
  auto candidate = auth_config(auth_policy_cell());
  vm::Dictionary additions{candidate, 32};
  for (int param : {8, 9, 10, 48}) {
    CHECK(configuration.set_ref(td::BitArray<32>{param}, additions.lookup_ref(td::BitArray<32>{param})));
  }
  ASSERT_TRUE(block::valid_config_data(configuration.get_root_cell(), address));
  CHECK(configuration.set_ref(td::BitArray<32>{48}, auth_policy_cell(0, 4)));
  ASSERT_TRUE(!block::valid_config_data(configuration.get_root_cell(), address));
}

TEST(AuthPolicy, trusted_state_admission_preserves_errors_and_retirement) {
  using tos::validator::validate_auth_policy_admission;
  auto initial = auth_config(auth_policy_cell());
  auto retired = auth_config(auth_policy_cell(1, 2));
  expect_ok(validate_auth_policy_admission(initial, td::Ref<vm::Cell>{}, false));
  expect_ok(validate_auth_policy_admission(retired, initial, true));
  expect_ok(validate_auth_policy_admission(retired, retired, true));
  ASSERT_TRUE(validate_auth_policy_admission(auth_config({}), td::Ref<vm::Cell>{}, false).is_error());
  ASSERT_TRUE(validate_auth_policy_admission(auth_config(auth_policy_cell(2)), retired, true).is_error());
  ASSERT_TRUE(validate_auth_policy_admission(initial, td::Ref<vm::Cell>{}, true).is_error());
  ASSERT_TRUE(
      validate_auth_policy_admission(td::Status::Error("candidate proof unavailable"), initial, true).is_error());
  ASSERT_TRUE(
      validate_auth_policy_admission(initial, td::Status::Error("previous proof unavailable"), true).is_error());
}
