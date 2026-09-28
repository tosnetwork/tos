/* Copyright (c) 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <map>

#include "block/validator-session-members.h"
#include "block/validator-set.h"
#include "td/utils/tests.h"

namespace {
td::Bits256 bits(unsigned char value) {
  auto result = td::Bits256::zero();
  result.as_slice().fill(value);
  return result;
}
td::Ref<block::ValidatorSet> validators(int label, bool shared_address = false) {
  std::vector<tos::ValidatorDescr> descriptors;
  for (int i = 0; i < 3; ++i) {
    // Deliberately unsorted ADNL addresses: removing the selector's sort must
    // not pass merely because descriptor order already equals transport order.
    descriptors.emplace_back(tos::ValidatorId{bits(label + i)}, 1, tos::ConsensusKeyId{bits(label + 10 + i)},
                             std::string(1312, 'k'), 1, bits(label + 20 + (shared_address ? 0 : (i + 2) % 3)));
  }
  return td::make_ref<block::ValidatorSet>(1, tos::ShardIdFull{tos::masterchainId}, std::move(descriptors));
}
}  // namespace
TEST(CurrentValidatorAdnl, OffsetAndTransportIdentity) {
  for (bool absent_other : {false, true}) {
    std::map<int, td::Ref<block::ValidatorSet>> sets{{-1, validators(1)}, {0, validators(40)}, {1, validators(80)}};
    if (absent_other) {
      sets[-1] = {};
      sets[1] = {};
    }
    std::vector<td::Bits256> input_addresses;
    for (const auto& member : sets[0]->export_vector())
      input_addresses.push_back(member.addr);
    ASSERT_TRUE(input_addresses != std::vector<td::Bits256>({bits(60), bits(61), bits(62)}));
    std::vector<int> calls;
    auto result = block::current_validator_adnl_ids([&](int offset) {
      calls.push_back(offset);
      return sets[offset];
    });
    ASSERT_TRUE(calls == std::vector<int>{0});
    ASSERT_TRUE(result == std::vector<td::Bits256>({bits(60), bits(61), bits(62)}));
  }
}
TEST(CurrentValidatorAdnl, NormalizationAndMissingCurrent) {
  auto set = validators(40, true);
  auto result = block::current_validator_adnl_ids([&](int offset) {
    ASSERT_EQ(offset, 0);
    return set;
  });
  ASSERT_TRUE(result == std::vector<td::Bits256>{bits(60)});
  auto missing = block::current_validator_adnl_ids([&](int offset) {
    ASSERT_EQ(offset, 0);
    return td::Ref<block::ValidatorSet>{};
  });
  ASSERT_TRUE(missing.empty());
  auto empty =
      td::make_ref<block::ValidatorSet>(1, tos::ShardIdFull{tos::masterchainId}, std::vector<tos::ValidatorDescr>{});
  ASSERT_TRUE(block::current_validator_adnl_ids([&](int) { return empty; }).empty());
}
