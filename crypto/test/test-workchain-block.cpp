#include <limits>
#include <random>
#include "workchain-counter-engine.h"

#include "block/workchain-block-execution.h"
#include "block/workchain-participant-lt.h"
#include "block/workchain-participant-record.h"
#include "block/workchain-value-flow.h"
#include "block/workchain-native-allocation.h"
#include "block/workchain-allocation-plan.h"
#include "block/workchain-import-evidence.h"
#include "block/workchain-native-inbox.h"
#include "block/workchain-payout-accounting.h"
#include "block/workchain-storage-overlay.h"
#include "block/workchain-payout-overlay.h"
#include "block/workchain-account-access.h"
#include "block/workchain-account-dictionary.h"
#include "block/workchain-account-access-codec.h"
#include "block/workchain-host-identity.h"
#include "block/workchain-host-input.h"
#include "block/workchain-account-engine.h"
#include "block/workchain-account-settlement.h"
#include "block/workchain-input-preflight.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/MerkleUpdate.h"
#include "vm/cells/UsageCell.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "emulator/transaction-emulator.h"
#include "uno/core/used-nullifiers.h"

namespace {

TEST(WorkchainBlock, PayoutPrincipalAndFees) {
  using C = block::CurrencyCollection;
  auto custody = td::Bits256::zero();
  auto coordinator = custody;
  coordinator.as_slice().back() = 1;
  auto plan = block::account_workchain_payout(custody, coordinator, C(1000), C(100), C(700),
                                             td::make_refint(30), td::make_refint(10), 100);
  ASSERT_TRUE(plan.is_ok());
  auto result = plan.move_as_ok();
  ASSERT_TRUE(result.custody_after == C(300));
  ASSERT_TRUE(result.operator_after == C(70));
  ASSERT_TRUE(result.exported == C(720));
  ASSERT_TRUE(result.fee_funding.value == C(30));
  ASSERT_TRUE(result.rows[0].fees == C(10));
  ASSERT_TRUE(block::verify_workchain_value_flow(result.rows, {result.fee_funding}, 2, 1, 100).is_ok());
  ASSERT_TRUE(block::account_workchain_payout(custody, coordinator, C(1000), C(29), C(700),
      td::make_refint(30), td::make_refint(10), 100).is_error());
  ASSERT_TRUE(block::account_workchain_payout(custody, coordinator, C(699), C(1000), C(700),
      td::make_refint(30), td::make_refint(10), 100).is_error());
  ASSERT_TRUE(block::account_workchain_payout(custody, coordinator, C(1000), C(100), C(700),
      td::make_refint(30), td::make_refint(31), 100).is_error());
  ASSERT_TRUE(block::account_workchain_payout(custody, custody, C(1000), C(100), C(700),
      td::make_refint(30), td::make_refint(10), 100).is_error());
  auto reverse = block::account_workchain_payout(coordinator, custody, C(1000), C(100), C(700),
      td::make_refint(30), td::make_refint(10), 100).move_as_ok();
  ASSERT_TRUE(reverse.rows[0].account == custody && reverse.rows[0].new_balance == C(70));
  ASSERT_TRUE(reverse.rows[1].account == coordinator && reverse.rows[1].new_balance == C(300));
  auto free = block::account_workchain_payout(custody, coordinator, C(700), C(0), C(700),
      td::make_refint(0), td::make_refint(0), 100).move_as_ok();
  ASSERT_TRUE(free.custody_after.is_zero() && free.operator_after.is_zero());
  ASSERT_TRUE(free.exported == C(700));
}

TEST(WorkchainBlock, NativeAccountValueFlow) {
  using C = block::CurrencyCollection;
  auto a = td::Bits256::zero();
  auto b = a;
  b.as_slice().back() = 1;
  // Coordinator funds a custody top-up. Both rows must balance separately.
  std::vector<block::WorkchainAccountValueFlow> rows{
      {a, C(20), C(0), C(12), C(0), C(3)},
      {b, C(100), C(4), C(99), C(10), C(0)}};
  std::vector<block::WorkchainInternalTransfer> edges{{a, b, C(5)}};
  auto verify = [&](const auto& r, const auto& t) {
    return block::verify_workchain_value_flow(r, t, 2, 1, 1024);
  };
  ASSERT_TRUE(verify(rows, edges).is_ok());
  auto shifted = rows;
  shifted[0].new_balance = C(11);
  shifted[1].new_balance = C(100); // Same batch total, wrong per-account allocation.
  ASSERT_TRUE(verify(shifted, edges).is_error());
  ASSERT_TRUE(verify(rows, std::vector<block::WorkchainInternalTransfer>{}).is_error());
  auto reversed = edges;
  reversed[0].from = b;
  reversed[0].to = a;
  ASSERT_TRUE(verify(rows, reversed).is_error());
  auto invalid = rows;
  invalid[0].fees = C(-1);
  ASSERT_TRUE(verify(invalid, edges).is_error());
  invalid = rows;
  invalid[1].account = a;
  ASSERT_TRUE(verify(invalid, edges).is_error());
  auto outside = edges;
  outside[0].to.as_slice().back() = 2;
  ASSERT_TRUE(verify(rows, outside).is_error());
  ASSERT_TRUE(block::verify_workchain_value_flow(rows, edges, 1, 1, 1024).is_error());
  ASSERT_TRUE(block::verify_workchain_value_flow(rows, edges, 2, 0, 1024).is_error());
  ASSERT_EQ(td::cmp(rows[0].old_balance.tomis, td::make_refint(20)), 0);
  auto extra = [&](long long n) {
    vm::Dictionary dict(32);
    vm::CellBuilder cb;
    ASSERT_TRUE(block::tlb::t_VarUIntegerPos_32.store_integer_value(cb, *td::make_refint(n)));
    ASSERT_TRUE(dict.set_builder(a.bits(), 32, cb));
    return dict.get_root_cell();
  };
  std::vector<block::WorkchainAccountValueFlow> multi{
      {a, C(0, extra(7)), C(0), C(0, extra(7)), C(0), C(0)}};
  ASSERT_TRUE(verify(multi, std::vector<block::WorkchainInternalTransfer>{}).is_ok());
  multi[0].new_balance = C(0, extra(6));
  ASSERT_TRUE(verify(multi, std::vector<block::WorkchainInternalTransfer>{}).is_error());
  auto huge = td::make_refint(0);
  huge.unique_write().set_pow2(255);
  std::vector<block::WorkchainAccountValueFlow> wide{
      {a, C(huge), C(0), C(huge), C(0), C(0)}};
  ASSERT_TRUE(verify(wide, std::vector<block::WorkchainInternalTransfer>{}).is_ok());
  wide[0].imported = C(huge);
  wide[0].exported = C(huge);
  ASSERT_TRUE(verify(wide, std::vector<block::WorkchainInternalTransfer>{}).is_error());
}

TEST(WorkchainBlock, ParticipantRecordBinding) {
  auto a = td::Bits256::zero();
  auto b = a;
  b.as_slice().back() = 1;
  auto c = b;
  c.as_slice().back() = 2;
  auto encoded = block::build_workchain_participant_records(b, c, {a, b}, 2);
  ASSERT_TRUE(encoded.is_ok());
  auto records = encoded.move_as_ok();
  ASSERT_EQ(records.size(), 2u);
  for (unsigned i = 0; i < 2; ++i) {
    ASSERT_TRUE(block::gen::t_UnoV2HostRecord.validate_ref(4096, records[i]));
    auto cs = vm::load_cell_slice(records[i]);
    ASSERT_EQ(cs.size(), 832u);
    ASSERT_EQ(cs.size_refs(), 0u);
    ASSERT_EQ(cs.fetch_ulong(32), 0x35739af6u);
    td::Bits256 hash;
    ASSERT_TRUE(cs.fetch_bits_to(hash) && hash == b);
    ASSERT_TRUE(cs.fetch_bits_to(hash) && hash == c);
    ASSERT_TRUE(cs.fetch_bits_to(hash) && hash == (i == 0 ? a : b));
    ASSERT_EQ(cs.fetch_ulong(32), i);
    ASSERT_TRUE(cs.empty_ext());
  }
  auto input_changed = block::build_workchain_participant_records(c, c, {a, b}, 2).move_as_ok();
  auto effects_changed = block::build_workchain_participant_records(b, b, {a, b}, 2).move_as_ok();
  auto account_changed = block::build_workchain_participant_records(b, c, {a, c}, 2).move_as_ok();
  for (unsigned i = 0; i < 2; ++i) {
    ASSERT_TRUE(input_changed[i]->get_hash() != records[i]->get_hash());
    ASSERT_TRUE(effects_changed[i]->get_hash() != records[i]->get_hash());
  }
  ASSERT_TRUE(account_changed[0]->get_hash() == records[0]->get_hash());
  ASSERT_TRUE(account_changed[1]->get_hash() != records[1]->get_hash());
  ASSERT_TRUE(block::build_workchain_participant_records(b, c, {a, b}, 1).is_error());
  ASSERT_TRUE(block::build_workchain_participant_records(b, c, {a, a}, 2).is_error());
  ASSERT_TRUE(block::build_workchain_participant_records(b, c, {b, a}, 2).is_error());
  ASSERT_TRUE(block::build_workchain_participant_records(b, c, {}, 2).is_error());
}

TEST(WorkchainBlock, HostIdentityBinding) {
  auto one = td::Bits256::zero();
  one.as_slice().back() = 1;
  auto two = one;
  two.as_slice().back() = 2;
  auto finality = vm::CellBuilder().store_long(1, 1).finalize();
  block::WorkchainHostIdentity base{-239, one, two, 2, UINT64_MAX, one, true,
      INT64_MIN, UINT64_MAX, UINT32_MAX, 1, two, UINT32_MAX, UINT32_MAX, UINT64_MAX, finality};
  auto encoded = block::encode_workchain_host_identity(base);
  ASSERT_TRUE(encoded.is_ok());
  auto root = encoded.move_as_ok();
  ASSERT_TRUE(block::gen::t_UnoV2HostIdentity.validate_ref(4096, root));
  auto top = vm::load_cell_slice(root);
  ASSERT_EQ(top.size(), 32u);
  ASSERT_EQ(top.size_refs(), 3u);
  auto domain = vm::load_cell_slice(top.fetch_ref());
  ASSERT_EQ(domain.size(), 672u);
  ASSERT_EQ(domain.fetch_ulong(32), 0x5ab37c9au);
  ASSERT_EQ(domain.fetch_long(32), -239);
  td::Bits256 hash;
  ASSERT_TRUE(domain.fetch_bits_to(hash) && hash == one);
  ASSERT_TRUE(domain.fetch_bits_to(hash) && hash == two);
  ASSERT_EQ(domain.fetch_long(32), 2);
  ASSERT_EQ(domain.fetch_ulong(64), UINT64_MAX);
  auto policy = vm::load_cell_slice(top.fetch_ref());
  ASSERT_EQ(policy.size(), 481u);
  ASSERT_EQ(policy.fetch_ulong(32), 0xf704b16cu);
  ASSERT_TRUE(policy.fetch_bits_to(hash) && hash == one);
  ASSERT_EQ(policy.fetch_ulong(1), 1u);
  ASSERT_EQ(policy.fetch_long(64), INT64_MIN);
  ASSERT_EQ(policy.fetch_ulong(64), UINT64_MAX);
  ASSERT_EQ(policy.fetch_ulong(32), UINT32_MAX);
  ASSERT_EQ(policy.fetch_ulong(32), 1u);
  auto context = vm::load_cell_slice(top.fetch_ref());
  ASSERT_EQ(context.size(), 416u);
  ASSERT_EQ(context.fetch_ulong(32), 0x8a4ca5dcu);
  ASSERT_TRUE(context.fetch_bits_to(hash) && hash == two);
  ASSERT_EQ(context.fetch_ulong(32), UINT32_MAX);
  ASSERT_EQ(context.fetch_ulong(32), UINT32_MAX);
  ASSERT_EQ(context.fetch_ulong(64), UINT64_MAX);
  ASSERT_TRUE(context.fetch_ref()->get_hash() == finality->get_hash());
  for (int field = 0; field < 16; ++field) {
    auto changed = base;
    switch (field) {
      case 0: changed.global_id = -238; break;
      case 1: changed.genesis_hash = two; break;
      case 2: changed.instance_id = one; break;
      case 3: changed.workchain_id = 3; break;
      case 4: changed.shard_id = 1; break;
      case 5: changed.configuration_hash = two; break;
      case 6: changed.extended = false; break;
      case 7: changed.engine_selector = 0; break;
      case 8: changed.vm_mode = 1; break;
      case 9: changed.descriptor_version = 1; break;
      case 10: changed.admission_version = 2; break;
      case 11: changed.previous_shard_hash = one; break;
      case 12: changed.height = 1; break;
      case 13: changed.gen_utime = 1; break;
      case 14: changed.host_after_lt = 1; break;
      case 15: changed.finality = vm::CellBuilder().store_long(0, 1).finalize(); break;
    }
    auto other = block::encode_workchain_host_identity(changed);
    ASSERT_TRUE(other.is_ok());
    ASSERT_TRUE(block::gen::t_UnoV2HostIdentity.validate_ref(4096, other.ok()));
    ASSERT_TRUE(other.ok()->get_hash() != root->get_hash());
  }
  base.finality.clear();
  ASSERT_TRUE(block::encode_workchain_host_identity(base).is_error());
}

TEST(WorkchainBlock, AdmittedIdentityAgreement) {
  auto leaf = vm::CellBuilder().store_long(1, 1).finalize();
  auto hash = td::Bits256(leaf->get_hash().bits());
  block::InputPolicyIdentity policy_id{leaf->get_hash(), true, INT64_MIN, UINT64_MAX, 3, 1};
  auto resolved = block::ResolvedInputPolicy::from_resolved_fields({1, 1, 1}, policy_id);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedInputPolicy>(resolved));
  block::CandidateAdmissionSession session(leaf, std::get<block::ResolvedInputPolicy>(resolved));
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(result));
  const auto& admitted = std::get<block::AdmittedInput>(result);
  block::WorkchainHostIdentity host{-1, hash, hash, 2, UINT64_MAX, hash, true,
      INT64_MIN, UINT64_MAX, 3, 1, hash, 1, 1, 1, leaf};
  auto good = block::encode_admitted_workchain_host_identity(host, admitted);
  ASSERT_TRUE(good.is_ok());
  ASSERT_TRUE(good.ok()->get_hash() == block::encode_workchain_host_identity(host).move_as_ok()->get_hash());
  for (int field = 0; field < 6; ++field) {
    auto changed = host;
    switch (field) {
      case 0: changed.configuration_hash = td::Bits256::zero(); break;
      case 1: changed.extended = false; break;
      case 2: changed.engine_selector = 0; break;
      case 3: changed.vm_mode = 0; break;
      case 4: changed.descriptor_version = 4; break;
      case 5: changed.admission_version = 2; break;
    }
    ASSERT_TRUE(block::encode_workchain_host_identity(changed).is_ok());
    ASSERT_TRUE(block::encode_admitted_workchain_host_identity(changed, admitted).is_error());
  }
}

TEST(WorkchainBlock, AccountDeclarationsCodec) {
  auto a = td::Bits256::zero();
  auto b = a;
  b.as_slice().back() = 1;
  block::WorkchainAccountDeclarations declarations{{{a, b}, {b, std::nullopt}}, {b}};
  auto encoded = block::encode_workchain_account_declarations(declarations, 2, 1);
  ASSERT_TRUE(encoded.is_ok());
  auto root = encoded.move_as_ok();
  ASSERT_TRUE(block::gen::t_UnoV2HostAccess.validate_ref(4096, root));
  auto decoded = block::decode_workchain_account_declarations(root, 2, 1);
  ASSERT_TRUE(decoded.is_ok());
  auto value = decoded.move_as_ok();
  ASSERT_EQ(value.reads.size(), 2u);
  ASSERT_EQ(value.writes.size(), 1u);
  ASSERT_TRUE(value.reads[0].account == a);
  ASSERT_TRUE(value.reads[0].old_account_hash == std::optional<td::Bits256>(b));
  ASSERT_TRUE(value.reads[1].account == b);
  ASSERT_TRUE(!value.reads[1].old_account_hash.has_value());
  ASSERT_TRUE(value.writes[0] == b);
  ASSERT_TRUE(block::decode_workchain_account_declarations(root, 1, 1).is_error());
  ASSERT_TRUE(block::decode_workchain_account_declarations(root, 2, 0).is_error());
  ASSERT_TRUE(block::encode_workchain_account_declarations(declarations, 1, 1).is_error());
  auto duplicate = declarations;
  duplicate.reads[1].account = a;
  ASSERT_TRUE(block::encode_workchain_account_declarations(duplicate, 2, 1).is_error());
  auto reversed = declarations;
  std::swap(reversed.reads[0], reversed.reads[1]);
  ASSERT_TRUE(block::encode_workchain_account_declarations(reversed, 2, 1).is_error());
  auto empty = block::encode_workchain_account_declarations({}, 0, 0);
  ASSERT_TRUE(empty.is_ok());
  auto empty_root = empty.move_as_ok();
  ASSERT_TRUE(block::gen::t_UnoV2HostAccess.validate_ref(4096, empty_root));
  ASSERT_EQ(vm::load_cell_slice(empty_root).size(), 34u);
  auto empty_value = block::decode_workchain_account_declarations(empty_root, 0, 0);
  ASSERT_TRUE(empty_value.is_ok());
  ASSERT_TRUE(empty_value.ok().reads.empty() && empty_value.ok().writes.empty());
}

TEST(WorkchainBlock, AccountDeclarationsMalformed) {
  // Independent TL-B builder, not the encoder under test.
  auto absent = vm::CellBuilder().store_long(0x439e6964, 32).store_long(0, 1).finalize();
  ASSERT_TRUE(block::gen::t_UnoV2HostRead.validate_ref(4096, absent));
  auto key = td::Bits256::zero();
  auto make = [&](td::Ref<vm::Cell> read, bool trailing) {
    vm::Dictionary reads(256);
    ASSERT_TRUE(reads.set_ref(key, read));
    vm::CellBuilder cb;
    cb.store_long(0x7bc07a6d, 32);
    ASSERT_TRUE(reads.append_dict_to_bool(cb));
    cb.store_long(0, 1);
    if (trailing) cb.store_long(0, 1);
    return cb.finalize();
  };
  auto valid = make(absent, false);
  ASSERT_TRUE(block::decode_workchain_account_declarations(valid, 1, 0).is_ok());
  auto tail = make(absent, true);
  ASSERT_TRUE(!block::gen::t_UnoV2HostAccess.validate_ref(4096, tail));
  ASSERT_TRUE(block::decode_workchain_account_declarations(tail, 1, 0).is_error());
  auto bad_read = vm::CellBuilder().store_long(0x439e6964, 32).store_long(0, 2).finalize();
  ASSERT_TRUE(!block::gen::t_UnoV2HostRead.validate_ref(4096, bad_read));
  ASSERT_TRUE(block::decode_workchain_account_declarations(make(bad_read, false), 1, 0).is_error());
  auto bad_tag = vm::CellBuilder().store_long(0x439e6965, 32).store_long(0, 1).finalize();
  ASSERT_TRUE(block::decode_workchain_account_declarations(make(bad_tag, false), 1, 0).is_error());
  ASSERT_TRUE(block::decode_workchain_account_declarations({}, 1, 0).is_error());
  auto long_label = vm::CellBuilder().store_long(2, 2).store_long(256, 9)
                        .store_bits(key.bits(), 256).store_ref(absent).finalize();
  auto noncanonical = vm::CellBuilder().store_long(0x7bc07a6d, 32).store_long(1, 1)
                          .store_ref(long_label).store_long(0, 1).finalize();
  ASSERT_TRUE(block::gen::t_UnoV2HostAccess.validate_ref(4096, noncanonical));
  ASSERT_TRUE(block::decode_workchain_account_declarations(noncanonical, 1, 0).is_error());
  vm::Dictionary writes(256);
  vm::CellBuilder empty;
  ASSERT_TRUE(writes.set_builder(key, empty));
  vm::CellBuilder only_write;
  only_write.store_long(0x7bc07a6d, 32).store_long(0, 1);
  ASSERT_TRUE(writes.append_dict_to_bool(only_write));
  auto undeclared = only_write.finalize();
  ASSERT_TRUE(block::gen::t_UnoV2HostAccess.validate_ref(4096, undeclared));
  ASSERT_TRUE(block::decode_workchain_account_declarations(undeclared, 0, 1).is_error());
}

TEST(WorkchainBlock, AccountAccessBinding) {
  auto a = td::Bits256::zero();
  auto b = a;
  b.as_slice().back() = 1;
  auto hash = a;
  hash.as_slice().back() = 7;
  auto make = [&] {
    return block::WorkchainAccountAccess::create({{a, hash}, {b, std::nullopt}}, {b}, 2, 1);
  };
  auto result = make();
  ASSERT_TRUE(result.is_ok());
  auto access = result.move_as_ok();
  ASSERT_TRUE(access.expected_read(a).move_as_ok() == std::optional<td::Bits256>(hash));
  ASSERT_TRUE(!access.expected_read(b).move_as_ok().has_value());
  ASSERT_TRUE(access.record_old_read(a, hash).is_ok());
  ASSERT_TRUE(access.record_old_read(b, std::nullopt).is_ok());
  ASSERT_TRUE(access.record_write(b).is_ok());
  ASSERT_TRUE(access.record_write(b).is_ok()); // Multiple semantic updates, one physical record.
  ASSERT_TRUE(access.finish({b}, {b}).is_ok());
  ASSERT_TRUE(access.record_write(b).is_error());
  ASSERT_TRUE(access.finish({b}, {b}).is_error());

  auto mismatch = make().move_as_ok();
  ASSERT_TRUE(mismatch.record_old_read(a, std::nullopt).is_error());
  ASSERT_TRUE(mismatch.record_old_read(a, hash).is_error());
  ASSERT_TRUE(mismatch.expected_read(b).is_error());
  ASSERT_TRUE(mismatch.finish({b}, {b}).is_error());
  auto false_absence = make().move_as_ok();
  ASSERT_TRUE(false_absence.record_old_read(b, hash).is_error());
  auto premature = make().move_as_ok();
  ASSERT_TRUE(premature.record_write(b).is_error());
  auto unauthorized = make().move_as_ok();
  ASSERT_TRUE(unauthorized.expected_read(hash).is_error());
  ASSERT_TRUE(unauthorized.record_old_read(a, hash).is_error());
  auto read_only = make().move_as_ok();
  ASSERT_TRUE(read_only.record_old_read(a, hash).is_ok());
  ASSERT_TRUE(read_only.record_write(a).is_error());
}

TEST(WorkchainBlock, AccountAccessExactCoverage) {
  auto a = td::Bits256::zero();
  auto b = a;
  b.as_slice().back() = 1;
  auto make = [&] {
    return block::WorkchainAccountAccess::create({{a, a}, {b, b}}, {b}, 2, 1).move_as_ok();
  };
  for (int mode = 0; mode < 6; ++mode) {
    auto access = make();
    if (mode != 0) ASSERT_TRUE(access.record_old_read(a, a).is_ok());
    ASSERT_TRUE(access.record_old_read(b, b).is_ok());
    if (mode != 1) ASSERT_TRUE(access.record_write(b).is_ok());
    std::vector<td::Bits256> changed = mode == 2 ? std::vector<td::Bits256>{a, b} : std::vector<td::Bits256>{b};
    std::vector<td::Bits256> participants = mode == 3 ? std::vector<td::Bits256>{} : std::vector<td::Bits256>{b};
    if (mode == 4) participants.push_back(b);
    if (mode == 5) changed.clear();
    ASSERT_TRUE(access.finish(changed, participants).is_error());
  }
  ASSERT_TRUE(block::WorkchainAccountAccess::create({{a, a}, {a, a}}, {}, 2, 0).is_error());
  ASSERT_TRUE(block::WorkchainAccountAccess::create({{b, b}, {a, a}}, {}, 2, 0).is_error());
  ASSERT_TRUE(block::WorkchainAccountAccess::create({{a, a}}, {a, a}, 1, 2).is_error());
  ASSERT_TRUE(block::WorkchainAccountAccess::create({{a, a}}, {b}, 1, 1).is_error());
  ASSERT_TRUE(block::WorkchainAccountAccess::create({{a, a}}, {}, 0, 0).is_error());
  ASSERT_TRUE(block::WorkchainAccountAccess::create({{a, a}}, {a}, 1, 0).is_error());
}

TEST(WorkchainBlock, ParticipantLtPlan) {
  auto a = td::Bits256::zero();
  auto b = a;
  b.as_slice().back() = 1;
  std::vector<block::WorkchainParticipantTiming> input{{a, 90, 2}, {b, 120, 0}};
  auto result = block::plan_workchain_participant_lts(100, input, 2, 2);
  ASSERT_TRUE(result.is_ok());
  auto plan = result.move_as_ok();
  ASSERT_EQ(plan.start_lt, 121u);
  ASSERT_EQ(plan.end_lt, 124u);
  ASSERT_EQ(plan.participants.size(), 2u);
  ASSERT_EQ(plan.participants[0].message_lt(0).move_as_ok(), 122u);
  ASSERT_EQ(plan.participants[0].message_lt(1).move_as_ok(), 123u);
  ASSERT_TRUE(plan.participants[0].message_lt(2).is_error());
  ASSERT_EQ(plan.participants[1].end_lt, 122u);
  ASSERT_TRUE(plan.participants[1].message_lt(0).is_error());
  ASSERT_TRUE(block::plan_workchain_participant_lts(100, input, 1, 2).is_error());
  ASSERT_TRUE(block::plan_workchain_participant_lts(100, input, 2, 1).is_error());
  input[1].account = a;
  ASSERT_TRUE(block::plan_workchain_participant_lts(100, input, 2, 2).is_error());
  input[0].account = b;
  ASSERT_TRUE(block::plan_workchain_participant_lts(100, input, 2, 2).is_error());
}

TEST(WorkchainBlock, ParticipantLtExhaustion) {
  const auto max = std::numeric_limits<std::uint64_t>::max();
  auto a = td::Bits256::zero();
  std::vector<block::WorkchainParticipantTiming> input{{a, 0, 0}};
  auto boundary = block::plan_workchain_participant_lts(max - 2, input, 1, 0);
  ASSERT_TRUE(boundary.is_ok());
  ASSERT_EQ(boundary.ok().start_lt, max - 1);
  ASSERT_EQ(boundary.ok().end_lt, max);
  ASSERT_TRUE(block::plan_workchain_participant_lts(max - 1, input, 1, 0).is_error());
  input[0].outbound_count = 1;
  ASSERT_TRUE(block::plan_workchain_participant_lts(max - 2, input, 1, 1).is_error());
  input[0].outbound_count = max;
  ASSERT_TRUE(block::plan_workchain_participant_lts(0, input, 1, max).is_error());
  ASSERT_TRUE(block::plan_workchain_participant_lts(0, {}, 1, 0).is_error());
}

class PreflightObservedCell final : public vm::Cell {
 public:
  PreflightObservedCell(td::Ref<vm::Cell> cell, unsigned* loads, bool unavailable = false, unsigned throw_at = 0)
      : cell_(std::move(cell)), loads_(loads), unavailable_(unavailable), throw_at_(throw_at) {
  }
  td::Status set_data_cell(td::Ref<vm::DataCell>&& cell) const override {
    return cell_->set_data_cell(std::move(cell));
  }
  td::Result<LoadedCell> load_cell() const override {
    ++*loads_;
    if (*loads_ == throw_at_) throw vm::VmVirtError{1};
    if (unavailable_) return td::Status::Error("test input unavailable");
    return cell_->load_cell();
  }
  bool is_virtualized() const override { return cell_->is_virtualized(); }
  vm::CellUsageTree::NodePtr get_tree_node() const override { return {}; }
  bool is_loaded() const override { return !unavailable_; }
  LevelMask get_level_mask() const override { return cell_->get_level_mask(); }

 private:
  const Hash do_get_hash(td::uint32 level) const override { return cell_->get_hash(level); }
  td::uint16 do_get_depth(td::uint32 level) const override { return cell_->get_depth(level); }
  td::Ref<vm::Cell> cell_;
  unsigned* loads_;
  bool unavailable_;
  unsigned throw_at_;
};

td::Ref<vm::Cell> number(std::uint64_t value) {
  return vm::CellBuilder().store_long(value, 64).finalize();
}

using CounterEngine = block::test::CounterEngine;

std::unique_ptr<block::Config> block_configuration(int version = block::kBlockTransitionMinGlobalVersion,
                                                 td::uint64 capabilities = tos::capBlockTransition,
                                                 td::uint64 vm_mode = 0, bool include_ingress = true) {
  vm::CellBuilder param;
  CHECK(block::gen::t_GlobalVersion.pack_capabilities(param, version, capabilities));
  vm::Dictionary config(32);
  CHECK(config.set_ref(td::BitArray<32>(8u), param.finalize()));
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.vm_mode = vm_mode;
  policy.executor_address.set_zero();
  policy.engine_configuration = vm::CellBuilder().finalize();
  if (include_ingress) {
    CHECK(config.set_ref(td::BitArray<32>(84u), block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
  }
  return block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
                                     block::Config::needCapabilities).move_as_ok();
}

td::Ref<vm::Cell> shard_fixture(int shard_wc = 2, int account_wc = 2, bool active = true,
                              unsigned account_count = 1, bool before_split = false, unsigned prefix_bits = 0,
                              std::uint64_t counter_value = 40, bool wrong_dictionary_key = false,
                              std::uint64_t operating_balance = 0, td::Ref<vm::Cell> payload = {},
                              td::Ref<vm::Cell> engine_override = {}) {
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  for (unsigned i = 0; i < account_count; ++i) {
    td::Bits256 address = td::Bits256::zero();
    if (i != 0) address = number(i)->get_hash().bits();
    vm::CellBuilder account;
    account.store_long(1, 1).store_long(4, 3).store_long(account_wc, 8).store_bits(address.bits(), 256)
        .store_zeroes(42).store_long(2, 64);
    ASSERT_TRUE(block::CurrencyCollection(td::make_refint(operating_balance)).store(account));
    if (active) {
      vm::CellBuilder engine;
      engine.store_long(counter_value, 64);
      if (payload.not_null()) engine.store_ref(payload);
      auto executor = block::encode_workchain_executor_state(
          {engine_override.not_null() ? engine_override : engine.finalize(), {}, {}}).move_as_ok();
      account.store_long(1, 1).store_zeroes(3).store_long(1, 1).store_ref(executor).store_long(0, 1);
    } else {
      account.store_long(0, 2);
    }
    auto root = account.finalize();
    ASSERT_TRUE(block::gen::t_Account.validate_ref(10000, root));
    vm::CellBuilder entry;
    entry.store_ref(root).store_zeroes(256).store_long(1, 64);
    auto dictionary_address = address;
    if (wrong_dictionary_key) dictionary_address = number(99)->get_hash().bits();
    ASSERT_TRUE(accounts.set_builder(dictionary_address, entry));
  }
  auto queue = vm::CellBuilder().store_zeroes(67).finalize();
  block::CurrencyCollection total_balance(0);
  for (unsigned i = 0; i < account_count; ++i) {
    block::CurrencyCollection next;
    ASSERT_TRUE(block::CurrencyCollection::add(total_balance,
        block::CurrencyCollection(td::make_refint(operating_balance)), next));
    total_balance = std::move(next);
  }
  vm::CellBuilder aux_builder;
  aux_builder.store_zeroes(128);
  ASSERT_TRUE(total_balance.store(aux_builder));
  auto aux = aux_builder.store_zeroes(7).finalize();
  auto root = vm::CellBuilder().store_long(0x9023afe2, 32).store_long(1, 32)
      .store_long(0, 2).store_long(prefix_bits, 6).store_long(shard_wc, 32).store_long(0, 64)
      .store_long(1, 32).store_long(0, 32).store_long(1, 32).store_long(2, 64).store_long(0, 32)
      .store_ref(queue).store_long(before_split, 1).store_ref(accounts.get_wrapped_dict_root())
      .store_ref(aux).store_long(0, 1).finalize();
  ASSERT_TRUE(block::gen::t_ShardStateUnsplit.validate_ref(10000, root));
  return root;
}

TEST(WorkchainBlock, AccountDictionaryChanges) {
  auto extract = [](td::Ref<vm::Cell> root) {
    block::gen::ShardStateUnsplit::Record state;
    CHECK(tlb::unpack_cell(root, state));
    return state.accounts;
  };
  auto root = extract(shard_fixture(2, 2, true, 2));
  vm::AugmentedDictionary updated(vm::load_cell_slice_ref(root), 256, block::tlb::aug_ShardAccounts);
  auto replacement = extract(shard_fixture(2, 2, true, 1, false, 0, 41));
  vm::AugmentedDictionary one(vm::load_cell_slice_ref(replacement), 256, block::tlb::aug_ShardAccounts);
  auto a = td::Bits256::zero();
  td::Bits256 b(number(1)->get_hash().bits());
  ASSERT_TRUE(updated.set(a, one.lookup(a)));
  block::WorkchainAccountDictionary old_state(root);
  block::WorkchainAccountDictionary new_state(updated.get_wrapped_dict_root());
  auto delta = old_state.changed_accounts(new_state, 1);
  ASSERT_TRUE(delta.is_ok());
  ASSERT_EQ(delta.ok().size(), 1u);
  ASSERT_TRUE(delta.ok()[0] == a);
  vm::AugmentedDictionary old_raw(vm::load_cell_slice_ref(root), 256, block::tlb::aug_ShardAccounts);
  block::tlb::ShardAccount::Record old_entry;
  ASSERT_TRUE(old_entry.unpack(old_raw.lookup(a)));
  auto make_access = [&] {
    return block::WorkchainAccountAccess::create(
        {{a, td::Bits256(old_entry.account->get_hash().bits())}}, {a}, 1, 1).move_as_ok();
  };
  auto access = make_access();
  ASSERT_TRUE(old_state.verify_old_read(access, a).is_ok());
  ASSERT_TRUE(access.record_write(a).is_ok());
  ASSERT_TRUE(access.finish(delta.ok(), {a}).is_ok());
  ASSERT_TRUE(old_state.changed_accounts(new_state, 0).is_error());
  block::WorkchainAccountDictionary identical(root);
  ASSERT_TRUE(old_state.changed_accounts(identical, 0).move_as_ok().empty());
  ASSERT_TRUE(updated.lookup_delete(b).not_null());
  block::WorkchainAccountDictionary deleted(updated.get_wrapped_dict_root());
  auto both = old_state.changed_accounts(deleted, 2).move_as_ok();
  ASSERT_EQ(both.size(), 2u);
  ASSERT_TRUE(both[0] == a && both[1] == b);
  auto underdeclared = make_access();
  ASSERT_TRUE(old_state.verify_old_read(underdeclared, a).is_ok());
  ASSERT_TRUE(underdeclared.record_write(a).is_ok());
  ASSERT_TRUE(underdeclared.finish(both, {a}).is_error());
  ASSERT_TRUE(old_state.changed_accounts(deleted, 1).is_error());
  block::WorkchainAccountDictionary inserted(extract(shard_fixture(2, 2, true, 3)));
  auto added = old_state.changed_accounts(inserted, 1).move_as_ok();
  ASSERT_EQ(added.size(), 1u);
  ASSERT_TRUE(added[0] == td::Bits256(number(2)->get_hash().bits()));
  vm::CellBuilder link;
  link.store_ref(old_entry.account).store_ones(256).store_long(2, 64);
  ASSERT_TRUE(old_raw.set_builder(a, link));
  block::WorkchainAccountDictionary link_only(old_raw.get_wrapped_dict_root());
  auto links = old_state.changed_accounts(link_only, 1).move_as_ok();
  ASSERT_EQ(links.size(), 1u);
  ASSERT_TRUE(links[0] == a); // Account hash unchanged; ShardAccount transaction link changed.
}

TEST(WorkchainBlock, AccountDictionaryBinding) {
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(), state));
  auto a = td::Bits256::zero();
  td::Bits256 absent(number(99)->get_hash().bits());
  vm::AugmentedDictionary raw(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::tlb::ShardAccount::Record entry;
  ASSERT_TRUE(entry.unpack(raw.lookup(a)));
  td::Bits256 hash(entry.account->get_hash().bits());
  auto access = block::WorkchainAccountAccess::create({{a, hash}, {absent, std::nullopt}}, {}, 2, 0).move_as_ok();
  block::WorkchainAccountDictionary view(state.accounts);
  ASSERT_TRUE(view.verify_old_read(access, a).is_ok());
  ASSERT_TRUE(view.verify_old_read(access, absent).is_ok());
  ASSERT_TRUE(access.finish({}, {}).is_ok());
  auto false_absence = block::WorkchainAccountAccess::create({{a, std::nullopt}}, {}, 1, 0).move_as_ok();
  ASSERT_TRUE(view.verify_old_read(false_absence, a).is_error());
  auto wrong_hash = block::WorkchainAccountAccess::create({{a, absent}}, {}, 1, 0).move_as_ok();
  ASSERT_TRUE(view.verify_old_read(wrong_hash, a).is_error());
}

block::WorkchainBlockInput input() {
  return {shard_fixture(), number(2), number(1), number(1)};
}

td::Ref<vm::Cell> inbound_envelope(std::uint64_t lt, std::uint64_t nonce = 0,
                                  td::optional<tos::LogicalTime> emitted = {},
                                  const td::Bits256& destination = td::Bits256::zero(),
                                  const block::CurrencyCollection& value = block::CurrencyCollection(100)) {
  vm::CellBuilder cb;
  cb.store_long(4, 4).store_long(4, 3).store_long(0, 8).store_zeroes(255).store_long(1, 1)
      .store_long(4, 3).store_long(2, 8).store_bits(destination.bits(), 256);
  ASSERT_TRUE(value.store(cb));
  cb.store_long(0, 4).store_long(1, 4).store_long(67, 8).store_long(lt, 64)
      .store_long(1, 32).store_zeroes(2).store_long(nonce, 64);
  auto message = cb.finalize();
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(4096, message));
  block::tlb::MsgEnvelope::Record_std record{0x60, 0x60, td::make_refint(67), message, emitted, {}};
  td::Ref<vm::Cell> envelope;
  ASSERT_TRUE(tlb::pack_cell(envelope, record));
  return envelope;
}

TEST(WorkchainBlock, NativeInboxPlan) {
  auto a = td::Bits256::zero();
  td::Bits256 b(number(1)->get_hash().bits());
  auto empty = block::plan_workchain_native_inbox({}, 2, {a, b}, 17, 0).move_as_ok();
  ASSERT_TRUE(empty.envelopes.empty());
  ASSERT_EQ(empty.after_lt, 17u);
  auto first = inbound_envelope(30, 1, {}, a);
  auto second = inbound_envelope(5, 2, 40, b);
  auto encoded = block::encode_workchain_batch_inbound({second, first}).move_as_ok();
  auto plan = block::plan_workchain_native_inbox(encoded, 2, {a, b}, 3, 2).move_as_ok();
  ASSERT_EQ(plan.envelopes.size(), 2u);
  ASSERT_TRUE(plan.envelopes[0]->get_hash() == first->get_hash());
  ASSERT_TRUE(plan.envelopes[1]->get_hash() == second->get_hash());
  ASSERT_EQ(plan.after_lt, 40u);
  block::tlb::MsgEnvelope::Record_std special_envelope;
  block::gen::Message::Record special_message;
  ASSERT_TRUE(tlb::unpack_cell(first, special_envelope));
  ASSERT_TRUE(tlb::type_unpack_cell(special_envelope.msg, block::gen::t_Message_Any, special_message));
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  // A referenced Any body itself must be ordinary under Native TL-B checks;
  // its opaque children need not satisfy the ordinary-only candidate profile.
  auto opaque_body = vm::CellBuilder().store_ref(library).finalize();
  special_message.body = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(opaque_body).finalize());
  ASSERT_TRUE(tlb::type_pack_cell(special_envelope.msg, block::gen::t_Message_Any, special_message));
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(4096, special_envelope.msg));
  td::Ref<vm::Cell> special_root;
  ASSERT_TRUE(tlb::pack_cell(special_root, special_envelope));
  auto special_inbox = block::encode_workchain_batch_inbound({special_root}).move_as_ok();
  auto native_body = block::plan_workchain_native_inbox(special_inbox, 2, {a}, 3, 1).move_as_ok();
  ASSERT_TRUE(native_body.envelopes[0]->get_hash() == special_root->get_hash());
  auto created = block::encode_workchain_batch_inbound({first}).move_as_ok();
  ASSERT_EQ(block::plan_workchain_native_inbox(created, 2, {a}, 3, 1).move_as_ok().after_lt, 30u);
  ASSERT_EQ(block::plan_workchain_native_inbox(encoded, 2, {a, b}, 41, 2).move_as_ok().after_lt, 41u);
  ASSERT_TRUE(block::plan_workchain_native_inbox(encoded, 2, {a}, 3, 2).is_error());
  ASSERT_TRUE(block::plan_workchain_native_inbox(encoded, 0, {a, b}, 3, 2).is_error());
  block::tlb::MsgEnvelope::Record_std anycast_envelope;
  block::gen::Message::Record anycast_message;
  block::gen::CommonMsgInfo::Record_int_msg_info anycast_info;
  block::gen::MsgAddressInt::Record_addr_std anycast_destination;
  ASSERT_TRUE(tlb::unpack_cell(first, anycast_envelope));
  ASSERT_TRUE(tlb::type_unpack_cell(anycast_envelope.msg, block::gen::t_Message_Any, anycast_message));
  ASSERT_TRUE(tlb::csr_unpack(anycast_message.info, anycast_info));
  ASSERT_TRUE(tlb::csr_unpack(anycast_info.dest, anycast_destination));
  anycast_destination.anycast = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1)
      .store_long(1, 5).store_long(0, 1).finalize());
  ASSERT_TRUE(tlb::csr_pack(anycast_info.dest, anycast_destination));
  ASSERT_TRUE(tlb::csr_pack(anycast_message.info, anycast_info));
  ASSERT_TRUE(tlb::type_pack_cell(anycast_envelope.msg, block::gen::t_Message_Any, anycast_message));
  td::Ref<vm::Cell> anycast_root;
  ASSERT_TRUE(tlb::pack_cell(anycast_root, anycast_envelope));
  auto anycast_inbox = block::encode_workchain_batch_inbound({anycast_root}).move_as_ok();
  ASSERT_TRUE(block::plan_workchain_native_inbox(anycast_inbox, 2, {a}, 3, 1).is_error());
  ASSERT_TRUE(block::plan_workchain_native_inbox({}, 2, {b, a}, 3, 0).is_error());
  ASSERT_TRUE(block::plan_workchain_native_inbox({}, 2, {a, a}, 3, 0).is_error());
  ASSERT_TRUE(block::plan_workchain_native_inbox({}, 2, {}, 3, 0).is_error());
  ASSERT_TRUE(block::plan_workchain_native_inbox({}, -1, {a}, 3, 0).is_error());
  // The count is rejected before the dictionary child is loaded.
  unsigned loads = 0;
  auto header = vm::load_cell_slice(encoded);
  auto observed = td::make_ref<PreflightObservedCell>(header.prefetch_ref(), &loads);
  auto bounded = vm::CellBuilder().store_long(0x57494e31, 32).store_long(2, 15)
      .store_long(1, 1).store_ref(observed).finalize();
  loads = 0;
  ASSERT_TRUE(block::plan_workchain_native_inbox(bounded, 2, {a, b}, 3, 1).is_error());
  ASSERT_EQ(loads, 0u);
}

TEST(WorkchainBlock, NativeTransferEffects) {
  auto a = td::Bits256::zero();
  td::Bits256 b(number(1)->get_hash().bits());
  block::WorkchainAccountEffects effects;
  effects.updates = {{a, number(21)}, {b, number(22)}};
  effects.native_transfers = {{a, b, block::CurrencyCollection(137)}, {b, a, block::CurrencyCollection(5)}};
  auto encode = [&](const auto& value, std::uint64_t limit = 2) {
    return block::encode_workchain_account_effects(value, 2, limit, 4096);
  };
  auto result = encode(effects);
  ASSERT_TRUE(result.is_ok());
  ASSERT_TRUE(block::gen::t_UnoV2HostEffects.validate_ref(4096, result.ok()));
  block::gen::UnoV2HostEffects::Record decoded;
  ASSERT_TRUE(tlb::unpack_cell(result.ok(), decoded));
  block::gen::UnoV2NativeEffects::Record native;
  ASSERT_TRUE(tlb::unpack_cell(decoded.native, native));
  vm::Dictionary transfers(native.transfers, 32);
  unsigned count = 0;
  ASSERT_TRUE(transfers.check_for_each([&](td::Ref<vm::CellSlice> cell, td::ConstBitPtr key, int width) {
    ASSERT_EQ(width, 32);
    ASSERT_EQ(key.get_uint(32), count);
    block::gen::UnoV2NativeTransfer::Record record;
    ASSERT_TRUE(tlb::unpack_cell(cell->prefetch_ref(), record));
    ASSERT_TRUE(record.source == (count == 0 ? a : b));
    ASSERT_TRUE(record.destination == (count == 0 ? b : a));
    block::CurrencyCollection value;
    ASSERT_TRUE(value.unpack(record.value));
    ASSERT_TRUE(value == block::CurrencyCollection(count == 0 ? 137 : 5));
    ASSERT_TRUE(count < 2);
    ++count;
    return true;
  }));
  ASSERT_EQ(count, 2u);
  ASSERT_TRUE(encode(effects, 1).is_error());
  auto wrong = effects;
  wrong.native_transfers[0].to = a;
  ASSERT_TRUE(encode(wrong).is_error());
  wrong = effects;
  std::swap(wrong.native_transfers[0], wrong.native_transfers[1]);
  ASSERT_TRUE(encode(wrong).is_error());
  wrong = effects;
  wrong.native_transfers[1] = wrong.native_transfers[0];
  ASSERT_TRUE(encode(wrong).is_error());
  wrong = effects;
  wrong.native_transfers[0].value = block::CurrencyCollection(0);
  ASSERT_TRUE(encode(wrong).is_error());
  wrong = effects;
  wrong.native_transfers[0].value = block::CurrencyCollection(-1);
  ASSERT_TRUE(encode(wrong).is_error());
  wrong = effects;
  wrong.updates.pop_back();
  ASSERT_TRUE(encode(wrong).is_error());
  wrong = effects;
  wrong.native_transfers[0].value = block::CurrencyCollection(td::make_refint(1) << 120);
  ASSERT_TRUE(encode(wrong).is_error());
}

TEST(WorkchainBlock, NativeAllocation) {
  using C = block::CurrencyCollection;
  auto a = td::Bits256::zero();
  td::Bits256 b(number(1)->get_hash().bits()), absent(number(2)->get_hash().bits());
  block::WorkchainAccountEffects output;
  output.updates = {{a, number(1)}, {b, number(2)}};
  auto base = block::encode_workchain_account_effects(output, 2, 2, 4096).move_as_ok();
  block::gen::UnoV2HostEffects::Record effects;
  ASSERT_TRUE(tlb::unpack_cell(base, effects));
  // Bypass the encoder's semantic guards with valid generated TL-B, so each
  // decoder guard is independently exercised rather than masked upstream.
  auto encode = [&](const std::vector<block::WorkchainInternalTransfer>& edges, bool hole = false) {
    vm::Dictionary transfers(32);
    std::uint32_t index = hole ? 1 : 0;
    for (const auto& edge : edges) {
      block::gen::UnoV2NativeTransfer::Record record;
      record.source = edge.from; record.destination = edge.to;
      ASSERT_TRUE(edge.value.pack_to(record.value));
      td::Ref<vm::Cell> root;
      ASSERT_TRUE(tlb::pack_cell(root, record));
      ASSERT_TRUE(transfers.set_ref(td::BitArray<32>(index), root, vm::Dictionary::SetMode::Add));
      ASSERT_TRUE(index < UINT32_MAX);
      ++index;
    }
    vm::CellBuilder native;
    native.store_long(0x0bd47725, 32).store_zeroes(1);
    ASSERT_TRUE(transfers.append_dict_to_bool(native));
    auto changed = effects;
    changed.native = native.finalize();
    ASSERT_TRUE(block::gen::t_UnoV2NativeEffects.validate_ref(4096, changed.native));
    return changed;
  };
  auto normal = encode({{a, b, C(137)}, {b, a, C(10)}});
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(1200), normal, 2, 4096).move_as_ok() == C(1073));
  ASSERT_TRUE(block::allocate_workchain_native_balance(b, C(1100), normal, 2, 4096).move_as_ok() == C(1227));
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(1200), normal, 1, 4096).is_error());
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(1200), effects, 0, 4096).move_as_ok() == C(1200));
  // The public decoder is also tested below the generated structural validator:
  // a leaf with a valid record reference plus trailing bits is noncanonical.
  auto malformed = effects;
  malformed.native = number(123);
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(1200), malformed, 2, 4096).is_error());
  block::gen::UnoV2NativeEffects::Record native;
  ASSERT_TRUE(tlb::unpack_cell(normal.native, native));
  vm::Dictionary trailing(native.transfers, 32);
  auto key = td::BitArray<32>::zero();
  vm::CellBuilder bad_leaf;
  bad_leaf.store_ref(trailing.lookup_ref(key)).store_zeroes(1);
  ASSERT_TRUE(trailing.set_builder(key, bad_leaf, vm::Dictionary::SetMode::Replace));
  vm::CellBuilder bad_native;
  bad_native.store_long(0x0bd47725, 32).store_zeroes(1);
  ASSERT_TRUE(trailing.append_dict_to_bool(bad_native));
  malformed.native = bad_native.finalize();
  ASSERT_TRUE(!block::gen::t_UnoV2NativeEffects.validate_ref(4096, malformed.native));
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(1200), malformed, 2, 4096).is_error());
  for (const auto& invalid : {encode({{a, a, C(1)}}), encode({{a, b, C(0)}}),
      encode({{b, a, C(1)}, {a, b, C(1)}}), encode({{a, b, C(1)}, {a, b, C(1)}}),
      encode({{a, absent, C(1)}}), encode({{a, b, C(1)}}, true)}) {
    ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(1200), invalid, 2, 4096).is_error());
  }
  ASSERT_TRUE(block::allocate_workchain_native_balance(absent, C(0), normal, 2, 4096).is_error());
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(-1), normal, 2, 4096).is_error());
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(1200), normal, 2, 0).is_error());
  auto incoming = encode({{b, a, C(1)}});
  auto wide = td::make_refint(1) << 120;
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(wide), effects, 2, 4096).is_error());
  C max;
  ASSERT_TRUE(C::sub(C(td::make_refint(1) << 256), C(1), max));
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, max, incoming, 2, 4096).is_error());
  auto extra = [](unsigned amount) {
    vm::Dictionary values(32);
    vm::CellBuilder value;
    ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(value, *td::make_refint(amount)));
    ASSERT_TRUE(values.set_builder(td::BitArray<32>(7u), value, vm::Dictionary::SetMode::Add));
    return C(0, values.get_root_cell());
  };
  auto extras = encode({{a, b, extra(5)}, {b, a, extra(7)}});
  ASSERT_TRUE(block::allocate_workchain_native_balance(a, C(0), extras, 2, 4096).move_as_ok() == extra(2));
  ASSERT_TRUE(block::allocate_workchain_native_balance(b, C(0), extras, 2, 4096).is_error());
}

TEST(WorkchainBlock, BatchNativeAllocation) {
  using C = block::CurrencyCollection;
  auto a = td::Bits256::zero(), b = a, c = a, absent = a;
  b.as_slice().back() = 1; c.as_slice().back() = 2; absent.as_slice().back() = 3;
  block::WorkchainAccountEffects output;
  output.updates = {{a, number(1)}, {b, number(2)}, {c, number(3)}};
  auto root = block::encode_workchain_account_effects(output, 3, 0, 4096).move_as_ok();
  block::gen::UnoV2HostEffects::Record base;
  ASSERT_TRUE(tlb::unpack_cell(root, base));
  // Deliberately bypass semantic encoding guards with generated TL-B records.
  auto encode = [&](const std::vector<block::WorkchainInternalTransfer>& edges, bool hole = false) {
    vm::Dictionary transfers(32);
    std::uint32_t index = hole ? 1 : 0;
    for (const auto& edge : edges) {
      block::gen::UnoV2NativeTransfer::Record record;
      record.source = edge.from; record.destination = edge.to;
      ASSERT_TRUE(edge.value.pack_to(record.value));
      td::Ref<vm::Cell> cell;
      ASSERT_TRUE(tlb::pack_cell(cell, record));
      ASSERT_TRUE(transfers.set_ref(td::BitArray<32>(index), cell, vm::Dictionary::SetMode::Add));
      ASSERT_TRUE(index < UINT32_MAX);
      ++index;
    }
    vm::CellBuilder native;
    native.store_long(0x0bd47725, 32).store_zeroes(1);
    ASSERT_TRUE(transfers.append_dict_to_bool(native));
    auto result = base;
    result.native = native.finalize();
    return result;
  };
  auto decode = [&](const auto& effects, unsigned accounts = 3, unsigned transfers = 4, int budget = 4096) {
    return block::plan_workchain_native_allocations(effects, accounts, transfers, budget);
  };
  auto edges = encode({{a, b, C(137)}, {a, c, C(5)}, {b, a, C(10)}, {c, b, C(2)}});
  auto plan = decode(edges).move_as_ok();
  ASSERT_EQ(plan.accounts.size(), 3u);
  ASSERT_EQ(plan.transfers.size(), 4u);
  ASSERT_TRUE(plan.accounts.at(a).incoming == C(10) && plan.accounts.at(a).outgoing == C(142));
  ASSERT_TRUE(plan.accounts.at(b).incoming == C(139) && plan.accounts.at(b).outgoing == C(10));
  ASSERT_TRUE(plan.accounts.at(c).incoming == C(5) && plan.accounts.at(c).outgoing == C(2));
  ASSERT_TRUE(plan.transfers[0].from == a && plan.transfers[0].to == b && plan.transfers[0].value == C(137));
  auto empty = decode(base, 3, 0).move_as_ok();
  ASSERT_TRUE(empty.transfers.empty() && empty.accounts.at(c).incoming.is_zero() && empty.accounts.at(c).outgoing.is_zero());
  ASSERT_TRUE(decode(edges, 2).is_error());
  ASSERT_TRUE(decode(edges, 3, 3).is_error());
  ASSERT_TRUE(decode(edges, 3, 4, 0).is_error());
  unsigned invalid_case = 0;
  for (const auto& invalid : {encode({{a, a, C(1)}}), encode({{a, b, C(0)}}),
      encode({{b, a, C(1)}, {a, b, C(1)}}), encode({{a, b, C(1)}, {a, b, C(1)}}),
      encode({{a, absent, C(1)}}), encode({{a, b, C(1)}}, true)}) {
    LOG(INFO) << "batch allocation rejection case=" << invalid_case;
    ASSERT_TRUE(decode(invalid).is_error());
    ASSERT_TRUE(invalid_case < UINT_MAX);
    ++invalid_case;
  }
  auto extra = [](td::RefInt256 amount) {
    vm::Dictionary values(32);
    vm::CellBuilder value;
    ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(value, *amount));
    ASSERT_TRUE(values.set_builder(td::BitArray<32>(7u), value, vm::Dictionary::SetMode::Add));
    return C(0, values.get_root_cell());
  };
  auto extras = encode({{a, c, extra(td::make_refint(5))}, {b, c, extra(td::make_refint(7))}});
  ASSERT_TRUE(decode(extras).move_as_ok().accounts.at(c).incoming == extra(td::make_refint(12)));
  ASSERT_TRUE(decode(extras, 3, 4, 1).is_error());
  C max;
  ASSERT_TRUE(C::sub(C(td::make_refint(1) << 248), C(1), max));
  auto overflow = encode({{a, c, extra(max.tomis)}, {b, c, extra(td::make_refint(1))}});
  ASSERT_TRUE(decode(overflow).is_error());
  auto malformed = base;
  malformed.native = number(123);
  ASSERT_TRUE(decode(malformed).is_error());
  vm::Dictionary bad_updates(base.updates, 256);
  vm::CellBuilder leaf;
  leaf.store_ref(number(1)).store_zeroes(1);
  ASSERT_TRUE(bad_updates.set_builder(a, leaf, vm::Dictionary::SetMode::Replace));
  malformed = base;
  vm::CellBuilder updates_cell;
  ASSERT_TRUE(bad_updates.append_dict_to_bool(updates_cell));
  malformed.updates = vm::load_cell_slice_ref(updates_cell.finalize());
  ASSERT_TRUE(decode(malformed).is_error());
  vm::Dictionary no_updates(256);
  vm::CellBuilder empty_updates_cell;
  ASSERT_TRUE(no_updates.append_dict_to_bool(empty_updates_cell));
  malformed.updates = vm::load_cell_slice_ref(empty_updates_cell.finalize());
  ASSERT_TRUE(decode(malformed).is_error());
  block::gen::UnoV2NativeEffects::Record native;
  ASSERT_TRUE(tlb::unpack_cell(edges.native, native));
  vm::Dictionary bad_transfers(native.transfers, 32);
  auto zero_key = td::BitArray<32>::zero();
  vm::CellBuilder trailing;
  trailing.store_ref(bad_transfers.lookup_ref(zero_key)).store_zeroes(1);
  ASSERT_TRUE(bad_transfers.set_builder(zero_key, trailing, vm::Dictionary::SetMode::Replace));
  vm::CellBuilder native_cell;
  native_cell.store_long(0x0bd47725, 32).store_zeroes(1);
  ASSERT_TRUE(bad_transfers.append_dict_to_bool(native_cell));
  malformed = base;
  malformed.native = native_cell.finalize();
  ASSERT_TRUE(decode(malformed).is_error());
}

TEST(WorkchainBlock, NativeCoordinatorEntry) {
  auto candidate = number(11);
  auto hash = td::Bits256(candidate->get_hash().bits());
  auto a = td::Bits256::zero();
  block::InputPolicyIdentity policy_id{candidate->get_hash(), false, 17, 9, 2, 1};
  auto policy = block::ResolvedInputPolicy::from_resolved_fields({10, 1024, 1}, policy_id);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedInputPolicy>(policy));
  block::CandidateAdmissionSession admission(candidate, std::get<block::ResolvedInputPolicy>(policy));
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(admission.evaluate()));
  const auto& admitted = std::get<block::AdmittedInput>(admission.evaluate());
  block::WorkchainHostIdentity identity{-1, hash, hash, 2, UINT64_MAX, hash, false,
      17, 9, 2, 1, hash, 1, 10, 20, number(1)};
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 2, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account coordinator(2, a.bits());
  ASSERT_TRUE(coordinator.unpack(accounts.lookup(a), 10, false));
  block::WorkchainAccountDeclarations access{{{a, td::Bits256(coordinator.total_state->get_hash().bits())}}, {a}};
  std::vector<td::Ref<vm::Cell>> inbox{inbound_envelope(4), inbound_envelope(5),
      inbound_envelope(6, 0, {}, td::Bits256(number(1)->get_hash().bits()))};
  auto input = block::encode_workchain_host_input(identity, admitted, access, inbox, 1, 1, 3).move_as_ok();
  block::WorkchainAccountEffects effects;
  effects.updates.push_back({a, number(321)});
  auto effects_root = block::encode_workchain_account_effects(effects, 1, 0, 4096).move_as_ok();
  auto binding = block::build_workchain_participant_records(td::Bits256(input->get_hash().bits()),
      td::Bits256(effects_root->get_hash().bits()), {a}, 1).move_as_ok()[0];
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = true;
  using Transaction = block::transaction::Transaction;
  Transaction tx(coordinator, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(tx.prepare_workchain_entry(binding, input, effects_root, number(321), cfg, 2, 4096).is_ok());
  ASSERT_TRUE(tx.balance == block::CurrencyCollection(1200));
  ASSERT_TRUE(tx.new_data->get_hash() == number(321)->get_hash());
  ASSERT_TRUE(tx.total_fees.is_zero());
  ASSERT_TRUE(tx.out_msgs.empty());
  ASSERT_TRUE(tx.serialize(cfg));
  block::gen::Transaction::Record record;
  ASSERT_TRUE(tlb::unpack_cell(tx.root, record));
  auto description = vm::load_cell_slice(record.description);
  ASSERT_EQ(description.size(), 4u);
  ASSERT_EQ(description.size_refs(), 3u);
  ASSERT_EQ(description.fetch_ulong(4), 12u);
  ASSERT_TRUE(description.fetch_ref()->get_hash() == binding->get_hash());
  ASSERT_TRUE(description.fetch_ref()->get_hash() == input->get_hash());
  ASSERT_TRUE(description.fetch_ref()->get_hash() == effects_root->get_hash());
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(4096, record.description));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(4096, record.description));
  auto skipped = vm::load_cell_slice(record.description);
  ASSERT_TRUE(block::tlb::t_TransactionDescr.skip(skipped) && skipped.empty_ext());
  auto storage = vm::load_cell_slice(record.description);
  bool found = true;
  ASSERT_TRUE(block::tlb::t_TransactionDescr.skip_to_storage_phase(storage, found));
  ASSERT_TRUE(!found && storage.empty_ext());
  for (auto scope : {block::WorkchainExecutionScope::AccountCompute, block::WorkchainExecutionScope::BlockTransition}) {
    ASSERT_TRUE(block::validate_transaction_execution_scope(record.description, scope).is_error());
  }
  block::gen::Account::Record_account account;
  block::gen::AccountStorage::Record account_storage;
  block::CurrencyCollection balance;
  ASSERT_TRUE(tlb::unpack_cell(tx.new_total_state, account));
  ASSERT_TRUE(tlb::csr_unpack(account.storage, account_storage));
  ASSERT_TRUE(balance.unpack(account_storage.balance));
  ASSERT_TRUE(balance == block::CurrencyCollection(1200));
  ASSERT_TRUE(coordinator.balance == block::CurrencyCollection(1000));
  auto reject = [&](td::Ref<vm::Cell> bad_binding, td::Ref<vm::Cell> data) {
    Transaction rejected(coordinator, Transaction::tr_workchain_batch, 21, 10);
    return rejected.prepare_workchain_entry(bad_binding, input, effects_root, data, cfg, 2, 4096).is_error();
  };
  for (bool wrong_input : {false, true}) {
    auto bad_binding = block::build_workchain_participant_records(
        wrong_input ? hash : td::Bits256(input->get_hash().bits()),
        wrong_input ? td::Bits256(effects_root->get_hash().bits()) : hash, {a}, 1).move_as_ok()[0];
    ASSERT_TRUE(reject(bad_binding, number(321)));
  }
  ASSERT_TRUE(reject(binding, number(322)));
  block::gen::UnoV2HostRecord::Record indexed;
  ASSERT_TRUE(tlb::unpack_cell(binding, indexed));
  indexed.effect_index = 1;
  td::Ref<vm::Cell> wrong_index;
  ASSERT_TRUE(tlb::pack_cell(wrong_index, indexed));
  ASSERT_TRUE(reject(wrong_index, number(321)));
  for (unsigned field = 0; field < 3; ++field) {
    auto wrong = identity;
    if (field == 0) wrong.workchain_id = 0;
    if (field == 1) wrong.gen_utime = 11;
    if (field == 2) wrong.host_after_lt = 21;
    auto changed_input = block::encode_workchain_host_input(wrong, admitted, access, inbox, 1, 1, 3).move_as_ok();
    auto changed_binding = block::build_workchain_participant_records(td::Bits256(changed_input->get_hash().bits()),
        td::Bits256(effects_root->get_hash().bits()), {a}, 1).move_as_ok()[0];
    Transaction rejected(coordinator, Transaction::tr_workchain_batch, 21, 10);
    ASSERT_TRUE(rejected.prepare_workchain_entry(changed_binding, changed_input, effects_root, number(321), cfg, 2, 4096).is_error());
  }
  // The entry need not be the first account in canonical key order.
  td::Bits256 b(number(1)->get_hash().bits());
  block::Account second(2, b.bits());
  ASSERT_TRUE(second.unpack(accounts.lookup(b), 10, false));
  auto two = access;
  two.reads.push_back({b, td::Bits256(second.total_state->get_hash().bits())});
  two.writes.push_back(b);
  auto two_input = block::encode_workchain_host_input(identity, admitted, two, inbox, 2, 2, 3).move_as_ok();
  auto two_effects = effects;
  two_effects.updates.push_back({b, number(321)});
  auto two_root = block::encode_workchain_account_effects(two_effects, 2, 0, 4096).move_as_ok();
  auto two_binding = block::build_workchain_participant_records(td::Bits256(two_input->get_hash().bits()),
      td::Bits256(two_root->get_hash().bits()), {a, b}, 2).move_as_ok()[1];
  Transaction second_tx(second, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(second_tx.prepare_workchain_entry(two_binding, two_input, two_root, number(321), cfg, 2, 4096).is_ok());
  ASSERT_TRUE(second_tx.balance == block::CurrencyCollection(1100));

  // One complete entry and one importing participant, with the same context.
  auto import_effects = two_effects;
  import_effects.native_transfers = {{a, b, block::CurrencyCollection(137)}, {b, a, block::CurrencyCollection(10)}};
  auto import_root = block::encode_workchain_account_effects(import_effects, 2, 2, 4096).move_as_ok();
  auto import_bindings = block::build_workchain_participant_records(td::Bits256(two_input->get_hash().bits()),
      td::Bits256(import_root->get_hash().bits()), {a, b}, 2).move_as_ok();
  Transaction importing_entry(coordinator, Transaction::tr_workchain_batch, 21, 10);
  Transaction importing_record(second, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(importing_entry.prepare_workchain_entry(import_bindings[0], two_input, import_root,
      number(321), cfg, 2, 4096).is_ok());
  ASSERT_TRUE(importing_record.prepare_workchain_import_participant(import_bindings[1], two_input, import_root,
      number(321), cfg, 2, 4096).is_ok());
  ASSERT_TRUE(importing_record.balance == block::CurrencyCollection(1227));
  ASSERT_TRUE(importing_entry.balance == block::CurrencyCollection(1073));
  ASSERT_TRUE(importing_entry.serialize(cfg) && importing_record.serialize(cfg));
  ASSERT_TRUE(!importing_record.storage_phase && !importing_record.compute_phase &&
      !importing_record.action_phase && !importing_record.bounce_phase);
  ASSERT_TRUE(importing_record.out_msgs.empty() && importing_record.total_fees.is_zero());
  for (unsigned field = 0; field < 12; ++field) {
    LOG(INFO) << "import participant rejection case=" << field;
    auto rejected_identity = identity;
    auto rejected_access = two;
    auto rejected_data = number(321);
    if (field == 3) rejected_data = number(322);
    if (field == 4) rejected_identity.workchain_id = 0;
    if (field == 5) rejected_identity.gen_utime = 11;
    if (field == 6) rejected_identity.host_after_lt = 21;
    if (field == 7) rejected_access.reads[1].old_account_hash = hash;
    if (field == 8) rejected_access.writes.pop_back();
    if (field == 9) {
      rejected_access.reads.push_back({hash, std::nullopt});
      rejected_access.writes.push_back(hash);
      std::sort(rejected_access.reads.begin(), rejected_access.reads.end(),
          [](const auto& lhs, const auto& rhs) { return lhs.account < rhs.account; });
      std::sort(rejected_access.writes.begin(), rejected_access.writes.end());
    }
    auto rejected_input = block::encode_workchain_host_input(rejected_identity, admitted,
        rejected_access, inbox, 3, 3, 3).move_as_ok();
    auto rejected_binding = block::build_workchain_participant_records(
        field == 0 ? hash : td::Bits256(rejected_input->get_hash().bits()),
        field == 1 ? hash : td::Bits256(import_root->get_hash().bits()), {a, b}, 2).move_as_ok()[1];
    if (field == 2) {
      block::gen::UnoV2HostRecord::Record bad_index;
      ASSERT_TRUE(tlb::unpack_cell(rejected_binding, bad_index));
      bad_index.effect_index = 0;
      ASSERT_TRUE(tlb::pack_cell(rejected_binding, bad_index));
    }
    Transaction rejected(second, Transaction::tr_workchain_batch, 21, 10);
    ASSERT_TRUE(rejected.prepare_workchain_import_participant(rejected_binding, rejected_input,
        import_root, rejected_data, cfg, field == 10 ? 1 : 2, field == 11 ? 0 : 4096).is_error());
    ASSERT_TRUE(rejected.root.is_null() && rejected.new_total_state.is_null());
    ASSERT_TRUE(second.balance == block::CurrencyCollection(1000));
  }
  block::gen::Transaction::Record imported_tx;
  ASSERT_TRUE(tlb::unpack_cell(importing_record.root, imported_tx));
  auto imported_description = vm::load_cell_slice(imported_tx.description);
  ASSERT_EQ(imported_description.fetch_ulong(4), 11u);
  ASSERT_TRUE(imported_description.fetch_ref()->get_hash() == import_bindings[1]->get_hash());
  ASSERT_TRUE(imported_description.empty_ext());
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(4096, importing_record.root));
  ASSERT_TRUE(block::tlb::t_Transaction.validate_ref(4096, importing_record.root));
  block::tlb::MsgEnvelope::Record_std unexpected_direct_import;
  ASSERT_TRUE(tlb::unpack_cell(inbox[2], unexpected_direct_import));
  importing_record.in_msg = unexpected_direct_import.msg;
  ASSERT_TRUE(!importing_record.serialize(cfg));
  importing_record.in_msg.clear();
  ASSERT_TRUE(importing_record.serialize(cfg));
  std::map<td::Bits256, td::Ref<vm::Cell>> import_transactions{{a, importing_entry.root}, {b, importing_record.root}};
  auto import_evidence = block::build_workchain_final_imports(2, 16, inbox, import_transactions,
      3, 2, 4096).move_as_ok();
  ASSERT_TRUE(import_evidence.account_credits.at(a) == block::CurrencyCollection(200));
  ASSERT_TRUE(import_evidence.account_credits.at(b) == block::CurrencyCollection(100));
  ASSERT_TRUE(import_evidence.value_imported == block::CurrencyCollection(501));
  ASSERT_TRUE(import_evidence.fees_collected == block::CurrencyCollection(201));
  std::vector<block::WorkchainAccountValueFlow> imported_rows;
  for (const auto* built : {&importing_entry, &importing_record}) {
    block::gen::Account::Record_account old_account, new_account;
    block::gen::AccountStorage::Record old_storage, new_storage;
    block::gen::Transaction::Record native_tx;
    block::CurrencyCollection before, after, fees;
    ASSERT_TRUE(tlb::unpack_cell(built->account.total_state, old_account));
    ASSERT_TRUE(tlb::unpack_cell(built->new_total_state, new_account));
    ASSERT_TRUE(tlb::csr_unpack(old_account.storage, old_storage) && tlb::csr_unpack(new_account.storage, new_storage));
    ASSERT_TRUE(tlb::unpack_cell(built->root, native_tx));
    ASSERT_TRUE(before.unpack(old_storage.balance) && after.unpack(new_storage.balance) && fees.unpack(native_tx.total_fees));
    ASSERT_TRUE(native_tx.r1.in_msg->prefetch_ulong(1) == 0);
    ASSERT_TRUE(native_tx.r1.out_msgs->prefetch_ulong(1) == 0 && native_tx.outmsg_cnt == 0);
    imported_rows.push_back({native_tx.account_addr, before, import_evidence.account_credits.at(native_tx.account_addr),
                            after, block::CurrencyCollection(0), fees});
  }
  ASSERT_TRUE(block::verify_workchain_value_flow(imported_rows, import_effects.native_transfers, 2, 2, 4096).is_ok());
  for (unsigned field = 0; field < 3; ++field) {
    auto wrong_rows = imported_rows;
    if (field < 2) wrong_rows[field].imported = block::CurrencyCollection(0);
    else std::swap(wrong_rows[0].imported, wrong_rows[1].imported);
    ASSERT_TRUE(block::verify_workchain_value_flow(wrong_rows, import_effects.native_transfers, 2, 2, 4096).is_error());
  }
  ASSERT_TRUE(coordinator.balance == block::CurrencyCollection(1000) && second.balance == block::CurrencyCollection(1000));

  // One entry plus one restricted allocation record, sharing a batch binding.
  // Unlike the isolated entry-role fixtures, the second record imports no
  // message and stores only its binding, never the full input/effects closure.
  auto pair_input = block::encode_workchain_host_input(identity, admitted, two,
      {inbox[0], inbox[1]}, 2, 2, 3).move_as_ok();
  auto pair_effects = two_effects;
  pair_effects.native_transfers = {{a, b, block::CurrencyCollection(137)}, {b, a, block::CurrencyCollection(10)}};
  auto pair_root = block::encode_workchain_account_effects(pair_effects, 2, 2, 4096).move_as_ok();
  auto pair_bindings = block::build_workchain_participant_records(td::Bits256(pair_input->get_hash().bits()),
      td::Bits256(pair_root->get_hash().bits()), {a, b}, 2).move_as_ok();
  Transaction paired_entry(coordinator, Transaction::tr_workchain_batch, 21, 10);
  Transaction participant(second, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(paired_entry.prepare_workchain_entry(pair_bindings[0], pair_input, pair_root,
      number(321), cfg, 2, 4096).is_ok());
  ASSERT_TRUE(participant.prepare_workchain_allocation_participant(pair_bindings[1], number(321),
      block::CurrencyCollection(137), block::CurrencyCollection(10), cfg, 4096).is_ok());
  ASSERT_TRUE(paired_entry.serialize(cfg) && participant.serialize(cfg));
  ASSERT_TRUE(participant.balance == block::CurrencyCollection(1127));
  std::map<td::Bits256, td::Ref<vm::Cell>> processing{{a, paired_entry.root}, {b, participant.root}};
  auto imports = block::build_workchain_final_imports(2, 16, {inbox[0], inbox[1]}, processing,
      2, 2, 4096).move_as_ok();
  ASSERT_TRUE(imports.account_credits.at(a) == block::CurrencyCollection(200));
  ASSERT_TRUE(imports.account_credits.find(b) == imports.account_credits.end());
  ASSERT_TRUE(imports.value_imported == block::CurrencyCollection(334));
  ASSERT_TRUE(imports.fees_collected == block::CurrencyCollection(134));
  block::tlb::InMsgDescr native_imports(16);
  ASSERT_TRUE(native_imports.validate_ref(4096, imports.in_msg_descr));
  ASSERT_TRUE(block::gen::t_InMsgDescr.validate_ref(4096, imports.in_msg_descr));
  vm::AugmentedDictionary imported_records(vm::load_cell_slice_ref(imports.in_msg_descr), 256, native_imports.aug);
  for (const auto& envelope_root : {inbox[0], inbox[1]}) {
    block::tlb::MsgEnvelope::Record_std envelope;
    ASSERT_TRUE(tlb::unpack_cell(envelope_root, envelope));
    auto record = imported_records.lookup(envelope.msg->get_hash().bits(), 256);
    ASSERT_TRUE(record.not_null());
    auto decoded_import = *record;
    ASSERT_EQ(decoded_import.fetch_ulong(3), 4u);
    ASSERT_TRUE(decoded_import.fetch_ref()->get_hash() == envelope_root->get_hash());
    ASSERT_TRUE(decoded_import.fetch_ref()->get_hash() == paired_entry.root->get_hash());
  }
  auto no_imports = block::build_workchain_final_imports(2, 16, {}, processing, 0, 2, 4096).move_as_ok();
  ASSERT_TRUE(no_imports.account_credits.empty() && no_imports.value_imported.is_zero() && no_imports.fees_collected.is_zero());
  ASSERT_TRUE(native_imports.validate_ref(4096, no_imports.in_msg_descr));
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {inbox[0], inbox[0]}, processing, 2, 2, 4096).is_error());
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {inbox[0], inbox[1]}, processing, 1, 2, 4096).is_error());
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {inbox[0]}, processing, 2, 1, 4096).is_error());
  ASSERT_TRUE(block::build_workchain_final_imports(2, 15, {inbox[0]}, processing, 2, 2, 4096).is_error());
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {inbox[0]}, processing, 2, 2, 0).is_error());
  auto wrong_processing = processing;
  wrong_processing[a] = participant.root;
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {inbox[0]}, wrong_processing, 2, 2, 4096).is_error());
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {inbound_envelope(21)}, processing, 2, 2, 4096).is_error());
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {inbound_envelope(5, 0, 21)}, processing, 2, 2, 4096).is_error());
  block::tlb::MsgEnvelope::Record_std excessive_fee;
  ASSERT_TRUE(tlb::unpack_cell(inbox[0], excessive_fee));
  excessive_fee.fwd_fee_remaining = td::make_refint(68);
  td::Ref<vm::Cell> excessive_envelope;
  ASSERT_TRUE(tlb::pack_cell(excessive_envelope, excessive_fee));
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {excessive_envelope}, processing, 2, 2, 4096).is_error());
  block::tlb::MsgEnvelope::Record_std zero_fee;
  ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(5, 77, {}, a, block::CurrencyCollection(0)), zero_fee));
  zero_fee.fwd_fee_remaining = td::make_refint(0);
  td::Ref<vm::Cell> zero_envelope;
  ASSERT_TRUE(tlb::pack_cell(zero_envelope, zero_fee));
  // Duplicate rejection must survive when all augmentation amounts are zero;
  // otherwise the aggregate-total check could mask a missing uniqueness guard.
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {zero_envelope, zero_envelope}, processing,
      2, 2, 4096).is_error());
  vm::Dictionary imported_extra_values(32);
  vm::CellBuilder imported_extra_value;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(imported_extra_value, *td::make_refint(5)));
  ASSERT_TRUE(imported_extra_values.set_builder(td::BitArray<32>(7u), imported_extra_value));
  block::CurrencyCollection extra_import_value(100, imported_extra_values.get_root_cell());
  auto extra_import_envelope = inbound_envelope(5, 0, {}, a, extra_import_value);
  // Primitive import accounting only: authorizing a new batch must also bind
  // this changed envelope to its entry input and corresponding state update.
  auto extra_imports = block::build_workchain_final_imports(2, 16, {extra_import_envelope}, processing,
      2, 2, 4096).move_as_ok();
  ASSERT_TRUE(extra_imports.account_credits.at(a) == extra_import_value);
  ASSERT_TRUE(extra_imports.value_imported == block::CurrencyCollection(167, imported_extra_values.get_root_cell()));
  ASSERT_TRUE(extra_imports.fees_collected == block::CurrencyCollection(67));
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, {extra_import_envelope}, processing, 2, 2, 1).is_error());
  std::vector<block::WorkchainAccountValueFlow> rows;
  auto actual_row = [&](const block::Account& before, const Transaction& built,
                        const block::CurrencyCollection& imported) {
    block::gen::Account::Record_account old_account, new_account;
    block::gen::AccountStorage::Record old_storage, new_storage;
    block::gen::Transaction::Record transaction;
    block::CurrencyCollection old_balance, new_balance, fees;
    ASSERT_TRUE(tlb::unpack_cell(before.total_state, old_account));
    ASSERT_TRUE(tlb::unpack_cell(built.new_total_state, new_account));
    ASSERT_TRUE(tlb::csr_unpack(old_account.storage, old_storage));
    ASSERT_TRUE(tlb::csr_unpack(new_account.storage, new_storage));
    ASSERT_TRUE(old_balance.unpack(old_storage.balance) && new_balance.unpack(new_storage.balance));
    ASSERT_TRUE(tlb::unpack_cell(built.root, transaction) && fees.unpack(transaction.total_fees));
    ASSERT_EQ(transaction.outmsg_cnt, 0);
    ASSERT_TRUE(fees.is_zero());
    rows.push_back({before.addr, old_balance, imported,
        new_balance, block::CurrencyCollection(0), fees});
    return transaction.description;
  };
  actual_row(coordinator, paired_entry, imports.account_credits.at(a));
  auto participant_desc = actual_row(second, participant, block::CurrencyCollection(0));
  auto participant_slice = vm::load_cell_slice(participant_desc);
  ASSERT_EQ(participant_slice.size(), 4u);
  ASSERT_EQ(participant_slice.size_refs(), 1u);
  ASSERT_EQ(participant_slice.fetch_ulong(4), 11u);
  ASSERT_TRUE(participant_slice.fetch_ref()->get_hash() == pair_bindings[1]->get_hash());
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(4096, participant_desc));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(4096, participant_desc));
  auto allocation_skipped = vm::load_cell_slice(participant_desc);
  ASSERT_TRUE(block::tlb::t_TransactionDescr.skip(allocation_skipped) && allocation_skipped.empty_ext());
  auto allocation_storage = vm::load_cell_slice(participant_desc);
  bool allocation_has_storage = true;
  ASSERT_TRUE(block::tlb::t_TransactionDescr.skip_to_storage_phase(allocation_storage, allocation_has_storage));
  ASSERT_TRUE(!allocation_has_storage && allocation_storage.empty_ext());
  td::RefInt256 allocation_storage_fees;
  ASSERT_TRUE(block::tlb::t_TransactionDescr.get_storage_fees(participant_desc, allocation_storage_fees));
  ASSERT_TRUE(td::sgn(allocation_storage_fees) == 0);
  for (auto scope : {block::WorkchainExecutionScope::AccountCompute, block::WorkchainExecutionScope::BlockTransition}) {
    ASSERT_TRUE(block::validate_transaction_execution_scope(participant_desc, scope).is_error());
  }
  ASSERT_TRUE(block::verify_workchain_value_flow(rows, pair_effects.native_transfers, 2, 2, 4096).is_ok());
  auto wrong_transfers = pair_effects.native_transfers;
  wrong_transfers[0].value = block::CurrencyCollection(138);
  ASSERT_TRUE(block::verify_workchain_value_flow(rows, wrong_transfers, 2, 2, 4096).is_error());
  ASSERT_TRUE(coordinator.balance == block::CurrencyCollection(1000) && second.balance == block::CurrencyCollection(1000));
  for (unsigned fault = 0; fault < 8; ++fault) {
    LOG(INFO) << "allocation participant rejection case=" << fault;
    Transaction rejected(second, Transaction::tr_workchain_batch, 21, 10);
    if (fault == 0) rejected.in_msg = number(1);
    if (fault == 1) rejected.out_msgs.push_back(number(1));
    auto incoming = block::CurrencyCollection(fault == 2 ? -1 : 0);
    auto outgoing = block::CurrencyCollection(fault == 3 ? 1001 : 0);
    if (fault == 5) outgoing = block::CurrencyCollection(-1);
    if (fault == 7) incoming = block::CurrencyCollection(td::make_refint(1) << 120);
    auto bad_binding = fault == 4 ? pair_bindings[0] : pair_bindings[1];
    ASSERT_TRUE(rejected.prepare_workchain_allocation_participant(bad_binding, number(321),
        incoming, outgoing, cfg, fault == 6 ? 0 : 4096).is_error());
    ASSERT_TRUE(rejected.balance == second.balance);
    ASSERT_TRUE(!rejected.serialize(cfg));
  }
  Transaction exhausted(second, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(exhausted.prepare_workchain_allocation_participant(pair_bindings[1], number(321),
      block::CurrencyCollection(1), block::CurrencyCollection(1001), cfg, 4096).is_ok());
  ASSERT_TRUE(exhausted.balance.is_zero() && exhausted.serialize(cfg));
  Transaction missing_binding(second, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(missing_binding.prepare_workchain_allocation_participant({}, number(321),
      block::CurrencyCollection(1), block::CurrencyCollection(0), cfg, 4096).is_error());
  ASSERT_TRUE(missing_binding.balance == second.balance && !missing_binding.serialize(cfg));
  // Artificial, non-admitted binding: a valid binding has no child references.
  // Probe the actual builder exception class, not a reachable valid-wire case.
  auto artificial_binding = number(1);
  for (unsigned depth = 0; depth < 1024; ++depth) artificial_binding = vm::CellBuilder().store_ref(artificial_binding).finalize();
  Transaction failed_builder(second, Transaction::tr_workchain_batch, 21, 10);
  bool binding_threw = false;
  try {
    auto status = failed_builder.prepare_workchain_allocation_participant(artificial_binding, number(321),
        block::CurrencyCollection(1), block::CurrencyCollection(0), cfg, 4096);
    ASSERT_TRUE(status.is_error());
  } catch (const vm::CellBuilder::CellWriteError&) {
    binding_threw = true;
  }
  ASSERT_TRUE(binding_threw);
  ASSERT_TRUE(failed_builder.balance == second.balance && !failed_builder.serialize(cfg));

  auto extra_amount = [](td::RefInt256 amount) {
    vm::Dictionary values(32);
    vm::CellBuilder value;
    ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(value, *amount));
    ASSERT_TRUE(values.set_builder(td::BitArray<32>(7u), value, vm::Dictionary::SetMode::Add));
    return block::CurrencyCollection(0, values.get_root_cell());
  };
  // Construct a Native-encoded opening state independently of this factory,
  // with a real encoded opening extra-currency balance (not only a cache edit).
  block::gen::Account::Record_account extra_root;
  block::gen::AccountStorage::Record extra_storage;
  ASSERT_TRUE(tlb::unpack_cell(second.total_state, extra_root));
  ASSERT_TRUE(tlb::csr_unpack(extra_root.storage, extra_storage));
  auto opening_extra = extra_amount(td::make_refint(5));
  ASSERT_TRUE(opening_extra.pack_to(extra_storage.balance));
  ASSERT_TRUE(tlb::csr_pack(extra_root.storage, extra_storage));
  td::Ref<vm::Cell> extra_cell;
  ASSERT_TRUE(tlb::pack_cell(extra_cell, extra_root));
  auto extra_shard_account = vm::CellBuilder().store_ref(extra_cell)
      .store_bits(second.last_trans_hash_.bits(), 256).store_long(second.last_trans_lt_, 64).finalize();
  block::Account extra_owner(2, b.bits());
  ASSERT_TRUE(extra_owner.unpack(vm::load_cell_slice_ref(extra_shard_account), 10, false));
  ASSERT_TRUE(extra_owner.balance == opening_extra);
  Transaction extra_tx(extra_owner, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(extra_tx.prepare_workchain_allocation_participant(pair_bindings[1], number(321),
      extra_amount(td::make_refint(7)), extra_amount(td::make_refint(3)), cfg, 4096).is_ok());
  ASSERT_TRUE(extra_tx.balance == extra_amount(td::make_refint(9)) && extra_tx.serialize(cfg));
  actual_row(extra_owner, extra_tx, block::CurrencyCollection(0));
  ASSERT_TRUE(rows.back().new_balance == extra_amount(td::make_refint(9)));
  for (unsigned fault = 0; fault < 3; ++fault) {
    LOG(INFO) << "allocation extra-currency rejection case=" << fault;
    Transaction rejected(extra_owner, Transaction::tr_workchain_batch, 21, 10);
    auto incoming = extra_amount(td::make_refint(7));
    auto outgoing = extra_amount(td::make_refint(fault == 0 ? 13 : 3));
    if (fault == 1) {
      block::CurrencyCollection max;
      ASSERT_TRUE(block::CurrencyCollection::sub(block::CurrencyCollection(td::make_refint(1) << 248),
          block::CurrencyCollection(1), max));
      incoming = extra_amount(max.tomis);
    }
    ASSERT_TRUE(rejected.prepare_workchain_allocation_participant(pair_bindings[1], number(321),
        incoming, outgoing, cfg, fault == 2 ? 1 : 4096).is_error());
    ASSERT_TRUE(rejected.balance == extra_owner.balance && !rejected.serialize(cfg));
  }

  // Either direction of effects/write-set disagreement must fail, even when
  // this entry's own declaration, hash and data remain entirely correct.
  for (bool extra_effect : {false, true}) {
    auto mismatched_input = extra_effect ? input : two_input;
    auto mismatched_effects = extra_effect ? two_root : effects_root;
    auto records = block::build_workchain_participant_records(td::Bits256(mismatched_input->get_hash().bits()),
        td::Bits256(mismatched_effects->get_hash().bits()), extra_effect ? std::vector<td::Bits256>{a, b} :
        std::vector<td::Bits256>{a}, 2).move_as_ok();
    Transaction rejected(coordinator, Transaction::tr_workchain_batch, 21, 10);
    ASSERT_TRUE(rejected.prepare_workchain_entry(records[0], mismatched_input, mismatched_effects,
        number(321), cfg, 2, 4096).is_error());
    ASSERT_TRUE(rejected.balance == coordinator.balance);
  }

  for (bool missing_write : {false, true}) {
    auto wrong = access;
    if (missing_write) wrong.writes.clear();
    else wrong.reads[0].old_account_hash = hash;
    auto changed_input = block::encode_workchain_host_input(identity, admitted, wrong, inbox, 1, 1, 3).move_as_ok();
    auto changed_binding = block::build_workchain_participant_records(td::Bits256(changed_input->get_hash().bits()),
        td::Bits256(effects_root->get_hash().bits()), {a}, 1).move_as_ok()[0];
    Transaction rejected(coordinator, Transaction::tr_workchain_batch, 21, 10);
    ASSERT_TRUE(rejected.prepare_workchain_entry(changed_binding, changed_input, effects_root, number(321), cfg, 2, 4096).is_error());
  }

  // Internal allocations use the complete effects, not message forwarding
  // fees. Each endpoint is tested in isolation here; this is not two entry
  // records in one accepted block or complete multi-account settlement.
  auto allocated_entry = [&](const std::vector<block::WorkchainInternalTransfer>& transfers,
                             bool use_second, const block::CurrencyCollection& expected, bool valid) {
    auto allocated_effects = two_effects;
    allocated_effects.native_transfers = transfers;
    auto root = block::encode_workchain_account_effects(allocated_effects, 2, 2, 4096).move_as_ok();
    auto records = block::build_workchain_participant_records(td::Bits256(two_input->get_hash().bits()),
        td::Bits256(root->get_hash().bits()), {a, b}, 2).move_as_ok();
    auto& owner = use_second ? second : coordinator;
    Transaction allocated(owner, Transaction::tr_workchain_batch, 21, 10);
    auto status = allocated.prepare_workchain_entry(records[use_second ? 1 : 0], two_input, root, number(321), cfg, 2, 4096);
    ASSERT_EQ(status.is_ok(), valid);
    if (!valid) {
      ASSERT_TRUE(allocated.balance == owner.balance);
      ASSERT_TRUE(!allocated.serialize(cfg));
      return;
    }
    ASSERT_TRUE(allocated.balance == expected);
    ASSERT_TRUE(allocated.serialize(cfg));
    block::gen::Account::Record_account result;
    block::gen::AccountStorage::Record result_storage;
    block::CurrencyCollection actual;
    ASSERT_TRUE(tlb::unpack_cell(allocated.new_total_state, result));
    ASSERT_TRUE(tlb::csr_unpack(result.storage, result_storage));
    ASSERT_TRUE(actual.unpack(result_storage.balance));
    ASSERT_TRUE(actual == expected);
    ASSERT_TRUE(owner.balance == block::CurrencyCollection(1000));
  };
  allocated_entry({{a, b, block::CurrencyCollection(137)}, {b, a, block::CurrencyCollection(10)}},
      false, block::CurrencyCollection(1073), true);
  allocated_entry({{a, b, block::CurrencyCollection(137)}, {b, a, block::CurrencyCollection(10)}},
      true, block::CurrencyCollection(1227), true);
  allocated_entry({{a, b, block::CurrencyCollection(1200)}}, false, block::CurrencyCollection(0), true);
  allocated_entry({{a, b, block::CurrencyCollection(1201)}}, false, block::CurrencyCollection(0), false);
  // A batch has simultaneous edges: canonical source order must not reject
  // an account whose incoming allocation funds the final unit of its debit.
  allocated_entry({{a, b, block::CurrencyCollection(1201)}, {b, a, block::CurrencyCollection(1)}},
      false, block::CurrencyCollection(0), true);

  // Tiny descriptor headers can still fail construction because of child
  // depth. This is an exception-boundary probe, not an admitted block profile.
  auto deep = number(1);
  for (unsigned depth = 0; depth < 1023; ++depth) deep = vm::CellBuilder().store_ref(deep).finalize();
  block::gen::UnoV2HostInput::Record deep_record;
  ASSERT_TRUE(tlb::unpack_cell(input, deep_record));
  deep_record.candidate = deep;
  td::Ref<vm::Cell> deep_input;
  ASSERT_TRUE(tlb::pack_cell(deep_input, deep_record));
  auto deep_binding = block::build_workchain_participant_records(td::Bits256(deep_input->get_hash().bits()),
      td::Bits256(effects_root->get_hash().bits()), {a}, 1).move_as_ok()[0];
  Transaction interrupted(coordinator, Transaction::tr_workchain_batch, 21, 10);
  bool threw = false;
  try {
    auto result = interrupted.prepare_workchain_entry(deep_binding, deep_input, effects_root, number(321), cfg, 2, 4096);
    ASSERT_TRUE(result.is_ok());
  } catch (const vm::CellBuilder::CellWriteError&) {
    threw = true;
  }
  ASSERT_TRUE(threw);
  ASSERT_TRUE(!interrupted.serialize(cfg));
  ASSERT_TRUE(interrupted.balance == coordinator.balance);
}

TEST(WorkchainBlock, AccountEngineExecution) {
  auto candidate = number(11);
  auto hash = td::Bits256(candidate->get_hash().bits());
  block::InputPolicyIdentity policy_id{candidate->get_hash(), false, 17, 9, 2, 1};
  auto resolved = block::ResolvedInputPolicy::from_resolved_fields({10, 1024, 1}, policy_id);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedInputPolicy>(resolved));
  block::CandidateAdmissionSession admission(candidate, std::get<block::ResolvedInputPolicy>(resolved));
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(admission.evaluate()));
  const auto& admitted = std::get<block::AdmittedInput>(admission.evaluate());
  block::WorkchainHostIdentity identity{-1, hash, hash, 2, UINT64_MAX, hash, false,
      17, 9, 2, 1, hash, 1, 1, 1, number(1)};
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 3, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto a = td::Bits256::zero();
  td::Bits256 b(number(1)->get_hash().bits());
  block::WorkchainAccountDeclarations declarations;
  for (auto key : {a, b}) {
    block::tlb::ShardAccount::Record record;
    ASSERT_TRUE(record.unpack(accounts.lookup(key)));
    declarations.reads.push_back({key, td::Bits256(record.account->get_hash().bits())});
    declarations.writes.push_back(key);
  }
  struct Engine final : block::WorkchainAccountEngine {
    mutable unsigned calls{0};
    td::Bits256 a, b;
    bool bad_read{false}, omit_write{false}, wrong_key{false}, null_data{false}, with_transfer{false};
    bool reverse_transfer{false};
    unsigned transfer_value{1};
    td::Ref<vm::Cell> payout;
    td::Result<block::WorkchainAccountEffects> execute_accounts(
        const td::Ref<vm::Cell>& input, block::WorkchainAccountReadView& view) const override {
      ++calls;
      if (bad_read) {
        auto ignored = view.read(td::Bits256(number(999)->get_hash().bits()));
        // Deliberately ignore the error and return otherwise valid effects.
      } else {
        TRY_RESULT(first, view.read(a));
        TRY_RESULT(second, view.read(b));
        if (first.is_null() || second.is_null() || input.is_null()) return td::Status::Error("missing engine input");
      }
      block::WorkchainAccountEffects result;
      result.updates.push_back({a, number(101)});
      if (!omit_write) result.updates.push_back({b, number(102)});
      if (wrong_key) result.updates[0].account = b;
      if (null_data) result.updates[0].data.clear();
      result.payout_request = payout;
      if (with_transfer) result.native_transfers.push_back({reverse_transfer ? b : a,
          reverse_transfer ? a : b, block::CurrencyCollection(transfer_value)});
      result.receipts = number(103);
      result.events = number(104);
      result.usage = {7, 8, 9};
      return result;
    }
  } engine;
  engine.a = a; engine.b = b;
  auto execute = [&](const auto& access) {
    return block::execute_workchain_account_engine(engine, state.accounts, identity, admitted, access, {}, 2, 2, 0);
  };
  auto result = execute(declarations);
  ASSERT_TRUE(result.is_ok());
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_EQ(result.ok().effects.updates.size(), 2u);
  ASSERT_TRUE(result.ok().effects.updates[1].data->get_hash() == number(102)->get_hash());
  auto wrong = declarations;
  wrong.reads[0].old_account_hash = hash;
  engine.calls = 0;
  ASSERT_TRUE(execute(wrong).is_error());
  ASSERT_EQ(engine.calls, 0u);
  engine.bad_read = true;
  ASSERT_TRUE(execute(declarations).is_error());
  engine.bad_read = false; engine.omit_write = true;
  ASSERT_TRUE(execute(declarations).is_error());
  engine.omit_write = false; engine.wrong_key = true;
  ASSERT_TRUE(execute(declarations).is_error());
  engine.wrong_key = false; engine.null_data = true;
  ASSERT_TRUE(execute(declarations).is_error());
  engine.null_data = false;
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = cfg.extra_currency_v2 = true;
  block::ActionPhaseConfig pricing;
  pricing.global_version = 16;
  pricing.disable_custom_fess = pricing.disable_anycast = pricing.extra_currency_v2 = true;
  pricing.action_fine_enabled = pricing.bounce_on_fail_enabled = pricing.message_skip_enabled = true;
  block::WorkchainSet workchains;
  pricing.workchains = &workchains;
  pricing.fwd_mc.lump_price = 100;
  pricing.fwd_mc.first_frac = 16384;
  auto settle = [&]() {
    return block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
        declarations, {}, 2, 2, 0, 2, a, b, td::make_refint(500), 4096, cfg, pricing);
  };
  for (bool with_payout : {false, true}) {
    if (with_payout) {
      vm::CellBuilder cb;
      cb.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(-1, 8).store_zeroes(256);
      ASSERT_TRUE(block::CurrencyCollection(137).store(cb));
      ASSERT_TRUE(block::tlb::t_Tomis.store_integer_ref(cb, td::make_refint(3)));
      engine.payout = cb.store_zeroes(4).store_zeroes(96).store_zeroes(2).store_bits(b.bits(), 256).finalize();
    }
    engine.calls = 0;
    auto settled = settle();
    ASSERT_TRUE(settled.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    const auto& value = settled.ok();
    auto expected_input = block::encode_workchain_host_input(identity, admitted, declarations, {}, 2, 2, 0).move_as_ok();
    ASSERT_TRUE(value.input->get_hash() == expected_input->get_hash());
    ASSERT_TRUE(block::gen::t_UnoV2HostEffects.validate_ref(4096, value.effects));
    block::gen::UnoV2HostEffects::Record decoded;
    ASSERT_TRUE(tlb::unpack_cell(value.effects, decoded));
    ASSERT_EQ(decoded.wire_bytes, 7u);
    ASSERT_EQ(decoded.verification_units, 8u);
    ASSERT_EQ(decoded.written_cells, 9u);
    ASSERT_EQ(decoded.receipts->prefetch_ulong(1), 1u);
    ASSERT_EQ(decoded.events->prefetch_ulong(1), 1u);
    ASSERT_TRUE(decoded.receipts->prefetch_ref()->get_hash() == number(103)->get_hash());
    ASSERT_TRUE(decoded.events->prefetch_ref()->get_hash() == number(104)->get_hash());
    block::gen::UnoV2NativeEffects::Record native;
    ASSERT_TRUE(tlb::unpack_cell(decoded.native, native));
    ASSERT_EQ(native.payout->prefetch_ulong(1), with_payout ? 1u : 0u);
    if (with_payout) ASSERT_TRUE(native.payout->prefetch_ref()->get_hash() == engine.payout->get_hash());
    vm::Dictionary updates(decoded.updates, 256);
    vm::AugmentedDictionary next(vm::load_cell_slice_ref(value.state.accounts), 256, block::tlb::aug_ShardAccounts);
    vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(value.state.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
    for (auto key : {a, b}) {
      block::Account account(2, key.bits());
      ASSERT_TRUE(account.unpack(next.lookup(key), identity.gen_utime, false));
      ASSERT_TRUE(account.data->get_hash() == number(key == a ? 101 : 102)->get_hash());
      ASSERT_TRUE(updates.lookup_ref(key)->get_hash() == account.data->get_hash());
      ASSERT_TRUE(account.balance == block::CurrencyCollection(with_payout ? (key == a ? 863 : 900) : 1000));
      auto block_root = vm::CellBuilder().append_cellslice(*blocks.lookup(key)).finalize();
      block::gen::AccountBlock::Record ab;
      ASSERT_TRUE(tlb::unpack_cell(block_root, ab));
      vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
      block::gen::Transaction::Record tx;
      ASSERT_TRUE(tlb::unpack_cell(txs.lookup_ref(td::BitArray<64>(account.last_trans_lt_)), tx));
      block::gen::UnoV2HostRecord::Record binding;
      ASSERT_TRUE(tlb::unpack_cell(vm::load_cell_slice(tx.description).prefetch_ref(), binding));
      ASSERT_TRUE(binding.input_hash == value.input->get_hash().bits());
      ASSERT_TRUE(binding.effects_hash == value.effects->get_hash().bits());
      ASSERT_TRUE(binding.account_id == key);
      ASSERT_EQ(binding.effect_index, key == a ? 0u : 1u);
      auto description = vm::load_cell_slice(tx.description);
      ASSERT_EQ(description.fetch_ulong(4), key == b ? 12u : 11u);
      ASSERT_TRUE(description.fetch_ref().not_null());
      if (key == b) {
        ASSERT_TRUE(description.fetch_ref()->get_hash() == value.input->get_hash());
        ASSERT_TRUE(description.fetch_ref()->get_hash() == value.effects->get_hash());
      }
      ASSERT_TRUE(description.empty_ext());
    }
    ASSERT_EQ(value.message.not_null(), with_payout);
    if (with_payout) {
      block::Account source(2, a.bits()), entry(2, b.bits());
      ASSERT_TRUE(source.unpack(accounts.lookup(a), identity.gen_utime, false));
      ASSERT_TRUE(entry.unpack(accounts.lookup(b), identity.gen_utime, false));
      auto direct_pair = [&](td::Ref<vm::Cell> in, td::Ref<vm::Cell> out, td::Ref<vm::Cell> requested,
                             td::Ref<vm::Cell> data, unsigned wrong_hash = 0, std::uint64_t transfers = 2) {
        auto records = block::build_workchain_participant_records(
            wrong_hash == 1 || in.is_null() ? hash : td::Bits256(in->get_hash().bits()),
            wrong_hash == 2 || out.is_null() ? hash : td::Bits256(out->get_hash().bits()), {a, b}, 2).move_as_ok();
        return block::transaction::Transaction::build_workchain_payout_pair(source, entry,
            records[0], records[1], data, number(102), requested, 3, identity.gen_utime,
            td::make_refint(500), transfers, 4096, cfg, pricing, in, out);
      };
      auto full_pair = direct_pair(value.input, value.effects, engine.payout, number(101)).move_as_ok();
      block::gen::Transaction::Record full_entry_record;
      ASSERT_TRUE(tlb::unpack_cell(full_pair.transactions[1]->root, full_entry_record));
      ASSERT_EQ(vm::load_cell_slice(full_entry_record.description).prefetch_ulong(4), 12u);
      ASSERT_TRUE(direct_pair({}, value.effects, engine.payout, number(101)).is_error());
      ASSERT_TRUE(direct_pair(value.input, {}, engine.payout, number(101)).is_error());
      ASSERT_TRUE(direct_pair(value.input, value.effects, engine.payout, number(101), true).is_error());
      // These pin the composite binding contract; entry preparation repeats
      // the hash checks, so they do not isolate each early duplicate check.
      ASSERT_TRUE(direct_pair(value.input, value.effects, engine.payout, number(101), 2).is_error());
      ASSERT_TRUE(direct_pair(value.input, value.effects, {}, number(101)).is_error());
      block::WorkchainAccountEffects unsupported_effects;
      unsupported_effects.updates = {{a, number(101)}, {b, number(102)}};
      auto no_payout = block::encode_workchain_account_effects(unsupported_effects, 2, 0, 4096).move_as_ok();
      ASSERT_TRUE(direct_pair(value.input, no_payout, engine.payout, number(101)).is_error());
      unsupported_effects.payout_request = engine.payout;
      unsupported_effects.native_transfers = {{a, b, block::CurrencyCollection(1)}};
      auto with_transfer = block::encode_workchain_account_effects(unsupported_effects, 2, 1, 4096).move_as_ok();
      auto mixed_pair = direct_pair(value.input, with_transfer, engine.payout, number(101)).move_as_ok();
      ASSERT_TRUE(mixed_pair.transactions[0]->balance == block::CurrencyCollection(862));
      ASSERT_TRUE(mixed_pair.transactions[1]->balance == block::CurrencyCollection(901));
      ASSERT_TRUE(direct_pair(value.input, with_transfer, engine.payout, number(101), 0, 0).is_error());
      ASSERT_TRUE(direct_pair(value.input, value.effects, engine.payout, number(333)).is_error());
      // Requests use the relaxed source form; only the priced Native message
      // has its source address filled and is a complete Message Any.
      vm::CellBuilder different_request;
      different_request.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(-1, 8).store_zeroes(256);
      ASSERT_TRUE(block::CurrencyCollection(138).store(different_request));
      ASSERT_TRUE(block::tlb::t_Tomis.store_integer_ref(different_request, td::make_refint(3)));
      auto different_message = different_request.store_zeroes(4).store_zeroes(96).store_zeroes(2)
          .store_bits(b.bits(), 256).finalize();
      ASSERT_TRUE(direct_pair(value.input, value.effects, different_message, number(101)).is_error());
      vm::CellBuilder over_request;
      over_request.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(-1, 8).store_zeroes(256);
      ASSERT_TRUE(block::CurrencyCollection(1001).store(over_request));
      ASSERT_TRUE(block::tlb::t_Tomis.store_integer_ref(over_request, td::make_refint(3)));
      auto over_message = over_request.store_zeroes(4).store_zeroes(96).store_zeroes(2)
          .store_bits(b.bits(), 256).finalize();
      auto incoming = unsupported_effects;
      incoming.native_transfers = {{b, a, block::CurrencyCollection(1)}};
      incoming.payout_request = over_message;
      auto incoming_root = block::encode_workchain_account_effects(incoming, 2, 1, 4096).move_as_ok();
      // Allocated custody can pay 1001, but its old balance authorizes only 1000.
      ASSERT_TRUE(direct_pair(value.input, incoming_root, over_message, number(101)).is_error());
      // An inbox to the non-entry role would be skipped by entry-local credit
      // selection. The enclosing payout profile must reject it, not lose it.
      auto unsupported_input = block::encode_workchain_host_input(identity, admitted, declarations,
          {inbound_envelope(0, 0, {}, a)}, 2, 2, 1).move_as_ok();
      ASSERT_TRUE(direct_pair(unsupported_input, value.effects, engine.payout, number(101)).is_error());
      std::vector<block::WorkchainStorageWrite> payout_writes;
      for (std::size_t i = 0; i < declarations.writes.size(); ++i) {
        payout_writes.push_back({declarations.writes[i], *declarations.reads[i].old_account_hash,
                                number(i == 0 ? 101 : 102)});
      }
      block::ClaimedWorkchainPayoutOverlay claim{value.state.accounts, value.state.account_blocks,
                                                value.message, value.state.end_lt};
      auto rebuilt = block::replay_workchain_payout_overlay(state.accounts, 2, identity.gen_utime,
          identity.host_after_lt, td::Bits256(value.input->get_hash().bits()),
          td::Bits256(value.effects->get_hash().bits()), payout_writes, a, b, engine.payout,
          td::make_refint(500), 2, 2, 2, 4096, cfg, pricing, claim, value.input, value.effects).move_as_ok();
      ASSERT_TRUE(rebuilt.state.account_blocks->get_hash() == value.state.account_blocks->get_hash());
      ASSERT_TRUE(rebuilt.state.accounts->get_hash() == value.state.accounts->get_hash());
      auto third = td::Bits256(number(2)->get_hash().bits());
      block::tlb::ShardAccount::Record third_old;
      ASSERT_TRUE(third_old.unpack(accounts.lookup(third)));
      auto three = declarations;
      three.reads.push_back({third, td::Bits256(third_old.account->get_hash().bits())});
      three.writes.push_back(third);
      std::sort(three.reads.begin(), three.reads.end(), [](const auto& x, const auto& y) { return x.account < y.account; });
      std::sort(three.writes.begin(), three.writes.end());
      block::WorkchainAccountEffects three_effects;
      std::vector<block::WorkchainStorageWrite> three_writes;
      for (const auto& read : three.reads) {
        auto data = number(read.account == a ? 101 : read.account == b ? 102 : 303);
        three_effects.updates.push_back({read.account, data});
        three_writes.push_back({read.account, *read.old_account_hash, data});
      }
      three_effects.payout_request = engine.payout;
      auto three_input = block::encode_workchain_host_input(identity, admitted, three, {}, 3, 3, 0).move_as_ok();
      auto three_output = block::encode_workchain_account_effects(three_effects, 3, 0, 4096).move_as_ok();
      auto construct_three = [&](const auto& writes, td::Ref<vm::Cell> input, td::Ref<vm::Cell> output,
                                  std::uint64_t after, std::uint64_t transfer_limit = 2) {
        return block::build_workchain_payout_overlay(state.accounts, 2, identity.gen_utime, after,
            td::Bits256(input->get_hash().bits()), td::Bits256(output->get_hash().bits()), writes, a, b,
            engine.payout, td::make_refint(500), 3, 3, transfer_limit, 4096, cfg, pricing, input, output);
      };
      auto three_overlay = construct_three(three_writes, three_input, three_output, identity.host_after_lt).move_as_ok();
      vm::AugmentedDictionary three_accounts(vm::load_cell_slice_ref(three_overlay.state.accounts), 256,
                                             block::tlb::aug_ShardAccounts);
      block::Account third_updated(2, third.bits());
      ASSERT_TRUE(third_updated.unpack(three_accounts.lookup(third), identity.gen_utime, false));
      ASSERT_TRUE(third_updated.data->get_hash() == number(303)->get_hash());
      auto third_tag = [&](const block::WorkchainPayoutOverlay& overlay) {
        vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(overlay.state.account_blocks), 256,
                                         block::tlb::aug_ShardAccountBlocks);
        block::gen::AccountBlock::Record ab;
        ASSERT_TRUE(tlb::unpack_cell(vm::CellBuilder().append_cellslice(*blocks.lookup(third)).finalize(), ab));
        vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
        block::gen::Transaction::Record tx;
        ASSERT_TRUE(tlb::unpack_cell(txs.lookup_ref(td::BitArray<64>(third_updated.last_trans_lt_)), tx));
        ASSERT_EQ(vm::load_cell_slice(tx.description).prefetch_ulong(4), 11u);
      };
      third_tag(three_overlay);
      three_effects.native_transfers = {{third, b, block::CurrencyCollection(1)}};
      auto mixed_output = block::encode_workchain_account_effects(three_effects, 3, 1, 4096).move_as_ok();
      auto mixed_three = construct_three(three_writes, three_input, mixed_output, identity.host_after_lt).move_as_ok();
      vm::AugmentedDictionary mixed_accounts(vm::load_cell_slice_ref(mixed_three.state.accounts), 256,
                                             block::tlb::aug_ShardAccounts);
      for (auto key : {a, b, third}) {
        block::Account updated(2, key.bits());
        ASSERT_TRUE(updated.unpack(mixed_accounts.lookup(key), identity.gen_utime, false));
        ASSERT_TRUE(updated.balance == block::CurrencyCollection(key == a ? 863 : key == b ? 901 : 999));
      }
      third_tag(mixed_three);
      block::ClaimedWorkchainPayoutOverlay mixed_claim{mixed_three.state.accounts,
          mixed_three.state.account_blocks, mixed_three.message, mixed_three.state.end_lt};
      auto replay_mixed = [&](const auto& claim) {
        return block::replay_workchain_payout_overlay(state.accounts, 2, identity.gen_utime,
            identity.host_after_lt, td::Bits256(three_input->get_hash().bits()),
            td::Bits256(mixed_output->get_hash().bits()), three_writes, a, b, engine.payout,
            td::make_refint(500), 3, 3, 1, 4096, cfg, pricing, claim, three_input, mixed_output);
      };
      auto mixed_replay = replay_mixed(mixed_claim).move_as_ok();
      ASSERT_TRUE(mixed_replay.state.accounts->get_hash() == mixed_claim.accounts->get_hash());
      ASSERT_TRUE(mixed_replay.state.account_blocks->get_hash() == mixed_claim.account_blocks->get_hash());
      for (unsigned field = 0; field < 4; ++field) {
        auto altered = mixed_claim;
        if (field == 0) altered.accounts = three_overlay.state.accounts;
        if (field == 1) altered.account_blocks = three_overlay.state.account_blocks;
        if (field == 2) altered.message = different_message;
        if (field == 3) altered.end_lt = block::participant_lt_detail::checked_add(altered.end_lt, 1).move_as_ok();
        ASSERT_TRUE(replay_mixed(altered).is_error());
      }
      three_effects.native_transfers = {{a, third, block::CurrencyCollection(1)}};
      auto receiving_output = block::encode_workchain_account_effects(three_effects, 3, 1, 4096).move_as_ok();
      auto receiving = construct_three(three_writes, three_input, receiving_output,
          identity.host_after_lt, 1).move_as_ok();
      vm::AugmentedDictionary receiving_accounts(vm::load_cell_slice_ref(receiving.state.accounts), 256,
                                                 block::tlb::aug_ShardAccounts);
      block::Account receiver(2, third.bits());
      ASSERT_TRUE(receiver.unpack(receiving_accounts.lookup(third), identity.gen_utime, false));
      ASSERT_TRUE(receiver.balance == block::CurrencyCollection(1001));
      three_effects.native_transfers = {{third, b, block::CurrencyCollection(1001)}};
      auto insolvent_output = block::encode_workchain_account_effects(three_effects, 3, 1, 4096).move_as_ok();
      ASSERT_TRUE(construct_three(three_writes, three_input, insolvent_output, identity.host_after_lt, 1).is_error());
      auto wrong_writes = three_writes;
      for (auto& write : wrong_writes) if (write.account == third) write.data = number(304);
      ASSERT_TRUE(construct_three(wrong_writes, three_input, three_output, identity.host_after_lt).is_error());
      wrong_writes = three_writes;
      wrong_writes[0].old_account_hash = hash;
      ASSERT_TRUE(construct_three(wrong_writes, three_input, three_output, identity.host_after_lt).is_error());
      ASSERT_TRUE(construct_three(three_writes, three_input, three_output, 2).is_error());
      wrong_writes = three_writes;
      wrong_writes.erase(std::remove_if(wrong_writes.begin(), wrong_writes.end(),
          [&](const auto& write) { return write.account == third; }), wrong_writes.end());
      ASSERT_TRUE(construct_three(wrong_writes, three_input, three_output, identity.host_after_lt).is_error());
      auto readonly = three;
      readonly.writes = declarations.writes;
      auto readonly_input = block::encode_workchain_host_input(identity, admitted, readonly, {}, 3, 3, 0).move_as_ok();
      ASSERT_TRUE(construct_three(payout_writes, readonly_input, value.effects, identity.host_after_lt).is_ok());
      for (auto& read : readonly.reads) if (read.account == third) read.old_account_hash = hash;
      auto bad_readonly = block::encode_workchain_host_input(identity, admitted, readonly, {}, 3, 3, 0).move_as_ok();
      ASSERT_TRUE(construct_three(payout_writes, bad_readonly, value.effects, identity.host_after_lt).is_error());
    }
    // API-width probe, not a proposed production storage limit.
    auto independent_storage = cfg;
    independent_storage.size_limits.max_acc_state_cells = std::numeric_limits<unsigned>::max();
    auto wide = block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
        declarations, {}, 2, 2, 0, 2, a, b, td::make_refint(500), 4096, independent_storage, pricing).move_as_ok();
    ASSERT_TRUE(wide.state.accounts->get_hash() == value.state.accounts->get_hash());
    ASSERT_TRUE(wide.state.account_blocks->get_hash() == value.state.account_blocks->get_hash());
  }
  engine.with_transfer = true;
  auto check_mixed = [&](bool reverse, unsigned amount, unsigned custody_balance, unsigned operator_balance) {
    engine.reverse_transfer = reverse;
    engine.transfer_value = amount;
    engine.calls = 0;
    auto mixed = settle().move_as_ok();
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_TRUE(mixed.message.not_null());
    vm::AugmentedDictionary result(vm::load_cell_slice_ref(mixed.state.accounts), 256,
                                   block::tlb::aug_ShardAccounts);
    for (auto key : {a, b}) {
      block::Account updated(2, key.bits());
      ASSERT_TRUE(updated.unpack(result.lookup(key), identity.gen_utime, false));
      ASSERT_TRUE(updated.balance == block::CurrencyCollection(key == a ? custody_balance : operator_balance));
    }
  };
  check_mixed(false, 1, 862, 901);
  // The explicit reverse edge and the host fee-funding edge share endpoints.
  check_mixed(true, 1, 864, 899);
  check_mixed(false, 863, 0, 1763);
  engine.transfer_value = 864;
  engine.calls = 0;
  ASSERT_TRUE(settle().is_error());
  ASSERT_EQ(engine.calls, 1u);
  check_mixed(true, 900, 1763, 0);
  engine.transfer_value = 901;
  engine.calls = 0;
  ASSERT_TRUE(settle().is_error());
  ASSERT_EQ(engine.calls, 1u);
  engine.reverse_transfer = false;
  engine.transfer_value = 1;
  engine.payout.clear();
  engine.calls = 0;
  const auto old_accounts_hash = state.accounts->get_hash();
  auto allocated = settle().move_as_ok();
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_TRUE(allocated.message.is_null());
  vm::AugmentedDictionary allocated_accounts(vm::load_cell_slice_ref(allocated.state.accounts), 256,
                                             block::tlb::aug_ShardAccounts);
  vm::AugmentedDictionary allocated_blocks(vm::load_cell_slice_ref(allocated.state.account_blocks), 256,
                                           block::tlb::aug_ShardAccountBlocks);
  td::Bits256 untouched(number(2)->get_hash().bits());
  ASSERT_TRUE(accounts.lookup(untouched)->contents_equal(*allocated_accounts.lookup(untouched)));
  ASSERT_TRUE(allocated_blocks.lookup(untouched).is_null());
  for (auto key : {a, b}) {
    block::Account updated(2, key.bits());
    ASSERT_TRUE(updated.unpack(allocated_accounts.lookup(key), identity.gen_utime, false));
    ASSERT_TRUE(updated.balance == block::CurrencyCollection(key == a ? 999 : 1001));
    auto ab_root = vm::CellBuilder().append_cellslice(*allocated_blocks.lookup(key)).finalize();
    ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(4096, ab_root));
    ASSERT_TRUE(block::tlb::t_AccountBlock.validate_ref(4096, ab_root));
    block::gen::AccountBlock::Record ab;
    ASSERT_TRUE(tlb::unpack_cell(ab_root, ab));
    ASSERT_TRUE(ab.account_addr == key);
    vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    auto tx_root = txs.lookup_ref(td::BitArray<64>(updated.last_trans_lt_));
    block::gen::Transaction::Record tx;
    ASSERT_TRUE(tlb::unpack_cell(tx_root, tx));
    ASSERT_EQ(tx.prev_trans_lt, 1u);
    ASSERT_TRUE(tx.prev_trans_hash == td::Bits256::zero());
    ASSERT_TRUE(updated.last_trans_hash_ == tx_root->get_hash().bits());
    auto desc = vm::load_cell_slice(tx.description);
    ASSERT_EQ(desc.fetch_ulong(4), key == b ? 12u : 11u);
    block::gen::UnoV2HostRecord::Record binding;
    ASSERT_TRUE(tlb::unpack_cell(desc.fetch_ref(), binding));
    ASSERT_TRUE(binding.account_id == key && binding.input_hash == allocated.input->get_hash().bits() &&
                binding.effects_hash == allocated.effects->get_hash().bits());
    if (key == b) {
      ASSERT_TRUE(desc.fetch_ref()->get_hash() == allocated.input->get_hash());
      ASSERT_TRUE(desc.fetch_ref()->get_hash() == allocated.effects->get_hash());
    }
    ASSERT_TRUE(desc.empty_ext());
    auto hashes = vm::load_cell_slice(ab.state_update);
    td::Bits256 before, after;
    ASSERT_EQ(hashes.fetch_ulong(8), 0x72u);
    ASSERT_TRUE(hashes.fetch_bits_to(before) && hashes.fetch_bits_to(after) && hashes.empty_ext());
    block::tlb::ShardAccount::Record prior;
    ASSERT_TRUE(prior.unpack(accounts.lookup(key)));
    ASSERT_TRUE(before == prior.account->get_hash().bits() && after == updated.total_state->get_hash().bits());
  }
  auto replay = [&](const auto& claim) {
    return block::replay_workchain_allocation_overlay(state.accounts, identity, allocated.input,
        allocated.effects, b, a, 2, 2, 2, 4096, cfg, claim);
  };
  auto repeated = replay(allocated.state).move_as_ok();
  ASSERT_TRUE(repeated.accounts->get_hash() == allocated.state.accounts->get_hash());
  ASSERT_TRUE(repeated.account_blocks->get_hash() == allocated.state.account_blocks->get_hash());
  for (unsigned field = 0; field < 3; ++field) {
    LOG(INFO) << "allocation replay mismatch field=" << field;
    auto claimed = allocated.state;
    if (field == 0) claimed.accounts = state.accounts;
    if (field == 1) claimed.account_blocks = number(2);
    if (field == 2) claimed.end_lt = 0;
    ASSERT_TRUE(replay(claimed).is_error());
  }
  auto wrong_identity = identity;
  wrong_identity.height = 2;
  ASSERT_TRUE(block::build_workchain_allocation_overlay(state.accounts, wrong_identity, allocated.input,
      allocated.effects, b, a, 2, 2, 2, 4096, cfg).is_error());
  ASSERT_TRUE(block::build_workchain_allocation_overlay(state.accounts, identity, allocated.input,
      allocated.effects, untouched, a, 2, 2, 2, 4096, cfg).is_error());
  auto later = identity;
  later.host_after_lt = 10;
  auto with_inbox = block::encode_workchain_host_input(later, admitted, declarations,
      {inbound_envelope(5)}, 2, 2, 1).move_as_ok();
  // The message-free wrapper still rejects custody imports; the explicit
  // inbound materializer below settles both authenticated receiving roles.
  ASSERT_TRUE(block::build_workchain_allocation_overlay(state.accounts, later, with_inbox,
      allocated.effects, b, a, 2, 2, 2, 4096, cfg).is_error());
  auto foreign_access = declarations;
  block::tlb::ShardAccount::Record foreign_old;
  ASSERT_TRUE(foreign_old.unpack(accounts.lookup(untouched)));
  foreign_access.reads.push_back({untouched, td::Bits256(foreign_old.account->get_hash().bits())});
  foreign_access.writes.push_back(untouched);
  std::sort(foreign_access.reads.begin(), foreign_access.reads.end(),
      [](const auto& lhs, const auto& rhs) { return lhs.account < rhs.account; });
  std::sort(foreign_access.writes.begin(), foreign_access.writes.end());
  block::WorkchainAccountEffects foreign_effects;
  foreign_effects.updates = {{a, number(101)}, {b, number(102)}, {untouched, number(103)}};
  std::sort(foreign_effects.updates.begin(), foreign_effects.updates.end(),
      [](const auto& lhs, const auto& rhs) { return lhs.account < rhs.account; });
  foreign_effects.native_transfers = {{a, b, block::CurrencyCollection(1)}};
  auto foreign_root = block::encode_workchain_account_effects(foreign_effects, 3, 2, 4096).move_as_ok();
  auto zero_foreign_input = block::encode_workchain_host_input(later, admitted, foreign_access,
      {inbound_envelope(5, 0, {}, untouched, block::CurrencyCollection(0))}, 3, 3, 1).move_as_ok();
  // The third account has a real participant and zero imported principal, so
  // neither missing-transaction evidence nor value flow can mask this guard.
  ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(state.accounts, later, zero_foreign_input,
      foreign_root, b, a, 3, 3, 2, 1, 4096, cfg).is_error());
  // The first message's created LT and the second message's emitted LT each
  // independently raise the shared schedule above the host boundary.
  auto imported_input = block::encode_workchain_host_input(identity, admitted, declarations,
      {inbound_envelope(30, 1, {}, b), inbound_envelope(5, 2, 40, b), inbound_envelope(6, 3, {}, a)},
      2, 2, 3).move_as_ok();
  auto inbound = block::build_workchain_inbound_allocation_overlay(state.accounts, identity, imported_input,
      allocated.effects, b, a, 2, 2, 2, 3, 4096, cfg).move_as_ok();
  ASSERT_EQ(inbound.state.end_lt, 42u);
  ASSERT_TRUE(inbound.imports.account_credits.at(a) == block::CurrencyCollection(100));
  ASSERT_TRUE(inbound.imports.account_credits.at(b) == block::CurrencyCollection(200));
  ASSERT_TRUE(inbound.imports.value_imported == block::CurrencyCollection(501));
  ASSERT_TRUE(inbound.imports.fees_collected == block::CurrencyCollection(201));
  vm::AugmentedDictionary inbound_accounts(vm::load_cell_slice_ref(inbound.state.accounts), 256,
                                           block::tlb::aug_ShardAccounts);
  vm::AugmentedDictionary inbound_blocks(vm::load_cell_slice_ref(inbound.state.account_blocks), 256,
                                         block::tlb::aug_ShardAccountBlocks);
  ASSERT_TRUE(accounts.lookup(untouched)->contents_equal(*inbound_accounts.lookup(untouched)));
  block::tlb::InMsgDescr import_schema(16);
  ASSERT_TRUE(import_schema.validate_ref(4096, inbound.imports.in_msg_descr));
  vm::AugmentedDictionary import_records(vm::load_cell_slice_ref(inbound.imports.in_msg_descr), 256,
                                         import_schema.aug);
  for (auto key : {a, b}) {
    block::Account updated(2, key.bits());
    ASSERT_TRUE(updated.unpack(inbound_accounts.lookup(key), identity.gen_utime, false));
    ASSERT_TRUE(updated.balance == block::CurrencyCollection(key == a ? 1099 : 1201));
    ASSERT_EQ(updated.last_trans_lt_, 41u);
    auto ab_root = vm::CellBuilder().append_cellslice(*inbound_blocks.lookup(key)).finalize();
    ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(4096, ab_root));
    block::gen::AccountBlock::Record ab;
    ASSERT_TRUE(tlb::unpack_cell(ab_root, ab));
    vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    auto tx_root = txs.lookup_ref(td::BitArray<64>(41u));
    ASSERT_TRUE(tx_root.not_null() && updated.last_trans_hash_ == tx_root->get_hash().bits());
    block::gen::Transaction::Record inbound_tx;
    ASSERT_TRUE(tlb::unpack_cell(tx_root, inbound_tx));
    ASSERT_TRUE(inbound_tx.account_addr == key && inbound_tx.prev_trans_hash == td::Bits256::zero());
    ASSERT_EQ(inbound_tx.prev_trans_lt, 1u);
    auto inbound_description = vm::load_cell_slice(inbound_tx.description);
    ASSERT_EQ(inbound_description.fetch_ulong(4), key == b ? 12u : 11u);
    block::gen::UnoV2HostRecord::Record inbound_binding;
    ASSERT_TRUE(tlb::unpack_cell(inbound_description.fetch_ref(), inbound_binding));
    ASSERT_TRUE(inbound_binding.account_id == key && inbound_binding.input_hash == imported_input->get_hash().bits() &&
                inbound_binding.effects_hash == allocated.effects->get_hash().bits());
    if (key == b) {
      ASSERT_TRUE(inbound_description.fetch_ref()->get_hash() == imported_input->get_hash());
      ASSERT_TRUE(inbound_description.fetch_ref()->get_hash() == allocated.effects->get_hash());
    }
    ASSERT_TRUE(inbound_description.empty_ext());
    std::vector<td::Ref<vm::Cell>> matching_imports;
    ASSERT_TRUE(import_records.check_for_each([&](td::Ref<vm::CellSlice> row, td::ConstBitPtr, int) {
      block::tlb::MsgEnvelope::Record_std envelope;
      block::gen::CommonMsgInfo::Record_int_msg_info info;
      block::gen::MsgAddressInt::Record_addr_std destination;
      if (!tlb::unpack_cell(row->prefetch_ref(0), envelope) || !tlb::unpack_cell_inexact(envelope.msg, info) ||
          !block::gen::csr_unpack(info.dest, destination)) return false;
      if (destination.address != key) return true;
      matching_imports.push_back(envelope.msg);
      return row->prefetch_ref(1)->get_hash() == tx_root->get_hash();
    }));
    ASSERT_EQ(matching_imports.size(), key == a ? 1u : 2u);
  }
  auto created_only_input = block::encode_workchain_host_input(identity, admitted, declarations,
      {inbound_envelope(30, 1, {}, b)}, 2, 2, 1).move_as_ok();
  ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(state.accounts, identity, created_only_input,
      allocated.effects, b, b, 2, 2, 2, 1, 4096, cfg).is_error());
  ASSERT_EQ(block::build_workchain_inbound_allocation_overlay(state.accounts, identity, created_only_input,
      allocated.effects, b, a, 2, 2, 2, 1, 4096, cfg).move_as_ok().state.end_lt, 32u);
  ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(state.accounts, identity, imported_input,
      allocated.effects, b, a, 2, 2, 2, 1, 4096, cfg).is_error());
  ASSERT_TRUE(block::build_workchain_allocation_overlay(state.accounts, identity, imported_input,
      allocated.effects, b, a, 2, 2, 2, 4096, cfg).is_error());
  auto replay_inbound = [&](const auto& claim) {
    return block::replay_workchain_inbound_allocation_overlay(state.accounts, identity, imported_input,
        allocated.effects, b, a, 2, 2, 2, 3, 4096, cfg, claim);
  };
  ASSERT_TRUE(replay_inbound(inbound).is_ok());
  for (unsigned field = 0; field < 4; ++field) {
    LOG(INFO) << "inbound allocation replay mismatch field=" << field;
    auto claim = inbound;
    if (field == 0) claim.state.accounts = state.accounts;
    if (field == 1) claim.state.account_blocks = number(2);
    if (field == 2) claim.state.end_lt = 0;
    if (field == 3) claim.imports.in_msg_descr = number(3);
    ASSERT_TRUE(replay_inbound(claim).is_error());
  }
  auto stale_cache = inbound;
  stale_cache.imports.account_credits.clear();
  stale_cache.imports.fees_collected = block::CurrencyCollection(0);
  auto cache_rebuilt = replay_inbound(stale_cache).move_as_ok();
  ASSERT_TRUE(cache_rebuilt.imports.account_credits.at(b) == block::CurrencyCollection(200));
  ASSERT_TRUE(cache_rebuilt.imports.account_credits.at(a) == block::CurrencyCollection(100));
  ASSERT_TRUE(cache_rebuilt.imports.fees_collected == block::CurrencyCollection(201));
  auto overflowing_lt = block::encode_workchain_host_input(identity, admitted, declarations,
      {inbound_envelope(UINT64_MAX, 0, {}, b)}, 2, 2, 1).move_as_ok();
  ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(state.accounts, identity, overflowing_lt,
      allocated.effects, b, a, 2, 2, 2, 1, 4096, cfg).is_error());
  ASSERT_TRUE(state.accounts->get_hash() == old_accounts_hash);
  block::WorkchainAccountEffects mixed;
  mixed.updates = {{a, number(101)}, {b, number(102)}};
  mixed.native_transfers = {{a, b, block::CurrencyCollection(1)}};
  mixed.payout_request = number(123);
  auto mixed_root = block::encode_workchain_account_effects(mixed, 2, 2, 4096).move_as_ok();
  ASSERT_TRUE(block::build_workchain_allocation_overlay(state.accounts, identity, allocated.input,
      mixed_root, b, a, 2, 2, 2, 4096, cfg).is_error());
  engine.reverse_transfer = true;
  engine.calls = 0;
  auto reversed = settle().move_as_ok();
  ASSERT_EQ(engine.calls, 1u);
  vm::AugmentedDictionary reverse_accounts(vm::load_cell_slice_ref(reversed.state.accounts), 256,
                                           block::tlb::aug_ShardAccounts);
  for (auto key : {a, b}) {
    block::Account updated(2, key.bits());
    ASSERT_TRUE(updated.unpack(reverse_accounts.lookup(key), identity.gen_utime, false));
    ASSERT_TRUE(updated.balance == block::CurrencyCollection(key == a ? 1001 : 999));
  }
  engine.transfer_value = 1001;
  // The first private account can receive the allocation, but the second
  // cannot fund it. No partially materialized dictionary is returned.
  engine.calls = 0;
  ASSERT_TRUE(settle().is_error());
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_TRUE(state.accounts->get_hash() == old_accounts_hash);
  ASSERT_TRUE(accounts.lookup(untouched)->contents_equal(*allocated_accounts.lookup(untouched)));
  engine.reverse_transfer = false;
  engine.transfer_value = 1;
  auto wide_storage_cfg = cfg;
  wide_storage_cfg.size_limits.max_acc_state_cells = std::numeric_limits<unsigned>::max();
  // The allocation currency traversal budget is independent of this storage
  // field. This is an API-width test, not a proposed production storage limit.
  ASSERT_TRUE(block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
      declarations, {}, 2, 2, 0, 2, a, b, td::make_refint(500), 4096, wide_storage_cfg, pricing).is_ok());
  engine.with_transfer = false;
  engine.calls = 0;
  ASSERT_TRUE(block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
      declarations, {}, 2, 2, 0, 2, a, b, td::make_refint(500), 0, cfg, pricing).is_error());
  ASSERT_EQ(engine.calls, 0u);
  auto unhandled_inbox = block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
      declarations, {inbound_envelope(5)}, 2, 2, 1, 2, a, b, td::make_refint(500), 4096, cfg, pricing);
  ASSERT_TRUE(unhandled_inbox.is_error());
  ASSERT_EQ(engine.calls, 0u);
}

TEST(WorkchainBlock, HostInputCommitment) {
  auto candidate = number(11);
  auto hash = td::Bits256(candidate->get_hash().bits());
  block::InputPolicyIdentity policy_id{candidate->get_hash(), false, 17, 9, 2, 1};
  auto resolved = block::ResolvedInputPolicy::from_resolved_fields({10, 1024, 1}, policy_id);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedInputPolicy>(resolved));
  auto policy = std::get<block::ResolvedInputPolicy>(resolved);
  block::CandidateAdmissionSession session(candidate, policy);
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(session.evaluate()));
  const auto& admitted = std::get<block::AdmittedInput>(session.evaluate());
  block::WorkchainHostIdentity identity{-1, hash, hash, 2, UINT64_MAX, hash, false,
      17, 9, 2, 1, hash, 1, 1, 1, number(1)};
  block::WorkchainAccountDeclarations access{{{td::Bits256::zero(), hash}}, {td::Bits256::zero()}};
  auto first = inbound_envelope(3);
  auto second = inbound_envelope(4);
  auto encode = [&](const auto& id, const auto& input, const auto& set,
                    const std::vector<td::Ref<vm::Cell>>& inbox) {
    return block::encode_workchain_host_input(id, input, set, inbox, 2, 2, 2);
  };
  auto encoded = encode(identity, admitted, access, {first, second});
  ASSERT_TRUE(encoded.is_ok());
  auto root = encoded.move_as_ok();
  ASSERT_TRUE(block::gen::t_UnoV2HostInput.validate_ref(4096, root));
  auto cs = vm::load_cell_slice(root);
  ASSERT_EQ(cs.size(), 33u);
  ASSERT_EQ(cs.size_refs(), 4u);
  ASSERT_EQ(cs.fetch_ulong(32), 0x7c0766c8u);
  ASSERT_TRUE(cs.fetch_ref()->get_hash() == block::encode_admitted_workchain_host_identity(identity, admitted).move_as_ok()->get_hash());
  ASSERT_TRUE(cs.fetch_ref()->get_hash() == block::encode_workchain_account_declarations(access, 2, 2).move_as_ok()->get_hash());
  ASSERT_TRUE(cs.fetch_ref()->get_hash() == candidate->get_hash());
  ASSERT_EQ(cs.fetch_ulong(1), 1u);
  auto inbox = block::decode_workchain_batch_inbound(cs.fetch_ref()).move_as_ok();
  ASSERT_EQ(inbox.size(), 2u);
  ASSERT_TRUE(inbox[0]->get_hash() == first->get_hash());
  ASSERT_TRUE(inbox[1]->get_hash() == second->get_hash());
  ASSERT_TRUE(encode(identity, admitted, access, {second, first}).move_as_ok()->get_hash() == root->get_hash());
  auto different = [&](td::Result<td::Ref<vm::Cell>> changed) {
    ASSERT_TRUE(changed.is_ok());
    ASSERT_TRUE(block::gen::t_UnoV2HostInput.validate_ref(4096, changed.ok()));
    ASSERT_TRUE(changed.ok()->get_hash() != root->get_hash());
  };
  different(encode(identity, admitted, access, {first}));
  auto empty = encode(identity, admitted, access, {}).move_as_ok();
  ASSERT_TRUE(block::gen::t_UnoV2HostInput.validate_ref(4096, empty));
  ASSERT_EQ(vm::load_cell_slice(empty).size_refs(), 3u);
  ASSERT_TRUE(empty->get_hash() != root->get_hash());
  auto changed_access = access;
  changed_access.reads[0].old_account_hash = std::nullopt;
  different(encode(identity, admitted, changed_access, {first, second}));
  changed_access = access;
  changed_access.writes.clear();
  different(encode(identity, admitted, changed_access, {first, second}));
  auto changed_identity = identity;
  changed_identity.height = 2;
  different(encode(changed_identity, admitted, access, {first, second}));
  block::CandidateAdmissionSession another(number(12), policy);
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(another.evaluate()));
  different(encode(identity, std::get<block::AdmittedInput>(another.evaluate()), access, {first, second}));
  changed_identity.vm_mode = 0;
  ASSERT_TRUE(encode(changed_identity, admitted, access, {first, second}).is_error());
  ASSERT_TRUE(encode(identity, admitted, access, {first, first}).is_error());
  ASSERT_TRUE(block::encode_workchain_host_input(identity, admitted, access, {first, second}, 2, 2, 1).is_error());
}

td::Ref<vm::Cell> inbound_transaction(td::Ref<vm::Cell> description, td::Ref<vm::Cell> ordinary_input = {}) {
  vm::CellBuilder messages;
  ASSERT_TRUE(messages.store_maybe_ref(ordinary_input));
  messages.store_long(0, 1);
  auto update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  return vm::CellBuilder().store_long(7, 4).store_zeroes(256).store_long(10, 64)
      .store_zeroes(256).store_long(0, 64).store_long(10, 32).store_zeroes(15)
      .store_long(2, 2).store_long(2, 2).store_ref(messages.finalize()).store_zeroes(5)
      .store_ref(update).store_ref(description).finalize();
}

}  // namespace

TEST(WorkchainBlock, ExtractExecutorFromShardState) {
  auto root = shard_fixture();
  auto bytes = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
  auto data = block::extract_workchain_engine_state(restored, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(data).fetch_ulong(64), 40u);
  ASSERT_TRUE(root->get_hash() == restored->get_hash());
  auto reject = [&](td::Ref<vm::Cell> state, td::Slice expected) {
    auto result = block::extract_workchain_engine_state(state, 2, td::Bits256::zero());
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), expected);
  };
  reject(shard_fixture(3), "block engine requires its own unsplit shard state");
  reject(shard_fixture(2, 2, true, 1, true), "block engine requires its own unsplit shard state");
  reject(shard_fixture(2, 2, true, 1, false, 1), "block engine requires its own unsplit shard state");
  reject(shard_fixture(2, 2, true, 0), "block workchain must contain exactly its executor account");
  reject(shard_fixture(2, 2, true, 2), "block workchain must contain exactly its executor account");
  reject(shard_fixture(2, 2, true, 1, false, 0, 40, true),
         "block workchain must contain exactly its executor account");
  reject(shard_fixture(2, 3), "invalid block executor account");
  reject(shard_fixture(2, 2, false), "block executor requires active state data without address rewriting");
  reject({}, "missing or invalid block workchain state identity");
  reject(number(0), "invalid block workchain shard state");
  auto wrong_address = block::extract_workchain_engine_state(root, 2, number(99)->get_hash().bits());
  ASSERT_TRUE(wrong_address.is_error());
  ASSERT_EQ(wrong_address.error().message(), "block workchain must contain exactly its executor account");
}

TEST(WorkchainBlock, CounterReplay) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(produced.new_engine_state).fetch_ulong(64), 42u);
  auto validated = block::replay_workchain_block(engine, in, produced).move_as_ok();
  ASSERT_TRUE(validated.new_engine_state->get_hash() == produced.new_engine_state->get_hash());
  auto previous = block::extract_workchain_engine_state(in.previous_shard_state, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(previous).fetch_ulong(64), 40u);
}

TEST(WorkchainBlock, CounterPayloadSurvivesBatchReplay) {
  // Wide unique leaves model account-cell storage, not private-note semantics.
  std::vector<td::Ref<vm::Cell>> layer;
  for (unsigned i = 0; i < (1u << 14); ++i) {
    layer.push_back(vm::CellBuilder().store_long(i, 64).store_zeroes(896).finalize());
  }
  while (layer.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(layer[i]).store_ref(layer[i + 1]).finalize());
    }
    layer = std::move(next);
  }
  auto payload = layer.front();
  std::size_t payload_loads = 0;
  auto usage = std::make_shared<vm::CellUsageTree>();
  usage->set_cell_load_callback([&](const vm::LoadedCell&) { ++payload_loads; });
  auto observed_payload = vm::UsageCell::create(payload, usage->root_ptr());
  // Prove the instrument observes loads, but neither hashing nor taking a
  // reference counts as reading the payload. Use a fresh tree for each phase.
  ASSERT_TRUE(observed_payload->get_hash() == payload->get_hash());
  ASSERT_EQ(payload_loads, 0u);
  vm::load_cell_slice(observed_payload);
  ASSERT_EQ(payload_loads, 1u);
  auto reset_observation = [&] {
    payload_loads = 0;
    usage = std::make_shared<vm::CellUsageTree>();
    usage->set_cell_load_callback([&](const vm::LoadedCell&) { ++payload_loads; });
    observed_payload = vm::UsageCell::create(payload, usage->root_ptr());
  };
  reset_observation();
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, observed_payload);
  const auto previous_hash = in.previous_shard_state->get_hash();
  CounterEngine engine({8, 1, 3}, 1, 2, CounterEngine::PayloadMode::PreserveReference);
  ASSERT_TRUE(CounterEngine().execute_block(in).is_error());
  ASSERT_TRUE(engine.execute_block(input()).is_error());
  auto effects = engine.execute_block(in).move_as_ok();
  auto result_state = vm::load_cell_slice(effects.new_engine_state);
  ASSERT_EQ(result_state.fetch_ulong(64), 42u);
  ASSERT_EQ(result_state.size_refs(), 1u);
  ASSERT_TRUE(result_state.fetch_ref()->get_hash() == payload->get_hash());
  ASSERT_EQ(payload_loads, 0u);

  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
  ASSERT_EQ(payload_loads, 0u);
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  ASSERT_EQ(cfg.size_limits.max_acc_state_cells, 65536u);
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  // Diagnostic only: do not require a future storage-stat optimization to
  // retain today's traversal cost. This fixture has no cached storage index.
  LOG(INFO) << "Counter payload reads: phase=prepare unique_tree_nodes=" << payload_loads;
  ASSERT_TRUE(tx.serialize(cfg));
  reset_observation();
  auto replay_input = in;
  replay_input.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, observed_payload);
  ASSERT_TRUE(replay_input.previous_shard_state->get_hash() == previous_hash);
  ASSERT_EQ(payload_loads, 0u);
  auto replayed = block::replay_workchain_batch_transaction(
      engine, replay_input, tx.root, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  LOG(INFO) << "Counter payload reads: phase=replay unique_tree_nodes=" << payload_loads;
  ASSERT_TRUE(replayed->get_hash() == tx.new_total_state->get_hash());
  auto wire = vm::std_boc_serialize(tx.new_data).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  ASSERT_TRUE(restored->get_hash() == tx.new_data->get_hash());
  vm::CellStorageStat stat;
  ASSERT_TRUE(stat.compute_used_storage(restored).is_ok());
  ASSERT_TRUE(stat.cells > 32767u);
  ASSERT_TRUE(stat.cells < cfg.size_limits.max_acc_state_cells);
  ASSERT_TRUE(wire.size() > (1u << 20));
  ASSERT_TRUE(in.previous_shard_state->get_hash() == previous_hash);
  LOG(INFO) << "Counter payload batch: wrapper cells=" << stat.cells << " boc bytes=" << wire.size();
}

TEST(WorkchainBlock, StorageParticipantNativeWrapper) {
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto key = td::Bits256::zero();
  block::Account account(2, key.bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(key), 10, false));
  auto old = account.total_state->get_hash();
  auto records = block::build_workchain_participant_records(key, key, {key}, 1).move_as_ok();
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tx.prepare_workchain_storage_participant(records[0], number(77), cfg).is_ok());
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(4096, tx.root));
  ASSERT_TRUE(block::tlb::t_Transaction.validate_ref(4096, tx.root));
  ASSERT_TRUE(!tx.storage_phase && !tx.compute_phase && !tx.action_phase && !tx.credit_phase && !tx.bounce_phase);
  ASSERT_TRUE(tx.balance == account.balance);
  ASSERT_TRUE(tx.balance == block::CurrencyCollection(1000));
  ASSERT_TRUE(tx.total_fees.is_zero() && tx.out_msgs.empty());
  ASSERT_TRUE(tx.new_data->get_hash() == number(77)->get_hash());
  ASSERT_TRUE(account.total_state->get_hash() == old); // No account commit during preparation.
  block::gen::Transaction::Record tr;
  ASSERT_TRUE(tlb::unpack_cell(tx.root, tr));
  ASSERT_TRUE(block::validate_transaction_execution_scope(tr.description, block::WorkchainExecutionScope::BlockTransition).is_error());
  ASSERT_TRUE(block::validate_transaction_execution_scope(tr.description, block::WorkchainExecutionScope::AccountCompute).is_error());
  auto parsed = vm::load_cell_slice(tr.description);
  ASSERT_EQ(parsed.fetch_ulong(4), 10u);
  ASSERT_TRUE(parsed.fetch_ref()->get_hash() == records[0]->get_hash());
  auto other_key = key;
  other_key.as_slice().back() = 1;
  auto wrong_records = block::build_workchain_participant_records(key, key, {other_key}, 1).move_as_ok();
  block::transaction::Transaction wrong_account(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(wrong_account.prepare_workchain_storage_participant(wrong_records[0], number(77), cfg).is_error());
  block::transaction::Transaction tampered(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tampered.prepare_workchain_storage_participant(records[0], number(77), cfg).is_ok());
  tampered.new_code = number(123);
  ASSERT_TRUE(!tampered.serialize(cfg));
  block::transaction::Transaction moved(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  moved.balance = block::CurrencyCollection(1);
  ASSERT_TRUE(moved.prepare_workchain_storage_participant(records[0], number(77), cfg).is_error());
  block::transaction::Transaction old_version(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  cfg.global_version = 15;
  ASSERT_TRUE(old_version.prepare_workchain_storage_participant(records[0], number(77), cfg).is_error());
  ASSERT_TRUE(!old_version.serialize(cfg));
  // Unlike the rejected preparation above, every case reaches the prepared
  // storage-only guard with an otherwise serializable nonzero account.
  for (unsigned field = 0; field < 11; ++field) {
    block::SerializeConfig current;
    current.global_version = 16;
    block::transaction::Transaction changed(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
    ASSERT_TRUE(changed.prepare_workchain_storage_participant(records[0], number(77), current).is_ok());
    switch (field) {
      case 0: current.global_version = 15; break;
      case 1: changed.new_library = number(123); break;
      case 2: changed.new_tick = !account.tick; break;
      case 3: changed.new_tock = !account.tock; break;
      case 4: changed.new_fixed_prefix_length = 1; break;
      case 5: changed.new_addr_rewrite_length = 0; break;
      case 6: changed.force_remove_anycast_address = true; break;
      case 7: changed.last_paid = 123; break;
      case 8: changed.due_payment = td::make_refint(1); break;
      case 9:
        changed.my_addr = vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3)
            .store_long(2, 8).store_bits(other_key.bits(), 256).finalize());
        break;
      case 10: changed.my_addr.clear(); break;
    }
    ASSERT_TRUE(!changed.serialize(current));
  }
  // Cached serialization must not bypass the storage-only checks either.
  cfg.global_version = 16;
  tx.new_code = number(123);
  ASSERT_TRUE(!tx.serialize(cfg));
}

TEST(WorkchainBlock, StorageOverlayNativeCommit) {
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 3), state));
  const auto original = state.accounts->get_hash();
  vm::AugmentedDictionary old(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto a = td::Bits256::zero();
  td::Bits256 b(number(1)->get_hash().bits());
  td::Bits256 untouched(number(2)->get_hash().bits());
  std::vector<block::WorkchainStorageWrite> writes;
  for (auto key : {a, b}) {
    block::tlb::ShardAccount::Record entry;
    ASSERT_TRUE(entry.unpack(old.lookup(key)));
    writes.push_back({key, td::Bits256(entry.account->get_hash().bits()), number(77)});
  }
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = true;
  auto built = block::build_workchain_storage_overlay(state.accounts, 2, 10, 20, a, b, writes, 2, cfg);
  ASSERT_TRUE(built.is_ok());
  auto result = built.move_as_ok();
  ASSERT_EQ(result.end_lt, 22u);
  ASSERT_TRUE(state.accounts->get_hash() == original);
  vm::AugmentedDictionary next(vm::load_cell_slice_ref(result.accounts), 256, block::tlb::aug_ShardAccounts);
  vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(result.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
  ASSERT_TRUE(old.lookup(untouched)->contents_equal(*next.lookup(untouched)));
  ASSERT_TRUE(blocks.lookup(untouched).is_null());
  for (auto key : {a, b}) {
    block::Account updated(2, key.bits());
    ASSERT_TRUE(updated.unpack(next.lookup(key), 10, false));
    ASSERT_EQ(updated.last_trans_lt_, 21u);
    ASSERT_EQ(updated.last_trans_end_lt_, 22u);
    ASSERT_TRUE(updated.data->get_hash() == number(77)->get_hash());
    auto block_cell = vm::CellBuilder().append_cellslice(*blocks.lookup(key)).finalize();
    ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(4096, block_cell));
    ASSERT_TRUE(block::tlb::t_AccountBlock.validate_ref(4096, block_cell));
    block::gen::AccountBlock::Record ab;
    ASSERT_TRUE(tlb::unpack_cell(block_cell, ab));
    ASSERT_TRUE(ab.account_addr == key);
    vm::AugmentedDictionary transactions(vm::DictNonEmpty(), ab.transactions, 64,
                                         block::tlb::aug_AccountTransactions);
    auto transaction_root = transactions.lookup_ref(td::BitArray<64>(21u));
    block::gen::Transaction::Record transaction;
    ASSERT_TRUE(tlb::unpack_cell(transaction_root, transaction));
    ASSERT_TRUE(transaction.account_addr == key);
    ASSERT_EQ(transaction.lt, 21u);
    ASSERT_EQ(transaction.prev_trans_lt, 1u);
    ASSERT_TRUE(transaction.prev_trans_hash == td::Bits256::zero());
    ASSERT_TRUE(updated.last_trans_hash_ == transaction_root->get_hash().bits());
    auto hashes = vm::load_cell_slice(ab.state_update);
    ASSERT_EQ(hashes.fetch_ulong(8), 0x72u);
    td::Bits256 before, after;
    ASSERT_TRUE(hashes.fetch_bits_to(before) && hashes.fetch_bits_to(after));
    block::tlb::ShardAccount::Record prior;
    ASSERT_TRUE(prior.unpack(old.lookup(key)));
    ASSERT_TRUE(before == prior.account->get_hash().bits());
    ASSERT_TRUE(after == updated.total_state->get_hash().bits());
  }
  auto repeat = block::build_workchain_storage_overlay(state.accounts, 2, 10, 20, a, b, writes, 2, cfg).move_as_ok();
  ASSERT_TRUE(repeat.accounts->get_hash() == result.accounts->get_hash());
  ASSERT_TRUE(repeat.account_blocks->get_hash() == result.account_blocks->get_hash());
  auto invalid_data = writes;
  invalid_data[1].data.clear();
  // Failure after committing the first PRIVATE account must publish no roots.
  ASSERT_TRUE(block::build_workchain_storage_overlay(state.accounts, 2, 10, 20, a, b, invalid_data, 2, cfg).is_error());
  ASSERT_TRUE(state.accounts->get_hash() == original);
  // A false old-state declaration is rejected before preparing transactions.
  writes[1].old_account_hash = a;
  ASSERT_TRUE(block::build_workchain_storage_overlay(state.accounts, 2, 10, 20, a, b, writes, 2, cfg).is_error());
  ASSERT_TRUE(state.accounts->get_hash() == original);
  ASSERT_TRUE(old.lookup(untouched)->contents_equal(*next.lookup(untouched)));
}

TEST(WorkchainBlock, ReplayStorageCachePreservesValidation) {
  std::vector<td::Ref<vm::Cell>> layer;
  for (unsigned i = 0; i < 256; ++i) layer.push_back(number(i));
  while (layer.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(layer[i]).store_ref(layer[i + 1]).finalize());
    }
    layer = std::move(next);
  }
  auto payload = layer.front();
  CounterEngine engine({8, 1, 3}, 1, 2, CounterEngine::PayloadMode::PreserveReference);
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  cfg.extra_currency_v2 = true;
  cfg.store_storage_dict_hash = true;
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, payload);
  auto unpack_account = [&](const td::Ref<vm::Cell>& root, block::Account& account) {
    block::gen::ShardStateUnsplit::Record state;
    ASSERT_TRUE(tlb::unpack_cell(root, state));
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
  };
  block::Account first_account(2, td::Bits256::zero().bits());
  unpack_account(in.previous_shard_state, first_account);
  block::transaction::Transaction first(first_account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(first.prepare_workchain_batch(in, engine.execute_block(in).move_as_ok(), cfg).is_ok());
  ASSERT_TRUE(first.serialize(cfg));
  ASSERT_TRUE(first.new_storage_dict_hash);
  auto previous_index = first.new_account_storage_stat.value().get_dict_root().move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  vm::CellBuilder entry;
  entry.store_ref(first.new_total_state).store_bits(first.root->get_hash().bits(), 256).store_long(first.start_lt, 64);
  ASSERT_TRUE(accounts.set_builder(td::Bits256::zero(), entry));
  state.accounts = accounts.get_wrapped_dict_root();
  state.gen_lt = first.end_lt;
  state.gen_utime = 10;
  ASSERT_TRUE(tlb::pack_cell(in.previous_shard_state, state));
  block::Account second_account(2, td::Bits256::zero().bits());
  unpack_account(in.previous_shard_state, second_account);
  block::transaction::Transaction second(second_account, block::transaction::Transaction::tr_workchain_batch, 20, 10);
  ASSERT_TRUE(second.prepare_workchain_batch(in, engine.execute_block(in).move_as_ok(), cfg).is_ok());
  ASSERT_TRUE(second.serialize(cfg));

  auto run = [&](td::Ref<vm::Cell> cached, bool expect_hit, bool valid_claim) {
    std::size_t loads = 0, lookups = 0, remembered = 0;
    auto usage = std::make_shared<vm::CellUsageTree>();
    usage->set_cell_load_callback([&](const vm::LoadedCell&) { ++loads; });
    auto observed = in;
    observed.previous_shard_state = vm::UsageCell::create(in.previous_shard_state, usage->root_ptr());
    block::WorkchainReplayStorageCache cache{
        [&](const td::Bits256& hash) {
          ++lookups;
          ASSERT_TRUE(hash == first.new_storage_dict_hash.value());
          return cached;
        },
        [&](td::Ref<vm::Cell> root, td::uint32 cells) {
          ++remembered;
          ASSERT_TRUE(td::Bits256(root->get_hash().bits()) == second.new_storage_dict_hash.value());
          ASSERT_EQ(cells, second.new_storage_used.cells);
        }};
    auto claimed = second.root;
    if (!valid_claim) {
      block::gen::Transaction::Record wrong;
      ASSERT_TRUE(tlb::unpack_cell(claimed, wrong));
      wrong.prev_trans_hash.set_zero();
      td::Ref<vm::Cell> messages;
      ASSERT_TRUE(tlb::pack_cell(messages, wrong.r1));
      claimed = vm::CellBuilder().store_long(7, 4).store_bits(wrong.account_addr.bits(), 256)
          .store_long(wrong.lt, 64).store_bits(wrong.prev_trans_hash.bits(), 256)
          .store_long(wrong.prev_trans_lt, 64).store_long(wrong.now, 32).store_long(wrong.outmsg_cnt, 15)
          .store_long(wrong.orig_status, 2).store_long(wrong.end_status, 2).store_ref(messages)
          .append_cellslice(wrong.total_fees).store_ref(wrong.state_update).store_ref(wrong.description).finalize();
      ASSERT_TRUE(block::gen::t_Transaction.validate_ref(4096, claimed));
    }
    auto replayed = block::replay_workchain_batch_transaction(
        engine, observed, claimed, 2, td::Bits256::zero(), 20, 10, cfg, nullptr, &cache);
    ASSERT_EQ(lookups, 1u);
    ASSERT_EQ(remembered, valid_claim ? 1u : 0u);
    ASSERT_EQ(replayed.is_ok(), valid_claim);
    if (valid_claim) ASSERT_TRUE(replayed.ok()->get_hash() == second.new_total_state->get_hash());
    LOG(INFO) << "Replay storage cache: hit=" << expect_hit << " valid_claim=" << valid_claim << " reads=" << loads;
    // A hit must avoid the 511-node payload; a miss remains the reference path.
    if (expect_hit) ASSERT_TRUE(loads < 100u);
    return loads;
  };
  auto cold_loads = run({}, false, true);
  ASSERT_TRUE(run(previous_index, true, true) < cold_loads);
  ASSERT_EQ(run(number(999), false, true), cold_loads);
  run(previous_index, true, false);
}

TEST(WorkchainBlock, CanonicalInboundList) {
  auto first = inbound_envelope(3);
  auto second = inbound_envelope(4);
  auto encoded = block::encode_workchain_batch_inbound({first, second}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBatchInbound.validate_ref(10000, encoded));
  auto wire = vm::std_boc_serialize(encoded).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto decoded = block::decode_workchain_batch_inbound(restored).move_as_ok();
  ASSERT_EQ(decoded.size(), 2u);
  ASSERT_TRUE(decoded[0]->get_hash() == first->get_hash());
  ASSERT_TRUE(decoded[1]->get_hash() == second->get_hash());
  auto reversed = block::encode_workchain_batch_inbound({second, first}).move_as_ok();
  ASSERT_TRUE(reversed->get_hash() == encoded->get_hash());
  // Increasing emitted LT must not disguise a duplicate original message.
  auto duplicate = block::encode_workchain_batch_inbound({first, inbound_envelope(3, 0, 5)});
  ASSERT_TRUE(duplicate.is_error());
  ASSERT_EQ(duplicate.error().message(), "duplicate batch inbound message");
  ASSERT_TRUE(block::encode_workchain_batch_inbound({number(0)}).is_error());
  ASSERT_TRUE(block::encode_workchain_batch_inbound({}).is_error());
  ASSERT_TRUE(block::encode_workchain_batch_inbound({{}}).is_error());
  auto delayed = inbound_envelope(1, 0, 5);
  auto delayed_root = block::encode_workchain_batch_inbound({delayed, second}).move_as_ok();
  auto delayed_list = block::decode_workchain_batch_inbound(delayed_root).move_as_ok();
  ASSERT_TRUE(delayed_list[0]->get_hash() == second->get_hash());
  ASSERT_TRUE(delayed_list[1]->get_hash() == delayed->get_hash());
  auto same_lt = inbound_envelope(3, 1);
  block::tlb::MsgEnvelope::Record_std a, b;
  ASSERT_TRUE(tlb::unpack_cell(first, a) && tlb::unpack_cell(same_lt, b));
  auto equal_root = block::encode_workchain_batch_inbound({first, same_lt}).move_as_ok();
  auto equal_list = block::decode_workchain_batch_inbound(equal_root).move_as_ok();
  ASSERT_TRUE(equal_list[0]->get_hash() == (a.msg->get_hash() < b.msg->get_hash() ? first : same_lt)->get_hash());
  auto mismatched_count = vm::CellBuilder().store_long(0x57494e31, 32).store_long(3, 15)
      .store_long(1, 1).store_ref(vm::load_cell_slice(encoded).prefetch_ref()).finalize();
  auto mismatch = block::decode_workchain_batch_inbound(mismatched_count);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "invalid or noncanonical batch inbound entries");
  vm::Dictionary gap(256);
  ASSERT_TRUE(gap.set_ref(number(99)->get_hash().bits(), 256, first));
  vm::CellBuilder gap_root;
  gap_root.store_long(0x57494e31, 32).store_long(1, 15);
  ASSERT_TRUE(std::move(gap).append_dict_to_bool(gap_root));
  auto gap_result = block::decode_workchain_batch_inbound(gap_root.finalize());
  ASSERT_TRUE(gap_result.is_error());
  ASSERT_EQ(gap_result.error().message(), "invalid or noncanonical batch inbound entries");
}

TEST(WorkchainBlock, InboundCommitmentAndMembership) {
  auto in = input();
  auto first = inbound_envelope(3);
  auto second = inbound_envelope(4);
  in.inbound_messages = block::encode_workchain_batch_inbound({first, second}).move_as_ok();
  auto encoded_input = block::encode_workchain_block_input(in).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBlockInput.validate_ref(10000, encoded_input));
  block::gen::WorkchainBlockInput::Record_workchain_block_input_v2 input_record;
  ASSERT_TRUE(tlb::unpack_cell(encoded_input, input_record));
  ASSERT_TRUE(input_record.inbound_messages->get_hash() == in.inbound_messages->get_hash());
  CounterEngine engine;
  auto effects = engine.execute_block(in).move_as_ok();
  auto description = block::make_workchain_batch_description(in, effects).move_as_ok();
  auto root = block::encode_workchain_batch_description(description);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, root));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, root));
  ASSERT_TRUE(block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::BlockTransition).is_ok());
  ASSERT_TRUE(block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::AccountCompute).is_error());
  auto decoded = block::decode_workchain_batch_description(root).move_as_ok();
  ASSERT_TRUE(decoded.inbound_messages->get_hash() == in.inbound_messages->get_hash());
  ASSERT_TRUE(block::replay_workchain_batch(engine, in, root).is_ok());
  auto forged = description;
  forged.inbound_messages = block::encode_workchain_batch_inbound({inbound_envelope(5)}).move_as_ok();
  auto wrong = block::replay_workchain_batch(engine, in, block::encode_workchain_batch_description(forged));
  ASSERT_TRUE(wrong.is_error());
  ASSERT_EQ(wrong.error().message(), "batch transaction commitments differ from replay");
  auto altered_input = in;
  altered_input.inbound_messages = forged.inbound_messages;
  auto wrong_input = block::replay_workchain_batch(engine, altered_input, root);
  ASSERT_TRUE(wrong_input.is_error());
  ASSERT_EQ(wrong_input.error().message(), "batch transaction input commitment differs from authenticated context");
  auto transaction = inbound_transaction(root);
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(10000, transaction));
  ASSERT_TRUE(block::tlb::t_Transaction.validate_ref(10000, transaction));
  block::tlb::MsgEnvelope::Record_std first_record, second_record, other;
  ASSERT_TRUE(tlb::unpack_cell(first, first_record));
  ASSERT_TRUE(tlb::unpack_cell(second, second_record));
  ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(5), other));
  ASSERT_TRUE(block::is_transaction_in_msg(transaction, first_record.msg));
  ASSERT_TRUE(block::is_transaction_in_msg(transaction, second_record.msg));
  ASSERT_TRUE(!block::is_transaction_in_msg(transaction, other.msg));
  ASSERT_TRUE(!block::is_transaction_in_msg(transaction, {}));
  ASSERT_TRUE(!block::is_transaction_in_msg(inbound_transaction(root, first_record.msg), first_record.msg));
  auto malformed = forged;
  malformed.inbound_messages = number(0);
  auto bad = block::encode_workchain_batch_description(malformed);
  ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, bad));
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, bad));
  ASSERT_TRUE(!block::is_transaction_in_msg(inbound_transaction(bad), other.msg));
  // A membership query is not acceptance: native credit requires host version.
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  auto status = tx.prepare_workchain_batch(in, effects, block::SerializeConfig{});
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.message(), "batch incoming credit requires activated host version");
  ASSERT_TRUE(account.balance.is_zero());
  ASSERT_TRUE(!tx.serialize(block::SerializeConfig{}));
}

TEST(WorkchainBlock, ExecutorWitnessEncoding) {
  CounterEngine engine;
  auto in = input();
  auto effects = engine.execute_block(in).move_as_ok();
  auto encoded_effects = block::encode_workchain_block_result(effects).move_as_ok();
  block::WorkchainExecutorState state{effects.new_engine_state, in.candidate, encoded_effects};
  auto root = block::encode_workchain_executor_state(state).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainExecutorState.validate_ref(10000, root));
  auto wire = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto decoded = block::decode_workchain_executor_state(restored).move_as_ok();
  ASSERT_TRUE(decoded.engine_state->get_hash() == state.engine_state->get_hash());
  ASSERT_TRUE(decoded.candidate->get_hash() == state.candidate->get_hash());
  ASSERT_TRUE(decoded.effects->get_hash() == state.effects->get_hash());
  auto missing = state;
  missing.candidate = {};
  ASSERT_TRUE(block::encode_workchain_executor_state(missing).is_error());
  auto bad = vm::CellBuilder().store_long(0x57424531, 32).store_long(1, 1).store_ref(number(99))
      .store_ref(vm::load_cell_slice(root).prefetch_ref(1)).finalize();
  ASSERT_TRUE(block::gen::t_WorkchainExecutorState.validate_ref(10000, bad));
  auto mismatch = block::decode_workchain_executor_state(bad);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "executor state differs from stored batch effects");
  auto missing_witness = vm::CellBuilder().store_long(0x57424531, 32).store_long(1, 1)
      .store_ref(state.engine_state).finalize();
  auto absent = block::decode_workchain_executor_state(missing_witness);
  ASSERT_TRUE(absent.is_error());
  ASSERT_EQ(absent.error().message(), "invalid workchain executor state references");
  auto initial = block::encode_workchain_executor_state({number(40), {}, {}}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainExecutorState.validate_ref(10000, initial));
  ASSERT_TRUE(block::decode_workchain_executor_state(initial).move_as_ok().candidate.is_null());
}

TEST(WorkchainBlock, BatchAccountCommitAndReload) {
  CounterEngine engine;
  auto in = input();
  auto effects = engine.execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto load = [&]() {
    block::Account account(2, td::Bits256::zero().bits());
    ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
    return account;
  };
  block::SerializeConfig cfg;
  auto account = load();
  auto old_account = account.total_state;
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(account.total_state->get_hash() == old_account->get_hash());
  block::gen::Transaction::Record record;
  ASSERT_TRUE(tlb::unpack_cell(tx.root, record));
  ASSERT_EQ(record.lt, 10u);
  ASSERT_EQ(record.now, 10u);
  ASSERT_EQ(record.outmsg_cnt, 0);
  ASSERT_TRUE(block::replay_workchain_batch(engine, in, record.description).is_ok());
  auto replayed_account = block::replay_workchain_batch_transaction(
      engine, in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(replayed_account->get_hash() == tx.new_total_state->get_hash());
  ASSERT_TRUE(account.total_state->get_hash() == old_account->get_hash());
  for (int mutation = 0; mutation < 8; ++mutation) {
    auto changed = record;
    if (mutation == 0) changed.prev_trans_hash = number(99)->get_hash().bits();
    if (mutation == 1) changed.prev_trans_lt = 5;
    if (mutation == 2) changed.now = 11;
    if (mutation == 3) changed.lt = 11;
    if (mutation == 4) changed.total_fees = vm::CellBuilder().store_long(1, 4).store_long(1, 8)
        .store_long(0, 1).as_cellslice_ref();
    if (mutation == 5) changed.orig_status = block::gen::AccountStatus::acc_state_frozen;
    if (mutation == 6) changed.state_update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
    if (mutation == 7) changed.account_addr = number(99)->get_hash().bits();
    td::Ref<vm::Cell> messages;
    ASSERT_TRUE(tlb::pack_cell(messages, changed.r1));
    auto altered = vm::CellBuilder().store_long(7, 4).store_bits(changed.account_addr.bits(), 256)
        .store_long(changed.lt, 64).store_bits(changed.prev_trans_hash.bits(), 256)
        .store_long(changed.prev_trans_lt, 64).store_long(changed.now, 32).store_long(changed.outmsg_cnt, 15)
        .store_long(changed.orig_status, 2).store_long(changed.end_status, 2).store_ref(messages)
        .append_cellslice(changed.total_fees).store_ref(changed.state_update).store_ref(changed.description).finalize();
    ASSERT_TRUE(block::gen::t_Transaction.validate_ref(4096, altered));
    auto rejected = block::replay_workchain_batch_transaction(
        engine, in, altered, 2, td::Bits256::zero(), 10, 10, cfg);
    ASSERT_TRUE(rejected.is_error());
    auto expected = mutation == 2 || mutation == 3 || mutation == 7
        ? td::Slice("batch transaction identity or time differs from host context")
        : td::Slice("batch transaction wrapper differs from replay");
    ASSERT_EQ(rejected.error().message(), expected);
  }
  auto committed = tx.commit(account);
  ASSERT_TRUE(committed.not_null());
  ASSERT_TRUE(account.balance.is_zero());
  ASSERT_TRUE(account.storage_used.cells > 0);
  ASSERT_EQ(account.last_trans_lt_, 10u);
  ASSERT_EQ(account.last_trans_end_lt_, 11u);
  auto stored = block::decode_workchain_executor_state(account.data).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(stored.engine_state).fetch_ulong(64), 42u);
  ASSERT_TRUE(stored.candidate->get_hash() == in.candidate->get_hash());
  ASSERT_TRUE(stored.effects->get_hash() == block::encode_workchain_block_result(effects).move_as_ok()->get_hash());
  vm::CellBuilder account_block;
  ASSERT_TRUE(account.create_account_block(account_block));
  auto block_root = account_block.finalize();
  ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(10000, block_root));
  ASSERT_TRUE(block::tlb::t_AccountBlock.validate_ref(10000, block_root));
  vm::CellBuilder entry;
  entry.store_ref(account.total_state).store_bits(account.last_trans_hash_.bits(), 256)
      .store_long(account.last_trans_lt_, 64);
  ASSERT_TRUE(accounts.set_builder(td::Bits256::zero(), entry));
  state.accounts = accounts.get_wrapped_dict_root();
  state.seq_no = 2;
  state.gen_lt = 11;
  state.gen_utime = 10;
  td::Ref<vm::Cell> next;
  ASSERT_TRUE(tlb::pack_cell(next, state));
  auto wire = vm::std_boc_serialize(next).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto new_data = block::extract_workchain_engine_state(restored, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(new_data).fetch_ulong(64), 42u);
  block::gen::ShardStateUnsplit::Record recovered_state;
  ASSERT_TRUE(tlb::unpack_cell(restored, recovered_state));
  vm::AugmentedDictionary recovered_accounts(vm::load_cell_slice_ref(recovered_state.accounts), 256,
                                              block::tlb::aug_ShardAccounts);
  block::Account recovered_account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(recovered_account.unpack(recovered_accounts.lookup(td::Bits256::zero()), 10, false));
  auto recovered_witness = block::decode_workchain_executor_state(recovered_account.data).move_as_ok();
  auto recovered_input = in;
  recovered_input.candidate = recovered_witness.candidate;
  auto replayed_from_storage = block::replay_workchain_batch_transaction(
      engine, recovered_input, committed, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(replayed_from_storage->get_hash() == recovered_account.total_state->get_hash());
  ASSERT_TRUE(recovered_witness.effects->get_hash() == stored.effects->get_hash());
  block::WorkchainBlockReplayContext context{in.previous_shard_state, in.configuration, in.finality_context};
  auto state_replay = block::replay_workchain_batch_state(
      engine, context, restored, committed, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(state_replay->get_hash() == recovered_account.total_state->get_hash());
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  auto resolved = registry.resolve_block(descriptor, configuration).move_as_ok();
  ASSERT_TRUE(block::replay_resolved_workchain_batch_state(
      resolved, context, restored, committed, 10, 10, cfg).is_ok());
  ASSERT_TRUE(block::replay_resolved_workchain_account_block(
      resolved, context, restored, block_root, 10, cfg).is_ok());
  for (int mutation = 0; mutation < 3; ++mutation) {
    block::gen::AccountBlock::Record altered;
    ASSERT_TRUE(tlb::unpack_cell(block_root, altered));
    if (mutation == 0) altered.account_addr = number(99)->get_hash().bits();
    if (mutation == 1) altered.state_update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
    if (mutation == 2) {
      vm::AugmentedDictionary transactions(vm::DictNonEmpty(), altered.transactions, 64,
                                             block::tlb::aug_AccountTransactions);
      ASSERT_TRUE(transactions.set_ref(td::BitArray<64>{11LL}, committed, vm::Dictionary::SetMode::Add));
      altered.transactions = vm::load_cell_slice_ref(transactions.get_root_cell());
    }
    td::Ref<vm::Cell> altered_root;
    ASSERT_TRUE(tlb::pack_cell(altered_root, altered));
    ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(4096, altered_root));
    auto rejected = block::replay_resolved_workchain_account_block(
        resolved, context, restored, altered_root, 10, cfg);
    ASSERT_TRUE(rejected.is_error());
    const td::Slice expected[] = {"AccountBlock differs from configured executor identity",
                                  "AccountBlock state update differs from its batch transaction",
                                  "block executor requires exactly one batch transaction"};
    ASSERT_EQ(rejected.error().message(), expected[mutation]);
  }
  resolved.policy.limits.wire_bytes = 7;
  auto limited = block::replay_resolved_workchain_batch_state(
      resolved, context, restored, committed, 10, 10, cfg);
  ASSERT_TRUE(limited.is_error());
  ASSERT_EQ(limited.error().message(), "block execution exceeds configured resource limits");
  block::gen::ShardStateUnsplit::Record original_state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, original_state));
  vm::AugmentedDictionary original_accounts(vm::load_cell_slice_ref(original_state.accounts), 256,
                                             block::tlb::aug_ShardAccounts);
  for (int mutation = 0; mutation < 3; ++mutation) {
    block::Account altered_account(2, td::Bits256::zero().bits());
    ASSERT_TRUE(altered_account.unpack(original_accounts.lookup(td::Bits256::zero()), 10, false));
    auto altered_effects = effects;
    auto altered_input = in;
    if (mutation == 1) altered_effects.receipts = number(99);
    if (mutation == 2) altered_input.candidate = number(3);
    block::transaction::Transaction altered_tx(
        altered_account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
    auto prepared = altered_tx.prepare_workchain_batch(altered_input, altered_effects, cfg);
    ASSERT_TRUE(prepared.is_ok());
    ASSERT_TRUE(altered_tx.serialize(cfg));
    vm::CellBuilder altered_entry;
    altered_entry.store_ref(altered_tx.new_total_state)
        .store_bits((mutation == 0 ? number(99)->get_hash() : committed->get_hash()).bits(), 256)
        .store_long(10, 64);
    vm::AugmentedDictionary altered_accounts(256, block::tlb::aug_ShardAccounts);
    ASSERT_TRUE(altered_accounts.set_builder(td::Bits256::zero(), altered_entry));
    auto altered_state = recovered_state;
    altered_state.accounts = altered_accounts.get_wrapped_dict_root();
    td::Ref<vm::Cell> altered_root;
    ASSERT_TRUE(tlb::pack_cell(altered_root, altered_state));
    auto rejected = block::replay_workchain_batch_state(
        engine, context, altered_root, committed, 2, td::Bits256::zero(), 10, 10, cfg);
    ASSERT_TRUE(rejected.is_error());
    const td::Slice expected[] = {"claimed executor transaction link differs from batch",
                                  "claimed executor account differs from batch replay",
                                  "batch transaction input commitment differs from authenticated context"};
    ASSERT_EQ(rejected.error().message(), expected[mutation]);
  }
}

TEST(WorkchainBlock, ResolvedBatchStaging) {
  auto in = input();
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  auto resolved = registry.resolve_block(descriptor, configuration).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  auto original = account.total_state;
  block::SerializeConfig cfg;
  auto staged = block::prepare_resolved_workchain_batch_transaction(resolved, in, account, 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(staged->root.not_null());
  ASSERT_TRUE(account.total_state->get_hash() == original->get_hash());
  ASSERT_TRUE(account.transactions.empty());
  auto replayed = block::replay_workchain_batch_transaction(
      *resolved.executor, in, staged->root, 2, td::Bits256::zero(), 10, 10, cfg).move_as_ok();
  ASSERT_TRUE(replayed->get_hash() == staged->new_total_state->get_hash());
  auto early = block::prepare_resolved_workchain_batch_transaction(resolved, in, account, 1, 10, cfg);
  ASSERT_TRUE(early.is_error());
  ASSERT_EQ(early.error().message(), "batch staging logical time differs from requested time");
  block::Account other(2, number(99)->get_hash().bits());
  auto wrong = block::prepare_resolved_workchain_batch_transaction(resolved, in, other, 10, 10, cfg);
  ASSERT_TRUE(wrong.is_error());
  ASSERT_EQ(wrong.error().message(), "batch staging account differs from configured executor");
  resolved.policy.limits.wire_bytes = 7;
  auto limited = block::prepare_resolved_workchain_batch_transaction(resolved, in, account, 10, 10, cfg);
  ASSERT_TRUE(limited.is_error());
  ASSERT_EQ(limited.error().message(), "block execution exceeds configured resource limits");
  ASSERT_TRUE(account.total_state->get_hash() == original->get_hash());
  ASSERT_TRUE(account.transactions.empty());
}

TEST(WorkchainBlock, UsedNullifierGrowthReachesNativeAccountLimit) {
  std::mt19937 random(91);
  std::vector<td::Bits256> keys(32768);
  for (auto& key : keys) {
    for (auto& byte : key.as_slice()) {
      byte = static_cast<char>(random());
    }
  }
  auto in = input();
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  ASSERT_EQ(cfg.size_limits.max_acc_state_cells, 65536u);
  auto fits = [&](std::size_t count) {
    auto used = uno_workchain::UsedNullifiers{}.with_used(
        std::vector<td::Bits256>(keys.begin(), keys.begin() + count)).move_as_ok();
    auto effects = CounterEngine().execute_block(in).move_as_ok();
    // Use the real persistent used-set representation as host payload. This
    // measures account admission, not a complete private-transfer execution.
    effects.new_engine_state = used.root();
    block::gen::ShardStateUnsplit::Record state;
    ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    block::Account account(2, td::Bits256::zero().bits());
    ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
    const auto original = account.total_state->get_hash();
    block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
    auto result = tx.prepare_workchain_batch(in, effects, cfg);
    ASSERT_TRUE(account.total_state->get_hash() == original);
    if (result.is_error()) {
      ASSERT_EQ(result.error().code(), block::AccountStorageStat::errorcode_limits_exceeded);
      ASSERT_TRUE(tx.new_data->get_hash() == account.data->get_hash());
      ASSERT_TRUE(!tx.serialize(cfg));
      return false;
    }
    ASSERT_TRUE(tx.serialize(cfg));
    return true;
  };
  std::size_t lower = 32000, upper = keys.size();
  ASSERT_TRUE(fits(lower));
  ASSERT_TRUE(!fits(upper));
  while (upper - lower > 1) {
    auto middle = lower + (upper - lower) / 2;
    if (fits(middle)) lower = middle;
    else upper = middle;
  }
  ASSERT_TRUE(fits(lower));
  ASSERT_TRUE(!fits(upper));
  LOG(INFO) << "Used-nullifier host capacity: accepted=" << lower << " rejected=" << upper
            << " account_cell_limit=" << cfg.size_limits.max_acc_state_cells
            << " scope=used-set-only payload plus host wrapper; not complete UNO state";
}

TEST(WorkchainBlock, BatchExecutorCellBudgetIncludesFullWrapper) {
  auto in = input();
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  // A balanced, uniquely labelled tree avoids both depth-limit rejection and
  // accidental deduplication. This is host test state, not a private-note tree.
  std::vector<td::Ref<vm::Cell>> layer;
  for (unsigned i = 0; i < (1u << 15); ++i) {
    layer.push_back(number(i));
  }
  while (layer.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < layer.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(layer[i]).store_ref(layer[i + 1]).finalize());
    }
    layer = std::move(next);
  }
  effects.new_engine_state = layer.front();
  vm::CellStorageStat payload_stat;
  ASSERT_TRUE(payload_stat.compute_used_storage(effects.new_engine_state).is_ok());
  ASSERT_EQ(payload_stat.cells, 65535u);
  auto encoded = block::encode_workchain_block_result(effects).move_as_ok();
  auto wrapper = block::encode_workchain_executor_state({effects.new_engine_state, in.candidate, encoded}).move_as_ok();
  vm::CellStorageStat wrapper_stat;
  ASSERT_TRUE(wrapper_stat.compute_used_storage(wrapper).is_ok());
  ASSERT_TRUE(wrapper_stat.cells > 65536u);
  ASSERT_TRUE(wrapper_stat.cells < std::numeric_limits<td::uint32>::max());

  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial));
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  ASSERT_EQ(cfg.size_limits.max_acc_state_cells, 65536u);
  const auto original = account.total_state->get_hash();
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  auto rejected = tx.prepare_workchain_batch(in, effects, cfg);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.error().code(), block::AccountStorageStat::errorcode_limits_exceeded);
  ASSERT_TRUE(tx.new_data->get_hash() == account.data->get_hash());
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(tx.out_msgs.empty());
  ASSERT_TRUE(account.total_state->get_hash() == original);

  const auto required = static_cast<td::uint32>(wrapper_stat.cells);
  cfg.size_limits.max_acc_state_cells = required - 1;
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_error());
  cfg.size_limits.max_acc_state_cells = required;
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(tx.new_data->get_hash() == wrapper->get_hash());
  ASSERT_TRUE(account.total_state->get_hash() == original);
  LOG(INFO) << "Batch executor cell budget: payload=" << payload_stat.cells << " wrapper=" << required;
}

TEST(WorkchainBlock, BatchPreparationRejectsUnsettledState) {
  CounterEngine engine;
  auto in = input();
  auto effects = engine.execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  block::SerializeConfig cfg;
  account.is_special = true;
  block::transaction::Transaction special(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(special.prepare_workchain_batch(in, effects, cfg).is_error());
  ASSERT_TRUE(special.out_msgs.empty());
  ASSERT_TRUE(special.total_fees.is_zero());
  ASSERT_TRUE(!special.serialize(cfg));
  account.is_special = false;
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  auto altered = effects;
  altered.outbound_messages = number(0);
  auto unsettled = tx.prepare_workchain_batch(in, altered, cfg);
  ASSERT_TRUE(unsettled.is_error());
  ASSERT_EQ(unsettled.error().message(), "batch native message settlement is not implemented");
  tx.balance = block::CurrencyCollection(1);
  auto value = tx.prepare_workchain_batch(in, effects, cfg);
  ASSERT_TRUE(value.is_error());
  ASSERT_EQ(value.error().message(), "batch state preparation cannot mix account phases or native value flow");
  tx.balance = account.balance;
  auto previous_hash = account.last_trans_hash_;
  account.last_trans_hash_ = number(99)->get_hash().bits();
  auto wrapper = tx.prepare_workchain_batch(in, effects, cfg);
  ASSERT_TRUE(wrapper.is_error());
  ASSERT_EQ(wrapper.error().message(), "batch account wrapper differs from committed input state");
  account.last_trans_hash_ = previous_hash;
  auto limited_cfg = cfg;
  limited_cfg.size_limits.max_acc_state_cells = 0;
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, limited_cfg).is_error());
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(tx.new_data->get_hash() == account.data->get_hash());
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  tx.new_data = number(99);
  ASSERT_TRUE(!tx.serialize(cfg));
  ASSERT_TRUE(account.total_state->get_hash() == account.orig_total_state->get_hash());
}

TEST(WorkchainBlock, NativePayoutPair) {
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 2, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto a = td::Bits256::zero();
  td::Bits256 b(number(1)->get_hash().bits());
  block::Account custody(2, a.bits()), coordinator(2, b.bits());
  ASSERT_TRUE(custody.unpack(accounts.lookup(a), 10, false));
  ASSERT_TRUE(coordinator.unpack(accounts.lookup(b), 10, false));
  const auto old_custody = custody.total_state->get_hash();
  const auto old_coordinator = coordinator.total_state->get_hash();
  auto bindings = block::build_workchain_participant_records(a, b, {a, b}, 2).move_as_ok();
  vm::CellBuilder cb;
  cb.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(-1, 8).store_zeroes(256);
  // Distinct principal and fee amounts expose swapped debit roles.
  ASSERT_TRUE(block::CurrencyCollection(137).store(cb));
  ASSERT_TRUE(block::tlb::t_Tomis.store_integer_ref(cb, td::make_refint(3)));
  auto request = cb.store_zeroes(4).store_zeroes(96).store_zeroes(2).store_bits(b.bits(), 256).finalize();
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = cfg.extra_currency_v2 = true;
  block::ActionPhaseConfig pricing;
  pricing.global_version = 16;
  pricing.disable_custom_fess = pricing.disable_anycast = pricing.extra_currency_v2 = true;
  pricing.action_fine_enabled = pricing.bounce_on_fail_enabled = pricing.message_skip_enabled = true;
  block::WorkchainSet workchains;
  pricing.workchains = &workchains;
  pricing.fwd_mc.lump_price = 100;
  pricing.fwd_mc.first_frac = 16384;
  using Transaction = block::transaction::Transaction;
  auto build = [&](td::Ref<vm::Cell> second_data) {
    return Transaction::build_workchain_payout_pair(custody, coordinator, bindings[0], bindings[1],
        number(70), second_data, request, 20, 10, td::make_refint(500), 0, 4096, cfg, pricing, {}, {});
  };
  auto result = build(number(71));
  ASSERT_TRUE(result.is_ok());
  ASSERT_TRUE(Transaction::build_workchain_payout_pair(custody, coordinator, bindings[0], bindings[1],
      number(70), number(71), request, 20, 10, td::make_refint(500), 0, 0, cfg, pricing, {}, {}).is_error());
  unsigned binding_loads = 0;
  auto observed_binding = td::make_ref<PreflightObservedCell>(bindings[0], &binding_loads);
  ASSERT_TRUE(Transaction::build_workchain_payout_pair(custody, coordinator, observed_binding, bindings[1],
      number(70), number(71), request, 20, 10, td::make_refint(500), 0, 0, cfg, pricing, {}, {}).is_error());
  ASSERT_EQ(binding_loads, 0u);
  vm::Dictionary extra_values(32);
  vm::CellBuilder extra_value;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(extra_value, *td::make_refint(5)));
  ASSERT_TRUE(extra_values.set_builder(td::BitArray<32>(7u), extra_value));
  block::gen::Account::Record_account extra_root;
  block::gen::AccountStorage::Record extra_storage;
  ASSERT_TRUE(tlb::unpack_cell(coordinator.total_state, extra_root));
  ASSERT_TRUE(tlb::csr_unpack(extra_root.storage, extra_storage));
  block::CurrencyCollection opening_extra(1000, extra_values.get_root_cell());
  ASSERT_TRUE(opening_extra.pack_to(extra_storage.balance));
  ASSERT_TRUE(tlb::csr_pack(extra_root.storage, extra_storage));
  td::Ref<vm::Cell> extra_cell;
  ASSERT_TRUE(tlb::pack_cell(extra_cell, extra_root));
  auto extra_shard = vm::CellBuilder().store_ref(extra_cell)
      .store_bits(coordinator.last_trans_hash_.bits(), 256).store_long(coordinator.last_trans_lt_, 64).finalize();
  block::Account extra_coordinator(2, b.bits());
  ASSERT_TRUE(extra_coordinator.unpack(vm::load_cell_slice_ref(extra_shard), 10, false));
  auto build_extra = [&](int budget) {
    return Transaction::build_workchain_payout_pair(custody, extra_coordinator, bindings[0], bindings[1],
        number(70), number(71), request, 20, 10, td::make_refint(500), 0, budget, cfg, pricing, {}, {});
  };
  auto enough = build_extra(4096).move_as_ok();
  ASSERT_TRUE(enough.transactions[1]->balance == block::CurrencyCollection(900, extra_values.get_root_cell()));
  block::gen::Account::Record_account serialized_extra;
  block::gen::AccountStorage::Record serialized_storage;
  block::CurrencyCollection serialized_balance;
  ASSERT_TRUE(tlb::unpack_cell(enough.transactions[1]->new_total_state, serialized_extra));
  ASSERT_TRUE(tlb::csr_unpack(serialized_extra.storage, serialized_storage));
  ASSERT_TRUE(serialized_balance.unpack(serialized_storage.balance));
  ASSERT_TRUE(serialized_balance == block::CurrencyCollection(900, extra_values.get_root_cell()));
  ASSERT_TRUE(build_extra(1).is_error());
  ASSERT_TRUE(extra_coordinator.balance == opening_extra);
  auto prepared = result.move_as_ok();
  auto& pair = prepared.transactions;
  ASSERT_EQ(pair.size(), 2u);
  ASSERT_TRUE(pair[0]->balance == block::CurrencyCollection(863));
  ASSERT_TRUE(pair[1]->balance == block::CurrencyCollection(900));
  ASSERT_TRUE(pair[0]->total_fees == block::CurrencyCollection(25));
  ASSERT_TRUE(pair[1]->total_fees.is_zero());
  ASSERT_EQ(pair[0]->out_msgs.size(), 1u);
  ASSERT_TRUE(pair[1]->out_msgs.empty());
  ASSERT_EQ(pair[0]->end_lt, 22u);
  ASSERT_EQ(pair[1]->end_lt, 21u);
  ASSERT_TRUE(prepared.accounting.exported == block::CurrencyCollection(212));
  ASSERT_TRUE(prepared.accounting.fee_funding.from == b);
  ASSERT_TRUE(prepared.accounting.fee_funding.to == a);
  ASSERT_TRUE(prepared.accounting.fee_funding.value == block::CurrencyCollection(100));
  for (std::size_t i = 0; i < pair.size(); ++i) {
    auto& tx = pair[i];
    ASSERT_TRUE(block::gen::t_Transaction.validate_ref(4096, tx->root));
    ASSERT_TRUE(block::tlb::t_Transaction.validate_ref(4096, tx->root));
    block::gen::Transaction::Record record;
    ASSERT_TRUE(tlb::unpack_cell(tx->root, record));
    const auto& key = i == 0 ? a : b;
    ASSERT_TRUE(record.account_addr == key);
    ASSERT_EQ(record.lt, 20u);
    ASSERT_EQ(record.outmsg_cnt, i == 0 ? 1 : 0);
    block::CurrencyCollection recorded_fees;
    ASSERT_TRUE(recorded_fees.validate_unpack(record.total_fees));
    ASSERT_TRUE(recorded_fees == block::CurrencyCollection(i == 0 ? 25 : 0));
    auto entry = vm::CellBuilder().store_ref(tx->new_total_state)
        .store_bits(tx->root->get_hash().bits(), 256).store_long(20, 64).finalize();
    block::Account decoded(2, key.bits());
    ASSERT_TRUE(decoded.unpack(vm::load_cell_slice_ref(entry), 10, false));
    ASSERT_TRUE(decoded.balance == block::CurrencyCollection(i == 0 ? 863 : 900));
    ASSERT_EQ(decoded.last_trans_end_lt_, i == 0 ? 22u : 21u);
    ASSERT_TRUE(decoded.data->get_hash() == number(i == 0 ? 70 : 71)->get_hash());
    ASSERT_EQ(vm::load_cell_slice(record.description).prefetch_ulong(4), 11u);
    auto description = vm::load_cell_slice(record.description);
    ASSERT_TRUE(description.prefetch_ref()->get_hash() == bindings[i]->get_hash());
    ASSERT_TRUE(block::tlb::t_TransactionDescr.skip(description));
    ASSERT_TRUE(description.empty_ext());
    description = vm::load_cell_slice(record.description);
    bool found = true;
    ASSERT_TRUE(block::tlb::t_TransactionDescr.skip_to_storage_phase(description, found));
    ASSERT_TRUE(!found && description.empty_ext());
    td::RefInt256 storage_fees;
    ASSERT_TRUE(block::tlb::t_TransactionDescr.get_storage_fees(record.description, storage_fees));
    ASSERT_EQ(td::sgn(storage_fees), 0);
    ASSERT_TRUE(block::validate_transaction_execution_scope(record.description,
        block::WorkchainExecutionScope::BlockTransition).is_error());
    ASSERT_TRUE(block::validate_transaction_execution_scope(record.description,
        block::WorkchainExecutionScope::AccountCompute).is_error());
    ASSERT_TRUE(!tx->storage_phase && !tx->compute_phase && !tx->action_phase && !tx->bounce_phase);
  }
  ASSERT_TRUE(build({}).is_error());
  block::gen::ShardStateUnsplit::Record poor_state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 2, false, 0, 40, false, 99), poor_state));
  vm::AugmentedDictionary poor_accounts(vm::load_cell_slice_ref(poor_state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account poor_coordinator(2, b.bits());
  ASSERT_TRUE(poor_coordinator.unpack(poor_accounts.lookup(b), 10, false));
  ASSERT_TRUE(Transaction::build_workchain_payout_pair(custody, poor_coordinator, bindings[0], bindings[1],
      number(70), number(71), request, 20, 10, td::make_refint(500), 0, 4096, cfg, pricing, {}, {}).is_error());
  auto mismatch = pricing;
  mismatch.global_version = 17;
  ASSERT_TRUE(Transaction::build_workchain_payout_pair(custody, coordinator, bindings[0], bindings[1],
      number(70), number(71), request, 20, 10, td::make_refint(500), 0, 4096, cfg, mismatch, {}, {}).is_error());
  for (unsigned field = 0; field < 3; ++field) {
    block::gen::UnoV2HostRecord::Record changed;
    ASSERT_TRUE(tlb::unpack_cell(bindings[1], changed));
    if (field == 0) changed.input_hash = b;
    if (field == 1) changed.effects_hash = a;
    if (field == 2) changed.effect_index = 0;
    td::Ref<vm::Cell> altered;
    ASSERT_TRUE(tlb::pack_cell(altered, changed));
    ASSERT_TRUE(Transaction::build_workchain_payout_pair(custody, coordinator, bindings[0], altered,
        number(70), number(71), request, 20, 10, td::make_refint(500), 0, 4096, cfg, pricing, {}, {}).is_error());
  }
  ASSERT_TRUE(custody.total_state->get_hash() == old_custody);
  ASSERT_TRUE(coordinator.total_state->get_hash() == old_coordinator);
  pair[0]->balance = block::CurrencyCollection(901);
  ASSERT_TRUE(!pair[0]->serialize(cfg));

  block::gen::ShardStateUnsplit::Record larger;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 4, false, 0, 40, false, 1000), larger));
  vm::AugmentedDictionary prior(vm::load_cell_slice_ref(larger.accounts), 256, block::tlb::aug_ShardAccounts);
  td::Bits256 third(number(2)->get_hash().bits()), untouched(number(3)->get_hash().bits());
  std::vector<block::WorkchainStorageWrite> writes;
  for (auto key : {a, b, third}) {
    block::tlb::ShardAccount::Record before;
    ASSERT_TRUE(before.unpack(prior.lookup(key)));
    writes.push_back({key, td::Bits256(before.account->get_hash().bits()), number(72)});
  }
  std::sort(writes.begin(), writes.end(), [](const auto& x, const auto& y) { return x.account < y.account; });
  unsigned state_loads = 0;
  auto observed_state = td::make_ref<PreflightObservedCell>(larger.accounts, &state_loads);
  ASSERT_TRUE(block::build_workchain_payout_overlay(observed_state, 2, 10, 20, a, b, writes,
      a, b, request, td::make_refint(500), 4, 4, 2, 0, cfg, pricing, {}, {}).is_error());
  ASSERT_EQ(state_loads, 0u);
  ASSERT_TRUE(block::build_workchain_payout_overlay(observed_state, 2, 10, 20, a, b, writes,
      a, b, request, td::make_refint(500), 4, 4, std::numeric_limits<std::uint64_t>::max(),
      4096, cfg, pricing, {}, {}).is_error());
  ASSERT_EQ(state_loads, 0u);
  vm::AugmentedDictionary extra_accounts(vm::load_cell_slice_ref(larger.accounts), 256,
                                        block::tlb::aug_ShardAccounts);
  vm::CellBuilder extra_entry;
  extra_entry.append_cellslice(vm::load_cell_slice(extra_shard));
  ASSERT_TRUE(extra_accounts.set_builder(b, extra_entry, vm::Dictionary::SetMode::Replace));
  auto extra_writes = writes;
  for (auto& write : extra_writes) if (write.account == b) write.old_account_hash = extra_cell->get_hash().bits();
  auto extra_state = extra_accounts.get_wrapped_dict_root();
  auto extra_overlay = [&](int budget, const block::SerializeConfig& config) {
    return block::build_workchain_payout_overlay(extra_state, 2, 10, 20, a, b, extra_writes,
        a, b, request, td::make_refint(500), 4, 4, 2, budget, config, pricing, {}, {});
  };
  auto ample_overlay = extra_overlay(4096, cfg).move_as_ok();
  ASSERT_TRUE(extra_overlay(1, cfg).is_error());
  auto alternate_storage = cfg;
  alternate_storage.size_limits.max_acc_state_cells = 32768;
  auto independent_overlay = extra_overlay(4096, alternate_storage).move_as_ok();
  ASSERT_TRUE(ample_overlay.state.accounts->get_hash() == independent_overlay.state.accounts->get_hash());
  ASSERT_TRUE(ample_overlay.state.account_blocks->get_hash() == independent_overlay.state.account_blocks->get_hash());
  block::ClaimedWorkchainPayoutOverlay extra_claim{ample_overlay.state.accounts, ample_overlay.state.account_blocks,
      ample_overlay.message, ample_overlay.state.end_lt};
  ASSERT_TRUE(block::replay_workchain_payout_overlay(extra_state, 2, 10, 20, a, b, extra_writes,
      a, b, request, td::make_refint(500), 4, 4, 2, 1, cfg, pricing, extra_claim, {}, {}).is_error());
  auto overlay = block::build_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, writes,
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {});
  ASSERT_TRUE(overlay.is_ok());
  auto materialized = overlay.move_as_ok();
  ASSERT_EQ(materialized.state.end_lt, 23u);
  ASSERT_TRUE(materialized.message.not_null());
  ASSERT_TRUE(materialized.fee_funding.from == a && materialized.fee_funding.to == b);
  ASSERT_TRUE(materialized.fee_funding.value == block::CurrencyCollection(100));
  block::gen::CommonMsgInfo::Record_int_msg_info actual_message;
  ASSERT_TRUE(tlb::unpack_cell_inexact(materialized.message, actual_message));
  ASSERT_EQ(actual_message.created_lt, 22u);
  block::gen::MsgAddressInt::Record_addr_std actual_source;
  ASSERT_TRUE(tlb::csr_unpack(actual_message.src, actual_source));
  ASSERT_TRUE(actual_source.address == b);
  vm::AugmentedDictionary next(vm::load_cell_slice_ref(materialized.state.accounts), 256, block::tlb::aug_ShardAccounts);
  vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(materialized.state.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
  ASSERT_TRUE(next.lookup(untouched)->contents_equal(*prior.lookup(untouched)));
  ASSERT_TRUE(blocks.lookup(untouched).is_null());
  for (auto key : {a, b, third}) {
    block::Account updated(2, key.bits());
    ASSERT_TRUE(updated.unpack(next.lookup(key), 10, false));
    ASSERT_TRUE(updated.balance == block::CurrencyCollection(key == b ? 863 : key == a ? 900 : 1000));
    ASSERT_EQ(updated.last_trans_lt_, 21u);
    ASSERT_EQ(updated.last_trans_end_lt_, key == b ? 23u : 22u);
    ASSERT_TRUE(updated.data->get_hash() == number(72)->get_hash());
    auto block_root = vm::CellBuilder().append_cellslice(*blocks.lookup(key)).finalize();
    ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(4096, block_root));
    ASSERT_TRUE(block::tlb::t_AccountBlock.validate_ref(4096, block_root));
    block::gen::AccountBlock::Record account_block;
    ASSERT_TRUE(tlb::unpack_cell(block_root, account_block));
    vm::AugmentedDictionary txs(vm::DictNonEmpty(), account_block.transactions, 64, block::tlb::aug_AccountTransactions);
    auto tx_root = txs.lookup_ref(td::BitArray<64>(21u));
    ASSERT_TRUE(tx_root.not_null());
    ASSERT_TRUE(updated.last_trans_hash_ == tx_root->get_hash().bits());
    if (key == b) {
      block::gen::Transaction::Record recorded;
      ASSERT_TRUE(tlb::unpack_cell(tx_root, recorded));
      vm::Dictionary outputs(recorded.r1.out_msgs, 15);
      ASSERT_TRUE(outputs.lookup_ref(td::BitArray<15>::zero())->get_hash() == materialized.message->get_hash());
    }
  }
  auto repeat = block::build_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, writes,
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {});
  ASSERT_TRUE(repeat.is_ok());
  ASSERT_TRUE(repeat.ok().state.accounts->get_hash() == materialized.state.accounts->get_hash());
  ASSERT_TRUE(repeat.ok().state.account_blocks->get_hash() == materialized.state.account_blocks->get_hash());
  block::ClaimedWorkchainPayoutOverlay claim{materialized.state.accounts, materialized.state.account_blocks,
                                           materialized.message, materialized.state.end_lt};
  auto replay = [&](const block::ClaimedWorkchainPayoutOverlay& claimed) {
    return block::replay_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, writes,
        b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, claimed, {}, {});
  };
  auto replayed = replay(claim);
  ASSERT_TRUE(replayed.is_ok());
  ASSERT_TRUE(replayed.ok().state.accounts->get_hash() == claim.accounts->get_hash());
  ASSERT_TRUE(replayed.ok().fee_funding.value == block::CurrencyCollection(100));
  auto changed = claim;
  changed.end_lt = block::participant_lt_detail::checked_add(claim.end_lt, 1).move_as_ok();
  ASSERT_TRUE(replay(changed).is_error());
  vm::AugmentedDictionary altered_accounts(vm::load_cell_slice_ref(claim.accounts), 256, block::tlb::aug_ShardAccounts);
  block::tlb::ShardAccount::Record changed_entry;
  ASSERT_TRUE(changed_entry.unpack(altered_accounts.lookup(a)));
  vm::CellBuilder wrong_link;
  wrong_link.store_ref(changed_entry.account).store_zeroes(256).store_long(21, 64);
  ASSERT_TRUE(altered_accounts.set_builder(a, wrong_link, vm::Dictionary::SetMode::Replace));
  changed = claim;
  changed.accounts = altered_accounts.get_wrapped_dict_root();
  ASSERT_TRUE(block::gen::t_ShardAccounts.validate_ref(10000, changed.accounts));
  ASSERT_TRUE(replay(changed).is_error());
  vm::AugmentedDictionary altered_blocks(vm::load_cell_slice_ref(claim.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
  block::gen::AccountBlock::Record altered_block;
  ASSERT_TRUE(tlb::unpack_cell(vm::CellBuilder().append_cellslice(*altered_blocks.lookup(a)).finalize(), altered_block));
  altered_block.state_update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  td::Ref<vm::Cell> altered_block_root;
  ASSERT_TRUE(tlb::pack_cell(altered_block_root, altered_block));
  ASSERT_TRUE(block::gen::t_AccountBlock.validate_ref(10000, altered_block_root));
  vm::CellBuilder altered_block_value;
  altered_block_value.append_cellslice(vm::load_cell_slice(altered_block_root));
  ASSERT_TRUE(altered_blocks.set_builder(a, altered_block_value, vm::Dictionary::SetMode::Replace));
  changed = claim;
  changed.account_blocks = altered_blocks.get_wrapped_dict_root();
  ASSERT_TRUE(replay(changed).is_error());
  block::gen::Message::Record altered_message;
  ASSERT_TRUE(tlb::type_unpack_cell(claim.message, block::gen::t_Message_Any, altered_message));
  block::gen::CommonMsgInfo::Record_int_msg_info altered_info;
  ASSERT_TRUE(tlb::csr_unpack(altered_message.info, altered_info));
  altered_info.created_at = 1;
  ASSERT_TRUE(tlb::csr_pack(altered_message.info, altered_info));
  changed = claim;
  ASSERT_TRUE(tlb::type_pack_cell(changed.message, block::gen::t_Message_Any, altered_message));
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(10000, changed.message));
  ASSERT_TRUE(replay(changed).is_error());
  auto wrong_read = writes;
  wrong_read[0].old_account_hash = td::Bits256::zero();
  ASSERT_TRUE(block::build_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, wrong_read,
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {}).is_error());
  auto invalid_writes = writes;
  for (auto& write : invalid_writes) if (write.account == third) write.data.clear();
  ASSERT_TRUE(block::build_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, invalid_writes,
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {}).is_error());
}

TEST(WorkchainBlock, NativePayoutPricing) {
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto key = td::Bits256::zero();
  auto operator_key = key;
  operator_key.as_slice().back() = 1;
  block::Account account(2, key.bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(key), 10, false));
  auto old = account.total_state->get_hash();
  vm::CellBuilder cb;
  cb.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(-1, 8).store_zeroes(256);
  ASSERT_TRUE(block::CurrencyCollection(100).store(cb));
  ASSERT_TRUE(block::tlb::t_Tomis.store_integer_ref(cb, td::make_refint(3)));
  cb.store_zeroes(4).store_zeroes(96).store_zeroes(2).store_bits(operator_key.bits(), 256);
  auto request = cb.finalize();
  ASSERT_TRUE(block::gen::t_MessageRelaxed_Any.validate_ref(4096, request));
  block::WorkchainSet workchains;
  block::ActionPhaseConfig cfg;
  cfg.global_version = 16;
  cfg.disable_custom_fess = cfg.disable_anycast = true;
  cfg.action_fine_enabled = cfg.bounce_on_fail_enabled = cfg.message_skip_enabled = cfg.extra_currency_v2 = true;
  cfg.workchains = &workchains;
  cfg.fwd_mc.lump_price = 100;
  cfg.fwd_mc.first_frac = 32768;
  using Transaction = block::transaction::Transaction;
  auto priced = Transaction::price_workchain_payout(account, request, 20, 10, td::make_refint(100), cfg);
  if (priced.is_error()) LOG(ERROR) << priced.error();
  ASSERT_TRUE(priced.is_ok());
  auto result = priced.move_as_ok();
  ASSERT_EQ(result.total_fee->to_long(), 100);
  ASSERT_EQ(result.collected_fee->to_long(), 50);
  ASSERT_EQ(result.end_lt, 22u);
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  ASSERT_TRUE(tlb::unpack_cell_inexact(result.message, info));
  ASSERT_EQ(info.created_lt, 21u);
  ASSERT_EQ(block::tlb::t_Tomis.as_integer(info.fwd_fee)->to_long(), 50);
  block::CurrencyCollection sent_value;
  ASSERT_TRUE(sent_value.unpack(info.value) && sent_value == result.payment);
  block::gen::MsgAddressInt::Record_addr_std src;
  ASSERT_TRUE(tlb::csr_unpack(info.src, src));
  ASSERT_EQ(src.workchain_id, 2);
  ASSERT_TRUE(src.address == key);
  auto settlement = block::account_workchain_payout(key, operator_key, account.balance,
      block::CurrencyCollection(100), result.payment, result.total_fee, result.collected_fee, 100).move_as_ok();
  ASSERT_TRUE(settlement.custody_after == block::CurrencyCollection(900));
  ASSERT_TRUE(settlement.operator_after.is_zero());
  ASSERT_TRUE(settlement.exported == block::CurrencyCollection(150));
  ASSERT_TRUE(Transaction::price_workchain_payout(account, request, 20, 10, td::make_refint(99), cfg).is_error());
  cfg.fwd_mc.lump_price = 102;
  auto repriced = Transaction::price_workchain_payout(account, request, 20, 10, td::make_refint(102), cfg).move_as_ok();
  ASSERT_EQ(repriced.total_fee->to_long(), 102);
  ASSERT_EQ(repriced.collected_fee->to_long(), 51);
  ASSERT_TRUE(repriced.message->get_hash() != result.message->get_hash());
  auto surplus = Transaction::price_workchain_payout(account, request, 20, 10, td::make_refint(500), cfg).move_as_ok();
  ASSERT_EQ(surplus.total_fee->to_long(), 102);
  ASSERT_TRUE(surplus.message->get_hash() == repriced.message->get_hash());
  vm::Dictionary zero_extra(32);
  vm::CellBuilder zero_amount;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(zero_amount, *td::make_refint(0)));
  ASSERT_TRUE(zero_extra.set_builder(operator_key.bits(), 32, zero_amount));
  block::gen::MessageRelaxed::Record zero_request;
  block::gen::CommonMsgInfoRelaxed::Record_int_msg_info zero_info;
  ASSERT_TRUE(tlb::type_unpack_cell(request, block::gen::t_MessageRelaxed_Any, zero_request));
  ASSERT_TRUE(tlb::csr_unpack(zero_request.info, zero_info));
  ASSERT_TRUE(block::CurrencyCollection(100, zero_extra.get_root_cell()).pack_to(zero_info.value));
  ASSERT_TRUE(tlb::csr_pack(zero_request.info, zero_info));
  td::Ref<vm::Cell> zero_encoded;
  ASSERT_TRUE(tlb::type_pack_cell(zero_encoded, block::gen::t_MessageRelaxed_Any, zero_request));
  ASSERT_TRUE(block::gen::t_MessageRelaxed_Any.validate_ref(4096, zero_encoded));
  // Generated syntax accepts zero entries; Native send's handwritten currency
  // validator requires positive extra amounts before its normalization path.
  ASSERT_TRUE(!block::tlb::t_CurrencyCollection.validate_csr(zero_info.value));
  auto normalized = Transaction::price_workchain_payout(account, zero_encoded, 20, 10, td::make_refint(500), cfg);
  ASSERT_TRUE(normalized.is_error());
  auto old_cfg = cfg;
  old_cfg.global_version = 15;
  ASSERT_TRUE(Transaction::price_workchain_payout(account, request, 20, 10, td::make_refint(500), old_cfg).is_error());
  account.is_special = true;
  ASSERT_TRUE(Transaction::price_workchain_payout(account, request, 20, 10, td::make_refint(500), cfg).is_error());
  account.is_special = false;
  ASSERT_TRUE(Transaction::price_workchain_payout(account, request, std::numeric_limits<std::uint64_t>::max(),
      10, td::make_refint(500), cfg).is_error());
  ASSERT_TRUE(Transaction::price_workchain_payout(account, request, 1, 10, td::make_refint(500), cfg).is_error());
  ASSERT_TRUE(Transaction::price_workchain_payout(account, request, 20, 10, td::make_refint(-1), cfg).is_error());
  ASSERT_TRUE(Transaction::price_workchain_payout(account, request, 20, 10, {}, cfg).is_error());
  for (unsigned field = 0; field < 8; ++field) {
    block::gen::MessageRelaxed::Record altered;
    block::gen::CommonMsgInfoRelaxed::Record_int_msg_info changed;
    ASSERT_TRUE(tlb::type_unpack_cell(request, block::gen::t_MessageRelaxed_Any, altered));
    ASSERT_TRUE(tlb::csr_unpack(altered.info, changed));
    switch (field) {
      case 0: changed.bounce = false; break;
      case 1: changed.bounced = true; break;
      case 2: ASSERT_TRUE(block::tlb::t_Tomis.pack_integer(changed.extra_flags, td::make_refint(0))); break;
      case 3: ASSERT_TRUE(block::tlb::t_Tomis.pack_integer(changed.fwd_fee, td::make_refint(1))); break;
      case 4: ASSERT_TRUE(block::CurrencyCollection(0).pack_to(changed.value)); break;
      case 5: ASSERT_TRUE(block::CurrencyCollection(1001).pack_to(changed.value)); break;
      case 6: changed.ihr_disabled = false; break;
      case 7:
        changed.dest = vm::load_cell_slice_ref(vm::CellBuilder().store_long(5, 3).store_long(1, 5)
            .store_long(0, 1).store_long(-1, 8).store_zeroes(256).finalize());
        break;
    }
    ASSERT_TRUE(tlb::csr_pack(altered.info, changed));
    td::Ref<vm::Cell> bad_profile;
    ASSERT_TRUE(tlb::type_pack_cell(bad_profile, block::gen::t_MessageRelaxed_Any, altered));
    ASSERT_TRUE(block::gen::t_MessageRelaxed_Any.validate_ref(4096, bad_profile));
    ASSERT_TRUE(Transaction::price_workchain_payout(account, bad_profile, 20, 10, td::make_refint(500), cfg).is_error());
  }
  block::gen::MessageRelaxed::Record expanded;
  ASSERT_TRUE(tlb::type_unpack_cell(request, block::gen::t_MessageRelaxed_Any, expanded));
  expanded.body = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1)
      .store_ref(vm::CellBuilder().store_bits(operator_key.bits(), 256).finalize()).finalize());
  block::gen::CommonMsgInfoRelaxed::Record_int_msg_info expanded_info;
  ASSERT_TRUE(tlb::csr_unpack(expanded.info, expanded_info));
  td::Bits256 payee(number(7)->get_hash().bits());
  expanded_info.dest = vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(0, 8)
      .store_bits(payee.bits(), 256).finalize());
  ASSERT_TRUE(tlb::csr_pack(expanded.info, expanded_info));
  td::Ref<vm::Cell> basechain_request;
  ASSERT_TRUE(tlb::type_pack_cell(basechain_request, block::gen::t_MessageRelaxed_Any, expanded));
  td::Ref<block::WorkchainInfo> basechain{true};
  basechain.write().workchain = 0;
  basechain.write().basic = basechain.write().active = basechain.write().accept_msgs = true;
  basechain.write().min_addr_len = basechain.write().max_addr_len = 256;
  basechain.write().addr_len_step = 0;
  workchains.emplace(0, basechain);
  cfg.fwd_std.lump_price = 200;
  cfg.fwd_std.bit_price = 65536;
  cfg.fwd_std.cell_price = 262144;
  cfg.fwd_std.first_frac = 32768;
  auto sized = Transaction::price_workchain_payout(account, basechain_request, 20, 10, td::make_refint(500), cfg).move_as_ok();
  ASSERT_EQ(sized.total_fee->to_long(), 460);
  ASSERT_EQ(sized.collected_fee->to_long(), 230);
  ASSERT_TRUE(tlb::unpack_cell_inexact(sized.message, info));
  block::gen::MsgAddressInt::Record_addr_std dest;
  ASSERT_TRUE(tlb::csr_unpack(info.dest, dest));
  ASSERT_EQ(dest.workchain_id, 0);
  ASSERT_TRUE(dest.address == payee);
  workchains.clear();
  ASSERT_TRUE(Transaction::price_workchain_payout(account, basechain_request, 20, 10, td::make_refint(500), cfg).is_error());
  // Inject a virtualization exception at every request-root load, including
  // loads inside Native staging. No load failure may become a priced result
  // or an ordinary returned error. Classification itself belongs to the host.
  unsigned loads = 0;
  auto observed = td::Ref<PreflightObservedCell>{true, request, &loads};
  ASSERT_TRUE(Transaction::price_workchain_payout(account, observed, 20, 10, td::make_refint(500), cfg).is_ok());
  ASSERT_TRUE(loads > 1);
  const auto total_loads = loads;
  for (unsigned fail_at = 1; fail_at <= total_loads; ++fail_at) {
    loads = 0;
    auto faulty = td::Ref<PreflightObservedCell>{true, request, &loads, false, fail_at};
    bool propagated = false;
    try {
      auto unexpected = Transaction::price_workchain_payout(account, faulty, 20, 10, td::make_refint(500), cfg);
      (void)unexpected;
    } catch (const vm::VmVirtError&) { propagated = true; }
    ASSERT_TRUE(propagated);
  }
  ASSERT_TRUE(account.total_state->get_hash() == old);
  ASSERT_TRUE(account.balance == block::CurrencyCollection(1000));
}

TEST(WorkchainBlock, BatchNativeMessageSettlement) {
  CounterEngine engine;
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000);
  auto effects = engine.execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  auto previous = account.total_state->get_hash();
  block::SerializeConfig cfg;
  block::WorkchainSet workchains;
  block::ActionPhaseConfig messages_cfg;
  messages_cfg.workchains = &workchains;
  messages_cfg.fwd_mc.lump_price = 100;
  messages_cfg.fwd_mc.first_frac = 32768;
  auto message = [&](int wc) {
    vm::CellBuilder cb;
    cb.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(wc, 8).store_zeroes(256);
    ASSERT_TRUE(block::CurrencyCollection(100).store(cb));
    cb.store_zeroes(8).store_zeroes(96).store_zeroes(2);
    auto result = cb.finalize();
    ASSERT_TRUE(block::gen::t_MessageRelaxed_Any.validate_ref(4096, result));
    return result;
  };
  auto requests = [&](unsigned count, bool invalid_last = false, unsigned first = 0) {
    vm::Dictionary dict(15);
    for (unsigned i = 0; i < count; ++i) {
      ASSERT_TRUE(dict.set_ref(td::BitArray<15>(i + first), message(invalid_last && i + 1 == count ? 9 : -1)));
    }
    vm::CellBuilder cb;
    ASSERT_TRUE(std::move(dict).append_dict_to_bool(cb));
    return cb.finalize();
  };
  using Transaction = block::transaction::Transaction;
  effects.outbound_messages = requests(2);
  Transaction tx(account, Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg, &messages_cfg).is_ok());
  ASSERT_TRUE(!tx.compute_phase && !tx.action_phase);
  ASSERT_EQ(tx.balance.tomis->to_long(), 600);
  ASSERT_EQ(tx.total_fees.tomis->to_long(), 100);
  ASSERT_EQ(tx.end_lt, 13u);
  ASSERT_EQ(tx.out_msgs.size(), 2u);
  for (unsigned i = 0; i < 2; ++i) {
    block::gen::Message::Record msg;
    block::gen::CommonMsgInfo::Record_int_msg_info info;
    ASSERT_TRUE(tlb::type_unpack_cell(tx.out_msgs[i], block::gen::t_Message_Any, msg));
    ASSERT_TRUE(tlb::csr_unpack(msg.info, info));
    block::CurrencyCollection value;
    ASSERT_TRUE(value.unpack(info.value));
    ASSERT_EQ(value.tomis->to_long(), 100);
    ASSERT_EQ(block::tlb::t_Tomis.as_integer(info.fwd_fee)->to_long(), 50);
    ASSERT_EQ(info.created_lt, 11u + i);
    ASSERT_EQ(info.created_at, 10u);
    ASSERT_TRUE(info.src->contents_equal(*account.my_addr));
  }
  ASSERT_EQ(account.balance.tomis->to_long(), 1000);
  ASSERT_TRUE(account.total_state->get_hash() == previous);
  // Serialization must not accept public-field changes after fee settlement.
  tx.balance = block::CurrencyCollection(601);
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.balance = block::CurrencyCollection(600);
  tx.total_fees = block::CurrencyCollection(101);
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.total_fees = block::CurrencyCollection(100);
  tx.end_lt = 14;
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.end_lt = 13;
  auto first_message = tx.out_msgs[0];
  tx.out_msgs[0] = message(-1);
  ASSERT_TRUE(!tx.serialize(cfg));
  tx.out_msgs[0] = first_message;
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(10000, tx.root));
  class MessageEngine final : public block::WorkchainBlockEngine {
   public:
    td::Ref<vm::Cell> requests;
    td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput& input) const override {
      TRY_RESULT(result, CounterEngine().execute_block(input));
      result.outbound_messages = requests;
      return result;
    }
  } replay_engine;
  replay_engine.requests = effects.outbound_messages;
  auto replayed = block::replay_workchain_batch_transaction(
      replay_engine, in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg, &messages_cfg);
  ASSERT_TRUE(replayed.is_ok());
  ASSERT_TRUE(replayed.ok()->get_hash() == tx.new_total_state->get_hash());
  auto different_prices = messages_cfg;
  different_prices.fwd_mc.lump_price = 102;
  auto wrong_fees = block::replay_workchain_batch_transaction(
      replay_engine, in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg, &different_prices);
  ASSERT_TRUE(wrong_fees.is_error());
  ASSERT_EQ(wrong_fees.error().message(), "batch transaction wrapper differs from replay");
  auto reject = [&](td::Ref<vm::Cell> outbound, const block::ActionPhaseConfig& pricing, td::Slice expected) {
    Transaction rejected(account, Transaction::tr_workchain_batch, 10, 10);
    auto altered = effects;
    altered.outbound_messages = std::move(outbound);
    auto status = rejected.prepare_workchain_batch(in, altered, cfg, &pricing);
    ASSERT_TRUE(status.is_error());
    ASSERT_EQ(status.message(), expected);
    ASSERT_TRUE(rejected.out_msgs.empty());
    ASSERT_EQ(rejected.balance.tomis->to_long(), 1000);
    ASSERT_TRUE(rejected.total_fees.is_zero());
    ASSERT_EQ(rejected.end_lt, 11u);
    ASSERT_TRUE(rejected.new_data->get_hash() == account.data->get_hash());
    ASSERT_TRUE(!rejected.serialize(cfg));
  };
  reject(requests(2, true), messages_cfg, "batch native message send failed");
  reject(requests(6), messages_cfg, "batch native message send failed");
  reject(requests(1, false, 1), messages_cfg, "invalid batch outbound requests");
  reject(number(0), messages_cfg, "invalid batch outbound dictionary");
  auto limited = messages_cfg;
  limited.max_actions = 1;
  reject(requests(2), limited, "invalid batch outbound requests");
  limited = messages_cfg;
  limited.workchains = nullptr;
  reject(requests(1), limited, "missing batch native message configuration");
  Transaction overflow(account, Transaction::tr_workchain_batch,
                       std::numeric_limits<std::uint64_t>::max() - 1, 10);
  auto no_lt = overflow.prepare_workchain_batch(in, effects, cfg, &messages_cfg);
  ASSERT_TRUE(no_lt.is_error());
  ASSERT_EQ(no_lt.message(), "invalid batch outbound requests");
  ASSERT_TRUE(overflow.out_msgs.empty());
}

TEST(WorkchainBlock, BatchCommitmentReplay) {
  CounterEngine engine;
  auto in = input();
  in.configuration = number(17);
  in.finality_context = number(19);
  auto produced = engine.execute_block(in).move_as_ok();
  auto context = block::encode_workchain_block_input(in).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBlockInput.validate_ref(10000, context));
  block::gen::WorkchainBlockInput::Record_workchain_block_input_v1 generated;
  ASSERT_TRUE(tlb::unpack_cell(context, generated));
  ASSERT_TRUE(generated.previous_shard_state->get_hash() == in.previous_shard_state->get_hash());
  ASSERT_TRUE(generated.candidate->get_hash() == in.candidate->get_hash());
  ASSERT_TRUE(generated.configuration->get_hash() == in.configuration->get_hash());
  ASSERT_TRUE(generated.finality_context->get_hash() == in.finality_context->get_hash());
  auto commitments = block::make_workchain_batch_description(in, produced).move_as_ok();
  auto description = block::encode_workchain_batch_description(commitments);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, description));
  auto wire = vm::std_boc_serialize(description).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto replayed = block::replay_workchain_batch(engine, in, restored).move_as_ok();
  ASSERT_TRUE(replayed.new_engine_state->get_hash() == produced.new_engine_state->get_hash());
  td::Ref<vm::Cell> block::WorkchainBlockInput::* fields[] = {
      &block::WorkchainBlockInput::previous_shard_state, &block::WorkchainBlockInput::candidate,
      &block::WorkchainBlockInput::configuration, &block::WorkchainBlockInput::finality_context};
  for (auto field : fields) {
    auto changed = in;
    changed.*field = number(99);
    auto result = block::replay_workchain_batch(engine, changed, description);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "batch transaction input commitment differs from authenticated context");
    changed.*field = {};
    auto missing = block::replay_workchain_batch(engine, changed, description);
    ASSERT_TRUE(missing.is_error());
    ASSERT_EQ(missing.error().message(), "batch commitment requires state, candidate, configuration and finality");
  }
}

TEST(WorkchainBlock, NativeQueueViewIsBoundToInput) {
  auto in = input();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  auto queue = block::extract_workchain_native_queue_state(in).move_as_ok();
  ASSERT_TRUE(queue->get_hash() == state.out_msg_queue_info->get_hash());
  auto before = block::encode_workchain_block_input(in).move_as_ok();
  // Empty queue with explicit dispatch metadata, rather than absent metadata.
  auto changed_queue = vm::CellBuilder().store_zeroes(66).store_long(1, 1)
      .store_zeroes(4 + 65).store_long(1, 1).store_zeroes(48).finalize();
  ASSERT_TRUE(block::gen::t_OutMsgQueueInfo.validate_ref(10000, changed_queue));
  state.out_msg_queue_info = changed_queue;
  auto changed = in;
  ASSERT_TRUE(tlb::pack_cell(changed.previous_shard_state, state));
  ASSERT_TRUE(block::gen::t_ShardStateUnsplit.validate_ref(10000, changed.previous_shard_state));
  ASSERT_TRUE(block::extract_workchain_native_queue_state(changed).move_as_ok()->get_hash() == changed_queue->get_hash());
  ASSERT_TRUE(block::encode_workchain_block_input(changed).move_as_ok()->get_hash() != before->get_hash());
  auto invalid = in;
  invalid.previous_shard_state = {};
  ASSERT_TRUE(block::extract_workchain_native_queue_state(invalid).is_error());
  invalid.previous_shard_state = number(0);
  ASSERT_TRUE(block::extract_workchain_native_queue_state(invalid).is_error());
}

TEST(WorkchainBlock, UnmatchedBatchInputDoesNotInvokeEngine) {
  class CountingEngine final : public block::WorkchainBlockEngine {
   public:
    mutable unsigned calls = 0;
    td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput& in) const override {
      ++calls;
      return CounterEngine().execute_block(in);
    }
  } engine;
  auto in = input();
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  auto claim = block::make_workchain_batch_description(in, effects).move_as_ok();
  auto description = block::encode_workchain_batch_description(claim);
  auto matched = block::replay_workchain_batch(engine, in, description);
  ASSERT_TRUE(matched.is_ok());
  ASSERT_EQ(engine.calls, 1u);

  td::Ref<vm::Cell> block::WorkchainBlockInput::* fields[] = {
      &block::WorkchainBlockInput::previous_shard_state, &block::WorkchainBlockInput::candidate,
      &block::WorkchainBlockInput::configuration, &block::WorkchainBlockInput::finality_context};
  for (auto field : fields) {
    auto changed = in;
    changed.*field = number(99);
    engine.calls = 0;
    auto rejected = block::replay_workchain_batch(engine, changed, description);
    ASSERT_EQ(engine.calls, 0u);
    ASSERT_TRUE(rejected.is_error());
  }
}

TEST(WorkchainBlock, BatchCommitmentRejectsEffectMutations) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  td::Ref<vm::Cell> block::WorkchainBlockResult::* fields[] = {
      &block::WorkchainBlockResult::new_engine_state, &block::WorkchainBlockResult::outbound_messages,
      &block::WorkchainBlockResult::actions, &block::WorkchainBlockResult::receipts,
      &block::WorkchainBlockResult::events, &block::WorkchainBlockResult::data_availability};
  for (auto field : fields) {
    auto changed = produced;
    changed.*field = number(99);
    auto claimed = block::make_workchain_batch_description(in, changed).move_as_ok();
    auto result = block::replay_workchain_batch(engine, in, block::encode_workchain_batch_description(claimed));
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "batch transaction commitments differ from replay");
    changed.*field = {};
    ASSERT_TRUE(block::make_workchain_batch_description(in, changed).is_error());
  }
  for (int i = 0; i < 3; ++i) {
    auto claimed = block::make_workchain_batch_description(in, produced).move_as_ok();
    if (i == 0) claimed.usage.wire_bytes = 99;
    if (i == 1) claimed.usage.verification_units = 99;
    if (i == 2) claimed.usage.written_cells = 99;
    auto result = block::replay_workchain_batch(engine, in, block::encode_workchain_batch_description(claimed));
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "batch transaction commitments differ from replay");
  }
}

TEST(WorkchainBlock, BatchDescriptionParsersAndScope) {
  block::WorkchainBatchDescription description;
  description.input_hash = number(11)->get_hash().bits();
  description.effects_hash = number(12)->get_hash().bits();
  description.usage = {13, 14, std::numeric_limits<std::uint64_t>::max()};
  auto root = block::encode_workchain_batch_description(description);
  ASSERT_EQ(vm::load_cell_slice(root).size(), 709u);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, root));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, root));
  block::gen::TransactionDescr::Record_trans_workchain_batch_v2 generated;
  ASSERT_TRUE(tlb::unpack_cell(root, generated));
  ASSERT_TRUE(generated.input_hash == description.input_hash);
  ASSERT_TRUE(generated.effects_hash == description.effects_hash);
  ASSERT_EQ(generated.wire_bytes, description.usage.wire_bytes);
  ASSERT_EQ(generated.verification_units, description.usage.verification_units);
  ASSERT_EQ(generated.written_cells, description.usage.written_cells);
  auto decoded = block::decode_workchain_batch_description(root).move_as_ok();
  ASSERT_TRUE(decoded.input_hash == description.input_hash);
  ASSERT_TRUE(decoded.effects_hash == description.effects_hash);
  ASSERT_TRUE(decoded.usage == description.usage);
  auto cs = vm::load_cell_slice(root);
  ASSERT_EQ(block::tlb::t_TransactionDescr.get_tag(cs), block::tlb::TransactionDescr::trans_workchain_batch_v2);
  ASSERT_TRUE(block::tlb::t_TransactionDescr.skip(cs));
  ASSERT_TRUE(cs.empty_ext());
  td::RefInt256 storage_fees;
  ASSERT_TRUE(block::tlb::t_TransactionDescr.get_storage_fees(root, storage_fees));
  ASSERT_EQ(td::sgn(storage_fees), 0);
  ASSERT_TRUE(block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::BlockTransition).is_ok());
  auto wrong_scope = block::validate_transaction_execution_scope(root, block::WorkchainExecutionScope::AccountCompute);
  ASSERT_TRUE(wrong_scope.is_error());
  ASSERT_EQ(wrong_scope.error().message(), "transaction description does not match execution scope");
  // Storage-only transaction: zero collected fees, no due fees, unchanged status.
  auto account = vm::CellBuilder().store_long(1, 4).store_long(0, 6).finalize();
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, account));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, account));
  ASSERT_TRUE(block::validate_transaction_execution_scope(account, block::WorkchainExecutionScope::AccountCompute).is_ok());
  ASSERT_TRUE(block::validate_transaction_execution_scope(account, block::WorkchainExecutionScope::BlockTransition).is_error());
  for (unsigned tag = 10; tag < 16; ++tag) {
    auto future = vm::CellBuilder().store_long(tag, 4).finalize();
    ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, future));
    ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, future));
    auto scope = block::validate_transaction_execution_scope(future, block::WorkchainExecutionScope::AccountCompute);
    ASSERT_TRUE(scope.is_error());
    ASSERT_EQ(scope.error().message(), "unknown transaction description for execution scope");
  }
}

TEST(WorkchainBlock, RejectMalformedBatchDescription) {
  for (int mutation = 0; mutation < 3; ++mutation) {
    vm::CellBuilder cb;
    cb.store_long(9, 4).store_zeroes(mutation == 0 ? 704 : mutation == 1 ? 706 : 705);
    if (mutation == 2) cb.store_ref(number(0));
    auto root = cb.finalize();
    ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, root));
    ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, root));
    auto decoded = block::decode_workchain_batch_description(root);
    ASSERT_TRUE(decoded.is_error());
    ASSERT_EQ(decoded.error().message(), "invalid batch transaction description");
  }
}

TEST(WorkchainBlock, ScopeClassifiesEveryConstructorPrefix) {
  // Prefix classification is separate from full TL-B payload validation.
  // Both fourth-bit values of the three-bit tick/tock tag must classify alike.
  for (unsigned tag = 0; tag < 16; ++tag) {
    auto prefix = vm::CellBuilder().store_long(tag, 4).finalize();
    bool account = block::validate_transaction_execution_scope(
        prefix, block::WorkchainExecutionScope::AccountCompute).is_ok();
    bool batch = block::validate_transaction_execution_scope(
        prefix, block::WorkchainExecutionScope::BlockTransition).is_ok();
    ASSERT_EQ(account, tag < 8);
    ASSERT_EQ(batch, tag == 9);
  }
}

TEST(WorkchainBlock, RetiredBatchDescriptorRejected) {
  auto retired = vm::CellBuilder().store_long(8, 4).store_zeroes(704).finalize();
  ASSERT_TRUE(!block::gen::t_TransactionDescr.validate_ref(10000, retired));
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.validate_ref(10000, retired));
  ASSERT_TRUE(block::decode_workchain_batch_description(retired).is_error());
  auto cs = vm::load_cell_slice(retired);
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.skip(cs));
  cs = vm::load_cell_slice(retired);
  bool found = false;
  ASSERT_TRUE(!block::tlb::t_TransactionDescr.skip_to_storage_phase(cs, found));
  ASSERT_TRUE(block::validate_transaction_execution_scope(
      retired, block::WorkchainExecutionScope::BlockTransition).is_error());

  block::WorkchainBatchDescription empty;
  auto current = block::encode_workchain_batch_description(empty);
  ASSERT_TRUE(block::gen::t_TransactionDescr.validate_ref(10000, current));
  ASSERT_TRUE(block::tlb::t_TransactionDescr.validate_ref(10000, current));
  auto transaction = inbound_transaction(current);
  ASSERT_TRUE(block::is_transaction_in_msg(transaction, {}));
  block::tlb::MsgEnvelope::Record_std envelope;
  ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(3), envelope));
  ASSERT_TRUE(!block::is_transaction_in_msg(transaction, envelope.msg));
}

TEST(WorkchainBlock, BatchTimeFollowsEveryInputAndLeavesEndSpace) {
  ASSERT_EQ(block::workchain_batch_start_lt(10).move_as_ok(), 11u);
  auto inbox = block::encode_workchain_batch_inbound(
      {inbound_envelope(20), inbound_envelope(3, 1, 30)}).move_as_ok();
  ASSERT_EQ(block::workchain_batch_start_lt(10, inbox).move_as_ok(), 31u);
  ASSERT_EQ(block::workchain_batch_start_lt(40, inbox).move_as_ok(), 41u);
  // Even an inconsistent old emission time cannot hide the creation LT.
  auto created = block::encode_workchain_batch_inbound({inbound_envelope(50, 0, 2)}).move_as_ok();
  ASSERT_EQ(block::workchain_batch_start_lt(10, created).move_as_ok(), 51u);
  auto maximum = std::numeric_limits<std::uint64_t>::max();
  ASSERT_EQ(block::workchain_batch_start_lt(maximum - 2).move_as_ok(), maximum - 1);
  ASSERT_TRUE(block::workchain_batch_start_lt(maximum - 1).is_error());
  ASSERT_TRUE(block::workchain_batch_start_lt(maximum).is_error());
  auto exhausted = block::encode_workchain_batch_inbound({inbound_envelope(maximum - 1)}).move_as_ok();
  ASSERT_TRUE(block::workchain_batch_start_lt(0, exhausted).is_error());
  ASSERT_TRUE(block::workchain_batch_start_lt(0, number(0)).is_error());
}

TEST(WorkchainBlock, InboxReconstructedFromNativeImports) {
  auto first = inbound_envelope(3);
  auto second = inbound_envelope(4);
  auto expected = block::encode_workchain_batch_inbound({first, second}).move_as_ok();
  block::WorkchainBatchDescription description;
  description.input_hash.set_zero();
  description.effects_hash.set_zero();
  description.inbound_messages = expected;
  auto transaction = inbound_transaction(block::encode_workchain_batch_description(description));
  auto final = vm::CellBuilder().store_long(4, 3).store_ref(first).store_ref(transaction)
      .store_long(1, 4).store_long(67, 8).finalize();
  auto deferred = vm::CellBuilder().store_long(4, 5).store_ref(second).store_ref(transaction)
      .store_long(1, 4).store_long(67, 8).finalize();
  auto transit = vm::CellBuilder().store_long(5, 5).store_ref(first).store_ref(first).finalize();
  auto routed = vm::CellBuilder().store_long(5, 3).store_ref(first).store_ref(first).store_long(0, 4).finalize();
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, final));
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, deferred));
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, transit));
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, routed));
  auto rebuilt = block::workchain_batch_inbound_from_imports({deferred, transit, routed, final}).move_as_ok();
  ASSERT_TRUE(rebuilt->get_hash() == expected->get_hash());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({transit}).move_as_ok().is_null());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({}).move_as_ok().is_null());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({final, final}).is_error());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({{}}).is_error());
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({number(0)}).is_error());
  // A well-formed discarded message is not a final delivery to the engine.
  auto discarded = vm::CellBuilder().store_long(6, 3).store_ref(first).store_long(10, 64)
      .store_long(1, 4).store_long(67, 8).finalize();
  ASSERT_TRUE(block::gen::t_InMsg.validate_ref(10000, discarded));
  ASSERT_TRUE(block::workchain_batch_inbound_from_imports({discarded}).is_error());
}

TEST(WorkchainBlock, NativeBatchCreditIsAtomicAndReplayable) {
  auto in = input();
  in.inbound_messages = block::encode_workchain_batch_inbound(
      {inbound_envelope(3), inbound_envelope(4)}).move_as_ok();
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  auto old_hash = account.total_state->get_hash();
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  using Transaction = block::transaction::Transaction;
  Transaction tx(account, Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(tx.prepare_workchain_batch(in, effects, cfg).is_ok());
  ASSERT_TRUE(tx.balance == block::CurrencyCollection(200));
  ASSERT_TRUE(tx.total_fees.is_zero());
  ASSERT_TRUE(account.balance.is_zero());
  ASSERT_TRUE(tx.serialize(cfg));
  ASSERT_TRUE(block::replay_workchain_batch_transaction(
      CounterEngine(), in, tx.root, 2, td::Bits256::zero(), 10, 10, cfg).is_ok());
  ASSERT_TRUE(account.total_state->get_hash() == old_hash);

  for (auto late : {inbound_envelope(10), inbound_envelope(3, 0, 10)}) {
    auto changed = in;
    changed.inbound_messages = block::encode_workchain_batch_inbound({late}).move_as_ok();
    Transaction rejected(account, Transaction::tr_workchain_batch, 10, 10);
    ASSERT_TRUE(rejected.prepare_workchain_batch(changed, effects, cfg).is_error());
    ASSERT_TRUE(rejected.balance.is_zero());
    ASSERT_TRUE(!rejected.serialize(cfg));
  }
  vm::CellBuilder message;
  message.store_long(4, 4).store_zeroes(2)
      .store_long(4, 3).store_long(-1, 8).store_zeroes(256);
  ASSERT_TRUE(block::CurrencyCollection(100).store(message));
  message.store_zeroes(8).store_zeroes(96).store_zeroes(2);
  auto outbound = message.finalize();
  vm::Dictionary requests(15);
  for (unsigned i = 0; i < 2; ++i) {
    ASSERT_TRUE(requests.set_ref(td::BitArray<15>(i), outbound));
  }
  vm::CellBuilder encoded_requests;
  ASSERT_TRUE(std::move(requests).append_dict_to_bool(encoded_requests));
  auto costly = effects;
  costly.outbound_messages = encoded_requests.finalize();
  block::WorkchainSet workchains;
  block::ActionPhaseConfig message_cfg;
  message_cfg.workchains = &workchains;
  message_cfg.global_version = cfg.global_version;
  message_cfg.fwd_mc.lump_price = 100;
  message_cfg.fwd_mc.first_frac = 32768;
  vm::Dictionary one_request(15);
  unsigned first_index = 0;
  ASSERT_TRUE(one_request.set_ref(td::BitArray<15>(first_index), outbound));
  vm::CellBuilder one_encoded;
  ASSERT_TRUE(std::move(one_request).append_dict_to_bool(one_encoded));
  auto funded_input = in;
  funded_input.candidate = vm::CellBuilder().store_long(2, 64).store_ref(one_encoded.finalize()).finalize();
  auto funded_effects = CounterEngine().execute_block(funded_input).move_as_ok();
  Transaction funded(account, Transaction::tr_workchain_batch, 10, 10);
  ASSERT_TRUE(funded.prepare_workchain_batch(funded_input, funded_effects, cfg, &message_cfg).is_ok());
  ASSERT_TRUE(funded.balance.is_zero());
  ASSERT_EQ(funded.out_msgs.size(), 1u);
  ASSERT_TRUE(funded.serialize(cfg));
  ASSERT_TRUE(block::replay_workchain_batch_transaction(
      CounterEngine(), funded_input, funded.root, 2, td::Bits256::zero(), 10, 10, cfg, &message_cfg).is_ok());
  Transaction insufficient(account, Transaction::tr_workchain_batch, 10, 10);
  auto failure = insufficient.prepare_workchain_batch(in, costly, cfg, &message_cfg);
  ASSERT_TRUE(failure.is_error());
  ASSERT_EQ(failure.message(), "batch native message send failed");
  ASSERT_TRUE(insufficient.balance.is_zero());
  ASSERT_TRUE(insufficient.out_msgs.empty());
  ASSERT_TRUE(insufficient.total_fees.is_zero());
  ASSERT_TRUE(account.total_state->get_hash() == old_hash);
}

TEST(WorkchainBlock, AccountEmulatorRejectsBatchTransaction) {
  block::WorkchainBatchDescription description;
  description.input_hash.set_zero();
  description.effects_hash.set_zero();
  auto messages = vm::CellBuilder().store_long(0, 2).finalize();
  auto update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  auto transaction = vm::CellBuilder().store_long(7, 4).store_zeroes(256).store_long(1, 64)
      .store_zeroes(256).store_long(0, 64).store_long(1, 32).store_long(0, 15)
      .store_long(0, 4).store_ref(messages).store_long(0, 5).store_ref(update)
      .store_ref(block::encode_workchain_batch_description(description)).finalize();
  ASSERT_TRUE(block::gen::t_Transaction.validate_ref(10000, transaction));
  ASSERT_TRUE(block::tlb::t_Transaction.validate_ref(10000, transaction));
  emulator::TransactionEmulator emulator(std::make_shared<block::Config>(0));
  block::Account account(2, td::Bits256::zero().bits());
  account.now_ = 17;
  auto result = emulator.emulate_transaction(std::move(account), transaction);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().message(), "transaction description does not match execution scope");
  ASSERT_EQ(account.now_, 17u);
}

TEST(WorkchainBlock, ResultWireRoundTrip) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  auto root = block::encode_workchain_block_result(produced).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainBlockResult.validate_ref(10000, root));
  auto bytes = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
  auto validated = block::replay_workchain_block(engine, in, restored).move_as_ok();
  auto encoded = block::encode_workchain_block_result(validated).move_as_ok();
  ASSERT_TRUE(encoded->get_hash() == root->get_hash());
  td::Ref<vm::Cell> block::WorkchainBlockResult::* fields[] = {
      &block::WorkchainBlockResult::new_engine_state,
      &block::WorkchainBlockResult::outbound_messages, &block::WorkchainBlockResult::actions,
      &block::WorkchainBlockResult::receipts, &block::WorkchainBlockResult::events,
      &block::WorkchainBlockResult::data_availability};
  std::uint64_t value = 100;
  for (auto field : fields) produced.*field = number(value++);
  auto distinct = block::encode_workchain_block_result(produced).move_as_ok();
  auto decoded = block::decode_workchain_block_result(distinct).move_as_ok();
  for (auto field : fields) {
    ASSERT_TRUE((decoded.*field)->get_hash() == (produced.*field)->get_hash());
  }
  produced = engine.execute_block(in).move_as_ok();
  produced.usage = {std::numeric_limits<std::uint64_t>::max(), 0,
                    std::numeric_limits<std::uint64_t>::max()};
  auto extreme = block::encode_workchain_block_result(produced).move_as_ok();
  ASSERT_TRUE(block::decode_workchain_block_result(extreme).move_as_ok().usage == produced.usage);
  auto mismatch = block::replay_workchain_block(engine, in, extreme);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "block execution replay differs from claimed result");
  produced.receipts = {};
  ASSERT_TRUE(block::encode_workchain_block_result(produced).is_error());
}

TEST(WorkchainBlock, RejectNonCanonicalResultWire) {
  CounterEngine engine;
  auto produced = engine.execute_block(input()).move_as_ok();
  auto valid = block::encode_workchain_block_result(produced).move_as_ok();
  auto cs = vm::load_cell_slice(valid);
  auto outputs = cs.prefetch_ref(1);
  auto envelope = [&](std::uint32_t tag, td::Ref<vm::Cell> out, unsigned extra_bits, unsigned refs) {
    vm::CellBuilder cb;
    cb.store_long(tag, 32).store_long(8, 64).store_long(1, 64).store_long(3, 64);
    if (extra_bits) cb.store_long(0, extra_bits);
    td::Ref<vm::Cell> children[] = {produced.new_engine_state, out,
                                  produced.data_availability, number(99)};
    for (unsigned i = 0; i < refs; ++i) cb.store_ref(children[i]);
    return cb.finalize();
  };
  auto reject = [&](td::Ref<vm::Cell> root, td::Slice expected) {
    auto decoded = block::decode_workchain_block_result(root);
    ASSERT_TRUE(decoded.is_error());
    ASSERT_EQ(decoded.error().message(), expected);
    ASSERT_TRUE(!block::gen::t_WorkchainBlockResult.validate_ref(10000, root));
  };
  auto absent = block::decode_workchain_block_result({});
  ASSERT_TRUE(absent.is_error());
  ASSERT_EQ(absent.error().message(), "missing block result envelope");
  auto proof = vm::MerkleProof::generate(valid, [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  reject(proof, "invalid block result envelope");
  auto output_proof = vm::MerkleProof::generate(outputs, [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  reject(envelope(0x57425232, output_proof, 0, 3), "invalid block output envelope");
  reject(envelope(0x57425231, outputs, 0, 3), "invalid block result envelope");
  reject(envelope(0x57425232, outputs, 1, 3), "invalid block result envelope");
  reject(envelope(0x57425232, outputs, 0, 2), "invalid block result envelope");
  reject(envelope(0x57425232, outputs, 0, 4), "invalid block result envelope");
  for (int mutation = 0; mutation < 3; ++mutation) {
    vm::CellBuilder cb;
    cb.store_long(mutation == 0 ? 0x57424f30 : 0x57424f31, 32);
    if (mutation == 1) cb.store_long(0, 1);
    cb.store_ref(produced.outbound_messages).store_ref(produced.actions).store_ref(produced.receipts);
    if (mutation != 2) cb.store_ref(produced.events);
    reject(envelope(0x57425232, cb.finalize(), 0, 3), "invalid block output envelope");
  }
}

TEST(WorkchainBlock, RejectEveryResultMutation) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  td::Ref<vm::Cell> block::WorkchainBlockResult::* fields[] = {
      &block::WorkchainBlockResult::new_engine_state,
      &block::WorkchainBlockResult::outbound_messages, &block::WorkchainBlockResult::actions,
      &block::WorkchainBlockResult::receipts, &block::WorkchainBlockResult::events,
      &block::WorkchainBlockResult::data_availability};
  for (auto field : fields) {
    auto altered = produced;
    altered.*field = number(99);
    auto result = block::replay_workchain_block(engine, in, altered);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "block execution replay differs from claimed result");
    altered.*field = {};
    ASSERT_TRUE(block::replay_workchain_block(engine, in, altered).is_error());
  }
  for (int i = 0; i < 3; ++i) {
    auto altered = produced;
    if (i == 0) altered.usage.wire_bytes = 99;
    if (i == 1) altered.usage.verification_units = 99;
    if (i == 2) altered.usage.written_cells = 99;
    ASSERT_TRUE(block::replay_workchain_block(engine, in, altered).is_error());
  }
}

TEST(WorkchainBlock, RejectOverflowAndMissingContext) {
  CounterEngine engine;
  auto in = input();
  auto produced = engine.execute_block(in).move_as_ok();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, std::numeric_limits<std::uint64_t>::max());
  auto overflow = block::replay_workchain_block(engine, in, produced);
  ASSERT_TRUE(overflow.is_error());
  ASSERT_EQ(overflow.error().message(), "counter overflow");
  in = input();
  in.finality_context = {};
  auto missing = block::replay_workchain_block(engine, in, produced);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "block replay requires state, candidate, configuration and finality");
}

TEST(WorkchainBlock, CollationCandidateScope) {
  using Scope = block::WorkchainExecutionScope;
  ASSERT_TRUE(block::validate_workchain_candidate_scope({}, Scope::AccountCompute).is_ok());
  ASSERT_TRUE(block::validate_workchain_candidate_scope(number(2), Scope::BlockTransition).is_ok());
  auto missing = block::validate_workchain_candidate_scope({}, Scope::BlockTransition);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "workchain candidate does not match configured execution scope");
  auto unexpected = block::validate_workchain_candidate_scope(number(2), Scope::AccountCompute);
  ASSERT_TRUE(unexpected.is_error());
  ASSERT_EQ(unexpected.error().message(), missing.error().message());
  ASSERT_TRUE(block::validate_workchain_candidate_scope({}, static_cast<Scope>(255)).is_error());
}

TEST(WorkchainBlock, InputPreflightUnionAndExactLimits) {
  auto shared = vm::CellBuilder().store_long(5, 3).finalize();
  auto first = vm::CellBuilder().store_long(0, 1).store_ref(shared).store_ref(shared).finalize();
  auto second = vm::CellBuilder().store_long(1, 2).store_ref(shared).finalize();
  block::WorkchainInputPreflight gate({3, 6, 3});
  ASSERT_TRUE(gate.add(first).is_ok());
  ASSERT_EQ(gate.usage().cells, 2u);
  ASSERT_EQ(gate.usage().bits, 4u);
  ASSERT_TRUE(gate.add(second).is_ok());
  ASSERT_TRUE(gate.add(first).is_ok());
  ASSERT_EQ(gate.usage().cells, 3u);
  ASSERT_EQ(gate.usage().bits, 6u);
  ASSERT_EQ(gate.usage().roots, 3u);
  ASSERT_TRUE(gate.add(first).is_error());
  block::WorkchainInputPreflight cells({2, 6, 2});
  ASSERT_TRUE(cells.add(first).is_ok());
  ASSERT_TRUE(cells.add(second).is_error());
  block::WorkchainInputPreflight bits({3, 5, 2});
  ASSERT_TRUE(bits.add(first).is_ok());
  ASSERT_TRUE(bits.add(second).is_error());
  ASSERT_TRUE(bits.add(first).is_error());
}

TEST(WorkchainBlock, InputPreflightStopsBeforeOverLimitLoad) {
  unsigned root_loads = 0, child_loads = 0;
  td::Ref<PreflightObservedCell> child{true, number(1), &child_loads};
  auto raw_root = vm::CellBuilder().store_long(1, 1).store_ref(child).finalize();
  td::Ref<PreflightObservedCell> root{true, raw_root, &root_loads};
  block::WorkchainInputPreflight gate({1, 65, 1});
  auto rejected = gate.add(root);
  ASSERT_EQ(root_loads, 1u);
  ASSERT_EQ(child_loads, 0u);
  ASSERT_TRUE(rejected.is_error());
  block::WorkchainInputPreflight accepted({2, 65, 1});
  ASSERT_TRUE(accepted.add(root).is_ok());
  ASSERT_EQ(root_loads, 2u);
  ASSERT_EQ(child_loads, 1u);
  block::WorkchainInputPreflight bits({2, 0, 1});
  ASSERT_TRUE(bits.add(root).is_error());
  ASSERT_EQ(root_loads, 3u);
  ASSERT_EQ(child_loads, 1u);
}

TEST(WorkchainBlock, InputPreflightDeepSharedGraph) {
  auto cell = vm::CellBuilder().finalize();
  for (unsigned i = 0; i < vm::CellTraits::max_depth; ++i) {
    cell = vm::CellBuilder().store_ref(cell).store_ref(cell).store_ref(cell).store_ref(cell).finalize();
  }
  block::WorkchainInputPreflight gate({vm::CellTraits::max_depth + 1, 0, 1});
  ASSERT_TRUE(gate.add(cell).is_ok());
  ASSERT_EQ(gate.usage().cells, vm::CellTraits::max_depth + 1u);
  ASSERT_EQ(gate.usage().bits, 0u);
}

TEST(WorkchainBlock, InputPreflightUnavailableAndSpecial) {
  unsigned loads = 0;
  td::Ref<PreflightObservedCell> absent{true, number(1), &loads, true};
  block::WorkchainInputPreflight unavailable({10, 1024, 2});
  ASSERT_TRUE(unavailable.add(absent).is_error());
  ASSERT_EQ(loads, 1u);
  ASSERT_TRUE(unavailable.add(number(1)).is_error());
  auto proof = vm::MerkleProof::generate(number(1), [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  block::WorkchainInputPreflight special({10, 1024, 1});
  ASSERT_TRUE(special.add(proof).is_error());
  block::WorkchainInputPreflight missing({1, 1, 1});
  ASSERT_TRUE(missing.add({}).is_error());
}

TEST(WorkchainBlock, EngineSpecialInputClassification) {
  const td::Ref<vm::Cell> special_cells[] = {
      vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true),
      vm::CellBuilder::do_create_pruned_branch(number(2), 1, 0),
      vm::CellBuilder::create_merkle_proof(number(2))};
  ASSERT_TRUE(CounterEngine().execute_block(input()).is_ok());
  for (const auto& special : special_cells) {
    bool is_special = false;
    vm::load_cell_slice_special(special, is_special);
    ASSERT_TRUE(is_special);
    auto in = input();
    in.candidate = special;
    auto result = CounterEngine().execute_block(in);
    ASSERT_TRUE(result.is_error());
    ASSERT_TRUE(!block::workchain_execution_requires_local_failure(result.error()));
  }

  // Native state/update transport permits library cells below account data;
  // transport authentication does not enforce an engine-specific state schema.
  auto before = shard_fixture();
  auto after = shard_fixture(2, 2, true, 1, false, 0, 40, false, 0, {}, special_cells[0]);
  auto update = vm::CellBuilder::create_merkle_update(before, after);
  ASSERT_TRUE(vm::MerkleUpdate::validate(update).is_ok());
  auto applied = vm::MerkleUpdate::apply(before, update).move_as_ok();
  ASSERT_TRUE(applied->get_hash() == after->get_hash());
  auto in = input();
  in.previous_shard_state = applied;
  auto state = block::extract_workchain_engine_state(applied, 2, td::Bits256::zero()).move_as_ok();
  ASSERT_TRUE(state->get_hash() == special_cells[0]->get_hash());
  auto result = CounterEngine().execute_block(in);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().code(), static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(result.error()));
}

TEST(WorkchainBlock, EngineExceptionIsNotCandidateInvalid) {
  class ThrowingEngine final : public block::RegisteredWorkchainBlockEngine {
   public:
    explicit ThrowingEngine(unsigned kind) : kind_(kind) {}
    block::WorkchainEngineKey engine_key() const override { return CounterEngine().engine_key(); }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& d, const block::Config& c,
        const td::Ref<vm::Cell>& root) const override {
      return CounterEngine().validate_and_resolve_config(d, c, root);
    }
    td::Result<block::WorkchainBlockPolicy> block_policy(
        const block::WorkchainExecutionDescriptor& d, const block::WorkchainEngineConfig& c) const override {
      return CounterEngine().block_policy(d, c);
    }
    td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput&) const override {
      ++calls;
      switch (kind_) {
        case 0: throw vm::VmError(vm::Excno::cell_und);
        case 1: throw vm::VmVirtError();
        case 2: throw vm::VmNoGas();
        case 3: throw vm::CellBuilder::CellCreateError();
        default: throw vm::CellBuilder::CellWriteError();
      }
    }
    mutable unsigned calls = 0;
   private:
    unsigned kind_;
  };
  for (unsigned kind = 0; kind < 5; ++kind) {
    ThrowingEngine engine(kind);
    block::ResolvedWorkchainBlockExecution execution;
    execution.executor = &engine;
    execution.descriptor.workchain_id = 2;
    execution.engine_config = std::make_shared<block::WorkchainEngineConfig>();
    execution.policy.limits = {8, 1, 3};
    auto result = block::execute_resolved_workchain_block(execution, input());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    auto prefixed = result.move_as_error().move_as_error_prefix("replay: ");
    ASSERT_TRUE(block::workchain_execution_requires_local_failure(prefixed));
  }
  ASSERT_TRUE(!block::workchain_execution_requires_local_failure(td::Status::Error("invalid candidate")));
  ASSERT_TRUE(!block::workchain_execution_requires_local_failure(td::Status::OK()));
}

TEST(WorkchainBlock, RegistryScopeIsolation) {
  block::WorkchainExecutionRegistry registry;
  CounterEngine counter;
  const auto key = counter.engine_key();
  ASSERT_TRUE(!registry.execution_scope(key).has_value());
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  ASSERT_TRUE(registry.has_engine(key));
  ASSERT_TRUE(registry.execution_scope(key) == block::WorkchainExecutionScope::BlockTransition);
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_error());
  ASSERT_TRUE(registry.register_block_engine(nullptr).is_error());
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = static_cast<std::int32_t>(key.selector);
  auto resolved = registry.resolve_block(descriptor, configuration).move_as_ok();
  auto scoped = registry.resolve_scoped(descriptor, configuration).move_as_ok();
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainBlockExecution>(scoped));
  ASSERT_TRUE(std::get<block::ResolvedWorkchainBlockExecution>(scoped).executor == resolved.executor);
  auto in = input();
  auto produced = block::execute_resolved_workchain_block(resolved, in).move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(produced.new_engine_state).fetch_ulong(64), 42u);
  auto account = registry.resolve(descriptor, configuration);
  ASSERT_TRUE(account.is_error());
  ASSERT_EQ(account.error().message(), "block engine cannot execute through account compute");
  descriptor.max_split = 1;
  auto split = registry.resolve_block(descriptor, configuration);
  ASSERT_TRUE(split.is_error());
  ASSERT_EQ(split.error().message(), "native ingress policy differs from execution descriptor");
  descriptor.max_split = 0;
  descriptor.vm_mode = 1;
  auto mode_configuration = block_configuration(block::kBlockTransitionMinGlobalVersion, tos::capBlockTransition, 1);
  auto null_config = registry.resolve_block(descriptor, *mode_configuration);
  ASSERT_TRUE(null_config.is_error());
  ASSERT_EQ(null_config.error().message(), "block engine returned null configuration");
  descriptor.active = false;
  auto inactive = registry.resolve_block(descriptor, configuration);
  ASSERT_TRUE(inactive.is_error());
  ASSERT_EQ(inactive.error().message(), "block workchain is inactive");
  descriptor.active = true;
  descriptor.vm_version = -1;
  auto missing = registry.resolve_block(descriptor, configuration);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "descriptor has no registered block engine");
  auto& native_registry = block::default_workchain_execution_registry();
  descriptor.vm_mode = 0;
  descriptor.workchain_id = 0;
  ASSERT_TRUE(native_registry.execution_scope(block::tvm_workchain_engine_key()) ==
              block::WorkchainExecutionScope::AccountCompute);
  ASSERT_TRUE(native_registry.resolve(descriptor, configuration).is_ok());
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainExecution>(
      native_registry.resolve_scoped(descriptor, configuration).move_as_ok()));
}

TEST(WorkchainBlock, IngressProtocolScopeDoesNotDependOnRegistry) {
  block::WorkchainNativeIngressPolicy ingress;
  ingress.workchain_id = 2;
  ingress.engine_key = block::tvm_workchain_engine_key();
  ingress.engine_configuration = vm::CellBuilder().finalize();
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = static_cast<std::int32_t>(ingress.engine_key.selector);
  block::WorkchainExecutionRegistry empty;
  ASSERT_TRUE(!empty.has_engine(ingress.engine_key));
  ASSERT_TRUE(block::reserved_workchain_engine_scope(ingress.engine_key) ==
              block::WorkchainExecutionScope::AccountCompute);
  ASSERT_TRUE(block::validate_workchain_native_ingress_binding(ingress, descriptor).is_error());
  ingress.engine_key = CounterEngine().engine_key();
  descriptor.vm_version = static_cast<std::int32_t>(ingress.engine_key.selector);
  ASSERT_TRUE(!empty.has_engine(ingress.engine_key));
  ASSERT_TRUE(block::validate_workchain_native_ingress_binding(ingress, descriptor).is_ok());
}

TEST(WorkchainBlock, DeclaredScopePreventsLocalComputeFallback) {
  class WrongLocalEngine final : public block::WorkchainEngine {
   public:
    explicit WrongLocalEngine(unsigned* calls) : calls_(calls) {}
    block::WorkchainEngineKey engine_key() const override { return CounterEngine().engine_key(); }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&) const override {
      ++*calls_;
      return std::shared_ptr<const block::WorkchainEngineConfig>(std::make_shared<block::WorkchainEngineConfig>());
    }
    block::AccountExecutionPolicy account_policy(const block::WorkchainExecutionDescriptor&,
        const block::WorkchainEngineConfig&) const override { return {}; }
    td::Result<block::WorkchainComputeOutput> run_compute(const block::WorkchainComputeInput&,
        const block::WorkchainComputeContext&) const override { return td::Status::Error("not invoked"); }
   private:
    unsigned* calls_;
  };
  unsigned calls = 0;
  block::WorkchainExecutionRegistry registry;
  registry.register_engine(std::make_unique<WrongLocalEngine>(&calls));
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = static_cast<std::int32_t>(CounterEngine().engine_key().selector);
  auto declared = block_configuration();
  auto scoped = registry.resolve_scoped(descriptor, *declared);
  auto direct = registry.resolve(descriptor, *declared);
  ASSERT_EQ(calls, 0u);
  ASSERT_TRUE(scoped.is_error());
  ASSERT_TRUE(direct.is_error());
  auto ordinary = block_configuration(block::kBlockTransitionMinGlobalVersion, tos::capBlockTransition, 0, false);
  ASSERT_TRUE(registry.resolve_scoped(descriptor, *ordinary).is_ok());
  ASSERT_EQ(calls, 1u);
}

TEST(WorkchainBlock, RegistryRequiresConsensusActivation) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  auto activated = block_configuration();
  ASSERT_TRUE(registry.resolve_block(descriptor, *activated).is_ok());
  for (int version : {block::kBlockTransitionMinGlobalVersion - 1,
                      block::kBlockTransitionMinGlobalVersion}) {
    for (td::uint64 capabilities : {td::uint64{0}, td::uint64{tos::capBlockTransition}}) {
      auto config = block_configuration(version, capabilities);
      bool expected = version >= block::kBlockTransitionMinGlobalVersion && capabilities != 0;
      ASSERT_EQ(registry.resolve_block(descriptor, *config).is_ok(), expected);
      ASSERT_EQ(registry.resolve_scoped(descriptor, *config).is_ok(), expected);
    }
  }
  block::Config unavailable(0);
  ASSERT_TRUE(registry.resolve_block(descriptor, unavailable).is_error());
}

TEST(WorkchainBlock, PublicIngressPolicyCodecAndDescriptorBinding) {
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x554e4f32};
  policy.vm_mode = 17;
  policy.descriptor_version = 2;
  policy.executor_address = number(9)->get_hash().bits();
  policy.engine_configuration = number(42);
  auto root = block::encode_workchain_native_ingress_policy(policy).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressPolicy.validate_ref(10000, root));
  auto wire = vm::std_boc_serialize(root).move_as_ok();
  auto restored = vm::std_boc_deserialize(wire.as_slice()).move_as_ok();
  auto decoded = block::decode_workchain_native_ingress_policy(restored).move_as_ok();
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(decoded).move_as_ok()->get_hash() == root->get_hash());
  ASSERT_TRUE(decoded.executor_address == policy.executor_address);
  ASSERT_TRUE(decoded.engine_configuration->get_hash() == policy.engine_configuration->get_hash());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x554e4f32;
  descriptor.vm_mode = 17;
  descriptor.version = 2;
  ASSERT_TRUE(block::validate_workchain_native_ingress_binding(decoded, descriptor).is_ok());
  for (int mutation = 0; mutation < 6; ++mutation) {
    auto changed = descriptor;
    if (mutation == 0) changed.workchain_id = 3;
    if (mutation == 1) changed.vm_version = 1;
    if (mutation == 2) changed.vm_mode = 18;
    if (mutation == 3) changed.version = 3;
    if (mutation == 4) changed.active = false;
    if (mutation == 5) changed.max_split = 1;
    ASSERT_TRUE(block::validate_workchain_native_ingress_binding(decoded, changed).is_error());
  }
  auto invalid = policy;
  invalid.engine_key.selector = std::numeric_limits<std::int64_t>::max();
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(invalid).is_error());
  invalid = policy;
  invalid.workchain_id = -1;
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(invalid).is_error());
  invalid = policy;
  invalid.engine_configuration = {};
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(invalid).is_error());
  auto extended = policy;
  extended.engine_key = {block::WorkchainFormat::Extended, std::numeric_limits<std::uint32_t>::max()};
  extended.vm_mode = 0;
  auto extended_root = block::encode_workchain_native_ingress_policy(extended).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressPolicy.validate_ref(10000, extended_root));
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(extended_root).move_as_ok().engine_key == extended.engine_key);
  extended.vm_mode = 1;
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(extended).is_error());
  auto wide_mode = policy;
  wide_mode.vm_mode = std::numeric_limits<std::uint64_t>::max();
  auto wide_root = block::encode_workchain_native_ingress_policy(wide_mode).move_as_ok();
  ASSERT_EQ(block::decode_workchain_native_ingress_policy(wide_root).move_as_ok().vm_mode, wide_mode.vm_mode);
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy({}).is_error());
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(number(0)).is_error());
  auto extra = vm::CellBuilder().append_cellslice(vm::load_cell_slice(root)).store_long(0, 1).finalize();
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(extra).is_error());
}

TEST(WorkchainBlock, PublicIngressRequiresStandardWorkchainRange) {
  block::WorkchainNativeIngressPolicy policy;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address.set_zero();
  policy.engine_configuration = number(0);
  for (int id : {0, 127, 128, std::numeric_limits<std::int32_t>::max()}) {
    policy.workchain_id = id;
    ASSERT_EQ(block::encode_workchain_native_ingress_policy(policy).is_ok(), id <= 127);
    auto raw = vm::CellBuilder().store_long(0x57495031, 32).store_long(id, 32).store_long(0, 1)
        .store_long(policy.engine_key.selector, 64).store_zeroes(64 + 32 + 256)
        .store_ref(policy.engine_configuration).finalize();
    ASSERT_TRUE(block::gen::t_WorkchainNativeIngressPolicy.validate_ref(10000, raw));
    ASSERT_EQ(block::decode_workchain_native_ingress_policy(raw).is_ok(), id <= 127);
  }
}

TEST(WorkchainBlock, PublicIngressTableCanonicalKeys) {
  block::WorkchainNativeIngressPolicy first;
  first.workchain_id = 2;
  first.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  first.executor_address.set_zero();
  first.engine_configuration = number(1);
  auto second = first;
  second.workchain_id = 3;
  second.engine_configuration = number(2);
  auto encoded = block::encode_workchain_native_ingress_table({first, second}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressTable.validate_ref(10000, encoded));
  auto reversed = block::encode_workchain_native_ingress_table({second, first}).move_as_ok();
  ASSERT_TRUE(encoded->get_hash() == reversed->get_hash());
  auto wire = vm::std_boc_serialize(encoded).move_as_ok();
  auto decoded = block::decode_workchain_native_ingress_table(vm::std_boc_deserialize(wire.as_slice()).move_as_ok())
      .move_as_ok();
  ASSERT_EQ(decoded.size(), 2u);
  ASSERT_TRUE(decoded.at(3).engine_configuration->get_hash() == second.engine_configuration->get_hash());
  auto empty = block::encode_workchain_native_ingress_table({}).move_as_ok();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressTable.validate_ref(10000, empty));
  ASSERT_TRUE(block::decode_workchain_native_ingress_table(empty).move_as_ok().empty());
  ASSERT_TRUE(block::encode_workchain_native_ingress_table({first, first}).is_error());
  vm::Dictionary wrong(32);
  ASSERT_TRUE(wrong.set_ref(td::BitArray<32>(3u), block::encode_workchain_native_ingress_policy(first).move_as_ok()));
  vm::CellBuilder cb;
  cb.store_long(0x57495431, 32);
  ASSERT_TRUE(std::move(wrong).append_dict_to_bool(cb));
  auto wrong_key = cb.finalize();
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressTable.validate_ref(10000, wrong_key));
  ASSERT_TRUE(block::decode_workchain_native_ingress_table(wrong_key).is_error());
  ASSERT_TRUE(block::decode_workchain_native_ingress_table({}).is_error());
  ASSERT_TRUE(block::decode_workchain_native_ingress_table(number(0)).is_error());
}

TEST(WorkchainBlock, NativeSenderEnforcesPublicExecutorAddress) {
  td::Ref<block::WorkchainInfo> info{true};
  info.write().workchain = 2;
  info.write().basic = info.write().active = info.write().accept_msgs = true;
  info.write().min_addr_len = info.write().max_addr_len = 256;
  info.write().addr_len_step = 0;
  block::WorkchainSet workchains{{2, info}};
  info.clear();
  auto in = input();
  in.previous_shard_state = shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000);
  auto effects = CounterEngine().execute_block(in).move_as_ok();
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(in.previous_shard_state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account sender(2, td::Bits256::zero().bits());
  ASSERT_TRUE(sender.unpack(accounts.lookup(td::Bits256::zero()), 10, false));
  block::ActionPhaseConfig cfg;
  cfg.workchains = &workchains;
  cfg.native_ingress_destinations.emplace(2, td::Bits256::zero());
  auto address = [](bool wrong) {
    return vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(2, 8)
        .store_zeroes(255).store_long(wrong, 1).finalize());
  };
  auto send = [&](td::Ref<vm::CellSlice> dest, bool accepted) {
    vm::CellBuilder cb;
    cb.store_long(6, 4).store_zeroes(2);
    ASSERT_TRUE(cb.append_cellslice_bool(dest));
    ASSERT_TRUE(block::CurrencyCollection(100).store(cb));
    cb.store_zeroes(8).store_zeroes(96).store_zeroes(2);
    auto message = cb.finalize();
    ASSERT_TRUE(block::gen::t_MessageRelaxed_Any.validate_ref(4096, message));
    vm::Dictionary requests(15);
    unsigned index = 0;
    ASSERT_TRUE(requests.set_ref(td::BitArray<15>(index), message));
    vm::CellBuilder root;
    ASSERT_TRUE(std::move(requests).append_dict_to_bool(root));
    effects.outbound_messages = root.finalize();
    using Transaction = block::transaction::Transaction;
    Transaction tx(sender, Transaction::tr_workchain_batch, 10, 10);
    block::SerializeConfig serialization;
    auto status = tx.prepare_workchain_batch(in, effects, serialization, &cfg);
    ASSERT_EQ(status.is_ok(), accepted);
    ASSERT_EQ(tx.out_msgs.size(), accepted ? 1u : 0u);
    ASSERT_EQ(tx.balance.tomis->to_long(), accepted ? 900 : 1000);
    ASSERT_EQ(sender.balance.tomis->to_long(), 1000);
    return accepted ? tx.out_msgs.front() : td::Ref<vm::Cell>{};
  };
  auto canonical_message = send(address(false), true);
  send(address(true), false);
  auto variable_address = [](bool wrong) {
    return vm::load_cell_slice_ref(vm::CellBuilder().store_long(6, 3).store_long(256, 9)
        .store_long(2, 32).store_zeroes(255).store_long(wrong, 1).finalize());
  };
  auto normalized_message = send(variable_address(false), true);
  ASSERT_TRUE(normalized_message->get_hash() == canonical_message->get_hash());
  send(variable_address(true), false);
  workchains.at(2).write().accept_msgs = false;
  send(address(false), false);
  send(variable_address(false), false);
  workchains.at(2).write().accept_msgs = true;
  send(address(false), true);
  auto anycast = vm::load_cell_slice_ref(vm::CellBuilder().store_long(2, 2).store_long(1, 1)
      .store_long(1, 5).store_long(0, 1).store_long(2, 8).store_zeroes(256).finalize());
  send(anycast, false);
  cfg.native_ingress_destinations.clear();
  send(address(true), true);
  send(anycast, true);
}

TEST(WorkchainBlock, ActivatedHostWithoutIngressPolicyIsIdle) {
  vm::Dictionary dictionary(32);
  vm::CellBuilder version;
  ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(version, 15, tos::capBlockTransition));
  ASSERT_TRUE(dictionary.set_ref(td::BitArray<32>{8}, version.finalize()));
  ASSERT_TRUE(block::validate_native_ingress_presence(dictionary).is_ok());
  auto config = block::Config::unpack_config(dictionary.get_root_cell(), td::Bits256::zero(),
                                             block::Config::needCapabilities).move_as_ok();
  ASSERT_TRUE(block::load_workchain_native_ingress_table(*config).move_as_ok().empty());
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*config).move_as_ok().empty());
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  auto execution = registry.resolve_block(descriptor, *config);
  ASSERT_TRUE(execution.is_error());
  ASSERT_EQ(execution.error().message(), "block workchain has no public native ingress policy");
  ASSERT_TRUE(dictionary.set_ref(td::BitArray<32>{84}, number(0)));
  config = block::Config::unpack_config(dictionary.get_root_cell(), td::Bits256::zero(),
                                       block::Config::needCapabilities).move_as_ok();
  ASSERT_TRUE(block::load_workchain_native_ingress_table(*config).is_error());
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*config).is_error());
}

TEST(WorkchainBlock, NativeIngressParameterPresenceRequiresActivation) {
  for (int version : {14, 15}) {
    for (td::uint64 capabilities : {td::uint64{0}, td::uint64{tos::capBlockTransition}}) {
      vm::Dictionary config(32);
      vm::CellBuilder param;
      ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(param, version, capabilities));
      ASSERT_TRUE(config.set_ref(td::BitArray<32>{8}, param.finalize()));
      ASSERT_TRUE(block::validate_native_ingress_presence(config).is_ok());
      auto table = block::encode_workchain_native_ingress_table({}).move_as_ok();
      ASSERT_TRUE(config.set_ref(td::BitArray<32>{84}, table));
      ASSERT_EQ(block::validate_native_ingress_presence(config).is_ok(), version >= 15 && capabilities != 0);
    }
  }
  vm::Dictionary missing_version(32);
  ASSERT_TRUE(missing_version.set_ref(td::BitArray<32>{84},
      block::encode_workchain_native_ingress_table({}).move_as_ok()));
  ASSERT_TRUE(block::validate_native_ingress_presence(missing_version).is_error());
  ASSERT_TRUE(missing_version.set_ref(td::BitArray<32>{8}, number(0)));
  ASSERT_TRUE(block::validate_native_ingress_presence(missing_version).is_error());
}

TEST(WorkchainBlock, ResolvedBlockResourcePolicy) {
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  const block::WorkchainBlockResourceUsage limits[] = {
      {8, 2, 3}, {9, 3, 4}, {7, 2, 3}, {8, 2, 2}, {8, 1, 3}, {0, 2, 3}, {8, 0, 3}, {8, 2, 0}};
  for (unsigned i = 0; i < std::size(limits); ++i) {
    block::WorkchainExecutionRegistry registry;
    ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>(limits[i], 2)).is_ok());
    auto resolved = registry.resolve_block(descriptor, configuration);
    if (i >= 5) {
      ASSERT_TRUE(resolved.is_error());
      ASSERT_EQ(resolved.error().message(), "block execution policy requires explicit nonzero resource limits");
      continue;
    }
    ASSERT_TRUE(resolved.is_ok());
    ASSERT_TRUE(resolved.ok().policy.limits == limits[i]);
    auto result = block::execute_resolved_workchain_block(resolved.ok(), input());
    if (i >= 2) {
      ASSERT_TRUE(result.is_error());
      ASSERT_EQ(result.error().message(), "block execution exceeds configured resource limits");
      continue;
    }
    ASSERT_TRUE(result.is_ok());
    auto wrong_identity = resolved.ok();
    wrong_identity.policy.executor_address = number(99)->get_hash().bits();
    auto rejected = block::execute_resolved_workchain_block(wrong_identity, input());
    ASSERT_TRUE(rejected.is_error());
    ASSERT_EQ(rejected.error().message(), "block workchain must contain exactly its executor account");
  }
}

TEST(WorkchainBlock, ReceiverRequiresMatchingPublicIngressPolicy) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  auto configuration = [](td::Ref<vm::Cell> table) {
    vm::Dictionary config(32);
    vm::CellBuilder version;
    CHECK(block::gen::t_GlobalVersion.pack_capabilities(version, 15, tos::capBlockTransition));
    CHECK(config.set_ref(td::BitArray<32>{8}, version.finalize()));
    if (table.not_null()) {
      CHECK(config.set_ref(td::BitArray<32>{84}, table));
    }
    return block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
                                       block::Config::needCapabilities).move_as_ok();
  };
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address.set_zero();
  policy.engine_configuration = vm::CellBuilder().finalize();
  auto resolve = [&](std::vector<block::WorkchainNativeIngressPolicy> policies) {
    auto cfg = configuration(block::encode_workchain_native_ingress_table(policies).move_as_ok());
    return registry.resolve_block(descriptor, *cfg);
  };
  ASSERT_TRUE(resolve({policy}).is_ok());
  auto missing = configuration({});
  ASSERT_TRUE(registry.resolve_block(descriptor, *missing).is_error());
  ASSERT_TRUE(resolve({}).is_error());
  auto wrong = policy;
  wrong.workchain_id = 3;
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong = policy;
  wrong.descriptor_version = 1;
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong = policy;
  wrong.executor_address = td::Bits256::ones();
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong = policy;
  wrong.engine_configuration = number(0);
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong.engine_configuration = vm::CellBuilder().store_ref(policy.engine_configuration).finalize();
  ASSERT_TRUE(resolve({wrong}).is_error());
  auto malformed = configuration(number(0));
  ASSERT_TRUE(registry.resolve_block(descriptor, *malformed).is_error());
  ASSERT_TRUE(resolve({policy}).is_ok());
}

TEST(WorkchainBlock, SenderResolvesIngressWithoutForeignEngine) {
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address = td::Bits256::ones();
  policy.engine_configuration = number(0);
  auto configuration = [&](td::Ref<vm::Cell> table, bool include_descriptor, unsigned descriptor_version = 0) {
    vm::Dictionary config(32);
    vm::CellBuilder version;
    CHECK(block::gen::t_GlobalVersion.pack_capabilities(version, 15, tos::capBlockTransition));
    CHECK(config.set_ref(td::BitArray<32>{8}, version.finalize()));
    if (table.not_null()) {
      CHECK(config.set_ref(td::BitArray<32>{84}, table));
    }
    vm::Dictionary workchains(32);
    if (include_descriptor) {
      vm::CellBuilder descriptor;
      descriptor.store_long(0xa6, 8).store_zeroes(32 + 24).store_long(7, 3).store_zeroes(13)
          .store_zeroes(512).store_long(descriptor_version, 32).store_long(1, 4)
          .store_long(0x434e5431, 32).store_zeroes(64);
      auto encoded = descriptor.finalize();
      CHECK(block::gen::t_WorkchainDescr.validate_ref(10000, encoded));
      CHECK(workchains.set(td::BitArray<32>{2}, vm::load_cell_slice_ref(encoded)));
    }
    vm::CellBuilder list;
    CHECK(std::move(workchains).append_dict_to_bool(list));
    CHECK(config.set_ref(td::BitArray<32>{12}, list.finalize()));
    return block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
        block::Config::needCapabilities | block::Config::needWorkchainInfo).move_as_ok();
  };
  auto table = block::encode_workchain_native_ingress_table({policy}).move_as_ok();
  auto good = configuration(table, true);
  ASSERT_TRUE(!block::default_workchain_execution_registry().execution_scope(policy.engine_key).has_value());
  auto destinations = block::resolve_native_ingress_destinations(*good).move_as_ok();
  ASSERT_EQ(destinations.size(), 1u);
  ASSERT_TRUE(destinations.at(2) == policy.executor_address);
  auto missing_descriptor = configuration(table, false);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*missing_descriptor).is_error());
  auto wrong_version = configuration(table, true, 1);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*wrong_version).is_error());
  auto missing_table = configuration({}, true);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*missing_table).move_as_ok().empty());
  auto empty = configuration(block::encode_workchain_native_ingress_table({}).move_as_ok(), true);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*empty).move_as_ok().empty());
}

TEST(WorkchainBlock, ScopedWorkchainConfigurationResolution) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  auto configuration_owner = block_configuration();
  auto& configuration = *configuration_owner;
  td::Ref<block::WorkchainInfo> info{true};
  auto& value = info.write();
  value.workchain = 2;
  value.enabled_since = 0;
  value.monitor_min_split = value.min_split = value.max_split = 0;
  value.basic = value.active = value.accept_msgs = true;
  value.flags = value.version = 0;
  value.zerostate_root_hash.set_zero();
  value.zerostate_file_hash.set_zero();
  value.vm_version = 0x434e5431;
  value.min_addr_len = value.max_addr_len = 256;
  value.addr_len_step = 0;
  block::WorkchainSet workchains{{2, std::move(info)}};
  auto scoped = registry.resolve_scoped_workchain(workchains, 2, configuration).move_as_ok();
  ASSERT_TRUE(scoped.has_value());
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainBlockExecution>(*scoped));
  ASSERT_TRUE(!registry.resolve_scoped_workchain(workchains, tos::masterchainId, configuration).move_as_ok().has_value());
  ASSERT_TRUE(!registry.resolve_scoped_workchain(workchains, 99, configuration).move_as_ok().has_value());
  auto account = registry.resolve_workchain(workchains, 2, configuration);
  ASSERT_TRUE(account.is_error());
  ASSERT_EQ(account.error().message(), "block engine cannot execute through account compute");
  block::LocalWorkchainRoleSet roles;
  roles.required_workchains.insert(2);
  ASSERT_TRUE(registry.validate_required_workchains(workchains, configuration, roles).is_ok());
  block::WorkchainExecutionRegistry unsupported;
  ASSERT_TRUE(unsupported.validate_required_workchains(workchains, configuration, {}).is_ok());
  ASSERT_TRUE(unsupported.validate_required_workchains(workchains, configuration, roles).is_error());
  ASSERT_TRUE(block::default_workchain_execution_registry()
                  .validate_required_workchains(workchains, configuration, roles).is_error());
  workchains[2].write().max_split = 1;
  auto split = registry.resolve_scoped_workchain(workchains, 2, configuration);
  ASSERT_TRUE(split.is_error());
  ASSERT_EQ(split.error().message(), "native ingress policy differs from execution descriptor");
  auto invalid_required = registry.validate_required_workchains(workchains, configuration, roles);
  ASSERT_TRUE(invalid_required.is_error());
  ASSERT_EQ(invalid_required.error().message(), "native ingress policy differs from execution descriptor");
  workchains[2].write().max_split = 0;
  workchains[2].write().workchain = 3;
  auto mismatch = registry.resolve_scoped_workchain(workchains, 2, configuration);
  ASSERT_TRUE(mismatch.is_error());
  ASSERT_EQ(mismatch.error().message(), "workchain descriptor identity differs from configuration key");
  workchains[2].write().workchain = 2;
  workchains[2].write().vm_version = static_cast<std::int32_t>(block::tvm_workchain_engine_key().selector);
  ASSERT_TRUE(block::default_workchain_execution_registry()
                  .validate_required_workchains(workchains, configuration, roles).is_error());
}
