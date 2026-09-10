#include "block/workchain-outbound-queues.h"

#include <limits>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <type_traits>
#include "workchain-counter-engine.h"

#include "block/workchain-block-execution.h"
#include "block/workchain-participant-lt.h"
#include "block/workchain-participant-record.h"
#include "block/workchain-value-flow.h"
#include "block/workchain-native-allocation.h"
#include "block/workchain-allocation-plan.h"
#include "block/workchain-import-evidence.h"
#include "block/workchain-native-inbox.h"
#include "block/native-bounce-body.h"
#include "block/native-bounce-storage.h"
#include "block/native-bounce-message.h"
#include "block/workchain-payout-accounting.h"
#include "block/workchain-bounce-accounting.h"
#include "block/workchain-native-disposal.h"
#include "block/workchain-storage-overlay.h"
#include "block/workchain-payout-overlay.h"
#include "block/workchain-account-access.h"
#include "block/workchain-account-dictionary.h"
#include "block/workchain-account-access-codec.h"
#include "block/workchain-host-identity.h"
#include "block/workchain-resource-policy.h"
#include "block/workchain-coordinator-state.h"
#include "block/workchain-host-input.h"
#include "block/workchain-account-engine.h"
#include "block/workchain-account-settlement.h"
#include "block/workchain-account-replay.h"
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
#include "workchain-fixture-dictionary.h"

namespace {

template <class Cell, class = void>
struct AllowsImplicitAccountPathMode : std::false_type {};

template <class Cell>
struct AllowsImplicitAccountPathMode<Cell, std::void_t<decltype(block::lookup_workchain_account_metered(
    std::declval<const Cell&>(), std::declval<const td::Bits256&>(),
    std::declval<block::NativeStateReadMeter&>()))>> : std::true_type {};

static_assert(!AllowsImplicitAccountPathMode<td::Ref<vm::Cell>>::value,
              "Account lookup callers must explicitly choose Read or Replace");

TEST(WorkchainBlock, SystemStateRegistration) {
  auto first = block::checked_increment_workchain_registered_accounts(0);
  ASSERT_TRUE(first.is_ok());
  ASSERT_EQ(first.ok(), 1u);
  auto last = block::checked_increment_workchain_registered_accounts(UINT64_MAX - 1);
  ASSERT_TRUE(last.is_ok());
  ASSERT_EQ(last.ok(), UINT64_MAX);
  auto overflow = block::checked_increment_workchain_registered_accounts(last.ok());
  ASSERT_TRUE(overflow.is_error());
  ASSERT_EQ(overflow.error().message(), "registered_accounts overflow");
  ASSERT_EQ(last.ok(), UINT64_MAX);
}

td::Ref<vm::Cell> coordinator_budget_fixture() {
  td::Ref<vm::Cell> result;
  CHECK(block::tlb::pack_cell(result, block::gen::UnoV2CoordinatorBudget::Record{0}));
  return result;
}

TEST(WorkchainBlock, CoordinatorStateLayout) {
  block::WorkchainCoordinatorState input{2, {1, UINT64_MAX, UINT64_MAX, UINT16_MAX}, UINT64_MAX};
  auto encoded = block::encode_workchain_coordinator_state(input);
  ASSERT_TRUE(encoded.is_ok());
  auto root = encoded.move_as_ok();
  auto cs = vm::load_cell_slice(root);
  ASSERT_EQ(cs.size(), 48u);
  ASSERT_EQ(cs.size_refs(), 2u);
  ASSERT_EQ(cs.fetch_ulong(32), block::gen::UnoV2CoordinatorDeposits::cons_tag[0]);
  ASSERT_EQ(cs.fetch_ulong(16), 2u);
  auto system = cs.fetch_ref();
  auto ss = vm::load_cell_slice(system);
  ASSERT_EQ(ss.size(), 192u);
  ASSERT_EQ(ss.size_refs(), 0u);
  ASSERT_EQ(ss.fetch_ulong(32), 0xbbd85560u);
  auto decoded = block::decode_workchain_coordinator_state(root);
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().layout_version, 2);
  ASSERT_EQ(decoded.ok().refundable_deposits, UINT64_MAX);
  ASSERT_EQ(decoded.ok().system.layout_version, 1);
  ASSERT_EQ(decoded.ok().system.base_compute, UINT64_MAX);
  ASSERT_EQ(decoded.ok().system.registered_accounts, UINT64_MAX);
  ASSERT_EQ(decoded.ok().system.system_pending_count, UINT16_MAX);
  auto again = block::encode_workchain_coordinator_state(decoded.ok());
  ASSERT_TRUE(again.is_ok());
  ASSERT_EQ(again.ok()->get_hash(), root->get_hash());
  for (int count : {-1, 65536}) {
    auto malformed = input;
    malformed.system.system_pending_count = count;
    ASSERT_TRUE(block::encode_workchain_coordinator_state(malformed).is_error());
  }
  // Raw generated packing makes malformed/unsupported fixtures independently
  // of the supported-layout encoder; no host default is involved.
  for (auto version : {std::uint16_t{0}, std::uint16_t{2}, std::uint16_t{65535}}) {
    auto changed = input;
    changed.layout_version = version == 2 ? 1 : version;
    ASSERT_TRUE(block::encode_workchain_coordinator_state(changed).is_error());
    block::gen::UnoV2CoordinatorDeposits::Record header;
    header.layout_version = changed.layout_version;
    header.system = system;
    header.budget = cs.prefetch_ref();
    td::Ref<vm::Cell> bad;
    ASSERT_TRUE(block::tlb::pack_cell(bad, header));
    ASSERT_TRUE(block::decode_workchain_coordinator_state(bad).is_error());
    changed = input;
    changed.system.layout_version = version;
    ASSERT_TRUE(block::encode_workchain_coordinator_state(changed).is_error());
    ASSERT_TRUE(block::tlb::pack_cell(header.system, changed.system));
    header.layout_version = 2;
    ASSERT_TRUE(block::tlb::pack_cell(bad, header));
    ASSERT_TRUE(block::decode_workchain_coordinator_state(bad).is_error());
  }
}

TEST(WorkchainBlock, CoordinatorStateExactFraming) {
  auto system = vm::CellBuilder().store_long(0xbbd85560, 32).store_long(1, 16)
      .store_long(7, 64).store_long(8, 64).store_long(9, 16).finalize();
  auto wrap = [](td::Ref<vm::Cell> child) {
    return vm::CellBuilder().store_long(block::gen::UnoV2CoordinatorDeposits::cons_tag[0], 32).store_long(2, 16).store_ref(child).store_ref(coordinator_budget_fixture()).finalize();
  };
  auto valid = wrap(system);
  auto fields = block::decode_workchain_coordinator_state(valid);
  ASSERT_TRUE(fields.is_ok());
  ASSERT_EQ(fields.ok().system.base_compute, 7u);
  ASSERT_EQ(fields.ok().system.registered_accounts, 8u);
  ASSERT_EQ(fields.ok().system.system_pending_count, 9);
  ASSERT_TRUE(block::decode_workchain_coordinator_state({}).is_error());
  ASSERT_TRUE(block::decode_workchain_coordinator_state(system).is_error());
  for (unsigned tag : {0u, 0x46ff26c0u, 0xbbd85560u}) {
    auto bad = vm::CellBuilder().store_long(tag, 32).store_long(2, 16).store_ref(system).store_ref(coordinator_budget_fixture()).finalize();
    ASSERT_TRUE(block::decode_workchain_coordinator_state(bad).is_error());
  }
  for (unsigned tag : {0u, 0xbbd85561u, 0x46ff26c1u}) {
    auto bad = vm::CellBuilder().store_long(tag, 32).store_long(1, 16)
        .store_long(7, 64).store_long(8, 64).store_long(9, 16).finalize();
    ASSERT_TRUE(block::decode_workchain_coordinator_state(wrap(bad)).is_error());
  }
  auto no_ref = vm::CellBuilder().store_long(block::gen::UnoV2CoordinatorDeposits::cons_tag[0], 32).store_long(2, 16).finalize();
  ASSERT_TRUE(block::decode_workchain_coordinator_state(no_ref).is_error());
  for (bool extra_ref : {false, true}) {
    for (bool outer : {false, true}) {
      vm::CellBuilder b;
      b.append_cellslice(vm::load_cell_slice(outer ? valid : system));
      if (extra_ref) b.store_ref(system); else b.store_long(0, 1);
      auto bad = b.finalize();
      ASSERT_TRUE(block::decode_workchain_coordinator_state(outer ? bad : wrap(bad)).is_error());
    }
  }
  auto short_system = vm::CellBuilder().store_long(0xbbd85560, 32).store_long(1, 16)
      .store_long(7, 64).store_long(8, 64).finalize();
  ASSERT_TRUE(block::decode_workchain_coordinator_state(wrap(short_system)).is_error());
  auto plain = vm::CellBuilder().store_long(17, 8).finalize();
  std::vector<td::Ref<vm::Cell>> special_cells{
      vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true),
      vm::CellBuilder::do_create_pruned_branch(plain, 1, 0),
      vm::CellBuilder::create_merkle_proof(plain)};
  for (const auto& special : special_cells) {
    ASSERT_TRUE(block::decode_workchain_coordinator_state(special).is_error());
    ASSERT_TRUE(block::decode_workchain_coordinator_state(wrap(special)).is_error());
  }
}

TEST(WorkchainBlock, ResourcePolicyWire) {
  block::WorkchainResourcePolicy policy{0x80010001u,
      {UINT64_MAX, 2, 3, UINT32_MAX, 5, 6},
      {7, UINT64_MAX, 9, 10, UINT16_MAX},
      {11, 12, 13, 14, UINT64_MAX, UINT32_MAX}, {1, 32, 64}, 7};
  auto encoded = block::encode_workchain_resource_policy(policy);
  ASSERT_TRUE(encoded.is_ok());
  auto root = encoded.move_as_ok();
  ASSERT_TRUE(block::gen::t_UnoV2ResourcePolicy.validate_ref(16, root));
  auto cs = vm::load_cell_slice(root);
  ASSERT_EQ(cs.size(), 128u);
  ASSERT_EQ(cs.size_refs(), 4u);
  ASSERT_EQ(cs.fetch_ulong(32), 0xf37fed2fu);
  ASSERT_EQ(cs.fetch_ulong(32), policy.admission_version);
  ASSERT_EQ(cs.fetch_ulong(64), policy.preflight_allowance);
  const unsigned widths[] = {320, 304, 384};
  const unsigned tags[] = {0xc5defa2au, 0x90aef2ddu, 0x7a310b92u};
  // Read wire order independently of generated unpack: a self-consistent
  // encoder/decoder field swap must not survive this round-trip fixture.
  const std::vector<std::pair<unsigned, std::uint64_t>> wire_fields[] = {
      {{64, UINT64_MAX}, {64, 2}, {64, 3}, {32, UINT32_MAX}, {32, 5}, {32, 6}},
      {{64, 7}, {64, UINT64_MAX}, {64, 9}, {64, 10}, {16, UINT16_MAX}},
      {{64, 11}, {64, 12}, {64, 13}, {64, 14}, {64, UINT64_MAX}, {32, UINT32_MAX}}};
  for (unsigned i = 0; i < 3; ++i) {
    auto child = vm::load_cell_slice(cs.fetch_ref());
    ASSERT_EQ(child.size(), widths[i]);
    ASSERT_EQ(child.size_refs(), 0u);
    ASSERT_EQ(child.fetch_ulong(32), tags[i]);
    for (const auto& field : wire_fields[i]) {
      ASSERT_EQ(child.fetch_ulong(field.first), field.second);
    }
    ASSERT_TRUE(child.empty_ext());
  }
  auto preflight = vm::load_cell_slice(cs.fetch_ref());
  ASSERT_EQ(preflight.size(), 104u);
  ASSERT_EQ(preflight.fetch_ulong(8), 0xc3u);
  ASSERT_EQ(preflight.fetch_ulong(32), 1u);
  ASSERT_EQ(preflight.fetch_ulong(32), 32u);
  ASSERT_EQ(preflight.fetch_ulong(32), 64u);
  ASSERT_TRUE(preflight.empty_ext());
  auto decoded = block::decode_workchain_resource_policy(root);
  ASSERT_TRUE(decoded.is_ok());
  const auto& v = decoded.ok();
  ASSERT_EQ(v.admission_version, 0x80010001u);
  ASSERT_EQ(v.input.max_cells, UINT64_MAX);
  ASSERT_EQ(v.input.max_bits, 2u);
  ASSERT_EQ(v.input.max_roots, 3u);
  ASSERT_EQ(v.input.max_reads, UINT32_MAX);
  ASSERT_EQ(v.input.max_writes, 5u);
  ASSERT_EQ(v.input.max_inbound, 6u);
  ASSERT_EQ(v.state.max_cells, 7u);
  ASSERT_EQ(v.state.max_bits, UINT64_MAX);
  ASSERT_EQ(v.state.max_account_cells, 9u);
  ASSERT_EQ(v.state.max_account_bits, 10u);
  ASSERT_EQ(v.state.max_account_depth, UINT16_MAX);
  ASSERT_EQ(v.work_output.max_proof_units, 11u);
  ASSERT_EQ(v.work_output.max_effect_cells, 12u);
  ASSERT_EQ(v.work_output.max_effect_bits, 13u);
  ASSERT_EQ(v.work_output.max_output_cells, 14u);
  ASSERT_EQ(v.work_output.max_output_bits, UINT64_MAX);
  ASSERT_EQ(v.work_output.max_transfers, UINT32_MAX);
  ASSERT_EQ(v.block_preflight.underload, 1u);
  ASSERT_EQ(v.block_preflight.soft_limit, 32u);
  ASSERT_EQ(v.block_preflight.hard_limit, 64u);
  auto again = block::encode_workchain_resource_policy(v);
  ASSERT_TRUE(again.is_ok());
  ASSERT_EQ(again.ok()->get_hash(), root->get_hash());
}

TEST(WorkchainBlock, ResourcePolicyBlockPreflight) {
  // Three wire thresholds, with deliberately distinct values. This is not a
  // production work-unit calibration or a block-accumulation implementation.
  block::WorkchainResourcePolicy policy{4, {1,2,3,4,5,6}, {7,8,9,10,11},
      {12,13,14,15,16,17}, {3,7,11}, 7};
  static_assert(!std::is_default_constructible_v<block::WorkchainResourcePolicy>);
  static_assert(!std::is_constructible_v<block::WorkchainResourcePolicy,
      std::uint32_t, block::gen::UnoV2ResourceInput::Record,
      block::gen::UnoV2ResourceState::Record, block::gen::UnoV2ResourceWorkOutput::Record>);
  auto encoded = block::encode_workchain_resource_policy(policy);
  ASSERT_TRUE(encoded.is_ok());
  auto decoded = block::decode_workchain_resource_policy(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().block_preflight.underload, 3u);
  ASSERT_EQ(decoded.ok().block_preflight.soft_limit, 7u);
  ASSERT_EQ(decoded.ok().block_preflight.hard_limit, 11u);
  ASSERT_EQ(decoded.ok().work_output.max_proof_units, 12u);
  auto cs = vm::load_cell_slice(encoded.ok());
  auto in = cs.fetch_ref(), state = cs.fetch_ref(), work = cs.fetch_ref(), limits = cs.fetch_ref();
  auto reframe = [&](unsigned tag, td::Ref<vm::Cell> bound) {
    vm::CellBuilder b;
    b.store_long(tag, 32).store_long(4, 32).store_long(7, 64).store_ref(in).store_ref(state).store_ref(work);
    if (bound.not_null()) b.store_ref(bound);
    return b.finalize();
  };
  // Historical three-reference encoding AND an otherwise current, four-ref
  // cell with only its tag changed must fail at the constructor check itself.
  for (auto bound : {td::Ref<vm::Cell>{}, limits}) {
    auto old = block::decode_workchain_resource_policy(reframe(0xbbd8a9ec, bound));
    ASSERT_TRUE(old.is_error());
    ASSERT_EQ(old.error().message(), "unrecognized resource policy constructor tag");
  }
  auto missing = block::decode_workchain_resource_policy(
      reframe(block::gen::UnoV2ResourcePolicy::cons_tag[0], {}));
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "malformed resource policy encoding");
  // Raw construction bypasses the generated packer's own ordering checks, so
  // the following assertions exercise decoding, not a fixture creation error.
  for (auto fields : {std::array<unsigned, 3>{8,7,11}, std::array<unsigned, 3>{3,12,11}}) {
    auto invalid = vm::CellBuilder().store_long(0xc3, 8)
        .store_long(fields[0], 32).store_long(fields[1], 32).store_long(fields[2], 32).finalize();
    ASSERT_TRUE(block::decode_workchain_resource_policy(
        reframe(block::gen::UnoV2ResourcePolicy::cons_tag[0], invalid)).is_error());
    policy.block_preflight = {fields[0], fields[1], fields[2]};
    ASSERT_TRUE(block::encode_workchain_resource_policy(policy).is_error());
  }
  policy.block_preflight = {0, 0x10000, UINT32_MAX};
  auto wide = block::encode_workchain_resource_policy(policy);
  ASSERT_TRUE(wide.is_ok());
  auto wide_decoded = block::decode_workchain_resource_policy(wide.ok());
  ASSERT_TRUE(wide_decoded.is_ok());
  ASSERT_EQ(wide_decoded.ok().block_preflight.soft_limit, 0x10000u);
  ASSERT_EQ(wide_decoded.ok().block_preflight.hard_limit, UINT32_MAX);
  policy.block_preflight = {UINT32_MAX, UINT32_MAX, UINT32_MAX};
  ASSERT_TRUE(block::encode_workchain_resource_policy(policy).is_ok());
}

TEST(WorkchainBlock, PreflightAllowanceWire) {
  // Deliberately unequal budgets prove this field is not the proof-work result.
  block::WorkchainResourcePolicy p{4, {1,2,3,4,5,6}, {7,8,9,10,11},
      {12,13,14,15,16,17}, {0,2,2}, UINT64_MAX};
  static_assert(!std::is_constructible_v<block::WorkchainResourcePolicy,
      std::uint32_t, block::gen::UnoV2ResourceInput::Record,
      block::gen::UnoV2ResourceState::Record, block::gen::UnoV2ResourceWorkOutput::Record,
      block::gen::ParamLimits::Record>);
  auto encoded = block::encode_workchain_resource_policy(p);
  ASSERT_TRUE(encoded.is_ok());
  auto root = vm::load_cell_slice(encoded.ok());
  ASSERT_EQ(root.size(), 128u);
  ASSERT_EQ(root.fetch_ulong(32), block::gen::UnoV2ResourcePolicy::cons_tag[0]);
  ASSERT_EQ(root.fetch_ulong(32), 4u);
  ASSERT_EQ(root.fetch_ulong(64), UINT64_MAX);
  auto decoded = block::decode_workchain_resource_policy(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().preflight_allowance, UINT64_MAX);
  ASSERT_EQ(decoded.ok().work_output.max_proof_units, 12u);
  // No runtime host rule is inferred from a codec: zero is carried, not replaced
  // by the unrelated proof-result limit. The C3 runner rejects zero allowances.
  p.preflight_allowance = 0;
  auto zero = block::encode_workchain_resource_policy(p);
  ASSERT_TRUE(zero.is_ok());
  auto zero_decoded = block::decode_workchain_resource_policy(zero.ok());
  ASSERT_TRUE(zero_decoded.is_ok());
  ASSERT_EQ(zero_decoded.ok().preflight_allowance, 0u);
  auto old_fields = [&](unsigned tag, unsigned allowance_bits) {
    vm::CellBuilder b;
    b.store_long(tag,32).store_long(4,32);
    if (allowance_bits) b.store_zeroes(allowance_bits);
    auto refs = vm::load_cell_slice(encoded.ok());
    for (unsigned i=0;i<4;++i) b.store_ref(refs.fetch_ref());
    return b.finalize();
  };
  // First isolate the tag cause using both historical tags and complete refs.
  for (unsigned tag : {0xbbd8a9ecu, 0xfb8a7703u}) {
    auto result = block::decode_workchain_resource_policy(old_fields(tag,0));
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "unrecognized resource policy constructor tag");
  }
  // Then retain the current tag and all four valid references: only the
  // allowance is absent/truncated. This must not be mistaken for an old tag.
  for (unsigned bits : {0u,63u}) {
    auto result = block::decode_workchain_resource_policy(
        old_fields(block::gen::UnoV2ResourcePolicy::cons_tag[0],bits));
    ASSERT_TRUE(result.is_error());
    ASSERT_EQ(result.error().message(), "missing or truncated preflight allowance");
  }
}

TEST(WorkchainBlock, EngineConfigurationFraming) {
  // Explicit codec/resolver fixture instance. This representable wire value
  // does not authenticate an installation or claim a production-issued identity.
  const auto fixture_instance = td::Bits256::ones();
  block::WorkchainResourcePolicy value{2, {1,2,3,4,5,6}, {7,8,9,10,11}, {12,13,14,15,16,17}, {1, 32, 64}, 7};
  // Test-only tagged business payload: the host must preserve, not interpret it.
  auto payload = vm::CellBuilder().store_long(0x12345678, 32).finalize();
  for (std::uint32_t version : {2u, 3u, 0x10002u, 0x10003u, 0x80000002u}) {
    value.admission_version = version;
    auto encoded = block::encode_workchain_engine_parameters({400, fixture_instance, value, payload, 10000000000ULL});
    ASSERT_TRUE(encoded.is_ok());
    auto root = encoded.move_as_ok();
    auto cs = vm::load_cell_slice(root);
    ASSERT_EQ(cs.size(), 384u);
    ASSERT_EQ(cs.size_refs(), 2u);
    ASSERT_EQ(cs.fetch_ulong(32), block::gen::UnoV2EngineConfiguration::cons_tag[0]);
    ASSERT_EQ(cs.fetch_ulong(32), 400u);
    auto decoded = block::decode_workchain_engine_parameters(root);
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.ok().instance_id, fixture_instance);
    ASSERT_EQ(decoded.ok().resources.admission_version, version);
    ASSERT_EQ(decoded.ok().parameters->get_hash(), payload->get_hash());
    auto resources = cs.fetch_ref();
    for (unsigned defect = 0; defect < 5; ++defect) {
      vm::CellBuilder b;
      b.store_long(defect == 0 ? 0 : block::gen::UnoV2EngineConfiguration::cons_tag[0], 32).store_long(400, 32).store_long(10000000000LL, 64).store_bits(fixture_instance.bits(), 256);
      if (defect != 1) b.store_ref(resources);
      if (defect != 2) b.store_ref(payload);
      if (defect == 3) b.store_long(0, 1);
      if (defect == 4) b.store_ref(payload);
      ASSERT_TRUE(block::decode_workchain_engine_parameters(b.finalize()).is_error());
    }
  }
  ASSERT_TRUE(block::decode_workchain_engine_parameters({}).is_error());
  ASSERT_TRUE(block::encode_workchain_engine_parameters({400, fixture_instance, value, {}, 10000000000ULL}).is_error());
}

// These are fixture acceptance records, not production defaults or a claim
// that a deployment has passed K acceptance at these intervals.
TEST(WorkchainBlock, EngineConfigurationAcceptedCadence) {
  // Explicit codec/resolver fixture instance. This representable wire value
  // does not authenticate an installation or claim a production-issued identity.
  const auto fixture_instance = td::Bits256::ones();
  static_assert(!std::is_default_constructible_v<block::WorkchainEngineParameters>);
  static_assert(!std::is_aggregate_v<block::WorkchainEngineParameters>);
  static_assert(!std::is_constructible_v<block::WorkchainEngineParameters,
      block::WorkchainResourcePolicy, td::Ref<vm::Cell>>);
  block::WorkchainResourcePolicy resources{2, {1,2,3,4,5,6}, {7,8,9,10,11}, {12,13,14,15,16,17}, {1, 32, 64}, 7};
  auto payload = vm::CellBuilder().store_long(0x12345678, 32).finalize();
  for (std::uint32_t accepted : {0u, 1u, 400u, 401u, UINT32_MAX}) {
    // Recording and installation validation are separate; even zero is a
    // representable explicit value, never an omitted-field default.
    auto encoded = block::encode_workchain_engine_parameters({accepted, fixture_instance, resources, payload, 10000000000ULL});
    ASSERT_EQ(encoded.is_ok() ? 0 : 401, 0);
    auto cs = vm::load_cell_slice(encoded.ok());
    ASSERT_EQ(cs.size() == 384 && cs.size_refs() == 2 ? 0 : 402, 0);
    ASSERT_EQ(cs.fetch_ulong(32) == block::gen::UnoV2EngineConfiguration::cons_tag[0] && cs.fetch_ulong(32) == accepted ? 0 : 403, 0);
    auto decoded = block::decode_workchain_engine_parameters(encoded.ok());
    ASSERT_EQ(decoded.is_ok() ? 0 : 404, 0);
    ASSERT_EQ(decoded.ok().k_accepted_target_rate_ms == accepted ? 0 : 405, 0);
  }
  auto resource = block::encode_workchain_resource_policy(resources).move_as_ok();
  auto missing = vm::CellBuilder().store_long(block::gen::UnoV2EngineConfiguration::cons_tag[0], 32).store_long(10000000000LL, 64).store_bits(fixture_instance.bits(), 256).store_ref(resource).store_ref(payload).finalize();
  ASSERT_EQ(block::decode_workchain_engine_parameters(missing).is_error() ? 0 : 406, 0);
  auto retired_cadence = vm::CellBuilder().store_long(0x6e1fa05f, 32).store_long(400, 32)
      .store_ref(resource).store_ref(payload).finalize();
  ASSERT_EQ(block::decode_workchain_engine_parameters(retired_cadence).is_error() ? 0 : 408, 0);
  static_assert(!std::is_constructible_v<block::WorkchainEngineParameters,
      std::uint32_t, block::WorkchainResourcePolicy, td::Ref<vm::Cell>>);
  for (bool with_cadence : {false, true}) {
    vm::CellBuilder legacy;
    legacy.store_long(0xb7226bea, 32);
    if (with_cadence) legacy.store_long(400, 32);
    auto root = legacy.store_ref(resource).store_ref(payload).finalize();
    ASSERT_EQ(block::decode_workchain_engine_parameters(root).is_error() ? 0 : 407, 0);
  }
}

TEST(WorkchainBlock, PreflightAllowanceConsistency) {
  block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {0,2,2}, 1};
  auto root = vm::CellBuilder().finalize();
  block::InputPolicyIdentity identity{root->get_hash(), false, 0x434e5431, 0, 0, 4};
  auto classify = [&](std::uint64_t allowance) {
    resources.preflight_allowance = allowance;
    auto wire = block::encode_workchain_resource_policy(resources);
    ASSERT_TRUE(wire.is_ok());
    auto decoded = block::decode_workchain_resource_policy(wire.ok());
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.ok().preflight_allowance, allowance);
    return block::ResolvedBatchInputPolicy::from_resolved_fields(decoded.move_as_ok(), identity);
  };
  ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(classify(1)));
  auto zero = classify(0);
  ASSERT_TRUE(std::holds_alternative<block::ConfigInvalid>(zero));
  ASSERT_EQ(std::get<block::ConfigInvalid>(zero).code, block::ConfigInvalidCode::ZeroLimit);
  for (std::uint64_t allowance : {std::uint64_t{3}, std::uint64_t{1} << 32, UINT64_MAX}) {
    auto excessive = classify(allowance);
    ASSERT_TRUE(std::holds_alternative<block::ConfigInvalid>(excessive));
    ASSERT_EQ(std::get<block::ConfigInvalid>(excessive).code,
              block::ConfigInvalidCode::PreflightAllowanceExceedsBlockBudget);
  }
  auto equal = classify(2);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(equal));
  ASSERT_EQ(std::get<block::ResolvedBatchInputPolicy>(equal).resources().preflight_allowance, 2u);
  // Configuration equality only. The closed production call path still lacks
  // evidence for a second call being refused after this full reservation.
}

TEST(WorkchainBlock, BatchPolicyVersionIdentityAgreement) {
  block::WorkchainResourcePolicy resources{2, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
  auto root = vm::CellBuilder().finalize();
  block::InputPolicyIdentity identity{root->get_hash(), false, 0x434e5431, 7, 5, 2};
  for (const auto& versions : {std::pair{2u, 2u}, std::pair{3u, 3u}, std::pair{4u, 4u},
                               std::pair{2u, 3u}, std::pair{3u, 2u},
                               std::pair{2u, 1u}, std::pair{1u, 2u},
                               std::pair{2u, 0x10002u}, std::pair{0x10002u, 2u},
                               std::pair{3u, 0x10003u}, std::pair{0x10003u, 3u}}) {
    resources.admission_version = versions.first;
    identity.admission_version = versions.second;
    auto result = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, identity);
    if (versions.first == versions.second) {
      ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(result));
      ASSERT_EQ(std::get<block::ResolvedBatchInputPolicy>(result).permits_fee_settlement(),
                versions.first == 3 || versions.first == 4);
      ASSERT_EQ(std::get<block::ResolvedBatchInputPolicy>(result).requires_proof_operation_meter(), versions.first == 4);
    } else {
      ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
      ASSERT_EQ(std::get<block::LocalUnavailable>(result).code,
                ((versions.first == 2 && versions.second == 3) || (versions.first == 3 && versions.second == 2))
                    ? block::LocalUnavailableCode::ExecutionFault
                    : block::LocalUnavailableCode::UnsupportedAdmissionVersion);
    }
  }
}

TEST(WorkchainBlock, BatchProfileUnsupportedNodeProbe) {
  // Also run with the support predicate restored to the version-2-only
  // implementation. This observes old-node execution binding, not installation.
  for (auto version : {3u, 4u}) {
  block::WorkchainResourcePolicy resources{version, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
  block::InputPolicyIdentity identity{vm::CellBuilder().finalize()->get_hash(), false, 0x434e5431, 7, 5, version};
  auto result = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, identity);
  if (block::workchain_batch_admission_version_supported(version)) {
    ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(result));
  } else {
    ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
    ASSERT_EQ(std::get<block::LocalUnavailable>(result).code,
              block::LocalUnavailableCode::UnsupportedAdmissionVersion);
  }
  }
}

void check_claimed_fee_framing(unsigned defect) {
  block::WorkchainResourcePolicy resources{3, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
  auto empty = vm::CellBuilder().finalize();
  block::InputPolicyIdentity identity{empty->get_hash(), false, 0x434e5431, 7, 5, 3};
  auto resolved = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, identity);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved));
  const auto& policy = std::get<block::ResolvedBatchInputPolicy>(resolved);
  auto frame = [](td::Ref<vm::Cell> native) {
    return vm::CellBuilder().store_long(0x4155a803, 32).store_long(0, 1)
        .store_ref(native).store_long(0, 2).store_zeroes(192).finalize();
  };
  // This helper authorizes framing only, not the complete native payload.
  ASSERT_TRUE(block::account_replay_detail::validate_claimed_fee_profile(
      frame(vm::CellBuilder().store_long(0x67e2d380, 32).finalize()), policy).is_ok());
  ASSERT_TRUE(block::account_replay_detail::validate_claimed_fee_profile(
      frame(vm::CellBuilder().store_long(0x0bd47725, 32).finalize()), policy).is_ok());
  auto claimed = empty;
  if (defect == 1) claimed = frame(empty);
  if (defect == 2) claimed = frame(vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true));
  if (defect == 3) claimed = frame(vm::CellBuilder().store_long(0xdeadbeef, 32).finalize());
  auto result = block::account_replay_detail::validate_claimed_fee_profile(claimed, policy);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
}

TEST(WorkchainBlock, ClaimedFeeOuterFraming) { check_claimed_fee_framing(0); }
TEST(WorkchainBlock, ClaimedFeeShortNativeFraming) { check_claimed_fee_framing(1); }
TEST(WorkchainBlock, ClaimedFeeSpecialNativeFraming) { check_claimed_fee_framing(2); }
TEST(WorkchainBlock, ClaimedFeeUnknownNativeFraming) { check_claimed_fee_framing(3); }

// A permissive test decoder isolates the ordinary-cell contract from today's
// generated tags. It is not an additional resource-policy wire constructor.
struct ResourcePolicyDecoderProbe {
  bool entered{false};
  struct type_class {
    bool unpack(vm::CellSlice& cs, ResourcePolicyDecoderProbe& record) const {
      record.entered = true;
      return cs.advance(264);
    }
  };
};

TEST(WorkchainBlock, ResourcePolicyRejectsSpecialBeforeDecoder) {
  auto ordinary = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize();
  auto special = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  ResourcePolicyDecoderProbe accepted;
  ASSERT_TRUE(block::resource_policy_detail::unpack_exact(ordinary, accepted));
  ASSERT_TRUE(accepted.entered);
  ResourcePolicyDecoderProbe rejected;
  ASSERT_TRUE(!block::resource_policy_detail::unpack_exact(special, rejected));
  ASSERT_TRUE(!rejected.entered);
}

TEST(WorkchainBlock, ResourcePolicyEncodedSpecialCells) {
  // Explicit codec/resolver fixture instance. This representable wire value
  // does not authenticate an installation or claim a production-issued identity.
  const auto fixture_instance = td::Bits256::ones();
  block::WorkchainResourcePolicy value{2, {1,2,3,4,5,6}, {7,8,9,10,11}, {12,13,14,15,16,17}, {1, 32, 64}, 7};
  auto resource = block::encode_workchain_resource_policy(value).move_as_ok();
  auto cs = vm::load_cell_slice(resource);
  auto input = cs.fetch_ref();
  auto state = cs.fetch_ref();
  auto work = cs.fetch_ref();
  auto preflight = cs.fetch_ref();
  auto plain = vm::CellBuilder().store_long(17, 8).finalize();
  std::vector<td::Ref<vm::Cell>> special_cells{
      vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true),
      vm::CellBuilder::do_create_pruned_branch(plain, 1, 0),
      vm::CellBuilder::create_merkle_proof(plain)};
  for (const auto& special : special_cells) {
    for (unsigned position = 0; position < 6; ++position) {
      auto altered_resource = position == 1 ? special
          : vm::CellBuilder().store_long(0xf37fed2f, 32).store_long(2, 32).store_long(7, 64)
                .store_ref(position == 2 ? special : input)
                .store_ref(position == 3 ? special : state)
                .store_ref(position == 4 ? special : work)
                .store_ref(position == 5 ? special : preflight).finalize();
      auto framing = position == 0 ? special
          : vm::CellBuilder().store_long(block::gen::UnoV2EngineConfiguration::cons_tag[0], 32).store_long(400, 32).store_long(10000000000LL, 64).store_bits(fixture_instance.bits(), 256)
                .store_ref(altered_resource).store_ref(plain).finalize();
      ASSERT_TRUE(block::decode_workchain_engine_parameters(framing).is_error());
      if (position != 0) ASSERT_TRUE(block::decode_workchain_resource_policy(altered_resource).is_error());
    }
    // Business contents are not the host's wire profile to interpret.
    auto opaque = block::encode_workchain_engine_parameters({400, fixture_instance, value, special, 10000000000ULL}).move_as_ok();
    ASSERT_TRUE(block::decode_workchain_engine_parameters(opaque).is_ok());
  }
}

TEST(WorkchainBlock, ResourcePolicyMalformedClosure) {
  block::WorkchainResourcePolicy value{1, {1,2,3,4,5,6}, {7,8,9,10,11}, {12,13,14,15,16,17}, {1, 32, 64}, 7};
  auto packed = block::encode_workchain_resource_policy(value);
  ASSERT_TRUE(packed.is_ok());
  auto root = packed.move_as_ok();
  auto top = vm::load_cell_slice(root);
  td::Ref<vm::Cell> cells[] = {root, top.fetch_ref(), top.fetch_ref(), top.fetch_ref(), top.fetch_ref()};
  auto empty = vm::CellBuilder().finalize();
  for (unsigned location = 0; location < 5; ++location) {
    for (unsigned defect = 0; defect < 3; ++defect) {
      // A root with four references cannot acquire a fifth in a valid Cell.
      // Test the extra-reference defect on every child; missing root refs are
      // exercised below. Do not count an unconstructible fifth ref as rejection.
      if (location == 0 && defect == 1) continue;
      vm::CellBuilder b;
      auto cs = vm::load_cell_slice(cells[location]);
      if (defect == 2) { cs.fetch_ulong(32); b.store_long(0, 32); }
      b.append_cellslice(cs);
      if (defect == 0) b.store_long(1, 1);
      if (defect == 1) b.store_ref(empty);
      auto malformed = b.finalize();
      if (location != 0) {
        malformed = vm::CellBuilder().store_long(0xf37fed2f, 32).store_long(1, 32).store_long(7, 64)
            .store_ref(location == 1 ? malformed : cells[1])
            .store_ref(location == 2 ? malformed : cells[2])
            .store_ref(location == 3 ? malformed : cells[3])
            .store_ref(location == 4 ? malformed : cells[4]).finalize();
      }
      ASSERT_TRUE(block::decode_workchain_resource_policy(malformed).is_error());
    }
  }
  ASSERT_TRUE(block::decode_workchain_resource_policy({}).is_error());
  auto missing = vm::CellBuilder().store_long(0xf37fed2f, 32).store_long(1, 32).store_long(7, 64)
      .store_ref(cells[1]).store_ref(cells[2]).finalize();
  ASSERT_TRUE(block::decode_workchain_resource_policy(missing).is_error());
  value.state.max_account_depth = 65536;
  ASSERT_TRUE(block::encode_workchain_resource_policy(value).is_error());
}

TEST(WorkchainBlock, BounceValueIsolation) {
  using C = block::CurrencyCollection;
  auto key = td::Bits256::zero();
  vm::Dictionary extra(32);
  vm::CellBuilder amount;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(amount, *td::make_refint(5)));
  ASSERT_TRUE(extra.set_builder(td::BitArray<32>::zero(), amount, vm::Dictionary::SetMode::Add));
  C imported(td::make_refint(123), extra.get_root_cell());
  auto result = block::account_workchain_bounce(key, C(1000), imported,
      td::make_refint(100), td::make_refint(25), 100);
  ASSERT_TRUE(result.is_ok());
  auto plan = result.move_as_ok();
  ASSERT_TRUE(plan.returned == C(td::make_refint(23), extra.get_root_cell()));
  ASSERT_TRUE(plan.row.exported == C(td::make_refint(98), extra.get_root_cell()));
  ASSERT_TRUE(plan.row.old_balance == C(1000) && plan.row.new_balance == C(1000));
  ASSERT_TRUE(plan.row.imported == imported && plan.row.fees == C(25));
  ASSERT_TRUE(block::verify_workchain_value_flow({plan.row}, {}, 1, 0, 100).is_ok());
  auto exact = block::account_workchain_bounce(key, C(0), imported,
      td::make_refint(123), td::make_refint(123), 100).move_as_ok();
  ASSERT_TRUE(exact.returned == C(td::make_refint(0), extra.get_root_cell()));
  ASSERT_TRUE(exact.row.exported == exact.returned && exact.row.new_balance.is_zero());
  auto free = block::account_workchain_bounce(key, C(0), imported,
      td::make_refint(0), td::make_refint(0), 100).move_as_ok();
  ASSERT_TRUE(free.returned == imported && free.row.exported == imported && free.row.fees.is_zero());
  // Even abundant old principal cannot subsidize this message's return.
  ASSERT_TRUE(block::account_workchain_bounce(key, C(1000000), imported,
      td::make_refint(124), td::make_refint(25), 100).is_error());
  ASSERT_TRUE(block::account_workchain_bounce(key, C(0), imported,
      td::make_refint(100), td::make_refint(101), 100).is_error());
  ASSERT_TRUE(block::account_workchain_bounce(key, C(0), imported,
      td::make_refint(-1), td::make_refint(0), 100).is_error());
}

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
    if (unavailable_ || *loads_ == unavailable_at_) return td::Status::Error("test input unavailable");
    return cell_->load_cell();
  }
  bool is_virtualized() const override { return cell_->is_virtualized(); }
  vm::CellUsageTree::NodePtr get_tree_node() const override { return {}; }
  bool is_loaded() const override { return !unavailable_; }
  void set_unavailable(bool value) const { unavailable_ = value; }
  void set_unavailable_at(unsigned value) const { unavailable_at_ = value; }
  LevelMask get_level_mask() const override { return cell_->get_level_mask(); }

 private:
  const Hash do_get_hash(td::uint32 level) const override { return cell_->get_hash(level); }
  td::uint16 do_get_depth(td::uint32 level) const override { return cell_->get_depth(level); }
  td::Ref<vm::Cell> cell_;
  unsigned* loads_;
  mutable bool unavailable_;
  unsigned throw_at_;
  mutable unsigned unavailable_at_ = 0;
};

TEST(WorkchainBlock, ResourcePolicyLocalLoadFailure) {
  block::WorkchainResourcePolicy value{1, {1,2,3,4,5,6}, {7,8,9,10,11}, {12,13,14,15,16,17}, {1, 32, 64}, 7};
  auto root = block::encode_workchain_resource_policy(value).move_as_ok();
  unsigned loads = 0;
  td::Ref<PreflightObservedCell> missing{true, root, &loads, true};
  bool threw = false;
  try {
    (void)block::decode_workchain_resource_policy(missing);
  } catch (const vm::VmError&) {
    threw = true;
  }
  ASSERT_TRUE(threw);
  ASSERT_EQ(loads, 1u);
  loads = 0;
  td::Ref<PreflightObservedCell> virtual_failure{true, root, &loads, false, 1};
  threw = false;
  try {
    (void)block::decode_workchain_resource_policy(virtual_failure);
  } catch (const vm::VmVirtError&) {
    threw = true;
  }
  ASSERT_TRUE(threw);
  ASSERT_EQ(loads, 1u);
}

TEST(WorkchainBlock, CoordinatorStateLocalLoadFailure) {
  auto encoded = block::encode_workchain_coordinator_state({2, {1, 0, 0, 0}, 0});
  ASSERT_TRUE(encoded.is_ok());
  auto root = encoded.move_as_ok();
  unsigned loads = 0;
  td::Ref<PreflightObservedCell> available{true, root, &loads, false};
  ASSERT_TRUE(block::decode_workchain_coordinator_state(available).is_ok());
  ASSERT_EQ(loads, 1u);
  loads = 0;
  td::Ref<PreflightObservedCell> missing{true, root, &loads, true};
  bool unavailable = false;
  try {
    (void)block::decode_workchain_coordinator_state(missing);
  } catch (const vm::VmError&) {
    unavailable = true;
  }
  ASSERT_TRUE(unavailable);
  ASSERT_EQ(loads, 1u);
  loads = 0;
  td::Ref<PreflightObservedCell> hidden{true, root, &loads, false, 1};
  bool virtual_failure = false;
  try {
    (void)block::decode_workchain_coordinator_state(hidden);
  } catch (const vm::VmVirtError&) {
    virtual_failure = true;
  }
  ASSERT_TRUE(virtual_failure);
  ASSERT_EQ(loads, 1u);
  auto system = vm::load_cell_slice(root).prefetch_ref();
  for (unsigned fault = 0; fault != 3; ++fault) {
    loads = 0;
    td::Ref<PreflightObservedCell> child{true, system, &loads, fault == 1, fault == 2 ? 1u : 0u};
    auto wrapper = vm::CellBuilder().store_long(block::gen::UnoV2CoordinatorDeposits::cons_tag[0], 32).store_long(2, 16).store_ref(child).store_ref(coordinator_budget_fixture()).finalize();
    bool failed = false;
    try {
      ASSERT_TRUE(block::decode_workchain_coordinator_state(wrapper).is_ok());
    } catch (const vm::VmError&) {
      ASSERT_EQ(fault, 1u);
      failed = true;
    } catch (const vm::VmVirtError&) {
      ASSERT_EQ(fault, 2u);
      failed = true;
    }
    ASSERT_EQ(failed, fault != 0);
    ASSERT_EQ(loads, 1u);
  }
}

td::Ref<vm::Cell> number(std::uint64_t value) {
  return vm::CellBuilder().store_long(value, 64).finalize();
}

class StateReadCallbackCell final : public vm::Cell {
 public:
  StateReadCallbackCell(td::Ref<vm::Cell> source, std::function<void()> callback,
                        std::function<void()> hash_callback = {}, std::function<void()> node_callback = {})
      : source_(std::move(source)), callback_(std::move(callback)), hash_callback_(std::move(hash_callback)),
        node_callback_(std::move(node_callback)) {}
  td::Status set_data_cell(td::Ref<vm::DataCell>&& cell) const override {
    return source_->set_data_cell(std::move(cell));
  }
  td::Result<LoadedCell> load_cell() const override {
    callback_();
    return source_->load_cell();
  }
  bool is_virtualized() const override { return source_->is_virtualized(); }
  bool is_loaded() const override { return source_->is_loaded(); }
  vm::CellUsageTree::NodePtr get_tree_node() const override {
    if (node_callback_) node_callback_();
    return source_->get_tree_node();
  }
  LevelMask get_level_mask() const override { return source_->get_level_mask(); }
 private:
  const Hash do_get_hash(td::uint32 level) const override {
    if (hash_callback_) hash_callback_();
    return source_->get_hash(level);
  }
  td::uint16 do_get_depth(td::uint32 level) const override { return source_->get_depth(level); }
  td::Ref<vm::Cell> source_;
  std::function<void()> callback_;
  std::function<void()> hash_callback_;
  std::function<void()> node_callback_;
};

TEST(WorkchainBlock, ScopedStateReadObserver) {
  auto child = number(700);
  auto root = vm::CellBuilder().store_ref(child).finalize();
  auto run = [&](bool observe) {
    unsigned source_loads = 0, first_loads = 0, observations = 0;
    td::Ref<vm::Cell> counted{td::Ref<PreflightObservedCell>{true, root, &source_loads}};
    auto tree = std::make_shared<vm::CellUsageTree>();
    auto tracked = vm::UsageCell::create(counted, tree->root_ptr());
    tree->set_cell_load_callback([&](const vm::LoadedCell&) { ++first_loads; });
    (void)vm::load_cell_slice(tracked);  // Loaded before observer installation.
    ASSERT_EQ(source_loads, 1u);
    {
      std::optional<vm::CellUsageTree::ScopedReadObserver> scope;
      if (observe) scope.emplace(tree->root_ptr(), [&](const vm::Cell&) { ++observations; });
      auto slice = vm::load_cell_slice(tracked);
      (void)vm::load_cell_slice(slice.prefetch_ref());
      tree->set_ignore_loads(true);
      (void)vm::load_cell_slice(tracked);
      tree->set_ignore_loads(false);
    }
    ASSERT_EQ(observations, observe ? 3u : 0u);
    ASSERT_EQ(first_loads, 2u);
    (void)vm::load_cell_slice(tracked);
    ASSERT_EQ(observations, observe ? 3u : 0u);  // Observer removed at scope exit.
    ASSERT_EQ(source_loads, 4u);
    if (observe) {
      bool refused = false;
      try {
        vm::CellUsageTree::ScopedReadObserver deny(tree->root_ptr(), [](const vm::Cell&) { throw 17; });
        (void)vm::load_cell_slice(tracked);
      } catch (int code) {
        ASSERT_EQ(code, 17);
        refused = true;
      }
      ASSERT_TRUE(refused);
      ASSERT_EQ(source_loads, 4u);  // Refusal precedes the source's load.
      (void)vm::load_cell_slice(tracked);
      ASSERT_EQ(source_loads, 5u);  // Exception unwinding removed the observer.
    }
    return vm::std_boc_serialize(vm::MerkleProof::generate(counted, tree.get()).move_as_ok()).move_as_ok();
  };
  ASSERT_EQ(run(false).as_slice(), run(true).as_slice());
}

TEST(WorkchainBlock, StateReadRefusalLeavesProofUnchanged) {
  // Native preserves loaded leaves instead of replacing them with pruned
  // branches. Use a non-leaf so an unmarked child really hides a subtree.
  auto child = vm::CellBuilder().store_long(701, 64).store_ref(number(702)).finalize();
  auto root = vm::CellBuilder().store_ref(child).finalize();
  vm::MerkleProofBuilder proof(root);
  auto child_view = vm::load_cell_slice(proof.root()).prefetch_ref();
  auto before = proof.extract_proof_boc().move_as_ok();
  bool refused = false;
  try {
    vm::CellUsageTree::ScopedReadObserver deny(proof.root()->get_tree_node(), [](const vm::Cell&) { throw 19; });
    (void)vm::load_cell_slice(child_view);
  } catch (int code) {
    ASSERT_EQ(code, 19);
    refused = true;
  }
  ASSERT_TRUE(refused);
  ASSERT_EQ(before.as_slice(), proof.extract_proof_boc().move_as_ok().as_slice());
  auto view = vm::MerkleProof::virtualize(proof.extract_proof().move_as_ok()).move_as_ok();
  bool pruned = false;
  try {
    (void)vm::load_cell_slice(vm::load_cell_slice(view).prefetch_ref());
  } catch (const vm::VmVirtError&) {
    pruned = true;
  }
  ASSERT_TRUE(pruned);
}

TEST(WorkchainBlock, StateReadMeterProofTracking) {
  auto leaf = number(9);
  auto left = vm::CellBuilder().store_long(1, 8).store_ref(leaf).finalize();
  auto right = vm::CellBuilder().store_long(2, 8).store_ref(leaf).finalize();
  auto root = vm::CellBuilder().store_ref(left).store_ref(right).store_ref(number(99)).finalize();
  auto read_proof = [&](bool metered) {
    vm::MerkleProofBuilder proof(root);
    block::NativeStateReadMeter meter(4, 80);
    unsigned callbacks = 0;
    proof.set_cell_load_callback([&](const vm::LoadedCell&) { ++callbacks; });
    auto load = [&](const td::Ref<vm::Cell>& cell) -> td::Ref<vm::CellSlice> {
      if (!metered) return vm::load_cell_slice_ref(cell);
      auto result = meter.load_ordinary(cell);
      ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(result));
      return std::get<td::Ref<vm::CellSlice>>(std::move(result));
    };
    auto top = load(proof.root());
    for (unsigned i : {0u, 1u, 0u}) {
      auto branch = load(top->prefetch_ref(i));
      ASSERT_EQ(branch->prefetch_ulong(8), i + 1);
      ASSERT_EQ(load(branch->prefetch_ref())->prefetch_ulong(64), 9u);
    }
    if (metered) {
      ASSERT_EQ(meter.usage().cells, 4u);
      ASSERT_EQ(meter.usage().bits, 80u);
    }
    auto encoded = proof.extract_proof_boc();
    ASSERT_TRUE(encoded.is_ok());
    return std::make_pair(encoded.move_as_ok(), callbacks);
  };
  auto unmetered = read_proof(false);
  auto metered = read_proof(true);
  ASSERT_EQ(unmetered.first.as_slice(), metered.first.as_slice());
  // Root, two branches, two paths to the same leaf. Check proof bytes first:
  // dropping usage provenance must be caught as a changed consensus artifact.
  ASSERT_EQ(unmetered.second, 5u);
  ASSERT_EQ(metered.second, 5u);

  vm::MerkleProofBuilder accounting_proof(root);
  std::vector<vm::CellHash> visit_order;
  accounting_proof.set_cell_load_callback([&](const vm::LoadedCell& cell) {
    visit_order.push_back(cell.data_cell->get_hash());
  });
  block::NativeStateReadMeter accounting_meter(5, 144);
  auto accounting = block::read_workchain_account_closure(accounting_proof.root(), accounting_meter, 5, 144, 2);
  ASSERT_TRUE(std::holds_alternative<block::WorkchainInputUsage>(accounting));
  const std::vector<vm::CellHash> expected_order{
      root->get_hash(), left->get_hash(), leaf->get_hash(), right->get_hash(), number(99)->get_hash()};
  ASSERT_EQ(visit_order.size(), expected_order.size());
  for (std::size_t i = 0; i < expected_order.size(); ++i) ASSERT_EQ(visit_order[i], expected_order[i]);

  unsigned loads = 0;
  td::Ref<PreflightObservedCell> observed{true, leaf, &loads};
  block::NativeStateReadMeter no_cells(0, 64);
  auto cell_denied = no_cells.load_ordinary(observed);
  ASSERT_TRUE(std::holds_alternative<block::NativeClosureLimit>(cell_denied));
  ASSERT_EQ(std::get<block::NativeClosureLimit>(cell_denied), block::NativeClosureLimit::Cells);
  ASSERT_EQ(loads, 0u);
  ASSERT_EQ(std::get<block::NativeClosureLimit>(no_cells.load_ordinary(root)), block::NativeClosureLimit::Cells);
  block::NativeStateReadMeter no_bits(1, 63);
  auto bit_denied = no_bits.load_ordinary(observed);
  ASSERT_TRUE(std::holds_alternative<block::NativeClosureLimit>(bit_denied));
  ASSERT_EQ(std::get<block::NativeClosureLimit>(bit_denied), block::NativeClosureLimit::Bits);
  ASSERT_EQ(loads, 1u);
  ASSERT_EQ(std::get<block::NativeClosureLimit>(no_bits.load_ordinary(observed)), block::NativeClosureLimit::Bits);
  ASSERT_EQ(loads, 1u);
  block::NativeStateReadMeter repeat(1, 64);
  ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(repeat.load_ordinary(observed)));
  ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(repeat.load_ordinary(observed)));
  ASSERT_EQ(loads, 3u);  // Deduplicated charging must not cache source loads.
  ASSERT_EQ(repeat.usage().cells, 1u);
  ASSERT_EQ(repeat.usage().bits, 64u);
  td::Ref<PreflightObservedCell> interrupted{true, leaf, &loads, false, 4};
  block::NativeStateReadMeter failing(1, 64);
  bool threw = false;
  try { (void)failing.load_ordinary(interrupted); } catch (const vm::VmVirtError&) { threw = true; }
  ASSERT_TRUE(threw);
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(failing.load_ordinary(interrupted)));
  ASSERT_EQ(std::get<block::LocalUnavailable>(failing.load_ordinary(interrupted)).code,
            block::LocalUnavailableCode::CellUnavailable);
  ASSERT_EQ(loads, 4u);
  auto proof = vm::MerkleProof::generate(root, [&](const td::Ref<vm::Cell>& node) {
    return node->get_hash() == left->get_hash();
  }).move_as_ok();
  auto virtual_root = vm::MerkleProof::virtualize(proof).move_as_ok();
  auto pruned = vm::load_cell_slice(virtual_root).prefetch_ref(0);
  block::NativeStateReadMeter missing_content(100, 10000);
  auto missing = missing_content.load_encoded(pruned);
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(missing));
  ASSERT_EQ(std::get<block::LocalUnavailable>(missing).code, block::LocalUnavailableCode::CellUnavailable);
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  block::NativeStateReadMeter opaque(1, 264), ordinary_only(1, 264);
  ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(opaque.load_encoded(library)));
  ASSERT_EQ(std::get<block::LocalUnavailable>(ordinary_only.load_ordinary(library)).code,
            block::LocalUnavailableCode::CellIdentity);

  auto encoded_proof = vm::MerkleProof::generate(root, [](const td::Ref<vm::Cell>&) { return true; }).move_as_ok();
  bool is_special = false;
  auto native_proof = vm::load_cell_slice_special(encoded_proof, is_special);
  ASSERT_TRUE(is_special);
  auto encoded_stub = native_proof.prefetch_ref();
  auto native_stub = vm::load_cell_slice_special(encoded_stub, is_special);
  ASSERT_TRUE(is_special);
  ASSERT_EQ(native_stub.special_type(), vm::Cell::SpecialType::PrunnedBranch);
  ASSERT_EQ(native_stub.size_refs(), 0u);
  ASSERT_EQ(native_proof.size(), 280u);
  ASSERT_EQ(native_stub.size(), 288u);
  block::NativeStateReadMeter encoded_meter(2, 568);
  auto encoded_closure = block::read_workchain_account_closure(encoded_proof, encoded_meter, 2, 568, 1);
  ASSERT_TRUE(std::holds_alternative<block::WorkchainInputUsage>(encoded_closure));
  ASSERT_EQ(encoded_meter.usage().cells, 2u);
  ASSERT_EQ(encoded_meter.usage().bits, 568u);
  // Virtualizing the same proof requests hidden content, not encoded storage.
  auto hidden_root = vm::MerkleProof::virtualize(encoded_proof).move_as_ok();
  block::NativeStateReadMeter hidden_meter(2, 568);
  auto hidden = hidden_meter.load_encoded(hidden_root);
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(hidden));
  ASSERT_EQ(hidden_meter.usage().cells, 0u);

  block::NativeStateReadMeter total(3, 80);
  for (const auto& account : {left, right}) {
    auto read = block::read_workchain_account_closure(account, total, 2, 72, 1);
    ASSERT_TRUE(std::holds_alternative<block::WorkchainInputUsage>(read));
    ASSERT_EQ(std::get<block::WorkchainInputUsage>(read).cells, 2u);
    ASSERT_EQ(std::get<block::WorkchainInputUsage>(read).bits, 72u);
  }
  ASSERT_EQ(total.usage().cells, 3u);
  ASSERT_EQ(total.usage().bits, 80u);
  auto local_cells = block::read_workchain_account_closure(right, total, 1, 72, 1);
  ASSERT_EQ(std::get<block::WorkchainAccountClosureLimit>(local_cells).kind,
            block::WorkchainAccountClosureLimit::Cells);
  auto local_bits = block::read_workchain_account_closure(right, total, 2, 71, 1);
  ASSERT_EQ(std::get<block::WorkchainAccountClosureLimit>(local_bits).kind,
            block::WorkchainAccountClosureLimit::Bits);
  auto local_depth = block::read_workchain_account_closure(right, total, 2, 72, 0);
  ASSERT_EQ(std::get<block::WorkchainAccountClosureLimit>(local_depth).kind,
            block::WorkchainAccountClosureLimit::Depth);
  for (unsigned depth : {12u, 20u}) {
    auto diamond = number(9);
    for (unsigned i = 0; i < depth; ++i) diamond = vm::CellBuilder().store_ref(diamond).store_ref(diamond).finalize();
    vm::MerkleProofBuilder tracked(diamond);
    unsigned visits = 0;
    tracked.set_cell_load_callback([&](const vm::LoadedCell&) { ++visits; });
    // Fixture depths are at most 20, so depth + 1 is representable.
    block::NativeStateReadMeter bounded(depth + 1, 64);
    auto closure = block::read_workchain_account_closure(tracked.root(), bounded, depth + 1, 64, 20);
    ASSERT_TRUE(std::holds_alternative<block::WorkchainInputUsage>(closure));
    ASSERT_EQ(visits, depth + 1);
    ASSERT_EQ(std::get<block::WorkchainInputUsage>(closure).cells, depth + 1);
    // Proof generation closes the visited set by content hash, not usage path.
    // Read the opposite edge at every level, although accounting first took 0.
    auto reconstructed = vm::MerkleProof::virtualize(tracked.extract_proof().move_as_ok()).move_as_ok();
    for (unsigned i = 0; i < depth; ++i) reconstructed = vm::load_cell_slice(reconstructed).prefetch_ref(1);
    ASSERT_EQ(vm::load_cell_slice(reconstructed).prefetch_ulong(64), 9u);
  }
}

block::MaterializedNativeCells own_native_fixture(const std::vector<td::Ref<vm::Cell>>& roots) {
  // Explicit fixture-only physical acquisition allowance, not a protocol default.
  auto result = block::NativeCellMaterializer::run(roots, {1000, 1000000, 8});
  ASSERT_TRUE(std::holds_alternative<block::MaterializedNativeCells>(result));
  return std::get<block::MaterializedNativeCells>(std::move(result));
}

using CounterEngine = block::test::CounterEngine;

td::Ref<vm::Cell> counter_configuration_shell(td::Ref<vm::Cell> business) {
  // Resolver-only fixture: this explicit instance identity is a wire value,
  // not a claim of installation against an authenticated masterchain state.
  // Live installation fixtures derive their claims from their actual zerostate.
  block::WorkchainResourcePolicy fixture_resources{4, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
  return block::encode_workchain_engine_parameters(
      {400, number(4002)->get_hash().bits(),
       fixture_resources, std::move(business), 10000000000ULL}).move_as_ok();
}

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
  policy.engine_configuration = counter_configuration_shell(vm::CellBuilder().finalize());
  if (include_ingress) {
    CHECK(config.set_ref(td::BitArray<32>(84u), block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
  }
  return block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
                                     block::Config::needCapabilities).move_as_ok();
}

TEST(WorkchainBlock, CounterConfigurationEnvelope) {
  auto config = block_configuration();
  auto table = block::decode_workchain_native_ingress_table(config->get_config_param(84)).move_as_ok();
  auto shell = table.at(2).engine_configuration;
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x434e5431;
  CounterEngine engine;
  ASSERT_EQ(engine.validate_and_resolve_config(descriptor, *config, shell).is_ok() ? 0 : 1125, 0);
  // A bare empty cell must fail framing; it is not empty business parameters.
  ASSERT_EQ(engine.validate_and_resolve_config(descriptor, *config, vm::CellBuilder().finalize()).is_error() ? 0 : 1126, 0);
  auto decoded = block::decode_workchain_engine_parameters(shell).move_as_ok();
  decoded.parameters = vm::CellBuilder().store_long(0, 1).finalize();
  auto nonempty = block::encode_workchain_engine_parameters(decoded).move_as_ok();
  ASSERT_TRUE(block::decode_workchain_engine_parameters(nonempty).is_ok());
  // Framing and descriptor are valid; the independent business predicate alone
  // rejects this input. No error-text matching substitutes for that isolation.
  ASSERT_EQ(engine.validate_and_resolve_config(descriptor, *config, nonempty).is_error() ? 0 : 1127, 0);
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

block::ResolvedBatchInputPolicy inbox_test_policy(
    std::uint32_t max_inbound, block::WorkchainInputLimits limits = {100000, 100000000, 100000},
    std::uint32_t max_reads = 16, std::uint32_t max_writes = 16) {
  block::WorkchainResourcePolicy resources{2, {limits.cells, limits.bits, limits.roots, max_reads, max_writes, max_inbound},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
  block::InputPolicyIdentity identity{vm::CellHash{}, false, 0x434e5431, 7, 5, 2};
  auto result = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, identity);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(result));
  return std::get<block::ResolvedBatchInputPolicy>(result);
}

block::WorkchainHostIdentity batch_test_identity(td::Ref<vm::Cell> finality) {
  auto zero = td::Bits256::zero();
  return {0, zero, zero, 2, UINT64_C(0x8000000000000000), zero, false,
          0x434e5431, 7, 5, 2, zero, 1, 1, 1, std::move(finality)};
}

TEST(WorkchainBlock, BatchInputUnionExactBounds) {
  auto declarations = block::encode_workchain_account_declarations({}, 16, 16).move_as_ok();
  std::vector<td::Ref<vm::Cell>> inbox;
  auto identity = batch_test_identity(declarations);
  block::BatchInputAdmissionSession generous(inbox_test_policy(8), declarations, declarations, identity, inbox);
  const auto& result = generous.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(result));
  const auto& admitted = std::get<block::AdmittedBatchInput>(result);
  const auto usage = admitted.usage();
  ASSERT_EQ(usage.roots, 3u);
  ASSERT_EQ(usage.cells, 6u);  // One shared input cell, four identity cells, one wrapper.
  std::vector<td::Ref<vm::Cell>> final_roots{admitted.root()};
  auto oracle = block::NativeCellMaterializer::run(final_roots, {100000, 100000000, 1});
  ASSERT_TRUE(std::holds_alternative<block::MaterializedNativeCells>(oracle));
  const auto& full = std::get<block::MaterializedNativeCells>(oracle).physical_usage();
  ASSERT_EQ(usage.cells, full.cells);
  ASSERT_EQ(usage.bits, full.bits);
  block::BatchInputAdmissionSession exact(inbox_test_policy(8, {usage.cells, usage.bits, 3}),
                                         declarations, declarations, identity, inbox);
  const auto& exact_result = exact.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(exact_result));
  ASSERT_EQ(std::get<block::AdmittedBatchInput>(exact_result).root()->get_hash(), admitted.root()->get_hash());
  ASSERT_TRUE(&exact_result == &exact.evaluate());
  for (unsigned bound = 0; bound < 3; ++bound) {
    block::WorkchainInputLimits limits{usage.cells, usage.bits, 3};
    ASSERT_TRUE(limits.cells > 0 && limits.bits > 0 && limits.roots > 1);
    if (bound == 0) --limits.cells;
    if (bound == 1) --limits.bits;
    if (bound == 2) --limits.roots;
    block::BatchInputAdmissionSession rejected(inbox_test_policy(8, limits), declarations, declarations, identity, inbox);
    const auto& failure = rejected.evaluate();
    ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(failure));
    ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(failure).category,
              block::WorkchainExecutionFailure::CandidateInvalid);
    ASSERT_TRUE(&failure == &rejected.evaluate());
  }
}

TEST(WorkchainBlock, BatchInputRootCountPrecedesAcquisition) {
  auto declarations = block::encode_workchain_account_declarations({}, 16, 16).move_as_ok();
  unsigned loads = 0;
  td::Ref<vm::Cell> observed{td::Ref<PreflightObservedCell>{true, declarations, &loads}};
  std::vector<td::Ref<vm::Cell>> inbox{observed, observed};
  block::BatchInputAdmissionSession session(inbox_test_policy(8, {100, 10000, 4}),
                                           observed, declarations, batch_test_identity(declarations), inbox);
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(result));
  ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(result).category,
            block::WorkchainExecutionFailure::CandidateInvalid);
  ASSERT_EQ(loads, 0u);  // 3+2 roots, even when both inbox references are identical.
  ASSERT_TRUE(&result == &session.evaluate());
  ASSERT_EQ(loads, 0u);
}

TEST(WorkchainBlock, DeclarationShapeCountsSharedSubtreesWithoutExpansion) {
  for (unsigned depth : {12u, 20u}) {
  auto record = vm::CellBuilder().store_long(0x439e6964, 32).store_long(0, 1).finalize();
  // Fixed depths below 32 keep both the shift and 256-depth in range.
  const std::uint64_t entries = UINT64_C(1) << depth;
  auto node = vm::CellBuilder().store_long(6, 3).store_long(256 - depth, 8).store_ref(record).finalize();
  for (unsigned i = 0; i < depth; ++i) {
    node = vm::CellBuilder().store_long(0, 2).store_ref(node).store_ref(node).finalize();
  }
  auto root = vm::CellBuilder().store_long(0x7bc07a6d, 32).store_long(1, 1).store_ref(node)
      .store_long(0, 1).finalize();
  auto shape = block::inspect_workchain_account_declarations(root, entries, 0);
  ASSERT_TRUE(shape.is_ok());
  ASSERT_EQ(shape.ok().reads, entries);
  ASSERT_EQ(shape.ok().writes, 0u);
  ASSERT_EQ(shape.ok().inspected_nodes, depth + 1u);
  ASSERT_TRUE(entries > 0);
  auto rejected = block::inspect_workchain_account_declarations(root, entries - 1, 0);
  ASSERT_TRUE(rejected.is_error());
  // Independent semantic decoder agrees on the modest positive fixture.
  if (depth == 12) {
    auto decoded = block::decode_workchain_account_declarations(root, entries, 0);
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.ok().reads.size(), shape.ok().reads);
  }
  }
}

TEST(WorkchainBlock, BatchInputNativeSpecialAndFailureProvenance) {
  auto declarations = block::encode_workchain_account_declarations({}, 16, 16).move_as_ok();
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  block::tlb::MsgEnvelope::Record_std envelope;
  block::gen::Message::Record message;
  ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(1), envelope));
  ASSERT_TRUE(tlb::type_unpack_cell(envelope.msg, block::gen::t_Message_Any, message));
  auto body = vm::CellBuilder().store_ref(library).finalize();
  message.body = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(body).finalize());
  ASSERT_TRUE(tlb::type_pack_cell(envelope.msg, block::gen::t_Message_Any, message));
  ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(4096, envelope.msg));
  td::Ref<vm::Cell> packed;
  ASSERT_TRUE(tlb::pack_cell(packed, envelope));
  block::tlb::MsgEnvelope::Record_std second_envelope;
  block::gen::Message::Record second_message;
  ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(2), second_envelope));
  ASSERT_TRUE(tlb::type_unpack_cell(second_envelope.msg, block::gen::t_Message_Any, second_message));
  second_message.body = message.body;
  ASSERT_TRUE(tlb::type_pack_cell(second_envelope.msg, block::gen::t_Message_Any, second_message));
  td::Ref<vm::Cell> second;
  ASSERT_TRUE(tlb::pack_cell(second, second_envelope));
  std::vector<td::Ref<vm::Cell>> inbox{packed, second};
  auto identity = batch_test_identity(body);
  block::BatchInputAdmissionSession valid(inbox_test_policy(8), declarations, declarations, identity, inbox);
  ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(valid.evaluate()));
  const auto& accepted = std::get<block::AdmittedBatchInput>(valid.evaluate());
  const auto usage = accepted.usage();
  ASSERT_EQ(usage.roots, 5u);
  std::vector<td::Ref<vm::Cell>> final_roots{accepted.root()};
  auto oracle = block::NativeCellMaterializer::run(final_roots, {100000, 100000000, 1});
  ASSERT_TRUE(std::holds_alternative<block::MaterializedNativeCells>(oracle));
  const auto& full = std::get<block::MaterializedNativeCells>(oracle).physical_usage();
  ASSERT_EQ(usage.cells, full.cells);
  ASSERT_EQ(usage.bits, full.bits);
  std::reverse(inbox.begin(), inbox.end());
  block::BatchInputAdmissionSession reversed(inbox_test_policy(8, {usage.cells, usage.bits, usage.roots}),
                                             declarations, declarations, identity, inbox);
  ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(reversed.evaluate()));
  ASSERT_EQ(std::get<block::AdmittedBatchInput>(reversed.evaluate()).root()->get_hash(), accepted.root()->get_hash());
  block::BatchInputAdmissionSession forbidden(inbox_test_policy(8), body, declarations, identity, inbox);
  const auto& bad = forbidden.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(bad));
  ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(bad).category,
            block::WorkchainExecutionFailure::CandidateInvalid);
  unsigned loads = 0;
  td::Ref<vm::Cell> unavailable{td::Ref<PreflightObservedCell>{true, declarations, &loads, true}};
  block::BatchInputAdmissionSession missing(inbox_test_policy(8), unavailable, declarations, identity, inbox);
  const auto& local = missing.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(local));
  ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(local).category,
            block::WorkchainExecutionFailure::LocalUnavailable);
  ASSERT_EQ(loads, 1u);
  ASSERT_TRUE(&local == &missing.evaluate());
  ASSERT_EQ(loads, 1u);
}

TEST(WorkchainBlock, BatchInputHostMismatchAndCorruptInbox) {
  auto declarations = block::encode_workchain_account_declarations({}, 16, 16).move_as_ok();
  const std::vector<td::Ref<vm::Cell>> empty;
  for (unsigned field = 0; field < 6; ++field) {
    auto identity = batch_test_identity(declarations);
    if (field == 0) identity.configuration_hash = td::Bits256::ones();
    if (field == 1) identity.extended = true;
    if (field == 2) identity.engine_selector = 1;
    if (field == 3) identity.vm_mode = 1;
    if (field == 4) identity.descriptor_version = 1;
    if (field == 5) identity.admission_version = 1;
    block::BatchInputAdmissionSession session(inbox_test_policy(8), declarations, declarations, identity, empty);
    const auto& result = session.evaluate();
    ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(result));
    ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(result).category,
              block::WorkchainExecutionFailure::LocalUnavailable);
  }
  auto envelope = inbound_envelope(1);
  for (const auto& inbox : {std::vector<td::Ref<vm::Cell>>{envelope, envelope},
                            std::vector<td::Ref<vm::Cell>>{declarations}}) {
    block::BatchInputAdmissionSession session(inbox_test_policy(8), declarations, declarations,
                                             batch_test_identity(declarations), inbox);
    const auto& result = session.evaluate();
    ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(result));
    ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(result).category,
              block::WorkchainExecutionFailure::AuthenticatedStateCorrupt);
  }
}

TEST(WorkchainBlock, BatchInputDeclarationSemanticsAndProvenance) {
  const std::vector<td::Ref<vm::Cell>> inbox;
  auto empty = block::encode_workchain_account_declarations({}, 16, 16).move_as_ok();
  const auto declaration = [](td::Ref<vm::Cell> reads, td::Ref<vm::Cell> writes) {
    vm::CellBuilder cb;
    cb.store_long(0x7bc07a6d, 32);
    CHECK(cb.store_maybe_ref(reads) && cb.store_maybe_ref(writes));
    return cb.finalize();
  };
  auto record = vm::CellBuilder().store_long(0x439e6964, 32).store_long(0, 1).finalize();
  auto read_leaf = vm::CellBuilder().store_long(6, 3).store_long(256, 9).store_ref(record).finalize();
  auto write_leaf = vm::CellBuilder().store_long(6, 3).store_long(256, 9).finalize();
  auto short_read = vm::CellBuilder().store_long(6, 3).store_long(255, 8).store_ref(record).finalize();
  auto short_write = vm::CellBuilder().store_long(6, 3).store_long(255, 8).finalize();
  auto two_reads = vm::CellBuilder().store_long(0, 2).store_ref(short_read).store_ref(short_read).finalize();
  auto two_writes = vm::CellBuilder().store_long(0, 2).store_ref(short_write).store_ref(short_write).finalize();
  auto valid = declaration(read_leaf, write_leaf);
  block::BatchInputAdmissionSession positive(inbox_test_policy(8, {100, 10000, 3}, 1, 1),
                                             empty, valid, batch_test_identity(empty), inbox);
  ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(positive.evaluate()));
  for (unsigned fault = 0; fault < 5; ++fault) {
    auto root = valid;
    if (fault == 0) root = declaration(two_reads, write_leaf);
    if (fault == 1) root = declaration(read_leaf, two_writes);
    if (fault == 2) root = declaration(read_leaf, read_leaf);  // Write leaf must have no refs.
    if (fault == 3) root = declaration(vm::CellBuilder().finalize(), {});  // Truncated label throws VmError.
    if (fault == 4) root = declaration(vm::CellBuilder().store_long(6, 3).store_long(256, 9)
                                      .store_ref(empty).finalize(), {});  // Bad read record returns Status.
    block::BatchInputAdmissionSession session(inbox_test_policy(8, {100, 10000, 3}, 1, 1),
                                              empty, root, batch_test_identity(empty), inbox);
    const auto& result = session.evaluate();
    ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(result));
    ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(result).category,
              block::WorkchainExecutionFailure::CandidateInvalid);
  }
  unsigned loads = 0;
  td::Ref<vm::Cell> missing{td::Ref<PreflightObservedCell>{true, valid, &loads, true}};
  block::BatchInputAdmissionSession unavailable(inbox_test_policy(8), empty, missing,
                                                batch_test_identity(empty), inbox);
  const auto& result = unavailable.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(result));
  ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(result).category,
            block::WorkchainExecutionFailure::LocalUnavailable);
  ASSERT_EQ(loads, 1u);
}

TEST(WorkchainBlock, DeclarationSingleLeafZeroAllowance) {
  auto record = vm::CellBuilder().store_long(0x439e6964, 32).store_long(0, 1).finalize();
  auto leaf = vm::CellBuilder().store_long(6, 3).store_long(256, 9).store_ref(record).finalize();
  vm::CellBuilder cb;
  cb.store_long(0x7bc07a6d, 32);
  ASSERT_TRUE(cb.store_maybe_ref(leaf) && cb.store_maybe_ref({}));
  auto root = cb.finalize();
  auto positive = block::inspect_workchain_account_declarations(root, 1, 0);
  ASSERT_TRUE(positive.is_ok());
  ASSERT_EQ(positive.ok().reads, 1u);
  ASSERT_TRUE(block::inspect_workchain_account_declarations(root, 0, 0).is_error());
}

TEST(WorkchainBlock, BatchInputDeclarationCacheBindsRemainingWidth) {
  auto record = vm::CellBuilder().store_long(0x439e6964, 32).store_long(0, 1).finalize();
  auto leaf = vm::CellBuilder().store_long(6, 3).store_long(253, 8).store_ref(record).finalize();
  const auto fork = [](td::Ref<vm::Cell> a, td::Ref<vm::Cell> b) {
    return vm::CellBuilder().store_long(0, 2).store_ref(a).store_ref(b).finalize();
  };
  auto shared = fork(leaf, leaf);
  auto left = fork(shared, shared);
  auto right = vm::CellBuilder().store_long(0, 1).store_long(-2, 2).store_long(0, 1)
      .store_ref(shared).store_ref(shared).finalize();
  auto root = vm::CellBuilder().store_long(0x7bc07a6d, 32).store_long(1, 1)
      .store_ref(fork(left, right)).store_long(0, 1).finalize();
  const std::vector<td::Ref<vm::Cell>> inbox;
  auto empty = block::encode_workchain_account_declarations({}, 16, 16).move_as_ok();
  block::BatchInputAdmissionSession session(inbox_test_policy(8), empty, root, batch_test_identity(empty), inbox);
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::BatchInputAdmissionFailure>(result));
  ASSERT_EQ(std::get<block::BatchInputAdmissionFailure>(result).category,
            block::WorkchainExecutionFailure::CandidateInvalid);
}

class InboxWorkspaceProbe final : public std::pmr::memory_resource {
 public:
  unsigned allocations{0};
  std::size_t max_allocation{0};
 private:
  void* do_allocate(std::size_t bytes, std::size_t alignment) override {
    ++allocations;
    max_allocation = std::max(max_allocation, bytes);
    return std::pmr::new_delete_resource()->allocate(bytes, alignment);
  }
  void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override {
    std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
  }
  bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};

TEST(WorkchainBlock, BoundedInboxCountBeforeWorkspace) {
  auto policy = inbox_test_policy(1);
  InboxWorkspaceProbe workspace;
  unsigned calls = 0;
  auto callback = [&](const auto&) { ++calls; return td::Status::OK(); };
  // Null entries also distinguish early count rejection from envelope parsing.
  std::vector<td::Ref<vm::Cell>> excess(32767);
  auto rejected = block::build_workchain_batch_inbound_structure(excess, policy, callback, workspace);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  ASSERT_EQ(workspace.allocations, 0u);
  ASSERT_EQ(calls, 0u);
  // A permissive policy does not replace the wire bound; its failure has the
  // same candidate category, while the legacy API retains its original code.
  std::vector<td::Ref<vm::Cell>> outside_wire(32768);
  auto wire_rejected = block::build_workchain_batch_inbound_structure(
      outside_wire, inbox_test_policy(UINT32_MAX), callback, workspace);
  ASSERT_TRUE(wire_rejected.is_error());
  ASSERT_EQ(wire_rejected.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  auto legacy_rejected = block::encode_workchain_batch_inbound(outside_wire);
  ASSERT_TRUE(legacy_rejected.is_error());
  ASSERT_EQ(legacy_rejected.error().code(), 0);
  ASSERT_EQ(workspace.allocations, 0u);
  ASSERT_EQ(calls, 0u);
  auto accepted = block::build_workchain_batch_inbound_structure({inbound_envelope(1)}, policy, callback, workspace);
  ASSERT_TRUE(accepted.is_ok());
  ASSERT_EQ(workspace.allocations, 1u);
  ASSERT_EQ(calls, 2u);
}

TEST(WorkchainBlock, BoundedInboxStructureMatchesNativeDictionary) {
  for (unsigned count : {1u, 2u, 3u, 8u, 64u, 257u}) {
    std::vector<td::Ref<vm::Cell>> envelopes;
    vm::Dictionary expected(256);
    for (unsigned i = 0; i < count; ++i) {
      auto envelope = inbound_envelope(1, i);
      block::tlb::MsgEnvelope::Record_std record;
      ASSERT_TRUE(tlb::unpack_cell(envelope, record));
      ASSERT_TRUE(expected.set_ref(record.msg->get_hash().bits(), 256, envelope));
      envelopes.push_back(envelope);
    }
    vm::CellBuilder wrapper;
    wrapper.store_long(0x57494e31, 32).store_long(count, 15);
    ASSERT_TRUE(std::move(expected).append_dict_to_bool(wrapper));
    const auto expected_hash = wrapper.finalize()->get_hash();
    for (bool reverse : {false, true}) {
      if (reverse) std::reverse(envelopes.begin(), envelopes.end());
      unsigned derived = 0;
      auto result = block::build_workchain_batch_inbound_structure(envelopes, inbox_test_policy(count), [&](const auto&) {
        ++derived;  // Test fixture count <= 257, hence <= 514 final nodes.
        return td::Status::OK();
      }, *std::pmr::get_default_resource());
      ASSERT_TRUE(result.is_ok());
      ASSERT_EQ(result.ok()->get_hash(), expected_hash);
      ASSERT_EQ(derived, 2 * count);
      ASSERT_TRUE(block::decode_workchain_batch_inbound(result.ok()).is_ok());
    }
  }
}

TEST(WorkchainBlock, BoundedInboxUniformPrefixLabels) {
  for (unsigned length = 1; length <= 12; ++length) {
    for (bool bit : {false, true}) {
      td::Ref<vm::Cell> selected[2];
      // Deterministic bounded fixture search. The two real message hashes share
      // exactly the chosen uniform prefix, then fork on the next bit.
      for (unsigned nonce = 0; nonce < (1u << 20) && (selected[0].is_null() || selected[1].is_null()); ++nonce) {
        auto message = vm::CellBuilder().store_long(nonce, 32).finalize_novm();
        auto key = message->get_hash().bits();
        unsigned matched = 0;
        while (matched < length && key[matched] == bit) ++matched;
        if (matched == length) selected[key[length] ? 1 : 0] = message;
      }
      ASSERT_TRUE(selected[0].not_null());
      ASSERT_TRUE(selected[1].not_null());
      std::vector<td::Ref<vm::Cell>> envelopes;
      vm::Dictionary expected(256);
      for (const auto& message : selected) {
        block::tlb::MsgEnvelope::Record_std record{0x60, 0x60, td::make_refint(67), message, {}, {}};
        td::Ref<vm::Cell> envelope;
        ASSERT_TRUE(tlb::pack_cell(envelope, record));
        ASSERT_TRUE(expected.set_ref(message->get_hash().bits(), 256, envelope));
        envelopes.push_back(envelope);
      }
      vm::CellBuilder wrapper;
      wrapper.store_long(0x57494e31, 32).store_long(2, 15);
      ASSERT_TRUE(std::move(expected).append_dict_to_bool(wrapper));
      const auto expected_hash = wrapper.finalize()->get_hash();
      auto result = block::build_workchain_batch_inbound_structure(envelopes, inbox_test_policy(2),
          [](const auto&) { return td::Status::OK(); }, *std::pmr::get_default_resource());
      ASSERT_TRUE(result.is_ok());
      ASSERT_EQ(result.ok()->get_hash(), expected_hash);
    }
  }
}

TEST(WorkchainBlock, BoundedInboxStopsBeforeSemanticDecode) {
  std::vector<td::Ref<vm::Cell>> envelopes;
  // Valid envelope framing, intentionally invalid message bodies. Structural
  // admission must not decode the messages, even when all derived nodes fit.
  for (unsigned i = 0; i < 8; ++i) {
    auto message = vm::CellBuilder().store_long(i, 8).finalize();
    block::tlb::MsgEnvelope::Record_std record{0x60, 0x60, td::make_refint(67), message, {}, {}};
    td::Ref<vm::Cell> envelope;
    ASSERT_TRUE(tlb::pack_cell(envelope, record));
    envelopes.push_back(envelope);
  }
  for (unsigned allowance = 0; allowance <= 16; ++allowance) {
    unsigned calls = 0;
    // This standalone test runs synchronously, with no concurrent Cell users.
    // Measure allocations independently of the callback count: batching all
    // construction ahead of callbacks must fail even if callbacks still stop.
    const auto baseline = vm::DataCell::get_total_data_cells();
    ASSERT_TRUE(baseline >= 0);
    auto result = block::build_workchain_batch_inbound_structure(envelopes, inbox_test_policy(8), [&](const auto&) {
      const auto live = vm::DataCell::get_total_data_cells();
      ASSERT_TRUE(live >= baseline);  // Both nonnegative; subtraction cannot overflow.
      ASSERT_EQ(live - baseline, calls + 1);
      if (calls++ >= allowance) return td::Status::Error(1234, "test derived budget");
      return td::Status::OK();
    }, *std::pmr::get_default_resource());
    if (allowance < 16) {
      ASSERT_TRUE(result.is_error());
      ASSERT_EQ(result.error().code(), 1234);
      ASSERT_EQ(calls, allowance + 1);
      ASSERT_EQ(vm::DataCell::get_total_data_cells(), baseline);
    } else {
      ASSERT_TRUE(result.is_ok());
      ASSERT_EQ(calls, 16u);
      ASSERT_TRUE(block::decode_workchain_batch_inbound(result.ok()).is_error());
    }
  }
  ASSERT_TRUE(block::encode_workchain_batch_inbound(envelopes).is_error());
}

TEST(WorkchainBlock, NativeDisposalPlan) {
  block::ActionPhaseConfig cfg;
  cfg.global_version = 16;
  cfg.bounce_msg_body = 256;
  cfg.fwd_std = block::MsgPrices(200, 0, 0, 0, 16384, 0);
  cfg.fwd_mc = block::MsgPrices(100, 0, 0, 0, 16384, 0);
  block::WorkchainSet workchains;
  auto key = td::Bits256::zero();
  auto processor = key;
  processor.as_slice().back() = 1;
  processor.as_slice()[0] = static_cast<char>(0x80);
  static_assert(!std::is_default_constructible_v<block::NativeDisposalProfile>);
  block::NativeDisposalProfile profile{block::NativeDisposalSource::OriginalDestination,
      {0, -block::ComputePhase::sk_no_state, {}}, true};
  auto make_message = [](bool bounce, bool bounced, int source_wc, int value, td::RefInt256 large = {}) {
    vm::CellBuilder cb;
    cb.store_long(0, 1).store_long(1, 1).store_long(bounce, 1).store_long(bounced, 1)
        .store_long(4, 3).store_long(source_wc, 8).store_zeroes(256)
        .store_long(4, 3).store_long(2, 8).store_zeroes(256);
    CHECK(block::CurrencyCollection(large.not_null() ? large : td::make_refint(value)).store(cb));
    CHECK(block::tlb::t_Tomis.store_integer_ref(cb, td::make_refint(3)));
    cb.store_zeroes(4).store_long(77, 64).store_long(99, 32).store_zeroes(2).store_long(42, 64);
    auto result = cb.finalize();
    CHECK(block::gen::t_Message_Any.validate_ref(1000, result));
    return result;
  };
  auto plan = [&](td::Ref<vm::Cell> message) {
    return block::plan_workchain_native_disposal(message, 2, key, processor,
        block::CurrencyCollection(1000), 88, 100, cfg, workchains, 100, profile);
  };
  auto accepted = plan(make_message(true, false, -1, 123)).move_as_ok();
  ASSERT_TRUE(accepted.bounce.not_null());
  ASSERT_TRUE(accepted.branch == block::NativeDisposalBranch::Bounce && accepted.row.account == processor);
  ASSERT_TRUE(accepted.original->get_hash() == make_message(true, false, -1, 123)->get_hash());
  ASSERT_TRUE(accepted.row.new_balance == block::CurrencyCollection(1000));
  ASSERT_TRUE(accepted.row.exported == block::CurrencyCollection(98));
  ASSERT_TRUE(accepted.row.fees == block::CurrencyCollection(25));
  block::gen::CommonMsgInfo::Record_int_msg_info out;
  ASSERT_TRUE(tlb::unpack_cell_inexact(accepted.bounce, out));
  block::CurrencyCollection returned;
  ASSERT_TRUE(returned.unpack(out.value));
  ASSERT_TRUE(returned == block::CurrencyCollection(23));
  ASSERT_EQ(block::tlb::t_Tomis.as_integer(out.fwd_fee)->to_long(), 75);
  ASSERT_EQ(out.created_lt, 88u);
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, key.bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(key), 100, false));
  using Tx = block::transaction::Transaction;
  // Native allocates the output after the transaction's starting LT (87 -> 88).
  Tx ordinary(account, Tx::tr_ord, 87, 100);
  ordinary.in_msg = make_message(true, false, -1, 123);
  cfg.workchains = &workchains;
  ASSERT_TRUE(ordinary.unpack_input_msg(false, &cfg));
  ASSERT_TRUE(ordinary.prepare_credit_phase());
  ordinary.compute_phase = std::make_unique<block::ComputePhase>();
  ordinary.compute_phase->skip_reason = block::ComputePhase::sk_no_state;
  ASSERT_TRUE(ordinary.prepare_bounce_phase(cfg));
  ASSERT_EQ(ordinary.out_msgs.size(), 1u);
  ASSERT_TRUE(ordinary.out_msgs[0]->get_hash() == accepted.bounce->get_hash());
  ASSERT_TRUE(ordinary.balance == accepted.row.new_balance);
  ASSERT_TRUE(ordinary.total_fees == block::CurrencyCollection(25));
  ASSERT_TRUE(accepted.row.fees == ordinary.total_fees);
  block::WorkchainSet stale_workchains;
  cfg.workchains = &stale_workchains; // Valid but stale: a missed rebind must fail an assertion, not crash.
  struct CreditCase { bool bounce, bounced; int wc, value, expected; };
  for (auto c : {CreditCase{false, false, -1, 123, 1123}, CreditCase{true, true, -1, 123, 1123},
                 CreditCase{true, false, 3, 123, 1123}, CreditCase{true, false, -1, 99, 1099}}) {
    LOG(INFO) << "disposal credit case " << c.bounce << '/' << c.bounced << '/' << c.wc << '/' << c.value;
    auto message = make_message(c.bounce, c.bounced, c.wc, c.value);
    auto credit = plan(message).move_as_ok();
    ASSERT_TRUE(credit.branch == block::NativeDisposalBranch::UnexpectedCredit && credit.bounce.is_null());
    ASSERT_TRUE(credit.original->get_hash() == message->get_hash());
    ASSERT_TRUE(credit.row.new_balance == block::CurrencyCollection(c.expected));
    ASSERT_TRUE(credit.row.exported.is_zero() && credit.row.fees.is_zero());
  }
  td::Ref<block::WorkchainInfo> basechain{true};
  basechain.write().workchain = 0;
  basechain.write().basic = basechain.write().active = basechain.write().accept_msgs = true;
  basechain.write().min_addr_len = basechain.write().max_addr_len = 256;
  basechain.write().addr_len_step = 0;
  workchains.emplace(0, basechain);
  auto standard = plan(make_message(true, false, 0, 223)).move_as_ok();
  ASSERT_TRUE(standard.branch == block::NativeDisposalBranch::Bounce);
  ASSERT_TRUE(standard.row.exported == block::CurrencyCollection(173));
  ASSERT_TRUE(standard.row.fees == block::CurrencyCollection(50));
  ASSERT_TRUE(tlb::unpack_cell_inexact(standard.bounce, out));
  ASSERT_TRUE(returned.unpack(out.value));
  ASSERT_TRUE(returned == block::CurrencyCollection(23));
  ASSERT_EQ(block::tlb::t_Tomis.as_integer(out.fwd_fee)->to_long(), 150);
  cfg.workchains = nullptr;
  ASSERT_TRUE(plan(make_message(true, false, 0, 223)).move_as_ok().branch == block::NativeDisposalBranch::Bounce);
  auto baseline = make_message(true, false, -1, 123);
  block::gen::Message::Record ref_input;
  ASSERT_TRUE(tlb::type_unpack_cell(baseline, block::gen::t_Message_Any, ref_input));
  ref_input.body = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(number(42)).finalize());
  td::Ref<vm::Cell> referenced;
  ASSERT_TRUE(tlb::type_pack_cell(referenced, block::gen::t_Message_Any, ref_input));
  ASSERT_TRUE(plan(referenced).move_as_ok().bounce->get_hash() == accepted.bounce->get_hash());
  profile.diagnostics = {2, 37, block::NativeBounceComputeInfo{123, 456}};
  auto diagnostic = plan(baseline).move_as_ok();
  block::gen::Message::Record diagnostic_message;
  ASSERT_TRUE(tlb::type_unpack_cell(diagnostic.bounce, block::gen::t_Message_Any, diagnostic_message));
  auto diagnostic_body = *diagnostic_message.body;
  if (diagnostic_body.fetch_ulong(1)) diagnostic_body = vm::load_cell_slice(diagnostic_body.fetch_ref());
  ASSERT_EQ(diagnostic_body.fetch_ulong(32), 0xfffffffeu);
  ASSERT_TRUE(diagnostic_body.fetch_ref().not_null() && diagnostic_body.fetch_ref().not_null());
  ASSERT_EQ(diagnostic_body.fetch_ulong(8), 2u);
  ASSERT_EQ(diagnostic_body.fetch_long(32), 37);
  ASSERT_EQ(diagnostic_body.fetch_ulong(1), 1u);
  ASSERT_EQ(diagnostic_body.fetch_ulong(32), 123u);
  ASSERT_EQ(diagnostic_body.fetch_ulong(32), 456u);
  profile.diagnostics = {0, -block::ComputePhase::sk_no_state, {}};
  cfg.global_version = 11;
  ASSERT_TRUE(plan(make_message(false, false, -1, 123)).is_error());
  cfg.global_version = 16;
  cfg.fwd_mc.first_frac = 65536;
  ASSERT_TRUE(plan(make_message(true, false, -1, 123)).is_error());
  cfg.fwd_mc.first_frac = 16384;
  ASSERT_TRUE(block::plan_workchain_native_disposal(make_message(true, false, -1, 123), 3, key, processor,
      block::CurrencyCollection(1000), 88, 100, cfg, workchains, 100, profile).is_error());
  ASSERT_TRUE(block::plan_workchain_native_disposal(make_message(true, false, -1, 123), 2, processor, processor,
      block::CurrencyCollection(1000), 88, 100, cfg, workchains, 100, profile).is_error());
  profile.source = block::NativeDisposalSource::ProcessingAccount;
  auto alternate = plan(make_message(true, false, -1, 123)).move_as_ok();
  ASSERT_TRUE(tlb::unpack_cell_inexact(alternate.bounce, out));
  tos::WorkchainId source_wc;
  td::Bits256 source_key;
  ASSERT_TRUE(block::tlb::t_MsgAddressInt.extract_std_address(out.src, source_wc, source_key));
  ASSERT_TRUE(source_wc == 2 && source_key == processor);
  block::gen::Message::Record anycast_input;
  ASSERT_TRUE(tlb::type_unpack_cell(make_message(true, false, 0, 223), block::gen::t_Message_Any, anycast_input));
  block::gen::CommonMsgInfo::Record_int_msg_info anycast_info;
  ASSERT_TRUE(tlb::csr_unpack(anycast_input.info, anycast_info));
  anycast_info.src = vm::load_cell_slice_ref(vm::CellBuilder().store_long(2, 2).store_long(33, 6)
      .store_long(0, 1).store_long(0, 8).store_zeroes(256).finalize());
  ASSERT_TRUE(tlb::csr_pack(anycast_input.info, anycast_info));
  td::Ref<vm::Cell> anycast;
  ASSERT_TRUE(tlb::type_pack_cell(anycast, block::gen::t_Message_Any, anycast_input));
  auto routed = plan(anycast).move_as_ok();
  ASSERT_TRUE(tlb::unpack_cell_inexact(routed.bounce, out));
  ASSERT_TRUE(block::tlb::t_MsgAddressInt.extract_std_address(out.dest, source_wc, source_key));
  ASSERT_TRUE(source_wc == 0 && source_key.cbits().get_uint(1) == 1);
  profile.source = block::NativeDisposalSource::OriginalDestination;
  routed = plan(anycast).move_as_ok();
  ASSERT_TRUE(tlb::unpack_cell_inexact(routed.bounce, out));
  ASSERT_TRUE(block::tlb::t_MsgAddressInt.extract_std_address(out.dest, source_wc, source_key));
  ASSERT_TRUE(source_wc == 0 && source_key == key);
  profile.allow_anycast = false;
  ASSERT_TRUE(plan(anycast).move_as_ok().branch == block::NativeDisposalBranch::UnexpectedCredit);
  profile.source = static_cast<block::NativeDisposalSource>(2);
  ASSERT_TRUE(plan(baseline).is_error());
  profile.source = block::NativeDisposalSource::OriginalDestination;
  // The Native bigint formula can exceed uint64 while still fitting Tomis.
  cfg.fwd_mc.lump_price = cfg.fwd_mc.cell_price = std::numeric_limits<td::uint64>::max();
  cfg.fwd_mc.first_frac = 0; // Keep the entire >64-bit price in the wire fee.
  auto large = plan(make_message(true, false, -1, 0, td::make_refint(1) << 80)).move_as_ok();
  ASSERT_TRUE(large.branch == block::NativeDisposalBranch::Bounce);
  ASSERT_TRUE(tlb::unpack_cell_inexact(large.bounce, out));
  ASSERT_TRUE(!block::tlb::t_Tomis.as_integer(out.fwd_fee)->unsigned_fits_bits(64));
  auto unaffordable = plan(make_message(true, false, -1, 123)).move_as_ok();
  ASSERT_TRUE(unaffordable.branch == block::NativeDisposalBranch::UnexpectedCredit);
}

TEST(WorkchainBlock, NativeBounceMessage) {
  auto address = [](int wc, bool last) {
    return vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(wc, 8)
        .store_zeroes(255).store_long(last, 1).finalize());
  };
  auto src = address(2, false), dest = address(-1, true);
  vm::Dictionary extra(32);
  vm::CellBuilder extra_amount;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(extra_amount, *td::make_refint(5)));
  ASSERT_TRUE(extra.set_builder(td::BitArray<32>::zero(), extra_amount));
  struct Case { unsigned bits; unsigned refs; bool extra; bool by_ref; };
  // These fixed fields occupy 672 bits before the Either selector. Pin both
  // adjacent boundaries independently of the serializer's capacity decision.
  for (auto c : {Case{0, 1, false, false}, Case{32, 1, false, false},
                 Case{350, 1, false, false}, Case{351, 1, false, true},
                 Case{800, 1, false, true}, Case{8, 4, false, false},
                 Case{8, 3, true, false}, Case{8, 4, true, true}}) {
    vm::CellBuilder body;
    body.store_zeroes(c.bits);
    for (unsigned i = 0; i < c.refs; ++i) body.store_ref(number(i));
    auto expected = vm::CellBuilder().append_builder(body).finalize();
    block::CurrencyCollection amount(td::make_refint(23), c.extra ? extra.get_root_cell() : td::Ref<vm::Cell>{});
    td::Ref<vm::Cell> output;
    ASSERT_TRUE(block::build_native_bounce_message(src, dest, amount,
        td::make_refint(3), 75, 12345, 6789, body, output));
    ASSERT_TRUE(block::gen::t_Message_Any.validate_ref(1000, output));
    auto cs = vm::load_cell_slice(output);
    block::gen::CommonMsgInfo::Record_int_msg_info info;
    ASSERT_TRUE(tlb::unpack(cs, info));
    ASSERT_TRUE(info.ihr_disabled && !info.bounce && info.bounced);
    ASSERT_TRUE(info.src->contents_equal(*src) && info.dest->contents_equal(*dest));
    block::CurrencyCollection value;
    ASSERT_TRUE(value.unpack(info.value));
    ASSERT_TRUE(value == amount);
    ASSERT_EQ(info.extra_flags->prefetch_ulong(4), 1u);
    ASSERT_EQ(info.extra_flags->prefetch_ulong(12), 259u);
    ASSERT_EQ(info.fwd_fee->prefetch_ulong(4), 1u);
    ASSERT_EQ(info.fwd_fee->prefetch_ulong(12), 331u);
    ASSERT_EQ(info.created_lt, 12345u);
    ASSERT_EQ(info.created_at, 6789u);
    ASSERT_EQ(cs.fetch_ulong(1), 0u); // No StateInit.
    bool ref = cs.fetch_ulong(1);
    ASSERT_EQ(ref, c.by_ref);
    auto actual = ref ? cs.fetch_ref() : vm::CellBuilder().append_cellslice(cs).finalize();
    ASSERT_TRUE(actual->get_hash() == expected->get_hash());
  }
}

TEST(WorkchainBlock, NativeBounceStorage) {
  auto leaf = vm::CellBuilder().store_zeroes(9).finalize();
  auto parent = vm::CellBuilder().store_zeroes(17).store_ref(leaf).finalize();
  auto extra = vm::CellBuilder().store_zeroes(7).finalize();
  std::vector<td::Ref<vm::Cell>> roots{leaf, parent};
  auto excluded = block::measure_native_bounce_storage(false, extra, roots).move_as_ok();
  ASSERT_EQ(excluded.cells, 2u);
  ASSERT_EQ(excluded.bits, 26u);
  auto included = block::measure_native_bounce_storage(true, extra, roots).move_as_ok();
  ASSERT_EQ(included.cells, 3u);
  ASSERT_EQ(included.bits, 33u);
  auto shared = block::measure_native_bounce_storage(true, leaf, roots).move_as_ok();
  ASSERT_EQ(shared.cells, 2u);
  ASSERT_EQ(shared.bits, 26u);
  auto absent = block::measure_native_bounce_storage(true, {}, roots).move_as_ok();
  ASSERT_EQ(absent.cells, 2u);
  ASSERT_EQ(absent.bits, 26u);
  std::vector<td::Ref<vm::Cell>> empty;
  auto zero = block::measure_native_bounce_storage(true, {}, empty).move_as_ok();
  ASSERT_EQ(zero.cells, 0u);
  ASSERT_EQ(zero.bits, 0u);
  roots.push_back({});
  // A failed actual root must not yield the successful prefix's 2/26 totals.
  ASSERT_TRUE(block::measure_native_bounce_storage(false, {}, roots).is_error());
}

TEST(WorkchainBlock, NativeBounceStorageCaller) {
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto address = td::Bits256::zero();
  block::Account account(2, address.bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(address), 100, false));
  vm::Dictionary extra(32);
  vm::CellBuilder extra_value;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(extra_value, *td::make_refint(5)));
  ASSERT_TRUE(extra.set_builder(td::BitArray<32>::zero(), extra_value));
  auto extra_root = extra.get_root_cell();
  ASSERT_EQ(vm::load_cell_slice(extra_root).size(), 22u);
  block::CurrencyCollection input_value(td::make_refint(123), extra_root);
  struct PricingCase { int version; bool extra_v2; bool counted; };
  for (auto profile : {PricingCase{12, false, true}, {12, true, true}, {13, false, true},
                       {13, true, false}, {16, false, true}, {16, true, false}}) {
    for (unsigned lump : {100u, 101u}) {
      block::ActionPhaseConfig config;
      config.global_version = profile.version;
      config.extra_currency_v2 = profile.extra_v2;
      config.bounce_msg_body = 256;
      config.fwd_mc = block::MsgPrices(lump, 65536, 65536, 0, 16384, 0);
      config.fwd_std = config.fwd_mc;
      vm::CellBuilder incoming;
      incoming.store_long(6, 4).store_long(4, 3).store_long(-1, 8).store_zeroes(256)
          .store_long(4, 3).store_long(2, 8).store_zeroes(256);
      ASSERT_TRUE(input_value.store(incoming));
      auto message = incoming.store_zeroes(8).store_long(77, 64).store_long(99, 32)
          .store_zeroes(2).store_long(0x1234, 16).finalize();
      block::transaction::Transaction tx(account, block::transaction::Transaction::tr_ord, 100, 100);
      tx.in_msg = message;
      ASSERT_TRUE(tx.unpack_input_msg(false, &config));
      ASSERT_TRUE(tx.prepare_credit_phase());
      tx.compute_phase = std::make_unique<block::ComputePhase>();
      tx.compute_phase->skip_reason = block::ComputePhase::sk_no_state;
      ASSERT_TRUE(tx.prepare_bounce_phase(config));
      ASSERT_TRUE(tx.bounce_phase != nullptr);
      ASSERT_EQ(tx.bounce_phase->msg_cells, profile.counted ? 1u : 0u);
      ASSERT_EQ(tx.bounce_phase->msg_bits, profile.counted ? 22u : 0u);
      const bool nofunds = profile.counted && lump == 101;
      ASSERT_EQ(tx.bounce_phase->nofunds, nofunds);
      ASSERT_EQ(tx.bounce_phase->ok, !nofunds);
      ASSERT_EQ(tx.out_msgs.size(), nofunds ? 0u : 1u);
      if (nofunds) {
        ASSERT_TRUE(tx.balance == block::CurrencyCollection(td::make_refint(1123), extra_root));
      } else {
        ASSERT_TRUE(tx.balance == block::CurrencyCollection(1000));
        block::gen::CommonMsgInfo::Record_int_msg_info returned;
        ASSERT_TRUE(tlb::unpack_cell_inexact(tx.out_msgs[0], returned));
        block::CurrencyCollection returned_value;
        ASSERT_TRUE(returned_value.unpack(returned.value));
        ASSERT_TRUE(returned_value == block::CurrencyCollection(
            td::make_refint(profile.counted ? 0 : lump == 100 ? 23 : 22), extra_root));
      }
    }
  }
}

TEST(WorkchainBlock, NativeBounceBody) {
  auto child = number(55);
  auto original = vm::CellBuilder().store_long(0x1234, 16).store_zeroes(304).store_ref(child).finalize();
  auto body = vm::load_cell_slice_ref(original);
  vm::CellBuilder value_builder;
  ASSERT_TRUE(block::CurrencyCollection(123).store(value_builder));
  auto value = vm::load_cell_slice_ref(value_builder.finalize());
  auto encode = [&](bool rich, bool full, int bits, const block::NativeBounceDiagnostics& diagnostics) {
    vm::CellBuilder encoded;
    block::store_native_bounce_body(encoded, rich, full, bits, *body, body, value, 77, 99, diagnostics);
    return encoded.finalize();
  };
  block::NativeBounceDiagnostics skipped{0, -1, {}};
  bool exhausted = false;
  try {
    vm::CellBuilder output;
    output.store_zeroes(1020);
    block::store_native_bounce_body(output, false, false, 1, *body, body, value, 77, 99, skipped);
  } catch (const vm::CellBuilder::CellCreateError&) {
    exhausted = true;
  }
  ASSERT_TRUE(exhausted);
  auto empty = vm::load_cell_slice(encode(false, false, 0, skipped));
  ASSERT_TRUE(empty.empty_ext());
  for (int bits : {256, 512}) {
    auto legacy = vm::load_cell_slice(encode(false, false, bits, skipped));
    ASSERT_EQ(legacy.size(), bits == 256 ? 288u : 352u);
    ASSERT_EQ(legacy.size_refs(), 0u);
    ASSERT_EQ(legacy.fetch_ulong(32), 0xffffffffu);
    ASSERT_EQ(legacy.fetch_ulong(16), 0x1234u);
    while (legacy.size()) ASSERT_EQ(legacy.fetch_ulong(1), 0u);
  }
  for (bool full : {false, true}) {
    for (unsigned phase = 0; phase < 3; ++phase) {
      block::NativeBounceDiagnostics diagnostics{phase, phase == 0 ? -1 : 42, {}};
      if (phase != 0) diagnostics.compute = block::NativeBounceComputeInfo{123456, 654321};
      auto root = encode(true, full, 256, diagnostics);
      ASSERT_TRUE(block::gen::t_NewBounceBody.validate_ref(4096, root));
      auto rich = vm::load_cell_slice(root);
      ASSERT_EQ(rich.fetch_ulong(32), 0xfffffffeu);
      auto returned_body = rich.fetch_ref();
      auto returned_info = vm::load_cell_slice(rich.fetch_ref());
      auto returned = vm::load_cell_slice(returned_body);
      ASSERT_EQ(returned.size(), 320u);
      ASSERT_EQ(returned.size_refs(), full ? 1u : 0u);
      ASSERT_EQ(returned.fetch_ulong(16), 0x1234u);
      while (returned.size()) ASSERT_EQ(returned.fetch_ulong(1), 0u);
      if (full) {
        ASSERT_TRUE(returned_body->get_hash() == original->get_hash());
        ASSERT_TRUE(returned.fetch_ref()->get_hash() == child->get_hash());
      }
      block::CurrencyCollection recovered;
      ASSERT_TRUE(recovered.fetch(returned_info));
      ASSERT_TRUE(recovered == block::CurrencyCollection(123));
      ASSERT_EQ(returned_info.fetch_ulong(64), 77u);
      ASSERT_EQ(returned_info.fetch_ulong(32), 99u);
      ASSERT_TRUE(returned_info.empty_ext());
      ASSERT_EQ(rich.fetch_ulong(8), phase);
      ASSERT_EQ(rich.fetch_long(32), phase == 0 ? -1 : 42);
      ASSERT_EQ(rich.fetch_ulong(1), phase == 0 ? 0u : 1u);
      if (phase != 0) {
        ASSERT_EQ(rich.fetch_ulong(32), 123456u);
        ASSERT_EQ(rich.fetch_ulong(32), 654321u);
      }
      ASSERT_TRUE(rich.empty_ext());
    }
  }
  // Exercise the ordinary transaction caller, not only the extracted encoder.
  // This ties format selection and phase diagnostics to actual bounce output.
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 1, false, 0, 40, false, 1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto address = td::Bits256::zero();
  block::Account account(2, address.bits());
  ASSERT_TRUE(account.unpack(accounts.lookup(address), 100, false));
  block::ActionPhaseConfig config;
  config.global_version = 16;
  config.extra_currency_v2 = true;
  config.bounce_msg_body = 256;
  config.fwd_mc = block::MsgPrices(0, 0, 0, 0, 0, 0);
  config.fwd_std = block::MsgPrices(0, 0, 0, 0, 0, 0);
  for (int legacy_bits : {0, 256}) {
    config.bounce_msg_body = legacy_bits;
    for (unsigned flags : {0u, 1u, 2u, 3u}) {
      for (unsigned phase = 0; phase < 3; ++phase) {
        vm::CellBuilder incoming;
        incoming.store_long(6, 4)
            .store_long(4, 3)
            .store_long(-1, 8)
            .store_zeroes(256)
            .store_long(4, 3)
            .store_long(2, 8)
            .store_zeroes(256);
        ASSERT_TRUE(block::CurrencyCollection(123).store(incoming));
        ASSERT_TRUE(block::tlb::t_Tomis.store_integer_ref(incoming, td::make_refint(flags)));
        auto message = incoming.store_zeroes(4)
                           .store_long(77, 64)
                           .store_long(99, 32)
                           .store_long(0, 1)
                           .store_long(1, 1)
                           .store_ref(original)
                           .finalize();
        block::transaction::Transaction transaction(account, block::transaction::Transaction::tr_ord, 100, 100);
        transaction.in_msg = message;
        ASSERT_TRUE(transaction.unpack_input_msg(false, &config));
        transaction.compute_phase = std::make_unique<block::ComputePhase>();
        transaction.compute_phase->skip_reason =
            phase == 0 ? block::ComputePhase::sk_no_state : block::ComputePhase::sk_none;
        transaction.compute_phase->success = phase == 2;
        transaction.compute_phase->exit_code = 42;
        transaction.compute_phase->gas_used = 123456;
        transaction.compute_phase->vm_steps = 654321;
        if (phase == 2) {
          transaction.action_phase = std::make_unique<block::ActionPhase>();
          transaction.action_phase->result_code = 7;
        }
        ASSERT_TRUE(transaction.prepare_bounce_phase(config));
        ASSERT_TRUE(transaction.bounce_phase && transaction.bounce_phase->ok);
        // The inline output root is excluded from pricing. Rich refs contain
        // a 320-bit body, optional 64-bit child, and 109-bit original info.
        ASSERT_EQ(transaction.bounce_phase->msg_cells, !(flags & 1u) ? 0u : flags == 3 ? 3u : 2u);
        ASSERT_EQ(transaction.bounce_phase->msg_bits, !(flags & 1u) ? 0u : flags == 3 ? 493u : 429u);
        ASSERT_EQ(transaction.out_msgs.size(), 1u);
        block::gen::Message::Record bounced;
        ASSERT_TRUE(tlb::type_unpack_cell(transaction.out_msgs[0], block::gen::t_Message_Any, bounced));
        vm::CellSlice encoded_body{*bounced.body};
        td::Ref<vm::Cell> actual;
        if (encoded_body.fetch_ulong(1))
          actual = encoded_body.fetch_ref();
        else
          actual = vm::CellBuilder().append_cellslice(encoded_body).finalize();
        block::NativeBounceDiagnostics expected{phase, phase == 0 ? -1 : phase == 2 ? 7 : 42, {}};
        if (phase != 0)
          expected.compute = block::NativeBounceComputeInfo{123456, 654321};
        ASSERT_TRUE(actual->get_hash() ==
                    encode((flags & 1u) != 0, (flags & 2u) != 0, legacy_bits, expected)->get_hash());
      }
    }
  }
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
  block::gen::UnoV2NativeEffects::Record_uno_v2_native_effects native;
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
  block::gen::UnoV2NativeEffects::Record_uno_v2_native_effects native;
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
  block::gen::UnoV2NativeEffects::Record_uno_v2_native_effects native;
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

TEST(WorkchainBlock, MessagePricesDefaultInitialization) {
  // No braces: this checks default initialization, not value-initialization's
  // separate zeroing rule. Missing member initialization must fail compilation.
  constexpr block::MsgPrices prices;
  static_assert(prices.lump_price == 0);
  static_assert(prices.bit_price == 0);
  static_assert(prices.cell_price == 0);
  static_assert(prices.ihr_factor == 0);
  static_assert(prices.first_frac == 0);
  static_assert(prices.next_frac == 0);
  const block::MsgPrices configured(101, 102, 103, 104, 105, 106);
  ASSERT_EQ(configured.lump_price, 101u);
  ASSERT_EQ(configured.bit_price, 102u);
  ASSERT_EQ(configured.cell_price, 103u);
  ASSERT_EQ(configured.ihr_factor, 104u);
  ASSERT_EQ(configured.first_frac, 105u);
  ASSERT_EQ(configured.next_frac, 106u);
}

void initialize_disposal_fixture_prices(block::ActionPhaseConfig& config) {
  // Disposal validates both schedules, even for a basechain destination.
  // Fixtures must declare actual schedules rather than inherit zero defaults.
  config.fwd_std = block::MsgPrices(200, 0, 0, 0, 16384, 0);
  config.fwd_mc = block::MsgPrices(100, 0, 0, 0, 16384, 0);
}

TEST(WorkchainBlock, DisposalFixturePricesOverwritePriorState) {
  block::ActionPhaseConfig config;
  // Defined poison makes a missing assignment fail independently of stack
  // layout, preceding tests, and the outer transaction's rejection guards.
  config.fwd_std = block::MsgPrices(901, 902, 903, 904, 905, 906);
  config.fwd_mc = block::MsgPrices(911, 912, 913, 914, 65536, 916);
  initialize_disposal_fixture_prices(config);
  ASSERT_EQ(config.fwd_std.lump_price, 200u);
  ASSERT_EQ(config.fwd_mc.lump_price, 100u);
  for (const auto* prices : {&config.fwd_std, &config.fwd_mc}) {
    ASSERT_EQ(prices->bit_price, 0u);
    ASSERT_EQ(prices->cell_price, 0u);
    ASSERT_EQ(prices->ihr_factor, 0u);
    ASSERT_EQ(prices->first_frac, 16384u);
    ASSERT_EQ(prices->next_frac, 0u);
  }
}

TEST(WorkchainBlock, AggregateFeeSettlement) {
  using C = block::CurrencyCollection;
  const auto coordinator_id = td::Bits256::zero();
  const td::Bits256 custody_id(number(1)->get_hash().bits());
  auto candidate = number(11);
  const td::Bits256 hash(candidate->get_hash().bits());
  block::InputPolicyIdentity policy_id{candidate->get_hash(), false, 17, 9, 2, 1};
  auto policy = block::ResolvedInputPolicy::from_resolved_fields({10, 1024, 1}, policy_id);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedInputPolicy>(policy));
  block::CandidateAdmissionSession admission(candidate, std::get<block::ResolvedInputPolicy>(policy));
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(admission.evaluate()));
  const auto& admitted = std::get<block::AdmittedInput>(admission.evaluate());
  block::WorkchainHostIdentity identity{-1, hash, hash, 2, UINT64_MAX, hash, false,
      17, 9, 2, 1, hash, 1, 10, 20, number(1)};
  block::gen::ShardStateUnsplit::Record old;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 3, false, 0, 40, false, 1000), old));
  auto original_hash = old.accounts->get_hash();
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(old.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account coordinator(2, coordinator_id.bits()), custody(2, custody_id.bits());
  ASSERT_TRUE(coordinator.unpack(accounts.lookup(coordinator_id), 10, false));
  ASSERT_TRUE(custody.unpack(accounts.lookup(custody_id), 10, false));
  block::WorkchainAccountDeclarations access{{
      {coordinator_id, td::Bits256(coordinator.total_state->get_hash().bits())},
      {custody_id, td::Bits256(custody.total_state->get_hash().bits())}}, {coordinator_id, custody_id}};
  auto input = block::encode_workchain_host_input(identity, admitted, access, {}, 2, 2, 0).move_as_ok();
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = true;
  block::WorkchainAccountEffects effects;
  effects.updates = {{coordinator_id, number(321)}, {custody_id, number(322)}};
  auto legacy = block::encode_workchain_account_effects(effects, 2, 1, 4096).move_as_ok();
  block::gen::UnoV2HostEffects::Record decoded;
  ASSERT_TRUE(tlb::unpack_cell(legacy, decoded));
  ASSERT_EQ(vm::load_cell_slice(decoded.native).prefetch_ulong(32), 0x0bd47725u);
  ASSERT_TRUE(!block::decode_workchain_native_effects(decoded.native).move_as_ok().fees.has_value());
  effects.fees = block::WorkchainFeeSettlement{custody_id, coordinator_id,
      td::make_refint(17), td::make_refint(23), td::make_refint(5)};
  auto root = block::encode_workchain_account_effects(effects, 2, 1, 4096).move_as_ok();
  ASSERT_TRUE(tlb::unpack_cell(root, decoded));
  ASSERT_EQ(vm::load_cell_slice(decoded.native).prefetch_ulong(32), 0x67e2d380u);
  ASSERT_TRUE(block::gen::t_UnoV2HostEffects.validate_ref(4096, root));
  auto native = block::decode_workchain_native_effects(decoded.native).move_as_ok();
  ASSERT_TRUE(native.fees.has_value());
  ASSERT_EQ(native.fees->custody, custody_id);
  ASSERT_EQ(native.fees->coordinator, coordinator_id);
  ASSERT_EQ(native.fees->state_fee->to_long(), 17);
  ASSERT_EQ(native.fees->compute_fee->to_long(), 23);
  ASSERT_EQ(native.fees->tip->to_long(), 5);
  ASSERT_TRUE(block::allocate_workchain_native_balance(custody_id, C(1000), decoded, 1, 4096).move_as_ok() == C(983));
  ASSERT_TRUE(block::allocate_workchain_native_balance(coordinator_id, C(1000), decoded, 1, 4096).move_as_ok() == C(1017));
  auto allocation = block::plan_workchain_native_allocations(decoded, 2, 1, 4096).move_as_ok();
  ASSERT_EQ(allocation.transfers.size(), 1u);
  ASSERT_TRUE(allocation.accounts.at(custody_id).outgoing == C(17));
  ASSERT_TRUE(allocation.accounts.at(coordinator_id).incoming == C(17));
  auto bindings = block::build_workchain_participant_records(td::Bits256(input->get_hash().bits()),
      td::Bits256(root->get_hash().bits()), {coordinator_id, custody_id}, 2).move_as_ok();
  block::transaction::Transaction prepared(custody, block::transaction::Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(prepared.prepare_workchain_import_participant(bindings[1], input, root, number(322), cfg, 1, 4096).is_ok());
  ASSERT_TRUE(prepared.balance == C(955));
  ASSERT_TRUE(prepared.total_fees == C(28));
  ASSERT_TRUE(prepared.out_msgs.empty() && prepared.serialize(cfg));
  ASSERT_TRUE(block::encode_workchain_account_effects(effects, 2, 0, 4096).is_error());
  auto built_result = block::build_workchain_inbound_allocation_overlay(old.accounts, identity,
      input, root, coordinator_id, custody_id, 2, 2, 1, 0, 4096, cfg);
  if (built_result.is_error()) LOG(ERROR) << built_result.error();
  ASSERT_TRUE(built_result.is_ok());
  auto built = built_result.move_as_ok();
  ASSERT_TRUE(built.exports.empty());
  vm::AugmentedDictionary next(vm::load_cell_slice_ref(built.state.accounts), 256, block::tlb::aug_ShardAccounts);
  vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(built.state.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
  for (const auto& key : {coordinator_id, custody_id}) {
    block::Account account(2, key.bits());
    ASSERT_TRUE(account.unpack(next.lookup(key), 10, false));
    ASSERT_TRUE(account.balance == C(key == custody_id ? 955 : 1017));
    block::gen::AccountBlock::Record ab;
    ASSERT_TRUE(tlb::unpack_cell(vm::CellBuilder().append_cellslice(*blocks.lookup(key)).finalize(), ab));
    vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    block::gen::Transaction::Record tx;
    ASSERT_TRUE(tlb::unpack_cell(txs.lookup_ref(td::BitArray<64>(account.last_trans_lt_)), tx));
    C fees;
    ASSERT_TRUE(fees.unpack(tx.total_fees));
    ASSERT_TRUE(fees == C(key == custody_id ? 28 : 0));
    ASSERT_EQ(tx.outmsg_cnt, 0);
  }
  ASSERT_TRUE(block::replay_workchain_inbound_allocation_overlay(old.accounts, identity, input, root,
      coordinator_id, custody_id, 2, 2, 1, 0, 4096, cfg, built).is_ok());
  // C and T share the collected-fee channel; only the authenticated schedule
  // can authorize their split. S uses a different channel. Test the numeric
  // settlement rather than an effects-hash mismatch between two claims.
  for (const auto& amounts : std::vector<std::vector<long long>>{
      {17, 28, 0, 955, 1017, 28}, {0, 40, 5, 955, 1000, 45}, {45, 0, 0, 955, 1045, 0}}) {
    auto alternative = effects;
    alternative.fees->state_fee = td::make_refint(amounts[0]);
    alternative.fees->compute_fee = td::make_refint(amounts[1]);
    alternative.fees->tip = td::make_refint(amounts[2]);
    const unsigned edges = amounts[0] == 0 ? 0 : 1;
    auto other_root = block::encode_workchain_account_effects(alternative, 2, edges, 4096).move_as_ok();
    block::gen::UnoV2HostEffects::Record other_decoded;
    ASSERT_TRUE(tlb::unpack_cell(other_root, other_decoded));
    ASSERT_EQ(block::plan_workchain_native_allocations(other_decoded, 2, edges, 4096).move_as_ok().transfers.size(), edges);
    auto other_bindings = block::build_workchain_participant_records(td::Bits256(input->get_hash().bits()),
        td::Bits256(other_root->get_hash().bits()), {coordinator_id, custody_id}, 2).move_as_ok();
    block::transaction::Transaction c(custody, block::transaction::Transaction::tr_workchain_batch, 21, 10);
    block::transaction::Transaction o(coordinator, block::transaction::Transaction::tr_workchain_batch, 21, 10);
    ASSERT_TRUE(c.prepare_workchain_import_participant(other_bindings[1], input, other_root, number(322), cfg, edges, 4096).is_ok());
    ASSERT_TRUE(o.prepare_workchain_entry(other_bindings[0], input, other_root, number(321), cfg, edges, 4096).is_ok());
    ASSERT_TRUE(c.balance == C(amounts[3]) && o.balance == C(amounts[4]));
    ASSERT_TRUE(c.total_fees == C(amounts[5]) && o.total_fees.is_zero());
    ASSERT_TRUE(c.out_msgs.empty() && o.out_msgs.empty() && c.serialize(cfg) && o.serialize(cfg));
    ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(old.accounts, identity, input, other_root,
        coordinator_id, custody_id, 2, 2, edges, 0, 4096, cfg).is_ok());
  }
  auto changed = effects;
  std::swap(changed.fees->custody, changed.fees->coordinator);
  auto wrong_roles = block::encode_workchain_account_effects(changed, 2, 1, 4096).move_as_ok();
  ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(old.accounts, identity, input, wrong_roles,
      coordinator_id, custody_id, 2, 2, 1, 0, 4096, cfg).is_error());
  // Direct disposal factory: no enclosing allocation/payout role guard can
  // mask a missing local check. Empty inbox keeps all other inputs identical.
  block::ActionPhaseConfig messages;
  initialize_disposal_fixture_prices(messages);
  messages.global_version = 16;
  block::WorkchainSet workchains;
  block::NativeDisposalProfile profile{block::NativeDisposalSource::OriginalDestination,
      {0, -block::ComputePhase::sk_no_state, {}}, false};
  block::WorkchainDisposalEntryContext disposal{custody_id, messages, workchains, profile, 1, 1};
  block::transaction::Transaction good_disposal(coordinator, block::transaction::Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(good_disposal.prepare_workchain_disposal_entry(bindings[0], input, root, number(321),
      cfg, 1, 4096, disposal).is_ok());
  ASSERT_TRUE(good_disposal.balance == C(1017) && good_disposal.total_fees.is_zero());
  auto wrong_bindings = block::build_workchain_participant_records(td::Bits256(input->get_hash().bits()),
      td::Bits256(wrong_roles->get_hash().bits()), {coordinator_id, custody_id}, 2).move_as_ok();
  block::transaction::Transaction bad_disposal(coordinator, block::transaction::Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(bad_disposal.prepare_workchain_disposal_entry(wrong_bindings[0], input, wrong_roles, number(321),
      cfg, 1, 4096, disposal).is_error());
  ASSERT_TRUE(bad_disposal.balance == C(1000) && bad_disposal.total_fees.is_zero());
  ASSERT_TRUE(bad_disposal.root.is_null() && bad_disposal.new_total_state.is_null() && bad_disposal.out_msgs.empty());
  changed = effects;
  changed.fees->compute_fee = td::make_refint(1000);
  auto unfunded = block::encode_workchain_account_effects(changed, 2, 1, 4096).move_as_ok();
  ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(old.accounts, identity, input, unfunded,
      coordinator_id, custody_id, 2, 2, 1, 0, 4096, cfg).is_error());
  ASSERT_EQ(old.accounts->get_hash(), original_hash);
  ASSERT_TRUE(custody.balance == C(1000) && coordinator.balance == C(1000));
}

TEST(WorkchainBlock, NativeDisposalEntry) {
  using Transaction = block::transaction::Transaction;
  const auto a = td::Bits256::zero();
  const td::Bits256 b(number(1)->get_hash().bits());
  const auto foreign = td::Bits256::ones();
  auto candidate = number(11);
  auto hash = td::Bits256(candidate->get_hash().bits());
  block::InputPolicyIdentity policy_id{candidate->get_hash(), false, 17, 9, 2, 1};
  auto policy = block::ResolvedInputPolicy::from_resolved_fields({10, 1024, 1}, policy_id);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedInputPolicy>(policy));
  block::CandidateAdmissionSession admission(candidate, std::get<block::ResolvedInputPolicy>(policy));
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(admission.evaluate()));
  const auto& admitted = std::get<block::AdmittedInput>(admission.evaluate());
  block::WorkchainHostIdentity identity{-1, hash, hash, 2, UINT64_MAX, hash, false,
      17, 9, 2, 1, hash, 1, 10, 20, number(1)};
  block::gen::ShardStateUnsplit::Record old;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 3, false, 0, 40, false, 1000), old));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(old.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account coordinator(2, a.bits()), custody(2, b.bits());
  ASSERT_TRUE(coordinator.unpack(accounts.lookup(a), 10, false));
  ASSERT_TRUE(custody.unpack(accounts.lookup(b), 10, false));
  block::WorkchainAccountDeclarations access{{
      {a, td::Bits256(coordinator.total_state->get_hash().bits())},
      {b, td::Bits256(custody.total_state->get_hash().bits())}}, {a, b}};
  auto bounce_envelope = [&](std::uint64_t lt) {
    block::tlb::MsgEnvelope::Record_std env;
    ASSERT_TRUE(tlb::unpack_cell(inbound_envelope(lt, lt, {}, foreign, block::CurrencyCollection(300)), env));
    auto message = vm::load_cell_slice(env.msg);
    ASSERT_EQ(message.fetch_ulong(4), 4u);
    env.msg = vm::CellBuilder().store_long(6, 4).append_cellslice(message).finalize();
    td::Ref<vm::Cell> root;
    ASSERT_TRUE(tlb::pack_cell(root, env));
    return root;
  };
  std::vector<td::Ref<vm::Cell>> inbox{inbound_envelope(1, 1, {}, a), inbound_envelope(2, 2, {}, b),
      inbound_envelope(3, 3, {}, foreign), bounce_envelope(4), bounce_envelope(5)};
  block::WorkchainAccountEffects effects;
  effects.updates = {{a, number(321)}, {b, number(322)}};
  effects.native_transfers = {{a, b, block::CurrencyCollection(137)}, {b, a, block::CurrencyCollection(10)}};
  auto effects_root = block::encode_workchain_account_effects(effects, 2, 2, 4096).move_as_ok();
  auto input = block::encode_workchain_host_input(identity, admitted, access, inbox, 2, 2, 5).move_as_ok();
  auto bindings = block::build_workchain_participant_records(td::Bits256(input->get_hash().bits()),
      td::Bits256(effects_root->get_hash().bits()), {a, b}, 2).move_as_ok();
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = true;
  block::ActionPhaseConfig messages;
  initialize_disposal_fixture_prices(messages);
  messages.global_version = 16;
  messages.bounce_msg_body = 256;
  block::WorkchainSet workchains;
  td::Ref<block::WorkchainInfo> basechain{true};
  basechain.write().workchain = 0;
  basechain.write().basic = basechain.write().active = basechain.write().accept_msgs = true;
  basechain.write().min_addr_len = basechain.write().max_addr_len = 256;
  basechain.write().addr_len_step = 0;
  workchains.emplace(0, basechain);
  block::NativeDisposalProfile profile{block::NativeDisposalSource::OriginalDestination,
      {0, -block::ComputePhase::sk_no_state, {}}, false};
  block::WorkchainDisposalEntryContext context{b, messages, workchains, profile, 5, 2};
  auto prepare = [&](Transaction& tx, const block::WorkchainDisposalEntryContext& resolved) {
    return tx.prepare_workchain_disposal_entry(bindings[0], input, effects_root, number(321), cfg, 2, 4096, resolved);
  };
  ASSERT_EQ(messages.fwd_mc.lump_price, 100u);
  ASSERT_EQ(messages.fwd_mc.first_frac, 16384u);
  block::tlb::MsgEnvelope::Record_std disposal_envelope;
  ASSERT_TRUE(tlb::unpack_cell(inbox[2], disposal_envelope));
  auto price_context = [&](const block::ActionPhaseConfig& prices) {
    return block::plan_workchain_native_disposal(disposal_envelope.msg, 2, foreign, a,
        block::CurrencyCollection(1000), 22, 10, prices, workchains, 4096, profile);
  };
  ASSERT_TRUE(price_context(messages).is_ok());
  auto invalid_mc_prices = messages;
  invalid_mc_prices.fwd_mc.first_frac = 65536;
  auto rejected_mc_prices = price_context(invalid_mc_prices);
  ASSERT_TRUE(rejected_mc_prices.is_error());
  ASSERT_EQ(rejected_mc_prices.error().message().str(), "invalid resolved disposal context");
  Transaction entry(coordinator, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(prepare(entry, context).is_ok());
  ASSERT_TRUE(entry.balance == block::CurrencyCollection(1073));
  ASSERT_TRUE(entry.total_fees == block::CurrencyCollection(100));
  ASSERT_EQ(entry.end_lt, 24u);
  ASSERT_EQ(entry.out_msgs.size(), 2u);
  ASSERT_TRUE(!entry.storage_phase && !entry.credit_phase && !entry.compute_phase &&
      !entry.action_phase && !entry.bounce_phase);
  ASSERT_TRUE(entry.serialize(cfg));
  Transaction participant(custody, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(participant.prepare_workchain_import_participant(bindings[1], input, effects_root, number(322),
      cfg, 2, 4096).is_ok());
  ASSERT_TRUE(participant.serialize(cfg));
  auto imports = block::build_workchain_routed_final_imports(2, 16, inbox,
      {{a, entry.root}, {b, participant.root}}, a, b, 5, 2, 4096).move_as_ok();
  ASSERT_TRUE(imports.account_credits.at(a) == block::CurrencyCollection(800));
  ASSERT_TRUE(imports.account_credits.at(b) == block::CurrencyCollection(100));
  ASSERT_TRUE(imports.value_imported == block::CurrencyCollection(1235));
  ASSERT_TRUE(imports.fees_collected == block::CurrencyCollection(335));
  std::vector<block::WorkchainAccountValueFlow> rows;
  for (const auto* tx : {&entry, &participant}) {
    block::gen::Transaction::Record rec;
    block::gen::Account::Record_account encoded;
    block::gen::AccountStorage::Record storage;
    block::CurrencyCollection after, fees, exported(0);
    ASSERT_TRUE(tlb::unpack_cell(tx->root, rec));
    ASSERT_TRUE(tlb::unpack_cell(tx->new_total_state, encoded) && tlb::csr_unpack(encoded.storage, storage));
    ASSERT_TRUE(after.unpack(storage.balance) && fees.unpack(rec.total_fees));
    ASSERT_EQ(storage.last_trans_lt, tx == &entry ? 24u : 22u);
    ASSERT_EQ(rec.outmsg_cnt, tx == &entry ? 2 : 0);
    vm::Dictionary outputs(rec.r1.out_msgs, 15);
    std::uint64_t count = 0;
    ASSERT_TRUE(outputs.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr, int width) {
      block::gen::CommonMsgInfo::Record_int_msg_info out;
      block::gen::MsgAddressInt::Record_addr_std src;
      block::CurrencyCollection payment, with_fee, next;
      if (width != 15 || value->size_ext() != 0x10000 || !tlb::unpack_cell_inexact(value->prefetch_ref(), out) ||
          !tlb::csr_unpack(out.src, src) || !payment.unpack(out.value)) return false;
      ASSERT_TRUE(out.bounced && !out.bounce && src.address == foreign && src.workchain_id == 2);
      ASSERT_EQ(out.created_lt, count == 0 ? 22u : 23u);
      ASSERT_TRUE(payment == block::CurrencyCollection(100));
      auto remaining = block::tlb::t_Tomis.as_integer(out.fwd_fee);
      ASSERT_TRUE(remaining.not_null() && block::CurrencyCollection(remaining) == block::CurrencyCollection(150));
      if (!block::CurrencyCollection::add(payment, block::CurrencyCollection(remaining), with_fee) ||
          !block::CurrencyCollection::add(exported, with_fee, next)) return false;
      exported = std::move(next);
      auto next_count = block::participant_lt_detail::checked_add(count, 1);
      ASSERT_TRUE(next_count.is_ok());
      count = next_count.move_as_ok();
      return true;
    }));
    rows.push_back({rec.account_addr, block::CurrencyCollection(1000), imports.account_credits.at(rec.account_addr),
        after, exported, fees});
  }
  ASSERT_TRUE(block::verify_workchain_value_flow(rows, effects.native_transfers, 2, 2, 4096).is_ok());
  // Exercise the same transactions through the private multi-account overlay,
  // not just entry preparation. The actual shard is unsplit; bind that identity.
  auto overlay_identity = identity;
  overlay_identity.shard_id = tos::shardIdAll;
  auto overlay_input = block::encode_workchain_host_input(overlay_identity, admitted, access, inbox, 2, 2, 5).move_as_ok();
  const auto original_hash = old.accounts->get_hash();
  auto build_overlay = [&](td::Ref<vm::Cell> resolved_effects) {
    return block::build_workchain_disposal_allocation_overlay(old.accounts, overlay_identity, overlay_input,
        resolved_effects, a, 2, 2, 2, 4096, cfg, context);
  };
  auto overlay_result = build_overlay(effects_root);
  ASSERT_TRUE(overlay_result.is_ok());
  auto overlay = overlay_result.move_as_ok();
  ASSERT_EQ(overlay.state.end_lt, 24u);
  ASSERT_EQ(overlay.exports.size(), 2u);
  ASSERT_TRUE(overlay.imports.account_credits.at(a) == block::CurrencyCollection(800));
  vm::AugmentedDictionary next_accounts(vm::load_cell_slice_ref(overlay.state.accounts), 256, block::tlb::aug_ShardAccounts);
  const td::Bits256 untouched(number(2)->get_hash().bits());
  ASSERT_EQ(next_accounts.lookup(untouched)->prefetch_ref()->get_hash(), accounts.lookup(untouched)->prefetch_ref()->get_hash());
  block::Account next_coordinator(2, a.bits()), next_custody(2, b.bits());
  ASSERT_TRUE(next_coordinator.unpack(next_accounts.lookup(a), 10, false));
  ASSERT_TRUE(next_custody.unpack(next_accounts.lookup(b), 10, false));
  ASSERT_TRUE(next_coordinator.balance == block::CurrencyCollection(1073));
  ASSERT_TRUE(next_custody.balance == block::CurrencyCollection(1227));
  ASSERT_EQ(next_coordinator.last_trans_end_lt_, 24u);
  ASSERT_EQ(next_custody.last_trans_end_lt_, 22u);
  for (unsigned i = 0; i < 2; ++i) {
    const auto& out = overlay.exports[i];
    ASSERT_EQ(out.msg_idx, i);
    ASSERT_EQ(out.lt, i == 0 ? 22u : 23u);
    ASSERT_EQ(out.msg->get_hash(), entry.out_msgs[i]->get_hash());
    ASSERT_EQ(td::Bits256(out.trans->get_hash().bits()), next_coordinator.last_trans_hash_);
    ASSERT_TRUE(!out.metadata && out.msg_env_from_dispatch_queue.is_null());
  }
  auto replay_overlay = [&](const block::WorkchainInboundAllocationOverlay& claim) {
    return block::replay_workchain_disposal_allocation_overlay(old.accounts, overlay_identity, overlay_input,
        effects_root, a, 2, 2, 2, 4096, cfg, context, claim);
  };
  ASSERT_TRUE(replay_overlay(overlay).is_ok());
  for (unsigned fault = 0; fault < 4; ++fault) {
    LOG(INFO) << "disposal overlay replay artifact case=" << fault;
    auto wrong = overlay;
    if (fault == 0) wrong.state.accounts = old.accounts;
    if (fault == 1) wrong.state.account_blocks = number(8);
    if (fault == 2) wrong.state.end_lt = 23;
    if (fault == 3) wrong.imports.in_msg_descr = number(9);
    ASSERT_TRUE(replay_overlay(wrong).is_error());
  }
  auto cache_only = overlay;
  cache_only.exports.clear();
  cache_only.imports.account_credits.clear();
  auto derived = replay_overlay(cache_only).move_as_ok();
  ASSERT_EQ(derived.exports.size(), 2u);
  ASSERT_TRUE(derived.imports.account_credits.at(a) == block::CurrencyCollection(800));
  ASSERT_TRUE(block::build_workchain_inbound_allocation_overlay(old.accounts, overlay_identity, overlay_input,
      effects_root, a, b, 2, 2, 2, 5, 4096, cfg).is_error());
  auto split_identity = overlay_identity;
  split_identity.shard_id = UINT64_MAX;
  auto split_input = block::encode_workchain_host_input(split_identity, admitted, access, inbox, 2, 2, 5).move_as_ok();
  ASSERT_TRUE(block::build_workchain_disposal_allocation_overlay(old.accounts, split_identity, split_input,
      effects_root, a, 2, 2, 2, 4096, cfg, context).is_error());
  // The later custody participant fails only after the private entry was
  // committed. Neither dictionary updates nor output caches may be published.
  auto insolvent = effects;
  insolvent.native_transfers[1].value = block::CurrencyCollection(2000);
  auto insolvent_root = block::encode_workchain_account_effects(insolvent, 2, 2, 4096).move_as_ok();
  ASSERT_TRUE(build_overlay(insolvent_root).is_error());
  ASSERT_EQ(old.accounts->get_hash(), original_hash);
  ASSERT_TRUE(build_overlay(effects_root).move_as_ok().state.accounts->get_hash() == overlay.state.accounts->get_hash());
  struct DisposalEngine final : block::WorkchainAccountEngine {
    mutable std::uint64_t calls{0};
    mutable std::uint64_t work_calls{0};
    std::uint64_t requested_work{0};
    unsigned work_fault{0};
    mutable td::Ref<vm::Cell> inspected_candidate;
    mutable std::optional<block::InputPolicyIdentity> work_identity;
    td::Result<std::uint64_t> proof_work(
        const td::Ref<vm::Cell>& candidate, const block::InputPolicyIdentity& identity) const override {
      work_calls = block::participant_lt_detail::checked_add(work_calls, 1).move_as_ok();
      inspected_candidate = candidate;
      work_identity = identity;
      if (work_fault == 1) return td::Status::Error(
          static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid), "invalid fixture proof shape");
      if (work_fault == 2) throw vm::VmError{vm::Excno::cell_und};
      if (work_fault == 3) throw vm::CellBuilder::CellCreateError{};
      if (work_fault == 4) throw vm::CellBuilder::CellWriteError{};
      if (work_fault == 5) return td::Status::Error("invalid fixture error category");
      if (work_fault == 6) throw vm::VmVirtError{1};
      if (work_fault == 7) throw vm::VmNoGas{};
      if (work_fault == 8) throw vm::VmFatal{};
      if (work_fault == 9) throw std::bad_alloc{};
      if (work_fault == 10) throw std::length_error("injected proof preflight length");
      if (work_fault == 11) throw 17;
      if (work_fault == 12) return td::Status::Error(
          static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt), "invalid preflight source claim");
      if (work_fault == 13) return td::Status::Error(
          static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable), "declared fixture local failure");
      return requested_work;  // Fixture has no cryptographic backend.
    }
    mutable td::Ref<vm::Cell> seen;
    block::WorkchainAccountEffects effects;
    td::Result<block::WorkchainAccountEffects> execute_accounts(
        const td::Ref<vm::Cell>& input, block::WorkchainAccountReadView& view) const override {
      TRY_RESULT(next, block::participant_lt_detail::checked_add(calls, 1));
      calls = next;
      seen = input;
      for (const auto& update : effects.updates) {
        TRY_RESULT(old, view.read(update.account));
        if (old.is_null()) return td::Status::Error("missing disposal engine account");
      }
      return effects;
    }
  } engine;
  engine.effects = effects;
  const auto owned_inbox = own_native_fixture(inbox);
  auto execute_disposal = [&](const block::WorkchainHostIdentity& id,
                             const block::WorkchainDisposalEntryContext& resolved) {
    return block::execute_and_settle_workchain_disposal(engine, old.accounts, id, admitted,
        access, owned_inbox, 2, 2, 2, a, td::make_refint(0), 4096, cfg, resolved);
  };
  auto settled_result = execute_disposal(overlay_identity, context);
  ASSERT_TRUE(settled_result.is_ok());
  auto settled = settled_result.move_as_ok();
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_EQ(engine.work_calls, 0u);  // Retained prototype does not acquire the batch preflight.
  ASSERT_EQ(engine.seen->get_hash(), overlay_input->get_hash());
  ASSERT_EQ(settled.input->get_hash(), overlay_input->get_hash());
  ASSERT_EQ(settled.effects->get_hash(), effects_root->get_hash());
  ASSERT_EQ(settled.state.accounts->get_hash(), overlay.state.accounts->get_hash());
  ASSERT_EQ(settled.state.account_blocks->get_hash(), overlay.state.account_blocks->get_hash());
  ASSERT_EQ(settled.imports.in_msg_descr->get_hash(), overlay.imports.in_msg_descr->get_hash());
  ASSERT_EQ(settled.exports.size(), 2u);
  auto replay_disposal = [&](const block::WorkchainAccountSettlement& claim) {
    engine.calls = 0;
    return block::replay_workchain_disposal_settlement(engine, old.accounts, overlay_identity, admitted,
        access, owned_inbox, 2, 2, 2, a, td::make_refint(0), 4096, cfg, context, claim);
  };
  ASSERT_TRUE(replay_disposal(settled).is_ok());
  ASSERT_EQ(engine.calls, 1u);
  auto absent_cache = settled;
  absent_cache.exports.clear();
  auto rebuilt_cache = replay_disposal(absent_cache).move_as_ok();
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_EQ(rebuilt_cache.exports.size(), 2u);
  for (unsigned field = 0; field < 6; ++field) {
    LOG(INFO) << "disposal runner replay case=" << field;
    auto wrong = settled;
    if (field == 0) wrong.input = input; // Valid encoding of another identity.
    if (field == 1) wrong.effects = insolvent_root;
    if (field == 2) wrong.state.accounts = old.accounts;
    if (field == 3) wrong.state.account_blocks = number(10);
    if (field == 4) wrong.imports.in_msg_descr = number(11);
    if (field == 5) wrong.state.end_lt = 23;
    ASSERT_TRUE(replay_disposal(wrong).is_error());
    ASSERT_EQ(engine.calls, field == 0 ? 0u : 1u);
  }
  for (unsigned fault = 0; fault < 4; ++fault) {
    auto id = overlay_identity;
    auto limited = context;
    auto prices = messages;
    if (fault == 0) id.shard_id = UINT64_MAX;
    if (fault == 1) limited.custody = a;
    if (fault == 2) limited.max_inbound = 4;
    if (fault == 3) prices.global_version = 15;
    block::WorkchainDisposalEntryContext resolved{limited.custody, prices, workchains, profile,
        limited.max_inbound, limited.max_outbound};
    engine.calls = 0;
    ASSERT_TRUE(execute_disposal(id, resolved).is_error());
    ASSERT_EQ(engine.calls, 0u);
  }
  engine.calls = 0;
  ASSERT_TRUE(block::execute_and_settle_workchain_accounts(engine, old.accounts, overlay_identity, admitted,
      access, owned_inbox, 2, 2, 5, 2, b, a, td::make_refint(0), 4096, cfg, messages).is_error());
  ASSERT_EQ(engine.calls, 0u);
  ASSERT_EQ(old.accounts->get_hash(), original_hash);
  auto mismatched_prices = messages;
  // Joint preparation must retain both the payout principal isolation and the
  // coordinator's disposal outputs/fees. Neither account is committed here.
  auto joint_prices = messages;
  joint_prices.workchains = &workchains;
  joint_prices.disable_custom_fess = joint_prices.disable_anycast = joint_prices.extra_currency_v2 = true;
  joint_prices.action_fine_enabled = joint_prices.bounce_on_fail_enabled = joint_prices.message_skip_enabled = true;
  joint_prices.fwd_mc = block::MsgPrices(100, 0, 0, 0, 16384, 0);
  vm::CellBuilder payout_body;
  payout_body.store_long(6, 4).store_zeroes(2).store_long(4, 3).store_long(-1, 8).store_zeroes(256);
  ASSERT_TRUE(block::CurrencyCollection(137).store(payout_body));
  ASSERT_TRUE(block::tlb::t_Tomis.store_integer_ref(payout_body, td::make_refint(3)));
  auto request = payout_body.store_zeroes(4).store_zeroes(96).store_zeroes(2).store_bits(a.bits(), 256).finalize();
  auto joint_effects = effects;
  joint_effects.payout_request = request;
  auto joint_root = block::encode_workchain_account_effects(joint_effects, 2, 2, 4096).move_as_ok();
  auto joint_bindings = block::build_workchain_participant_records(td::Bits256(overlay_input->get_hash().bits()),
      td::Bits256(joint_root->get_hash().bits()), {a, b}, 2).move_as_ok();
  block::WorkchainDisposalEntryContext joint_context{b, joint_prices, workchains, profile, 5, 3};
  auto joint = [&](const block::WorkchainDisposalEntryContext& resolved, std::uint64_t fee_budget) {
    return Transaction::build_workchain_payout_pair(custody, coordinator, joint_bindings[1], joint_bindings[0],
        number(322), number(321), request, 21, 10, td::make_refint(fee_budget), 2, 4096,
        cfg, joint_prices, overlay_input, joint_root, &resolved);
  };
  auto joint_result = joint(joint_context, 100);
  if (joint_result.is_error()) LOG(ERROR) << "joint payout preparation failed: " << joint_result.error();
  ASSERT_TRUE(joint_result.is_ok());
  const auto& pair = joint_result.ok().transactions;
  ASSERT_TRUE(pair[0]->balance == block::CurrencyCollection(1090));
  ASSERT_TRUE(pair[1]->balance == block::CurrencyCollection(973));
  ASSERT_TRUE(pair[0]->total_fees == block::CurrencyCollection(25));
  ASSERT_TRUE(pair[1]->total_fees == block::CurrencyCollection(100));
  ASSERT_EQ(pair[0]->out_msgs.size(), 1u);
  ASSERT_EQ(pair[1]->out_msgs.size(), 2u);
  ASSERT_EQ(pair[0]->end_lt, 23u);
  ASSERT_EQ(pair[1]->end_lt, 24u);
  ASSERT_TRUE(joint_result.ok().accounting.fee_funding.value == block::CurrencyCollection(100));
  for (unsigned i = 0; i < 2; ++i) {
    ASSERT_EQ(pair[1]->out_msgs[i]->get_hash(), entry.out_msgs[i]->get_hash());
  }
  engine.effects = joint_effects;
  engine.calls = 0;
  auto joint_settled_result = block::execute_and_settle_workchain_disposal(engine, old.accounts,
      overlay_identity, admitted, access, owned_inbox, 2, 2, 2, a, td::make_refint(100), 4096, cfg, joint_context);
  if (joint_settled_result.is_error()) LOG(ERROR) << "joint overlay failed: " << joint_settled_result.error();
  ASSERT_TRUE(joint_settled_result.is_ok());
  auto joint_settled = joint_settled_result.move_as_ok();
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_EQ(joint_settled.exports.size(), 3u);
  ASSERT_EQ(joint_settled.state.end_lt, 24u);
  ASSERT_EQ(joint_settled.message->get_hash(), pair[0]->out_msgs[0]->get_hash());
  {
    // Aggregate user fees coexist with payout forwarding and disposal fees.
    // The three charges have different funders and must never overwrite one
    // another. All final balances below are decoded from Native artifacts.
    auto charged_effects = joint_effects;
    charged_effects.fees = block::WorkchainFeeSettlement{b, a,
        td::make_refint(17), td::make_refint(23), td::make_refint(5)};
    // Inspect the prepared pair before the enclosing overlay's conservation
    // check can reject it. This distinguishes fee preservation from a later
    // generic rejection of inconsistent value flow.
    auto charged_root = block::encode_workchain_account_effects(charged_effects, 2, 3, 4096).move_as_ok();
    auto charged_bindings = block::build_workchain_participant_records(
        td::Bits256(overlay_input->get_hash().bits()), td::Bits256(charged_root->get_hash().bits()),
        {a, b}, 2).move_as_ok();
    auto charged_pair_result = Transaction::build_workchain_payout_pair(custody, coordinator,
        charged_bindings[1], charged_bindings[0], number(322), number(321), request, 21, 10,
        td::make_refint(100), 3, 4096, cfg, joint_prices, overlay_input, charged_root, &joint_context);
    if (charged_pair_result.is_error()) LOG(ERROR) << charged_pair_result.error();
    ASSERT_TRUE(charged_pair_result.is_ok());
    const auto& charged_pair = charged_pair_result.ok().transactions;
    ASSERT_TRUE(charged_pair[0]->balance == block::CurrencyCollection(1045));
    ASSERT_TRUE(charged_pair[1]->balance == block::CurrencyCollection(990));
    ASSERT_TRUE(charged_pair[0]->total_fees == block::CurrencyCollection(53));
    ASSERT_TRUE(charged_pair[1]->total_fees == block::CurrencyCollection(100));
    ASSERT_EQ(charged_pair[0]->out_msgs.size(), 1u);
    ASSERT_EQ(charged_pair[1]->out_msgs.size(), 2u);
    {
      // Fees alone fit (1227 - 1100 = 127), but the unchanged payout needs
      // another 137. Reject the pair, rather than return the fee-only prefix.
      // Observe this before calling the enclosing overlay.
      auto underfunded = charged_effects;
      underfunded.fees->compute_fee = td::make_refint(1078);
      auto underfunded_root = block::encode_workchain_account_effects(underfunded, 2, 3, 4096).move_as_ok();
      auto underfunded_bindings = block::build_workchain_participant_records(
          td::Bits256(overlay_input->get_hash().bits()), td::Bits256(underfunded_root->get_hash().bits()),
          {a, b}, 2).move_as_ok();
      Transaction fee_only(custody, Transaction::tr_workchain_batch, 21, 10);
      ASSERT_TRUE(fee_only.prepare_workchain_import_participant(underfunded_bindings[1], overlay_input,
          underfunded_root, number(322), cfg, 3, 4096).is_ok());
      ASSERT_TRUE(fee_only.balance == block::CurrencyCollection(127));
      ASSERT_TRUE(fee_only.total_fees == block::CurrencyCollection(1083));
      ASSERT_EQ(fee_only.out_msgs.size(), 0u);
      auto insufficient_pair = Transaction::build_workchain_payout_pair(custody, coordinator,
          underfunded_bindings[1], underfunded_bindings[0], number(322), number(321), request, 21, 10,
          td::make_refint(100), 3, 4096, cfg, joint_prices, overlay_input, underfunded_root, &joint_context);
      ASSERT_TRUE(insufficient_pair.is_error());
      engine.effects = underfunded;
      engine.calls = 0;
      auto insufficient_batch = block::execute_and_settle_workchain_disposal(engine, old.accounts,
          overlay_identity, admitted, access, owned_inbox, 2, 2, 3, a, td::make_refint(100),
          4096, cfg, joint_context);
      ASSERT_TRUE(insufficient_batch.is_error());
      ASSERT_EQ(engine.calls, 1u);
      // This also exercises the enclosing rejection after one engine call;
      // the isolated mutation witness above concerns the direct pair only.
      // Original accounts are const inputs and finalized cells are immutable:
      // their unchanged bytes would not be a live rollback/publication test.
    }
    engine.effects = charged_effects;
    engine.calls = 0;
    auto charged_result = block::execute_and_settle_workchain_disposal(engine, old.accounts,
        overlay_identity, admitted, access, owned_inbox, 2, 2, 3, a, td::make_refint(100), 4096, cfg, joint_context);
    if (charged_result.is_error()) LOG(ERROR) << charged_result.error();
    ASSERT_TRUE(charged_result.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    auto charged = charged_result.move_as_ok();
    ASSERT_EQ(charged.exports.size(), 3u);
    vm::AugmentedDictionary states(vm::load_cell_slice_ref(charged.state.accounts), 256, block::tlb::aug_ShardAccounts);
    vm::AugmentedDictionary account_blocks(vm::load_cell_slice_ref(charged.state.account_blocks),
        256, block::tlb::aug_ShardAccountBlocks);
    for (const auto& key : {a, b}) {
      block::Account account(2, key.bits());
      ASSERT_TRUE(account.unpack(states.lookup(key), 10, false));
      ASSERT_TRUE(account.balance == block::CurrencyCollection(key == b ? 1045 : 990));
      block::gen::AccountBlock::Record ab;
      ASSERT_TRUE(tlb::unpack_cell(vm::CellBuilder().append_cellslice(*account_blocks.lookup(key)).finalize(), ab));
      vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
      block::gen::Transaction::Record tx;
      ASSERT_TRUE(tlb::unpack_cell(txs.lookup_ref(td::BitArray<64>(account.last_trans_lt_)), tx));
      block::CurrencyCollection fees;
      ASSERT_TRUE(fees.unpack(tx.total_fees));
      ASSERT_TRUE(fees == block::CurrencyCollection(key == b ? 53 : 100));
      ASSERT_EQ(tx.outmsg_cnt, key == b ? 1 : 2);
    }
    engine.calls = 0;
    auto charged_replay = block::replay_workchain_disposal_settlement(engine, old.accounts,
        overlay_identity, admitted, access, owned_inbox, 2, 2, 3, a, td::make_refint(100), 4096,
        cfg, joint_context, charged);
    ASSERT_TRUE(charged_replay.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_EQ(charged_replay.ok().state.accounts->get_hash(), charged.state.accounts->get_hash());
    ASSERT_EQ(charged_replay.ok().state.account_blocks->get_hash(), charged.state.account_blocks->get_hash());
    engine.calls = 0;
    ASSERT_TRUE(block::execute_and_settle_workchain_disposal(engine, old.accounts,
        overlay_identity, admitted, access, owned_inbox, 2, 2, 2, a, td::make_refint(100),
        4096, cfg, joint_context).is_error());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_EQ(old.accounts->get_hash(), original_hash);
    engine.effects = joint_effects;
  }
  for (const auto& output : joint_settled.exports) {
    bool found = false;
    for (const auto& transaction : pair) {
      for (const auto& expected : transaction->out_msgs) {
        if (output.msg->get_hash() == expected->get_hash()) {
          ASSERT_EQ(output.trans->get_hash(), transaction->root->get_hash());
          found = true;
        }
      }
    }
    ASSERT_TRUE(found);
  }
  engine.calls = 0;
  auto joint_claim = joint_settled;
  joint_claim.exports.clear();
  auto joint_replay = block::replay_workchain_disposal_settlement(engine, old.accounts, overlay_identity,
      admitted, access, owned_inbox, 2, 2, 2, a, td::make_refint(100), 4096, cfg, joint_context, joint_claim);
  ASSERT_TRUE(joint_replay.is_ok());
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_EQ(joint_replay.ok().exports.size(), 3u);
  {
    // The legacy permit has no effects budget. Preserve its opaque receipt
    // handling: wrapping identical content must add no acquisition or alter
    // the effects, account or transaction bytes.
    auto saved_effects = engine.effects;
    engine.effects.receipts = number(98765);
    auto plain = block::execute_and_settle_workchain_disposal(engine, old.accounts,
        overlay_identity, admitted, access, owned_inbox, 2, 2, 2, a,
        td::make_refint(100), 4096, cfg, joint_context);
    ASSERT_TRUE(plain.is_ok());
    unsigned receipt_loads = 0;
    engine.effects.receipts = td::Ref<PreflightObservedCell>{
        true, engine.effects.receipts, &receipt_loads, true};
    engine.calls = 0;
    auto opaque = block::execute_and_settle_workchain_disposal(engine, old.accounts,
        overlay_identity, admitted, access, owned_inbox, 2, 2, 2, a,
        td::make_refint(100), 4096, cfg, joint_context);
    ASSERT_EQ(receipt_loads, 0u);
    ASSERT_TRUE(opaque.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_EQ(opaque.ok().effects->get_hash(), plain.ok().effects->get_hash());
    ASSERT_EQ(opaque.ok().state.accounts->get_hash(), plain.ok().state.accounts->get_hash());
    ASSERT_EQ(opaque.ok().state.account_blocks->get_hash(), plain.ok().state.account_blocks->get_hash());
    engine.effects = std::move(saved_effects);
  }
  {
    // The mixed payout/disposal path must consume the complete admission cut,
    // not silently return to singleton permits or caller-supplied state limits.
    auto complete_identity = batch_test_identity(number(1));
    complete_identity.gen_utime = overlay_identity.gen_utime;
    complete_identity.host_after_lt = overlay_identity.host_after_lt;
    auto declaration_root = block::encode_workchain_account_declarations(access, 2, 2).move_as_ok();
    auto initial_policy = inbox_test_policy(5, {1000, 1000000, 8}, 2, 2);
    auto initial_resources = initial_policy.resources();
    // Explicit fixture budget for complete Native records, not a host default.
    initial_resources.work_output.max_output_bits = 65536;
    auto resolved_initial = block::ResolvedBatchInputPolicy::from_resolved_fields(
        initial_resources, initial_policy.identity());
    ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved_initial));
    auto policy = std::get<block::ResolvedBatchInputPolicy>(resolved_initial);
    block::BatchInputAdmissionSession session(policy, candidate, declaration_root, complete_identity, inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(session.evaluate()));
    const auto& full = std::get<block::AdmittedBatchInput>(session.evaluate());
    // Exercise the very first complete settlement with an unavailable,
    // untouched account, so an erroneous whole-state output traversal cannot
    // fail an earlier warm fixture and mask this control.
    vm::AugmentedDictionary sparse(vm::load_cell_slice_ref(old.accounts), 256, block::tlb::aug_ShardAccounts);
    const td::Bits256 untouched(number(2)->get_hash().bits());
    auto untouched_entry = sparse.lookup(untouched);
    ASSERT_TRUE(untouched_entry.not_null() && untouched_entry->size_ext() == 0x10140);
    unsigned untouched_loads = 0;
    td::Ref<PreflightObservedCell> unavailable_untouched{
        true, untouched_entry->prefetch_ref(), &untouched_loads};
    vm::CellSlice rest{*untouched_entry};
    rest.fetch_ref();
    vm::CellBuilder replacement;
    replacement.append_cellslice(rest).store_ref(unavailable_untouched);
    ASSERT_TRUE(sparse.set_builder(untouched, replacement, vm::Dictionary::SetMode::Replace));
    auto cold_accounts = sparse.get_wrapped_dict_root();
    ASSERT_EQ(cold_accounts->get_hash(), old.accounts->get_hash());
    // Augmentation was built while available; the source becomes cold only
    // after fixture construction, not during its own balance decoding.
    unavailable_untouched->set_unavailable(true);
    untouched_loads = 0;
    unsigned source_loads = 0;
    td::Ref<vm::Cell> observed{td::Ref<StateReadCallbackCell>{true, cold_accounts, [&] { ++source_loads; }}};
    // The complete host, not the settlement result, owns proof tracking across
    // account execution and outbound construction. Reuse the same immutable
    // old-account source across the independent policy-boundary attempts.
    auto settlement_tree = std::make_shared<vm::CellUsageTree>();
    observed = vm::UsageCell::create(observed, settlement_tree->root_ptr());
    engine.calls = 0;
    auto complete_result = block::execute_and_settle_workchain_disposal(engine, observed,
        complete_identity, full, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context);
    LOG(INFO) << "unavailable untouched-account settlement";
    if (complete_result.is_error()) LOG(ERROR) << complete_result.error();
    ASSERT_TRUE(complete_result.is_ok());
    ASSERT_EQ(untouched_loads, 0u);
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_TRUE(source_loads > 0);
    ASSERT_EQ(engine.seen->get_hash(), full.root()->get_hash());
    ASSERT_EQ(complete_result.ok().exports.size(), 3u);
    {
      const auto saved = engine.effects;
      auto with_fees = saved;
      with_fees.fees = block::WorkchainFeeSettlement{b, a,
          td::make_refint(17), td::make_refint(23), td::make_refint(5)};
      auto fee_root = block::encode_workchain_account_effects(with_fees, 2, 3, 4096).move_as_ok();
      for (std::uint32_t version : {2u, 3u}) {
        auto resources = policy.resources();
        auto policy_identity = policy.identity();
        auto host_identity = complete_identity;
        resources.admission_version = policy_identity.admission_version = host_identity.admission_version = version;
        auto resolved = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, policy_identity);
        ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved));
        block::BatchInputAdmissionSession fee_session(std::get<block::ResolvedBatchInputPolicy>(resolved),
            candidate, declaration_root, host_identity, inbox);
        ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(fee_session.evaluate()));
        const auto& fee_input = std::get<block::AdmittedBatchInput>(fee_session.evaluate());
        engine.effects = with_fees;
        engine.calls = engine.work_calls = 0;
        auto built = block::execute_and_settle_workchain_disposal(engine, old.accounts,
            host_identity, fee_input, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context);
        ASSERT_EQ(engine.calls, 1u);
        ASSERT_EQ(engine.work_calls, 1u);
        if (version == 2) {
          ASSERT_TRUE(built.is_error());
          ASSERT_EQ(built.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
          auto claim = complete_result.ok();
          claim.input = fee_input.root();
          claim.effects = fee_root;
          // The engine emits no fees here: removing the claim guard must not
          // be hidden by the independently tested engine-output guard.
          engine.effects = saved;
          for (bool disposal : {false, true}) {
            engine.calls = engine.work_calls = 0;
            auto replay = disposal
                ? block::replay_workchain_disposal_settlement(engine, old.accounts, host_identity,
                    fee_input, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context, claim)
                : block::replay_workchain_account_settlement(engine, old.accounts, host_identity,
                    fee_input, owned_inbox, b, a, td::make_refint(100), 4096, cfg, joint_prices, claim);
            ASSERT_TRUE(replay.is_error());
            ASSERT_EQ(replay.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
            ASSERT_EQ(engine.calls, 0u);
            ASSERT_EQ(engine.work_calls, 1u);
          }
        } else {
          if (built.is_error()) LOG(ERROR) << built.error();
          ASSERT_TRUE(built.is_ok());
          engine.calls = engine.work_calls = 0;
          auto replay = block::replay_workchain_disposal_settlement(engine, old.accounts, host_identity,
              fee_input, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context, built.ok());
          ASSERT_TRUE(replay.is_ok());
          ASSERT_EQ(engine.calls, 1u);
          ASSERT_EQ(engine.work_calls, 1u);
          ASSERT_EQ(replay.ok().effects->get_hash(), built.ok().effects->get_hash());
          ASSERT_EQ(replay.ok().state.accounts->get_hash(), built.ok().state.accounts->get_hash());
        }
      }
      engine.effects = saved;
    }
    // Independent full-record closure oracle; do not include the whole
    // ShardAccounts dictionary (its untouched accounts are not new output).
    vm::CellStorageStat output_size;
    vm::AugmentedDictionary new_accounts(vm::load_cell_slice_ref(complete_result.ok().state.accounts),
        256, block::tlb::aug_ShardAccounts);
    for (const auto& key : access.writes) {
      auto value = new_accounts.lookup(key);
      block::tlb::ShardAccount::Record record;
      ASSERT_TRUE(value.not_null() && record.unpack(value));
      ASSERT_TRUE(output_size.add_used_storage(record.account).is_ok());
    }
    ASSERT_TRUE(output_size.add_used_storage(complete_result.ok().state.account_blocks).is_ok());
    ASSERT_TRUE(output_size.add_used_storage(complete_result.ok().imports.in_msg_descr).is_ok());
    for (const auto& output : complete_result.ok().exports) {
      ASSERT_TRUE(output_size.add_used_storage(output.msg).is_ok());
      ASSERT_TRUE(output_size.add_used_storage(output.trans).is_ok());
    }
    LOG(INFO) << "complete record output: cells=" << output_size.cells << " bits=" << output_size.bits;
    ASSERT_TRUE(output_size.cells > 1 && output_size.bits > 1);
    td::uint64 settlement_state_loads = 0;
    auto with_output_limits = [&](std::uint64_t cells, std::uint64_t bits,
        std::optional<block::gen::UnoV2ResourceState::Record> account_bounds = std::nullopt,
        std::optional<std::uint64_t> proof_units = std::nullopt) {
      auto resources = policy.resources();
      resources.work_output.max_output_cells = cells;
      resources.work_output.max_output_bits = bits;
      if (proof_units) resources.work_output.max_proof_units = *proof_units;
      if (account_bounds) resources.state = *account_bounds;
      auto resolved = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, policy.identity());
      ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved));
      block::BatchInputAdmissionSession bounded(std::get<block::ResolvedBatchInputPolicy>(resolved),
          candidate, declaration_root, complete_identity, inbox);
      ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(bounded.evaluate()));
      settlement_state_loads = 0;
      td::Ref<vm::Cell> observed_accounts{td::Ref<StateReadCallbackCell>{true, old.accounts, [&] {
        settlement_state_loads = block::participant_lt_detail::checked_add(settlement_state_loads, 1).move_as_ok();
      }}};
      return block::execute_and_settle_workchain_disposal(engine,
          vm::UsageCell::create(observed_accounts, settlement_tree->root_ptr()), complete_identity,
          std::get<block::AdmittedBatchInput>(bounded.evaluate()), owned_inbox, a,
          td::make_refint(100), 4096, cfg, joint_context);
    };
    auto exact_output = with_output_limits(output_size.cells, output_size.bits);
    ASSERT_TRUE(exact_output.is_ok());
    ASSERT_EQ(exact_output.ok().state.accounts->get_hash(), complete_result.ok().state.accounts->get_hash());
    ASSERT_TRUE(exact_output.ok().output_admission != nullptr);
    ASSERT_EQ(exact_output.ok().output_admission->usage().cells, output_size.cells);
    ASSERT_EQ(exact_output.ok().output_admission->usage().bits, output_size.bits);
    {
      for (std::uint64_t limit : {0u, 1u}) {
        engine.requested_work = limit;
        engine.calls = engine.work_calls = 0;
        auto exact = with_output_limits(256, 65536, std::nullopt, limit);
        ASSERT_TRUE(exact.is_ok());
        ASSERT_TRUE(settlement_state_loads > 0);
        ASSERT_EQ(engine.calls, 1u);
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_EQ(engine.inspected_candidate->get_hash(), candidate->get_hash());
        ASSERT_TRUE(engine.work_identity.has_value());
        ASSERT_EQ(engine.work_identity->configuration_hash, policy.identity().configuration_hash);
        ASSERT_EQ(engine.work_identity->admission_version, policy.identity().admission_version);
        ASSERT_EQ(engine.work_identity->engine_selector, policy.identity().engine_selector);
        ASSERT_EQ(engine.work_identity->vm_mode, policy.identity().vm_mode);
        ASSERT_EQ(engine.work_identity->descriptor_version, policy.identity().descriptor_version);
        ASSERT_EQ(engine.work_identity->extended, policy.identity().extended);
        ASSERT_EQ(exact.ok().state.accounts->get_hash(), complete_result.ok().state.accounts->get_hash());
        engine.requested_work = block::participant_lt_detail::checked_add(limit, 1).move_as_ok();
        engine.calls = engine.work_calls = 0;
        auto excess = with_output_limits(256, 65536, std::nullopt, limit);
        ASSERT_TRUE(excess.is_error());
        ASSERT_EQ(excess.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
        ASSERT_EQ(engine.calls, 0u);
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_EQ(settlement_state_loads, 0u);
        auto limited_resources = policy.resources();
        limited_resources.work_output.max_proof_units = limit;
        auto limited_policy = block::ResolvedBatchInputPolicy::from_resolved_fields(
            limited_resources, policy.identity());
        ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(limited_policy));
        block::BatchInputAdmissionSession limited_session(
            std::get<block::ResolvedBatchInputPolicy>(limited_policy),
            candidate, declaration_root, complete_identity, inbox);
        ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(limited_session.evaluate()));
        td::uint64 state_loads = 0;
        td::Ref<vm::Cell> observed_state{td::Ref<StateReadCallbackCell>{true, old.accounts, [&] {
          state_loads = block::participant_lt_detail::checked_add(state_loads, 1).move_as_ok();
        }}};
        engine.calls = engine.work_calls = 0;
        auto early = block::execute_workchain_account_engine(engine, observed_state,
            std::get<block::AdmittedBatchInput>(limited_session.evaluate()));
        ASSERT_TRUE(early.is_error());
        ASSERT_EQ(early.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
        ASSERT_EQ(state_loads, 0u);
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_EQ(engine.calls, 0u);
        engine.requested_work = limit;
        auto allowed = block::execute_workchain_account_engine(engine, observed_state,
            std::get<block::AdmittedBatchInput>(limited_session.evaluate()));
        ASSERT_TRUE(allowed.is_ok());
        ASSERT_TRUE(state_loads > 0);
      }
      engine.requested_work = 0;
      {
        unsigned source_loads = 0;
        td::Ref<PreflightObservedCell> source{true, candidate, &source_loads};
        block::BatchInputAdmissionSession owned(policy, source, declaration_root, complete_identity, inbox);
        ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(owned.evaluate()));
        ASSERT_TRUE(source_loads > 0);
        source->set_unavailable(true);
        source_loads = 0;
        const auto& admitted_candidate = std::get<block::AdmittedBatchInput>(owned.evaluate()).candidate();
        ASSERT_TRUE(admitted_candidate->load_cell().is_ok());
        ASSERT_EQ(admitted_candidate->get_hash(), candidate->get_hash());
        ASSERT_EQ(source_loads, 0u);
      }
      {
        auto invalid_state = policy.resources().state;
        invalid_state.max_account_depth = 70000;
        engine.requested_work = 1;
        engine.calls = engine.work_calls = 0;
        auto invalid = with_output_limits(256, 65536, invalid_state, 0);
        ASSERT_TRUE(invalid.is_error());
        ASSERT_EQ(invalid.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        ASSERT_EQ(engine.work_calls, 0u);
        ASSERT_EQ(engine.calls, 0u);
        engine.requested_work = 0;
      }
      for (unsigned fault = 1; fault <= 13; ++fault) {
        engine.work_fault = fault;
        engine.calls = engine.work_calls = 0;
        auto refused = with_output_limits(256, 65536, std::nullopt, 0);
        ASSERT_TRUE(refused.is_error());
        ASSERT_EQ(refused.error().code(), static_cast<int>(fault == 1
            ? block::WorkchainExecutionFailure::CandidateInvalid : block::WorkchainExecutionFailure::LocalUnavailable));
        ASSERT_EQ(engine.calls, 0u);
        ASSERT_EQ(engine.work_calls, 1u);
        block::BatchInputAdmissionSession direct_session(policy, candidate, declaration_root, complete_identity, inbox);
        ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(direct_session.evaluate()));
        engine.calls = engine.work_calls = 0;
        auto direct = block::execute_workchain_account_engine(engine, old.accounts,
            std::get<block::AdmittedBatchInput>(direct_session.evaluate()));
        ASSERT_TRUE(direct.is_error());
        ASSERT_EQ(direct.error().code(), static_cast<int>(fault == 1
            ? block::WorkchainExecutionFailure::CandidateInvalid : block::WorkchainExecutionFailure::LocalUnavailable));
        ASSERT_EQ(engine.calls, 0u);
        ASSERT_EQ(engine.work_calls, 1u);
      }
      engine.work_fault = 0;
      {
        // Positive liveness and the null-context ordering control use the same
        // admitted input and engine. A later state-read failure cannot satisfy
        // the zero-work assertion after an earlier proof inspection.
        engine.calls = engine.work_calls = 0;
        auto direct_valid = block::execute_workchain_account_engine(engine, old.accounts, full);
        ASSERT_TRUE(direct_valid.is_ok());
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_EQ(engine.calls, 1u);
        engine.calls = engine.work_calls = 0;
        auto direct_missing = block::execute_workchain_account_engine(engine, {}, full);
        ASSERT_TRUE(direct_missing.is_error());
        ASSERT_EQ(engine.work_calls, 0u);
        ASSERT_EQ(engine.calls, 0u);
        ASSERT_EQ(direct_missing.error().code(),
                  static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      }
      {
        // Preflight must precede even commitment hashing, and the succeeding
        // replay must not re-inspect after crossing into semantic processing.
        td::uint64 commitment_hashes = 0;
        auto claimed = complete_result.ok();
        claimed.input = td::Ref<StateReadCallbackCell>{true, claimed.input, [] {}, [&] {
          commitment_hashes = block::participant_lt_detail::checked_add(commitment_hashes, 1).move_as_ok();
        }};
        engine.work_fault = 13;
        engine.calls = engine.work_calls = 0;
        auto refused = block::replay_workchain_disposal_settlement(engine, old.accounts, complete_identity,
            full, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context, claimed);
        ASSERT_TRUE(refused.is_error());
        ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        ASSERT_EQ(commitment_hashes, 0u);
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_EQ(engine.calls, 0u);
        engine.work_fault = 0;
        engine.calls = engine.work_calls = 0;
        auto replayed = block::replay_workchain_disposal_settlement(engine, old.accounts, complete_identity,
            full, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context, claimed);
        ASSERT_TRUE(replayed.is_ok());
        ASSERT_TRUE(commitment_hashes > 0);
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_EQ(engine.calls, 1u);
        ASSERT_EQ(replayed.ok().state.accounts->get_hash(), complete_result.ok().state.accounts->get_hash());

        commitment_hashes = 0;
        engine.work_fault = 13;
        engine.calls = engine.work_calls = 0;
        auto account_refused = block::replay_workchain_account_settlement(engine, old.accounts, complete_identity,
            full, owned_inbox, joint_context.custody, a, td::make_refint(100), 4096, cfg,
            joint_context.messages, claimed);
        ASSERT_EQ(commitment_hashes, 0u);
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_TRUE(account_refused.is_error());
        ASSERT_EQ(account_refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        engine.work_fault = 0;
        engine.calls = engine.work_calls = 0;
        auto account_later = block::replay_workchain_account_settlement(engine, old.accounts, complete_identity,
            full, owned_inbox, joint_context.custody, a, td::make_refint(100), 4096, cfg,
            joint_context.messages, claimed);
        // This fixture includes foreign destinations: the strict inbox path
        // rejects them, but only after passing the commitment boundary.
        ASSERT_TRUE(account_later.is_error());
        ASSERT_TRUE(commitment_hashes > 0);
        ASSERT_EQ(engine.work_calls, 1u);
        ASSERT_EQ(engine.calls, 0u);

        // Owned but malformed Native envelope, not a candidate wire error.
        // It distinguishes semantic inbox processing from shape admission:
        // preflight failure wins; with preflight allowed the parser refuses.
        auto malformed_inbox = own_native_fixture({number(999)});
        for (unsigned entry = 0; entry < 4; ++entry) {
          auto invoke = [&]() -> td::Result<block::WorkchainAccountSettlement> {
            if (entry == 0) return block::execute_and_settle_workchain_accounts(engine, old.accounts,
                complete_identity, full, malformed_inbox, joint_context.custody, a, td::make_refint(100),
                4096, cfg, joint_context.messages);
            if (entry == 1) return block::execute_and_settle_workchain_disposal(engine, old.accounts,
                complete_identity, full, malformed_inbox, a, td::make_refint(100), 4096, cfg, joint_context);
            if (entry == 2) return block::replay_workchain_account_settlement(engine, old.accounts,
                complete_identity, full, malformed_inbox, joint_context.custody, a, td::make_refint(100),
                4096, cfg, joint_context.messages, complete_result.ok());
            return block::replay_workchain_disposal_settlement(engine, old.accounts,
                complete_identity, full, malformed_inbox, a, td::make_refint(100), 4096, cfg,
                joint_context, complete_result.ok());
          };
          engine.work_fault = 13;
          engine.calls = engine.work_calls = 0;
          auto before_parser = invoke();
          ASSERT_EQ(engine.work_calls, 1u);
          ASSERT_EQ(engine.calls, 0u);
          ASSERT_TRUE(before_parser.is_error());
          ASSERT_EQ(before_parser.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
          engine.work_fault = 0;
          engine.calls = engine.work_calls = 0;
          auto parser_refused = invoke();
          ASSERT_EQ(engine.work_calls, 1u);
          ASSERT_EQ(engine.calls, 0u);
          ASSERT_TRUE(parser_refused.is_error());
        }

        for (unsigned fault = 0; fault < 6; ++fault) {
          auto old_source = old.accounts;
          auto local_identity = complete_identity;
          auto local_context = joint_context;
          auto local_cfg = cfg;
          int currency_cells = 4096;
          if (fault == 0) old_source.clear();
          if (fault == 1) currency_cells = 0;
          if (fault == 2) local_context.max_inbound = 0;
          if (fault == 3) local_identity.shard_id = 0;
          if (fault == 4) local_context.custody = a;
          if (fault == 5) local_cfg.global_version = 0;
          engine.calls = engine.work_calls = 0;
          auto invalid_context = block::execute_and_settle_workchain_disposal(engine, old_source,
              local_identity, full, owned_inbox, a, td::make_refint(100), currency_cells, local_cfg, local_context);
          ASSERT_EQ(engine.work_calls, 0u);
          ASSERT_EQ(engine.calls, 0u);
          ASSERT_TRUE(invalid_context.is_error());
          ASSERT_EQ(invalid_context.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        }

        // Admission cannot be moved from one registered executor to another.
        auto inspected = block::ProofAdmittedBatchInput::admit(engine, full);
        ASSERT_TRUE(inspected.is_ok());
        DisposalEngine other = engine;
        other.calls = other.work_calls = 0;
        td::uint64 reads = 0, metadata_reads = 0;
        td::Ref<vm::Cell> observed_old{td::Ref<StateReadCallbackCell>{true, old.accounts, [&] {
          reads = block::participant_lt_detail::checked_add(reads, 1).move_as_ok();
        }, [] {}, [&] {
          metadata_reads = block::participant_lt_detail::checked_add(metadata_reads, 1).move_as_ok();
        }}};
        auto wrong_engine = block::execute_and_settle_workchain_disposal(other, observed_old, complete_identity,
            inspected.ok(), owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context);
        ASSERT_TRUE(wrong_engine.is_error());
        ASSERT_EQ(wrong_engine.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        ASSERT_EQ(reads, 0u);
        ASSERT_EQ(metadata_reads, 0u);
        ASSERT_EQ(other.calls, 0u);
        ASSERT_EQ(other.work_calls, 0u);
        auto direct_wrong_engine = block::account_engine_detail::execute(other, observed_old, inspected.ok(),
            access, full.policy().resources().input.max_reads, full.policy().resources().input.max_writes);
        ASSERT_EQ(reads, 0u);
        ASSERT_EQ(other.calls, 0u);
        ASSERT_TRUE(direct_wrong_engine.is_error());
        ASSERT_EQ(direct_wrong_engine.error().code(),
            static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        auto matching = block::execute_and_settle_workchain_disposal(engine, observed_old, complete_identity,
            inspected.ok(), owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context);
        ASSERT_TRUE(matching.is_ok());
        ASSERT_TRUE(reads > 0);
        ASSERT_TRUE(metadata_reads > 0);
      }
    }
    {
      block::tlb::Aug_OutMsgDescr augmentation(16);
      vm::AugmentedDictionary descriptors(256, augmentation);
      vm::AugmentedDictionary outgoing(352, block::tlb::aug_OutMsgQueue);
      vm::AugmentedDictionary dispatch(256, block::tlb::aug_DispatchQueue);
      block::WorkchainOutboundQueueRoots empty{descriptors.get_wrapped_dict_root(),
          outgoing.get_wrapped_dict_root(), dispatch.get_wrapped_dict_root()};
      block::WorkchainOutboundQueuePolicy queue_policy{{2, tos::shardIdAll}, 10, 16, false, true, 3};
      std::vector<bool> defer(3, false);
      auto queued = block::continue_workchain_outbound_queues(empty, complete_result.ok(), defer, {}, queue_policy);
      if (queued.is_error()) LOG(ERROR) << queued.error();
      ASSERT_TRUE(queued.is_ok());
      auto total_size = output_size;
      ASSERT_TRUE(total_size.add_used_storage(queued.ok().roots.descriptors).is_ok());
      ASSERT_TRUE(total_size.cells > output_size.cells && total_size.bits > output_size.bits);
      ASSERT_EQ(queued.ok().output_admission->usage().cells, total_size.cells);
      ASSERT_EQ(queued.ok().output_admission->usage().bits, total_size.bits);
      ASSERT_EQ(complete_result.ok().output_admission->usage().cells, output_size.cells);
      auto exact = with_output_limits(total_size.cells, total_size.bits);
      ASSERT_TRUE(exact.is_ok());
      auto exact_queue = block::continue_workchain_outbound_queues(empty, exact.ok(), defer, {}, queue_policy);
      ASSERT_TRUE(exact_queue.is_ok());
      ASSERT_EQ(exact_queue.ok().roots.descriptors->get_hash(), queued.ok().roots.descriptors->get_hash());
      for (bool cells : {false, true}) {
        // Both totals exceed the original settlement totals, so subtraction
        // is safe and the earlier stage remains admissible.
        auto short_budget = with_output_limits(total_size.cells - (cells ? 1 : 0),
                                               total_size.bits - (cells ? 0 : 1));
        ASSERT_TRUE(short_budget.is_ok());
        auto rejected = block::continue_workchain_outbound_queues(empty, short_budget.ok(), defer, {}, queue_policy);
        ASSERT_TRUE(rejected.is_error());
        ASSERT_EQ(rejected.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
        ASSERT_EQ(short_budget.ok().output_admission->usage().cells, output_size.cells);
      }
      auto missing = complete_result.ok();
      missing.output_admission.reset();
      auto rejected = block::continue_workchain_outbound_queues(empty, missing, defer, {}, queue_policy);
      ASSERT_TRUE(rejected.is_error());
      ASSERT_EQ(rejected.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      auto limited = queue_policy;
      limited.max_outputs = 2;
      for (const auto& failure : {
          block::continue_workchain_outbound_queues(empty, complete_result.ok(), defer, {}, limited),
          block::continue_workchain_outbound_queues(empty, complete_result.ok(), {}, {}, queue_policy),
          block::continue_workchain_outbound_queues(empty, complete_result.ok(), defer, {foreign}, queue_policy)}) {
        ASSERT_TRUE(failure.is_error());
        ASSERT_EQ(failure.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
      }
      std::vector<block::WorkchainQueuedOutput> independently_queued;
      auto deferred_choices = defer;
      for (std::size_t i = 0; i < complete_result.ok().exports.size(); ++i) {
        block::gen::CommonMsgInfo::Record_int_msg_info info;
        block::gen::MsgAddressInt::Record_addr_std source;
        ASSERT_TRUE(tlb::unpack_cell_inexact(complete_result.ok().exports[i].msg, info));
        ASSERT_TRUE(tlb::csr_unpack(info.src, source));
        deferred_choices[i] = td::Bits256(source.address) == foreign;
        independently_queued.push_back({complete_result.ok().exports[i], deferred_choices[i]});
      }
      auto deferred = block::continue_workchain_outbound_queues(
          empty, complete_result.ok(), deferred_choices, {foreign}, queue_policy);
      ASSERT_TRUE(deferred.is_ok());
      ASSERT_EQ(deferred.ok().deferred, 2u);
      auto reference = block::build_workchain_outbound_queues(empty, independently_queued, {foreign}, queue_policy);
      ASSERT_TRUE(reference.is_ok());
      ASSERT_EQ(reference.ok().roots.descriptors->get_hash(), deferred.ok().roots.descriptors->get_hash());
      ASSERT_EQ(reference.ok().roots.outgoing->get_hash(), deferred.ok().roots.outgoing->get_hash());
      ASSERT_EQ(reference.ok().roots.dispatch->get_hash(), deferred.ok().roots.dispatch->get_hash());
      auto deferred_size = output_size;
      ASSERT_TRUE(deferred_size.add_used_storage(deferred.ok().roots.descriptors).is_ok());
      ASSERT_EQ(deferred.ok().output_admission->usage().cells, deferred_size.cells);
      ASSERT_EQ(deferred.ok().output_admission->usage().bits, deferred_size.bits);
      // Seed an earlier Native record of the same block. This rearranges a
      // local fixture, not a second engine batch or an authorization proof.
      auto seeded = block::build_workchain_outbound_queues(
          empty, {independently_queued.front()}, {foreign}, queue_policy);
      ASSERT_TRUE(seeded.is_ok());
      auto remaining = complete_result.ok();
      remaining.exports.erase(remaining.exports.begin());
      deferred_choices.erase(deferred_choices.begin());
      auto resumed = block::continue_workchain_outbound_queues(
          seeded.ok().roots, remaining, deferred_choices, {foreign}, queue_policy);
      ASSERT_TRUE(resumed.is_ok());
      ASSERT_EQ(resumed.ok().roots.descriptors->get_hash(), deferred.ok().roots.descriptors->get_hash());
      ASSERT_EQ(resumed.ok().output_admission->usage().cells, deferred_size.cells);
      ASSERT_EQ(resumed.ok().output_admission->usage().bits, deferred_size.bits);
      // Persist/reopen the queue fixture to remove unrelated live wrappers.
      // This is a queue-subtree proof comparison, not a complete shard proof.
      vm::CellBuilder queue_container;
      queue_container.store_ref(seeded.ok().roots.outgoing).store_ref(seeded.ok().roots.dispatch);
      auto queue_bytes = vm::std_boc_serialize(queue_container.finalize()).move_as_ok();
      auto queue_root = vm::std_boc_deserialize(queue_bytes.as_slice()).move_as_ok();
      for (unsigned missing = 0; missing < 3; ++missing) {
        auto local = remaining;
        if (missing == 0) local.state_admission.reset();
        if (missing == 1) local.state_usage_node = {};
        if (missing == 2) {
          auto expired = std::make_shared<vm::CellUsageTree>();
          local.state_usage_node = expired->root_ptr();
        }
        auto refused = block::continue_workchain_outbound_queues(
            seeded.ok().roots, local, deferred_choices, {foreign}, queue_policy);
        ASSERT_TRUE(refused.is_error());
        ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      }
      {
        auto inner = std::make_shared<vm::CellUsageTree>();
        auto outer = std::make_shared<vm::CellUsageTree>();
        auto raw = vm::load_cell_slice(queue_root);
        auto nested = seeded.ok().roots;
        nested.dispatch = vm::UsageCell::create(
            vm::UsageCell::create(raw.prefetch_ref(1), inner->root_ptr()), outer->root_ptr());
        auto local = remaining;
        local.state_usage_node = outer->root_ptr();
        auto refused = block::continue_workchain_outbound_queues(
            nested, local, deferred_choices, {foreign}, queue_policy);
        ASSERT_TRUE(refused.is_error());
        ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        // An enclosing observer owns its refusal signal; the continuation must
        // not reinterpret it as its own quota or local-failure verdict.
        nested.dispatch = vm::UsageCell::create(raw.prefetch_ref(1), outer->root_ptr());
        vm::CellUsageTree::ScopedReadObserver enclosing(outer->root_ptr(), [](const vm::Cell&) {
          throw block::account_settlement_detail::UnadmittedStateRead{};
        });
        bool propagated = false;
        try {
          auto result = block::continue_workchain_outbound_queues(
              nested, local, deferred_choices, {foreign}, queue_policy);
          (void)result;
        } catch (const block::account_settlement_detail::UnadmittedStateRead&) {
          propagated = true;
        }
        ASSERT_TRUE(propagated);
      }
      block::NativeStateReadUsage queue_state_usage{0, 0};
      td::uint64 queue_source_loads = 0;
      auto trace_queue = [&](bool metered, const block::WorkchainAccountSettlement& settlement,
                             std::optional<block::WorkchainExecutionFailure> failure = std::nullopt,
                             bool fault = false) {
        auto tree = std::make_shared<vm::CellUsageTree>();
        std::map<vm::CellHash, unsigned> observed_cells;
        tree->set_cell_load_callback([&](const vm::LoadedCell& cell) {
          observed_cells.emplace(cell.data_cell->get_hash(), cell.data_cell->get_bits());
        });
        auto source_root = queue_root;
        queue_source_loads = 0;
        {
          auto raw = vm::load_cell_slice(queue_root);
          td::Ref<vm::Cell> broken{td::Ref<StateReadCallbackCell>{true, raw.prefetch_ref(1), [&] {
            queue_source_loads = block::participant_lt_detail::checked_add(queue_source_loads, 1).move_as_ok();
            if (fault) throw vm::VmError{vm::Excno::dict_err, "injected queue source fault"};
          }}};
          vm::CellBuilder container;
          container.store_ref(raw.prefetch_ref(0)).store_ref(broken);
          source_root = container.finalize();
        }
        auto tracked_root = vm::UsageCell::create(source_root, tree->root_ptr());
        block::NativeStateReadMeter initial(*settlement.state_admission);
        auto acquired = initial.load_encoded(tracked_root);
        ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(acquired));
        const auto& slice = std::get<td::Ref<vm::CellSlice>>(acquired);
        block::WorkchainOutboundQueueRoots tracked_queues{seeded.ok().roots.descriptors,
            slice->prefetch_ref(0), slice->prefetch_ref(1)};
        auto local = settlement;
        local.state_admission = std::make_shared<const block::NativeStateReadMeter>(initial);
        local.state_usage_node = tree->root_ptr();
        std::vector<block::WorkchainQueuedOutput> remaining_choices(independently_queued.begin() + 1,
                                                                  independently_queued.end());
        auto result = metered
            ? block::continue_workchain_outbound_queues(tracked_queues, local, deferred_choices, {foreign}, queue_policy)
            : block::build_workchain_outbound_queues(tracked_queues, remaining_choices, {foreign}, queue_policy);
        if (failure) {
          ASSERT_TRUE(result.is_error());
          ASSERT_EQ(result.error().code(), static_cast<int>(*failure));
          ASSERT_EQ(local.state_admission->usage().cells, initial.usage().cells);
          ASSERT_EQ(local.state_admission->usage().bits, initial.usage().bits);
          return std::make_pair(td::BufferSlice{}, td::BufferSlice{});
        }
        if (result.is_error()) LOG(ERROR) << result.error();
        ASSERT_TRUE(result.is_ok());
        ASSERT_EQ(result.ok().roots.outgoing->get_hash(), deferred.ok().roots.outgoing->get_hash());
        ASSERT_EQ(result.ok().roots.dispatch->get_hash(), deferred.ok().roots.dispatch->get_hash());
        // Capture construction loads before proof generation makes further reads.
        const auto construction_loads = queue_source_loads;
        if (metered) {
          auto expected = settlement.state_admission->usage();
          unsigned additional = 0;
          for (const auto& [hash, bits] : observed_cells) {
            if (settlement.state_admission->charged_hashes().count(hash)) continue;
            expected.cells = block::participant_lt_detail::checked_add(expected.cells, 1).move_as_ok();
            expected.bits = block::participant_lt_detail::checked_add(expected.bits, bits).move_as_ok();
            ++additional;
          }
          ASSERT_TRUE(additional > 1);
          ASSERT_TRUE(result.ok().state_admission != nullptr);
          ASSERT_EQ(result.ok().state_admission->usage().cells, expected.cells);
          ASSERT_EQ(result.ok().state_admission->usage().bits, expected.bits);
          queue_state_usage = expected;
          ASSERT_EQ(local.state_admission->usage().cells, initial.usage().cells);
        }
        vm::CellBuilder updated;
        updated.store_ref(result.ok().roots.outgoing).store_ref(result.ok().roots.dispatch);
        auto update = vm::MerkleUpdate::generate(tracked_root, updated.finalize(), tree.get()).move_as_ok();
        auto proof = vm::MerkleProof::generate(tracked_root, tree.get()).move_as_ok();
        queue_source_loads = construction_loads;
        return std::make_pair(vm::std_boc_serialize(update).move_as_ok(), vm::std_boc_serialize(proof).move_as_ok());
      };
      auto unmetered_proof = trace_queue(false, remaining);
      const auto unmetered_loads = queue_source_loads;
      ASSERT_TRUE(unmetered_loads > 0);
      auto metered_proof = trace_queue(true, remaining);
      ASSERT_EQ(queue_source_loads,
          block::participant_lt_detail::checked_add(unmetered_loads, unmetered_loads).move_as_ok());
      ASSERT_EQ(unmetered_proof.first.as_slice(), metered_proof.first.as_slice());
      ASSERT_EQ(unmetered_proof.second.as_slice(), metered_proof.second.as_slice());
      const auto exact_queue_usage = queue_state_usage;
      ASSERT_TRUE(exact_queue_usage.cells > remaining.state_admission->usage().cells);
      ASSERT_TRUE(exact_queue_usage.bits > remaining.state_admission->usage().bits);
      for (unsigned dimension = 0; dimension < 3; ++dimension) {
        auto bounds = policy.resources().state;
        // Positive measured totals exceed the already admitted account union.
        bounds.max_cells = exact_queue_usage.cells - (dimension == 1 ? 1 : 0);
        bounds.max_bits = exact_queue_usage.bits - (dimension == 2 ? 1 : 0);
        auto bounded = with_output_limits(256, 65536, bounds);
        ASSERT_TRUE(bounded.is_ok());
        bounded.ok_ref().exports.erase(bounded.ok_ref().exports.begin());
        LOG(INFO) << "queue state boundary dimension " << dimension;
        auto proof = trace_queue(true, bounded.ok(), dimension == 0 ? std::nullopt :
            std::optional{block::WorkchainExecutionFailure::CandidateInvalid});
        if (dimension == 0) ASSERT_EQ(proof.first.as_slice(), metered_proof.first.as_slice());
      }
      (void)trace_queue(true, remaining, block::WorkchainExecutionFailure::LocalUnavailable, true);
    }
    {
      auto saved_effects = engine.effects;
      ASSERT_TRUE(!engine.effects.updates.empty());
      unsigned output_loads = 0;
      td::Ref<PreflightObservedCell> source{true, number(989898), &output_loads};
      engine.effects.updates[0].data = source;
      auto available = with_output_limits(256, 65536);
      ASSERT_TRUE(available.is_ok());
      const auto final_read = output_loads;
      ASSERT_TRUE(final_read > 1);
      output_loads = 0;
      source->set_unavailable_at(final_read);
      auto unavailable = with_output_limits(256, 65536);
      ASSERT_EQ(output_loads, final_read);
      ASSERT_TRUE(unavailable.is_error());
      ASSERT_EQ(unavailable.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      engine.effects = std::move(saved_effects);
    }
    {
      auto saved_effects = engine.effects;
      ASSERT_TRUE(!engine.effects.updates.empty());
      const std::vector<std::function<void()>> faults{
          [] { throw vm::VmError{vm::Excno::cell_und, "output test read"}; },
          [] { throw vm::VmVirtError{1}; },
          [] { throw vm::VmNoGas{}; },
          [] { throw vm::VmFatal{}; },
          [] { throw vm::CellBuilder::CellCreateError{}; },
          [] { throw vm::CellBuilder::CellWriteError{}; },
          [] { throw std::bad_alloc{}; },
          [] { throw std::length_error{"output test length"}; },
          [] { throw std::runtime_error{"output test runtime"}; }};
      unsigned escaped = 0;
      for (std::size_t kind = 0; kind < faults.size(); ++kind) {
        unsigned loads = 0, fail_at = 0;
        td::Ref<vm::Cell> source{td::Ref<StateReadCallbackCell>{true, number(989898), [&] {
          ++loads;
          if (loads == fail_at) faults[kind]();
        }}};
        engine.effects.updates[0].data = source;
        auto available = with_output_limits(256, 65536);
        ASSERT_TRUE(available.is_ok());
        ASSERT_TRUE(loads > 1);
        fail_at = loads;  // Final read is output closure admission, not construction.
        loads = 0;
        LOG(INFO) << "local output exception kind " << kind;
        try {
          auto failed = with_output_limits(256, 65536);
          ASSERT_TRUE(failed.is_error());
          ASSERT_EQ(failed.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
        } catch (...) {
          ++escaped;
          LOG(ERROR) << "escaped output exception kind " << kind;
        }
        ASSERT_EQ(loads, fail_at);
      }
      ASSERT_EQ(escaped, 0u);
      engine.effects = std::move(saved_effects);
    }
    {
      auto continuation = *exact_output.ok().output_admission;
      ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(
          continuation.load_encoded(exact_output.ok().state.account_blocks)));
      ASSERT_EQ(continuation.usage().cells, output_size.cells);
      auto extra = number(0x777777);
      ASSERT_TRUE(!continuation.charged_hashes().count(extra->get_hash()));
      auto exhausted = continuation.load_encoded(extra);
      ASSERT_TRUE(std::holds_alternative<block::NativeClosureLimit>(exhausted));
      ASSERT_EQ(std::get<block::NativeClosureLimit>(exhausted), block::NativeClosureLimit::Cells);
      // Failing a copied continuation cannot poison the immutable snapshot.
      auto separate = *exact_output.ok().output_admission;
      ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(
          separate.load_encoded(exact_output.ok().state.account_blocks)));
    }
    for (unsigned dimension = 0; dimension < 2; ++dimension) {
      LOG(INFO) << "output admission dimension " << dimension;
      // The independent counts were both proved positive before subtraction.
      auto over_output = with_output_limits(output_size.cells - (dimension == 0),
          output_size.bits - (dimension == 1));
      ASSERT_TRUE(over_output.is_error());
      ASSERT_EQ(over_output.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
    }
    {
      auto saved_effects = engine.effects;
      ASSERT_EQ(engine.effects.updates.size(), 2u);
      td::Ref<vm::Cell> shared = number(0x7788);
      for (unsigned i = 0; i < 4; ++i) {
        shared = vm::CellBuilder().store_long(i, 64).store_ref(shared).finalize();
      }
      engine.effects.updates[0].data = shared;
      engine.effects.updates[1].data = vm::CellBuilder().store_long(0x77, 8).store_ref(shared).finalize();
      auto enlarged = with_output_limits(256, 65536);
      ASSERT_TRUE(enlarged.is_ok());
      vm::AugmentedDictionary produced(vm::load_cell_slice_ref(enlarged.ok().state.accounts),
          256, block::tlb::aug_ShardAccounts);
      vm::AugmentedDictionary prior(vm::load_cell_slice_ref(old.accounts), 256, block::tlb::aug_ShardAccounts);
      std::uint64_t old_cells = 0, old_bits = 0, new_cells = 0, new_bits = 0;
      unsigned old_depth = 0, new_depth = 0;
      std::vector<std::uint64_t> per_account_cells;
      for (const auto& key : access.writes) {
        auto old_value = prior.lookup(key), new_value = produced.lookup(key);
        block::tlb::ShardAccount::Record old_record, new_record;
        ASSERT_TRUE(old_value.not_null() && old_record.unpack(old_value));
        ASSERT_TRUE(new_value.not_null() && new_record.unpack(new_value));
        vm::CellStorageStat old_size, new_size;
        ASSERT_TRUE(old_size.compute_used_storage(old_record.account).is_ok());
        ASSERT_TRUE(new_size.compute_used_storage(new_record.account).is_ok());
        per_account_cells.push_back(new_size.cells);
        old_cells = std::max<std::uint64_t>(old_cells, old_size.cells);
        old_bits = std::max<std::uint64_t>(old_bits, old_size.bits);
        old_depth = std::max<unsigned>(old_depth, old_record.account->get_depth());
        new_cells = std::max<std::uint64_t>(new_cells, new_size.cells);
        new_bits = std::max<std::uint64_t>(new_bits, new_size.bits);
        new_depth = std::max<unsigned>(new_depth, new_record.account->get_depth());
      }
      ASSERT_TRUE(new_cells > old_cells && new_bits > old_bits && new_depth > old_depth);
      ASSERT_EQ(per_account_cells.size(), 2u);
      ASSERT_TRUE(per_account_cells[0] < per_account_cells[1]);
      for (unsigned dimension = 0; dimension < 3; ++dimension) {
        LOG(INFO) << "new account closure dimension " << dimension;
        auto bounds = policy.resources().state;
        // Strict growth above proves both positivity and old-state readability.
        if (dimension == 0) bounds.max_account_cells = new_cells - 1;
        if (dimension == 1) bounds.max_account_bits = new_bits - 1;
        if (dimension == 2) bounds.max_account_depth = new_depth - 1;
        engine.calls = 0;
        auto rejected = with_output_limits(256, 65536, bounds);
        ASSERT_EQ(engine.calls, 1u);
        ASSERT_TRUE(rejected.is_error());
        ASSERT_EQ(rejected.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
      }
      engine.effects = std::move(saved_effects);
    }
    vm::CellStorageStat effects_size;
    ASSERT_TRUE(effects_size.compute_used_storage(complete_result.ok().effects).is_ok());
    ASSERT_TRUE(effects_size.cells > 1 && effects_size.bits > 1);
    auto with_effect_limits = [&](std::uint64_t cells, std::uint64_t bits,
                                  std::optional<std::uint32_t> transfers = std::nullopt) {
      auto resources = policy.resources();
      resources.work_output.max_effect_cells = cells;
      resources.work_output.max_effect_bits = bits;
      if (transfers) resources.work_output.max_transfers = *transfers;
      auto resolved = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, policy.identity());
      ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved));
      block::BatchInputAdmissionSession measured(std::get<block::ResolvedBatchInputPolicy>(resolved),
          candidate, declaration_root, complete_identity, inbox);
      ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(measured.evaluate()));
      return block::execute_and_settle_workchain_disposal(engine, old.accounts, complete_identity,
          std::get<block::AdmittedBatchInput>(measured.evaluate()), owned_inbox, a,
          td::make_refint(100), 4096, cfg, joint_context);
    };
    auto exact_effects = with_effect_limits(effects_size.cells, effects_size.bits);
    ASSERT_TRUE(exact_effects.is_ok());
    ASSERT_EQ(exact_effects.ok().effects->get_hash(), complete_result.ok().effects->get_hash());
    ASSERT_EQ(exact_effects.ok().state.accounts->get_hash(), complete_result.ok().state.accounts->get_hash());
    for (unsigned field = 0; field < 5; ++field) {
      auto saved_effects = engine.effects;
      LOG(INFO) << "effects prewalk group " << field;
      ASSERT_TRUE(!engine.effects.updates.empty());
      ASSERT_TRUE(!engine.effects.native_transfers.empty());
      unsigned effect_loads = 0;
      td::Ref<vm::Cell> missing = td::Ref<PreflightObservedCell>{true, number(98765), &effect_loads, true};
      if (field == 0) engine.effects.updates[0].data = missing;
      if (field == 1) engine.effects.native_transfers[0].value.extra = missing;
      if (field == 2) engine.effects.payout_request = missing;
      if (field == 3) engine.effects.receipts = missing;
      if (field == 4) engine.effects.events = missing;
      // The encoder rejects this self-transfer before loading the selected
      // reference. One load therefore witnesses acquisition before encoding,
      // not the final closure walk masking removal of that group's prewalk.
      ASSERT_TRUE(!engine.effects.native_transfers.empty());
      engine.effects.native_transfers[0].to = engine.effects.native_transfers[0].from;
      engine.calls = 0;
      auto unavailable = with_effect_limits(128, 8192);
      if (effect_loads != 1) LOG(ERROR) << "missing effects prewalk group " << field;
      ASSERT_EQ(effect_loads, 1u);
      ASSERT_TRUE(unavailable.is_error());
      ASSERT_EQ(unavailable.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      ASSERT_EQ(engine.calls, 1u);
      ASSERT_TRUE(engine.effects.native_transfers.size() > 1);
      for (std::uint32_t transfer_limit : {0u, 1u}) {
        LOG(INFO) << "effects transfer limit " << transfer_limit;
        effect_loads = engine.calls = 0;
        auto excessive_transfers = with_effect_limits(128, 8192, transfer_limit);
        // Check the observable read before the error class: moving the count
        // gate after acquisition must fail here, not at a later code assertion.
        ASSERT_EQ(effect_loads, 0u);
        ASSERT_TRUE(excessive_transfers.is_error());
        ASSERT_EQ(excessive_transfers.error().code(),
            static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
        ASSERT_EQ(engine.calls, 1u);
      }
      engine.effects = std::move(saved_effects);
    }
    for (unsigned dimension = 0; dimension < 2; ++dimension) {
      LOG(INFO) << "effects early limit dimension " << dimension;
      auto saved_effects = engine.effects;
      ASSERT_TRUE(!engine.effects.updates.empty());
      ASSERT_TRUE(!engine.effects.native_transfers.empty());
      unsigned parent_loads = 0, child_loads = 0;
      td::Ref<vm::Cell> child = td::Ref<PreflightObservedCell>{true, number(87654), &child_loads};
      auto parent = vm::CellBuilder().store_long(3, 2).store_ref(child).finalize();
      engine.effects.updates[0].data = td::Ref<PreflightObservedCell>{true, parent, &parent_loads};
      engine.effects.native_transfers[0].to = engine.effects.native_transfers[0].from;
      engine.calls = 0;
      auto early_limit = with_effect_limits(dimension == 0 ? 1 : 128, dimension == 1 ? 1 : 8192);
      ASSERT_TRUE(early_limit.is_error());
      ASSERT_EQ(early_limit.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
      ASSERT_EQ(parent_loads, 1u);
      ASSERT_EQ(child_loads, 0u);
      ASSERT_EQ(engine.calls, 1u);
      engine.effects = std::move(saved_effects);
    }
    // Both independent counts are positive above, so each subtraction is safe.
    for (unsigned dimension = 0; dimension < 2; ++dimension) {
      engine.calls = 0;
      auto over = with_effect_limits(effects_size.cells - (dimension == 0),
          effects_size.bits - (dimension == 1));
      if (over.is_ok()) LOG(ERROR) << "effects limit bypass in dimension " << dimension;
      ASSERT_TRUE(over.is_error());
      ASSERT_EQ(over.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
      ASSERT_EQ(engine.calls, 1u);
    }
    auto claim = complete_result.ok();
    claim.exports.clear();
    // A claimed accounting cache is not the rebuilt output allowance.
    claim.output_admission = std::make_shared<const block::NativeStateReadMeter>(1, 1);
    engine.calls = 0;
    auto replayed = block::replay_workchain_disposal_settlement(engine, old.accounts, complete_identity,
        full, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context, claim);
    ASSERT_TRUE(replayed.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_EQ(replayed.ok().exports.size(), 3u);
    ASSERT_TRUE(replayed.ok().output_admission != nullptr);
    ASSERT_EQ(replayed.ok().output_admission->usage().cells, output_size.cells);
    ASSERT_EQ(replayed.ok().output_admission->usage().bits, output_size.bits);
    ASSERT_EQ(replayed.ok().state.accounts->get_hash(), complete_result.ok().state.accounts->get_hash());
    ASSERT_EQ(replayed.ok().state.account_blocks->get_hash(), complete_result.ok().state.account_blocks->get_hash());
    auto wrong_artifacts = complete_result.ok();
    // Keep this a valid, authorized constructor so it still reaches the
    // independent replay comparison rather than the earlier profile framing gate.
    auto different_effects = engine.effects;
    different_effects.events = number(88);
    wrong_artifacts.effects = block::encode_workchain_account_effects(different_effects, 2, 2, 4096).move_as_ok();
    engine.calls = 0;
    auto wrong_effects = block::replay_workchain_disposal_settlement(engine, old.accounts, complete_identity,
        full, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context, wrong_artifacts);
    ASSERT_TRUE(wrong_effects.is_error());
    ASSERT_TRUE(!block::workchain_execution_requires_local_failure(wrong_effects.error()));
    ASSERT_EQ(engine.calls, 1u);
    auto wrong_context = joint_context;
    wrong_context.max_inbound = 6;
    engine.calls = source_loads = 0;
    auto mismatch = block::execute_and_settle_workchain_disposal(engine, observed, complete_identity,
        full, owned_inbox, a, td::make_refint(100), 4096, cfg, wrong_context);
    ASSERT_TRUE(mismatch.is_error());
    ASSERT_EQ(mismatch.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(engine.calls, 0u);
    ASSERT_EQ(source_loads, 0u);
    claim.input = number(99);
    auto wrong_commitment = block::replay_workchain_disposal_settlement(engine, observed, complete_identity,
        full, owned_inbox, a, td::make_refint(100), 4096, cfg, joint_context, claim);
    ASSERT_TRUE(wrong_commitment.is_error());
    ASSERT_TRUE(!block::workchain_execution_requires_local_failure(wrong_commitment.error()));
    ASSERT_EQ(engine.calls, 0u);
    ASSERT_EQ(source_loads, 0u);
    auto empty_native = own_native_fixture({});
    auto missing_inbox = block::execute_and_settle_workchain_disposal(engine, observed, complete_identity,
        full, empty_native, a, td::make_refint(100), 4096, cfg, joint_context);
    ASSERT_TRUE(missing_inbox.is_error());
    ASSERT_EQ(engine.calls, 0u);
    ASSERT_EQ(source_loads, 0u);
    auto resources = policy.resources();
    resources.state.max_cells = 1;
    auto bounded = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, policy.identity());
    ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(bounded));
    block::BatchInputAdmissionSession limited(std::get<block::ResolvedBatchInputPolicy>(bounded),
        candidate, declaration_root, complete_identity, inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(limited.evaluate()));
    auto refused = block::execute_and_settle_workchain_disposal(engine, observed, complete_identity,
        std::get<block::AdmittedBatchInput>(limited.evaluate()), owned_inbox, a, td::make_refint(100),
        4096, cfg, joint_context);
    ASSERT_TRUE(refused.is_error());
    ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
    ASSERT_EQ(engine.calls, 0u);
  }
  {
    // Exercise real Native dictionary/envelope encodings with simultaneous
    // emitters. The processing account and actual bounce source differ.
    block::tlb::Aug_OutMsgDescr augmentation(16);
    vm::AugmentedDictionary empty_descriptors(256, augmentation);
    vm::AugmentedDictionary empty_outgoing(352, block::tlb::aug_OutMsgQueue);
    vm::AugmentedDictionary empty_dispatch(256, block::tlb::aug_DispatchQueue);
    block::WorkchainOutboundQueueRoots empty{empty_descriptors.get_wrapped_dict_root(),
        empty_outgoing.get_wrapped_dict_root(), empty_dispatch.get_wrapped_dict_root()};
    block::WorkchainOutboundQueuePolicy queue_policy{{2, tos::shardIdAll}, 10, 16, false, true, 3};
    std::vector<block::WorkchainQueuedOutput> choices;
    for (const auto& output : joint_settled.exports) choices.push_back({output, false});
    // Compare shared Native encoding with the independent generated record
    // packers. Boundary LTs exercise bit preservation, not message admission.
    for (bool defer : {false, true}) {
      for (bool with_metadata : {false, true}) {
        for (std::uint64_t lt : {std::uint64_t{0}, std::uint64_t{22}, UINT64_MAX}) {
          td::optional<block::MsgMetadata> metadata;
          if (with_metadata) metadata = block::MsgMetadata{2, 2, a, 21};
          block::tlb::MsgEnvelope::Record_std env{defer ? 0 : 96, defer ? 0 : 96,
              td::make_refint(7), choices.front().output.msg, {}, metadata};
          auto encoded_result = block::encode_native_new_export(env, choices.front().output.trans, lt, defer);
          ASSERT_TRUE(encoded_result.is_ok());
          auto encoded = encoded_result.move_as_ok();
          // Independent fixed-field wire oracle, not the inverse of the
          // hand-written envelope packer. Address zeroing is caller policy.
          vm::CellBuilder expected_envelope;
          expected_envelope.store_long(with_metadata ? 5 : 4, 4)
              .store_long(defer ? 0 : 96, 8).store_long(defer ? 0 : 96, 8)
              .store_long(1, 4).store_long(7, 8).store_ref(choices.front().output.msg);
          if (with_metadata) {
            expected_envelope.store_long(0, 1).store_long(1, 1) // no emitted LT, metadata present
                .store_long(0, 4).store_long(2, 32) // metadata tag and depth
                .store_long(4, 3).store_long(2, 8).store_bits(a.bits(), 256).store_long(21, 64);
          }
          ASSERT_EQ(encoded.envelope->get_hash(), expected_envelope.finalize()->get_hash());
          try {
            ASSERT_TRUE(block::encode_native_new_export(env, {}, lt, defer).is_error());
          } catch (vm::CellBuilder::CellCreateError&) {
            ASSERT_TRUE(false); // Missing transaction must be an explicit argument error.
          } catch (vm::CellBuilder::CellWriteError&) {
            ASSERT_TRUE(false);
          }
          td::Ref<vm::Cell> expected_descriptor, expected_enqueued;
          if (defer) {
            block::gen::OutMsg::Record_msg_export_new_defer rec{encoded.envelope, choices.front().output.trans};
            ASSERT_TRUE(tlb::pack_cell(expected_descriptor, rec));
          } else {
            block::gen::OutMsg::Record_msg_export_new rec{encoded.envelope, choices.front().output.trans};
            ASSERT_TRUE(tlb::pack_cell(expected_descriptor, rec));
          }
          block::gen::EnqueuedMsg::Record rec{lt, encoded.envelope};
          ASSERT_TRUE(tlb::pack_cell(expected_enqueued, rec));
          ASSERT_EQ(encoded.descriptor->get_hash(), expected_descriptor->get_hash());
          ASSERT_EQ(encoded.enqueued->get_hash(), expected_enqueued->get_hash());
          block::tlb::MsgEnvelope::Record_std decoded;
          ASSERT_TRUE(tlb::unpack_cell(encoded.envelope, decoded));
          ASSERT_EQ(decoded.cur_addr, defer ? 0 : 96);
          ASSERT_EQ(decoded.next_addr, defer ? 0 : 96);
          ASSERT_TRUE(decoded.metadata == metadata);
          ASSERT_TRUE(block::CurrencyCollection(decoded.fwd_fee_remaining) == block::CurrencyCollection(7));
          ASSERT_EQ(decoded.msg->get_hash(), choices.front().output.msg->get_hash());
        }
      }
    }
    auto plain_result = block::build_workchain_outbound_queues(empty, choices, {}, queue_policy);
    ASSERT_TRUE(plain_result.is_ok());
    auto plain = plain_result.move_as_ok();
    ASSERT_EQ(plain.queued, 3u);
    ASSERT_EQ(plain.deferred, 0u);
    ASSERT_EQ(plain.roots.dispatch->get_hash(), empty.dispatch->get_hash());
    vm::AugmentedDictionary descriptors(vm::load_cell_slice_ref(plain.roots.descriptors), 256, augmentation);
    vm::AugmentedDictionary outgoing(vm::load_cell_slice_ref(plain.roots.outgoing), 352, block::tlb::aug_OutMsgQueue);
    ASSERT_EQ(outgoing.get_root_extra()->prefetch_ulong(64), 22u);
    block::CurrencyCollection exported_total;
    ASSERT_TRUE(exported_total.unpack(descriptors.get_root_extra()));
    ASSERT_TRUE(exported_total == block::CurrencyCollection(712));
    for (const auto& choice : choices) {
      auto record = descriptors.lookup(choice.output.msg->get_hash().bits(), 256);
      ASSERT_TRUE(record.not_null());
      ASSERT_EQ(record->prefetch_ulong(3), 1u);
      auto envelope = record->prefetch_ref();
      ASSERT_EQ(record->prefetch_ref(1)->get_hash(), choice.output.trans->get_hash());
      td::BitArray<352> queue_key;
      ASSERT_TRUE(block::compute_out_msg_queue_key(envelope, queue_key));
      auto queued = outgoing.lookup(queue_key.bits(), 352);
      ASSERT_TRUE(queued.not_null());
      ASSERT_EQ(queued->prefetch_ulong(64), choice.output.lt);
      ASSERT_EQ(queued->prefetch_ref()->get_hash(), envelope->get_hash());
    }
    ASSERT_TRUE(block::build_workchain_outbound_queues(plain.roots, choices, {}, queue_policy).is_error());
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, choices, {foreign}, queue_policy).is_error());
    // A processing-account backlog is not a backlog for a foreign-source bounce.
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, choices, {a}, queue_policy).is_ok());
    for (auto& choice : choices) choice.defer = choice.output.trans->get_hash() == pair[1]->root->get_hash();
    auto deferred_result = block::build_workchain_outbound_queues(empty, choices, {foreign}, queue_policy);
    ASSERT_TRUE(deferred_result.is_ok());
    const auto& deferred = deferred_result.ok();
    ASSERT_EQ(deferred.queued, 1u);
    ASSERT_EQ(deferred.deferred, 2u);
    vm::AugmentedDictionary dispatch(vm::load_cell_slice_ref(deferred.roots.dispatch), 256, block::tlb::aug_DispatchQueue);
    ASSERT_TRUE(dispatch.lookup(a).is_null());
    vm::Dictionary account_queue(64);
    std::uint64_t dispatch_count;
    ASSERT_TRUE(block::unpack_account_dispatch_queue(dispatch.lookup(foreign), account_queue, dispatch_count));
    ASSERT_EQ(dispatch_count, 2u);
    ASSERT_TRUE(account_queue.lookup(td::BitArray<64>(22)).not_null());
    ASSERT_TRUE(account_queue.lookup(td::BitArray<64>(23)).not_null());
    auto first = choices.front();
    for (const auto& choice : choices) if (choice.defer && choice.output.msg_idx == 0) first = choice;
    auto second = first;
    for (const auto& choice : choices) if (choice.defer && choice.output.msg_idx == 1) second = choice;
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, {first}, {}, queue_policy).is_error());
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, {second}, {}, queue_policy).is_ok());
    auto disabled_deferral = queue_policy;
    disabled_deferral.deferring_enabled = false;
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, {second}, {}, disabled_deferral).is_error());
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, {first}, {foreign}, disabled_deferral).is_ok());
    auto limited_outputs = queue_policy;
    limited_outputs.max_outputs = 2;
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, choices, {foreign}, limited_outputs).is_error());
    auto wrong_lt = first;
    wrong_lt.output.lt = block::participant_lt_detail::checked_add(first.output.lt, 1).move_as_ok();
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, {wrong_lt}, {foreign}, queue_policy).is_error());
    auto seeded = block::build_workchain_outbound_queues(empty, {first}, {foreign}, queue_policy).move_as_ok();
    block::WorkchainOutboundQueueRoots resumed{empty.descriptors, empty.outgoing, seeded.roots.dispatch};
    second.defer = false;
    ASSERT_TRUE(block::build_workchain_outbound_queues(resumed, {second}, {}, queue_policy).is_error());
    second.defer = true;
    ASSERT_TRUE(block::build_workchain_outbound_queues(resumed, {second}, {}, queue_policy).is_ok());
    queue_policy.metadata_enabled = true;
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, choices, {foreign}, queue_policy).is_error());
    for (auto& choice : choices) {
      const auto processing = choice.defer ? a : b;
      choice.output.metadata = block::MsgMetadata{0, 2, processing, 21};
    }
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, choices, {foreign}, queue_policy).is_ok());
    for (auto& choice : choices) if (choice.defer) choice.output.metadata = block::MsgMetadata{0, 2, foreign, 21};
    ASSERT_TRUE(block::build_workchain_outbound_queues(empty, choices, {foreign}, queue_policy).is_error());
    ASSERT_EQ(empty.descriptors->get_hash(), empty_descriptors.get_wrapped_dict_root()->get_hash());
    ASSERT_EQ(empty.outgoing->get_hash(), empty_outgoing.get_wrapped_dict_root()->get_hash());
    ASSERT_EQ(empty.dispatch->get_hash(), empty_dispatch.get_wrapped_dict_root()->get_hash());
  }
  ASSERT_EQ(old.accounts->get_hash(), original_hash);
  // A touched storage participant is not another Native receiving role.
  // Its misdirected import belongs to the coordinator, even in this write set.
  const td::Bits256 third(number(2)->get_hash().bits());
  block::Account third_account(2, third.bits());
  ASSERT_TRUE(third_account.unpack(accounts.lookup(third), 10, false));
  auto expanded_access = access;
  expanded_access.reads.push_back({third, td::Bits256(third_account.total_state->get_hash().bits())});
  expanded_access.writes.push_back(third);
  std::sort(expanded_access.reads.begin(), expanded_access.reads.end(),
      [](const auto& lhs, const auto& rhs) { return lhs.account < rhs.account; });
  std::sort(expanded_access.writes.begin(), expanded_access.writes.end());
  auto expanded_effects = joint_effects;
  expanded_effects.updates.push_back({third, number(323)});
  std::sort(expanded_effects.updates.begin(), expanded_effects.updates.end(),
      [](const auto& lhs, const auto& rhs) { return lhs.account < rhs.account; });
  auto expanded_inbox = inbox;
  expanded_inbox.push_back(inbound_envelope(6, 6, {}, third, block::CurrencyCollection(100)));
  const auto expanded_owned = own_native_fixture(expanded_inbox);
  auto expanded_context = joint_context;
  expanded_context.max_inbound = 6;
  engine.effects = expanded_effects;
  engine.calls = 0;
  auto expanded_result = block::execute_and_settle_workchain_disposal(engine, old.accounts, overlay_identity,
      admitted, expanded_access, expanded_owned, 3, 3, 2, a, td::make_refint(100), 4096, cfg, expanded_context);
  if (expanded_result.is_error()) LOG(ERROR) << "expanded joint overlay failed: " << expanded_result.error();
  ASSERT_TRUE(expanded_result.is_ok());
  auto expanded = expanded_result.move_as_ok();
  ASSERT_EQ(engine.calls, 1u);
  ASSERT_EQ(expanded.exports.size(), 3u);
  vm::AugmentedDictionary expanded_accounts(vm::load_cell_slice_ref(expanded.state.accounts), 256,
      block::tlb::aug_ShardAccounts);
  block::Account next_third(2, third.bits()), expanded_coordinator(2, a.bits());
  ASSERT_TRUE(next_third.unpack(expanded_accounts.lookup(third), 10, false));
  ASSERT_TRUE(expanded_coordinator.unpack(expanded_accounts.lookup(a), 10, false));
  ASSERT_TRUE(next_third.balance == block::CurrencyCollection(1000));
  ASSERT_TRUE(expanded_coordinator.balance == block::CurrencyCollection(1073));
  ASSERT_EQ(next_third.data->get_hash(), number(323)->get_hash());
  ASSERT_EQ(next_third.last_trans_lt_, 21u);
  ASSERT_EQ(old.accounts->get_hash(), original_hash);
  engine.effects = joint_effects;
  auto insufficient_outputs = joint_context;
  insufficient_outputs.max_outbound = 2;
  ASSERT_TRUE(joint(insufficient_outputs, 100).is_error());
  ASSERT_TRUE(joint(joint_context, 99).is_error());
  auto wrong_custody = joint_context;
  wrong_custody.custody = foreign;
  ASSERT_TRUE(joint(wrong_custody, 100).is_error());
  auto other_prices = joint_prices;
  block::WorkchainDisposalEntryContext unshared_prices{b, other_prices, workchains, profile, 5, 3};
  ASSERT_TRUE(joint(unshared_prices, 100).is_error());
  block::WorkchainSet divergent_table; // Missing the bounce destination workchain.
  block::WorkchainDisposalEntryContext unshared_table{b, joint_prices, divergent_table, profile, 5, 3};
  ASSERT_TRUE(joint(unshared_table, 100).is_error());
  ASSERT_TRUE(Transaction::build_workchain_payout_pair(custody, coordinator, joint_bindings[1], joint_bindings[0],
      number(322), number(321), request, 21, 10, td::make_refint(100), 2, 4096,
      cfg, joint_prices, {}, {}, &joint_context).is_error());
  auto absent_table = joint_prices;
  absent_table.workchains = nullptr;
  ASSERT_TRUE(Transaction::build_workchain_payout_pair(custody, coordinator, joint_bindings[1], joint_bindings[0],
      number(322), number(321), request, 21, 10, td::make_refint(100), 2, 4096,
      cfg, absent_table, {}, {}).is_error());
  auto joint_imports = block::build_workchain_routed_final_imports(2, 16, inbox,
      {{a, pair[1]->root}, {b, pair[0]->root}}, a, b, 5, 2, 4096).move_as_ok();
  std::vector<block::WorkchainAccountValueFlow> joint_rows;
  for (const auto& tx : pair) {
    block::gen::Transaction::Record record;
    block::gen::Account::Record_account account_record;
    block::gen::AccountStorage::Record storage;
    block::CurrencyCollection after, fees, exported(0);
    ASSERT_TRUE(tlb::unpack_cell(tx->root, record));
    ASSERT_TRUE(tlb::unpack_cell(tx->new_total_state, account_record) && tlb::csr_unpack(account_record.storage, storage));
    ASSERT_TRUE(after.unpack(storage.balance) && fees.unpack(record.total_fees));
    vm::Dictionary messages(record.r1.out_msgs, 15);
    ASSERT_TRUE(messages.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr, int width) {
      block::gen::CommonMsgInfo::Record_int_msg_info info;
      block::CurrencyCollection payment, with_fee, next;
      if (width != 15 || value->size_ext() != 0x10000 ||
          !tlb::unpack_cell_inexact(value->prefetch_ref(), info) || !payment.unpack(info.value)) return false;
      auto forwarding = block::tlb::t_Tomis.as_integer(info.fwd_fee);
      if (forwarding.is_null() ||
          !block::CurrencyCollection::add(payment, block::CurrencyCollection(forwarding), with_fee) ||
          !block::CurrencyCollection::add(exported, with_fee, next)) return false;
      exported = std::move(next);
      return true;
    }));
    joint_rows.push_back({record.account_addr, block::CurrencyCollection(1000),
        joint_imports.account_credits.at(record.account_addr), after, exported, fees});
  }
  auto joint_transfers = effects.native_transfers;
  std::sort(joint_rows.begin(), joint_rows.end(), [](const auto& x, const auto& y) { return x.account < y.account; });
  joint_transfers.push_back(joint_result.ok().accounting.fee_funding);
  ASSERT_TRUE(block::verify_workchain_value_flow(joint_rows, joint_transfers, 2, 3, 4096).is_ok());
  ASSERT_TRUE(coordinator.balance == block::CurrencyCollection(1000));
  ASSERT_TRUE(custody.balance == block::CurrencyCollection(1000));
  mismatched_prices.global_version = 15;
  block::WorkchainDisposalEntryContext mismatch{b, mismatched_prices, workchains, profile, 5, 2};
  Transaction wrong_version(coordinator, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(prepare(wrong_version, mismatch).is_error());
  auto unaffordable_prices = messages;
  unaffordable_prices.fwd_std.lump_price = 301;
  block::WorkchainDisposalEntryContext no_outputs{b, unaffordable_prices, workchains, profile, 5, 0};
  Transaction only_credit(coordinator, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(prepare(only_credit, no_outputs).is_ok());
  ASSERT_TRUE(only_credit.balance == block::CurrencyCollection(1673));
  ASSERT_TRUE(only_credit.out_msgs.empty() && only_credit.total_fees.is_zero());
  ASSERT_EQ(only_credit.end_lt, 22u);
  ASSERT_TRUE(only_credit.serialize(cfg));
  // Only one bounce: after an unchecked wrap no later message can mask it.
  auto one_input = block::encode_workchain_host_input(identity, admitted, access, {inbox.back()}, 2, 2, 1).move_as_ok();
  auto one_bindings = block::build_workchain_participant_records(td::Bits256(one_input->get_hash().bits()),
      td::Bits256(effects_root->get_hash().bits()), {a, b}, 2).move_as_ok();
  Transaction overflow(coordinator, Transaction::tr_workchain_batch, UINT64_MAX - 1, 10);
  ASSERT_TRUE(overflow.prepare_workchain_disposal_entry(one_bindings[0], one_input, effects_root, number(321),
      cfg, 2, 4096, context).is_error());
  // Only a custody message: neither own-credit checks nor the disposal helper
  // may mask the full-inbox context checks of the coordinator transaction.
  for (unsigned fault = 0; fault < 5; ++fault) {
    LOG(INFO) << "disposal entry envelope context case=" << fault;
    block::tlb::MsgEnvelope::Record_std envelope;
    ASSERT_TRUE(tlb::unpack_cell(inbox[1], envelope));
    block::gen::Message::Record message;
    block::gen::CommonMsgInfo::Record_int_msg_info info;
    block::gen::MsgAddressInt::Record_addr_std destination;
    ASSERT_TRUE(tlb::type_unpack_cell(envelope.msg, block::gen::t_Message_Any, message));
    ASSERT_TRUE(tlb::csr_unpack(message.info, info) && tlb::csr_unpack(info.dest, destination));
    if (fault == 0) destination.anycast = vm::load_cell_slice_ref(
        vm::CellBuilder().store_long(33, 6).store_long(0, 1).finalize());
    if (fault == 1) destination.workchain_id = 0;
    if (fault == 2) info.created_lt = 21;
    if (fault == 3) info.created_at = 11;
    if (fault == 4) envelope.emitted_lt = 21;
    ASSERT_TRUE(tlb::csr_pack(info.dest, destination) && tlb::csr_pack(message.info, info));
    ASSERT_TRUE(tlb::type_pack_cell(envelope.msg, block::gen::t_Message_Any, message));
    td::Ref<vm::Cell> altered;
    ASSERT_TRUE(tlb::pack_cell(altered, envelope));
    auto altered_input = block::encode_workchain_host_input(identity, admitted, access, {altered}, 2, 2, 1).move_as_ok();
    auto altered_bindings = block::build_workchain_participant_records(td::Bits256(altered_input->get_hash().bits()),
        td::Bits256(effects_root->get_hash().bits()), {a, b}, 2).move_as_ok();
    Transaction rejected(coordinator, Transaction::tr_workchain_batch, 21, 10);
    ASSERT_TRUE(rejected.prepare_workchain_disposal_entry(altered_bindings[0], altered_input, effects_root,
        number(321), cfg, 2, 4096, context).is_error());
    ASSERT_TRUE(rejected.root.is_null() && rejected.new_total_state.is_null());
  }
  // This is Native cash allocation, NOT authorization to spend an unexpected
  // bucket. The enclosing engine must maintain its liability and authorize any
  // sweep. Make the retained 100 load-bearing: 1150 exceeds 1000+100+10.
  auto funded_effects = effects;
  funded_effects.native_transfers[0].value = block::CurrencyCollection(1150);
  auto funded_root = block::encode_workchain_account_effects(funded_effects, 2, 2, 4096).move_as_ok();
  auto funded_bindings = block::build_workchain_participant_records(td::Bits256(input->get_hash().bits()),
      td::Bits256(funded_root->get_hash().bits()), {a, b}, 2).move_as_ok();
  Transaction funded(coordinator, Transaction::tr_workchain_batch, 21, 10);
  ASSERT_TRUE(funded.prepare_workchain_disposal_entry(funded_bindings[0], input, funded_root, number(321),
      cfg, 2, 4096, context).is_ok());
  ASSERT_TRUE(funded.balance == block::CurrencyCollection(60));
  ASSERT_TRUE(funded.serialize(cfg));
  for (auto bad : {0u, 1u, 2u, 3u}) {
    LOG(INFO) << "disposal entry bound case=" << bad;
    auto limited = context;
    if (bad == 0) limited.custody = a;
    if (bad == 1) limited.max_inbound = 4;
    if (bad == 2) limited.max_outbound = 1;
    if (bad == 3) limited.max_outbound = 0;
    Transaction rejected(coordinator, Transaction::tr_workchain_batch, 21, 10);
    ASSERT_TRUE(prepare(rejected, limited).is_error());
    ASSERT_TRUE(rejected.root.is_null() && rejected.new_total_state.is_null());
  }
  // A caller cannot alter an already serialized, sealed message list.
  entry.out_msgs[0] = number(7);
  ASSERT_TRUE(!entry.serialize(cfg));
  ASSERT_TRUE(coordinator.balance == block::CurrencyCollection(1000));
  ASSERT_TRUE(custody.balance == block::CurrencyCollection(1000));
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
  // Record-shape primitive only: these existing transaction fixtures are not
  // claims that the changed inbox has already been settled by the full host.
  auto foreign = td::Bits256::ones();
  ASSERT_TRUE(foreign != a && foreign != b);
  auto misdirected = inbound_envelope(5, 81, {}, foreign, extra_import_value);
  auto routed = [&](const auto& inputs, const auto& txs, const auto& entry, const auto& reserve) {
    return block::build_workchain_routed_final_imports(2, 16, inputs, txs, entry, reserve, 3, 2, 4096);
  };
  std::vector<td::Ref<vm::Cell>> routed_inbox{inbox[0], inbox[2], misdirected};
  auto routed_result = routed(routed_inbox, import_transactions, a, b);
  ASSERT_TRUE(routed_result.is_ok());
  auto routed_evidence = routed_result.move_as_ok();
  ASSERT_TRUE(routed_evidence.account_credits.at(a) == block::CurrencyCollection(200, imported_extra_values.get_root_cell()));
  ASSERT_TRUE(routed_evidence.account_credits.at(b) == block::CurrencyCollection(100));
  ASSERT_TRUE(routed_evidence.account_credits.find(foreign) == routed_evidence.account_credits.end());
  ASSERT_TRUE(routed_evidence.value_imported == block::CurrencyCollection(501, imported_extra_values.get_root_cell()));
  ASSERT_TRUE(routed_evidence.fees_collected == block::CurrencyCollection(201));
  ASSERT_TRUE(native_imports.validate_ref(4096, routed_evidence.in_msg_descr));
  ASSERT_TRUE(block::gen::t_InMsgDescr.validate_ref(4096, routed_evidence.in_msg_descr));
  vm::AugmentedDictionary routed_records(vm::load_cell_slice_ref(routed_evidence.in_msg_descr), 256, native_imports.aug);
  block::tlb::MsgEnvelope::Record_std original_misdirected;
  ASSERT_TRUE(tlb::unpack_cell(misdirected, original_misdirected));
  auto routed_record = routed_records.lookup(original_misdirected.msg->get_hash().bits(), 256);
  ASSERT_TRUE(routed_record.not_null());
  auto routed_slice = *routed_record;
  ASSERT_EQ(routed_slice.fetch_ulong(3), 4u);
  ASSERT_TRUE(routed_slice.fetch_ref()->get_hash() == misdirected->get_hash());
  ASSERT_TRUE(routed_slice.fetch_ref()->get_hash() == importing_entry.root->get_hash());
  // The strict existing factory must not gain the address exception.
  ASSERT_TRUE(block::build_workchain_final_imports(2, 16, routed_inbox, import_transactions, 3, 2, 4096).is_error());
  ASSERT_TRUE(routed(inbox, import_transactions, a, b).move_as_ok().in_msg_descr->get_hash() == import_evidence.in_msg_descr->get_hash());
  ASSERT_TRUE(routed(routed_inbox, import_transactions, a, a).is_error());
  auto missing_entry = import_transactions;
  missing_entry.erase(a);
  ASSERT_TRUE(routed(routed_inbox, missing_entry, a, b).is_error());
  auto wrong_entry = import_transactions;
  wrong_entry[a] = importing_record.root;
  ASSERT_TRUE(routed(routed_inbox, wrong_entry, a, b).is_error());
  // No correctly addressed coordinator message may mask the routed identity check.
  ASSERT_TRUE(routed(std::vector<td::Ref<vm::Cell>>{misdirected}, wrong_entry, a, b).is_error());
  ASSERT_TRUE(routed(std::vector<td::Ref<vm::Cell>>{misdirected, misdirected}, import_transactions, a, b).is_error());
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

TEST(WorkchainBlock, MeteredAccountLookupProof) {
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2, 2, true, 3, false, 0, 40, false, 1000), state));
  const std::vector<td::Bits256> keys{td::Bits256::zero(), td::Bits256(number(1)->get_hash().bits()),
                                     td::Bits256(number(999)->get_hash().bits()), td::Bits256::zero()};
  auto run = [&](bool metered) {
    vm::MerkleProofBuilder proof(state.accounts);
    block::NativeStateReadMeter meter(100, 100000);
    std::set<vm::CellHash> loaded_hashes;
    proof.set_cell_load_callback([&](const vm::LoadedCell& loaded) {
      loaded_hashes.insert(loaded.data_cell->get_hash());
    });
    std::vector<td::Ref<vm::CellSlice>> values;
    for (const auto& key : keys) {
      if (metered) {
        auto result = block::lookup_workchain_account_metered(proof.root(), key, meter,
            block::WorkchainAccountPathMode::Read);
        ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(result));
        values.push_back(std::get<td::Ref<vm::CellSlice>>(std::move(result)));
      } else {
        vm::AugmentedDictionary original(vm::load_cell_slice_ref(proof.root()), 256, block::tlb::aug_ShardAccounts);
        values.push_back(original.lookup(key));
      }
    }
    ASSERT_TRUE(values[0].not_null());
    ASSERT_TRUE(values[1].not_null());
    ASSERT_TRUE(values[2].is_null());
    ASSERT_TRUE(values[3]->contents_equal(*values[0]));
    if (metered) {
      // Native may reload admitted edges. Compare sets, not callback counts:
      // no semantic lookup may fetch content outside the prewalk's allowance.
      ASSERT_EQ(loaded_hashes.size(), meter.charged_hashes().size());
      for (const auto& hash : loaded_hashes) ASSERT_TRUE(meter.charged_hashes().count(hash) == 1);
    }
    return std::make_pair(proof.extract_proof_boc().move_as_ok(), std::move(values));
  };
  auto ordinary = run(false);
  auto metered = run(true);
  ASSERT_EQ(ordinary.first.as_slice(), metered.first.as_slice());
  for (unsigned i : {0u, 1u, 3u}) ASSERT_TRUE(ordinary.second[i]->contents_equal(*metered.second[i]));

  vm::MerkleProofBuilder stopped(state.accounts);
  unsigned loads = 0;
  stopped.set_cell_load_callback([&](const vm::LoadedCell&) { ++loads; });
  block::NativeStateReadMeter root_only(1, 100000);
  auto rejected = block::lookup_workchain_account_metered(stopped.root(), keys[0], root_only,
      block::WorkchainAccountPathMode::Read);
  ASSERT_TRUE(std::holds_alternative<block::NativeClosureLimit>(rejected));
  ASSERT_EQ(std::get<block::NativeClosureLimit>(rejected), block::NativeClosureLimit::Cells);
  ASSERT_EQ(loads, 1u);  // Root wrapper loaded; first dictionary edge not loaded.
}

TEST(WorkchainBlock, AccountReplacementStateDependencies) {
  for (bool branched : {false, true}) {
    vm::AugmentedDictionary initial(256, block::tlb::aug_ShardAccounts);
    std::vector<vm::CellHash> unrelated_accounts;
    std::vector<td::Bits256> keys;
    const unsigned count = branched ? 4 : 3;
    const unsigned writes = branched ? 2 : 1;
    for (unsigned i = 0; i < count; ++i) {
      auto key = i ? td::Bits256(number(i)->get_hash().bits()) : td::Bits256::zero();
      if (branched) {
        key = td::Bits256::zero();
        key.bits().store_uint(i, 2);  // Four distinct prefixes: 00, 01, 10, 11.
      }
      keys.push_back(key);
      vm::Dictionary currencies(32);
      vm::CellBuilder amount;
      ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(amount, *td::make_refint(7)));
      td::BitArray<32> currency_key;
      currency_key.bits().store_uint(i + 1, 32);  // i < 4, so the identifier fits.
      ASSERT_TRUE(currencies.set_builder(currency_key, amount));
      if (branched) {
        currency_key.bits().store_uint(100, 32);
        ASSERT_TRUE(currencies.set_builder(currency_key, amount));
      }
      vm::CellBuilder account;
      account.store_long(1, 1)
          .store_long(4, 3)
          .store_long(2, 8)
          .store_bits(key.bits(), 256)
          .store_zeroes(42)
          .store_long(2, 64);
      ASSERT_TRUE(block::CurrencyCollection(td::make_refint(1000), currencies.get_root_cell()).store(account));
      account.store_zeroes(2);
      auto root = account.finalize();
      ASSERT_TRUE(block::gen::t_Account.validate_ref(10000, root));
      if (i >= writes)
        unrelated_accounts.push_back(root->get_hash());
      vm::CellBuilder entry;
      entry.store_ref(root).store_zeroes(256).store_long(1, 64);
      ASSERT_TRUE(initial.set_builder(key, entry));
    }
    auto old = initial.get_wrapped_dict_root();
    if (branched) {
      auto edge = vm::load_cell_slice(old).prefetch_ref();
      vm::dict::LabelParser top{vm::load_cell_slice_ref(edge), 256, vm::dict::LabelParser::chk_size};
      ASSERT_EQ(top.l_bits, 0);
      vm::dict::LabelParser sibling{vm::load_cell_slice_ref(top.remainder->prefetch_ref(1)), 255,
                                    vm::dict::LabelParser::chk_size};
      ASSERT_TRUE(sibling.l_bits < 255);
      sibling.skip_label();
      ASSERT_TRUE(sibling.remainder.write().advance_refs(2));
      auto extra = block::tlb::aug_ShardAccounts.extract_extra(sibling.remainder);
      ASSERT_TRUE(extra.not_null());
      ASSERT_EQ(extra->size_refs(), 1u);
      ASSERT_TRUE(vm::load_cell_slice(extra->prefetch_ref()).size_refs() > 0);
      // A fork's extra occupies its entire remainder. Native must reject a
      // trailing bit, and admission must reject it before following extra refs.
      auto sibling_cell = top.remainder->prefetch_ref(1);
      auto malformed = vm::CellBuilder().append_cellslice(vm::load_cell_slice(sibling_cell))
          .store_long(0, 1).finalize();
      vm::AugmentedDictionary decoder(malformed, 255, block::tlb::aug_ShardAccounts, false);
      ASSERT_TRUE(decoder.get_root_extra().is_null());
      block::NativeStateReadMeter malformed_meter(1000, 1000000);
      bool rejected = false;
      try {
        auto result = block::admit_workchain_account_augmentation(malformed, 255, malformed_meter);
        ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(result));
      } catch (const vm::VmError&) {
        rejected = true;
      }
      ASSERT_TRUE(rejected);
      ASSERT_EQ(malformed_meter.charged_hashes().size(), 1u);
    }
    vm::MerkleProofBuilder tracked(old);
    std::set<vm::CellHash> loaded;
    tracked.set_cell_load_callback([&](const vm::LoadedCell& cell) { loaded.insert(cell.data_cell->get_hash()); });
    block::NativeStateReadMeter meter(1000, 1000000);
    std::vector<td::Ref<vm::Cell>> admitted_accounts;
    for (unsigned i = 0; i < writes; ++i) {
      const auto& key = keys[i];
      auto acquired =
          block::lookup_workchain_account_metered(tracked.root(), key, meter, block::WorkchainAccountPathMode::Replace);
      ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(acquired));
      block::tlb::ShardAccount::Record record;
      ASSERT_TRUE(record.unpack(std::get<td::Ref<vm::CellSlice>>(acquired)));
      auto closure = block::read_workchain_account_closure(record.account, meter, 1000, 1000000, 1024);
      ASSERT_TRUE(std::holds_alternative<block::WorkchainInputUsage>(closure));
      admitted_accounts.push_back(record.account);
    }
    // Native replacement and independent difference computation run unchanged.
    // Their source loads must stay in the admitted old-state union, including
    // sibling currency augmentation but not unrelated account contents.
    vm::AugmentedDictionary staged(vm::load_cell_slice_ref(tracked.root()), 256, block::tlb::aug_ShardAccounts);
    for (unsigned i = 0; i < writes; ++i) {
      vm::CellBuilder replacement;
      replacement.store_ref(admitted_accounts[i]).store_zeroes(256).store_long(2, 64);
      ASSERT_TRUE(staged.set_builder(keys[i], replacement, vm::Dictionary::SetMode::Replace));
    }
    block::WorkchainAccountDictionary before(tracked.root()), after(staged.get_wrapped_dict_root());
    auto changes = before.changed_accounts(after, writes).move_as_ok();
    ASSERT_EQ(changes.size(), writes);
    for (unsigned i = 0; i < writes; ++i)
      ASSERT_EQ(changes[i], keys[i]);
    ASSERT_EQ(loaded.size(), meter.charged_hashes().size());
    for (const auto& hash : loaded)
      ASSERT_TRUE(meter.charged_hashes().count(hash) == 1);
    for (const auto& hash : unrelated_accounts)
      ASSERT_EQ(loaded.count(hash), 0u);
  }
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
  block::WorkchainHostIdentity identity{-1, hash, hash, 2,    UINT64_MAX, hash, false, 17,
                                        9,  2,    1,    hash, 1,          1,    1,     number(1)};
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
    td::Result<std::uint64_t> proof_work(
        const td::Ref<vm::Cell>&, const block::InputPolicyIdentity&) const override {
      return 0;  // This fixture performs no proof verification.
    }
    mutable unsigned calls{0};
    mutable td::Ref<vm::Cell> seen_input;
    td::Bits256 a, b;
    bool bad_read{false}, omit_write{false}, wrong_key{false}, null_data{false}, with_transfer{false};
    bool reverse_transfer{false};
    unsigned transfer_value{1};
    td::Ref<vm::Cell> payout;
    std::function<void()> finish;
    td::Result<block::WorkchainAccountEffects> execute_accounts(
        const td::Ref<vm::Cell>& input, block::WorkchainAccountReadView& view) const override {
      ++calls;
      seen_input = input;
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
      if (finish) finish();
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
  {
    // Exercise the actual account runner with the complete batch admission,
    // not a singleton permit plus a second caller-supplied declaration set.
    const std::vector<td::Ref<vm::Cell>> inbox;
    auto batch_identity = batch_test_identity(number(42));
    auto declaration_root = block::encode_workchain_account_declarations(declarations, 2, 2).move_as_ok();
    block::BatchInputAdmissionSession batch(inbox_test_policy(1, {100, 100000, 3}, 2, 2),
        candidate, declaration_root, batch_identity, inbox);
    const auto& evaluated = batch.evaluate();
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(evaluated));
    const auto& full = std::get<block::AdmittedBatchInput>(evaluated);
    engine.calls = 0;
    auto complete = block::execute_workchain_account_engine(engine, state.accounts, full);
    ASSERT_TRUE(complete.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_EQ(engine.seen_input->get_hash(), full.root()->get_hash());
    ASSERT_EQ(complete.ok().input->get_hash(), full.root()->get_hash());
    ASSERT_TRUE(engine.seen_input->get_hash() != candidate->get_hash());
    ASSERT_EQ(complete.ok().effects.updates[1].data->get_hash(), number(102)->get_hash());

    auto oversized_resources = full.policy().resources();
    oversized_resources.state.max_account_depth = 70000;
    auto oversized_resolved = block::ResolvedBatchInputPolicy::from_resolved_fields(
        oversized_resources, full.policy().identity());
    ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(oversized_resolved));
    block::BatchInputAdmissionSession oversized_session(
        std::get<block::ResolvedBatchInputPolicy>(oversized_resolved), candidate,
        declaration_root, batch_identity, inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(oversized_session.evaluate()));
    engine.calls = 0;
    auto oversized_policy = block::execute_workchain_account_engine(engine, state.accounts,
        std::get<block::AdmittedBatchInput>(oversized_session.evaluate()));
    ASSERT_TRUE(oversized_policy.is_error());
    ASSERT_EQ(oversized_policy.error().code(),
        static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(engine.calls, 0u);

    block::NativeStateReadMeter reads_only(1000, 1000000);
    for (const auto& read : declarations.reads) {
      auto acquired = block::lookup_workchain_account_metered(state.accounts, read.account, reads_only,
          block::WorkchainAccountPathMode::Read);
      ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(acquired));
      block::tlb::ShardAccount::Record account;
      ASSERT_TRUE(account.unpack(std::get<td::Ref<vm::CellSlice>>(acquired)));
      auto closure = block::read_workchain_account_closure(account.account, reads_only, 1000, 1000000, 1024);
      ASSERT_TRUE(std::holds_alternative<block::WorkchainInputUsage>(closure));
    }
    auto write_resources = full.policy().resources();
    write_resources.state.max_cells = reads_only.usage().cells;
    auto write_policy = block::ResolvedBatchInputPolicy::from_resolved_fields(write_resources, full.policy().identity());
    ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(write_policy));
    block::BatchInputAdmissionSession write_limited(std::get<block::ResolvedBatchInputPolicy>(write_policy),
        candidate, declaration_root, batch_identity, inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(write_limited.evaluate()));
    engine.calls = 0;
    auto write_denied = block::execute_workchain_account_engine(engine, state.accounts,
        std::get<block::AdmittedBatchInput>(write_limited.evaluate()));
    ASSERT_TRUE(write_denied.is_error());
    ASSERT_EQ(write_denied.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
    ASSERT_EQ(engine.calls, 0u);

    for (unsigned bound = 0; bound < 5; ++bound) {
      auto resources = full.policy().resources();
      switch (bound) {
        case 0: resources.state.max_cells = 1; break;
        case 1: resources.state.max_bits = 1; break;
        case 2: resources.state.max_account_cells = 1; break;
        case 3: resources.state.max_account_bits = 1; break;
        case 4: resources.state.max_account_depth = 1; break;
      }
      auto policy = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, full.policy().identity());
      ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(policy));
      block::BatchInputAdmissionSession bounded(std::get<block::ResolvedBatchInputPolicy>(policy),
          candidate, declaration_root, batch_identity, inbox);
      ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(bounded.evaluate()));
      engine.calls = 0;
      auto denied = block::execute_workchain_account_engine(engine, state.accounts,
          std::get<block::AdmittedBatchInput>(bounded.evaluate()));
      ASSERT_TRUE(denied.is_error());
      ASSERT_EQ(engine.calls, 0u);
      const auto expected = bound < 2 ? block::WorkchainExecutionFailure::CandidateInvalid :
                                       block::WorkchainExecutionFailure::AuthenticatedStateCorrupt;
      ASSERT_EQ(denied.error().code(), static_cast<int>(expected));
    }

    // Missing lookup data and missing closure data are distinct reached paths.
    unsigned missing_loads = 0;
    td::Ref<PreflightObservedCell> missing_root{true, state.accounts, &missing_loads, true};
    engine.calls = 0;
    auto missing_lookup = block::execute_workchain_account_engine(engine, missing_root, full);
    ASSERT_TRUE(missing_lookup.is_error());
    ASSERT_EQ(missing_lookup.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(missing_loads, 1u);
    ASSERT_EQ(engine.calls, 0u);

    auto entry = accounts.lookup(declarations.reads.front().account);
    vm::CellSlice prior(*entry);
    auto prior_account = prior.fetch_ref();
    unsigned account_loads = 0;
    td::Ref<PreflightObservedCell> missing_account{true, prior_account, &account_loads};
    vm::CellBuilder replaced;
    replaced.store_ref(missing_account).append_cellslice(prior);
    vm::AugmentedDictionary with_missing(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    ASSERT_TRUE(with_missing.set_builder(declarations.reads.front().account, replaced));
    auto missing_state = with_missing.get_wrapped_dict_root();
    ASSERT_EQ(missing_state->get_hash(), state.accounts->get_hash());
    missing_account->set_unavailable(true);
    account_loads = 0;
    engine.calls = 0;
    auto missing_closure = block::execute_workchain_account_engine(engine, missing_state, full);
    ASSERT_TRUE(missing_closure.is_error());
    ASSERT_EQ(missing_closure.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(account_loads, 1u);
    ASSERT_EQ(engine.calls, 0u);

    block::NativeStateReadMeter path_meter(256, 16384);
    auto path = block::lookup_workchain_account_metered(state.accounts, declarations.reads.front().account, path_meter,
        block::WorkchainAccountPathMode::Replace);
    ASSERT_TRUE(std::holds_alternative<td::Ref<vm::CellSlice>>(path));
    auto resources = full.policy().resources();
    resources.state.max_cells = path_meter.usage().cells;
    auto closure_policy = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, full.policy().identity());
    ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(closure_policy));
    block::BatchInputAdmissionSession closure_limited(std::get<block::ResolvedBatchInputPolicy>(closure_policy),
        candidate, declaration_root, batch_identity, inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(closure_limited.evaluate()));
    account_loads = 0;
    engine.calls = 0;
    auto exhausted_closure = block::execute_workchain_account_engine(engine, missing_state,
        std::get<block::AdmittedBatchInput>(closure_limited.evaluate()));
    ASSERT_TRUE(exhausted_closure.is_error());
    ASSERT_EQ(exhausted_closure.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
    // The entire lookup fits; the next account Cell is refused before its
    // unavailable loader can run. This distinguishes closure from lookup limits.
    ASSERT_EQ(account_loads, 0u);
    ASSERT_EQ(engine.calls, 0u);

    auto mismatched = declarations;
    mismatched.reads[0].old_account_hash = hash;
    auto wrong_root = block::encode_workchain_account_declarations(mismatched, 2, 2).move_as_ok();
    block::BatchInputAdmissionSession wrong_batch(inbox_test_policy(1, {100, 100000, 3}, 2, 2),
        candidate, wrong_root, batch_identity, inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(wrong_batch.evaluate()));
    engine.calls = 0;
    auto rejected = block::execute_workchain_account_engine(engine, state.accounts,
        std::get<block::AdmittedBatchInput>(wrong_batch.evaluate()));
    ASSERT_TRUE(rejected.is_error());
    ASSERT_TRUE(!block::workchain_execution_requires_local_failure(rejected.error()));
    ASSERT_EQ(engine.calls, 0u);
  }
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
  pricing.fwd_mc = block::MsgPrices(100, 0, 0, 0, 16384, 0);
  pricing.fwd_std = block::MsgPrices(200, 0, 0, 0, 16384, 0);
  auto settle = [&]() {
    return block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
        declarations, own_native_fixture({}), 2, 2, 0, 2, a, b, td::make_refint(500), 4096, cfg, pricing);
  };
  {
    const std::vector<td::Ref<vm::Cell>> empty_inbox;
    auto complete_identity = batch_test_identity(number(42));
    auto access = block::encode_workchain_account_declarations(declarations, 2, 2).move_as_ok();
    block::BatchInputAdmissionSession session(inbox_test_policy(1, {100, 100000, 3}, 2, 2),
        candidate, access, complete_identity, empty_inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(session.evaluate()));
    const auto& complete = std::get<block::AdmittedBatchInput>(session.evaluate());
    auto native = own_native_fixture({});
    engine.calls = 0;
    auto settled = block::execute_and_settle_workchain_accounts(engine, state.accounts,
        complete_identity, complete, native, a, b, td::make_refint(500), 4096, cfg, pricing);
    ASSERT_TRUE(settled.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_EQ(settled.ok().input->get_hash(), complete.root()->get_hash());
    ASSERT_TRUE(settled.ok().state.accounts->get_hash() != state.accounts->get_hash());
    ASSERT_EQ(engine.seen_input->get_hash(), complete.root()->get_hash());
    {
      // Each exception comes from the old-state loader, not candidate decoding.
      // VmError does not cover the other Native exception classes in this list.
      const std::vector<std::function<void()>> faults{
          [] { throw vm::VmError{vm::Excno::dict_err}; },
          [] { throw vm::VmVirtError{1}; },
          [] { throw vm::VmNoGas{}; },
          [] { throw vm::VmFatal{}; },
          [] { throw vm::CellBuilder::CellCreateError{}; },
          [] { throw vm::CellBuilder::CellWriteError{}; },
          [] { throw std::bad_alloc{}; },
          [] { throw std::length_error("injected state allocation length"); }};
      for (const auto& fault : faults) {
        unsigned loads = 0;
        td::Ref<vm::Cell> unavailable{td::Ref<StateReadCallbackCell>{true, state.accounts, [&] {
          ++loads;
          fault();
        }}};
        engine.calls = 0;
        auto refused = block::execute_workchain_account_engine(engine, unavailable, complete);
        ASSERT_EQ(loads, 1u);
        ASSERT_EQ(engine.calls, 0u);
        ASSERT_TRUE(refused.is_error());
        ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      }
      // Native initialization reads the dictionary root edge once for its
      // augmentation. Fail its subsequent lookup load, inside acquire(), not
      // the earlier prototype dictionary constructor outside the boundary.
      unsigned prototype_loads = 0;
      auto root_slice = vm::load_cell_slice(state.accounts);
      auto edge = root_slice.fetch_ref();
      td::Ref<vm::Cell> failing_edge{td::Ref<StateReadCallbackCell>{true, edge, [&] {
        if (++prototype_loads == 2) throw vm::VmError{vm::Excno::dict_err};
      }}};
      auto prototype_source = vm::CellBuilder().store_ref(failing_edge).append_cellslice(root_slice).finalize();
      ASSERT_EQ(prototype_source->get_hash(), state.accounts->get_hash());
      engine.calls = 0;
      bool prototype_exception = false;
      try {
        (void)block::execute_workchain_account_engine(engine, prototype_source, identity, admitted,
            declarations, {}, 2, 2, 0);
      } catch (const vm::VmError&) {
        prototype_exception = true;
      }
      ASSERT_EQ(prototype_loads, 2u);
      ASSERT_EQ(engine.calls, 0u);
      ASSERT_TRUE(prototype_exception);
      // A format predicate has stronger evidence than a loader throwing the
      // same generic VM error. The old source is the authenticated-state role
      // of this private fixture, not a candidate supplied to a live validator.
      auto malformed_root = vm::CellBuilder().finalize();
      engine.calls = 0;
      auto corrupt_root = block::execute_workchain_account_engine(engine, malformed_root, complete);
      ASSERT_TRUE(corrupt_root.is_error());
      ASSERT_EQ(corrupt_root.error().code(),
                static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
      ASSERT_EQ(engine.calls, 0u);

      auto entry = accounts.lookup(declarations.reads.front().account);
      vm::CellBuilder malformed_entry;
      malformed_entry.append_cellslice(*entry).store_long(0, 1);
      vm::AugmentedDictionary malformed_accounts(vm::load_cell_slice_ref(state.accounts), 256,
                                                 block::tlb::aug_ShardAccounts);
      ASSERT_TRUE(malformed_accounts.set_builder(declarations.reads.front().account, malformed_entry));
      ASSERT_EQ(malformed_accounts.lookup(declarations.reads.front().account)->size_ext(), 0x10141u);
      auto corrupt_entry = block::execute_workchain_account_engine(
          engine, malformed_accounts.get_wrapped_dict_root(), complete);
      ASSERT_TRUE(corrupt_entry.is_error());
      ASSERT_EQ(corrupt_entry.error().code(),
                static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
      ASSERT_EQ(engine.calls, 0u);

      // Force the first declared key's opposite sibling to be a fork, then
      // corrupt only that sibling's augmentation. Declared account hashes are
      // unchanged: this must fail in Replace-path admission, before the engine.
      vm::AugmentedDictionary branched(vm::load_cell_slice_ref(state.accounts), 256,
                                        block::tlb::aug_ShardAccounts);
      for (unsigned prefix : {0x80u, 0xc0u}) {
        auto key = td::Bits256::zero();
        key.as_slice()[0] = static_cast<char>(prefix);
        ASSERT_TRUE(branched.set(key, entry));
      }
      auto branched_root = branched.get_wrapped_dict_root();
      auto top_edge = vm::load_cell_slice(branched_root).prefetch_ref();
      vm::dict::LabelParser top{vm::load_cell_slice_ref(top_edge), 256,
                                vm::dict::LabelParser::chk_size};
      ASSERT_EQ(top.l_bits, 0);
      auto sibling = top.remainder->prefetch_ref(1);
      vm::dict::LabelParser sibling_label{vm::load_cell_slice_ref(sibling), 255,
                                          vm::dict::LabelParser::chk_size};
      ASSERT_TRUE(sibling_label.l_bits < 255);
      for (bool malformed_leaf : {false, true}) {
        auto bad_sibling = malformed_leaf
            ? vm::CellBuilder().store_long(6, 3).store_long(255, 8).finalize()
            : vm::CellBuilder().append_cellslice(vm::load_cell_slice(sibling)).store_ref(number(3)).finalize();
        auto edge_body = vm::load_cell_slice(top_edge);
        auto left = edge_body.fetch_ref();
        ASSERT_TRUE(edge_body.advance_refs(1));
        auto bad_edge = vm::CellBuilder().store_ref(left).store_ref(bad_sibling)
            .append_cellslice(edge_body).finalize();
        auto wrapper = vm::load_cell_slice(branched_root);
        ASSERT_TRUE(wrapper.advance_refs(1));
        auto bad_source = vm::CellBuilder().store_ref(bad_edge).append_cellslice(wrapper).finalize();
        auto corrupt_sibling = block::execute_workchain_account_engine(engine, bad_source, complete);
        ASSERT_TRUE(corrupt_sibling.is_error());
        ASSERT_EQ(corrupt_sibling.error().code(),
                  static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
        ASSERT_EQ(engine.calls, 0u);
      }

      // Fail only when the selected account closure is reached: construction
      // is healthy, the declared hash matches, and earlier lookup reads succeed.
      bool armed = false;
      unsigned closure_loads = 0, prior_loads = 0;
      vm::CellSlice prior(*entry);
      auto prior_account = prior.fetch_ref();
      td::Ref<vm::Cell> failing_account{td::Ref<StateReadCallbackCell>{true, prior_account, [&] {
        if (armed) {
          ++closure_loads;
          throw vm::VmError{vm::Excno::dict_err};
        }
      }}};
      vm::CellBuilder late_entry;
      late_entry.store_ref(failing_account).append_cellslice(prior);
      vm::AugmentedDictionary late_accounts(vm::load_cell_slice_ref(state.accounts), 256,
                                            block::tlb::aug_ShardAccounts);
      ASSERT_TRUE(late_accounts.set_builder(declarations.reads.front().account, late_entry));
      auto late_root = late_accounts.get_wrapped_dict_root();
      ASSERT_EQ(late_root->get_hash(), state.accounts->get_hash());
      td::Ref<vm::Cell> observed_root{td::Ref<StateReadCallbackCell>{true, late_root, [&] { ++prior_loads; }}};
      armed = true;
      auto late_failure = block::execute_workchain_account_engine(engine, observed_root, complete);
      ASSERT_TRUE(late_failure.is_error());
      ASSERT_EQ(late_failure.error().code(),
                static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      ASSERT_TRUE(prior_loads > 0);
      ASSERT_EQ(closure_loads, 1u);
      ASSERT_EQ(engine.calls, 0u);
      // The source-only boundary must not swallow the engine's exceptions.
      // The enclosing execution boundary still owes their classification.
      engine.calls = 0;
      engine.finish = [] { throw vm::VmError{vm::Excno::unknown}; };
      bool engine_exception = false;
      try {
        (void)block::execute_workchain_account_engine(engine, state.accounts, complete);
      } catch (const vm::VmError&) {
        engine_exception = true;
      }
      engine.finish = {};
      ASSERT_EQ(engine.calls, 1u);
      ASSERT_TRUE(engine_exception);
    }
    {
      // The private tree must not remain live in returned artifacts. A caller
      // can start a fresh proof and load an untouched account without nesting.
      vm::MerkleProofBuilder fresh(settled.ok().state.accounts);
      vm::AugmentedDictionary result_accounts(vm::load_cell_slice_ref(fresh.root()), 256,
                                              block::tlb::aug_ShardAccounts);
      block::tlb::ShardAccount::Record untouched;
      ASSERT_TRUE(untouched.unpack(result_accounts.lookup(td::Bits256(number(2)->get_hash().bits()))));
      (void)vm::load_cell_slice(untouched.account);
    }
    {
      vm::MerkleProofBuilder foreign(state.accounts);
      auto mixed = vm::CellBuilder().append_cellslice(vm::load_cell_slice(foreign.root())).finalize();
      ASSERT_TRUE(mixed->get_tree_node().empty());
      ASSERT_TRUE(!vm::load_cell_slice(mixed).prefetch_ref()->get_tree_node().empty());
      engine.calls = 0;
      auto refused = block::execute_and_settle_workchain_accounts(engine, mixed,
          complete_identity, complete, native, a, b, td::make_refint(500), 4096, cfg, pricing);
      ASSERT_TRUE(refused.is_error());
      ASSERT_EQ(engine.calls, 0u);
      ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      ASSERT_EQ(refused.error().message(), "authenticated settlement source has nested tracking");
    }
    {
      vm::MerkleProofBuilder tracked(state.accounts);
      engine.calls = 0;
      auto success = block::execute_and_settle_workchain_accounts(engine, tracked.root(),
          complete_identity, complete, native, a, b, td::make_refint(500), 4096, cfg, pricing);
      ASSERT_TRUE(success.is_ok());
      ASSERT_EQ(engine.calls, 1u);
      ASSERT_EQ(success.ok().state.accounts->get_hash(), settled.ok().state.accounts->get_hash());
      ASSERT_EQ(success.ok().state.account_blocks->get_hash(), settled.ok().state.account_blocks->get_hash());
    }
    {
      vm::MerkleProofBuilder tracked(state.accounts);
      vm::AugmentedDictionary tracked_accounts(vm::load_cell_slice_ref(tracked.root()), 256,
                                               block::tlb::aug_ShardAccounts);
      const td::Bits256 third(number(2)->get_hash().bits());
      block::tlb::ShardAccount::Record third_record;
      ASSERT_TRUE(third_record.unpack(tracked_accounts.lookup(third)));
      // Preload this unrelated account: a first-load-only observer would miss
      // the later unauthorized access, despite sharing the same proof tree.
      (void)vm::load_cell_slice(third_record.account);
      bool armed = false, injected = false;
      engine.finish = [&] { armed = true; };
      td::Ref<vm::Cell> observed{td::Ref<StateReadCallbackCell>{true, tracked.root(), [&] {
        if (armed && !injected) {
          injected = true;
          (void)vm::load_cell_slice(third_record.account);
        }
      }}};
      engine.calls = 0;
      auto refused = block::execute_and_settle_workchain_accounts(engine, observed,
          complete_identity, complete, native, a, b, td::make_refint(500), 4096, cfg, pricing);
      engine.finish = {};
      ASSERT_TRUE(injected);
      ASSERT_EQ(engine.calls, 1u);
      ASSERT_TRUE(refused.is_error());
      ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      ASSERT_EQ(refused.error().message(), "settlement read outside admitted old-state footprint");
    }
    auto replay_complete = [&](const block::WorkchainAccountSettlement& claim) {
      return block::replay_workchain_account_settlement(engine, state.accounts,
          complete_identity, complete, native, a, b, td::make_refint(500), 4096, cfg, pricing, claim);
    };
    engine.calls = 0;
    auto repeated_complete = replay_complete(settled.ok());
    ASSERT_TRUE(repeated_complete.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_EQ(repeated_complete.ok().state.accounts->get_hash(), settled.ok().state.accounts->get_hash());
    ASSERT_EQ(repeated_complete.ok().state.account_blocks->get_hash(), settled.ok().state.account_blocks->get_hash());
    auto wrong_claim = settled.ok();
    wrong_claim.input = candidate;
    engine.calls = 0;
    auto rejected_claim = replay_complete(wrong_claim);
    ASSERT_TRUE(rejected_claim.is_error());
    ASSERT_EQ(engine.calls, 0u);
    wrong_claim = settled.ok();
    wrong_claim.state.accounts = state.accounts;
    engine.calls = 0;
    ASSERT_TRUE(replay_complete(wrong_claim).is_error());
    ASSERT_EQ(engine.calls, 1u);
    auto wrong_identity = complete_identity;
    ++wrong_identity.height;  // Fixture value is 1, not a policy counter.
    engine.calls = 0;
    auto wrong_context = block::execute_and_settle_workchain_accounts(engine, state.accounts,
        wrong_identity, complete, native, a, b, td::make_refint(500), 4096, cfg, pricing);
    ASSERT_TRUE(wrong_context.is_error());
    ASSERT_EQ(engine.calls, 0u);
    const std::vector<td::Ref<vm::Cell>> incoming{inbound_envelope(0, 77, {}, b)};
    block::BatchInputAdmissionSession incoming_session(inbox_test_policy(1, {100, 100000, 4}, 2, 2),
        candidate, access, complete_identity, incoming);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(incoming_session.evaluate()));
    const auto& with_incoming = std::get<block::AdmittedBatchInput>(incoming_session.evaluate());
    auto incoming_native = own_native_fixture(incoming);
    engine.calls = 0;
    auto accepted_inbox = block::execute_and_settle_workchain_accounts(engine, state.accounts,
        complete_identity, with_incoming, incoming_native, a, b, td::make_refint(500), 4096, cfg, pricing);
    ASSERT_TRUE(accepted_inbox.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    for (unsigned mismatch = 0; mismatch < 3; ++mismatch) {
      const auto& admitted_inbox = mismatch == 0 ? complete : with_incoming;
      auto supplied = mismatch == 0 ? own_native_fixture(incoming) :
          mismatch == 1 ? own_native_fixture({}) : own_native_fixture({inbound_envelope(0, 78, {}, b)});
      engine.calls = 0;
      auto inconsistent = block::execute_and_settle_workchain_accounts(engine, state.accounts,
          complete_identity, admitted_inbox, supplied, a, b, td::make_refint(500), 4096, cfg, pricing);
      ASSERT_TRUE(inconsistent.is_error());
      ASSERT_EQ(engine.calls, 0u);
    }
  }
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
    // Enabling disposal must not disable the existing no-foreign-input payout
    // path. Compare full artifacts under the same unsplit identity.
    auto unsplit = identity;
    unsplit.shard_id = tos::shardIdAll;
    block::NativeDisposalProfile disposal_profile{block::NativeDisposalSource::OriginalDestination,
        {0, -block::ComputePhase::sk_no_state, {}}, false};
    block::WorkchainDisposalEntryContext disposal_context{a, pricing, workchains, disposal_profile, 0, 1};
    engine.calls = 0;
    auto enabled = block::execute_and_settle_workchain_disposal(engine, state.accounts, unsplit, admitted,
        declarations, own_native_fixture({}), 2, 2, 2, b, td::make_refint(500), 4096, cfg, disposal_context);
    ASSERT_TRUE(enabled.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    auto strict = block::execute_and_settle_workchain_accounts(engine, state.accounts, unsplit, admitted,
        declarations, own_native_fixture({}), 2, 2, 0, 2, a, b, td::make_refint(500), 4096, cfg, pricing).move_as_ok();
    ASSERT_EQ(engine.calls, 2u);
    ASSERT_EQ(enabled.ok().input->get_hash(), strict.input->get_hash());
    ASSERT_EQ(enabled.ok().state.accounts->get_hash(), strict.state.accounts->get_hash());
    ASSERT_EQ(enabled.ok().state.account_blocks->get_hash(), strict.state.account_blocks->get_hash());
    ASSERT_EQ(enabled.ok().imports.in_msg_descr->get_hash(), strict.imports.in_msg_descr->get_hash());
    ASSERT_EQ(enabled.ok().message.not_null(), with_payout);
    if (with_payout) ASSERT_EQ(enabled.ok().message->get_hash(), strict.message->get_hash());
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
    block::gen::UnoV2NativeEffects::Record_uno_v2_native_effects native;
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
      // Both roles import before applying the graph and priced payout. Pricing
      // must still enforce the independent old-custody principal envelope.
      auto imported_payout_input = block::encode_workchain_host_input(identity, admitted, declarations,
          {inbound_envelope(0, 0, {}, a), inbound_envelope(1, 1, {}, b)}, 2, 2, 2).move_as_ok();
      auto imported_pair = direct_pair(imported_payout_input, with_transfer, engine.payout, number(101)).move_as_ok();
      ASSERT_TRUE(imported_pair.transactions[0]->balance == block::CurrencyCollection(962));
      ASSERT_TRUE(imported_pair.transactions[1]->balance == block::CurrencyCollection(1001));
      ASSERT_TRUE(direct_pair(imported_payout_input, incoming_root, over_message, number(101)).is_error());
      // Old principal permits the payout, but the committed outgoing graph
      // must leave enough credited custody balance to fund it as well.
      auto depleted = unsupported_effects;
      depleted.native_transfers = {{a, b, block::CurrencyCollection(963)}};
      auto exact_funding = block::encode_workchain_account_effects(depleted, 2, 1, 4096).move_as_ok();
      auto exact_pair = direct_pair(imported_payout_input, exact_funding, engine.payout, number(101)).move_as_ok();
      ASSERT_TRUE(exact_pair.transactions[0]->balance == block::CurrencyCollection(0));
      ASSERT_TRUE(exact_pair.transactions[1]->balance == block::CurrencyCollection(1963));
      depleted.native_transfers = {{a, b, block::CurrencyCollection(964)}};
      auto insufficient_funding = block::encode_workchain_account_effects(depleted, 2, 1, 4096).move_as_ok();
      ASSERT_TRUE(direct_pair(imported_payout_input, insufficient_funding, engine.payout, number(101)).is_error());
      std::vector<block::WorkchainStorageWrite> payout_writes;
      for (std::size_t i = 0; i < declarations.writes.size(); ++i) {
        payout_writes.push_back({declarations.writes[i], *declarations.reads[i].old_account_hash,
                                number(i == 0 ? 101 : 102)});
      }
      auto late_input = block::encode_workchain_host_input(identity, admitted, declarations,
          {inbound_envelope(30, 1, {}, a), inbound_envelope(1, 2, 40, b)}, 2, 2, 2).move_as_ok();
      auto build_imported_payout = [&](std::uint64_t bound) {
        return block::build_workchain_payout_overlay(state.accounts, 2, identity.gen_utime,
            identity.host_after_lt, td::Bits256(late_input->get_hash().bits()),
            td::Bits256(with_transfer->get_hash().bits()), payout_writes, a, b, engine.payout,
            td::make_refint(500), 2, 2, 2, 4096, cfg, pricing, late_input, with_transfer, bound);
      };
      auto imported_overlay = build_imported_payout(2).move_as_ok();
      ASSERT_TRUE(build_imported_payout(1).is_error());
      ASSERT_EQ(imported_overlay.state.end_lt, 43u);
      ASSERT_TRUE(imported_overlay.imports.value_imported == block::CurrencyCollection(334));
      ASSERT_TRUE(imported_overlay.imports.fees_collected == block::CurrencyCollection(134));
      block::gen::CommonMsgInfo::Record_int_msg_info priced_imported_message;
      ASSERT_TRUE(tlb::unpack_cell_inexact(imported_overlay.message, priced_imported_message));
      ASSERT_EQ(priced_imported_message.created_lt, 42u);
      vm::AugmentedDictionary imported_accounts(vm::load_cell_slice_ref(imported_overlay.state.accounts), 256,
                                                 block::tlb::aug_ShardAccounts);
      vm::AugmentedDictionary imported_blocks(vm::load_cell_slice_ref(imported_overlay.state.account_blocks), 256,
                                               block::tlb::aug_ShardAccountBlocks);
      block::tlb::InMsgDescr imported_schema(16);
      ASSERT_TRUE(imported_schema.validate_ref(4096, imported_overlay.imports.in_msg_descr));
      vm::AugmentedDictionary imported_messages(vm::load_cell_slice_ref(imported_overlay.imports.in_msg_descr),
                                                 256, imported_schema.aug);
      std::map<td::Bits256, td::Ref<vm::Cell>> imported_transactions;
      for (auto key : {a, b}) {
        block::Account updated(2, key.bits());
        ASSERT_TRUE(updated.unpack(imported_accounts.lookup(key), identity.gen_utime, false));
        ASSERT_TRUE(updated.balance == block::CurrencyCollection(key == a ? 962 : 1001));
        ASSERT_TRUE(imported_overlay.imports.account_credits.at(key) == block::CurrencyCollection(100));
        ASSERT_EQ(updated.last_trans_lt_, 41u);
        ASSERT_EQ(updated.last_trans_end_lt_, key == a ? 43u : 42u);
        block::gen::AccountBlock::Record ab;
        ASSERT_TRUE(tlb::unpack_cell(vm::CellBuilder().append_cellslice(*imported_blocks.lookup(key)).finalize(), ab));
        vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
        auto tx_root = txs.lookup_ref(td::BitArray<64>(41u));
        ASSERT_TRUE(tx_root.not_null() && updated.last_trans_hash_ == tx_root->get_hash().bits());
        imported_transactions.emplace(key, tx_root);
      }
      ASSERT_TRUE(imported_messages.check_for_each([&](td::Ref<vm::CellSlice> row, td::ConstBitPtr, int) {
        block::tlb::MsgEnvelope::Record_std envelope;
        block::gen::CommonMsgInfo::Record_int_msg_info info;
        block::gen::MsgAddressInt::Record_addr_std destination;
        if (!tlb::unpack_cell(row->prefetch_ref(0), envelope) || !tlb::unpack_cell_inexact(envelope.msg, info) ||
            !block::gen::csr_unpack(info.dest, destination)) return false;
        auto found = imported_transactions.find(destination.address);
        return found != imported_transactions.end() && row->prefetch_ref(1)->get_hash() == found->second->get_hash();
      }));
      block::ClaimedWorkchainPayoutOverlay imported_claim{imported_overlay.state.accounts,
          imported_overlay.state.account_blocks, imported_overlay.message, imported_overlay.state.end_lt,
          imported_overlay.imports.in_msg_descr};
      auto replay_imported = [&](const auto& claim, std::uint64_t bound) {
        return block::replay_workchain_payout_overlay(state.accounts, 2, identity.gen_utime,
            identity.host_after_lt, td::Bits256(late_input->get_hash().bits()),
            td::Bits256(with_transfer->get_hash().bits()), payout_writes, a, b, engine.payout,
            td::make_refint(500), 2, 2, 2, 4096, cfg, pricing, claim, late_input, with_transfer, bound);
      };
      ASSERT_TRUE(replay_imported(imported_claim, 2).is_ok());
      ASSERT_TRUE(replay_imported(imported_claim, 1).is_error());
      for (unsigned field = 0; field < 5; ++field) {
        LOG(INFO) << "inbound payout replay mismatch field=" << field;
        auto changed = imported_claim;
        if (field == 0) changed.accounts = value.state.accounts;
        if (field == 1) changed.account_blocks = value.state.account_blocks;
        if (field == 2) changed.message = value.message;
        if (field == 3) changed.end_lt = value.state.end_lt;
        if (field == 4) changed.in_msg_descr = value.imports.in_msg_descr;
        ASSERT_TRUE(replay_imported(changed, 2).is_error());
      }
      block::ClaimedWorkchainPayoutOverlay claim{value.state.accounts, value.state.account_blocks,
                                                value.message, value.state.end_lt, value.imports.in_msg_descr};
      auto rebuilt = block::replay_workchain_payout_overlay(state.accounts, 2, identity.gen_utime,
          identity.host_after_lt, td::Bits256(value.input->get_hash().bits()),
          td::Bits256(value.effects->get_hash().bits()), payout_writes, a, b, engine.payout,
          td::make_refint(500), 2, 2, 2, 4096, cfg, pricing, claim, value.input, value.effects, 0).move_as_ok();
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
      // The unsupported destination is deliberately in the actual write set.
      // Zero principal prevents an independent missing-credit rejection from
      // hiding removal of the receiving-role restriction.
      auto receiving_role = [&](const td::Bits256& destination) {
        auto input = block::encode_workchain_host_input(identity, admitted, three,
            {inbound_envelope(30, 1, {}, destination, block::CurrencyCollection(0))}, 3, 3, 1).move_as_ok();
        return block::build_workchain_payout_overlay(state.accounts, 2, identity.gen_utime,
            identity.host_after_lt, td::Bits256(input->get_hash().bits()),
            td::Bits256(three_output->get_hash().bits()), three_writes, a, b,
            engine.payout, td::make_refint(500), 3, 3, 2, 4096, cfg, pricing, input, three_output, 1);
      };
      ASSERT_TRUE(receiving_role(b).is_ok());
      ASSERT_TRUE(receiving_role(third).is_error());
      auto construct_three = [&](const auto& writes, td::Ref<vm::Cell> input, td::Ref<vm::Cell> output,
                                  std::uint64_t after, std::uint64_t transfer_limit = 2) {
        return block::build_workchain_payout_overlay(state.accounts, 2, identity.gen_utime, after,
            td::Bits256(input->get_hash().bits()), td::Bits256(output->get_hash().bits()), writes, a, b,
            engine.payout, td::make_refint(500), 3, 3, transfer_limit, 4096, cfg, pricing, input, output, 0);
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
          mixed_three.state.account_blocks, mixed_three.message, mixed_three.state.end_lt, mixed_three.imports.in_msg_descr};
      auto replay_mixed = [&](const auto& claim) {
        return block::replay_workchain_payout_overlay(state.accounts, 2, identity.gen_utime,
            identity.host_after_lt, td::Bits256(three_input->get_hash().bits()),
            td::Bits256(mixed_output->get_hash().bits()), three_writes, a, b, engine.payout,
            td::make_refint(500), 3, 3, 1, 4096, cfg, pricing, claim, three_input, mixed_output, 0);
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
        declarations, own_native_fixture({}), 2, 2, 0, 2, a, b, td::make_refint(500), 4096, independent_storage, pricing).move_as_ok();
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
  const auto saved_payout = engine.payout;
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
      declarations, own_native_fixture({}), 2, 2, 0, 2, a, b, td::make_refint(500), 4096, wide_storage_cfg, pricing).is_ok());
  engine.with_transfer = false;
  engine.calls = 0;
  ASSERT_TRUE(block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
      declarations, own_native_fixture({}), 2, 2, 0, 2, a, b, td::make_refint(500), 0, cfg, pricing).is_error());
  ASSERT_EQ(engine.calls, 0u);
  auto unhandled_inbox = block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
      declarations, own_native_fixture({inbound_envelope(5, 0, {}, untouched)}), 2, 2, 1, 2, a, b,
      td::make_refint(500), 4096, cfg, pricing);
  ASSERT_TRUE(unhandled_inbox.is_error());
  ASSERT_EQ(engine.calls, 0u);
  std::vector<td::Ref<vm::Cell>> incoming{
      inbound_envelope(30, 1, {}, a, block::CurrencyCollection(17)),
      inbound_envelope(5, 2, 40, b, block::CurrencyCollection(23))};
  const auto owned = own_native_fixture(incoming);
  for (bool payout : {false, true}) {
    engine.payout = payout ? saved_payout : td::Ref<vm::Cell>{};
    engine.calls = 0;
    auto result = block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
        declarations, owned, 2, 2, 2, 2, a, b, td::make_refint(500), 4096, cfg, pricing).move_as_ok();
    ASSERT_EQ(engine.calls, 1u);
    auto expected = block::encode_workchain_host_input(identity, admitted, declarations, incoming, 2, 2, 2).move_as_ok();
    ASSERT_TRUE(result.input->get_hash() == expected->get_hash());
    ASSERT_TRUE(engine.seen_input->get_hash() == expected->get_hash());
    ASSERT_TRUE(result.imports.value_imported == block::CurrencyCollection(174));
    ASSERT_TRUE(result.imports.fees_collected == block::CurrencyCollection(134));
    ASSERT_TRUE(result.imports.account_credits.at(a) == block::CurrencyCollection(17));
    ASSERT_TRUE(result.imports.account_credits.at(b) == block::CurrencyCollection(23));
    ASSERT_EQ(result.message.not_null(), payout);
    block::tlb::InMsgDescr import_schema(cfg.global_version);
    ASSERT_TRUE(import_schema.validate_ref(4096, result.imports.in_msg_descr));
    vm::AugmentedDictionary imports(vm::load_cell_slice_ref(result.imports.in_msg_descr), 256, import_schema.aug);
    for (const auto& cell : incoming) {
      block::tlb::MsgEnvelope::Record_std envelope;
      ASSERT_TRUE(tlb::unpack_cell(cell, envelope));
      ASSERT_TRUE(imports.lookup(envelope.msg->get_hash().bits(), 256).not_null());
    }
    vm::AugmentedDictionary next(vm::load_cell_slice_ref(result.state.accounts), 256, block::tlb::aug_ShardAccounts);
    for (auto key : {a, b}) {
      block::Account account(2, key.bits());
      ASSERT_TRUE(account.unpack(next.lookup(key), identity.gen_utime, false));
      ASSERT_TRUE(account.balance == block::CurrencyCollection(key == a ? (payout ? 880 : 1017) : (payout ? 923 : 1023)));
      ASSERT_TRUE(account.last_trans_lt_ > 40);
    }
    ASSERT_TRUE(state.accounts->get_hash() == old_accounts_hash);
    auto reversed = own_native_fixture({incoming[1], incoming[0]});
    auto replay = block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
        declarations, reversed, 2, 2, 2, 2, a, b, td::make_refint(500), 4096, cfg, pricing).move_as_ok();
    ASSERT_EQ(engine.calls, 2u); // Exactly once in each independent execution context.
    ASSERT_TRUE(replay.input->get_hash() == result.input->get_hash());
    ASSERT_TRUE(replay.state.accounts->get_hash() == result.state.accounts->get_hash());
    ASSERT_TRUE(replay.state.account_blocks->get_hash() == result.state.account_blocks->get_hash());
    ASSERT_TRUE(replay.imports.in_msg_descr->get_hash() == result.imports.in_msg_descr->get_hash());
    auto verify_claim = [&](const auto& claim) {
      return block::replay_workchain_account_settlement(engine, state.accounts, identity, admitted,
          declarations, owned, 2, 2, 2, 2, a, b, td::make_refint(500), 4096, cfg, pricing, claim);
    };
    engine.calls = 0;
    auto checked = verify_claim(result);
    ASSERT_TRUE(checked.is_ok());
    ASSERT_EQ(engine.calls, 1u);
    ASSERT_TRUE(checked.ok().state.accounts->get_hash() == result.state.accounts->get_hash());
    // Derived caches are not independent wire claims and cannot replace replay.
    auto poisoned = result;
    poisoned.imports.value_imported = block::CurrencyCollection(999);
    poisoned.imports.fees_collected = block::CurrencyCollection(998);
    poisoned.imports.account_credits.clear();
    auto recovered = verify_claim(poisoned).move_as_ok();
    ASSERT_TRUE(recovered.imports.value_imported == block::CurrencyCollection(174));
    ASSERT_TRUE(recovered.imports.fees_collected == block::CurrencyCollection(134));
    ASSERT_TRUE(recovered.imports.account_credits.at(a) == block::CurrencyCollection(17));
    for (unsigned field = 0; field < 8; ++field) {
      if (field == 7 && !payout) continue;
      LOG(INFO) << "full settlement replay mismatch payout=" << payout << " field=" << field;
      auto claim = result;
      if (field == 0) claim.input = allocated.input;
      if (field == 1) claim.effects = allocated.effects;
      if (field == 2) claim.state.accounts = state.accounts;
      if (field == 3) claim.state.account_blocks = allocated.state.account_blocks;
      if (field == 4) claim.imports.in_msg_descr = allocated.imports.in_msg_descr;
      if (field == 5) claim.state.end_lt = 0;
      if (field == 6) claim.message = payout ? td::Ref<vm::Cell>{} : number(1);
      if (field == 7) {
        block::tlb::MsgEnvelope::Record_std other;
        ASSERT_TRUE(tlb::unpack_cell(incoming[0], other));
        claim.message = other.msg; // A different, structurally valid Native message.
      }
      // The no-payout fixture has unchanged effects; select a distinct but
      // valid encoded effects cell for this field rather than testing equality.
      if (field == 1 && !payout) {
        auto altered = block::WorkchainAccountEffects{};
        altered.updates = {{a, number(900)}, {b, number(901)}};
        std::sort(altered.updates.begin(), altered.updates.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.account < rhs.account; });
        claim.effects = block::encode_workchain_account_effects(altered, 2, 2, 4096).move_as_ok();
      }
      engine.calls = 0;
      ASSERT_TRUE(verify_claim(claim).is_error());
      ASSERT_EQ(engine.calls, field == 0 ? 0u : 1u);
      ASSERT_TRUE(state.accounts->get_hash() == old_accounts_hash);
    }
    for (unsigned field = 0; field < 5; ++field) {
      auto claim = result;
      if (field == 0) claim.input.clear();
      if (field == 1) claim.effects.clear();
      if (field == 2) claim.state.accounts.clear();
      if (field == 3) claim.state.account_blocks.clear();
      if (field == 4) claim.imports.in_msg_descr.clear();
      engine.calls = 0;
      ASSERT_TRUE(verify_claim(claim).is_error());
      ASSERT_EQ(engine.calls, 0u);
    }
  }
  engine.calls = 0;
  ASSERT_TRUE(block::execute_and_settle_workchain_accounts(engine, state.accounts, identity, admitted,
      declarations, owned, 2, 2, 1, 2, a, b, td::make_refint(500), 4096, cfg, pricing).is_error());
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

TEST(WorkchainBlock, StorageFixtureDictionaryContracts) {
  const auto first = td::Bits256::zero();
  auto second = first;
  second.as_slice()[0] = 1;
  const auto empty = block::test::FixtureDictionary{};
  auto staged = empty.with_entries({first, second}).move_as_ok();
  ASSERT_EQ(empty.size(), 0u);
  ASSERT_EQ(staged.size(), 2u);
  ASSERT_TRUE(empty.root().is_null());
  ASSERT_TRUE(staged.contains(first));
  ASSERT_TRUE(staged.contains(second));
  ASSERT_TRUE(staged.with_entries({first}).is_error());
  ASSERT_TRUE(block::test::FixtureDictionary::from_root(staged.root(), 1).is_error());
  auto loaded = block::test::FixtureDictionary::from_root(staged.root(), 2).move_as_ok();
  ASSERT_EQ(loaded.size(), 2u);
  ASSERT_TRUE(loaded.root()->get_hash() == staged.root()->get_hash());
  ASSERT_EQ(block::test::FixtureDictionary::from_root({}, 0).move_as_ok().size(), 0u);
  vm::Dictionary nonempty_value(256);
  vm::CellBuilder payload;
  payload.store_long(1, 1);
  ASSERT_TRUE(nonempty_value.set_builder(first, payload));
  ASSERT_TRUE(block::test::FixtureDictionary::from_root(nonempty_value.get_root_cell(), 1).is_error());
}

TEST(WorkchainBlock, FixtureDictionaryReachesNativeAccountLimit) {
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
    auto used = block::test::FixtureDictionary{}.with_entries(
        std::vector<td::Bits256>(keys.begin(), keys.begin() + count)).move_as_ok();
    auto effects = CounterEngine().execute_block(in).move_as_ok();
    // Generic dictionary fixture measures Native account admission, not a
    // confidential account schema or a production capacity recommendation.
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
  LOG(INFO) << "Fixture dictionary host capacity: accepted=" << lower << " rejected=" << upper
            << " account_cell_limit=" << cfg.size_limits.max_acc_state_cells
            << " scope=test dictionary plus host wrapper; not confidential account state";
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
      a, b, request, td::make_refint(500), 4, 4, 2, 0, cfg, pricing, {}, {}, 0).is_error());
  ASSERT_EQ(state_loads, 0u);
  ASSERT_TRUE(block::build_workchain_payout_overlay(observed_state, 2, 10, 20, a, b, writes,
      a, b, request, td::make_refint(500), 4, 4, std::numeric_limits<std::uint64_t>::max(),
      4096, cfg, pricing, {}, {}, 0).is_error());
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
        a, b, request, td::make_refint(500), 4, 4, 2, budget, config, pricing, {}, {}, 0);
  };
  auto ample_overlay = extra_overlay(4096, cfg).move_as_ok();
  ASSERT_TRUE(extra_overlay(1, cfg).is_error());
  auto alternate_storage = cfg;
  alternate_storage.size_limits.max_acc_state_cells = 32768;
  auto independent_overlay = extra_overlay(4096, alternate_storage).move_as_ok();
  ASSERT_TRUE(ample_overlay.state.accounts->get_hash() == independent_overlay.state.accounts->get_hash());
  ASSERT_TRUE(ample_overlay.state.account_blocks->get_hash() == independent_overlay.state.account_blocks->get_hash());
  block::ClaimedWorkchainPayoutOverlay extra_claim{ample_overlay.state.accounts, ample_overlay.state.account_blocks,
      ample_overlay.message, ample_overlay.state.end_lt, ample_overlay.imports.in_msg_descr};
  ASSERT_TRUE(block::replay_workchain_payout_overlay(extra_state, 2, 10, 20, a, b, extra_writes,
      a, b, request, td::make_refint(500), 4, 4, 2, 1, cfg, pricing, extra_claim, {}, {}, 0).is_error());
  auto overlay = block::build_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, writes,
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {}, 0);
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
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {}, 0);
  ASSERT_TRUE(repeat.is_ok());
  ASSERT_TRUE(repeat.ok().state.accounts->get_hash() == materialized.state.accounts->get_hash());
  ASSERT_TRUE(repeat.ok().state.account_blocks->get_hash() == materialized.state.account_blocks->get_hash());
  block::ClaimedWorkchainPayoutOverlay claim{materialized.state.accounts, materialized.state.account_blocks,
                                           materialized.message, materialized.state.end_lt, materialized.imports.in_msg_descr};
  auto replay = [&](const block::ClaimedWorkchainPayoutOverlay& claimed) {
    return block::replay_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, writes,
        b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, claimed, {}, {}, 0);
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
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {}, 0).is_error());
  auto invalid_writes = writes;
  for (auto& write : invalid_writes) if (write.account == third) write.data.clear();
  ASSERT_TRUE(block::build_workchain_payout_overlay(larger.accounts, 2, 10, 20, a, b, invalid_writes,
      b, a, request, td::make_refint(500), 4, 4, 2, 4096, cfg, pricing, {}, {}, 0).is_error());
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

TEST(WorkchainBlock, MissingImportEnumeratorIsLocalFailure) {
  InboxWorkspaceProbe workspace;
  bool escaped = false;
  bool local_failure = false;
  try {
    auto result = block::workchain_batch_inbound_from_candidate_imports({}, workspace);
    local_failure = result.is_error() && block::workchain_execution_requires_local_failure(result.error());
  } catch (const std::bad_function_call&) {
    escaped = true;
  }
  ASSERT_TRUE(!escaped);
  ASSERT_TRUE(local_failure);
  ASSERT_EQ(workspace.allocations, 0u);
}

TEST(WorkchainBlock, ImportEnumeratorStateFaultIsLocalFailure) {
  InboxWorkspaceProbe workspace;
  auto result = block::workchain_batch_inbound_from_candidate_imports(
      [](const block::CandidateImportVisitor&) -> bool {
        // Fault injection for an authenticated-state access captured by a host
        // callback. An untyped callback exception cannot prove candidate fault.
        throw vm::VmError{vm::Excno::dict_err};
      }, workspace);
  ASSERT_TRUE(result.is_error());
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(result.error()));
  ASSERT_EQ(workspace.allocations, 0u);
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

  InboxWorkspaceProbe workspace;
  auto streamed = block::workchain_batch_inbound_from_candidate_imports(
      [&](const block::CandidateImportVisitor& visit) {
        for (const auto& root : {deferred, transit, routed, final}) {
          if (!visit(vm::load_cell_slice_ref(root))) return false;
        }
        return true;
      }, workspace);
  ASSERT_TRUE(streamed.is_ok());
  ASSERT_TRUE(streamed.ok()->get_hash() == expected->get_hash());
  InboxWorkspaceProbe no_retained;
  auto transit_only = block::workchain_batch_inbound_from_candidate_imports(
      [&](const block::CandidateImportVisitor& visit) { return visit(vm::load_cell_slice_ref(transit)); }, no_retained);
  ASSERT_TRUE(transit_only.is_ok() && transit_only.ok().is_null());
  ASSERT_EQ(no_retained.allocations, 0u);

  unsigned visited = 0;
  auto excessive = block::workchain_batch_inbound_from_candidate_imports(
      [&](const block::CandidateImportVisitor& visit) {
        for (unsigned i = 0; i < 32769; ++i) {
          ++visited;
          if (!visit(vm::load_cell_slice_ref(final))) return false;
        }
        return true;
      }, workspace);
  ASSERT_TRUE(excessive.is_error());
  ASSERT_TRUE(workspace.max_allocation / sizeof(td::Ref<vm::Cell>) <= 32767);
  ASSERT_EQ(visited, 32768u);  // First excess is probed, never retained; no further enumeration.
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
  produced.usage = {101, 102, 103};
  auto distinct = block::encode_workchain_block_result(produced).move_as_ok();
  auto decoded = block::decode_workchain_block_result(distinct).move_as_ok();
  ASSERT_TRUE(decoded.usage == produced.usage);
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

TEST(WorkchainBlock, DualNativeIngressCodecAndVersion) {
  // Explicit codec/resolver fixture instance. This representable wire value
  // does not authenticate an installation or claim a production-issued identity.
  const auto fixture_instance = td::Bits256::ones();
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address = td::Bits256::zero();
  policy.custody_address = td::Bits256::ones();
  block::WorkchainResourcePolicy resources{2, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
  auto business = vm::CellBuilder().store_long(0x12345678, 32).finalize();
  policy.engine_configuration = block::encode_workchain_engine_parameters({400, fixture_instance, resources, business, 10000000000ULL}).move_as_ok();
  auto encoded = block::encode_workchain_native_ingress_policy(policy);
  ASSERT_TRUE(encoded.is_ok());
  auto root = encoded.move_as_ok();
  ASSERT_EQ(vm::load_cell_slice(root).size(), 737u);
  ASSERT_TRUE(block::gen::t_WorkchainNativeIngressPolicy.validate_ref(10000, root));
  // The generated CRC tag and field encoder are independent of the hand codec.
  block::gen::WorkchainNativeIngressPolicy::Record_workchain_native_ingress_v2 record;
  ASSERT_TRUE(tlb::unpack_cell(root, record));
  ASSERT_TRUE(record.custody_address == *policy.custody_address);
  td::Ref<vm::Cell> repacked;
  ASSERT_TRUE(tlb::pack_cell(repacked, record));
  ASSERT_TRUE(repacked->get_hash() == root->get_hash());
  auto decoded = block::decode_workchain_native_ingress_policy(repacked);
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_TRUE(decoded.ok().custody_address == policy.custody_address);
  auto same_role = policy;
  same_role.custody_address = policy.executor_address;
  ASSERT_TRUE(block::encode_workchain_native_ingress_policy(same_role).is_error());
  record.custody_address = policy.executor_address;
  ASSERT_TRUE(tlb::pack_cell(repacked, record));
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(repacked).is_error());
  auto trailing = vm::CellBuilder().append_cellslice(vm::load_cell_slice(root)).store_long(0, 1).finalize();
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(trailing).is_error());
  auto truncated = vm::CellBuilder().store_long(0x4abd5ab4, 32).store_zeroes(449)
      .store_ref(policy.engine_configuration).finalize();
  ASSERT_TRUE(block::decode_workchain_native_ingress_policy(truncated).is_error());

  for (unsigned version : {15u, 16u}) {
    vm::Dictionary config(32);
    vm::CellBuilder cfg_version;
    ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(cfg_version, version, tos::capBlockTransition));
    ASSERT_TRUE(config.set_ref(td::BitArray<32>{8}, cfg_version.finalize()));
    ASSERT_TRUE(config.set_ref(td::BitArray<32>{84},
        block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
    ASSERT_EQ(block::validate_native_ingress_presence(config).is_ok(), version == 16);
    auto unpacked = block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
                                                block::Config::needCapabilities);
    ASSERT_TRUE(unpacked.is_ok());
    ASSERT_EQ(block::load_workchain_native_ingress_table(*unpacked.ok()).is_ok(), version == 16);
    if (version == 16) {
      block::WorkchainExecutionRegistry registry;
      ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
      block::WorkchainExecutionDescriptor descriptor;
      descriptor.workchain_id = 2;
      descriptor.active = true;
      descriptor.vm_version = 0x434e5431;
      ASSERT_TRUE(registry.resolve_block(descriptor, *unpacked.ok()).is_error());
      policy.custody_address.reset();
      // Singleton and dual policies share framing; Counter business parameters are empty.
      policy.engine_configuration = counter_configuration_shell(vm::CellBuilder().finalize());
      ASSERT_TRUE(config.set_ref(td::BitArray<32>{84},
          block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
      auto legacy = block::Config::unpack_config(config.get_root_cell(), td::Bits256::zero(),
                                               block::Config::needCapabilities);
      ASSERT_TRUE(legacy.is_ok());
      ASSERT_TRUE(registry.resolve_block(descriptor, *legacy.ok()).is_ok());
    }
  }
}

TEST(WorkchainBlock, MultiAccountAdmissionVersionInstallation) {
  // Explicit codec/resolver fixture instance. This representable wire value
  // does not authenticate an installation or claim a production-issued identity.
  const auto fixture_instance = td::Bits256::ones();
  vm::Dictionary configuration(32);
  // A complete, test-only configuration makes this exercise valid_config_data,
  // not merely its resource-policy helper. None of these values are defaults.
  auto put = [&](unsigned index, td::Ref<vm::Cell> value) {
    ASSERT_TRUE(configuration.set_ref(td::BitArray<32>{index}, std::move(value)));
  };
  put(0, vm::CellBuilder().store_zeroes(256).finalize());
  vm::Dictionary storage(32);
  vm::CellBuilder storage_price;
  storage_price.store_long(0xcc, 8).store_zeroes(288);
  ASSERT_TRUE(storage.set_builder(td::BitArray<32>::zero(), storage_price));
  put(18, storage.get_root_cell());
  for (unsigned index : {20u, 21u}) {
    put(index, vm::CellBuilder().store_long(0xdd, 8).store_zeroes(384).finalize());
  }
  for (unsigned index : {22u, 23u}) {
    vm::CellBuilder limits;
    limits.store_long(0x5d, 8);
    for (unsigned field = 0; field < 3; ++field) limits.store_long(0xc3, 8).store_zeroes(96);
    put(index, limits.finalize());
  }
  for (unsigned index : {24u, 25u}) {
    put(index, vm::CellBuilder().store_long(0xea, 8).store_zeroes(256).finalize());
  }
  put(28, vm::CellBuilder().store_long(0xc1, 8).store_long(1, 32).store_long(1, 32)
      .store_long(1, 32).store_long(1, 32).finalize());
  vm::Dictionary validators(16);
  vm::CellBuilder validator;
  validator.store_long(0x53, 8).store_long(0x8e81278a, 32).store_zeroes(256).store_long(1, 64);
  ASSERT_TRUE(validators.set_builder(td::BitArray<16>::zero(), validator));
  vm::CellBuilder validator_set;
  validator_set.store_long(0x12, 8).store_long(0, 32).store_long(1, 32)
      .store_long(1, 16).store_long(1, 16).store_long(1, 64);
  ASSERT_TRUE(validators.append_dict_to_bool(validator_set));
  put(34, validator_set.finalize());
  ASSERT_TRUE(block::valid_config_data(configuration.get_root_cell(), td::Bits256::zero()));
  vm::CellBuilder version;
  ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(version, 16, tos::capBlockTransition));
  ASSERT_TRUE(configuration.set_ref(td::BitArray<32>{8}, version.finalize()));
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = {block::WorkchainFormat::Basic, 0x434e5431};
  policy.executor_address = td::Bits256::zero();
  policy.custody_address = td::Bits256::ones();
  vm::CellBuilder descriptor;
  descriptor.store_long(0xa6, 8).store_zeroes(32 + 24)
      .store_long(1, 1).store_long(1, 1).store_long(0, 1)
      .store_zeroes(13 + 512).store_long(policy.descriptor_version, 32).store_long(1, 4)
      .store_long(policy.engine_key.selector, 32).store_long(0, 64);
  vm::Dictionary workchains(32);
  ASSERT_TRUE(workchains.set(td::BitArray<32>{2}, vm::load_cell_slice_ref(descriptor.finalize())));
  vm::CellBuilder workchain_list;
  ASSERT_TRUE(workchains.append_dict_to_bool(workchain_list));
  put(12, workchain_list.finalize());
  auto business = vm::CellBuilder().store_long(0x12345678, 32).finalize();
  for (std::uint32_t admission : {0u, 1u, 2u, 3u, 4u, 5u, 0x10002u, 0x10003u, 0x10004u, 0x80000002u}) {
    block::WorkchainResourcePolicy resources{admission, {64,4096,8,16,16,5},
        {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
    policy.engine_configuration = block::encode_workchain_engine_parameters({400, fixture_instance, resources, business, 10000000000ULL}).move_as_ok();
    ASSERT_TRUE(configuration.set_ref(td::BitArray<32>{84},
        block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
    ASSERT_EQ(block::validate_native_ingress_presence(configuration).is_ok(), admission == 2 || admission == 3 || admission == 4);
    ASSERT_EQ(block::valid_config_data(configuration.get_root_cell(), td::Bits256::zero()), admission == 2 || admission == 3 || admission == 4);
  }
  // Every semantic zero is rejected at installation, before candidate admission.
  for (unsigned field = 0; field < 13; ++field) {
    block::WorkchainResourcePolicy resources{2, {64,4096,8,16,16,5},
        {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
    if (field == 0) resources.input.max_reads = 0;
    if (field == 1) resources.input.max_writes = 0;
    if (field == 2) resources.input.max_inbound = 0;
    if (field == 3) resources.state.max_cells = 0;
    if (field == 4) resources.state.max_bits = 0;
    if (field == 5) resources.state.max_account_cells = 0;
    if (field == 6) resources.state.max_account_bits = 0;
    if (field == 7) resources.state.max_account_depth = 0;
    if (field == 8) resources.work_output.max_effect_cells = 0;
    if (field == 9) resources.work_output.max_effect_bits = 0;
    if (field == 10) resources.work_output.max_output_cells = 0;
    if (field == 11) resources.work_output.max_output_bits = 0;
    if (field == 12) resources.preflight_allowance = 0;
    policy.engine_configuration = block::encode_workchain_engine_parameters({400, fixture_instance, resources, business, 10000000000ULL}).move_as_ok();
    ASSERT_TRUE(configuration.set_ref(td::BitArray<32>{84},
        block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
    ASSERT_TRUE(!block::valid_config_data(configuration.get_root_cell(), td::Bits256::zero()));
  }
  // Exercise the actual installation path: it does not call the resolved-policy
  // factory, so factory-only controls cannot establish installation rejection.
  for (std::uint64_t allowance : {std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{2},
                                  std::uint64_t{3}, std::uint64_t{1} << 32}) {
    block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
        {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {0,2,2}, allowance};
    policy.engine_configuration = block::encode_workchain_engine_parameters(
        {400, fixture_instance, resources, business, 10000000000ULL}).move_as_ok();
    ASSERT_TRUE(configuration.set_ref(td::BitArray<32>{84},
        block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
    auto installed = block::validate_native_ingress_presence(configuration);
    const bool valid = allowance == 1 || allowance == 2;
    ASSERT_EQ(installed.is_ok(), valid);
    if (allowance == 0) {
      ASSERT_EQ(installed.error().message(), "zero multi-account input bound in configuration");
    } else if (!valid) {
      ASSERT_EQ(installed.error().message(), "preflight allowance exceeds block budget in configuration");
    }
    ASSERT_EQ(block::valid_config_data(configuration.get_root_cell(), td::Bits256::zero()), valid);
  }
  // Missing either mandatory reference is rejected by the installation gate.
  for (unsigned refs = 0; refs < 2; ++refs) {
    vm::CellBuilder malformed;
    malformed.store_long(block::gen::UnoV2EngineConfiguration::cons_tag[0], 32).store_long(400, 32).store_long(10000000000LL, 64).store_bits(fixture_instance.bits(), 256);
    if (refs) malformed.store_ref(business);
    policy.engine_configuration = malformed.finalize();
    ASSERT_TRUE(configuration.set_ref(td::BitArray<32>{84},
        block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
    ASSERT_TRUE(block::validate_native_ingress_presence(configuration).is_error());
  }
}

TEST(WorkchainBlock, AccountRegistryReplayConnectivity) {
  // Explicit codec/resolver fixture instance. This representable wire value
  // does not authenticate an installation or claim a production-issued identity.
  const auto fixture_instance = td::Bits256::ones();
  // Connectivity only: a local registry and explicit synthetic parameters.
  // No live actor gate is opened and no confidential proof is implemented here.
  struct Parameters final : block::WorkchainEngineConfig {
    explicit Parameters(std::uint64_t value) : value(value) {}
    std::uint64_t value;
  };
  struct Engine final : block::RegisteredWorkchainAccountEngine {
    td::Bits256 a, b;
    mutable td::uint64 configs{0}, inspections{0}, executions{0};
    mutable const block::WorkchainEngineConfig* inspected_config{nullptr};
    mutable const block::WorkchainEngineConfig* executed_config{nullptr};
    mutable std::weak_ptr<const block::WorkchainEngineConfig> config_lifetime;
    mutable std::uint64_t metered_calls{0}, last_consumed{0};
    bool attempt_proof{false};
    td::Result<block::WorkchainAccountEffects> execute_metered_accounts(
        const td::Ref<vm::Cell>& input, block::WorkchainAccountReadView& view,
        const block::WorkchainEngineConfig& configuration, block::WorkchainProofVerifier& proofs) const override {
      ++metered_calls;
      if (attempt_proof) {
        UnoCryptoVerifyRequestV2 request{};
        request.abi_version = UNO_BALANCE_ABI_VERSION;
        request.relation = UNO_RELATION_SEND;
        request.limits = {100, 100, 8, 1024, 4096};
        request.context_bytes = 1;
        request.point_count = 10;
        request.commitment_count = 8;
        request.response_count = 6;
        request.proof_bytes = 864;
        // Deliberately ignore the error. Only the runner's sticky status can
        // stop successful-looking effects escaping this fixture's violation.
        auto ignored = proofs.verify(request);
        ASSERT_TRUE(ignored.is_error());
      }
      last_consumed = proofs.consumed();
      return execute_accounts(input, view, configuration);
    }
    block::WorkchainEngineKey engine_key() const override {
      return {block::WorkchainFormat::Basic, 0x434e5431};
    }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&,
        const td::Ref<vm::Cell>& payload) const override {
      TRY_RESULT(next, block::participant_lt_detail::checked_add(configs, 1));
      configs = next;
      TRY_RESULT(parsed, block::decode_workchain_engine_parameters(payload));
      bool special = false;
      auto cs = vm::load_cell_slice_special(parsed.parameters, special);
      if (special || cs.size_ext() != 40 || cs.fetch_ulong(32) != 0x50524231) {
        return td::Status::Error("invalid connectivity parameters");
      }
      auto config = std::make_shared<Parameters>(cs.fetch_ulong(8));
      config_lifetime = config;
      return std::shared_ptr<const block::WorkchainEngineConfig>(std::move(config));
    }
    td::Result<std::uint64_t> proof_work(
        const td::Ref<vm::Cell>&, const block::InputPolicyIdentity&,
        const block::WorkchainEngineConfig& configuration) const override {
      TRY_RESULT(next, block::participant_lt_detail::checked_add(inspections, 1));
      inspections = next;
      inspected_config = &configuration;
      const auto* config = dynamic_cast<const Parameters*>(&configuration);
      if (!config) return td::Status::Error(
          static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable), "wrong connectivity config type");
      return config->value;  // Synthetic declared units, not cryptographic work.
    }
    td::Result<block::WorkchainAccountEffects> execute_accounts(
        const td::Ref<vm::Cell>&, block::WorkchainAccountReadView& view,
        const block::WorkchainEngineConfig& configuration) const override {
      TRY_RESULT(next, block::participant_lt_detail::checked_add(executions, 1));
      executions = next;
      executed_config = &configuration;
      const auto* config = dynamic_cast<const Parameters*>(&configuration);
      if (!config) return td::Status::Error(
          static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable), "wrong connectivity config type");
      TRY_RESULT(first, view.read(a));
      TRY_RESULT(second, view.read(b));
      if (first.is_null() || second.is_null()) return td::Status::Error("missing connectivity account");
      block::WorkchainAccountEffects effects;
      effects.updates = {{a, number(config->value)}, {b, number(config->value)}};
      return effects;
    }
  };
  const auto a = td::Bits256::zero();
  const td::Bits256 b(number(1)->get_hash().bits());
  auto engine = std::make_unique<Engine>();
  engine->a = a;
  engine->b = b;
  auto* observed = engine.get();
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_account_engine(std::move(engine)).is_ok());
  static_assert(!std::is_base_of_v<block::WorkchainAccountEngine, block::RegisteredWorkchainAccountEngine>);

  block::WorkchainResourcePolicy resources{2, {100,100000,3,2,2,1},
      {256,16384,128,8192,64}, {64,128,8192,256,65536,16}, {1, 32, 64}, 7};
  block::WorkchainNativeIngressPolicy ingress;
  ingress.workchain_id = 2;
  ingress.engine_key = observed->engine_key();
  ingress.descriptor_version = 5;
  ingress.vm_mode = 7;
  ingress.executor_address = a;
  ingress.custody_address = b;
  ingress.engine_configuration = block::encode_workchain_engine_parameters({400, fixture_instance, resources,
      vm::CellBuilder().store_long(0x50524231,32).store_long(37,8).finalize(), 10000000000ULL}).move_as_ok();
  vm::Dictionary config_dict(32);
  vm::CellBuilder version;
  ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(version, 16, tos::capBlockTransition));
  ASSERT_TRUE(config_dict.set_ref(td::BitArray<32>{8}, version.finalize()));
  ASSERT_TRUE(config_dict.set_ref(td::BitArray<32>{84},
      block::encode_workchain_native_ingress_table({ingress}).move_as_ok()));
  auto descriptor = vm::CellBuilder().store_long(0xa6,8).store_zeroes(32).store_zeroes(24)
      .store_long(1,1).store_long(1,1).store_long(1,1).store_zeroes(13+512)
      .store_long(5,32).store_long(1,4).store_long(0x434e5431,32).store_long(7,64).finalize();
  ASSERT_TRUE(block::gen::t_WorkchainDescr.validate_ref(10000, descriptor));
  vm::Dictionary workchains(32);
  ASSERT_TRUE(workchains.set(td::BitArray<32>{2}, vm::load_cell_slice_ref(descriptor)));
  vm::CellBuilder list;
  ASSERT_TRUE(workchains.append_dict_to_bool(list));
  ASSERT_TRUE(config_dict.set_ref(td::BitArray<32>{12}, list.finalize()));
  auto config = block::Config::unpack_config(config_dict.get_root_cell(), td::Bits256::zero(),
      block::Config::needCapabilities | block::Config::needWorkchainInfo).move_as_ok();
  auto resolved = registry.resolve_scoped_workchain(2, *config);
  ASSERT_TRUE(resolved.is_ok() && resolved.ok().has_value());
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainAccountBinding>(*resolved.ok()));
  auto binding = std::get<block::ResolvedWorkchainAccountBinding>(std::move(*resolved.ok_ref()));
  ASSERT_EQ(observed->configs, 1u);
  for (unsigned missing = 0; missing < 2; ++missing) {
    auto incomplete = binding;
    if (missing == 0) incomplete.executor = nullptr;
    else incomplete.engine_config.reset();
    auto refused = block::ConfiguredWorkchainAccountEngine::bind(incomplete);
    ASSERT_TRUE(refused.is_error());
    ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
  }
  auto configured = block::ConfiguredWorkchainAccountEngine::bind(binding);
  ASSERT_TRUE(configured.is_ok());
  const auto* expected_config = binding.engine_config.get();
  binding.engine_config.reset();
  ASSERT_EQ(observed->config_lifetime.use_count(), 1);
  // Configuration hash is tested through settlement below, without a direct
  // hash-mismatch invocation that could mask a missing entry-path guard.
  for (unsigned field = 1; field < 6; ++field) {
    auto wrong = binding.input_policy.identity();
    if (field == 1) wrong.extended = !wrong.extended;
    if (field == 2) wrong.engine_selector ^= 1;
    if (field == 3) wrong.vm_mode ^= 1;
    if (field == 4) wrong.descriptor_version ^= 1;
    if (field == 5) wrong.admission_version ^= 1;
    auto refused = configured.ok()->proof_work(number(11), wrong);
    ASSERT_TRUE(refused.is_error());
    ASSERT_EQ(refused.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(observed->inspections, 0u);
  }
  auto units = configured.ok()->proof_work(number(11), binding.input_policy.identity());
  ASSERT_TRUE(units.is_ok());
  ASSERT_EQ(units.ok(), 37u);
  ASSERT_EQ(observed->inspections, 1u);
  observed->inspections = 0;

  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(shard_fixture(2,2,true,3,false,0,40,false,1000), state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts),256,block::tlb::aug_ShardAccounts);
  block::WorkchainAccountDeclarations declarations;
  for (const auto& key : {a,b}) {
    block::tlb::ShardAccount::Record old;
    ASSERT_TRUE(old.unpack(accounts.lookup(key)));
    declarations.reads.push_back({key, td::Bits256(old.account->get_hash().bits())});
    declarations.writes.push_back(key);
  }
  auto identity = batch_test_identity(number(42));
  identity.configuration_hash = config->get_root_cell()->get_hash().bits();
  const std::vector<td::Ref<vm::Cell>> inbox;
  auto access = block::encode_workchain_account_declarations(declarations,2,2).move_as_ok();
  block::BatchInputAdmissionSession admission(binding.input_policy,number(11),access,identity,inbox);
  ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(admission.evaluate()));
  const auto& admitted = std::get<block::AdmittedBatchInput>(admission.evaluate());
  auto native = own_native_fixture({});
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = cfg.extra_currency_v2 = true;
  block::ActionPhaseConfig pricing;
  pricing.global_version = 16;
  pricing.disable_custom_fess = pricing.disable_anycast = pricing.extra_currency_v2 = true;
  // Both inputs are internally consistent; only the adapter belongs to the
  // other authenticated cut. Admission's own identity guard cannot catch this.
  auto other_policy_identity = binding.input_policy.identity();
  other_policy_identity.configuration_hash = number(999)->get_hash();
  auto other_policy = block::ResolvedBatchInputPolicy::from_resolved_fields(
      binding.input_policy.resources(), other_policy_identity);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(other_policy));
  auto other_identity = identity;
  other_identity.configuration_hash = other_policy_identity.configuration_hash.bits();
  block::BatchInputAdmissionSession other_admission(
      std::get<block::ResolvedBatchInputPolicy>(other_policy), number(11), access, other_identity, inbox);
  ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(other_admission.evaluate()));
  auto wrong_cut = block::execute_and_settle_workchain_accounts(*configured.ok(), state.accounts,
      other_identity, std::get<block::AdmittedBatchInput>(other_admission.evaluate()), native,
      b, a, td::make_refint(0), 4096, cfg, pricing);
  ASSERT_TRUE(wrong_cut.is_error());
  ASSERT_EQ(wrong_cut.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
  ASSERT_EQ(observed->inspections, 0u);
  ASSERT_EQ(observed->executions, 0u);
  auto staged = block::execute_and_settle_workchain_accounts(*configured.ok(),state.accounts,
      identity,admitted,native,b,a,td::make_refint(0),4096,cfg,pricing);
  if (staged.is_error()) LOG(ERROR) << staged.error();
  ASSERT_TRUE(staged.is_ok());
  ASSERT_EQ(observed->inspections,1u);
  ASSERT_EQ(observed->executions,1u);
  ASSERT_TRUE(observed->inspected_config == expected_config);
  ASSERT_TRUE(observed->executed_config == expected_config);
  block::WorkchainAccountEffects expected_effects;
  expected_effects.updates = {{a,number(37)},{b,number(37)}};
  ASSERT_EQ(staged.ok().effects->get_hash(),
      block::encode_workchain_account_effects(expected_effects,2,16,4096).move_as_ok()->get_hash());
  auto replayed = block::replay_workchain_account_settlement(*configured.ok(),state.accounts,
      identity,admitted,native,b,a,td::make_refint(0),4096,cfg,pricing,staged.ok());
  if (replayed.is_error()) LOG(ERROR) << replayed.error();
  ASSERT_TRUE(replayed.is_ok());
  ASSERT_EQ(observed->inspections,2u);
  ASSERT_EQ(observed->executions,2u);
  ASSERT_TRUE(observed->inspected_config == expected_config);
  ASSERT_TRUE(observed->executed_config == expected_config);
  ASSERT_EQ(replayed.ok().state.accounts->get_hash(),staged.ok().state.accounts->get_hash());
  ASSERT_TRUE(replayed.ok().state.accounts->get_hash() != state.accounts->get_hash());
  // Exercise the new profile through the existing configured runner. The
  // fixture's declared 37 units are deliberately less than the backend shape,
  // but the authenticated cap is greater; substituting the cap for the
  // declaration must therefore be observably different.
  for (auto version : {2u, 3u, 4u}) {
    auto resources = binding.input_policy.resources();
    resources.admission_version = version;
    resources.work_output.max_proof_units = 3000;
    auto policy_identity = binding.input_policy.identity();
    policy_identity.admission_version = version;
    auto resolved_policy = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, policy_identity);
    ASSERT_TRUE(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved_policy));
    auto next_binding = binding;
    next_binding.engine_config = std::shared_ptr<const block::WorkchainEngineConfig>(
        observed->config_lifetime.lock());
    next_binding.input_policy = std::get<block::ResolvedBatchInputPolicy>(resolved_policy);
    auto next = block::ConfiguredWorkchainAccountEngine::bind(next_binding).move_as_ok();
    auto next_identity = identity;
    next_identity.admission_version = version;
    block::BatchInputAdmissionSession next_session(next_binding.input_policy, number(11), access, next_identity, inbox);
    ASSERT_TRUE(std::holds_alternative<block::AdmittedBatchInput>(next_session.evaluate()));
    const auto& structural = std::get<block::AdmittedBatchInput>(next_session.evaluate());
    auto token = block::ProofAdmittedBatchInput::admit(*next, structural).move_as_ok();
    ASSERT_EQ(token.declared_proof_work(), 37u);
    observed->metered_calls = 0;
    observed->attempt_proof = true;
    observed->last_consumed = UINT64_MAX;
    auto result = block::execute_and_settle_workchain_accounts(*next, state.accounts,
        next_identity, token, native, b, a, td::make_refint(0), 4096, cfg, pricing);
    if (version == 4) {
      ASSERT_TRUE(result.is_error());
      ASSERT_EQ(result.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
      ASSERT_EQ(observed->metered_calls, 1u);
      ASSERT_EQ(observed->last_consumed, 0u);
      observed->attempt_proof = false;
      auto no_proof = block::execute_and_settle_workchain_accounts(*next, state.accounts,
          next_identity, token, native, b, a, td::make_refint(0), 4096, cfg, pricing);
      ASSERT_TRUE(no_proof.is_ok());
      ASSERT_EQ(observed->metered_calls, 2u);
      ASSERT_EQ(no_proof.ok().effects->get_hash(), staged.ok().effects->get_hash());
    } else {
      ASSERT_TRUE(result.is_ok());
      ASSERT_EQ(observed->metered_calls, 0u);
      if (version == 2) {
        ASSERT_EQ(result.ok().state.account_blocks->get_hash(), staged.ok().state.account_blocks->get_hash());
      }
      ASSERT_EQ(result.ok().effects->get_hash(), staged.ok().effects->get_hash());
    }
  }
}

TEST(WorkchainBlock, MultiAccountRegistryBinding) {
  // Explicit codec/resolver fixture instance. This representable wire value
  // does not authenticate an installation or claim a production-issued identity.
  const auto fixture_instance = td::Bits256::ones();
  struct Engine final : block::RegisteredWorkchainAccountEngine {
    td::Result<std::uint64_t> proof_work(
        const td::Ref<vm::Cell>&, const block::InputPolicyIdentity&,
        const block::WorkchainEngineConfig&) const override {
      return td::Status::Error(static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable),
                               "binding must not invoke proof preflight");
    }
    block::WorkchainEngineKey key{block::WorkchainFormat::Basic, 0x434e5431};
    mutable unsigned config_calls = 0, execute_calls = 0;
    mutable td::Ref<vm::Cell> seen;
    bool null_config = false;
    unsigned throw_kind = 0;
    block::WorkchainEngineKey engine_key() const override { return key; }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&,
        const td::Ref<vm::Cell>& payload) const override {
      ++config_calls;
      seen = payload;
      if (throw_kind == 1) throw vm::VmError{vm::Excno::cell_und};
      if (throw_kind == 2) throw vm::VmVirtError{1};
      if (null_config) return std::shared_ptr<const block::WorkchainEngineConfig>{};
      TRY_RESULT(parsed, block::decode_workchain_engine_parameters(payload));
      if (parsed.parameters->get_hash() != vm::CellBuilder().store_long(37, 8).finalize()->get_hash()) {
        return td::Status::Error("unsupported test account engine payload");
      }
      return std::shared_ptr<const block::WorkchainEngineConfig>(new block::WorkchainEngineConfig);
    }
    td::Result<block::WorkchainAccountEffects> execute_accounts(
        const td::Ref<vm::Cell>&, block::WorkchainAccountReadView&,
        const block::WorkchainEngineConfig&) const override {
      ++execute_calls;
      return td::Status::Error("binding must not execute");
    }
  };
  struct ComputeEngine final : block::WorkchainEngine {
    block::WorkchainEngineKey engine_key() const override {
      return {block::WorkchainFormat::Basic, 0x434e5431};
    }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&) const override {
      return td::Status::Error("compute callback must not be reached");
    }
    block::AccountExecutionPolicy account_policy(const block::WorkchainExecutionDescriptor&,
        const block::WorkchainEngineConfig&) const override { return {}; }
    td::Result<block::WorkchainComputeOutput> run_compute(const block::WorkchainComputeInput&,
        const block::WorkchainComputeContext&) const override {
      return td::Status::Error("compute execution must not be reached");
    }
  };
  auto engine = std::make_unique<Engine>();
  auto* observed = engine.get();
  block::WorkchainResourcePolicy resource_policy{2, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {1, 32, 64}, 7};
  auto engine_parameters = [&](unsigned value) {
    return block::encode_workchain_engine_parameters(
        {400, fixture_instance, resource_policy, vm::CellBuilder().store_long(value, 8).finalize(), 10000000000ULL}).move_as_ok();
  };
  block::WorkchainNativeIngressPolicy policy;
  policy.workchain_id = 2;
  policy.engine_key = engine->engine_key();
  policy.executor_address = td::Bits256::zero();
  policy.custody_address = td::Bits256::ones();
  policy.engine_configuration = engine_parameters(37);
  auto configuration = [&](unsigned version, td::uint64 capabilities,
                           const block::WorkchainExecutionDescriptor* actual = nullptr) {
    vm::Dictionary dictionary(32);
    vm::CellBuilder version_cell;
    ASSERT_TRUE(block::gen::t_GlobalVersion.pack_capabilities(version_cell, version, capabilities));
    ASSERT_TRUE(dictionary.set_ref(td::BitArray<32>{8}, version_cell.finalize()));
    ASSERT_TRUE(dictionary.set_ref(td::BitArray<32>{84},
        block::encode_workchain_native_ingress_table({policy}).move_as_ok()));
    if (actual) {
      vm::CellBuilder record;
      record.store_long(0xa6, 8).store_zeroes(32).store_long(0, 8)
          .store_long(actual->min_split, 8).store_long(actual->max_split, 8)
          .store_long(1, 1).store_long(actual->active, 1).store_long(actual->accept_msgs, 1)
          .store_zeroes(13 + 512).store_long(actual->version, 32).store_long(1, 4)
          .store_long(actual->vm_version, 32).store_long(actual->vm_mode, 64);
      auto encoded = record.finalize();
      ASSERT_TRUE(block::gen::t_WorkchainDescr.validate_ref(10000, encoded));
      vm::Dictionary workchains(32);
      ASSERT_TRUE(workchains.set(td::BitArray<32>{actual->workchain_id}, vm::load_cell_slice_ref(encoded)));
      vm::CellBuilder list;
      ASSERT_TRUE(workchains.append_dict_to_bool(list));
      ASSERT_TRUE(dictionary.set_ref(td::BitArray<32>{12}, list.finalize()));
    }
    return block::Config::unpack_config(dictionary.get_root_cell(), td::Bits256::zero(),
        block::Config::needCapabilities | block::Config::needWorkchainInfo).move_as_ok();
  };
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = static_cast<std::int32_t>(policy.engine_key.selector);
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_account_engine(std::move(engine)).is_ok());
  ASSERT_TRUE(registry.has_engine(policy.engine_key));
  ASSERT_TRUE(registry.execution_scope(policy.engine_key) == block::WorkchainExecutionScope::BlockTransition);
  ASSERT_TRUE(registry.register_account_engine(nullptr).is_error());
  ASSERT_TRUE(registry.register_account_engine(std::make_unique<Engine>()).is_error());
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_error());
  ASSERT_TRUE(!registry.register_engine_if_absent(std::make_unique<ComputeEngine>()));
  auto reserved = std::make_unique<Engine>();
  reserved->key = block::tvm_workchain_engine_key();
  ASSERT_TRUE(registry.register_account_engine(std::move(reserved)).is_error());
  block::WorkchainExecutionRegistry reverse;
  ASSERT_TRUE(reverse.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  ASSERT_TRUE(reverse.register_account_engine(std::make_unique<Engine>()).is_error());
  block::WorkchainExecutionRegistry compute;
  compute.register_engine(std::make_unique<ComputeEngine>());
  ASSERT_TRUE(compute.register_account_engine(std::make_unique<Engine>()).is_error());
  auto config = configuration(16, tos::capBlockTransition);
  ASSERT_TRUE(reverse.resolve_account_binding(descriptor, *config).is_error());
  ASSERT_TRUE(compute.resolve_account_binding(descriptor, *config).is_error());
  auto binding = registry.resolve_account_binding(descriptor, *config);
  ASSERT_TRUE(binding.is_ok());
  ASSERT_TRUE(binding.ok().executor == observed);
  ASSERT_TRUE(binding.ok().engine_config != nullptr);
  ASSERT_TRUE(binding.ok().ingress.executor_address == policy.executor_address);
  ASSERT_TRUE(binding.ok().ingress.custody_address == policy.custody_address);
  ASSERT_TRUE(observed->seen->get_hash() == policy.engine_configuration->get_hash());
  ASSERT_EQ(observed->config_calls, 1u);
  ASSERT_EQ(observed->execute_calls, 0u);
  // Binding a local implementation is not admission or live host integration.
  ASSERT_TRUE(registry.resolve_block(descriptor, *config).is_error());
  ASSERT_TRUE(registry.resolve(descriptor, *config).is_error());
  for (auto version : {15u, 16u}) {
    for (auto caps : {td::uint64{0}, td::uint64{tos::capBlockTransition}}) {
      if (version == 16 && caps) continue;
      ASSERT_TRUE(registry.resolve_account_binding(descriptor, *configuration(version, caps)).is_error());
      ASSERT_EQ(observed->config_calls, 1u);
    }
  }
  auto invalid = descriptor;
  invalid.active = false;
  ASSERT_TRUE(registry.resolve_account_binding(invalid, *config).is_error());
  invalid = descriptor;
  invalid.max_split = 1;
  ASSERT_TRUE(registry.resolve_account_binding(invalid, *config).is_error());
  invalid = descriptor;
  invalid.version = 1;
  ASSERT_TRUE(registry.resolve_account_binding(invalid, *config).is_error());
  ASSERT_EQ(observed->config_calls, 1u);
  policy.custody_address.reset();
  ASSERT_TRUE(registry.resolve_account_binding(descriptor, *configuration(16, tos::capBlockTransition)).is_error());
  ASSERT_EQ(observed->config_calls, 1u);
  policy.custody_address = td::Bits256::ones();
  policy.engine_key.selector = 123;
  ASSERT_TRUE(registry.resolve_account_binding(descriptor, *configuration(16, tos::capBlockTransition)).is_error());
  policy.engine_key = observed->engine_key();
  policy.workchain_id = 3;
  ASSERT_TRUE(registry.resolve_account_binding(descriptor, *configuration(16, tos::capBlockTransition)).is_error());
  policy.workchain_id = 2;
  ASSERT_EQ(observed->config_calls, 1u);
  observed->null_config = true;
  ASSERT_TRUE(registry.resolve_account_binding(descriptor, *config).is_error());
  ASSERT_EQ(observed->config_calls, 2u);
  observed->null_config = false;
  policy.engine_configuration = engine_parameters(38);
  ASSERT_TRUE(registry.resolve_account_binding(descriptor, *configuration(16, tos::capBlockTransition)).is_error());
  ASSERT_EQ(observed->config_calls, 3u);
  for (unsigned kind : {1u, 2u}) {
    observed->throw_kind = kind;
    unsigned caught = 0;
    try {
      auto ignored = registry.resolve_account_binding(descriptor, *config);
      (void)ignored;
    } catch (const vm::VmError&) { caught = 1; }
      catch (const vm::VmVirtError&) { caught = 2; }
    ASSERT_EQ(caught, kind);
  }
  ASSERT_EQ(observed->config_calls, 5u);
  ASSERT_EQ(observed->execute_calls, 0u);
  observed->throw_kind = 0;
  policy.engine_configuration = engine_parameters(37);
  auto full = configuration(16, tos::capBlockTransition, &descriptor);
  auto from_config = registry.resolve_account_binding_from_config(2, *full);
  ASSERT_TRUE(from_config.is_ok());
  ASSERT_TRUE(from_config.ok().executor == observed);
  ASSERT_EQ(from_config.ok().descriptor.workchain_id, 2);
  ASSERT_EQ(from_config.ok().descriptor.min_addr_len, 256u);
  ASSERT_EQ(from_config.ok().descriptor.max_addr_len, 256u);
  ASSERT_EQ(observed->config_calls, 6u);
  ASSERT_TRUE(registry.resolve_account_binding_from_config(3, *full).is_error());
  ASSERT_TRUE(registry.resolve_account_binding_from_config(tos::masterchainId, *full).is_error());
  ASSERT_TRUE(registry.resolve_account_binding_from_config(2, *config).is_error());
  for (int mode : {0, block::Config::needCapabilities, block::Config::needWorkchainInfo}) {
    auto incomplete = block::Config::unpack_config(full->get_root_cell(), td::Bits256::zero(), mode).move_as_ok();
    auto local = registry.resolve_account_binding_from_config(2, *incomplete);
    ASSERT_TRUE(local.is_error());
    ASSERT_TRUE(block::workchain_execution_requires_local_failure(local.error()));
  }
  auto absent = registry.resolve_account_binding_from_config(3, *full);
  ASSERT_TRUE(absent.is_error());
  ASSERT_TRUE(!block::workchain_execution_requires_local_failure(absent.error()));
  auto changed = descriptor;
  changed.version = 1;
  ASSERT_TRUE(registry.resolve_account_binding_from_config(2,
      *configuration(16, tos::capBlockTransition, &changed)).is_error());
  changed = descriptor;
  changed.vm_mode = 1;
  ASSERT_TRUE(registry.resolve_account_binding_from_config(2,
      *configuration(16, tos::capBlockTransition, &changed)).is_error());
  ASSERT_EQ(observed->config_calls, 6u);
  changed = descriptor;
  changed.vm_version = 123;
  ASSERT_TRUE(registry.resolve_account_binding_from_config(2,
      *configuration(16, tos::capBlockTransition, &changed)).is_error());
  ASSERT_EQ(observed->config_calls, 6u);
  changed = descriptor;
  changed.version = policy.descriptor_version = 5;
  changed.vm_mode = policy.vm_mode = 7;
  auto nonzero = registry.resolve_account_binding_from_config(2,
      *configuration(16, tos::capBlockTransition, &changed));
  ASSERT_TRUE(nonzero.is_ok());
  ASSERT_EQ(nonzero.ok().descriptor.version, 5u);
  ASSERT_EQ(nonzero.ok().descriptor.vm_mode, 7u);
  ASSERT_EQ(observed->config_calls, 7u);
  ASSERT_EQ(observed->execute_calls, 0u);
  // Installation and binding must accept the same authenticated version.
  // This is not full 3+inbox admission; a batch policy cannot enter the old session.
  static_assert(!std::is_constructible_v<block::CandidateAdmissionSession,
                td::Ref<vm::Cell>, block::ResolvedBatchInputPolicy>);
  for (unsigned cells : {64u, 128u}) {
    resource_policy.admission_version = cells == 64 ? 2 : 3;
    resource_policy.input.max_cells = cells;
    resource_policy.input.max_bits = cells == 64 ? 4096 : 8192;
    resource_policy.input.max_roots = cells == 64 ? 8 : 16;
    policy.engine_configuration = engine_parameters(37);
    auto cut = configuration(16, tos::capBlockTransition, &changed);
    vm::Dictionary installed(cut->get_root_cell(), 32);
    ASSERT_TRUE(block::validate_native_ingress_presence(installed).is_ok());
    auto resolved = registry.resolve_account_binding_from_config(2, *cut);
    ASSERT_TRUE(resolved.is_ok());
    ASSERT_EQ(resolved.ok().input_policy.limits().cells, cells);
    ASSERT_EQ(resolved.ok().input_policy.limits().bits, resource_policy.input.max_bits);
    ASSERT_EQ(resolved.ok().input_policy.limits().roots, resource_policy.input.max_roots);
    ASSERT_EQ(resolved.ok().input_policy.identity().admission_version, resource_policy.admission_version);
    ASSERT_EQ(resolved.ok().input_policy.permits_fee_settlement(), cells == 128);
    ASSERT_TRUE(!resolved.ok().input_policy.identity().extended);
    ASSERT_EQ(resolved.ok().input_policy.identity().engine_selector, 0x434e5431);
    ASSERT_EQ(resolved.ok().input_policy.identity().descriptor_version, changed.version);
    ASSERT_EQ(resolved.ok().input_policy.identity().vm_mode, changed.vm_mode);
    ASSERT_TRUE(resolved.ok().input_policy.identity().configuration_hash == cut->get_root_cell()->get_hash());
    ASSERT_TRUE(resolved.ok().authenticated_configuration->get_hash() == cut->get_root_cell()->get_hash());
    auto live_binding = registry.resolve_scoped_workchain(2, *cut);
    ASSERT_TRUE(live_binding.is_ok() && live_binding.ok().has_value());
    ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainAccountBinding>(*live_binding.ok()));
    const auto& live = std::get<block::ResolvedWorkchainAccountBinding>(*live_binding.ok());
    ASSERT_EQ(live.input_policy.limits().cells, cells);
    ASSERT_TRUE(live.authenticated_configuration->get_hash() == cut->get_root_cell()->get_hash());
    block::LocalWorkchainRoleSet required;
    required.required_workchains.insert(2);
    auto readiness = registry.validate_required_workchains(cut->get_workchain_list(), *cut, required);
    if (readiness.is_ok()) {
      // Model the caller continuing past the role gate with the registered
      // engine, not a registry-empty or missing-engine negative fixture.
      block::WorkchainAccountReadView view({});
      auto unexpected = observed->execute_accounts({}, view, *live.engine_config);
      ASSERT_TRUE(unexpected.is_error());
    }
    ASSERT_EQ(observed->execute_calls, 0u);
    ASSERT_TRUE(readiness.is_error());
    ASSERT_EQ(readiness.code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
  }
  for (unsigned kind : {1u, 2u}) {
    observed->throw_kind = kind;
    auto cut = configuration(16, tos::capBlockTransition, &changed);
    auto fault = registry.resolve_scoped_workchain(2, *cut);
    ASSERT_TRUE(fault.is_error());
    ASSERT_EQ(fault.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    block::LocalWorkchainRoleSet required;
    required.required_workchains.insert(2);
    auto role_fault = registry.validate_required_workchains(cut->get_workchain_list(), *cut, required);
    ASSERT_TRUE(role_fault.is_error());
    ASSERT_EQ(role_fault.code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
    ASSERT_EQ(observed->execute_calls, 0u);
  }
  observed->throw_kind = 0;
  const auto before_invalid_policy = observed->config_calls;
  for (unsigned kind : {0u, 1u, 2u, 3u, 4u, 5u, 6u}) {
    resource_policy.input.max_cells = kind == 0 ? 0 : 64;
    resource_policy.input.max_bits = kind == 1 ? 0 : 4096;
    resource_policy.input.max_roots = kind == 2 ? 0 : 8;
    resource_policy.input.max_reads = kind == 4 ? 0 : 16;
    resource_policy.input.max_writes = kind == 5 ? 0 : 16;
    resource_policy.input.max_inbound = kind == 6 ? 0 : 5;
    resource_policy.admission_version = kind == 3 ? 0x10002 : 2;
    policy.engine_configuration = engine_parameters(37);
    auto invalid_cut = configuration(16, tos::capBlockTransition, &changed);
    vm::Dictionary invalid_installation(invalid_cut->get_root_cell(), 32);
    ASSERT_TRUE(block::validate_native_ingress_presence(invalid_installation).is_error());
    auto refused = registry.resolve_account_binding_from_config(2, *invalid_cut);
    ASSERT_TRUE(refused.is_error());
    ASSERT_TRUE(block::workchain_execution_requires_local_failure(refused.error()));
    ASSERT_EQ(refused.error().code(), static_cast<int>(kind != 3
        ? block::WorkchainExecutionFailure::AuthenticatedStateCorrupt
        : block::WorkchainExecutionFailure::LocalUnavailable));
    auto live_refused = registry.resolve_scoped_workchain(2, *invalid_cut);
    ASSERT_TRUE(live_refused.is_error());
    ASSERT_EQ(live_refused.error().code(), refused.error().code());
    ASSERT_EQ(observed->config_calls, before_invalid_policy);
  }
  policy.engine_configuration = vm::CellBuilder().finalize();
  auto malformed_cut = configuration(16, tos::capBlockTransition, &changed);
  auto malformed_binding = registry.resolve_account_binding_from_config(2, *malformed_cut);
  ASSERT_TRUE(malformed_binding.is_error());
  ASSERT_EQ(malformed_binding.error().code(),
            static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
  ASSERT_EQ(observed->config_calls, before_invalid_policy);
  ASSERT_EQ(observed->execute_calls, 0u);

  // The live resolver derives descriptors from Config, not a caller-supplied map.
  // Keep the singleton execution positive control while checking local failures.
  policy.custody_address.reset();
  policy.descriptor_version = descriptor.version;
  policy.vm_mode = descriptor.vm_mode;
  policy.engine_configuration = counter_configuration_shell(vm::CellBuilder().finalize());
  auto singleton_cut = configuration(16, tos::capBlockTransition, &descriptor);
  auto live = reverse.resolve_scoped_workchain(2, *singleton_cut);
  ASSERT_TRUE(live.is_ok() && live.ok().has_value());
  ASSERT_TRUE(std::holds_alternative<block::ResolvedWorkchainBlockExecution>(*live.ok()));
  auto produced = block::execute_resolved_workchain_block(
      std::get<block::ResolvedWorkchainBlockExecution>(*live.ok()), input());
  ASSERT_TRUE(produced.is_ok());
  ASSERT_EQ(vm::load_cell_slice(produced.ok().new_engine_state).fetch_ulong(64), 42u);
  auto other_cut = configuration(15, tos::capBlockTransition, &descriptor);
  ASSERT_TRUE(singleton_cut->get_root_cell()->get_hash() != other_cut->get_root_cell()->get_hash());
  auto own_map = reverse.resolve_scoped_workchain(singleton_cut->get_workchain_list(), 2, *singleton_cut);
  ASSERT_TRUE(own_map.is_ok() && own_map.ok().has_value());
  auto foreign_map = reverse.resolve_scoped_workchain(other_cut->get_workchain_list(), 2, *singleton_cut);
  ASSERT_TRUE(foreign_map.is_error());
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(foreign_map.error()));
  block::WorkchainExecutionRegistry unavailable;
  auto unresolved = unavailable.resolve_scoped_workchain(2, *singleton_cut);
  ASSERT_TRUE(unresolved.is_error());
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(unresolved.error()));
  for (int mode : {0, block::Config::needCapabilities, block::Config::needWorkchainInfo}) {
    auto incomplete = block::Config::unpack_config(singleton_cut->get_root_cell(), td::Bits256::zero(), mode)
                          .move_as_ok();
    auto refused = reverse.resolve_scoped_workchain(2, *incomplete);
    ASSERT_TRUE(refused.is_error());
    ASSERT_TRUE(block::workchain_execution_requires_local_failure(refused.error()));
    auto master = reverse.resolve_scoped_workchain(tos::masterchainId, *incomplete);
    ASSERT_TRUE(master.is_ok() && !master.ok().has_value());
    block::LocalWorkchainRoleSet required_role;
    required_role.required_workchains.insert(2);
    auto role = reverse.validate_required_workchains(incomplete->get_workchain_list(), *incomplete, required_role);
    ASSERT_TRUE(block::workchain_execution_requires_local_failure(role));
  }
  auto absent_scope = reverse.resolve_scoped_workchain(99, *singleton_cut);
  ASSERT_TRUE(absent_scope.is_ok() && !absent_scope.ok().has_value());

  struct FaultyConfigEngine final : block::RegisteredWorkchainBlockEngine {
    unsigned kind;
    mutable unsigned config_calls = 0;
    explicit FaultyConfigEngine(unsigned value) : kind(value) {}
    block::WorkchainEngineKey engine_key() const override { return CounterEngine().engine_key(); }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&, const td::Ref<vm::Cell>&) const override {
      ++config_calls;
      switch (kind) {
        case 0: throw vm::VmError{vm::Excno::dict_err};
        case 1: throw vm::VmVirtError{1};
        case 2: throw vm::CellBuilder::CellCreateError{};
        case 3: throw vm::CellBuilder::CellWriteError{};
        case 4: throw vm::VmNoGas{};
        case 5: throw vm::VmFatal{};
        case 6: throw std::bad_alloc{};
        case 7: throw std::runtime_error("local configuration callback failure");
        default:
          return td::Status::Error(static_cast<int>(kind == 8 ? block::WorkchainExecutionFailure::CandidateInvalid
              : kind == 9 ? block::WorkchainExecutionFailure::AuthenticatedStateCorrupt
                          : block::WorkchainExecutionFailure::LocalUnavailable), "typed configuration failure");
      }
    }
    td::Result<block::WorkchainBlockPolicy> block_policy(
        const block::WorkchainExecutionDescriptor&, const block::WorkchainEngineConfig&) const override {
      return td::Status::Error("failed configuration must not reach policy");
    }
    td::Result<block::WorkchainBlockResult> execute_block(const block::WorkchainBlockInput&) const override {
      return td::Status::Error("configuration resolution must not execute");
    }
  };
  unsigned escaped = 0;
  bool all_local = true;
  block::LocalWorkchainRoleSet required;
  required.required_workchains.insert(2);
  for (unsigned kind = 0; kind != 11; ++kind) {
    block::WorkchainExecutionRegistry faults;
    auto faulty = std::make_unique<FaultyConfigEngine>(kind);
    auto* counts = faulty.get();
    ASSERT_TRUE(faults.register_block_engine(std::move(faulty)).is_ok());
    try {
      auto direct = faults.resolve_scoped_workchain(2, *singleton_cut);
      bool local = direct.is_error() && block::workchain_execution_requires_local_failure(direct.error());
      if (!local) LOG(ERROR) << "direct configuration fault kind " << kind << " was not local";
      all_local &= local;
      if (direct.is_error() && kind == 9) {
        ASSERT_EQ(direct.error().code(), static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
      }
    } catch (...) {
      LOG(ERROR) << "direct configuration fault kind " << kind << " escaped";
      ++escaped;
    }
    try {
      auto role = faults.validate_required_workchains(singleton_cut->get_workchain_list(), *singleton_cut, required);
      bool local = block::workchain_execution_requires_local_failure(role);
      if (!local) LOG(ERROR) << "required-role configuration fault kind " << kind << " was not local";
      all_local &= local;
    } catch (...) {
      LOG(ERROR) << "required-role configuration fault kind " << kind << " escaped";
      ++escaped;
    }
    ASSERT_EQ(counts->config_calls, 2u);
  }
  ASSERT_EQ(escaped, 0u);
  ASSERT_TRUE(all_local);

  struct PolicyEngine final : block::WorkchainEngine {
    unsigned kind;
    mutable unsigned config_calls = 0, policy_calls = 0;
    explicit PolicyEngine(unsigned value) : kind(value) {}
    block::WorkchainEngineKey engine_key() const override { return CounterEngine().engine_key(); }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&) const override {
      ++config_calls;
      return std::shared_ptr<const block::WorkchainEngineConfig>(new block::WorkchainEngineConfig);
    }
    block::AccountExecutionPolicy account_policy(const block::WorkchainExecutionDescriptor&,
        const block::WorkchainEngineConfig&) const override {
      ++policy_calls;
      if (kind == 2) throw vm::CellBuilder::CellCreateError{};
      block::AccountExecutionPolicy result;
      result.kind = kind == 1 ? block::AccountExecutionPolicyKind::ShardLocalExecutor
                              : block::AccountExecutionPolicyKind::AnyAccount;
      return result;
    }
    td::Result<block::WorkchainComputeOutput> run_compute(const block::WorkchainComputeInput&,
        const block::WorkchainComputeContext&) const override {
      return td::Status::Error("role checking must not execute");
    }
  };
  // Disabled ingress activation leaves the registered AccountCompute path
  // available. This is not a V2 multi-account execution fixture.
  auto compute_cut = configuration(14, 0, &descriptor);
  for (unsigned kind = 0; kind != 3; ++kind) {
    block::WorkchainExecutionRegistry registry;
    auto engine = std::make_unique<PolicyEngine>(kind);
    auto* counts = engine.get();
    registry.register_engine(std::move(engine));
    unsigned policy_escaped = 0;
    bool expected = false;
    try {
      auto result = registry.validate_required_workchains(compute_cut->get_workchain_list(), *compute_cut, required);
      expected = kind == 0 ? result.is_ok() : block::workchain_execution_requires_local_failure(result);
    } catch (...) { ++policy_escaped; }
    if (!expected || policy_escaped) LOG(ERROR) << "account policy fault kind " << kind << " failed boundary";
    ASSERT_EQ(counts->config_calls, 1u);
    ASSERT_EQ(counts->policy_calls, 1u);
    ASSERT_EQ(policy_escaped, 0u);
    ASSERT_TRUE(expected);
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

TEST(WorkchainBlock, NativeDestinationRouting) {
  td::Ref<block::WorkchainInfo> info{true};
  info.write().workchain = 2;
  info.write().basic = info.write().active = info.write().accept_msgs = true;
  info.write().min_addr_len = info.write().max_addr_len = 256;
  info.write().addr_len_step = 0;
  block::WorkchainSet workchains{{2, info}};
  info.clear();
  block::ActionPhaseConfig cfg;
  cfg.workchains = &workchains;
  auto sender = td::Bits256::zero();
  sender.as_slice()[0] = static_cast<char>(0x80);
  auto make_address = [](int wc, bool var, bool anycast) {
    vm::CellBuilder cb;
    cb.store_long(var ? 3 : 2, 2).store_long(anycast, 1);
    if (anycast) cb.store_long(1, 5).store_long(0, 1);
    if (var) cb.store_long(256, 9);
    cb.store_long(wc, var ? 32 : 8).store_zeroes(256);
    return vm::load_cell_slice_ref(cb.finalize());
  };
  auto canonical = make_address(2, false, false);
  auto variable = make_address(2, true, false);
  bool mc = true;
  ASSERT_TRUE(block::transaction::rewrite_native_destination(variable, cfg, sender, &mc));
  ASSERT_TRUE(!mc && variable->contents_equal(*canonical));
  auto master = make_address(-1, false, false);
  ASSERT_TRUE(block::transaction::rewrite_native_destination(master, cfg, sender, &mc) && mc);
  auto unknown = make_address(3, false, false);
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(unknown, cfg, sender));
  workchains.at(2).write().accept_msgs = false;
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(canonical, cfg, sender));
  workchains.at(2).write().accept_msgs = true;
  auto anycast = make_address(2, false, true);
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(anycast, cfg, sender, nullptr, false));
  ASSERT_TRUE(block::transaction::rewrite_native_destination(anycast, cfg, sender));
  auto decoded = *anycast;
  ASSERT_EQ(decoded.fetch_ulong(3), 5u);
  ASSERT_EQ(decoded.fetch_ulong(5), 1u);
  ASSERT_EQ(decoded.fetch_ulong(1), 1u); // Actual sender prefix, not the old zero.
  cfg.native_ingress_destinations.emplace(2, std::set<tos::StdSmcAddress>{sender});
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(canonical, cfg, sender));
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(anycast, cfg, sender));
  cfg.native_ingress_destinations.at(2) = {td::Bits256::zero()};
  ASSERT_TRUE(block::transaction::rewrite_native_destination(canonical, cfg, sender));
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(anycast, cfg, sender));
  cfg.native_ingress_destinations.at(2).insert(sender);
  auto custody = vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(2, 8)
      .store_bits(sender.bits(), 256).finalize());
  ASSERT_TRUE(block::transaction::rewrite_native_destination(custody, cfg, sender));
  ASSERT_TRUE(block::transaction::rewrite_native_destination(canonical, cfg, sender));
  auto foreign = vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(2, 8)
      .store_bits(td::Bits256::ones().bits(), 256).finalize());
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(foreign, cfg, sender));
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(anycast, cfg, sender));
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
  cfg.native_ingress_destinations.emplace(2, std::set<tos::StdSmcAddress>{td::Bits256::zero()});
  cfg.fwd_std = cfg.fwd_mc = block::MsgPrices(0, 0, 0, 0, 0, 0);
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
  policy.engine_configuration = counter_configuration_shell(vm::CellBuilder().finalize());
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
  // Preserve the original nonempty-business defect inside valid framing.
  wrong.engine_configuration = counter_configuration_shell(number(0));
  ASSERT_TRUE(block::decode_workchain_engine_parameters(wrong.engine_configuration).is_ok());
  ASSERT_TRUE(resolve({wrong}).is_error());
  wrong.engine_configuration = counter_configuration_shell(
      vm::CellBuilder().store_ref(vm::CellBuilder().finalize()).finalize());
  ASSERT_TRUE(block::decode_workchain_engine_parameters(wrong.engine_configuration).is_ok());
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
  auto configuration = [&](td::Ref<vm::Cell> table, bool include_descriptor, unsigned descriptor_version = 0,
                           unsigned global_version = 15) {
    vm::Dictionary config(32);
    vm::CellBuilder version;
    CHECK(block::gen::t_GlobalVersion.pack_capabilities(version, global_version, tos::capBlockTransition));
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
  ASSERT_TRUE(destinations.at(2) == std::set<tos::StdSmcAddress>{policy.executor_address});
  auto missing_descriptor = configuration(table, false);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*missing_descriptor).is_error());
  auto wrong_version = configuration(table, true, 1);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*wrong_version).is_error());
  auto missing_table = configuration({}, true);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*missing_table).move_as_ok().empty());
  auto empty = configuration(block::encode_workchain_native_ingress_table({}).move_as_ok(), true);
  ASSERT_TRUE(block::resolve_native_ingress_destinations(*empty).move_as_ok().empty());
  policy.custody_address = td::Bits256::zero();
  auto dual = configuration(block::encode_workchain_native_ingress_table({policy}).move_as_ok(), true, 0, 16);
  auto resolved_dual = block::resolve_native_ingress_destinations(*dual);
  ASSERT_TRUE(resolved_dual.is_ok());
  ASSERT_EQ(resolved_dual.ok().size(), 1u);
  ASSERT_EQ(resolved_dual.ok().at(2).size(), 2u);
  ASSERT_EQ(resolved_dual.ok().at(2).count(policy.executor_address), 1u);
  ASSERT_EQ(resolved_dual.ok().at(2).count(*policy.custody_address), 1u);
  block::ActionPhaseConfig action_config;
  action_config.workchains = &dual->get_workchain_list();
  action_config.native_ingress_destinations = resolved_dual.move_as_ok();
  for (const auto& account : {policy.executor_address, *policy.custody_address}) {
    auto destination = vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(2, 8)
        .store_bits(account.bits(), 256).finalize());
    ASSERT_TRUE(block::transaction::rewrite_native_destination(destination, action_config, td::Bits256::zero()));
  }
  auto unknown_account = td::Bits256::zero();
  unknown_account.as_slice()[0] = 1;
  auto destination = vm::load_cell_slice_ref(vm::CellBuilder().store_long(4, 3).store_long(2, 8)
      .store_bits(unknown_account.bits(), 256).finalize());
  ASSERT_TRUE(!block::transaction::rewrite_native_destination(destination, action_config, td::Bits256::zero()));
}

TEST(WorkchainBlock, ScopedWorkchainConfigurationResolution) {
  block::WorkchainExecutionRegistry registry;
  ASSERT_TRUE(registry.register_block_engine(std::make_unique<CounterEngine>()).is_ok());
  auto configuration_owner = block_configuration();
  // Satisfy the independent mode precondition so it cannot mask removal of
  // the map provenance guard, even when no local role is requested.
  configuration_owner = block::Config::unpack_config(configuration_owner->get_root_cell(), td::Bits256::zero(),
      block::Config::needCapabilities | block::Config::needWorkchainInfo).move_as_ok();
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
  // A separately assembled map is not an authenticated Config view, even if
  // every individual descriptor is otherwise well-formed.
  auto scoped = registry.resolve_scoped_workchain(workchains, 2, configuration);
  ASSERT_TRUE(scoped.is_error());
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(scoped.error()));
  block::LocalWorkchainRoleSet roles;
  roles.required_workchains.insert(2);
  auto required = registry.validate_required_workchains(workchains, configuration, roles);
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(required));
  // An empty role set does not authorize mixing configuration sources.
  ASSERT_TRUE(block::workchain_execution_requires_local_failure(
      registry.validate_required_workchains(workchains, configuration, {})));
}
