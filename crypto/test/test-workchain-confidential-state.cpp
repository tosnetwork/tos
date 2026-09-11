#include "block/workchain-confidential-state.h"
#include "block/workchain-coordinator-state.h"
#include "td/utils/tests.h"
#include "td/utils/misc.h"
#include <algorithm>

namespace {
td::Bits256 bits(unsigned value) {
  td::Bits256 result;
  result.set_zero();
  result.as_slice()[31] = static_cast<char>(value);
  return result;
}
td::Bits256 public_point() {
  auto bytes = td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76");
  CHECK(bytes.is_ok());
  td::Bits256 result;
  result.as_slice().copy_from(bytes.ok());
  return result;
}
block::WorkchainConfidentialAccount account() {
  return {1, 1, 2, -23903, bits(1), {2, bits(2), bits(3)}, {bits(4), bits(5), bits(6)},
      {10000000000ULL, 0, bits(7)}, public_point(), 0, {bits(0), bits(0)}, 0, 0, {}, block::WorkchainAccountActive{}};
}
block::WorkchainPendingReceipt receipt(unsigned index) {
  auto id = block::derive_workchain_receipt_id(bits(9), bits(10), index);
  CHECK(id.is_ok());
  return {id.move_as_ok(), {2, bits(8), bits(9)}, 11, bits(3), 0, bits(4),
      {public_point(), public_point()}, bits(10), index, 0};
}
void sort_pending(block::WorkchainConfidentialAccount& value) {
  std::sort(value.pending.begin(), value.pending.end(),
      [](const auto& a, const auto& b) { return a.receipt_id < b.receipt_id; });
}
}

TEST(ConfidentialState, ReceiptIdentityAndRecovery) {
  auto r = receipt(0);
  auto encoded = block::encode_workchain_pending_receipt(r);
  ASSERT_TRUE(encoded.is_ok());
  auto decoded = block::decode_workchain_pending_receipt(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().source.workchain_id, 2);
  ASSERT_EQ(decoded.ok().source.account, bits(8));
  ASSERT_EQ(decoded.ok().source.instance, bits(9));
  ASSERT_EQ(decoded.ok().source_operation_nonce, 11u);
  ASSERT_EQ(decoded.ok().target_instance, bits(3));
  ASSERT_EQ(decoded.ok().target_key_epoch, 0u);
  ASSERT_EQ(decoded.ok().asset, bits(4));
  ASSERT_EQ(decoded.ok().ciphertext.commitment, public_point());
  ASSERT_EQ(decoded.ok().ciphertext.handle, public_point());
  ASSERT_EQ(decoded.ok().operation_id, bits(10));
  ASSERT_EQ(decoded.ok().output_index, 0u);
  ASSERT_EQ(decoded.ok().status, 0u);
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(12), bits(10), 0).move_as_ok() != r.receipt_id);
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(9), bits(10), 1).move_as_ok() != r.receipt_id);
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(9), bits(10), UINT32_MAX).is_ok());
  ASSERT_TRUE(block::derive_workchain_receipt_id(bits(9), bits(10), std::uint64_t{1} << 32).is_error());
  r.receipt_id = bits(0);
  ASSERT_TRUE(block::encode_workchain_pending_receipt(r).is_error());
  block::gen::UnoV2PendingReceipt::Record raw;
  ASSERT_TRUE(block::resource_policy_detail::unpack_exact(encoded.ok(), raw));
  raw.receipt_id = bits(0);
  td::Ref<vm::Cell> malformed;
  ASSERT_TRUE(tlb::pack_cell(malformed, raw));
  auto bad = block::decode_workchain_pending_receipt(malformed);
  ASSERT_TRUE(bad.is_error());
  ASSERT_EQ(bad.error().message(), "pending receipt identity mismatch");
}

TEST(ConfidentialState, AccountRoundtripAndLifecycle) {
  auto value = account();
  value.auth_nonce = UINT64_MAX;
  value.available_revision = UINT64_MAX;
  value.lifecycle = block::WorkchainAccountReadOnly{};
  for (unsigned i = 0; i < 16; ++i) value.pending.push_back(receipt(i));
  sort_pending(value);
  auto encoded = block::encode_workchain_confidential_account(value);
  ASSERT_TRUE(encoded.is_ok());
  std::reverse(value.pending.begin(), value.pending.end());
  ASSERT_EQ(block::encode_workchain_confidential_account(value).move_as_ok()->get_hash(), encoded.ok()->get_hash());
  auto decoded = block::decode_workchain_confidential_account(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  const auto& out = decoded.ok();
  ASSERT_EQ(out.schema_version, 1u);
  ASSERT_EQ(out.relation_profile, 1u);
  ASSERT_EQ(out.proof_profile, 2u);
  ASSERT_EQ(out.global_id, value.global_id);
  ASSERT_EQ(out.genesis_hash, value.genesis_hash);
  ASSERT_EQ(out.address.account, value.address.account);
  ASSERT_EQ(out.address.instance, value.address.instance);
  ASSERT_EQ(out.bindings.policy, value.bindings.policy);
  ASSERT_EQ(out.bindings.custody, value.bindings.custody);
  ASSERT_EQ(out.funding.paid_deposit, value.funding.paid_deposit);
  ASSERT_EQ(out.funding.refund_account, value.funding.refund_account);
  ASSERT_EQ(out.public_key, value.public_key);
  ASSERT_EQ(out.auth_nonce, UINT64_MAX);
  ASSERT_EQ(out.available_revision, UINT64_MAX);
  ASSERT_EQ(out.pending.size(), 16u);
  ASSERT_TRUE(std::holds_alternative<block::WorkchainAccountReadOnly>(out.lifecycle));
  ASSERT_EQ(block::encode_workchain_confidential_account(out).move_as_ok()->get_hash(), encoded.ok()->get_hash());
  for (const block::WorkchainConfidentialLifecycle& lifecycle : {
      block::WorkchainConfidentialLifecycle{block::WorkchainAccountActive{}},
      block::WorkchainConfidentialLifecycle{block::WorkchainAccountClosed{}},
      block::WorkchainConfidentialLifecycle{block::WorkchainAccountMigrated{{2, bits(18), bits(19)}, bits(20)}}}) {
    auto encoded_lifecycle = block::encode_workchain_account_lifecycle(lifecycle);
    ASSERT_TRUE(encoded_lifecycle.is_ok());
    auto decoded_lifecycle = block::decode_workchain_account_lifecycle(encoded_lifecycle.ok());
    ASSERT_TRUE(decoded_lifecycle.is_ok());
    ASSERT_EQ(decoded_lifecycle.ok().index(), lifecycle.index());
    ASSERT_EQ(block::encode_workchain_account_lifecycle(decoded_lifecycle.ok()).move_as_ok()->get_hash(),
              encoded_lifecycle.ok()->get_hash());
  }
}

TEST(ConfidentialState, RejectMalformedAndExcessiveState) {
  auto value = account();
  auto encoded = block::encode_workchain_confidential_account(value);
  ASSERT_TRUE(encoded.is_ok());  // Initial (0,0) ciphertext is canonical.
  auto bad_key = value;
  bad_key.public_key = bits(0);
  ASSERT_TRUE(block::encode_workchain_confidential_account(bad_key).is_error());
  bad_key.public_key = td::Bits256::ones();
  ASSERT_TRUE(block::encode_workchain_confidential_account(bad_key).is_error());
  value.available.commitment = td::Bits256::ones();
  ASSERT_TRUE(block::encode_workchain_confidential_account(value).is_error());
  ASSERT_TRUE(block::decode_workchain_confidential_account({}).is_error());
  ASSERT_TRUE(block::decode_workchain_confidential_account(vm::CellBuilder().store_long(0, 32).finalize()).is_error());
  ASSERT_TRUE(block::decode_workchain_account_lifecycle(vm::CellBuilder().store_long(0, 32).finalize()).is_error());
  block::gen::UnoV2AccountState::Record raw;
  ASSERT_TRUE(block::resource_policy_detail::unpack_exact(encoded.ok(), raw));
  for (unsigned defect = 0; defect < 4; ++defect) {
    auto changed = raw;
    if (defect == 0) changed.schema_version = 2;
    if (defect == 1) changed.pending_count = 1;
    if (defect == 2) changed.crypto = vm::CellBuilder().finalize();
    if (defect == 3) changed.lifecycle = vm::CellBuilder().store_long(0, 32).finalize();
    td::Ref<vm::Cell> bad;
    ASSERT_TRUE(tlb::pack_cell(bad, changed));
    ASSERT_TRUE(block::decode_workchain_confidential_account(bad).is_error());
  }
  value = account();
  for (unsigned i = 0; i < 17; ++i) value.pending.push_back(receipt(i));
  sort_pending(value);
  auto excessive = block::encode_workchain_confidential_account(value);
  ASSERT_TRUE(excessive.is_error());
  ASSERT_EQ(excessive.error().message(), "pending capacity exceeded");
  value.pending = {receipt(0), receipt(0)};
  ASSERT_TRUE(block::encode_workchain_confidential_account(value).is_error());
  value.pending = {receipt(0)};
  value.pending[0].target_instance = bits(18);
  ASSERT_TRUE(block::encode_workchain_confidential_account(value).is_error());
}

TEST(ConfidentialState, RegistrationDepositWire) {
  block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {0,2,2}, 1};
  auto business = vm::CellBuilder().finalize();
  for (std::uint64_t deposit : {std::uint64_t{0}, std::uint64_t{10000000000ULL}, std::uint64_t{UINT64_MAX}}) {
    auto encoded = block::encode_workchain_engine_parameters({400, bits(1), resources, business, deposit});
    ASSERT_TRUE(encoded.is_ok());
    auto cs = vm::load_cell_slice(encoded.ok());
    ASSERT_EQ(cs.size(), 384u);
    ASSERT_EQ(cs.fetch_ulong(32), block::gen::UnoV2EngineConfiguration::cons_tag[0]);
    ASSERT_EQ(cs.fetch_ulong(32), 400u);
    ASSERT_EQ(cs.fetch_ulong(64), deposit);  // Independent wire-order check.
    auto decoded = block::decode_workchain_engine_parameters(encoded.ok());
    ASSERT_TRUE(decoded.is_ok());
    ASSERT_EQ(decoded.ok().registration_deposit, deposit);
  }
  auto policy = block::encode_workchain_resource_policy(resources).move_as_ok();
  auto old = vm::CellBuilder().store_long(0x41868cd4, 32).store_long(400, 32)
      .store_bits(bits(1).bits(), 256).store_ref(policy).store_ref(business).finalize();
  auto retired = block::decode_workchain_engine_parameters(old);
  ASSERT_TRUE(retired.is_error());
  ASSERT_EQ(retired.error().message(), "unrecognized engine configuration constructor tag");
  auto missing = vm::CellBuilder().store_long(block::gen::UnoV2EngineConfiguration::cons_tag[0], 32)
      .store_long(400, 32).store_bits(bits(1).bits(), 256).store_ref(policy).store_ref(business).finalize();
  auto incomplete = block::decode_workchain_engine_parameters(missing);
  ASSERT_TRUE(incomplete.is_error());
  ASSERT_EQ(incomplete.error().message(), "missing fields in registration_deposit layout");
  static_assert(!std::is_constructible_v<block::WorkchainEngineParameters, std::uint32_t, td::Bits256,
      block::WorkchainResourcePolicy, td::Ref<vm::Cell>>);
}

TEST(ConfidentialState, CoordinatorDepositMigration) {
  block::WorkchainCoordinatorState state{2, {1, 1000000, 3, 0}, 30000000000ULL};
  auto encoded = block::encode_workchain_coordinator_state(state);
  ASSERT_TRUE(encoded.is_ok());
  auto decoded = block::decode_workchain_coordinator_state(encoded.ok());
  ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().refundable_deposits, state.refundable_deposits);
  ASSERT_EQ(decoded.ok().system.registered_accounts, 3u);
  block::gen::UnoV2CoordinatorDeposits::Record raw;
  ASSERT_TRUE(block::resource_policy_detail::unpack_exact(encoded.ok(), raw));
  auto missing = vm::CellBuilder().store_long(block::gen::UnoV2CoordinatorDeposits::cons_tag[0], 32)
      .store_long(2, 16).store_ref(raw.system).finalize();
  ASSERT_TRUE(block::decode_workchain_coordinator_state(missing).is_error());
  raw.budget = vm::CellBuilder().finalize();
  td::Ref<vm::Cell> malformed;
  ASSERT_TRUE(tlb::pack_cell(malformed, raw));
  ASSERT_TRUE(block::decode_workchain_coordinator_state(malformed).is_error());
  for (bool empty : {true, false}) {
    td::Ref<vm::Cell> system, legacy;
    ASSERT_TRUE(tlb::pack_cell(system, block::gen::UnoV2SystemState::Record{1, 1000000, empty ? 0ULL : 1ULL, 0}));
    ASSERT_TRUE(tlb::pack_cell(legacy, block::gen::UnoV2CoordinatorState::Record{1, system}));
    ASSERT_TRUE(block::decode_workchain_coordinator_state(legacy).is_error());  // No fallback.
    auto migrated = block::migrate_empty_workchain_coordinator_state(legacy);
    ASSERT_EQ(migrated.is_ok(), empty);
    if (empty) {
      auto current = block::decode_workchain_coordinator_state(migrated.ok());
      ASSERT_TRUE(current.is_ok());
      ASSERT_EQ(current.ok().layout_version, 2u);
      ASSERT_EQ(current.ok().system.layout_version, 1);
      ASSERT_EQ(current.ok().system.base_compute, 1000000u);
      ASSERT_EQ(current.ok().system.registered_accounts, 0u);
      ASSERT_EQ(current.ok().refundable_deposits, 0u);
    } else {
      ASSERT_EQ(migrated.error().message(), "legacy coordinator is not empty");
    }
  }
}
