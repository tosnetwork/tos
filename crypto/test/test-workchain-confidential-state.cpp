#include "block/workchain-confidential-state.h"
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
