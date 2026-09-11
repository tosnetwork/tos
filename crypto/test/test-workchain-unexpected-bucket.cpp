#include "block/workchain-unexpected-bucket.h"
#include "block/block-parse.h"
#include "block/workchain-rejected-deposit.h"
#include "block/workchain-deposit-admission.h"
#include "td/utils/misc.h"
#include "td/utils/tests.h"

namespace {
block::WorkchainUnexpectedSender sender(unsigned value) {
  td::Bits256 address;
  address.as_slice().fill(static_cast<char>(value));
  return {0, address};
}
block::WorkchainUnexpectedBucket empty_bucket() {
  return {{}, {}, td::make_refint(0), {}, 0};
}
}  // namespace

TEST(WorkchainUnexpectedBucket, DepositAdmissionSeparatesPrincipalAndOperatingFee) {
  using namespace block;
  auto point_bytes = td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76").move_as_ok();
  td::Bits256 point;
  point.as_slice().copy_from(point_bytes);
  WorkchainConfidentialAccount account{2, 1, 4, -23903, sender(1).account,
      {2, sender(2).account, sender(3).account}, {sender(4).account, sender(5).account, sender(6).account},
      {10000000000ULL, 0, sender(7).account}, point, 0, {td::Bits256::zero(), td::Bits256::zero()},
      0, 0, {}, WorkchainAccountActive{}, {}};
  // Frozen ConfigParam 84 initial values, not implementation defaults. This
  // pure test passes them explicitly; live resolution must read the payload.
  WorkchainDepositPolicy policy{1000000000, (std::uint64_t{1} << 62) - 1, 3000000, 16, 4};
  const auto message = sender(8).account;
  auto decide = [&](std::int64_t total, std::uint64_t sequence = 0, std::uint64_t principal = 1000000000) {
    return admit_workchain_deposit(policy, message, account.address, account.bindings.asset,
        account.bindings.custody, principal, td::make_refint(total), sequence,
        std::optional<WorkchainConfidentialAccount>{account});
  };
  auto accepted = decide(1003000000).move_as_ok();
  ASSERT_TRUE(std::holds_alternative<WorkchainDepositAdmission>(accepted));
  auto charge = std::get<WorkchainDepositAdmission>(accepted);
  ASSERT_EQ(charge.amount, 1000000000u);
  ASSERT_EQ(charge.operating_fee, 3000000u);
  ASSERT_EQ(charge.next_sequence, 1u);
  ASSERT_EQ(charge.id, derive_workchain_deposit_id(message, 1).move_as_ok());
  auto rejected = [&](auto result, WorkchainDepositRejection reason) {
    ASSERT_TRUE(result.is_ok());
    ASSERT_TRUE(std::holds_alternative<WorkchainDepositRejection>(result.ok()));
    ASSERT_TRUE(std::get<WorkchainDepositRejection>(result.ok()) == reason);
  };
  rejected(decide(2999999), WorkchainDepositRejection::SlotFee);
  rejected(decide(3000000, 0, 0), WorkchainDepositRejection::Amount);
  rejected(decide(1002999999, 0, 999999999), WorkchainDepositRejection::Amount);
  rejected(decide(INT64_MAX, 0, UINT64_MAX), WorkchainDepositRejection::Amount);
  rejected(decide(1002999999), WorkchainDepositRejection::SlotFee);
  rejected(decide(1003000001), WorkchainDepositRejection::SlotFee);
  policy.slot_fee = 5000000;  // In-transit price rise rejects, never reduces principal.
  rejected(decide(1003000000), WorkchainDepositRejection::SlotFee);
  policy.slot_fee = 2000000;  // Price reduction also rejects the excess deterministically.
  rejected(decide(1003000000), WorkchainDepositRejection::SlotFee);
  policy.slot_fee = 3000000;
  rejected(decide(1003000000, UINT64_MAX), WorkchainDepositRejection::SequenceExhausted);
  ASSERT_TRUE(std::holds_alternative<WorkchainDepositAdmission>(
      decide(static_cast<std::int64_t>(policy.maximum) + 3000000, 0, policy.maximum).move_as_ok()));
  account.lifecycle = WorkchainAccountClosed{};
  rejected(decide(1003000000), WorkchainDepositRejection::Lifecycle);
  account.lifecycle = WorkchainAccountActive{};
  account.system_pending.push_back({charge.id, message, 1, charge.amount, account.address.instance,
      0, account.bindings.asset, {point, point}, 0});
  rejected(decide(1003000000), WorkchainDepositRejection::Duplicate);
  for (unsigned i = 2; i <= 4; ++i)
    account.system_pending.push_back({derive_workchain_deposit_id(message, i).move_as_ok(), message, i,
        charge.amount, account.address.instance, 0, account.bindings.asset, {point, point}, 0});
  rejected(decide(1003000000, 4), WorkchainDepositRejection::Capacity);
  ASSERT_EQ(account.system_pending.size(), 4u);  // Every decision leaves its input untouched.
  auto missing = admit_workchain_deposit(policy, message, account.address, account.bindings.asset,
      account.bindings.custody, 1000000000, td::make_refint(1003000000), 0,
      td::Status::Error("database unavailable"));
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().code(), -7201);
  auto absent = admit_workchain_deposit(policy, message, account.address, account.bindings.asset,
      account.bindings.custody, 1000000000, td::make_refint(1003000000), 0,
      std::optional<WorkchainConfidentialAccount>{});
  rejected(std::move(absent), WorkchainDepositRejection::Unregistered);
}

TEST(WorkchainUnexpectedBucket, BothFullNeverRejectsAndPreservesValue) {
  // Small explicit test limits reach both boundaries; M4 configuration uses
  // unfrozen 256/256. There is no production default in the implementation.
  const block::WorkchainUnexpectedLimits limits{1, 1};
  auto old = empty_bucket();
  auto first = block::credit_workchain_unexpected(old, limits, sender(1), block::CurrencyCollection(7), 100).move_as_ok();
  ASSERT_EQ(old.entries.size(), 0u);
  ASSERT_EQ(first.bucket.entries.size(), 1u);
  ASSERT_TRUE(!first.sender_attribution_lost);
  auto second = block::credit_workchain_unexpected(first.bucket, limits, sender(2), block::CurrencyCollection(11), 100).move_as_ok();
  ASSERT_EQ(second.bucket.overflow.size(), 1u);
  ASSERT_TRUE(!second.sender_attribution_lost);
  auto same = block::credit_workchain_unexpected(second.bucket, limits, sender(2), block::CurrencyCollection(13), 100).move_as_ok();
  ASSERT_TRUE(!same.sender_attribution_lost);
  ASSERT_EQ(td::cmp(same.bucket.overflow[0].tomis, 24), 0);
  auto full = block::credit_workchain_unexpected(same.bucket, limits, sender(3), block::CurrencyCollection(17), 100).move_as_ok();
  ASSERT_TRUE(full.sender_attribution_lost);
  ASSERT_EQ(td::cmp(full.bucket.unkeyed, 17), 0);
  ASSERT_EQ(td::cmp(block::workchain_unexpected_balance(full.bucket).move_as_ok().tomis, 48), 0);
  auto root = block::encode_workchain_unexpected_bucket(full.bucket, limits, 100).move_as_ok();
  auto decoded = block::decode_workchain_unexpected_bucket(root, limits, 100).move_as_ok();
  ASSERT_EQ(td::cmp(block::workchain_unexpected_balance(decoded).move_as_ok().tomis, 48), 0);
  ASSERT_EQ(block::encode_workchain_unexpected_bucket(decoded, limits, 100).move_as_ok()->get_hash(), root->get_hash());
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(root, {0, 1}, 100).is_error());
}

TEST(WorkchainUnexpectedBucket, ExactShapeAndNoPartialMutation) {
  const block::WorkchainUnexpectedLimits limits{1, 1};
  auto old = empty_bucket();
  auto root = block::encode_workchain_unexpected_bucket(old, limits, 100).move_as_ok();
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(root, limits, 100).is_ok());
  vm::CellBuilder wrong;
  wrong.store_long(0x554e5835, 32);
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(wrong.finalize(), limits, 100).is_error());
  vm::CellBuilder trailing;
  trailing.append_cellslice(vm::load_cell_slice(root)).store_long(1, 1);
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(trailing.finalize(), limits, 100).is_error());
  old.overflow = {{sender(1), td::make_refint(1)}, {sender(1), td::make_refint(2)}};
  ASSERT_TRUE(block::encode_workchain_unexpected_bucket(old, {1, 2}, 100).is_error());
  old = empty_bucket();
  old.unkeyed = (td::make_refint(1) << 256) - 1;
  ASSERT_TRUE(block::credit_workchain_unexpected(old, {0, 0}, sender(1), block::CurrencyCollection(1), 100).is_error());
  ASSERT_EQ(td::cmp(old.unkeyed, (td::make_refint(1) << 256) - 1), 0);
  ASSERT_EQ(old.entries.size(), 0u);
}

TEST(WorkchainUnexpectedBucket, ExtraCurrenciesAreRetainedWithoutBodyOrAttribution) {
  vm::Dictionary extra(32);
  vm::CellBuilder amount;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(amount, *td::make_refint(5)));
  ASSERT_TRUE(extra.set_builder(td::BitArray<32>(7), amount, vm::Dictionary::SetMode::Add));
  block::CurrencyCollection imported(td::make_refint(3), extra.get_root_cell());
  auto result = block::credit_workchain_unexpected(empty_bucket(), {1, 1}, sender(1), imported, 100).move_as_ok();
  ASSERT_TRUE(result.extra_attribution_lost);
  ASSERT_TRUE(!result.sender_attribution_lost);
  ASSERT_TRUE(block::workchain_unexpected_balance(result.bucket).move_as_ok() == imported);
  auto root = block::encode_workchain_unexpected_bucket(result.bucket, {1, 1}, 100).move_as_ok();
  auto read = block::decode_workchain_unexpected_bucket(root, {1, 1}, 100).move_as_ok();
  ASSERT_TRUE(block::workchain_unexpected_balance(read).move_as_ok() == imported);
}

TEST(WorkchainUnexpectedBucket, RejectedIngressUsesNativeBounceOrSenderBucket) {
  block::WorkchainResourcePolicy resources{4, {64, 4096, 8, 16, 16, 5},
      {256, 16384, 128, 8192, 64}, {32, 128, 8192, 256, 16384, 16}, {0, 2, 2}, 1};
  block::WorkchainNativeIngressPolicy ingress;
  ingress.workchain_id = 2;
  ingress.engine_key = {block::WorkchainFormat::Basic, 0x554e4f32};
  ingress.vm_mode = 17;
  ingress.descriptor_version = 2;
  ingress.executor_address = sender(1).account;
  ingress.custody_address = sender(2).account;
  ingress.engine_configuration = block::encode_workchain_engine_parameters(
      {400, sender(7).account, resources, vm::CellBuilder().finalize(), 10}).move_as_ok();
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id = 2;
  descriptor.active = true;
  descriptor.vm_version = 0x554e4f32;
  descriptor.vm_mode = 17;
  descriptor.version = 2;
  block::WorkchainSet workchains;
  td::Ref<block::WorkchainInfo> basechain{true};
  basechain.write().workchain = 0;
  basechain.write().basic = basechain.write().active = basechain.write().accept_msgs = true;
  basechain.write().min_addr_len = basechain.write().max_addr_len = 256;
  workchains.emplace(0, basechain);
  block::ActionPhaseConfig prices;
  prices.global_version = 16;
  prices.bounce_msg_body = 256;
  prices.fwd_std = block::MsgPrices(200, 0, 0, 0, 16384, 0);
  prices.fwd_mc = block::MsgPrices(100, 0, 0, 0, 16384, 0);
  for (bool bounced : {false, true}) {
    vm::CellBuilder body;
    body.store_long(bounced ? 7 : 6, 4).store_long(4, 3).store_long(0, 8)
        .store_bits(sender(8).account.bits(), 256).store_long(4, 3).store_long(2, 8)
        .store_bits(ingress.custody_address->bits(), 256);
    ASSERT_TRUE(block::CurrencyCollection(300).store(body));
    auto message = body.store_zeroes(8).store_long(1, 64).store_long(1, 32)
        .store_zeroes(2).store_long(123, 32).finalize();
    td::Ref<vm::Cell> envelope;
    ASSERT_TRUE(tlb::pack_cell(envelope,
        block::tlb::MsgEnvelope::Record_std{0x60, 0x60, td::make_refint(0), message, {}, {}}));
    const td::Bits256 id(message->get_hash().bits());
    block::WorkchainNativeInboxPlan inbox{{envelope}, 1};
    auto plan = [&](const auto& messages, const td::Bits256& identity, const auto& costs) {
      return block::plan_workchain_rejected_deposit(ingress, descriptor, messages, identity,
          block::CurrencyCollection(200), empty_bucket(), {1, 1}, 2, 1, costs, workchains, 100);
    };
    auto result = plan(inbox, id, prices).move_as_ok();
    if (bounced) {
      ASSERT_TRUE(result.native.branch == block::NativeDisposalBranch::UnexpectedCredit);
      ASSERT_TRUE(result.native.bounce.is_null());
      ASSERT_EQ(result.unexpected.entries.size(), 1u);
      ASSERT_TRUE(result.unexpected.entries[0].sender.account == sender(8).account);
      ASSERT_EQ(td::cmp(result.unexpected.entries[0].tomis, 300), 0);
    } else {
      ASSERT_TRUE(result.native.branch == block::NativeDisposalBranch::Bounce);
      ASSERT_TRUE(result.unexpected.entries.empty());
      block::gen::CommonMsgInfo::Record_int_msg_info bounced_info;
      ASSERT_TRUE(tlb::unpack_cell_inexact(result.native.bounce, bounced_info));
      int wc;
      td::Bits256 address;
      ASSERT_TRUE(block::tlb::t_MsgAddressInt.extract_std_address(bounced_info.src, wc, address));
      ASSERT_EQ(wc, 2);
      ASSERT_TRUE(address == *ingress.custody_address && address != ingress.executor_address);
      ASSERT_TRUE(block::tlb::t_MsgAddressInt.extract_std_address(bounced_info.dest, wc, address));
      ASSERT_EQ(wc, 0);
      ASSERT_TRUE(address == sender(8).account);
      block::CurrencyCollection returned;
      ASSERT_TRUE(returned.unpack(bounced_info.value) && returned == block::CurrencyCollection(100));
      ASSERT_TRUE(bounced_info.bounced);
    }
    ASSERT_TRUE(plan(inbox, sender(9).account, prices).is_error());
    inbox.envelopes.push_back(envelope);
    ASSERT_TRUE(plan(inbox, id, prices).is_error());
    inbox.envelopes.pop_back();
    auto invalid_prices = prices;
    invalid_prices.fwd_std.first_frac = 65536;
    ASSERT_TRUE(plan(inbox, id, invalid_prices).is_error());  // Never fall back on local context error.
    auto unaffordable = prices;
    unaffordable.fwd_std.lump_price = 301;
    auto bucket = plan(inbox, id, unaffordable).move_as_ok();
    ASSERT_TRUE(bucket.native.branch == block::NativeDisposalBranch::UnexpectedCredit);
    ASSERT_TRUE(bucket.native.bounce.is_null());
    ASSERT_EQ(td::cmp(bucket.unexpected.entries[0].tomis, 300), 0);
  }
}
