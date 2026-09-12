#pragma once
// TEST ONLY. Assertions consume accepted block transactions and their applied
// state update. Wallet expectations are not inputs to either node actor.
#include "m3-live-state.h"
#include "m3-live-wallet.h"

namespace m3_live {
inline block::m3_test::Point test_secret(const td::Bits256& account) {
  td::Bits256 a, b;
  a.as_slice().fill(0x11);
  b.as_slice().fill(0x22);
  CHECK(account == a || account == b);
  block::m3_test::Point secret{};
  secret[0] = account == a ? 101 : 223;
  return secret;
}
inline void assert_accepted_transfer(const std::filesystem::path& fixture,
                                     const td::Ref<vm::Cell>& previous, const AcceptedStep& step) {
  const auto coordinator = td::Bits256::zero();
  auto transaction = accepted_transaction(step, coordinator);
  block::gen::Transaction::Record tx;
  CHECK(tlb::unpack_cell(transaction, tx));
  // Both operation selection and balance checks read the permanent block. The
  // proposer-side candidate/proof files are deliberately not accepted here.
  auto input = block::m3_test::input_from_block(step.block, coordinator, tx.lt).move_as_ok();
  auto decoded = block::decode_workchain_transfer_input(input).move_as_ok();
  const auto source = std::visit([](const auto& value) { return value.claims.source.account; }, decoded.data);
  td::Ref<vm::Cell> destination_before, destination_after;
  std::optional<block::m3_test::Point> recipient;
  if (auto* send = std::get_if<block::WorkchainSendData>(&decoded.data)) {
    destination_before = account_data(previous, send->destination.account);
    destination_after = account_data(step.state, send->destination.account);
    recipient = test_secret(send->destination.account);
  }
  // Fixed scenario expectations, never computed from the observed ciphertext.
  const auto old_value = std::stoull(field(fixture / "operation.expected.txt", "before"));
  const auto new_value = std::stoull(field(fixture / "operation.expected.txt", "after"));
  // The M4 fixture deposits two amounts of 1e9. A selected receipt can exceed
  // the post-fee available balance, so that balance alone is not a valid
  // decryption search bound. This is a test-wallet limit, not a consensus limit.
  const auto bound = std::max<std::uint64_t>(2000000000, std::max(old_value, new_value));
  auto before_root = account_data(previous, source), after_root = account_data(step.state, source);
  if (vm::load_cell_slice(before_root).prefetch_ulong(32) ==
      block::gen::UnoV2AccountStateWithdrawalsV2::cons_tag[0]) {
    const auto limit = m5_live_withdrawal_limit(fixture);
    CHECK(limit);
    auto before = block::decode_workchain_withdrawal_account(before_root, *limit).move_as_ok();
    auto after = block::decode_workchain_withdrawal_account(after_root, *limit).move_as_ok();
    CHECK(before.origin_pending.size() == after.origin_pending.size());
    for (std::size_t i = 0; i < before.origin_pending.size(); ++i)
      CHECK(block::encode_workchain_system_receipt(before.origin_pending[i]).move_as_ok()->get_hash() ==
            block::encode_workchain_system_receipt(after.origin_pending[i]).move_as_ok()->get_hash());
    // Existing balance/nonce/user/Deposit-pending assertions consume only their
    // codec's projection. Real roots above retain and validate the full envelope;
    // the separate backing observer reads W directly from those real roots.
    before.account.schema_version = after.account.schema_version = 2;
    before_root = block::encode_workchain_confidential_account(before.account).move_as_ok();
    after_root = block::encode_workchain_confidential_account(after.account).move_as_ok();
  }
  auto balances = block::m3_test::assert_block_transfer(step.block, coordinator, tx.lt,
      before_root, after_root, test_secret(source), bound,
      old_value, new_value, destination_before, destination_after, recipient).move_as_ok();
  if (auto* send = std::get_if<block::WorkchainSendData>(&decoded.data)) {
    auto receipt = block::derive_workchain_receipt_id(send->claims.source.instance,
        decoded.claimed_operation_id, 0).move_as_ok();
    // Wallet tracking starts from accepted block bytes, not proposed IDs.
    td::write_file((fixture / "accepted-receipt.id").string(), td::hex_encode(receipt.as_slice())).ensure();
  }
  std::cout << "actual block transfer: available " << balances.before << " -> " << balances.after << '\n';
}
inline void assert_accepted_closure(const td::Ref<vm::Cell>& previous, const AcceptedStep& step,
                                    const td::Bits256& subject_from_block, std::uint64_t expected_other = 49490,
                                    std::optional<std::uint32_t> withdrawal_limit = std::nullopt) {
  const auto coordinator = td::Bits256::zero();
  auto transaction = accepted_transaction(step, coordinator);
  block::gen::Transaction::Record tx;
  CHECK(tlb::unpack_cell(transaction, tx) && tx.outmsg_cnt == 1);
  vm::Dictionary outgoing(tx.r1.out_msgs, 15);
  // A literal 0 selects BitArray's non-template pointer constructor, not its
  // templated integer constructor. Store the zero index explicitly.
  td::BitArray<15> first_message;
  first_message.bits().store_uint(0, 15);
  auto message = outgoing.lookup_ref(first_message);
  CHECK(message.not_null());
  block::gen::ShardStateUnsplit::Record before, after;
  CHECK(tlb::unpack_cell(previous, before) && tlb::unpack_cell(step.state, after));
  block::m3_test::RefundObserved observed{transaction, message, before.accounts, after.accounts,
                                        coordinator, 2, after.gen_utime};
  auto before_account = account_data(previous, subject_from_block);
  auto after_account = account_data(step.state, subject_from_block);
  if (vm::load_cell_slice(before_account).prefetch_ulong(32) ==
      block::gen::UnoV2AccountStateWithdrawalsV2::cons_tag[0]) {
    CHECK(withdrawal_limit);
    auto old = block::decode_workchain_withdrawal_account(before_account, *withdrawal_limit).move_as_ok();
    auto closed = block::decode_workchain_withdrawal_account(after_account, *withdrawal_limit).move_as_ok();
    CHECK(old.origin_pending.empty() && closed.origin_pending.empty());
    CHECK(closed.control.withdrawals.empty());
    for (const auto& record : old.control.withdrawals) {
      CHECK(record.timing.phase == 1);
      std::uint32_t deadline;
      CHECK(!__builtin_add_overflow(record.timing.queue_removed_height, record.timing.settlement_blocks, &deadline));
      CHECK(after.seq_no > deadline);
    }
    old.account.schema_version = closed.account.schema_version = 2;
    before_account = block::encode_workchain_confidential_account(old.account).move_as_ok();
    after_account = block::encode_workchain_confidential_account(closed.account).move_as_ok();
  }
  block::m3_test::assert_closure(account_data(previous, coordinator), account_data(step.state, coordinator),
      before_account, after_account,
      test_secret(subject_from_block), 100000, observed).ensure();
  td::Bits256 other;
  other.as_slice().fill(subject_from_block.as_slice()[0] == 0x11 ? 0x22 : 0x11);
  auto sender = block::decode_workchain_confidential_account(account_data(step.state, other)).move_as_ok();
  const auto value = block::m3_test::decrypt(sender.available, test_secret(other),
      std::max<std::uint64_t>(100000, expected_other)).move_as_ok();
  block::m3_test::assert_balance(value, expected_other).ensure();
  auto system = block::decode_workchain_coordinator_state(account_data(step.state, coordinator)).move_as_ok();
  CHECK(system.system.registered_accounts == 2);
  std::cout << "actual closure: zero available; historical deposit is an outbound message only; "
               "delivery NOT guaranteed, no recipient credit asserted; other available=" << value
            << " closed available=0 registered_accounts=2\n";
}
}  // namespace m3_live
