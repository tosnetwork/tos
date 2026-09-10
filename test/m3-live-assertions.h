#pragma once
// TEST ONLY. Assertions consume accepted block transactions and their applied
// state update. Wallet expectations are not inputs to either node actor.
#include "m3-live-state.h"

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
  auto balances = block::m3_test::assert_block_transfer(step.block, coordinator, tx.lt,
      account_data(previous, source), account_data(step.state, source), test_secret(source), 100000,
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
                                    const td::Bits256& subject_from_block) {
  const auto coordinator = td::Bits256::zero();
  auto transaction = accepted_transaction(step, coordinator);
  block::gen::Transaction::Record tx;
  CHECK(tlb::unpack_cell(transaction, tx) && tx.outmsg_cnt == 1);
  vm::Dictionary outgoing(tx.r1.out_msgs, 15);
  auto message = outgoing.lookup_ref(td::BitArray<15>(0));
  CHECK(message.not_null());
  block::gen::ShardStateUnsplit::Record before, after;
  CHECK(tlb::unpack_cell(previous, before) && tlb::unpack_cell(step.state, after));
  block::m3_test::RefundObserved observed{transaction, message, before.accounts, after.accounts,
                                        coordinator, 2, after.gen_utime};
  block::m3_test::assert_closure(account_data(previous, coordinator), account_data(step.state, coordinator),
      account_data(previous, subject_from_block), account_data(step.state, subject_from_block),
      test_secret(subject_from_block), 100000, observed).ensure();
  std::cout << "actual closure: zero available; historical deposit is an outbound message only; "
               "delivery NOT guaranteed, no recipient credit asserted\n";
}
}  // namespace m3_live
