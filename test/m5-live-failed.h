#pragma once
// Test-only observation: real final-import plus accepted Native state. No
// replacement state is computed by the production Failed transition as oracle.
#include "m4-live-deposit.h"
#include "m5-live-return.h"

namespace m3_live {
inline void prepare_m5_failed_request(const std::filesystem::path& fixture) {
  const auto key = wallet_account(0);
  const auto owner = m5_live_account(account_data(load(fixture / "current-state.boc"),key),
                                   m5_live_withdrawal_limit(fixture));
  const auto bounce = load(fixture / "failed-bounce.boc");
  save_operation(fixture, block::m3_test::encode_m5_test_failed(
      {owner.account.address,td::Bits256(bounce->get_hash().bits())}),
      {key,owner.account.bindings.custody});
}

inline void assert_m5_failed(const std::filesystem::path& fixture,
    const td::Ref<vm::Cell>& previous, const AcceptedStep& step, const td::Bits256& custody) {
  using namespace block;
  const auto selector = m3_test::decode_m5_test_failed(m4_recorded_candidate(step.block)).move_as_ok();
  const auto limit = m5_live_withdrawal_limit(fixture);
  const auto before = m5_live_account(account_data(previous,selector.owner.account),limit);
  const auto after = m5_live_account(account_data(step.state,selector.owner.account),limit);
  const auto real_bounce = load(fixture / "failed-bounce.boc");
  CHECK(selector.inbound_message == td::Bits256(real_bounce->get_hash().bits()));
  const auto described = describe_workchain_late_return(real_bounce,2,custody).move_as_ok();
  const auto found = std::find_if(before.control.withdrawals.begin(),before.control.withdrawals.end(),
      [&](const auto& record){return record.timing.payout_created_lt == described.payout_created_lt;});
  auto expected_control = before.control;
  if (found != before.control.withdrawals.end())
    expected_control.withdrawals.erase(expected_control.withdrawals.begin() +
        std::distance(before.control.withdrawals.begin(),found));
  CHECK(limit);
  CHECK(encode_workchain_withdrawal_control(expected_control,*limit).move_as_ok()->get_hash() ==
        encode_workchain_withdrawal_control(after.control,*limit).move_as_ok()->get_hash());
  if (after.origin_pending.size() == before.origin_pending.size()) {
    CHECK(limit.has_value());
    auto expected_owner = before;
    expected_owner.control = expected_control;
    CHECK(encode_workchain_withdrawal_account(
          {expected_owner.account, expected_owner.control, expected_owner.origin_pending}, *limit).move_as_ok()->get_hash() ==
          account_data(step.state, selector.owner.account)->get_hash());
    const auto old_coordinator = decode_workchain_coordinator_state(account_data(previous, td::Bits256::zero())).move_as_ok();
    const auto coordinator = decode_workchain_coordinator_state(account_data(step.state, td::Bits256::zero())).move_as_ok();
    CHECK(old_coordinator.deposit_sequence == coordinator.deposit_sequence);
    const auto old_bucket = decode_workchain_unexpected_bucket(old_coordinator.unexpected, {256,256}, 4096).move_as_ok();
    const auto bucket = decode_workchain_unexpected_bucket(coordinator.unexpected, {256,256}, 4096).move_as_ok();
    CHECK(bucket.entries.size() == old_bucket.entries.size() + 1);
    const auto& entry = bucket.entries.back();
    const auto recovered = m5_recorded_return(step.block);
    CHECK(entry.account_id && *entry.account_id == selector.owner.account && !entry.return_failed);
    CHECK(CurrencyCollection(entry.tomis) == recovered);
    auto balance = [&](const td::Ref<vm::Cell>& root, const td::Bits256& key) {
      gen::ShardStateUnsplit::Record state; CHECK(::tlb::unpack_cell(root, state));
      vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
      Account account(2,key.bits()); CHECK(account.unpack(accounts.lookup(key),state.gen_utime,false));
      return account.balance;
    };
    CHECK(balance(previous,custody) == balance(step.state,custody));
    CurrencyCollection expected;
    CHECK(CurrencyCollection::add(balance(previous,td::Bits256::zero()),recovered,expected));
    CHECK(balance(step.state,td::Bits256::zero()) == expected);
    gen::Transaction::Record transaction;
    CHECK(::tlb::unpack_cell(accepted_transaction(step,custody),transaction));
    CurrencyCollection fees; CHECK(fees.unpack(transaction.total_fees));
    CHECK(fees.is_zero() && transaction.outmsg_cnt == 0);
    std::cout << "BUCKET_AUTHENTICATED recovered=" << recovered.tomis
              << " account=" << entry.account_id->to_hex() << " sequence=unchanged no-issuance\n";
    return;
  }
  // Close the route observation loop: this is the exact message the real wc0
  // recipient transaction exported, not merely some accepted custody import.
  gen::CommonMsgInfo::Record_int_msg_info sent, returned;
  CHECK(::tlb::unpack_cell_inexact(load(fixture / "prepare-payout.boc"),sent));
  CHECK(::tlb::unpack_cell_inexact(real_bounce,returned));
  tos::WorkchainId destination_wc; td::Bits256 destination;
  CHECK(block::tlb::t_MsgAddressInt.extract_std_address(returned.dest,destination_wc,destination));
  CHECK(destination_wc == 2 && destination == custody && sent.created_lt == described.payout_created_lt);
  CHECK(before.account.available.commitment == after.account.available.commitment &&
        before.account.available.handle == after.account.available.handle &&
        before.account.auth_nonce == after.account.auth_nonce &&
        before.account.available_revision == after.account.available_revision);
  // This narrow sequence enters Failed with empty pending; inspect all buckets,
  // not just the issued effects. The codec independently enumerates counts.
  CHECK(before.account.pending.empty() && before.account.system_pending.empty() && before.origin_pending.empty());
  CHECK(after.account.pending.empty() && after.account.system_pending.empty() && after.origin_pending.size() == 1);
  auto old_coordinator = decode_workchain_coordinator_state(account_data(previous,td::Bits256::zero())).move_as_ok();
  auto coordinator = decode_workchain_coordinator_state(account_data(step.state,td::Bits256::zero())).move_as_ok();
  CHECK(old_coordinator.deposit_sequence && coordinator.deposit_sequence);
  std::uint64_t sequence;
  CHECK(!__builtin_add_overflow(*old_coordinator.deposit_sequence,std::uint64_t{1},&sequence));
  CHECK(*coordinator.deposit_sequence == sequence);
  const auto& receipt = after.origin_pending.front();
  gen::ShardStateUnsplit::Record observed_state; CHECK(::tlb::unpack_cell(step.state,observed_state));
  bool late = found == before.control.withdrawals.end();
  if (!late && found->timing.phase == 1) {
    std::uint64_t end;
    CHECK(!__builtin_add_overflow(found->timing.queue_removed_height,found->timing.settlement_blocks,&end));
    late = observed_state.seq_no > end;
  }
  CHECK(workchain_system_origin_sequence(receipt.origin) == sequence);
  if (late) {
    const auto* origin = std::get_if<WorkchainDepositOrigin>(&receipt.origin);
    CHECK(origin && origin->inbound_message == selector.inbound_message);
  } else {
    const auto* origin = std::get_if<WorkchainSettlementOrigin>(&receipt.origin);
    CHECK(origin && origin->attempt_id == found->attempt_id);
  }
  const auto recovered = m5_recorded_return(step.block);
  const auto components = m5_live_return_fee_components(fixture);
  const CurrencyCollection fee(workchain_unsigned_fee(components.total));
  CurrencyCollection amount;
  CHECK(CurrencyCollection::sub(recovered,fee,amount));
  CHECK(CurrencyCollection(workchain_unsigned_fee(receipt.amount)) == amount);
  m3_test::assert_balance(m3_test::decrypt(receipt.ciphertext,test_secret(selector.owner.account),2000000000).move_as_ok(),
                         receipt.amount).ensure();
  auto balance = [&](const td::Ref<vm::Cell>& root, const td::Bits256& key) {
    gen::ShardStateUnsplit::Record state; CHECK(::tlb::unpack_cell(root,state));
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts),256,block::tlb::aug_ShardAccounts);
    Account value(2,key.bits()); CHECK(value.unpack(accounts.lookup(key),state.gen_utime,false));
    return value.balance;
  };
  CurrencyCollection credited, expected;
  CHECK(CurrencyCollection::add(balance(previous,custody),recovered,credited));
  CHECK(CurrencyCollection::sub(credited,fee,expected));
  CHECK(balance(step.state,custody) == expected);
  CurrencyCollection operating;
  CHECK(CurrencyCollection::add(balance(previous,td::Bits256::zero()),
      CurrencyCollection(workchain_unsigned_fee(components.state)),operating));
  gen::Transaction::Record tx;
  CHECK(::tlb::unpack_cell(accepted_transaction(step,custody),tx) && tx.outmsg_cnt == 0);
  CurrencyCollection collected; CHECK(collected.unpack(tx.total_fees));
  const bool correct_routing = balance(step.state,td::Bits256::zero()) == operating &&
      collected == CurrencyCollection(workchain_unsigned_fee(components.compute));
  if (!correct_routing)
    std::cerr << "FAILED_COST_ROUTING: coordinator_actual=" << balance(step.state,td::Bits256::zero()).tomis
              << " coordinator_expected=" << operating.tomis << " collected_actual=" << collected.tomis
              << " collected_expected=" << components.compute << std::endl;
  CHECK(correct_routing);
  CurrencyCollection principal; CHECK(principal.unpack(sent.value));
  CurrencyCollection return_loss, actual_cost;
  CHECK(CurrencyCollection::sub(principal,recovered,return_loss));
  CHECK(CurrencyCollection::add(return_loss,fee,actual_cost));
  // D78: return loss is an observation, not a prelock-funded debt.
  CHECK(!amount.is_zero());
  std::cout << "FAILED_AUTHENTICATED inbound=" << selector.inbound_message.to_hex()
            << " late=" << late << " recovered=" << recovered.tomis << " receipt=" << receipt.amount
            << " sequence=" << *old_coordinator.deposit_sequence << "->" << sequence
            << " W_records=" << after.control.withdrawals.size()
            << " custody=" << expected.tomis << " fees=" << fee.tomis << std::endl;
}
} // namespace m3_live
