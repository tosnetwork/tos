#pragma once
// TEST ONLY. Real Native payer messages and accepted-block accounting.
// No detached balances, deployment configuration, or execution permission.
#include "m3-live-wallet.h"
#include "crypto/test/workchain-m4-deposit-input.h"
#include "crypto/test/workchain-m5-failed-input.h"
#include "block/workchain-budget-backing.h"

namespace m3_live {
inline void assert_m4_bounce_received(const std::filesystem::path& fixture) {
  const auto expected = load(fixture / "rejected-bounce.boc");
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  CHECK(tlb::unpack_cell_inexact(expected, info));
  tos::WorkchainId wc; td::Bits256 recipient;
  CHECK(block::tlb::t_MsgAddressInt.extract_std_address(info.dest, wc, recipient) && wc == 0);
  auto archive = tos::fetch_tl_object<tos::tos_api::db_candidate>(
      td::read_file((fixture / "bounce-recipient.candidate").string()).move_as_ok(), true).move_as_ok();
  const auto id = tos::create_block_id(archive->id_);
  const auto root = vm::std_boc_deserialize(archive->data_.as_slice()).move_as_ok();
  CHECK(id.id.workchain == wc && td::Bits256(root->get_hash().bits()) == id.root_hash &&
        td::sha256_bits256(archive->data_) == id.file_hash);
  block::gen::Block::Record block;
  block::gen::BlockExtra::Record extra;
  CHECK(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.extra, extra));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(extra.account_blocks), 256, block::tlb::aug_ShardAccountBlocks);
  auto leaf = accounts.lookup(recipient);
  block::gen::AccountBlock::Record account;
  CHECK(leaf.not_null() && block::gen::t_AccountBlock.unpack(leaf.write(), account));
  vm::AugmentedDictionary txs(vm::DictNonEmpty(), account.transactions, 64, block::tlb::aug_AccountTransactions);
  unsigned matched = 0;
  CHECK(txs.check_for_each_extra([&](auto value, auto, td::ConstBitPtr, int) {
    block::gen::Transaction::Record tx;
    if (!tlb::unpack_cell(value->prefetch_ref(), tx)) return false;
    auto input = *tx.r1.in_msg;
    if (input.fetch_ulong(1) != 1) return true;
    const auto message = input.fetch_ref();
    if (message.is_null() || message->get_hash() != expected->get_hash()) return true;
    block::gen::TransactionDescr::Record_trans_ord ordinary;
    if (!tlb::unpack_cell(tx.description, ordinary)) return false;
    auto phase = ordinary.credit_ph;
    if (phase.write().fetch_ulong(1) != 1) return false;
    block::gen::TrCreditPhase::Record credit;
    if (!tlb::csr_unpack(phase, credit)) return false;
    block::CurrencyCollection amount;
    if (!amount.unpack(credit.credit)) return false;
    ++matched;
    std::cout << "Actual wc0 sender received exact bounce message; Native credit=" << amount.tomis
              << "; block=" << id.to_str() << '\n';
    return true;
  }));
  CHECK(matched == 1);
}
inline void assert_m4_master_import(const std::filesystem::path& fixture) {
  auto archive = tos::fetch_tl_object<tos::tos_api::db_candidate>(
      td::read_file((fixture / "m4-master.candidate").string()).move_as_ok(), true).move_as_ok();
  const auto id = tos::create_block_id(archive->id_);
  const auto root = vm::std_boc_deserialize(archive->data_.as_slice()).move_as_ok();
  CHECK(id.id.workchain == tos::masterchainId && td::Bits256(root->get_hash().bits()) == id.root_hash &&
        td::sha256_bits256(archive->data_) == id.file_hash);
  block::gen::Block::Record master, shard;
  block::gen::BlockExtra::Record extra;
  block::gen::McBlockExtra::Record custom;
  CHECK(tlb::unpack_cell(root, master) && tlb::unpack_cell(master.extra, extra));
  CHECK(extra.custom->size() == 1 && extra.custom->prefetch_ulong(1) == 1 && extra.custom->size_refs() == 1);
  CHECK(tlb::unpack_cell(extra.custom->prefetch_ref(), custom));
  CHECK(tlb::unpack_cell(load(fixture / "accepted-block.boc"), shard));
  block::ValueFlow flow;
  CHECK(flow.unpack(vm::load_cell_slice_ref(shard.value_flow)));
  vm::AugmentedDictionary imported(custom.shard_fees, 96, block::tlb::aug_ShardFees);
  td::BitArray<96> key;
  key.bits().store_int(2, 32);
  (key.bits() + 32).store_uint(tos::shardIdAll, 64);
  auto row = imported.lookup(key);
  block::gen::ShardFeeCreated::Record amounts;
  block::CurrencyCollection paid;
  CHECK(row.not_null() && block::gen::t_ShardFeeCreated.unpack(row.write(), amounts) && row->empty());
  CHECK(paid.unpack(amounts.fees) && paid == flow.fees_collected);
  std::cout << "Actual masterchain import " << id.to_str() << " wc=2 fees=" << paid.tomis << '\n';
}

inline void prepare_m4_deposit(const std::filesystem::path& fixture) {
  using namespace block;
  auto root = load(fixture / "zerostate.boc");
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0},
                      root->get_hash().bits(), td::Bits256::zero()};
  auto config = ConfigInfo::extract_config(root, zero,
      Config::needWorkchainInfo | Config::needCapabilities).move_as_ok();
  const auto ingress = load_workchain_native_ingress_table(*config).move_as_ok().at(2);
  const auto parameters = decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
  const auto business = m3_test::decode_m3_test_business_parameters(parameters.parameters).move_as_ok();
  const auto limits = m3_test::require_m4_deposit_policy(business).move_as_ok();
  const auto target = wallet_state(fixture, 0);
  const auto principal = std::stoull(field(fixture / "deposit.request.txt", "principal"));
  std::uint64_t value;
  CHECK(!__builtin_add_overflow(principal, limits.slot_fee, &value));
  const bool rejection_fixture = std::filesystem::exists(fixture / "deposit.rejection.txt");
  bool bounce = true;
  if (rejection_fixture) {
    const auto extra = std::stoull(field(fixture / "deposit.rejection.txt", "extra"));
    CHECK(!__builtin_add_overflow(value, extra, &value));
    bounce = field(fixture / "deposit.rejection.txt", "bounce") == "1";
  }
  auto body = m3_test::encode_m4_test_deposit({target.address, principal});
  save_operation(fixture, body, {target.address.account, *ingress.custody_address});
  // Exactly the registration payer route: wc=0 supplies src/LT/time, mode 1
  // pays forwarding separately. No fabricated final-import envelope.
  vm::CellBuilder internal;
  internal.store_long(bounce ? 6 : 4, 4).store_long(0, 2).store_long(4, 3).store_long(2, 8)
      .store_bits(ingress.executor_address.bits(), 256);
  CHECK(CurrencyCollection(workchain_unsigned_fee(value)).store(internal));
  internal.store_zeroes(8).store_zeroes(96).store_long(0, 1).store_long(1, 1).store_ref(body);
  td::Bits256 payer = td::Bits256::zero(); payer.as_slice()[31] = 1;
  vm::CellBuilder external;
  external.store_long(2, 2).store_long(0, 2).store_long(4, 3).store_long(0, 8)
      .store_bits(payer.bits(), 256).store_long(0, 4).store_zeroes(2).store_ref(internal.finalize());
  save(fixture / "deposit.message.boc", external.finalize());
}

inline td::Ref<vm::Cell> m4_recorded_candidate(const td::Ref<vm::Cell>& root,
                                             td::Ref<vm::Cell>* effects = nullptr);
inline bool m4_deposit_was_rejected(const td::Ref<vm::Cell>& root) {
  td::Ref<vm::Cell> effects;
  m4_recorded_candidate(root, &effects);
  block::gen::UnoV2HostEffects::Record record;
  CHECK(tlb::unpack_cell(effects, record));
  auto events = *record.events;
  if (events.fetch_ulong(1) == 0) { CHECK(events.empty_ext()); return false; }
  CHECK(events.size() == 0 && events.size_refs() == 1);
  const auto event = vm::load_cell_slice(events.fetch_ref());
  CHECK(event.size() == 291 && event.size_refs() == 0 && event.prefetch_ulong(32) == 0x55445234);
  return true;
}
inline void assert_rejected_deposit(const std::filesystem::path& fixture,
    const td::Ref<vm::Cell>& previous, const AcceptedStep& step, const td::Bits256& custody) {
  using namespace block;
  CHECK(m4_deposit_was_rejected(step.block));
  const auto candidate = m4_recorded_candidate(step.block);
  const auto deposit = m3_test::decode_m4_test_deposit(candidate).move_as_ok();
  CHECK(account_data(previous, deposit.destination.account)->get_hash() ==
        account_data(step.state, deposit.destination.account)->get_hash());
  gen::ShardStateUnsplit::Record before, after;
  CHECK(::tlb::unpack_cell(previous, before) && ::tlb::unpack_cell(step.state, after));
  auto read_native = [&](const auto& state, const td::Bits256& key) {
    vm::AugmentedDictionary dict(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    Account account(2, key.bits());
    CHECK(account.unpack(dict.lookup(key), state.gen_utime, false));
    return account.balance;
  };
  // Section 11.3: this rejected Deposit was addressed to the coordinator;
  // its value never entered custody. This is NOT a general assertion that
  // bucket bookkeeping alone preserves custody's directly auditable balance.
  CHECK(read_native(before, custody) == read_native(after, custody));
  const auto coordinator = td::Bits256::zero();
  const auto old = decode_workchain_coordinator_state(account_data(previous, coordinator)).move_as_ok();
  const auto next = decode_workchain_coordinator_state(account_data(step.state, coordinator)).move_as_ok();
  CHECK(old.deposit_sequence == next.deposit_sequence && old.system.registered_accounts == next.system.registered_accounts);
  gen::Transaction::Record tx;
  CHECK(::tlb::unpack_cell(accepted_transaction(step, coordinator), tx));
  if (tx.outmsg_cnt == 1) {
    vm::Dictionary outputs(tx.r1.out_msgs, 15);
    td::BitArray<15> key; key.bits().store_uint(0, 15);
    const auto outgoing = outputs.lookup_ref(key);
    gen::CommonMsgInfo::Record_int_msg_info info;
    CHECK(::tlb::unpack_cell_inexact(outgoing, info) && info.bounced && !info.bounce);
    tos::WorkchainId wc; td::Bits256 address;
    CHECK(block::tlb::t_MsgAddressInt.extract_std_address(info.src, wc, address) && wc == 2 && address == coordinator);
    CHECK(block::tlb::t_MsgAddressInt.extract_std_address(info.dest, wc, address) && wc == 0);
    CurrencyCollection returned; CHECK(returned.unpack(info.value));
    CHECK(old.unexpected->get_hash() == next.unexpected->get_hash());
    CHECK(read_native(before, coordinator) == read_native(after, coordinator));
    save(fixture / "rejected-bounce.boc", outgoing);
    std::cout << "Actual rejected Deposit bounce value=" << returned.tomis << "; custody unchanged\n";
  } else {
    CHECK(tx.outmsg_cnt == 0);
    const auto bucket = decode_workchain_unexpected_bucket(next.unexpected, {256, 256}, 4096).move_as_ok();
    CHECK(!bucket.entries.empty());
    const auto& retained = bucket.entries.back();
    CHECK(retained.sender.workchain == 0);
    CurrencyCollection increase;
    // Authenticated after balance includes the inbound credit; checked
    // subtraction establishes a nonnegative measured bucket increase.
    CHECK(CurrencyCollection::sub(read_native(after, coordinator), read_native(before, coordinator), increase));
    CHECK(td::cmp(increase.tomis, retained.tomis) == 0);
    std::cout << "Actual rejected Deposit sender bucket value=" << retained.tomis
              << "; no account_id; custody unchanged because destination was coordinator\n";
  }
}
inline void assert_accepted_deposit(const std::filesystem::path& fixture,
    const td::Ref<vm::Cell>& previous, const AcceptedStep& step) {
  using namespace block;
  const auto input = m4_recorded_candidate(step.block);
  const auto deposit = m3_test::decode_m4_test_deposit(input).move_as_ok();
  const auto before = decode_workchain_confidential_account(account_data(previous, deposit.destination.account)).move_as_ok();
  const auto after = decode_workchain_confidential_account(account_data(step.state, deposit.destination.account)).move_as_ok();
  CHECK(after.system_pending.size() == before.system_pending.size() + 1);
  CHECK(after.available.commitment == before.available.commitment && after.available.handle == before.available.handle);
  const WorkchainDepositReceipt* added = nullptr;
  for (const auto& receipt : after.system_pending) {
    auto old = std::find_if(before.system_pending.begin(), before.system_pending.end(),
        [&](const auto& r) { return r.receipt_id == receipt.receipt_id; });
    if (old == before.system_pending.end()) {
      CHECK(!added);
      added = &receipt;
    }
  }
  CHECK(added && added->amount == deposit.principal);
  td::write_file((fixture / "accepted-receipt.id").string(), td::hex_encode(added->receipt_id.as_slice())).ensure();
  std::cout << "Actual Native Deposit accepted: principal=" << deposit.principal
            << " system_pending=" << after.system_pending.size() << '\n';
}

inline td::Ref<vm::Cell> m4_recorded_candidate(const td::Ref<vm::Cell>& root, td::Ref<vm::Cell>* effects) {
  block::gen::Block::Record block;
  block::gen::BlockExtra::Record extra;
  CHECK(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.extra, extra));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(extra.account_blocks), 256,
                                    block::tlb::aug_ShardAccountBlocks);
  auto leaf = accounts.lookup(td::Bits256::zero());
  block::gen::AccountBlock::Record account;
  CHECK(leaf.not_null() && block::gen::t_AccountBlock.unpack(leaf.write(), account));
  vm::AugmentedDictionary txs(vm::DictNonEmpty(), account.transactions, 64, block::tlb::aug_AccountTransactions);
  td::Ref<vm::Cell> candidate;
  CHECK(txs.check_for_each_extra([&](auto value, auto, td::ConstBitPtr, int) {
    block::gen::Transaction::Record tx;
    block::gen::TransactionDescr::Record_trans_workchain_entry_v3 entry;
    block::gen::UnoV2HostInput::Record host;
    if (candidate.not_null() || !tlb::unpack_cell(value->prefetch_ref(), tx) ||
        !tlb::unpack_cell(tx.description, entry) || !tlb::unpack_cell(entry.input, host)) return false;
    candidate = host.candidate;
    if (effects) *effects = entry.effects;
    return true;
  }));
  CHECK(candidate.not_null());
  return candidate;
}

// Accepted final-import evidence, not a selector's claimed value or a proposed
// effects list. The node has authenticated this dictionary through block replay.
inline block::CurrencyCollection m5_recorded_return(const td::Ref<vm::Cell>& root) {
  using namespace block;
  const auto selector = m3_test::decode_m5_test_failed(m4_recorded_candidate(root)).move_as_ok();
  gen::Block::Record header; gen::BlockExtra::Record extra;
  CHECK(::tlb::unpack_cell(root, header) && ::tlb::unpack_cell(header.extra, extra));
  vm::AugmentedDictionary inputs(vm::load_cell_slice_ref(extra.in_msg_descr), 256, block::tlb::aug_InMsgDescrDefault);
  auto leaf = inputs.lookup(selector.inbound_message);
  gen::InMsg::Record_msg_import_fin imported;
  CHECK(leaf.not_null() && gen::t_InMsg.unpack(leaf.write(), imported));
  block::tlb::MsgEnvelope::Record_std envelope;
  gen::CommonMsgInfo::Record_int_msg_info info;
  CHECK(::tlb::unpack_cell(imported.in_msg, envelope) &&
        ::tlb::unpack_cell_inexact(envelope.msg, info) && info.bounced);
  CHECK(td::Bits256(envelope.msg->get_hash().bits()) == selector.inbound_message);
  tos::WorkchainId wc; td::Bits256 destination;
  CHECK(block::tlb::t_MsgAddressInt.extract_std_address(info.dest, wc, destination) && wc == 2);
  gen::Transaction::Record transaction;
  CHECK(::tlb::unpack_cell(imported.transaction, transaction) && transaction.account_addr == destination);
  CurrencyCollection amount; CHECK(amount.unpack(info.value));
  return amount;
}

inline block::WorkchainOperationFeeAmounts m5_live_return_fee_components(const std::filesystem::path& fixture) {
  auto root = load(fixture / "zerostate.boc");
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},root->get_hash().bits(),td::Bits256::zero()};
  auto config = block::ConfigInfo::extract_config(root,zero,block::Config::needWorkchainInfo | block::Config::needCapabilities).move_as_ok();
  auto ingress = block::load_workchain_native_ingress_table(*config).move_as_ok().at(2);
  auto business = block::m3_test::decode_m3_test_business_parameters(
      block::decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok().parameters).move_as_ok();
  CHECK(business.failed && business.deposit && business.operation_tariff);
  std::uint64_t compute, fee;
  CHECK(!__builtin_mul_overflow(business.operation_tariff->base,business.failed->issuance_billing_units,&compute));
  CHECK(!__builtin_add_overflow(business.deposit->slot_fee,compute,&fee));
  return {business.deposit->slot_fee,compute,0,fee};
}
inline std::uint64_t m5_live_return_fee(const std::filesystem::path& fixture) {
  return m5_live_return_fee_components(fixture).total;
}

inline block::CurrencyCollection m4_wallet_liabilities(const td::Ref<vm::Cell>& root,
    std::optional<std::uint32_t> withdrawal_limit = {}) {
  using namespace block;
  gen::ShardStateUnsplit::Record state;
  CHECK(::tlb::unpack_cell(root, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  CurrencyCollection total(0);
  // Finite test-wallet observation, not a production decryption path or an
  // unconditional cryptographic identity. No predicted balance is substituted.
  for (unsigned owner : {0u, 1u}) {
    const auto key = wallet_account(owner);
    auto leaf = accounts.lookup(key);
    if (leaf.is_null()) continue;  // authenticated nonmembership before registration
    Account native(2, key.bits());
    CHECK(native.unpack(leaf, state.gen_utime, false));
    const auto complete = m5_live_account(native.data,withdrawal_limit);
    const auto& account = complete.account;
    auto add = [&](const WorkchainCiphertext& ciphertext) {
      const auto value = m3_test::decrypt(ciphertext, test_secret(key), 2000000000).move_as_ok();
      CurrencyCollection next;
      CHECK(CurrencyCollection::add(total, CurrencyCollection(workchain_unsigned_fee(value)), next));
      total = std::move(next);
    };
    add(account.available);
    for (const auto& entry : account.pending) add(entry.ciphertext);
    for (const auto& entry : account.system_pending) add(entry.ciphertext);
    for (const auto& entry : complete.origin_pending) add(entry.ciphertext);
  }
  return total;
}

inline td::Status check_m4_fee_pair(const block::CurrencyCollection& old_reserve,
    const block::CurrencyCollection& reserve, const block::CurrencyCollection& old_liability,
    const block::CurrencyCollection& liability, const block::CurrencyCollection& fee) {
  block::CurrencyCollection r, n;
  // Checked subtraction rejects insufficient balances; neither may wrap.
  if (!block::CurrencyCollection::sub(old_reserve, fee, r) ||
      !block::CurrencyCollection::sub(old_liability, fee, n) ||
      td::cmp(r.tomis, reserve.tomis) || td::cmp(n.tomis, liability.tomis))
    return td::Status::Error("M4 custody fee debit and confidential fee debit are not paired");
  return td::Status::OK();
}

inline void assert_m4_block_backing(const std::filesystem::path& fixture, const AcceptedStep& step,
                                    const td::Bits256& custody) {
  using namespace block;
  CurrencyCollection book(0);
  // Reconstruct book value from each accepted block's permanent input, NEVER
  // from the custody balance being checked or a caller-supplied claimed sum.
  for (unsigned n = 1; n <= step.id.id.seqno; ++n) {
    auto root = n == step.id.id.seqno ? step.block : load(fixture / "m4-blocks" / (std::to_string(n) + ".boc"));
    auto candidate = m4_recorded_candidate(root);
    CurrencyCollection next;
    if (m3_test::is_m4_test_deposit(candidate)) {
      auto deposit = m3_test::decode_m4_test_deposit(candidate).move_as_ok();
      if (m4_deposit_was_rejected(root)) next = book;
      else CHECK(CurrencyCollection::add(book, CurrencyCollection(workchain_unsigned_fee(deposit.principal)), next));
    } else if (m3_test::is_m5_test_failed(candidate)) {
      CHECK(CurrencyCollection::add(book, m5_recorded_return(root), next));
      book = next;
      CHECK(CurrencyCollection::sub(book, CurrencyCollection(workchain_unsigned_fee(m5_live_return_fee(fixture))), next));
    } else {
      auto replay = m3_test::decode_m5_accounting_replay(candidate).move_as_ok();
      if (const auto* withdrawal = std::get_if<WorkchainWithdrawalInput>(&replay)) {
        // Prepare now emits the payout in this accepted block. Net physical
        // payout and Native forwarding cost leave backing immediately, not Paid.
        CHECK(CurrencyCollection::sub(book, CurrencyCollection(workchain_unsigned_fee(
            withdrawal->data.amounts.operation_fee)), next));
        book = next;
        CHECK(CurrencyCollection::sub(book, CurrencyCollection(workchain_unsigned_fee(
            withdrawal->data.amounts.principal)), next));
        book = next;
        CHECK(CurrencyCollection::sub(book, CurrencyCollection(workchain_unsigned_fee(
            withdrawal->data.amounts.outward_fee)), next));
      } else if (const auto* transfer = std::get_if<WorkchainTransferInput>(&std::get<WorkchainReplayInput>(replay))) {
        // Each accepted operation already verified this public fee against the
        // authenticated tariff. Insufficient book backing must fail subtraction.
        CHECK(CurrencyCollection::sub(book, CurrencyCollection(workchain_unsigned_fee(
            workchain_transfer_claims(transfer->data).authorized_fee)), next));
      } else next = book; // Registration/closure affect operating funds only.
    }
    book = std::move(next);
  }
  gen::ShardStateUnsplit::Record state;
  CHECK(::tlb::unpack_cell(step.state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  Account coordinator(2, td::Bits256::zero().bits());
  CHECK(coordinator.unpack(accounts.lookup(td::Bits256::zero()), state.gen_utime, false));
  const auto budget = decode_workchain_coordinator_state(coordinator.data).move_as_ok();
  const auto held = workchain_budget_bucket_holdings(budget, 4096).move_as_ok();
  const auto refundable = workchain_protected_refundable(budget.refundable_deposits);
  check_workchain_budget_backing(coordinator.balance, refundable, held).ensure();
  std::cout << "Actual coordinator protected backing: balance=" << coordinator.balance.tomis
            << " refundable=" << refundable.tomis << " unexpected=" << held.tomis << " OK\n";
  Account native(2, custody.bits());
  CHECK(native.unpack(accounts.lookup(custody), state.gen_utime, false));
  check_m4_backing(native.balance.tomis, book.tomis, td::make_refint(0)).ensure();
  const auto limit = m5_live_withdrawal_limit(fixture);
  const auto liabilities = m4_wallet_liabilities(step.state,limit);
  CurrencyCollection p(0), w(0);
  for (unsigned owner : {0u,1u}) {
    const auto key = wallet_account(owner);
    auto leaf = accounts.lookup(key);
    if (leaf.is_null()) continue;
    Account account(2,key.bits()); CHECK(account.unpack(leaf,state.gen_utime,false));
    for (const auto& record : m5_live_account(account.data,limit).control.withdrawals) {
      CHECK(record.timing.phase == 0); // No phase-1/Paid/late profile in this live sequence.
      CurrencyCollection next;
      CHECK(CurrencyCollection::add(p,CurrencyCollection(workchain_unsigned_fee(record.principal)),next)); p=next;
      CHECK(CurrencyCollection::add(w,CurrencyCollection(workchain_unsigned_fee(record.principal)),next)); w=next;
    }
  }
  CurrencyCollection lhs, rhs;
  CHECK(CurrencyCollection::add(native.balance,p,lhs));
  CHECK(CurrencyCollection::add(liabilities,w,rhs));
  std::cout << "BACKING_REPLAY block=" << step.id.id.seqno << " R_actual=" << native.balance.tomis
            << " R_book=" << book.tomis << " N_hidden=" << liabilities.tomis
            << " P=" << p.tomis << " W=" << w.tomis << "; first-layer=OK; checking R+P=N+W" << std::endl;
  check_m4_backing(lhs.tomis, rhs.tomis, td::make_refint(0)).ensure();
  const auto candidate = m4_recorded_candidate(step.block);
  if (!m3_test::is_m4_test_deposit(candidate) && !m3_test::is_m5_test_failed(candidate)) {
    const auto replay = m3_test::decode_m5_accounting_replay(candidate).move_as_ok();
    std::optional<std::uint64_t> public_fee;
    if (const auto* withdrawal = std::get_if<WorkchainWithdrawalInput>(&replay))
      public_fee = withdrawal->data.amounts.operation_fee;
    else if (const auto* transfer = std::get_if<WorkchainTransferInput>(&std::get<WorkchainReplayInput>(replay)))
      public_fee = workchain_transfer_claims(transfer->data).authorized_fee;
    if (public_fee) {
      const auto previous = load(fixture / "current-state.boc");
      gen::ShardStateUnsplit::Record old;
      CHECK(::tlb::unpack_cell(previous, old));
      vm::AugmentedDictionary previous_accounts(vm::load_cell_slice_ref(old.accounts), 256, block::tlb::aug_ShardAccounts);
      Account old_native(2, custody.bits());
      CHECK(old_native.unpack(previous_accounts.lookup(custody), old.gen_utime, false));
      const auto old_liabilities = m4_wallet_liabilities(previous,limit);
      const CurrencyCollection fee(workchain_unsigned_fee(*public_fee));
      auto fee_reserve = native.balance, fee_liability = liabilities;
      if (const auto* withdrawal = std::get_if<WorkchainWithdrawalInput>(&replay)) {
        CurrencyCollection next;
        for (auto amount : {withdrawal->data.amounts.principal,withdrawal->data.amounts.outward_fee}) {
          CHECK(CurrencyCollection::add(fee_reserve,CurrencyCollection(workchain_unsigned_fee(amount)),next)); fee_reserve=next;
          CHECK(CurrencyCollection::add(fee_liability,CurrencyCollection(workchain_unsigned_fee(amount)),next)); fee_liability=next;
        }
      }
      check_m4_fee_pair(old_native.balance, fee_reserve, old_liabilities, fee_liability, fee).ensure();
      CurrencyCollection corrupted;
      CHECK(CurrencyCollection::add(fee_liability, CurrencyCollection(1), corrupted));
      const auto red = check_m4_fee_pair(old_native.balance, fee_reserve, old_liabilities, corrupted, fee);
      CHECK(red.is_error() && red.message() == "M4 custody fee debit and confidential fee debit are not paired");
      check_m4_fee_pair(old_native.balance, fee_reserve, old_liabilities, fee_liability, fee).ensure();
      std::cout << "Actual paired custody/N fee debit=" << fee.tomis << "; unpaired control rejected, restored OK\n";
    }
  }
  // Nonzero controls use the SAME predicate on the actual accepted values.
  if (!book.is_zero()) {
    CurrencyCollection wrong;
    CHECK(CurrencyCollection::add(book, CurrencyCollection(1), wrong));
    CHECK(check_m4_backing(native.balance.tomis, wrong.tomis, td::make_refint(0)).is_error());
    CHECK(check_m4_backing(native.balance.tomis, book.tomis, td::make_refint(1)).is_error());
  }
  std::filesystem::create_directories(fixture / "m4-blocks");
  const auto output = fixture / "m4-blocks" / (std::to_string(step.id.id.seqno) + ".boc");
  CHECK(!std::filesystem::exists(output));
  save(output, step.block);
  std::cout << "M4 actual block " << step.id.to_str() << " R_actual=" << native.balance.tomis
            << " R_book=" << book.tomis << " observed wallet liabilities=" << liabilities.tomis
            << "; D=0 (atomic operation set); nonzero controls="
            << (book.is_zero() ? "not applicable" : "rejected; restored OK") << '\n';
}
} // namespace m3_live
