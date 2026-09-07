#pragma once

#include "block/workchain-storage-overlay.h"
#include "block/workchain-account-access-codec.h"

namespace block {

struct WorkchainPayoutOverlay {
  WorkchainStorageOverlay state;
  td::Ref<vm::Cell> message;
  WorkchainInternalTransfer fee_funding;
};

// Claimed Native artifacts only. Fee-funding rows are derived by replay, never
// accepted as claimant-supplied accounting evidence.
struct ClaimedWorkchainPayoutOverlay {
  td::Ref<vm::Cell> accounts, account_blocks, message;
  std::uint64_t end_lt;
};

// Post-execution materialization of one payout and the complete storage write
// set. Roles, effects, configuration and input closures must be authenticated
// and admitted by the enclosing host. This does not authorize a withdrawal.
// Source/VM/builder/allocation exceptions propagate to that boundary.
inline td::Result<WorkchainPayoutOverlay> build_workchain_payout_overlay(
    td::Ref<vm::Cell> old_accounts, tos::WorkchainId workchain, tos::UnixTime now,
    std::uint64_t after_lt, const td::Bits256& input_hash, const td::Bits256& effects_hash,
    const std::vector<WorkchainStorageWrite>& writes, const td::Bits256& custody,
    const td::Bits256& coordinator, td::Ref<vm::Cell> request, td::RefInt256 fee_budget,
    std::uint64_t max_reads, std::uint64_t max_participants, int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    td::Ref<vm::Cell> entry_input, td::Ref<vm::Cell> entry_effects) {
  if (extra_validation_cells <= 0) return td::Status::Error("invalid payout overlay currency budget");
  if (workchain < 0 || writes.empty() || writes.size() > max_participants || custody == coordinator) {
    return td::Status::Error("invalid payout overlay domain or count");
  }
  std::vector<WorkchainAccountRead> reads;
  std::vector<td::Bits256> keys;
  std::size_t custody_index = writes.size(), coordinator_index = writes.size();
  for (std::size_t i = 0; i < writes.size(); ++i) {
    reads.push_back({writes[i].account, writes[i].old_account_hash});
    keys.push_back(writes[i].account);
    if (writes[i].account == custody) custody_index = i;
    if (writes[i].account == coordinator) coordinator_index = i;
  }
  if (custody_index == writes.size() || coordinator_index == writes.size()) {
    return td::Status::Error("payout roles absent from write set");
  }
  if (entry_input.is_null() != entry_effects.is_null()) {
    return td::Status::Error("payout overlay requires both context roots");
  }
  if (entry_input.not_null()) {
    gen::UnoV2HostInput::Record input;
    gen::UnoV2HostEffects::Record effects;
    gen::UnoV2HostIdentity::Record identity;
    gen::UnoV2HostDomain::Record domain;
    gen::UnoV2HostContext::Record context;
    if (!tlb::unpack_cell(entry_input, input) || !tlb::unpack_cell(entry_effects, effects) ||
        !tlb::unpack_cell(input.identity, identity) || !tlb::unpack_cell(identity.domain, domain) ||
        !tlb::unpack_cell(identity.context, context) || domain.workchain_id != workchain ||
        context.gen_utime != now || context.host_after_lt != after_lt) {
      return td::Status::Error("payout overlay context differs from host");
    }
    TRY_RESULT(declarations, decode_workchain_account_declarations(input.access, max_reads, max_participants));
    if (declarations.writes != keys) return td::Status::Error("payout writes differ from committed access");
    reads = std::move(declarations.reads);
    vm::Dictionary updates(effects.updates, 256);
    std::uint64_t seen = 0;
    if (!updates.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int bits) {
          if (seen >= writes.size() || bits != 256 || td::Bits256(key) != writes[seen].account ||
              value->size_ext() != 0x10000 || writes[seen].data.is_null() ||
              value->prefetch_ref()->get_hash() != writes[seen].data->get_hash()) return false;
          auto next = participant_lt_detail::checked_add(seen, 1);
          if (next.is_error()) return false;
          seen = next.move_as_ok();
          return true;
        }) || seen != writes.size()) return td::Status::Error("payout data differs from committed effects");
  }
  TRY_RESULT(access, WorkchainAccountAccess::create(reads, keys, max_reads, max_participants));
  for (const auto& write : writes) {
    TRY_RESULT(expected, access.expected_read(write.account));
    if (!expected || *expected != write.old_account_hash) {
      return td::Status::Error("payout write old hash differs from committed read");
    }
  }
  TRY_RESULT(bindings, build_workchain_participant_records(input_hash, effects_hash, keys, max_participants));
  WorkchainAccountDictionary original(old_accounts);
  for (const auto& read : reads) TRY_STATUS(original.verify_old_read(access, read.account));
  vm::AugmentedDictionary staged(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
  vm::AugmentedDictionary blocks(256, tlb::aug_ShardAccountBlocks);
  std::vector<std::unique_ptr<Account>> accounts;
  std::vector<WorkchainParticipantTiming> timing;
  for (const auto& write : writes) {
    auto account = std::make_unique<Account>(workchain, write.account.bits());
    if (!account->unpack(staged.lookup(write.account), now, false)) {
      throw vm::VmError{vm::Excno::dict_err, "invalid authenticated payout account"};
    }
    timing.push_back({write.account, account->last_trans_end_lt_, write.account == custody ? 1u : 0u});
    accounts.push_back(std::move(account));
  }
  TRY_RESULT(schedule, plan_workchain_participant_lts(after_lt, timing, max_participants, 1));
  using Transaction = transaction::Transaction;
  TRY_RESULT(pair, Transaction::build_workchain_payout_pair(*accounts[custody_index], *accounts[coordinator_index],
      bindings[custody_index], bindings[coordinator_index], writes[custody_index].data, writes[coordinator_index].data,
      request, schedule.start_lt, now, fee_budget, extra_validation_cells, cfg, message_cfg,
      entry_input, entry_effects));
  std::vector<std::unique_ptr<Transaction>> transactions(writes.size());
  transactions[custody_index] = std::move(pair.transactions[0]);
  transactions[coordinator_index] = std::move(pair.transactions[1]);
  std::vector<WorkchainAccountValueFlow> rows;
  std::vector<td::Bits256> participants;
  td::Ref<vm::Cell> payout;
  for (std::size_t i = 0; i < writes.size(); ++i) {
    auto& account = *accounts[i];
    if (!transactions[i]) {
      transactions[i] = std::make_unique<Transaction>(account, Transaction::tr_workchain_batch, schedule.start_lt, now);
      TRY_STATUS(transactions[i]->prepare_workchain_storage_participant(bindings[i], writes[i].data, cfg));
    }
    auto& tx = *transactions[i];
    if (tx.start_lt != schedule.start_lt || tx.end_lt != schedule.participants[i].end_lt || !tx.serialize(cfg)) {
      return td::Status::Error("payout overlay transaction differs from planned schedule");
    }
    // Re-read Native artifacts instead of accepting the allocation helper's
    // self-consistent rows as independent evidence of the serialized result.
    gen::Transaction::Record record;
    gen::Account::Record_account old_record, next_record;
    gen::AccountStorage::Record old_storage, next_storage;
    CurrencyCollection before, after, fees, exported(0);
    if (!tlb::unpack_cell(tx.root, record) || record.account_addr != account.addr ||
        !tlb::unpack_cell(account.total_state, old_record) || !tlb::csr_unpack(old_record.storage, old_storage) ||
        !tlb::unpack_cell(tx.new_total_state, next_record) || !tlb::csr_unpack(next_record.storage, next_storage) ||
        !before.unpack(old_storage.balance) || !after.unpack(next_storage.balance) || !fees.unpack(record.total_fees) ||
        next_storage.last_trans_lt != tx.end_lt || record.r1.in_msg->prefetch_ulong(1) != 0 ||
        record.outmsg_cnt != (i == custody_index ? 1 : 0)) {
      return td::Status::Error("invalid payout overlay native artifacts");
    }
    auto description = vm::load_cell_slice(record.description);
    bool is_entry = entry_input.not_null() && i == coordinator_index;
    auto tag = is_entry ? tlb::TransactionDescr::trans_workchain_entry_v3 :
        (i == custody_index || i == coordinator_index ? tlb::TransactionDescr::trans_workchain_settlement_participant_v3 :
                                                       tlb::TransactionDescr::trans_workchain_storage_participant_v3);
    if (description.fetch_ulong(4) != static_cast<unsigned>(tag) || description.size_refs() != (is_entry ? 3u : 1u) ||
        description.fetch_ref()->get_hash() != bindings[i]->get_hash() ||
        (is_entry && (description.fetch_ref()->get_hash() != entry_input->get_hash() ||
                   description.fetch_ref()->get_hash() != entry_effects->get_hash())) || !description.empty_ext()) {
      return td::Status::Error("payout serialized entry or participant differs from context");
    }
    auto hashes = vm::load_cell_slice(record.state_update);
    td::Bits256 old_hash, new_hash;
    if (hashes.fetch_ulong(8) != 0x72 || !hashes.fetch_bits_to(old_hash) || !hashes.fetch_bits_to(new_hash) ||
        old_hash != account.total_state->get_hash().bits() || new_hash != tx.new_total_state->get_hash().bits()) {
      return td::Status::Error("payout overlay state hash binding mismatch");
    }
    vm::Dictionary messages(record.r1.out_msgs, 15);
    unsigned seen = 0;
    if (!messages.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int bits) {
          if (i != custody_index || seen != 0 || bits != 15 || key.get_uint(15) != 0 || value->size_ext() != 0x10000) return false;
          ++seen;  // Guard establishes seen == 0 before this bounded increment.
          payout = value->prefetch_ref();
          gen::CommonMsgInfo::Record_int_msg_info message;
          CurrencyCollection payment;
          if (!tlb::unpack_cell_inexact(payout, message) || !message.ihr_disabled || !payment.unpack(message.value)) return false;
          auto forwarding = tlb::t_Tomis.as_integer(message.fwd_fee);
          return forwarding.not_null() && CurrencyCollection::add(payment, CurrencyCollection(forwarding), exported) &&
                 exported.tomis->unsigned_fits_bits(256);
        }) || seen != static_cast<unsigned>(record.outmsg_cnt)) {
      return td::Status::Error("invalid payout overlay outbound value");
    }
    rows.push_back({account.addr, before, CurrencyCollection(0), after, exported, fees});
    // These accounts and transactions are private. Failure in a later record
    // still publishes neither dictionary nor a message; no CellDb is touched.
    tx.commit(account);
    vm::CellBuilder account_block, entry;
    if (!account.create_account_block(account_block) ||
        !blocks.set_builder(account.addr, account_block, vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("cannot build payout overlay AccountBlock");
    }
    entry.store_ref(account.total_state).store_bits(account.last_trans_hash_.bits(), 256).store_long(account.last_trans_lt_, 64);
    if (!staged.set_builder(account.addr, entry, vm::Dictionary::SetMode::Replace)) {
      return td::Status::Error("cannot replace payout overlay ShardAccount");
    }
    TRY_STATUS(access.record_write(account.addr));
    participants.push_back(account.addr);
  }
  TRY_STATUS(verify_workchain_value_flow(rows, {pair.accounting.fee_funding}, max_participants, 1,
      extra_validation_cells));
  auto next_root = staged.get_wrapped_dict_root();
  WorkchainAccountDictionary next(next_root);
  TRY_RESULT(changed, original.changed_accounts(next, max_participants));
  TRY_STATUS(access.finish(changed, participants));
  return WorkchainPayoutOverlay{{next_root, blocks.get_wrapped_dict_root(), schedule.end_lt}, payout,
                                pair.accounting.fee_funding};
}

// Both old state and claimed cells require prior source-aware admission. This
// reconstructs Native artifacts, not engine execution or withdrawal authority.
// Return the reconstructed result on success, never the claimant's containers.
inline td::Result<WorkchainPayoutOverlay> replay_workchain_payout_overlay(
    td::Ref<vm::Cell> old_accounts, tos::WorkchainId workchain, tos::UnixTime now,
    std::uint64_t after_lt, const td::Bits256& input_hash, const td::Bits256& effects_hash,
    const std::vector<WorkchainStorageWrite>& writes, const td::Bits256& custody,
    const td::Bits256& coordinator, td::Ref<vm::Cell> request, td::RefInt256 fee_budget,
    std::uint64_t max_reads, std::uint64_t max_participants, int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const ClaimedWorkchainPayoutOverlay& claimed,
    td::Ref<vm::Cell> entry_input, td::Ref<vm::Cell> entry_effects) {
  if (claimed.accounts.is_null() || claimed.account_blocks.is_null() || claimed.message.is_null()) {
    return td::Status::Error("missing claimed payout overlay artifact");
  }
  TRY_RESULT(rebuilt, build_workchain_payout_overlay(old_accounts, workchain, now, after_lt, input_hash, effects_hash,
      writes, custody, coordinator, request, fee_budget, max_reads, max_participants, extra_validation_cells, cfg, message_cfg,
      entry_input, entry_effects));
  if (claimed.accounts->get_hash() != rebuilt.state.accounts->get_hash()) {
    return td::Status::Error("claimed payout accounts differ from replay");
  }
  if (claimed.account_blocks->get_hash() != rebuilt.state.account_blocks->get_hash()) {
    return td::Status::Error("claimed payout AccountBlocks differ from replay");
  }
  if (claimed.message->get_hash() != rebuilt.message->get_hash()) {
    return td::Status::Error("claimed payout message differs from replay");
  }
  if (claimed.end_lt != rebuilt.state.end_lt) {
    return td::Status::Error("claimed payout end LT differs from replay");
  }
  return rebuilt;
}

}  // namespace block
