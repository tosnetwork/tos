#pragma once

#include "block/workchain-construction-observer.h"

#include "block/workchain-storage-overlay.h"
#include "block/workchain-account-access-codec.h"
#include "block/workchain-allocation-plan.h"
#include "block/workchain-import-evidence.h"
#include "block/workchain-native-inbox.h"

namespace block {

struct WorkchainPayoutOverlay {
  WorkchainStorageOverlay state;
  td::Ref<vm::Cell> message;
  WorkchainInternalTransfer fee_funding;
  WorkchainFinalImportEvidence imports;
  // Reconstructed transaction outputs; Native queue admission is separate.
  std::vector<NewOutMsg> exports;
};

// Claimed Native artifacts only. Fee-funding rows are derived by replay, never
// accepted as claimant-supplied accounting evidence.
struct ClaimedWorkchainPayoutOverlay {
  td::Ref<vm::Cell> accounts, account_blocks, message;
  std::uint64_t end_lt;
  td::Ref<vm::Cell> in_msg_descr;
};

// Post-execution materialization of one payout and the complete storage write
// set. Roles, effects, configuration and input closures must be authenticated
// and admitted by the enclosing host. This does not authorize a withdrawal.
// Both receiving roles are planned before old-state reads. Their full-context
// credit traversals require admission; count bounds alone do not bound closure
// work. Strict callers reject foreign recipients. Explicit disposal callers
// route them through the coordinator without filtering the committed inbox.
// Source/VM/builder/allocation exceptions propagate to that boundary.
inline td::Result<WorkchainPayoutOverlay> build_workchain_payout_overlay(
    td::Ref<vm::Cell> old_accounts, tos::WorkchainId workchain, tos::UnixTime now,
    std::uint64_t after_lt, const td::Bits256& input_hash, const td::Bits256& effects_hash,
    const std::vector<WorkchainStorageWrite>& writes, const td::Bits256& custody,
    const td::Bits256& coordinator, td::Ref<vm::Cell> request, td::RefInt256 fee_budget,
    std::uint64_t max_reads, std::uint64_t max_participants, std::uint64_t max_transfers, int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    td::Ref<vm::Cell> entry_input, td::Ref<vm::Cell> entry_effects, std::uint64_t max_inbound,
    const WorkchainDisposalEntryContext* disposal = nullptr,
    const WorkchainConstructionObserver& observer = {}) {
  if (extra_validation_cells <= 0) return td::Status::Error("invalid payout overlay currency budget");
  // Reserve the host-derived fee edge before reading or materializing state.
  auto flow_bound = participant_lt_detail::checked_add(max_transfers, 1);
  if (flow_bound.is_error()) return td::Status::Error("payout transfer count overflow");
  auto flow_limit = flow_bound.move_as_ok();
  if (workchain < 0 || writes.empty() || writes.size() > max_participants || custody == coordinator) {
    return td::Status::Error("invalid payout overlay domain or count");
  }
  std::vector<WorkchainAccountRead> reads;
  WorkchainAllocationPlan allocations;
  WorkchainNativeInboxPlan inbox{{}, after_lt};
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
  if (disposal && (entry_input.is_null() || disposal->max_inbound != max_inbound)) {
    return td::Status::Error("disposal payout requires a complete consistent context");
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
        context.gen_utime != now || context.host_after_lt != after_lt ||
        (disposal && domain.shard_id != tos::shardIdAll)) {
      return td::Status::Error("payout overlay context differs from host");
    }
    td::Ref<vm::Cell> inbox_root;
    if (input.inbox->prefetch_ulong(1) != 0) inbox_root = input.inbox->prefetch_ref();
    std::vector<td::Bits256> recipients{custody, coordinator};
    std::sort(recipients.begin(), recipients.end());
    TRY_RESULT(planned_inbox, disposal ? plan_workchain_disposal_inbox(inbox_root, workchain, after_lt, max_inbound) :
        plan_workchain_native_inbox(inbox_root, workchain, recipients, after_lt, max_inbound));
    inbox = std::move(planned_inbox);
    TRY_RESULT(declarations, decode_workchain_account_declarations(input.access, max_reads, max_participants));
    if (declarations.writes != keys) return td::Status::Error("payout writes differ from committed access");
    reads = std::move(declarations.reads);
    TRY_RESULT(planned, plan_workchain_native_allocations(effects, max_participants, max_transfers, extra_validation_cells));
    allocations = std::move(planned);
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
  auto outbound_limit = disposal ? disposal->max_outbound : 1;
  TRY_RESULT(schedule, plan_workchain_participant_lts(inbox.after_lt, timing, max_participants, outbound_limit));
  using Transaction = transaction::Transaction;
  TRY_RESULT(pair, Transaction::build_workchain_payout_pair(*accounts[custody_index], *accounts[coordinator_index],
      bindings[custody_index], bindings[coordinator_index], writes[custody_index].data, writes[coordinator_index].data,
      request, schedule.start_lt, now, fee_budget, max_transfers, extra_validation_cells, cfg, message_cfg,
      entry_input, entry_effects, disposal));
  // Preparation is performed once. Actual coordinator output count changes
  // end LTs, not the common start determined by old state and the inbox.
  timing[coordinator_index].outbound_count = pair.transactions[1]->out_msgs.size();
  TRY_RESULT(actual_schedule, plan_workchain_participant_lts(inbox.after_lt, timing, max_participants, outbound_limit));
  schedule = std::move(actual_schedule);
  std::vector<std::unique_ptr<Transaction>> transactions(writes.size());
  transactions[custody_index] = std::move(pair.transactions[0]);
  transactions[coordinator_index] = std::move(pair.transactions[1]);
  std::vector<WorkchainAccountValueFlow> rows;
  std::vector<td::Bits256> participants;
  std::map<td::Bits256, td::Ref<vm::Cell>> processing;
  td::Ref<vm::Cell> payout;
  std::vector<NewOutMsg> exports;
  for (std::size_t i = 0; i < writes.size(); ++i) {
    auto& account = *accounts[i];
    if (!transactions[i]) {
      transactions[i] = std::make_unique<Transaction>(account, Transaction::tr_workchain_batch, schedule.start_lt, now);
      if (entry_input.not_null()) {
        // The exact update/write-set scan above proves every write is a plan
        // key. No fallback zero totals may replace a missing authenticated key.
        const auto& totals = allocations.accounts.at(writes[i].account);
        TRY_STATUS(transactions[i]->prepare_workchain_allocation_participant(bindings[i], writes[i].data,
            totals.incoming, totals.outgoing, cfg, extra_validation_cells));
      } else {
        TRY_STATUS(transactions[i]->prepare_workchain_storage_participant(bindings[i], writes[i].data, cfg));
      }
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
        static_cast<std::uint64_t>(record.outmsg_cnt) != schedule.participants[i].outbound_count) {
      return td::Status::Error("invalid payout overlay native artifacts");
    }
    auto description = vm::load_cell_slice(record.description);
    bool is_entry = entry_input.not_null() && i == coordinator_index;
    auto tag = is_entry ? tlb::TransactionDescr::trans_workchain_entry_v3 :
        (entry_input.not_null() || i == custody_index || i == coordinator_index ? tlb::TransactionDescr::trans_workchain_settlement_participant_v3 :
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
    std::uint64_t seen = 0;
    if (!messages.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int bits) {
          if (seen >= schedule.participants[i].outbound_count || bits != 15 ||
              key.get_uint(15) != seen || value->size_ext() != 0x10000) return false;
          auto cell = value->prefetch_ref();
          gen::CommonMsgInfo::Record_int_msg_info message;
          CurrencyCollection payment;
          auto lt = schedule.participants[i].message_lt(seen);
          if (lt.is_error() || !tlb::unpack_cell_inexact(cell, message) || !message.ihr_disabled ||
              message.created_lt != lt.ok() || message.created_at != now || !payment.unpack(message.value)) return false;
          auto forwarding = tlb::t_Tomis.as_integer(message.fwd_fee);
          CurrencyCollection outgoing, total;
          if (forwarding.is_null() || !CurrencyCollection::add(payment, CurrencyCollection(forwarding), outgoing) ||
              !CurrencyCollection::add(exported, outgoing, total) || !total.tomis->unsigned_fits_bits(256)) return false;
          auto next = participant_lt_detail::checked_add(seen, 1);
          if (next.is_error()) return false;
          if (i == custody_index) payout = cell;
          exports.emplace_back(message.created_lt, cell, tx.root, static_cast<unsigned>(seen));
          exported = std::move(total);
          seen = next.move_as_ok();
          return true;
        }) || seen != static_cast<std::uint64_t>(record.outmsg_cnt)) {
      return td::Status::Error("invalid payout overlay outbound value");
    }
    rows.push_back({account.addr, before, CurrencyCollection(0), after, exported, fees});
    processing.emplace(account.addr, tx.root);
    // These accounts and transactions are private. Failure in a later record
    // still publishes neither dictionary nor a message; no CellDb is touched.
    if (tx.commit(account).is_null()) return td::Status::Error("cannot commit private payout account");
    TRY_STATUS(observe_workchain_construction(observer, WorkchainConstructionStage::ParticipantFinalize, i));
    vm::CellBuilder account_block, entry;
    if (!account.create_account_block(account_block) ||
        !blocks.set_builder(account.addr, account_block, vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("cannot build payout overlay AccountBlock");
    }
    TRY_STATUS(observe_workchain_construction(observer, WorkchainConstructionStage::AccountBlockStage, i));
    entry.store_ref(account.total_state).store_bits(account.last_trans_hash_.bits(), 256).store_long(account.last_trans_lt_, 64);
    if (!staged.set_builder(account.addr, entry, vm::Dictionary::SetMode::Replace)) {
      return td::Status::Error("cannot replace payout overlay ShardAccount");
    }
    TRY_STATUS(observe_workchain_construction(observer, WorkchainConstructionStage::AccountRootStage, i));
    TRY_STATUS(access.record_write(account.addr));
    participants.push_back(account.addr);
  }
  TRY_RESULT(imports, disposal ? build_workchain_routed_final_imports(workchain, cfg.global_version, inbox.envelopes,
      processing, coordinator, custody, max_inbound, max_participants, extra_validation_cells, observer) :
      build_workchain_final_imports(workchain, cfg.global_version, inbox.envelopes,
      processing, max_inbound, max_participants, extra_validation_cells, observer));
  for (auto& row : rows) {
    auto credit = imports.account_credits.find(row.account);
    if (credit != imports.account_credits.end()) row.imported = credit->second;
  }
  // The host-derived fee edge is not an engine transfer. It is added exactly
  // once to the independently decoded graph, with a checked count allowance.
  allocations.transfers.push_back(pair.accounting.fee_funding);
  TRY_STATUS(verify_workchain_value_flow(rows, allocations.transfers, max_participants, flow_limit,
      extra_validation_cells));
  auto next_root = staged.get_wrapped_dict_root();
  WorkchainAccountDictionary next(next_root);
  TRY_RESULT(changed, original.changed_accounts(next, max_participants));
  TRY_STATUS(access.finish(changed, participants));
  return WorkchainPayoutOverlay{{next_root, blocks.get_wrapped_dict_root(), schedule.end_lt}, payout,
                                pair.accounting.fee_funding, std::move(imports), std::move(exports)};
}

// Both old state and claimed cells require prior source-aware admission. This
// reconstructs Native artifacts, not engine execution or withdrawal authority.
// Return the reconstructed result on success, never the claimant's containers.
inline td::Result<WorkchainPayoutOverlay> replay_workchain_payout_overlay(
    td::Ref<vm::Cell> old_accounts, tos::WorkchainId workchain, tos::UnixTime now,
    std::uint64_t after_lt, const td::Bits256& input_hash, const td::Bits256& effects_hash,
    const std::vector<WorkchainStorageWrite>& writes, const td::Bits256& custody,
    const td::Bits256& coordinator, td::Ref<vm::Cell> request, td::RefInt256 fee_budget,
    std::uint64_t max_reads, std::uint64_t max_participants, std::uint64_t max_transfers, int extra_validation_cells,
    const SerializeConfig& cfg, const ActionPhaseConfig& message_cfg,
    const ClaimedWorkchainPayoutOverlay& claimed,
    td::Ref<vm::Cell> entry_input, td::Ref<vm::Cell> entry_effects, std::uint64_t max_inbound,
    const WorkchainDisposalEntryContext* disposal = nullptr) {
  if (claimed.accounts.is_null() || claimed.account_blocks.is_null() || claimed.message.is_null() ||
      claimed.in_msg_descr.is_null()) {
    return td::Status::Error("missing claimed payout overlay artifact");
  }
  TRY_RESULT(rebuilt, build_workchain_payout_overlay(old_accounts, workchain, now, after_lt, input_hash, effects_hash,
      writes, custody, coordinator, request, fee_budget, max_reads, max_participants, max_transfers, extra_validation_cells, cfg, message_cfg,
      entry_input, entry_effects, max_inbound, disposal));
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
  if (claimed.in_msg_descr->get_hash() != rebuilt.imports.in_msg_descr->get_hash()) {
    return td::Status::Error("claimed payout InMsgDescr differs from replay");
  }
  return rebuilt;
}

}  // namespace block
