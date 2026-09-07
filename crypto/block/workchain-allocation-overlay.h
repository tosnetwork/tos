#pragma once

#include "block/workchain-allocation-plan.h"
#include "block/workchain-host-input.h"
#include "block/workchain-storage-overlay.h"

namespace block {

// Existing-account, internal-transfer materialization. The single entry carries
// the full committed input/effects; other records carry only their binding.
// Inbox and payout settlement are intentionally rejected until Native message
// evidence and their distinct authorization/fee paths are reconstructed here.
// Roles, input, effects, policy and old-state provenance require admission and
// authentication before this call. Exceptions retain that source at the caller.
// No mutable account escapes and no CellDb write occurs, including on failure.
inline td::Result<WorkchainStorageOverlay> build_workchain_allocation_overlay(
    td::Ref<vm::Cell> old_accounts, const WorkchainHostIdentity& identity,
    td::Ref<vm::Cell> input, td::Ref<vm::Cell> effects, const td::Bits256& coordinator,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_transfers,
    int extra_validation_cells, const SerializeConfig& cfg) {
  gen::UnoV2HostInput::Record decoded;
  gen::UnoV2HostEffects::Record output;
  gen::UnoV2NativeEffects::Record native;
  if (identity.workchain_id < 0 || !tlb::unpack_cell(input, decoded) || !tlb::unpack_cell(effects, output) ||
      !tlb::unpack_cell(output.native, native)) return td::Status::Error("invalid allocation overlay input");
  TRY_RESULT(expected_identity, encode_workchain_host_identity(identity));
  if (decoded.identity->get_hash() != expected_identity->get_hash()) {
    return td::Status::Error("allocation overlay identity mismatch");
  }
  if (decoded.inbox->prefetch_ulong(1) != 0 || native.payout->prefetch_ulong(1) != 0) {
    return td::Status::Error("allocation overlay requires message-free settlement");
  }
  TRY_RESULT(declarations, decode_workchain_account_declarations(decoded.access, max_reads, max_writes));
  TRY_RESULT(plan, plan_workchain_native_allocations(output, max_writes, max_transfers, extra_validation_cells));
  std::vector<td::Bits256> keys;
  for (const auto& entry : plan.accounts) keys.push_back(entry.first);
  if (keys != declarations.writes || plan.accounts.find(coordinator) == plan.accounts.end()) {
    return td::Status::Error("allocation overlay write set or entry role mismatch");
  }
  TRY_RESULT(access, WorkchainAccountAccess::create(declarations.reads, keys, max_reads, max_writes));
  TRY_RESULT(bindings, build_workchain_participant_records(td::Bits256(input->get_hash().bits()),
      td::Bits256(effects->get_hash().bits()), keys, max_writes));
  WorkchainAccountDictionary original(old_accounts);
  for (const auto& read : declarations.reads) TRY_STATUS(original.verify_old_read(access, read.account));
  vm::AugmentedDictionary staged(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
  vm::AugmentedDictionary blocks(256, tlb::aug_ShardAccountBlocks);
  vm::Dictionary updates(output.updates, 256);
  std::vector<std::unique_ptr<Account>> accounts;
  std::vector<WorkchainParticipantTiming> timing;
  for (const auto& key : keys) {
    TRY_RESULT(old_hash, access.expected_read(key));
    if (!old_hash) return td::Status::Error("allocation account creation requires registration settlement");
    auto account = std::make_unique<Account>(identity.workchain_id, key.bits());
    if (!account->unpack(staged.lookup(key), identity.gen_utime, false)) {
      throw vm::VmError{vm::Excno::dict_err, "invalid authenticated allocation account"};
    }
    timing.push_back({key, account->last_trans_end_lt_, 0});
    accounts.push_back(std::move(account));
  }
  TRY_RESULT(schedule, plan_workchain_participant_lts(identity.host_after_lt, timing, max_writes, 0));
  std::vector<WorkchainAccountValueFlow> rows;
  std::vector<td::Bits256> participants;
  for (std::size_t i = 0; i < keys.size(); ++i) {
    auto& account = *accounts[i];
    transaction::Transaction tx(account, transaction::Transaction::tr_workchain_batch,
                                schedule.start_lt, identity.gen_utime);
    if (keys[i] == coordinator) {
      TRY_STATUS(tx.prepare_workchain_entry(bindings[i], input, effects, updates.lookup_ref(keys[i]),
                                           cfg, max_transfers, extra_validation_cells));
    } else {
      const auto& totals = plan.accounts.at(keys[i]);
      TRY_STATUS(tx.prepare_workchain_allocation_participant(bindings[i], updates.lookup_ref(keys[i]),
          totals.incoming, totals.outgoing, cfg, extra_validation_cells));
    }
    if (tx.start_lt != schedule.start_lt || tx.end_lt != schedule.participants[i].end_lt || !tx.serialize(cfg)) {
      return td::Status::Error("allocation transaction differs from native schedule or limits");
    }
    // Derive balances and fees from serialized Native artifacts, not the plan
    // or mutable transaction cache. Zero imports/exports are backed by both
    // the message-free input/effects above and each Native message dictionary.
    gen::Transaction::Record record;
    gen::Account::Record_account old_record, next_record;
    gen::AccountStorage::Record old_storage, next_storage;
    CurrencyCollection before, after, fees;
    if (!tlb::unpack_cell(tx.root, record) || record.account_addr != account.addr ||
        record.prev_trans_hash != account.last_trans_hash_ || record.prev_trans_lt != account.last_trans_lt_ ||
        !tlb::unpack_cell(account.total_state, old_record) || !tlb::csr_unpack(old_record.storage, old_storage) ||
        !tlb::unpack_cell(tx.new_total_state, next_record) || !tlb::csr_unpack(next_record.storage, next_storage) ||
        !before.unpack(old_storage.balance) || !after.unpack(next_storage.balance) || !fees.unpack(record.total_fees) ||
        !fees.is_zero() || next_storage.last_trans_lt != tx.end_lt || record.lt != tx.start_lt ||
        record.r1.in_msg->prefetch_ulong(1) != 0 || record.r1.out_msgs->prefetch_ulong(1) != 0 || record.outmsg_cnt != 0) {
      return td::Status::Error("invalid allocation overlay native artifacts");
    }
    auto hashes = vm::load_cell_slice(record.state_update);
    td::Bits256 old_hash, new_hash;
    if (hashes.fetch_ulong(8) != 0x72 || !hashes.fetch_bits_to(old_hash) || !hashes.fetch_bits_to(new_hash) ||
        !hashes.empty_ext() || old_hash != account.total_state->get_hash().bits() ||
        new_hash != tx.new_total_state->get_hash().bits()) {
      return td::Status::Error("allocation overlay state hash mismatch");
    }
    rows.push_back({account.addr, before, CurrencyCollection(0), after, CurrencyCollection(0), fees});
    // Commit only private objects. A later participant failure cannot publish
    // these dictionary roots or mutate the caller's authenticated old root.
    if (tx.commit(account).is_null()) return td::Status::Error("cannot commit private allocation account");
    vm::CellBuilder account_block, entry;
    if (!account.create_account_block(account_block) ||
        !blocks.set_builder(account.addr, account_block, vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("cannot construct allocation AccountBlock");
    }
    entry.store_ref(account.total_state).store_bits(account.last_trans_hash_.bits(), 256)
        .store_long(account.last_trans_lt_, 64);
    if (!staged.set_builder(account.addr, entry, vm::Dictionary::SetMode::Replace)) {
      return td::Status::Error("cannot replace allocation ShardAccount");
    }
    TRY_STATUS(access.record_write(account.addr));
    participants.push_back(account.addr);
  }
  TRY_STATUS(verify_workchain_value_flow(rows, plan.transfers, max_writes, max_transfers, extra_validation_cells));
  auto next_root = staged.get_wrapped_dict_root();
  WorkchainAccountDictionary next(next_root);
  TRY_RESULT(changed, original.changed_accounts(next, max_writes));
  TRY_STATUS(access.finish(changed, participants));
  return WorkchainStorageOverlay{next_root, blocks.get_wrapped_dict_root(), schedule.end_lt};
}

// Reconstruct all Native artifacts, never adopt claimed roots after comparing
// only a batch digest. Engine replay and authenticated inputs remain upstream.
inline td::Result<WorkchainStorageOverlay> replay_workchain_allocation_overlay(
    td::Ref<vm::Cell> old_accounts, const WorkchainHostIdentity& identity,
    td::Ref<vm::Cell> input, td::Ref<vm::Cell> effects, const td::Bits256& coordinator,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_transfers,
    int extra_validation_cells, const SerializeConfig& cfg, const WorkchainStorageOverlay& claimed) {
  if (claimed.accounts.is_null() || claimed.account_blocks.is_null()) {
    return td::Status::Error("missing claimed allocation artifacts");
  }
  TRY_RESULT(rebuilt, build_workchain_allocation_overlay(old_accounts, identity, input, effects, coordinator,
      max_reads, max_writes, max_transfers, extra_validation_cells, cfg));
  if (rebuilt.accounts->get_hash() != claimed.accounts->get_hash() ||
      rebuilt.account_blocks->get_hash() != claimed.account_blocks->get_hash() || rebuilt.end_lt != claimed.end_lt) {
    return td::Status::Error("claimed allocation artifacts differ from replay");
  }
  return rebuilt;
}

}  // namespace block
