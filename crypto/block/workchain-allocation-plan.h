#pragma once

#include <map>

#include "block/block-auto.h"
#include "block/workchain-value-flow.h"

namespace block {

struct WorkchainAllocationTotals {
  CurrencyCollection incoming{0}, outgoing{0};
};

struct WorkchainAllocationPlan {
  std::map<td::Bits256, WorkchainAllocationTotals> accounts;
  std::vector<WorkchainInternalTransfer> transfers;
};

// Decode the replayed effects graph once for the entire batch. Ordered account
// lookup makes work O((accounts + transfers) log accounts), not one graph scan
// per participant. The retained graph is also the independently decoded input
// to Native row conservation; caller-supplied aggregate balances are not used.
// Post-admission only: entry counts do not bound closure loads or currency work.
// This neither authenticates effects nor checks available funds or authorizes
// a debit. Native constructors and independent value-flow checks are both still
// required. Source/VM/builder exceptions propagate to the source-aware boundary.
inline td::Result<WorkchainAllocationPlan> plan_workchain_native_allocations(
    const gen::UnoV2HostEffects::Record& effects, std::uint64_t max_accounts,
    std::uint64_t max_transfers, int extra_validation_cells) {
  if (extra_validation_cells <= 0) return td::Status::Error("invalid batch allocation currency budget");
  WorkchainAllocationPlan plan;
  vm::Dictionary updates(effects.updates, 256);
  if (!updates.check_for_each([&](td::Ref<vm::CellSlice> leaf, td::ConstBitPtr key, int bits) {
        if (plan.accounts.size() >= max_accounts || bits != 256 || leaf->size_ext() != 0x10000) return false;
        td::Bits256 account(key);
        return plan.accounts.emplace(account, WorkchainAllocationTotals{}).second;
      }) || plan.accounts.empty()) return td::Status::Error("invalid batch allocation update set");
  gen::UnoV2NativeEffects::Record native;
  if (!::tlb::unpack_cell(effects.native, native)) return td::Status::Error("invalid batch native effects");
  vm::Dictionary transfers(native.transfers, 32);
  if (!transfers.check_for_each([&](td::Ref<vm::CellSlice> leaf, td::ConstBitPtr key, int bits) {
        if (plan.transfers.size() >= max_transfers || bits != 32 ||
            key.get_uint(32) != plan.transfers.size() || leaf->size_ext() != 0x10000) return false;
        gen::UnoV2NativeTransfer::Record record;
        CurrencyCollection value;
        if (!::tlb::unpack_cell(leaf->prefetch_ref(), record) || record.source == record.destination ||
            !value.unpack(record.value) || value.tomis.is_null() || !value.tomis->is_valid() ||
            !value.tomis->unsigned_fits_bits(256) || value.is_zero() ||
            !value.validate_extra(extra_validation_cells)) return false;
        if (!plan.transfers.empty()) {
          const auto& prior = plan.transfers.back();
          if (!(prior.from < record.source || (prior.from == record.source && prior.to < record.destination))) return false;
        }
        auto from = plan.accounts.find(record.source), to = plan.accounts.find(record.destination);
        if (from == plan.accounts.end() || to == plan.accounts.end()) return false;
        auto add = [&](CurrencyCollection& sum) {
          CurrencyCollection next;
          if (!CurrencyCollection::add(sum, value, next) || !next.tomis->unsigned_fits_bits(256)) return false;
          sum = std::move(next);
          return true;
        };
        if (!add(from->second.outgoing) || !add(to->second.incoming)) return false;
        plan.transfers.push_back({record.source, record.destination, std::move(value)});
        return true;
      })) return td::Status::Error("invalid batch allocation transfer graph or arithmetic");
  return plan;
}

}  // namespace block
