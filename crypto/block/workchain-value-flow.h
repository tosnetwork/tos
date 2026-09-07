#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

#include "block/block.h"

namespace block {

struct WorkchainAccountValueFlow {
  td::Bits256 account;
  CurrencyCollection old_balance, imported, new_balance, exported, fees;
};
struct WorkchainInternalTransfer {
  td::Bits256 from, to;
  CurrencyCollection value;
};

// Read-only arithmetic validation. Rows must come from independently rebuilt
// Native account/message evidence. Transfer authorization is checked separately
// against semantic effects; conservation alone does not authorize spending.
// All input closures must already be admitted. Parsing/allocation exceptions
// propagate to the source-aware host boundary, not a candidate error catch-all.
inline td::Status verify_workchain_value_flow(
    const std::vector<WorkchainAccountValueFlow>& rows,
    const std::vector<WorkchainInternalTransfer>& transfers,
    std::uint64_t max_accounts, std::uint64_t max_transfers, int extra_validation_cells) {
  if (rows.empty() || rows.size() > max_accounts || transfers.size() > max_transfers || extra_validation_cells <= 0) {
    return td::Status::Error("value-flow inputs exceed admitted bounds");
  }
  auto valid = [&](const CurrencyCollection& value) {
    return value.tomis.not_null() && value.tomis->is_valid() && value.tomis->unsigned_fits_bits(256) &&
           value.validate_extra(extra_validation_cells);
  };
  auto checked_add = [](const CurrencyCollection& a, const CurrencyCollection& b, CurrencyCollection& out) {
    // The bigint backing store can temporarily exceed the nominal width.
    // Pin the accumulator to unsigned 256 bits rather than relying on storage
    // exhaustion. Native wire-amount limits are enforced separately.
    return CurrencyCollection::add(a, b, out) && out.tomis->unsigned_fits_bits(256);
  };
  std::vector<CurrencyCollection> left, right;
  left.reserve(rows.size());
  right.reserve(rows.size());
  const td::Bits256* previous = nullptr;
  for (const auto& row : rows) {
    if (previous && !(*previous < row.account)) return td::Status::Error("value-flow accounts not strictly ordered");
    previous = &row.account;
    for (const auto* value : {&row.old_balance, &row.imported, &row.new_balance, &row.exported, &row.fees}) {
      if (!valid(*value)) return td::Status::Error("invalid value-flow amount");
    }
    CurrencyCollection lhs, subtotal, rhs;
    if (!checked_add(row.old_balance, row.imported, lhs) ||
        !checked_add(row.new_balance, row.exported, subtotal) ||
        !checked_add(subtotal, row.fees, rhs)) {
      return td::Status::Error("value-flow arithmetic overflow");
    }
    left.push_back(std::move(lhs));
    right.push_back(std::move(rhs));
  }
  auto locate = [&](const td::Bits256& key) {
    return std::lower_bound(rows.begin(), rows.end(), key,
        [](const WorkchainAccountValueFlow& row, const td::Bits256& id) { return row.account < id; });
  };
  for (const auto& transfer : transfers) {
    if (!valid(transfer.value)) return td::Status::Error("invalid internal transfer amount");
    auto from = locate(transfer.from), to = locate(transfer.to);
    if (from == rows.end() || from->account != transfer.from || to == rows.end() || to->account != transfer.to) {
      return td::Status::Error("internal transfer account outside value-flow rows");
    }
    // Successful lookup establishes begin <= iterator < end before distance
    // conversion; both distances are valid indices in the parallel vectors.
    auto debit = static_cast<std::size_t>(from - rows.begin());
    auto credit = static_cast<std::size_t>(to - rows.begin());
    CurrencyCollection incoming, outgoing;
    if (!checked_add(left[credit], transfer.value, incoming) ||
        !checked_add(right[debit], transfer.value, outgoing)) {
      return td::Status::Error("internal transfer arithmetic overflow");
    }
    left[credit] = std::move(incoming);
    right[debit] = std::move(outgoing);
  }
  for (auto it = rows.begin(); it != rows.end(); ++it) {
    // Iteration establishes a nonnegative, in-range vector offset.
    auto i = static_cast<std::size_t>(it - rows.begin());
    CurrencyCollection remainder;
    // sub checks nonnegativity and every extra-currency subtraction; no raw
    // subtraction or encoding-hash equality is used for monetary comparison.
    if (!CurrencyCollection::sub(left[i], right[i], remainder) || !remainder.is_zero()) {
      return td::Status::Error("per-account native value-flow mismatch");
    }
  }
  return td::Status::OK();
}

}  // namespace block
