/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <algorithm>

#include "vm/cells/CellSlice.h"

#include "wallet-index-lineage.h"

namespace tos_wallet_index {

td::Result<uint64_t> window_lt_bound(const std::vector<WindowShardTip>& tips, const td::Bits256& account) {
  td::optional<uint64_t> bound;
  for (const auto& tip : tips) {
    if (tip.shard.workchain != tos::basechainId || tip.shard.shard == 0) {
      return td::Status::Error("window tip is not a basechain shard");
    }
    if (!tos::shard_contains(tip.shard.shard, account)) {
      continue;
    }
    if (bound) {
      return td::Status::Error("window tips overlap");
    }
    bound = tip.end_lt;
  }
  if (!bound) {
    return td::Status::Error("no window tip contains the account");
  }
  return bound.value();
}

td::Result<TransactionLink> parse_transaction_link(const td::Ref<vm::Cell>& transaction) {
  if (transaction.is_null()) {
    return td::Status::Error("empty transaction row");
  }
  vm::CellSlice cs{vm::NoVm(), transaction};
  TransactionLink link;
  unsigned long long lt = 0, prev_lt = 0, now = 0;
  if (cs.special_type() != vm::Cell::SpecialType::Ordinary || cs.size() < 4 + 256 + 64 + 256 + 64 + 32 ||
      cs.fetch_ulong(4) != 7 || !cs.fetch_bits_to(link.account.bits(), 256) || !cs.fetch_ulong_bool(64, lt) ||
      !cs.fetch_bits_to(link.prev_hash.bits(), 256) || !cs.fetch_ulong_bool(64, prev_lt) ||
      !cs.fetch_ulong_bool(32, now)) {
    return td::Status::Error("row is not a transaction");
  }
  link.lt = lt;
  link.prev_lt = prev_lt;
  link.now = static_cast<uint32_t>(now);
  link.hash = transaction->get_hash().bits();
  return link;
}

namespace {
LineageResult refused(std::string reason) {
  return {LineageVerdict::Refused, std::move(reason)};
}
}  // namespace

LineageResult verify_account_lineage(const td::Bits256& account, const td::optional<AccountHead>& head,
                                     uint64_t window_bound, const std::vector<td::Ref<vm::Cell>>& rows,
                                     size_t max_events) {
  if (rows.size() > max_events) {
    return refused("more rows than the per-account retention");
  }
  std::vector<TransactionLink> links;
  links.reserve(rows.size());
  for (const auto& row : rows) {
    auto link = parse_transaction_link(row);
    if (link.is_error()) {
      return refused(link.error().message().str());
    }
    if (link.ok().account != account) {
      return refused("row belongs to another account");
    }
    if (link.ok().lt <= window_bound) {
      return refused("row is outside the window");
    }
    if (!links.empty() && link.ok().lt >= links.back().lt) {
      return refused("rows are not ordered newest first");
    }
    links.push_back(link.move_as_ok());
  }
  if (!head) {
    // Nothing in H anchors an account it does not hold. Rows may be forged,
    // and no rows may be a history omitted for an account destroyed inside
    // the window, which H cannot tell from one that never existed. Only the
    // window's blocks can decide.
    return {LineageVerdict::NeedsBlocks, links.empty() ? "account is absent from the checked state and has no rows"
                                                       : "account is absent from the checked state"};
  }
  if (head.value().last_trans_lt <= window_bound) {
    if (!links.empty()) {
      return refused("rows are newer than the account's last transaction");
    }
    return {LineageVerdict::OutsideWindow, ""};
  }
  if (links.empty()) {
    return refused("in-window history is missing");
  }
  if (links.front().lt != head.value().last_trans_lt || links.front().hash != head.value().last_trans_hash) {
    return refused("newest row is not the account's last transaction");
  }
  for (size_t i = 0; i < links.size(); ++i) {
    const auto& link = links[i];
    if (link.prev_lt == 0) {
      // The account was created inside the window. It may have existed
      // before under the same address, which its state cannot show.
      return {LineageVerdict::NeedsBlocks, i + 1 < links.size() ? "rows precede an account creation in the window"
                                                                : "history starts inside the window"};
    }
    if (link.prev_lt <= window_bound) {
      return i + 1 == links.size() ? LineageResult{LineageVerdict::Complete, ""} : refused("rows are not hash-linked");
    }
    if (i + 1 == links.size()) {
      if (links.size() == max_events) {
        return {LineageVerdict::Complete, ""};
      }
      return refused("history is truncated inside the window");
    }
    const auto& next = links[i + 1];
    if (next.lt != link.prev_lt || next.hash != link.prev_hash) {
      return refused("rows are not hash-linked");
    }
  }
  return refused("unreachable lineage state");
}

}  // namespace tos_wallet_index
