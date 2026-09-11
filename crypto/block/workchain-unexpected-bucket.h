#pragma once

#include "block/block.h"
#include "vm/dict.h"
#include <algorithm>
#include <vector>

namespace block {

// D29/D30, M4 subset: only sender attribution. No confidential account_id,
// original body, claim, retry or sweep operation is representable here.
// Layout is an implementation choice: UNX4/version 1, counts, rebase_count,
// unkeyed uint256, HashmapE 32 entry refs, HashmapE 288 overflow uint256,
// and Native extra-currency dictionary. Entry = kind 0 + wc:int32 + src:bits256
// + tomis:uint256. Unknown kinds/versions and trailing bits/refs are rejected.
// Net values use unsigned 256-bit arithmetic, not cumulative traffic counters.
struct WorkchainUnexpectedSender {
  std::int32_t workchain;
  td::Bits256 account;
};
struct WorkchainUnexpectedEntry {
  WorkchainUnexpectedSender sender;
  td::RefInt256 tomis;
};
struct WorkchainUnexpectedLimits {
  std::uint32_t entries, overflow_sources;
  // No local defaults. M4 test configuration supplies 256/256, NOT frozen.
  // Both limits must arrive through authenticated test configuration.
};
struct WorkchainUnexpectedBucket {
  std::vector<WorkchainUnexpectedEntry> entries, overflow;
  td::RefInt256 unkeyed;
  td::Ref<vm::Cell> extra;
  std::uint64_t rebase_count;
};
struct WorkchainUnexpectedCredit {
  WorkchainUnexpectedBucket bucket;
  // These flags are mandatory inputs to the caller's effects event/alarm.
  bool sender_attribution_lost, extra_attribution_lost;
};

namespace unexpected_detail {
inline bool amount(const td::RefInt256& value) {
  return value.not_null() && value->is_valid() && value->unsigned_fits_bits(256);
}
inline td::Result<td::RefInt256> add(const td::RefInt256& a, const td::RefInt256& b) {
  if (!amount(a) || !amount(b)) return td::Status::Error("invalid unexpected bucket amount");
  auto result = a + b;
  if (!amount(result)) return td::Status::Error("unexpected bucket amount overflow");
  return result;
}
inline td::BitArray<288> key(const WorkchainUnexpectedSender& sender) {
  td::BitArray<288> result;
  result.bits().store_int(sender.workchain, 32);
  (result.bits() + 32).copy_from(sender.account.bits(), 256);
  return result;
}
}  // namespace unexpected_detail

// Codec/structural errors have no consensus provenance here. The caller must
// distinguish unavailable old state from malformed candidate bytes. Allocation
// and cell acquisition exceptions propagate; they never select another branch.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_unexpected_bucket(
    const WorkchainUnexpectedBucket& value, WorkchainUnexpectedLimits limits, int extra_validation_cells) {
  if (value.entries.size() > limits.entries || value.overflow.size() > limits.overflow_sources ||
      !unexpected_detail::amount(value.unkeyed) || extra_validation_cells <= 0 ||
      !CurrencyCollection(td::make_refint(0), value.extra).validate_extra(extra_validation_cells)) {
    return td::Status::Error("invalid unexpected bucket structure or limits");
  }
  vm::Dictionary entries(32), overflow(288);
  auto total = value.unkeyed;
  std::uint32_t index = 0;
  for (const auto& entry : value.entries) {
    if (!unexpected_detail::amount(entry.tomis) || td::sgn(entry.tomis) <= 0)
      return td::Status::Error("invalid attributed unexpected amount");
    TRY_RESULT(sum, unexpected_detail::add(total, entry.tomis));
    total = sum;
    vm::CellBuilder leaf;
    leaf.store_long(0, 8).store_long(entry.sender.workchain, 32)
        .store_bits(entry.sender.account.bits(), 256).store_int256(*entry.tomis, 256, false);
    if (!entries.set_ref(td::BitArray<32>(index++), leaf.finalize(), vm::Dictionary::SetMode::Add))
      return td::Status::Error("duplicate unexpected entry index");
  }
  for (const auto& entry : value.overflow) {
    if (!unexpected_detail::amount(entry.tomis) || td::sgn(entry.tomis) <= 0)
      return td::Status::Error("invalid overflow amount");
    TRY_RESULT(sum, unexpected_detail::add(total, entry.tomis));
    total = sum;
    vm::CellBuilder leaf;
    leaf.store_int256(*entry.tomis, 256, false);
    if (!overflow.set_builder(unexpected_detail::key(entry.sender), leaf, vm::Dictionary::SetMode::Add))
      return td::Status::Error("duplicate unexpected overflow source");
  }
  vm::CellBuilder root;
  root.store_long(0x554e5834, 32).store_long(1, 16)
      .store_long(value.entries.size(), 32).store_long(value.overflow.size(), 32)
      .store_long(value.rebase_count, 64).store_int256(*value.unkeyed, 256, false);
  if (!entries.append_dict_to_bool(root) || !overflow.append_dict_to_bool(root) ||
      !vm::dict::store_cell_dict(root, value.extra)) return td::Status::Error("cannot encode unexpected bucket");
  return root.finalize();
}

inline td::Result<WorkchainUnexpectedBucket> decode_workchain_unexpected_bucket(
    const td::Ref<vm::Cell>& root, WorkchainUnexpectedLimits limits, int extra_validation_cells) {
  if (root.is_null()) return td::Status::Error("missing unexpected bucket");
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() < 435 || cs.fetch_ulong(32) != 0x554e5834 || cs.fetch_ulong(16) != 1)
    return td::Status::Error("unknown unexpected bucket shape");
  const auto count = cs.fetch_ulong(32), overflow_count = cs.fetch_ulong(32);
  if (count > limits.entries || overflow_count > limits.overflow_sources)
    return td::Status::Error("unexpected bucket exceeds authenticated limits");
  const auto rebase = cs.fetch_ulong(64);
  auto unkeyed = cs.fetch_int256(256, false);
  // Preflight each HashmapE selector/ref before constructing dictionaries.
  td::Ref<vm::Cell> roots[3];
  for (auto& item : roots) {
    if (!cs.size()) return td::Status::Error("missing unexpected dictionary selector");
    if (cs.fetch_ulong(1)) {
      if (!cs.size_refs()) return td::Status::Error("missing unexpected dictionary root");
      item = cs.fetch_ref();
    }
  }
  if (!cs.empty_ext()) return td::Status::Error("trailing unexpected bucket fields");
  WorkchainUnexpectedBucket value{{}, {}, unkeyed, roots[2], rebase};
  vm::Dictionary entries(roots[0], 32), overflow(roots[1], 288);
  if (!entries.check_for_each([&](td::Ref<vm::CellSlice> leaf, td::ConstBitPtr key, int width) {
        if (width != 32 || value.entries.size() >= count ||
            key.get_uint(32) != value.entries.size() || leaf->size_ext() != 0x10000) return false;
        bool exotic = false;
        auto entry = vm::load_cell_slice_special(leaf->prefetch_ref(), exotic);
        if (exotic || entry.size_ext() != 552 || entry.fetch_ulong(8) != 0) return false;
        WorkchainUnexpectedSender sender{static_cast<std::int32_t>(entry.fetch_long(32)), {}};
        entry.fetch_bits_to(sender.account);
        value.entries.push_back({sender, entry.fetch_int256(256, false)});
        return true;
      }) || value.entries.size() != count ||
      !overflow.check_for_each([&](td::Ref<vm::CellSlice> leaf, td::ConstBitPtr key, int width) {
        if (width != 288 || value.overflow.size() >= overflow_count || leaf->size_ext() != 256) return false;
        value.overflow.push_back({{static_cast<std::int32_t>(key.get_int(32)), td::Bits256(key + 32)},
                                  leaf.write().fetch_int256(256, false)});
        return true;
      }) || value.overflow.size() != overflow_count) return td::Status::Error("invalid unexpected dictionaries");
  TRY_RESULT(canonical, encode_workchain_unexpected_bucket(value, limits, extra_validation_cells));
  if (canonical->get_hash() != root->get_hash()) return td::Status::Error("noncanonical unexpected bucket");
  return value;
}

inline td::Result<CurrencyCollection> workchain_unexpected_balance(const WorkchainUnexpectedBucket& bucket) {
  auto total = bucket.unkeyed;
  for (const auto& entry : bucket.entries) {
    TRY_RESULT(next, unexpected_detail::add(total, entry.tomis));
    total = next;
  }
  for (const auto& entry : bucket.overflow) {
    TRY_RESULT(next, unexpected_detail::add(total, entry.tomis));
    total = next;
  }
  if (!unexpected_detail::amount(total)) return td::Status::Error("invalid unexpected net balance");
  return CurrencyCollection(total, bucket.extra);
}

// Post-classification only. This consumes neither the message nor any state;
// caller commits its returned bucket with Native credit/queue removal atomically.
// M4 failed Deposit belongs to src, never to the intended confidential account.
// Consequently no confidential account obtains bucket rights. M5's account_id
// category is deliberately unrepresentable. Before introducing it, closure
// must additionally establish no bucket attribution to that account (D29/§10).
inline td::Result<WorkchainUnexpectedCredit> credit_workchain_unexpected(
    const WorkchainUnexpectedBucket& old, WorkchainUnexpectedLimits limits,
    const WorkchainUnexpectedSender& sender, const CurrencyCollection& imported, int extra_validation_cells) {
  TRY_RESULT(validated, encode_workchain_unexpected_bucket(old, limits, extra_validation_cells));
  if (!unexpected_detail::amount(imported.tomis) || !imported.validate_extra(extra_validation_cells))
    return td::Status::Error("invalid unexpected imported value");
  auto next = old;
  bool lost = false;
  if (td::sgn(imported.tomis) > 0) {
    if (next.entries.size() < limits.entries) {
      next.entries.push_back({sender, imported.tomis});
    } else {
      auto found = std::find_if(next.overflow.begin(), next.overflow.end(), [&](const auto& entry) {
        return entry.sender.workchain == sender.workchain && entry.sender.account == sender.account;
      });
      if (found != next.overflow.end()) {
        TRY_RESULT(sum, unexpected_detail::add(found->tomis, imported.tomis));
        found->tomis = sum;
      } else if (next.overflow.size() < limits.overflow_sources) {
        next.overflow.push_back({sender, imported.tomis});
      } else {
        TRY_RESULT(sum, unexpected_detail::add(next.unkeyed, imported.tomis));
        next.unkeyed = sum;
        lost = true;  // D29: only both full permits losing sender attribution.
      }
    }
  }
  CurrencyCollection extra;
  if (!CurrencyCollection::add(CurrencyCollection(td::make_refint(0), old.extra),
                               CurrencyCollection(td::make_refint(0), imported.extra), extra))
    return td::Status::Error("unexpected extra-currency sum overflow");
  next.extra = extra.extra;
  TRY_RESULT(before, workchain_unexpected_balance(old));
  TRY_RESULT(after, workchain_unexpected_balance(next));
  CurrencyCollection expected;
  if (!CurrencyCollection::add(before, imported, expected) || !(expected == after))
    return td::Status::Error("unexpected credit does not conserve value");
  TRY_RESULT(encoded, encode_workchain_unexpected_bucket(next, limits, extra_validation_cells));
  return WorkchainUnexpectedCredit{std::move(next), lost, imported.extra.not_null()};
}

}  // namespace block
