#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "block/block-parse.h"
#include "block/workchain-account-access.h"
#include "block/workchain-native-materialization.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

namespace block {

// Raised only by explicit format predicates on an acquired account slice.
// A provider's generic VmError does not establish this fact. Deriving from
// VmError preserves existing decoder callers' exception handling; the batch
// acquisition boundary distinguishes this more precise source failure first.
// The reason must be a static-lifetime string literal, as at every throw below.
struct WorkchainAccountFormatError : vm::VmError {
  explicit WorkchainAccountFormatError(const char* reason) : vm::VmError(vm::Excno::dict_err, reason) {}
};

struct WorkchainAccountClosureLimit {
  enum Kind { Cells, Bits, Depth } kind;
};
using WorkchainAccountClosureRead = std::variant<WorkchainInputUsage, NativeClosureLimit,
                                               WorkchainAccountClosureLimit, LocalUnavailable>;

// Per-account closure limits are independent of the shared physical meter.
// Iterative traversal retains at most four pending edges per charged local
// cell plus its initial root; no recursive C++ walk and no detached cell copy.
// A failed account must end the enclosing batch acquisition attempt. These
// outcomes are not final voting classifications: an oversized persisted account
// and a candidate exceeding its aggregate allowance have different provenance.
// This account-closure traversal is depth-first, lower reference index first;
// all replaying nodes must use this order, including the first path chosen for
// each shared hash. Dedup marks representative paths; the Native proof builder
// closes its visited set by content hash, so other paths to that same content
// are not necessarily pruned. Subsequent engine/settlement reads must still
// retain the original usage tree: this pass covers declared account closures,
// not every state read needed for a complete block proof.
inline WorkchainAccountClosureRead read_workchain_account_closure(
    const td::Ref<vm::Cell>& account, NativeStateReadMeter& total,
    std::uint64_t max_cells, std::uint64_t max_bits, std::uint16_t max_depth) {
  if (account.is_null()) return LocalUnavailable{LocalUnavailableCode::CellUnavailable};
  if (account->get_depth() > max_depth) return WorkchainAccountClosureLimit{WorkchainAccountClosureLimit::Depth};
  WorkchainInputUsage usage{0, 0, 1};  // One account closure, not an input logical root.
  std::set<vm::CellHash> seen;
  std::vector<td::Ref<vm::Cell>> pending{account};
  while (!pending.empty()) {
    auto node = std::move(pending.back());
    pending.pop_back();
    // Defensive only: the initial root was checked, and prefetch_ref below
    // uses indices strictly below size_refs(), which guarantees non-null refs.
    if (node.is_null()) return LocalUnavailable{LocalUnavailableCode::CellUnavailable};
    const auto hash = node->get_hash();
    if (seen.find(hash) != seen.end()) continue;
    if (usage.cells >= max_cells) return WorkchainAccountClosureLimit{WorkchainAccountClosureLimit::Cells};
    auto result = total.load_encoded(node);
    if (auto* limit = std::get_if<NativeClosureLimit>(&result)) return *limit;
    if (auto* local = std::get_if<LocalUnavailable>(&result)) return *local;
    auto slice = std::get<td::Ref<vm::CellSlice>>(std::move(result));
    const auto bits = slice->size();
    // Establish the remainder before addition; cells < max_cells was checked
    // before the source load. Shared global cells still charge this local set.
    // The aggregate may already be charged; any local failure ends the batch
    // attempt, so that partially charged meter must never be reused.
    if (usage.bits > max_bits || bits > max_bits - usage.bits) {
      return WorkchainAccountClosureLimit{WorkchainAccountClosureLimit::Bits};
    }
    seen.emplace(hash);
    ++usage.cells;
    usage.bits += bits;
    for (unsigned i = slice->size_refs(); i > 0; --i) pending.push_back(slice->prefetch_ref(i - 1));
  }
  return usage;
}

// Admit the exact lookup/absence path before invoking the Native dictionary.
// The Native implementation remains the semantic decoder and validates root
// augmentation. Its extra-value skip reads only the current slice, not a child
// currency dictionary. The root edge is included even for a prefix mismatch.
// Both passes preserve the original usage tree. This bounds physical state
// reads, not the selected Account closure (which needs separate admission).
// The source must be immutable authenticated state, never candidate InMsgDescr.
// Native parse exceptions retain that provenance at the enclosing boundary.
// A replacement also reads sibling augmentation when rebuilding parent edges.
// Admit only that node's extra-value refs, never its account/subdictionary refs.
// Label parsing and extra extraction do not load children. Extra-value closure
// traversal is iterative, with a local visited set bounded by the aggregate
// charged-cell allowance and at most four pending refs per visited cell.
inline NativeMeteredRead admit_workchain_account_augmentation(
    const td::Ref<vm::Cell>& node, int remaining, NativeStateReadMeter& meter) {
  auto acquired = meter.load_ordinary(node);
  if (!std::holds_alternative<td::Ref<vm::CellSlice>>(acquired)) return acquired;
  vm::dict::LabelParser label{std::get<td::Ref<vm::CellSlice>>(std::move(acquired)), remaining,
                              vm::dict::LabelParser::chk_size};
  label.skip_label();
  td::Ref<vm::CellSlice> extra;
  if (label.l_bits != remaining) {
    // chk_size validates the fork's two child references. Keep the advance
    // checked locally (unreachable failure under chk_size); the extra must consume everything after those refs,
    // exactly as Native get_node_extra requires for a fork (not for a leaf).
    if (!label.remainder.write().advance_refs(2)) {
      throw WorkchainAccountFormatError{"invalid authenticated account augmentation fork"};
    }
    vm::CellSlice tail{*label.remainder};
    if (!tlb::aug_ShardAccounts.skip_extra(tail) || !tail.empty_ext()) {
      throw WorkchainAccountFormatError{"invalid authenticated account augmentation fork extra"};
    }
    extra = std::move(label.remainder);
  } else {
    extra = tlb::aug_ShardAccounts.extract_extra(std::move(label.remainder));
  }
  if (extra.is_null()) {
    throw WorkchainAccountFormatError{"invalid authenticated account augmentation"};
  }
  std::vector<td::Ref<vm::Cell>> pending;
  for (unsigned i = extra->size_refs(); i > 0; --i) pending.push_back(extra->prefetch_ref(i - 1));
  std::set<vm::CellHash> seen;
  while (!pending.empty()) {
    auto cell = std::move(pending.back());
    pending.pop_back();
    const auto hash = cell->get_hash();
    if (seen.find(hash) != seen.end()) continue;
    auto loaded = meter.load_encoded(cell);
    if (!std::holds_alternative<td::Ref<vm::CellSlice>>(loaded)) return loaded;
    seen.emplace(hash);
    auto slice = std::get<td::Ref<vm::CellSlice>>(std::move(loaded));
    for (unsigned i = slice->size_refs(); i > 0; --i) pending.push_back(slice->prefetch_ref(i - 1));
  }
  return extra;
}

enum class WorkchainAccountPathMode { Read, Replace };

// Lookup is top-down: charge the current path node, then (for Replace) its
// opposite sibling's augmentation before descending into the selected child.
// The sibling closure itself uses lower-reference-first DFS. The mode must be
// explicit; a future write caller must not silently inherit read-only coverage.
inline NativeMeteredRead lookup_workchain_account_metered(
    const td::Ref<vm::Cell>& shard_accounts, const td::Bits256& account, NativeStateReadMeter& meter,
    WorkchainAccountPathMode mode) {
  auto root_result = meter.load_ordinary(shard_accounts);
  if (!std::holds_alternative<td::Ref<vm::CellSlice>>(root_result)) return root_result;
  auto root = std::get<td::Ref<vm::CellSlice>>(std::move(root_result));
  if (!root->have(1)) {
    throw WorkchainAccountFormatError{"invalid authenticated ShardAccounts root"};
  }
  if (root->prefetch_ulong(1)) {
    auto node = root->prefetch_ref();
    auto key = account.bits();
    int remaining = 256;
    while (true) {
      auto node_result = meter.load_ordinary(node);
      if (!std::holds_alternative<td::Ref<vm::CellSlice>>(node_result)) return node_result;
      auto slice = std::get<td::Ref<vm::CellSlice>>(std::move(node_result));
      vm::dict::LabelParser label{std::move(slice), remaining, vm::dict::LabelParser::chk_size};
      if (!label.is_prefix_of(key, remaining)) break;
      // LabelParser validates 0 <= l_bits <= remaining. A continued edge
      // consumes one more key bit, so at most 257 nodes precede termination.
      remaining -= label.l_bits;
      if (!remaining) break;
      key += label.l_bits;
      const bool branch = *key++;
      --remaining;
      if (mode == WorkchainAccountPathMode::Replace) {
        auto sibling = admit_workchain_account_augmentation(label.remainder->prefetch_ref(!branch), remaining, meter);
        if (!std::holds_alternative<td::Ref<vm::CellSlice>>(sibling)) return sibling;
      }
      node = label.remainder->prefetch_ref(branch);
    }
  }
  vm::AugmentedDictionary native(root, 256, tlb::aug_ShardAccounts);
  return native.lookup(account);
}

// The root is the complete ShardAccounts field of an authenticated shard state,
// or of a candidate whose structure has passed bounded admission. This class
// does not authenticate the containing block. VM/virtualization/allocation
// exceptions propagate to the host's source-aware boundary; missing cells are
// never interpreted as an absent account.
class WorkchainAccountDictionary {
 public:
  explicit WorkchainAccountDictionary(td::Ref<vm::Cell> shard_accounts)
      : accounts_(vm::load_cell_slice_ref(std::move(shard_accounts)), 256, tlb::aug_ShardAccounts) {
  }

  td::Status verify_old_read(WorkchainAccountAccess& access, const td::Bits256& account);
  // Hash-based subtree skipping relies on the old dictionary being validated.
  // Changed-node augmentation in the new dictionary is checked by scan_diff.
  // max_changes bounds returned keys, not all traversal work: structural/state
  // budgets must already bound the input cells at the host admission boundary.
  td::Result<std::vector<td::Bits256>> changed_accounts(WorkchainAccountDictionary& next,
                                                      std::uint64_t max_changes);

 private:
  vm::AugmentedDictionary accounts_;
};

inline td::Status WorkchainAccountDictionary::verify_old_read(WorkchainAccountAccess& access,
                                                            const td::Bits256& account) {
  auto declaration = access.expected_read(account);
  if (declaration.is_error()) return declaration.move_as_error();
  auto value = accounts_.lookup(account);
  if (value.is_null()) return access.record_old_read(account, std::nullopt);
  tlb::ShardAccount::Record record;
  if (value->size_ext() != 0x10140 || !record.unpack(value)) {
    // An invalid authenticated old dictionary is not a candidate mismatch.
    // Keep the exception in the old-state read scope of the source-aware host.
    throw vm::VmError{vm::Excno::dict_err, "invalid old ShardAccount entry"};
  }
  return access.record_old_read(account, td::Bits256(record.account->get_hash().bits()));
}

inline td::Result<std::vector<td::Bits256>> WorkchainAccountDictionary::changed_accounts(
    WorkchainAccountDictionary& next, std::uint64_t max_changes) {
  std::vector<td::Bits256> keys;
  bool limit_reached = false;
  bool scanned = accounts_.scan_diff(
      next.accounts_,
      [&](td::ConstBitPtr key, int key_len, td::Ref<vm::CellSlice>, td::Ref<vm::CellSlice>) {
        if (key_len != 256) throw vm::VmError{vm::Excno::dict_err, "invalid ShardAccounts key width"};
        if (keys.size() >= max_changes) {
          limit_reached = true;
          return false;
        }
        keys.emplace_back(key);
        return true;
      }, 2);
  if (limit_reached) return td::Status::Error("account difference exceeds admitted bound");
  if (!scanned) throw vm::VmError{vm::Excno::dict_err, "invalid ShardAccounts difference"};
  return keys;
}

}  // namespace block
