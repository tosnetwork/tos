#pragma once

#include "block/workchain-account-access.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/dict.h"
#include <map>

namespace block {

struct WorkchainAccountDeclarations {
  std::vector<WorkchainAccountRead> reads;
  std::vector<td::Bits256> writes;
};

struct WorkchainDeclarationShape {
  std::uint64_t reads{0}, writes{0}, inspected_nodes{0};
};

// Shallow structural admission over an already acquired ordinary closure.
// Do not enumerate keys here: a shared DAG can encode exponentially many keys.
// Cache by hash AND remaining key width, separately for read/write semantics.
// A successful subtree has one valid remaining width. Exact label consumption
// makes child width strictly increase with parent width for a fixed fork cell;
// exact leaf profiles pin one width, so uniqueness follows by induction.
// Fork/leaf reference profiles must also remain disjoint. Thus each role caches
// at most closure_cells completed
// states, plus at most 257 active frames on the first failing path. A looser
// bound independent of that disjointness is 257 * closure_cells states.
// Logical multiplicity is still counted at both edges of a shared fork.
// Canonical encoding and write-subset semantics remain post-commitment checks;
// this result is not an authenticated access ledger or an execution permit.
inline td::Result<WorkchainDeclarationShape> inspect_workchain_account_declarations(
    td::Ref<vm::Cell> root, std::uint64_t max_reads, std::uint64_t max_writes) {
  if (root.is_null()) return td::Status::Error("missing account declarations");
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() != 34 || cs.fetch_ulong(32) != 0x7bc07a6d) {
    return td::Status::Error("invalid account declarations header");
  }
  td::Ref<vm::Cell> roots[2];
  if (!cs.fetch_maybe_ref(roots[0]) || !cs.fetch_maybe_ref(roots[1]) || !cs.empty_ext()) {
    return td::Status::Error("invalid account declarations references");
  }
  WorkchainDeclarationShape shape;
  for (unsigned role = 0; role < 2; ++role) {
    const auto limit = role == 0 ? max_reads : max_writes;
    std::map<std::pair<vm::CellHash, int>, std::uint64_t> counts;
    std::function<td::Result<std::uint64_t>(td::Ref<vm::Cell>, int)> visit;
    visit = [&](td::Ref<vm::Cell> node, int remaining) -> td::Result<std::uint64_t> {
      const auto key = std::make_pair(node->get_hash(), remaining);
      auto found = counts.find(key);
      if (found != counts.end()) return found->second;
      if (shape.inspected_nodes == UINT64_MAX) return td::Status::Error("declaration visit count overflow");
      ++shape.inspected_nodes;
      vm::dict::LabelParser label(node, remaining);
      const auto length = label.l_bits;
      label.skip_label();
      std::uint64_t count;
      if (length == remaining) {
        if (limit == 0) return td::Status::Error("account declaration count exceeded");
        const auto& value = label.remainder;
        if (role == 0) {
          if (value->size_ext() != 0x10000) return td::Status::Error("invalid read declaration leaf");
          bool entry_special = false;
          auto entry = vm::load_cell_slice_special(value->prefetch_ref(), entry_special);
          if (entry_special || entry.size_refs() != 0 || entry.size() < 33 ||
              entry.fetch_ulong(32) != 0x439e6964) return td::Status::Error("invalid read declaration record");
          const bool present = entry.fetch_ulong(1) != 0;
          if (entry.size() != (present ? 256u : 0u)) return td::Status::Error("invalid read declaration hash");
        } else if (!value->empty_ext()) {
          return td::Status::Error("invalid write declaration leaf");
        }
        count = 1;
      } else {
        // LabelParser validates 0 <= length < remaining and exactly two refs.
        const int child_width = remaining - length - 1;
        TRY_RESULT(left, visit(label.remainder->prefetch_ref(0), child_width));
        TRY_RESULT(right, visit(label.remainder->prefetch_ref(1), child_width));
        // Both child counts <= limit; guard subtraction and the sum explicitly.
        if (right > limit || left > limit - right) return td::Status::Error("account declaration count exceeded");
        count = left + right;
      }
      counts.emplace(key, count);
      return count;
    };
    if (roots[role].not_null()) {
      TRY_RESULT(count, visit(roots[role], 256));
      (role == 0 ? shape.reads : shape.writes) = count;
    }
  }
  return shape;
}

// Serialization only, not authentication or admission. The caller must first
// bound the candidate closure; entry limits additionally bound materialization.
// VM, virtualization, allocation and cell construction exceptions propagate to
// the caller's provenance-aware boundary, never becoming account absence.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_account_declarations(
    const WorkchainAccountDeclarations& value, std::uint64_t max_reads, std::uint64_t max_writes) {
  // Check before copying vectors into the access ledger.
  if (value.reads.size() > max_reads || value.writes.size() > max_writes) {
    return td::Status::Error("account declarations exceed admitted bounds");
  }
  auto checked = WorkchainAccountAccess::create(value.reads, value.writes, max_reads, max_writes);
  if (checked.is_error()) return checked.move_as_error();
  vm::Dictionary reads(256), writes(256);
  for (const auto& read : value.reads) {
    vm::CellBuilder cb;
    cb.store_long(0x439e6964, 32).store_long(read.old_account_hash.has_value(), 1);
    if (read.old_account_hash) cb.store_bits(read.old_account_hash->bits(), 256);
    if (!reads.set_ref(read.account, cb.finalize())) {
      return td::Status::Error("cannot encode account read declaration");
    }
  }
  for (const auto& write : value.writes) {
    vm::CellBuilder empty;
    if (!writes.set_builder(write, empty)) return td::Status::Error("cannot encode account write declaration");
  }
  vm::CellBuilder cb;
  cb.store_long(0x7bc07a6d, 32);
  if (!reads.append_dict_to_bool(cb) || !writes.append_dict_to_bool(cb)) {
    return td::Status::Error("cannot encode account declarations");
  }
  return cb.finalize();
}

inline td::Result<WorkchainAccountDeclarations> decode_workchain_account_declarations(
    td::Ref<vm::Cell> root, std::uint64_t max_reads, std::uint64_t max_writes) {
  if (root.is_null()) return td::Status::Error("missing account declarations");
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special || cs.size() != 34 || cs.fetch_ulong(32) != 0x7bc07a6d) {
    return td::Status::Error("invalid account declarations header");
  }
  td::Ref<vm::Cell> reads_root, writes_root;
  if (!cs.fetch_maybe_ref(reads_root) || !cs.fetch_maybe_ref(writes_root) || !cs.empty_ext()) {
    return td::Status::Error("invalid account declarations references");
  }
  vm::Dictionary reads(std::move(reads_root), 256), writes(std::move(writes_root), 256);
  WorkchainAccountDeclarations result;
  if (!reads.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int width) {
        // No entry is materialized beyond the admitted count.
        if (result.reads.size() >= max_reads || width != 256 || value->size_ext() != 0x10000) return false;
        bool entry_special = false;
        auto entry = vm::load_cell_slice_special(value->prefetch_ref(), entry_special);
        if (entry_special || entry.size_refs() != 0 || entry.size() < 33 ||
            entry.fetch_ulong(32) != 0x439e6964) return false;
        bool present = entry.fetch_ulong(1) != 0;
        if (entry.size() != (present ? 256u : 0u)) return false;
        WorkchainAccountRead read{td::Bits256(key), std::nullopt};
        if (present) {
          td::Bits256 hash;
          if (!entry.fetch_bits_to(hash)) return false;
          read.old_account_hash = hash;
        }
        result.reads.push_back(std::move(read));
        return true;
      })) return td::Status::Error("invalid or excessive account read declarations");
  if (!writes.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int width) {
        if (result.writes.size() >= max_writes || width != 256 || !value->empty_ext()) return false;
        result.writes.emplace_back(key);
        return true;
      })) return td::Status::Error("invalid or excessive account write declarations");
  // Enforce the same set semantics as the execution ledger and one canonical
  // dictionary encoding. Rebuilding is bounded by the admitted entry counts.
  TRY_RESULT(canonical, encode_workchain_account_declarations(result, max_reads, max_writes));
  if (canonical->get_hash() != root->get_hash()) {
    return td::Status::Error("noncanonical account declarations");
  }
  return result;
}

}  // namespace block
