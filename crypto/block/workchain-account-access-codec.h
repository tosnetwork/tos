#pragma once

#include "block/workchain-account-access.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

namespace block {

struct WorkchainAccountDeclarations {
  std::vector<WorkchainAccountRead> reads;
  std::vector<td::Bits256> writes;
};

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
