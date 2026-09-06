#pragma once

#include <cstdint>
#include <set>
#include <vector>

#include "td/utils/Status.h"
#include "vm/cells/DataCell.h"

namespace block {

// Structural work, not engine wire bytes, logical actions or persistent writes.
// Callers must resolve these bounds from a versioned policy, not local settings.
struct WorkchainInputLimits {
  std::uint64_t cells;
  std::uint64_t bits;
  std::uint64_t roots;
};

struct WorkchainInputUsage {
  std::uint64_t cells{0};
  std::uint64_t bits{0};
  std::uint64_t roots{0};
};

// Counts the union across add() calls. Only complete, non-virtualized ordinary
// input cells are admitted; proof/state acquisition has a separate contract.
// Failure is sticky: partially visited input must not become an accepted cache.
// This neither decodes an inbox nor constructs a batch commitment.
class WorkchainInputPreflight {
 public:
  explicit WorkchainInputPreflight(WorkchainInputLimits limits) : limits_(limits) {
  }

  const WorkchainInputUsage& usage() const {
    return usage_;
  }

  td::Status add(const td::Ref<vm::Cell>& root) {
    if (failed_) {
      return td::Status::Error("input preflight already failed");
    }
    failed_ = true;
    if (root.is_null() || usage_.roots >= limits_.roots) {
      return td::Status::Error("input preflight root limit or missing root");
    }
    ++usage_.roots;
    std::vector<td::Ref<vm::Cell>> pending{root};
    while (!pending.empty()) {
      auto cell = std::move(pending.back());
      pending.pop_back();
      if (cell.is_null() || cell->is_virtualized()) {
        return td::Status::Error("input preflight requires complete ordinary cells");
      }
      auto hash = cell->get_hash();
      if (seen_.count(hash)) {
        continue;
      }
      // Reject before loading the first distinct cell over budget.
      if (usage_.cells >= limits_.cells) {
        return td::Status::Error("input preflight cell limit");
      }
      TRY_RESULT(loaded, cell->load_cell());
      const auto& data = loaded.data_cell;
      if (data.is_null() || data->is_special()) {
        return td::Status::Error("input preflight requires complete ordinary cells");
      }
      if (data->get_bits() > limits_.bits - usage_.bits) {
        return td::Status::Error("input preflight bit limit");
      }
      ++usage_.cells;
      usage_.bits += data->get_bits();
      seen_.insert(hash);
      // At most four edges per admitted cell; DFS avoids recursive C++ frames.
      for (unsigned i = data->get_refs_cnt(); i > 0; --i) {
        pending.push_back(data->get_ref(i - 1));
      }
    }
    failed_ = false;
    return td::Status::OK();
  }

 private:
  WorkchainInputLimits limits_;
  WorkchainInputUsage usage_;
  std::set<vm::CellHash> seen_;
  bool failed_{false};
};

}  // namespace block
