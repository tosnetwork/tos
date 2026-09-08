#pragma once

#include <map>
#include <set>
#include <stdexcept>

#include "block/workchain-input-admission.h"

namespace block {

// Physical acquisition limits for a selected Native closure, not the final
// logical-root definition or complete batch admission policy. Empty input may
// use zero limits. Production limits must be allocated from authenticated
// admission, including the shared union and derived inbox/witness wrappers.
struct NativeClosureLimits {
  std::uint64_t cells, bits, roots;
};
enum class NativeClosureLimit { Cells, Bits, Roots };

using NativeMeteredRead = std::variant<td::Ref<vm::CellSlice>, NativeClosureLimit, LocalUnavailable>;
struct NativeStateReadUsage { std::uint64_t cells, bits; };

// Read-through physical meter for selected authenticated state paths. Unlike
// materialization below, this preserves LoadedCell::tree_node and effective
// level. Every requested read calls the source, even on a charged hash: two
// paths with identical content can belong to different usage-tree nodes. The
// meter must not cache LoadedCell. A caller may deduplicate its accounting walk,
// but that walk's usage tree alone is not a proof of all subsequent reads.
// Limits bound distinct cells/bits, not call count or per-account closures.
// The enclosing bounded dictionary traversal must bound those independently.
// A cell-limit failure precedes loading; a bit-limit failure needs at most the
// current cell's load (at most 1023 bits and four refs), with no child loads.
// The hash set has at most limits.cells entries. No source closure is retained.
// This is not a bound on CellUsageTree: the caller must also bound path visits
// (key width for lookups, per-account visited hashes for closure traversal).
// Native exceptions propagate to the source-aware boundary; any interrupted
// read leaves this attempt failed, so retry cannot bypass accounting.
class NativeStateReadMeter {
 public:
  NativeStateReadMeter(std::uint64_t cells, std::uint64_t bits) : cells_(cells), bits_(bits) {}
  const NativeStateReadUsage& usage() const { return usage_; }
  // Read-only accounting evidence; callers cannot precharge or clear entries.
  const std::set<vm::CellHash>& charged_hashes() const { return seen_; }

  NativeMeteredRead load_ordinary(const td::Ref<vm::Cell>& cell) {
    auto result = load_encoded(cell);
    if (auto* slice = std::get_if<td::Ref<vm::CellSlice>>(&result); slice && (*slice)->is_special()) {
      return fail(LocalUnavailable{LocalUnavailableCode::CellIdentity});
    }
    return result;
  }

  // Read encoded Native special cells without interpreting proofs or resolving
  // libraries. Closure traversal follows present refs with Native effective
  // levels; a stored pruned Cell counts only its encoding, not hidden content.
  // A virtual pruned branch is missing content, not a complete encoded closure.
  NativeMeteredRead load_encoded(const td::Ref<vm::Cell>& cell) {
    try {
      return read(cell);
    } catch (const vm::VmVirtError&) {
      failure_ = LocalUnavailable{LocalUnavailableCode::CellUnavailable};
      throw;
    } catch (const std::bad_alloc&) {
      failure_ = LocalUnavailable{LocalUnavailableCode::Allocation};
      throw;
    } catch (const std::length_error&) {
      failure_ = LocalUnavailable{LocalUnavailableCode::Allocation};
      throw;
    } catch (const vm::CellBuilder::CellCreateError&) {
      failure_ = LocalUnavailable{LocalUnavailableCode::Construction};
      throw;
    } catch (const vm::CellBuilder::CellWriteError&) {
      failure_ = LocalUnavailable{LocalUnavailableCode::Construction};
      throw;
    }
    // VmError, VmNoGas and VmFatal propagate with the ExecutionFault marker
    // installed before the read. The outer boundary must contain all of them.
    // Own-output admission's boundary is in workchain-account-settlement.h;
    // additions here require updating its exception inventory and fault tests.
  }

 private:
  NativeMeteredRead read(const td::Ref<vm::Cell>& cell) {
    if (auto* limit = std::get_if<NativeClosureLimit>(&failure_)) return *limit;
    if (auto* local = std::get_if<LocalUnavailable>(&failure_)) return *local;
    failure_ = LocalUnavailable{LocalUnavailableCode::ExecutionFault};
    if (cell.is_null()) return fail(LocalUnavailable{LocalUnavailableCode::CellUnavailable});
    const auto hash = cell->get_hash();
    const bool fresh = seen_.find(hash) == seen_.end();
    if (fresh && usage_.cells >= cells_) return fail(NativeClosureLimit::Cells);
    auto result = cell->load_cell();
    if (result.is_error()) return fail(LocalUnavailable{LocalUnavailableCode::CellUnavailable});
    auto loaded = result.move_as_ok();
    if (loaded.data_cell.is_null()) return fail(LocalUnavailable{LocalUnavailableCode::CellUnavailable});
    if (loaded.data_cell->special_type() == vm::Cell::SpecialType::PrunnedBranch &&
        loaded.effective_level < loaded.data_cell->get_level()) {
      return fail(LocalUnavailable{LocalUnavailableCode::CellUnavailable});
    }
    if (fresh) {
      const auto bits = loaded.data_cell->get_bits();
      // usage.bits <= bits_ holds after every successful read; establish it
      // explicitly before subtraction, then bound both counter additions.
      if (usage_.bits > bits_ || bits > bits_ - usage_.bits) return fail(NativeClosureLimit::Bits);
      seen_.emplace(hash);
      ++usage_.cells;  // usage.cells < cells_ was checked before loading.
      usage_.bits += bits;
    }
    td::Ref<vm::CellSlice> slice{true, std::move(loaded)};
    failure_ = std::monostate{};
    return slice;
  }

 private:
  template <class Failure> NativeMeteredRead fail(Failure failure) {
    failure_ = failure;
    return failure;
  }
  const std::uint64_t cells_, bits_;
  NativeStateReadUsage usage_{0, 0};
  std::set<vm::CellHash> seen_;
  std::variant<std::monostate, NativeClosureLimit, LocalUnavailable> failure_;
};

class NativeCellMaterializer;
class MaterializedNativeCells {
 public:
  const std::vector<td::Ref<vm::Cell>>& roots() const { return roots_; }
  const WorkchainInputUsage& physical_usage() const { return usage_; }

 private:
  friend class NativeCellMaterializer;
  MaterializedNativeCells(std::vector<td::Ref<vm::Cell>> roots, WorkchainInputUsage usage)
      : roots_(std::move(roots)), usage_(usage) {}
  std::vector<td::Ref<vm::Cell>> roots_;
  WorkchainInputUsage usage_;
};

using NativeMaterializationResult = std::variant<MaterializedNativeCells, NativeClosureLimit, LocalUnavailable>;

// One synchronous acquisition attempt, with no partial result or retained
// failure cache. Retrying is a new attempt. This proves detached ownership and
// physical size only: NOT queue authentication, message validity/completeness,
// executable proof materialization, or final consensus admission.
// Native encoded special cells are preserved, never resolved as VM libraries.
// Virtualized views and unavailable/corrupt acquisition remain local failures.
// A limit outcome does not authorize dropping or rejecting a queued message.
// With an exact, authenticated whole-candidate allowance, exceeding it rejects
// that candidate, never causes local abstention. A temporary acquisition slice
// or exhausted remainder has no independent consensus verdict. Configuration
// validity must be established separately, before allocating these allowances.
// finalize_novm enters no interpreter and no Ref::write/make_copy is used.
// Explicit VM catches also contain failures from a virtual load_cell callback;
// custom loaders must otherwise honor the Native loader exception contract.
// Counters bound the encoded representation, never a virtualized proof's
// expansion. Peak auxiliary memory is O(cells + roots): source and detached
// nodes coexist, and duplicate roots still consume output space and work.
// Immutable acyclic sources and stable hashes imply postorder map entries are
// present and complete. Defensive map checks below assert local consistency,
// not independently reachable peer-input rejection rules.
class NativeCellMaterializer {
 public:
  static NativeMaterializationResult run(td::Span<td::Ref<vm::Cell>> roots, NativeClosureLimits limits) {
    try {
      return materialize(roots, limits);
    } catch (const std::bad_alloc&) {
      return LocalUnavailable{LocalUnavailableCode::Allocation};
    } catch (const std::length_error&) {
      return LocalUnavailable{LocalUnavailableCode::Allocation};
    } catch (const vm::CellBuilder::CellCreateError&) {
      return LocalUnavailable{LocalUnavailableCode::Construction};
    } catch (const vm::CellBuilder::CellWriteError&) {
      return LocalUnavailable{LocalUnavailableCode::Construction};
    } catch (const vm::VmVirtError&) {
      return LocalUnavailable{LocalUnavailableCode::CellUnavailable};
    } catch (const vm::VmError&) {
      return LocalUnavailable{LocalUnavailableCode::ExecutionFault};
    } catch (const vm::VmNoGas&) {
      return LocalUnavailable{LocalUnavailableCode::ExecutionFault};
    } catch (const vm::VmFatal&) {
      return LocalUnavailable{LocalUnavailableCode::ExecutionFault};
    }
  }

 private:
  static bool checked_charge(std::uint64_t& used, std::uint64_t amount, std::uint64_t limit) {
    // Establish used <= limit before subtracting; the remainder bounds addition.
    if (used > limit || amount > limit - used) return false;
    used += amount;
    return true;
  }

  static NativeMaterializationResult materialize(td::Span<td::Ref<vm::Cell>> roots,
                                                 NativeClosureLimits limits) {
    static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
    if (roots.size() > limits.roots) return NativeClosureLimit::Roots;
    WorkchainInputUsage usage{0, 0, static_cast<std::uint64_t>(roots.size())};
    struct Node {
      td::Ref<vm::DataCell> source;
      td::Ref<vm::Cell> detached;
    };
    struct Frame { td::Ref<vm::Cell> cell; bool finish; };
    std::map<vm::CellHash, Node> nodes;
    std::vector<td::Ref<vm::Cell>> detached_roots;
    detached_roots.reserve(roots.size());
    for (const auto& root : roots) {
      std::vector<Frame> pending{{root, false}};
      while (!pending.empty()) {
        auto frame = std::move(pending.back());
        pending.pop_back();
        if (frame.cell.is_null() || frame.cell->is_virtualized()) {
          return LocalUnavailable{LocalUnavailableCode::CellIdentity};
        }
        const auto hash = frame.cell->get_hash();
        auto found = nodes.find(hash);
        if (frame.finish) {
          if (found == nodes.end()) return LocalUnavailable{LocalUnavailableCode::CellIdentity};
          const auto& source = found->second.source;
          vm::CellBuilder builder;
          builder.store_bits(source->get_data(), source->get_bits());
          for (unsigned i = 0; i < source->get_refs_cnt(); ++i) {
            auto child = nodes.find(source->get_ref(i)->get_hash());
            if (child == nodes.end() || child->second.detached.is_null()) {
              return LocalUnavailable{LocalUnavailableCode::CellIdentity};
            }
            builder.store_ref(child->second.detached);
          }
          td::Ref<vm::Cell> detached = builder.finalize_novm(source->is_special());
          if (source->check_equals_unloaded(detached).is_error()) {
            return LocalUnavailable{LocalUnavailableCode::CellIdentity};
          }
          found->second.detached = std::move(detached);
          continue;
        }
        if (found != nodes.end()) {
          if (found->second.detached.is_null() ||
              frame.cell->check_equals_unloaded(found->second.detached).is_error()) {
            return LocalUnavailable{LocalUnavailableCode::CellIdentity};
          }
          continue;
        }
        // The first distinct cell above the budget is never loaded.
        if (!checked_charge(usage.cells, 1, limits.cells)) return NativeClosureLimit::Cells;
        auto loaded = frame.cell->load_cell();
        if (loaded.is_error()) return LocalUnavailable{LocalUnavailableCode::CellUnavailable};
        auto data = loaded.move_as_ok();
        auto source = std::move(data.data_cell);
        if (source.is_null() || source->is_virtualized() || data.effective_level != source->get_level() ||
            frame.cell->check_equals_unloaded(source).is_error()) {
          return LocalUnavailable{LocalUnavailableCode::CellIdentity};
        }
        if (!checked_charge(usage.bits, source->get_bits(), limits.bits)) return NativeClosureLimit::Bits;
        nodes.emplace(hash, Node{source, {}});
        pending.push_back({frame.cell, true});
        // At most four edges per charged cell; no recursive C++ traversal.
        for (unsigned i = source->get_refs_cnt(); i > 0; --i) pending.push_back({source->get_ref(i - 1), false});
      }
      auto found = nodes.find(root->get_hash());
      if (found == nodes.end() || found->second.detached.is_null()) {
        return LocalUnavailable{LocalUnavailableCode::CellIdentity};
      }
      detached_roots.push_back(found->second.detached);
    }
    return MaterializedNativeCells(std::move(detached_roots), usage);
  }
};

}  // namespace block
