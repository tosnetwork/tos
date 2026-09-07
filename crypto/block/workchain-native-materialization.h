#pragma once

#include <map>
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
