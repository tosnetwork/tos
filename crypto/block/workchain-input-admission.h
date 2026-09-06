#pragma once

#include <map>
#include <optional>
#include <variant>
#include <new>

#include "block/workchain-input-preflight.h"
#include "vm/cells.h"
#include "vm/excno.hpp"

namespace block {

enum class CandidateInvalidCode { MissingRoot, CellLimit, BitLimit, RootLimit, ForbiddenSpecial, VirtualizedInput };
struct CandidateInvalid {
  CandidateInvalidCode code;
};
enum class LocalUnavailableCode { CellUnavailable, CellIdentity, Construction, Allocation, ExecutionFault,
                                  UnsupportedAdmissionVersion };
struct LocalUnavailable {
  LocalUnavailableCode code;
};
enum class ConfigInvalidCode { ZeroLimit };
struct ConfigInvalid {
  ConfigInvalidCode code;
};

// Identity storage only: the caller must authenticate and resolve configuration.
// This prototype does not decode param 84 or authorize a configuration transition.
struct InputPolicyIdentity {
  vm::CellHash configuration_hash;
  std::uint8_t engine_format;
  std::int64_t engine_selector;
  std::uint32_t descriptor_version;
  std::uint16_t admission_version;
};

class CandidateAdmissionSession;
class ResolvedInputPolicy {
 public:
  static std::variant<ResolvedInputPolicy, ConfigInvalid, LocalUnavailable> from_resolved_fields(
      WorkchainInputLimits limits, InputPolicyIdentity identity) {
    if (!limits.cells || !limits.bits || !limits.roots) return ConfigInvalid{ConfigInvalidCode::ZeroLimit};
    if (identity.admission_version != 1) return LocalUnavailable{LocalUnavailableCode::UnsupportedAdmissionVersion};
    return ResolvedInputPolicy(limits, identity);
  }
  const WorkchainInputLimits& limits() const { return limits_; }
  const InputPolicyIdentity& identity() const { return identity_; }

 private:
  ResolvedInputPolicy(WorkchainInputLimits limits, InputPolicyIdentity identity) : limits_(limits), identity_(identity) {}
  WorkchainInputLimits limits_;
  InputPolicyIdentity identity_;
};

// A detached, entirely materialized ordinary candidate DAG. No external lazy
// reference survives construction. This is not full logical-inbox admission.
class AdmittedInput {
 public:
  td::Ref<vm::Cell> candidate() const { return candidate_; }
  const WorkchainInputUsage& usage() const { return usage_; }
  const InputPolicyIdentity& policy_identity() const { return identity_; }

 private:
  friend class CandidateAdmissionSession;
  AdmittedInput(td::Ref<vm::Cell> candidate, WorkchainInputUsage usage, InputPolicyIdentity identity)
      : candidate_(std::move(candidate)), usage_(usage), identity_(identity) {}
  td::Ref<vm::Cell> candidate_;
  WorkchainInputUsage usage_;
  InputPolicyIdentity identity_;
};

using InputAdmissionResult = std::variant<AdmittedInput, CandidateInvalid, LocalUnavailable>;

// Single immutable candidate attempt. Repeated evaluation returns the original
// typed outcome, including a local failure; recovery requires a fresh session.
// Not installed at consensus entry points. Native inbox/proof adapters must not
// inherit the ordinary-candidate restriction without their own protocol policy.
class CandidateAdmissionSession {
 public:
  CandidateAdmissionSession(td::Ref<vm::Cell> candidate, ResolvedInputPolicy policy)
      : candidate_(std::move(candidate)), policy_(policy) {}

  const InputAdmissionResult& evaluate() {
    if (!result_) {
      try {
        result_.emplace(materialize());
      } catch (const std::bad_alloc&) {
        result_.emplace(LocalUnavailable{LocalUnavailableCode::Allocation});
      } catch (const vm::CellBuilder::CellCreateError&) {
        result_.emplace(LocalUnavailable{LocalUnavailableCode::Construction});
      } catch (const vm::CellBuilder::CellWriteError&) {
        result_.emplace(LocalUnavailable{LocalUnavailableCode::Construction});
      } catch (const vm::VmError&) {
        result_.emplace(LocalUnavailable{LocalUnavailableCode::ExecutionFault});
      } catch (const vm::VmVirtError&) {
        result_.emplace(LocalUnavailable{LocalUnavailableCode::CellUnavailable});
      } catch (const vm::VmNoGas&) {
        result_.emplace(LocalUnavailable{LocalUnavailableCode::ExecutionFault});
      }
    }
    return *result_;
  }

 private:
  static bool consume(std::uint64_t& used, std::uint64_t amount, std::uint64_t limit) {
    if (used > limit || amount > limit - used) return false;
    used += amount;
    return true;
  }

  InputAdmissionResult materialize() {
    if (candidate_.is_null()) return CandidateInvalid{CandidateInvalidCode::MissingRoot};
    WorkchainInputUsage usage;
    const auto& limits = policy_.limits();
    if (!consume(usage.roots, 1, limits.roots)) return CandidateInvalid{CandidateInvalidCode::RootLimit};
    struct Node {
      td::Ref<vm::DataCell> source;
      td::Ref<vm::Cell> detached;
    };
    struct Frame { td::Ref<vm::Cell> cell; bool finish; };
    std::map<vm::CellHash, Node> nodes;
    std::vector<Frame> stack{{candidate_, false}};
    while (!stack.empty()) {
      auto frame = std::move(stack.back());
      stack.pop_back();
      if (frame.cell.is_null()) return LocalUnavailable{LocalUnavailableCode::CellIdentity};
      if (frame.cell->is_virtualized()) return CandidateInvalid{CandidateInvalidCode::VirtualizedInput};
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
        auto detached = builder.finalize();
        if (detached->get_hash() != hash) return LocalUnavailable{LocalUnavailableCode::CellIdentity};
        found->second.detached = std::move(detached);
        continue;
      }
      if (found != nodes.end()) {
        if (found->second.detached.is_null()) return LocalUnavailable{LocalUnavailableCode::CellIdentity};
        continue;
      }
      if (!consume(usage.cells, 1, limits.cells)) return CandidateInvalid{CandidateInvalidCode::CellLimit};
      auto loaded = frame.cell->load_cell();
      if (loaded.is_error()) return LocalUnavailable{LocalUnavailableCode::CellUnavailable};
      auto source = loaded.move_as_ok().data_cell;
      if (source.is_null() || source->get_hash() != hash) return LocalUnavailable{LocalUnavailableCode::CellIdentity};
      if (source->is_special()) return CandidateInvalid{CandidateInvalidCode::ForbiddenSpecial};
      if (!consume(usage.bits, source->get_bits(), limits.bits)) return CandidateInvalid{CandidateInvalidCode::BitLimit};
      nodes.emplace(hash, Node{source, {}});
      stack.push_back({frame.cell, true});
      for (unsigned i = source->get_refs_cnt(); i > 0; --i) stack.push_back({source->get_ref(i - 1), false});
    }
    auto root = nodes.find(candidate_->get_hash());
    if (root == nodes.end() || root->second.detached.is_null()) return LocalUnavailable{LocalUnavailableCode::CellIdentity};
    return AdmittedInput(root->second.detached, usage, policy_.identity());
  }

  td::Ref<vm::Cell> candidate_;
  ResolvedInputPolicy policy_;
  std::optional<InputAdmissionResult> result_;
};

}  // namespace block
