#pragma once

#include "block/workchain-account-access-codec.h"
#include "block/workchain-block-execution.h"
#include "block/workchain-host-identity.h"
#include "block/workchain-native-materialization.h"
#include "block/workchain-resource-policy.h"
#include "vm/vmstate.h"

namespace block {

class BatchInputAdmissionSession;

// Complete structural input, not a valid transaction or authenticated inbox.
// Commitment comparison and complete inbox semantics still precede state reads,
// proofs and execution. All retained closures have detached Native ownership.
class AdmittedBatchInput {
 public:
  const td::Ref<vm::Cell>& root() const { return root_; }
  const td::Ref<vm::Cell>& candidate() const { return candidate_; }
  const WorkchainInputUsage& usage() const { return usage_; }
  const ResolvedBatchInputPolicy& policy() const { return policy_; }
 private:
  friend class BatchInputAdmissionSession;
  AdmittedBatchInput(td::Ref<vm::Cell> root, td::Ref<vm::Cell> candidate,
                     WorkchainInputUsage usage, ResolvedBatchInputPolicy policy)
      : root_(std::move(root)), candidate_(std::move(candidate)), usage_(usage), policy_(std::move(policy)) {}
  td::Ref<vm::Cell> root_, candidate_;
  WorkchainInputUsage usage_;
  ResolvedBatchInputPolicy policy_;
};

// Existing consensus categories, with allocation-free diagnostic storage.
struct BatchInputAdmissionFailure {
  WorkchainExecutionFailure category;
  const char* reason;
};
using BatchInputAdmissionResult = std::variant<AdmittedBatchInput, BatchInputAdmissionFailure>;

// One immutable synchronous attempt. The host owns the authenticated identity
// and inbox vector throughout evaluation; no vector is copied before count
// admission. Repeated evaluation returns the identical cached success/failure.
// This does not authenticate the caller's Config cut or message completeness.
class BatchInputAdmissionSession {
 public:
  BatchInputAdmissionSession(ResolvedBatchInputPolicy policy, td::Ref<vm::Cell> candidate,
                            td::Ref<vm::Cell> declarations, WorkchainHostIdentity identity,
                            const std::vector<td::Ref<vm::Cell>>& inbox)
      : policy_(std::move(policy)), candidate_(std::move(candidate)), declarations_(std::move(declarations)),
        identity_(std::move(identity)), inbox_(inbox) {}
  BatchInputAdmissionSession(ResolvedBatchInputPolicy, td::Ref<vm::Cell>, td::Ref<vm::Cell>,
                            WorkchainHostIdentity, std::vector<td::Ref<vm::Cell>>&&) = delete;

  const BatchInputAdmissionResult& evaluate() {
    if (result_) return *result_;
    try {
      result_.emplace(admit());
    } catch (const std::bad_alloc&) {
      result_.emplace(local("input allocation failed"));
    } catch (const std::length_error&) {
      result_.emplace(local("input allocation length failed"));
    } catch (const vm::CellBuilder::CellCreateError&) {
      result_.emplace(local("input cell construction failed"));
    } catch (const vm::CellBuilder::CellWriteError&) {
      result_.emplace(local("input cell writing failed"));
    } catch (const vm::VmVirtError&) {
      result_.emplace(local("input cell view unavailable"));
    } catch (const vm::VmError&) {
      result_.emplace(local("input acquisition failed"));
    } catch (const vm::VmNoGas&) {
      result_.emplace(local("unexpected interpreter resource failure"));
    } catch (const vm::VmFatal&) {
      result_.emplace(local("unexpected interpreter failure"));
    }
    return *result_;
  }

 private:
  static BatchInputAdmissionFailure local(const char* reason) {
    return {WorkchainExecutionFailure::LocalUnavailable, reason};
  }
  static BatchInputAdmissionFailure invalid(const char* reason) {
    return {WorkchainExecutionFailure::CandidateInvalid, reason};
  }

  BatchInputAdmissionResult admit() {
    // Detached candidate parsing below must not invoke interpreter-provided
    // loaders or gas hooks; errors in such a context are local, not bad input.
    if (vm::VmStateInterface::get()) return local("input admission inside interpreter context");
    const auto limits = policy_.limits();
    if (inbox_.size() > policy_.resources().input.max_inbound || inbox_.size() > 32767) {
      return invalid("input inbox count exceeded");
    }
    // Establish roots >= 3 before subtraction; the remaining allowance proves
    // that adding N below cannot overflow. Sharing never reduces logical roots.
    if (limits.roots < 3 || inbox_.size() > limits.roots - 3) return invalid("input root count exceeded");
    const std::uint64_t logical_roots = 3 + static_cast<std::uint64_t>(inbox_.size());
    if (candidate_.is_null() || declarations_.is_null()) return invalid("missing candidate input root");
    if (identity_.finality.is_null()) return local("missing host finality");
    const auto& id = policy_.identity();
    if (identity_.configuration_hash != td::Bits256(id.configuration_hash.bits()) ||
        identity_.extended != id.extended || identity_.engine_selector != id.engine_selector ||
        identity_.vm_mode != id.vm_mode || identity_.descriptor_version != id.descriptor_version ||
        identity_.admission_version != id.admission_version) return local("host policy identity mismatch");

    // The third logical root is host context: acquire its referenced finality
    // now, then charge its fixed wrappers in the same union without new roots.
    std::vector<td::Ref<vm::Cell>> roots;
    roots.reserve(static_cast<std::size_t>(logical_roots));
    roots.insert(roots.end(), {candidate_, declarations_, identity_.finality});
    roots.insert(roots.end(), inbox_.begin(), inbox_.end());
    // This derived root count equals roots.size(). The materializer's generic
    // root guard is therefore unreachable here; the authenticated max_roots is
    // enforced only by the session guard above, before allocating this vector.
    auto acquired = NativeCellMaterializer::run(roots, {limits.cells, limits.bits, logical_roots});
    if (std::holds_alternative<NativeClosureLimit>(acquired)) return invalid("input closure limit exceeded");
    if (std::holds_alternative<LocalUnavailable>(acquired)) return local("input closure unavailable");
    const auto& materialized = std::get<MaterializedNativeCells>(acquired);
    roots = materialized.roots();
    auto usage = materialized.physical_usage();

    // Seed from the detached graph, not is_loaded() on its root. Track ordinary
    // traversal separately: sharing with Native input never exempts a candidate
    // descendant from its ordinary-only profile. This map is bounded by cells.
    std::map<vm::CellHash, bool> seen;
    struct Visit { td::Ref<vm::Cell> cell; bool ordinary; };
    std::vector<Visit> pending;
    for (std::size_t i = 0; i < roots.size(); ++i) {
      pending.push_back({roots[i], i < 2});
      while (!pending.empty()) {
        auto visit = std::move(pending.back());
        pending.pop_back();
        const auto hash = visit.cell->get_hash();
        auto found = seen.find(hash);
        if (found != seen.end() && (!visit.ordinary || found->second)) continue;
        auto loaded = visit.cell->load_cell();
        if (loaded.is_error()) return local("detached input load failed");
        const auto& data = loaded.ok().data_cell;
        if (visit.ordinary && data->is_special()) return invalid("candidate profile forbids special cells");
        seen[hash] = visit.ordinary;
        for (unsigned j = 0; j < data->get_refs_cnt(); ++j) pending.push_back({data->get_ref(j), visit.ordinary});
      }
    }
    if (seen.size() != usage.cells) return local("detached input union differs from acquisition");

    try {
      auto declarations = inspect_workchain_account_declarations(roots[1], policy_.resources().input.max_reads,
                                                                policy_.resources().input.max_writes);
      if (declarations.is_error()) return invalid("invalid or excessive account declarations");
    } catch (const vm::VmError&) {
      // Only detached ordinary candidate cells are reachable here, and the
      // interpreter-context guard excludes external VM load hooks. Dictionary
      // parse errors therefore describe candidate bytes, not missing CellDb data.
      return invalid("malformed account declaration dictionary");
    }

    auto charge = [&](const td::Ref<vm::Cell>& cell) -> td::Status {
      if (seen.count(cell->get_hash())) return td::Status::OK();
      if (usage.cells >= limits.cells) return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid), "derived input cell limit");
      TRY_RESULT(loaded, cell->load_cell());
      const auto& data = loaded.data_cell;
      // Acquisition and each successful charge preserve usage.bits <= limit.
      if (data->get_bits() > limits.bits - usage.bits) return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid), "derived input bit limit");
      for (unsigned j = 0; j < data->get_refs_cnt(); ++j) {
        if (!seen.count(data->get_ref(j)->get_hash())) return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable), "unadmitted derived child");
      }
      seen.emplace(cell->get_hash(), false);
      ++usage.cells;  // usage.cells < limit established before loading.
      usage.bits += data->get_bits();  // Bounded by the checked remainder above.
      return td::Status::OK();
    };
    auto classify = [](const td::Status& error) -> BatchInputAdmissionFailure {
      if (error.code() == static_cast<int>(WorkchainExecutionFailure::CandidateInvalid)) return invalid("derived input limit exceeded");
      if (workchain_execution_requires_local_failure(error)) return {static_cast<WorkchainExecutionFailure>(error.code()), "derived input local failure"};
      return local("unclassified host construction failure");
    };
    auto identity = identity_;
    identity.finality = roots[2];
    auto identity_root = encode_workchain_host_identity(identity, charge);
    if (identity_root.is_error()) return classify(identity_root.error());
    td::Ref<vm::Cell> inbox_root;
    if (!inbox_.empty()) {
      std::vector<td::Ref<vm::Cell>> envelopes(roots.begin() + 3, roots.end());
      auto encoded = build_workchain_batch_inbound_structure(envelopes, policy_, charge, *std::pmr::get_default_resource());
      if (encoded.is_error()) return classify(encoded.error());
      inbox_root = encoded.move_as_ok();
    }
    vm::CellBuilder wrapper;
    wrapper.store_long(0x7c0766c8, 32).store_ref(identity_root.move_as_ok()).store_ref(roots[1]).store_ref(roots[0]);
    if (!wrapper.store_maybe_ref(inbox_root)) return local("input wrapper construction failed");
    auto root = wrapper.finalize_novm();
    auto charged = charge(root);
    if (charged.is_error()) return classify(charged);
    return AdmittedBatchInput(std::move(root), roots[0], usage, policy_);
  }

  ResolvedBatchInputPolicy policy_;
  td::Ref<vm::Cell> candidate_, declarations_;
  WorkchainHostIdentity identity_;
  const std::vector<td::Ref<vm::Cell>>& inbox_;
  std::optional<BatchInputAdmissionResult> result_;
};

// The host supplies the complete authenticated inbox, not candidate claims.
// Native envelopes are not subjected to the ordinary-candidate wire profile.
// Before calling, admission must bound all supplied closures and the derived
// dictionary/wrapper cost. Count limits alone do not bound traversal or bytes.
// This encoder does not authenticate completeness, resolve policy or execute an
// engine. Native inbox failures must retain that source at the caller boundary.
// This is post-admission construction, not validator preflight: the inbox
// encoder performs semantic decoding. A validator must check the claimed input
// commitment before rebuilding the fully authenticated inbox through this path.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_host_input(
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& access,
    const std::vector<td::Ref<vm::Cell>>& authenticated_inbox,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound) {
  if (authenticated_inbox.size() > max_inbound) {
    return td::Status::Error("host inbox exceeds admitted count");
  }
  TRY_RESULT(identity_root, encode_admitted_workchain_host_identity(identity, admitted));
  TRY_RESULT(access_root, encode_workchain_account_declarations(access, max_reads, max_writes));
  td::Ref<vm::Cell> inbox_root;
  if (!authenticated_inbox.empty()) {
    TRY_RESULT(encoded, encode_workchain_batch_inbound(authenticated_inbox));
    inbox_root = std::move(encoded);
  }
  vm::CellBuilder cb;
  cb.store_long(0x7c0766c8, 32).store_ref(identity_root).store_ref(access_root)
      .store_ref(admitted.candidate());
  if (!cb.store_maybe_ref(inbox_root)) return td::Status::Error("cannot encode host input inbox reference");
  return cb.finalize();
}

}  // namespace block
