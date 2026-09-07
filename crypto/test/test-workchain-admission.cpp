#include <type_traits>

#include "block/workchain-input-admission.h"
#include "block/workchain-native-materialization.h"
#include "block/native-bounce-storage.h"
#include "td/utils/tests.h"
#include "vm/cells/MerkleProof.h"
#include "vm/boc.h"
#include "vm/vmstate.h"

namespace {

static_assert(!std::is_default_constructible_v<block::AdmittedInput>);
static_assert(!std::is_constructible_v<block::AdmittedInput, td::Ref<vm::Cell>,
                                     block::WorkchainInputUsage, block::InputPolicyIdentity>);

td::Ref<vm::Cell> leaf() { return vm::CellBuilder().store_long(1, 1).finalize(); }

block::ResolvedInputPolicy policy(block::WorkchainInputLimits limits) {
  block::InputPolicyIdentity identity{leaf()->get_hash(), true, 0x434e5431, UINT64_MAX, 1, 1};
  auto result = block::ResolvedInputPolicy::from_resolved_fields(limits, identity);
  ASSERT_TRUE(std::holds_alternative<block::ResolvedInputPolicy>(result));
  return std::get<block::ResolvedInputPolicy>(result);
}

class FallibleCell final : public vm::Cell {
 public:
  FallibleCell(td::Ref<vm::Cell> cell, bool* fail, unsigned* loads)
      : cell_(std::move(cell)), fail_(fail), loads_(loads) {}
  td::Status set_data_cell(td::Ref<vm::DataCell>&& value) const override {
    return cell_->set_data_cell(std::move(value));
  }
  td::Result<LoadedCell> load_cell() const override {
    ++*loads_;
    if (loader_exception == 1) throw vm::CellBuilder::CellCreateError{};
    if (loader_exception == 2) throw vm::CellBuilder::CellWriteError{};
    if (loader_exception == 3) throw vm::VmFatal{};
    if (loader_exception == 4) throw vm::VmError{vm::Excno::cell_und, "injected VM loader failure"};
    if (loader_exception == 5) throw vm::VmVirtError{};
    if (loader_exception == 6) throw vm::VmNoGas{};
    if (loader_exception == 7) throw std::bad_alloc{};
    if (loader_exception == 8) throw std::length_error{"injected allocation length failure"};
    if (*fail_) return td::Status::Error("injected cell acquisition failure");
    auto result = cell_->load_cell();
    if (result.is_error()) return result.move_as_error();
    auto loaded = result.move_as_ok();
    if (effective_level) loaded.effective_level = *effective_level;
    if (empty_data) loaded.data_cell.clear();
    return loaded;
  }
  mutable unsigned loader_exception{0};
  mutable bool wrong_depth{false}, forward_virtualization{false}, empty_data{false};
  mutable unsigned virtualization_queries{0};
  mutable std::optional<td::uint32> effective_level;
  bool is_virtualized() const override {
    ++virtualization_queries;
    return forward_virtualization && cell_->is_virtualized();
  }
  bool is_loaded() const override { return true; } // Intentionally not evidence of availability.
  vm::CellUsageTree::NodePtr get_tree_node() const override { return {}; }
  LevelMask get_level_mask() const override { return cell_->get_level_mask(); }
 private:
  const Hash do_get_hash(td::uint32 level) const override { return cell_->get_hash(level); }
  td::uint16 do_get_depth(td::uint32 level) const override { return wrong_depth ? 7 : cell_->get_depth(level); }
  td::Ref<vm::Cell> cell_;
  bool* fail_;
  unsigned* loads_;
};
} // namespace

TEST(WorkchainAdmission, OwnsEveryDescendantAndPreservesIdentity) {
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  auto root = vm::CellBuilder().store_ref(child).store_ref(child).finalize();
  block::CandidateAdmissionSession session(root, policy({2, 1, 1}));
  const auto& outcome = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(outcome));
  const auto& accepted = std::get<block::AdmittedInput>(outcome);
  ASSERT_EQ(accepted.usage().cells, 2u);
  ASSERT_EQ(accepted.usage().bits, 1u);
  ASSERT_EQ(accepted.usage().roots, 1u);
  ASSERT_EQ(loads, 1u);
  ASSERT_TRUE(accepted.candidate()->get_hash() == root->get_hash());
  ASSERT_TRUE(accepted.policy_identity().configuration_hash == leaf()->get_hash());
  ASSERT_EQ(accepted.policy_identity().engine_selector, 0x434e5431);
  ASSERT_TRUE(accepted.policy_identity().extended);
  ASSERT_EQ(accepted.policy_identity().vm_mode, UINT64_MAX);
  ASSERT_EQ(accepted.policy_identity().descriptor_version, 1u);
  ASSERT_EQ(accepted.policy_identity().admission_version, 1u);
  fail = true;
  auto detached = accepted.candidate()->load_cell().move_as_ok().data_cell;
  ASSERT_TRUE(detached->get_ref(0)->load_cell().is_ok());
  ASSERT_TRUE(detached->get_ref(1)->load_cell().is_ok());
  ASSERT_EQ(loads, 1u);
  ASSERT_TRUE(&session.evaluate() == &outcome);
}

TEST(WorkchainAdmission, LocalFailureRemainsLocalUntilNewAttempt) {
  bool fail = true;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  auto root = vm::CellBuilder().store_ref(child).finalize();
  ASSERT_TRUE(root->is_loaded());
  block::CandidateAdmissionSession failed(root, policy({2, 1, 1}));
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(failed.evaluate()));
  ASSERT_EQ(std::get<block::LocalUnavailable>(failed.evaluate()).code,
            block::LocalUnavailableCode::CellUnavailable);
  ASSERT_EQ(loads, 1u);
  fail = false;
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(failed.evaluate()));
  ASSERT_EQ(loads, 1u);
  block::CandidateAdmissionSession retry(root, policy({2, 1, 1}));
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(retry.evaluate()));
  ASSERT_EQ(loads, 2u);
}

TEST(WorkchainAdmission, ProtocolRejectionPrecedesUnnecessaryLoads) {
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  auto root = vm::CellBuilder().store_ref(child).finalize();
  block::CandidateAdmissionSession cells(root, policy({1, 1, 1}));
  ASSERT_TRUE(std::holds_alternative<block::CandidateInvalid>(cells.evaluate()));
  ASSERT_EQ(loads, 0u);
  ASSERT_EQ(std::get<block::CandidateInvalid>(cells.evaluate()).code, block::CandidateInvalidCode::CellLimit);
  auto two_bits = vm::CellBuilder().store_long(1, 2).finalize();
  block::CandidateAdmissionSession bits(two_bits, policy({1, 1, 1}));
  ASSERT_TRUE(std::holds_alternative<block::CandidateInvalid>(bits.evaluate()));
  ASSERT_EQ(std::get<block::CandidateInvalid>(bits.evaluate()).code, block::CandidateInvalidCode::BitLimit);
  auto proof = vm::MerkleProof::generate(leaf(), [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  block::CandidateAdmissionSession special(proof, policy({10, 1000, 1}));
  ASSERT_TRUE(std::holds_alternative<block::CandidateInvalid>(special.evaluate()));
  ASSERT_EQ(std::get<block::CandidateInvalid>(special.evaluate()).code, block::CandidateInvalidCode::ForbiddenSpecial);
}

TEST(WorkchainAdmission, ConfigurationFailureIsSeparate) {
  block::InputPolicyIdentity identity{leaf()->get_hash(), false, 1, 0, 1, 1};
  for (auto limits : {block::WorkchainInputLimits{0, 1, 1}, {1, 0, 1}, {1, 1, 0}}) {
    auto result = block::ResolvedInputPolicy::from_resolved_fields(limits, identity);
    ASSERT_TRUE(std::holds_alternative<block::ConfigInvalid>(result));
    ASSERT_EQ(std::get<block::ConfigInvalid>(result).code, block::ConfigInvalidCode::ZeroLimit);
  }
  identity.admission_version = 2;
  auto unsupported = block::ResolvedInputPolicy::from_resolved_fields({1, 1, 1}, identity);
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(unsupported));
  ASSERT_EQ(std::get<block::LocalUnavailable>(unsupported).code,
            block::LocalUnavailableCode::UnsupportedAdmissionVersion);
}

TEST(WorkchainAdmission, WireSpecialAndLocalViewHaveDifferentProvenance) {
  auto pruned = vm::CellBuilder::do_create_pruned_branch(leaf(), 1, 0);
  auto bytes = vm::std_boc_serialize(pruned).move_as_ok();
  // Permit the encoded level here to test this boundary, not an earlier BoC
  // profile gate. Deserialization still does not manufacture a VirtualCell.
  auto received = vm::std_boc_deserialize(bytes.as_slice(), false, true).move_as_ok();
  ASSERT_TRUE(!received->is_virtualized());
  block::CandidateAdmissionSession wire(received, policy({10, 1000, 1}));
  ASSERT_TRUE(std::holds_alternative<block::CandidateInvalid>(wire.evaluate()));
  ASSERT_EQ(std::get<block::CandidateInvalid>(wire.evaluate()).code,
            block::CandidateInvalidCode::ForbiddenSpecial);

  for (bool descendant : {false, true}) {
    bool fail = false;
    unsigned loads = 0;
    td::Ref<FallibleCell> wrapped{true, received->virtualize(0), &fail, &loads};
    // Synthetic local-loader inconsistency: build before exposing the view,
    // defeating the normal parent's cached virtualization propagation. This
    // probes the loop defensively, not a reachable serialized peer input.
    td::Ref<vm::Cell> root = wrapped;
    if (descendant) root = vm::CellBuilder().store_ref(wrapped).finalize();
    wrapped->forward_virtualization = true;
    block::CandidateAdmissionSession local(root, policy({10, 1000, 1}));
    const auto& outcome = local.evaluate();
    ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(outcome));
    ASSERT_EQ(std::get<block::LocalUnavailable>(outcome).code, block::LocalUnavailableCode::CellIdentity);
    ASSERT_EQ(loads, 0u);
    wrapped->forward_virtualization = false;
    local.evaluate();
    // Re-evaluation could return the same category at the same storage address;
    // only the load counter independently detects another acquisition attempt.
    ASSERT_EQ(loads, 0u);
  }
}

TEST(WorkchainAdmission, NativeClosureOwnsSpecialRepresentation) {
  static_assert(!std::is_default_constructible_v<block::MaterializedNativeCells>);
  static_assert(!std::is_constructible_v<block::MaterializedNativeCells,
      std::vector<td::Ref<vm::Cell>>, block::WorkchainInputUsage>);
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  auto pruned = vm::CellBuilder::do_create_pruned_branch(leaf(), 1, 0);
  auto proof = vm::MerkleProof::generate(leaf(), [](const td::Ref<vm::Cell>&) { return false; }).move_as_ok();
  auto root = vm::CellBuilder().store_ref(child).store_ref(library).store_ref(pruned).store_ref(proof).finalize();
  std::vector<td::Ref<vm::Cell>> roots{root, library};
  auto result = block::NativeCellMaterializer::run(roots, {5, 833, 2});
  ASSERT_TRUE(std::holds_alternative<block::MaterializedNativeCells>(result));
  const auto& owned = std::get<block::MaterializedNativeCells>(result);
  ASSERT_EQ(owned.physical_usage().cells, 5u);
  ASSERT_EQ(owned.physical_usage().bits, 833u);
  ASSERT_EQ(owned.physical_usage().roots, 2u);
  ASSERT_EQ(loads, 1u);
  ASSERT_EQ(owned.roots().size(), 2u);
  ASSERT_TRUE(root->check_equals_unloaded(owned.roots()[0]).is_ok());
  ASSERT_TRUE(library->check_equals_unloaded(owned.roots()[1]).is_ok());
  fail = true;
  auto data = owned.roots()[0]->load_cell().move_as_ok().data_cell;
  ASSERT_TRUE(data->get_ref(0)->load_cell().is_ok());
  ASSERT_TRUE(data->get_ref(1)->load_cell().move_as_ok().data_cell->is_special());
  ASSERT_TRUE(data->get_ref(2)->check_equals_unloaded(pruned).is_ok());
  ASSERT_TRUE(data->get_ref(3)->check_equals_unloaded(proof).is_ok());
  auto size = block::measure_native_bounce_storage(false, {}, owned.roots()).move_as_ok();
  ASSERT_EQ(size.cells, 5u);
  ASSERT_EQ(size.bits, 833u);
  ASSERT_EQ(loads, 1u); // Native pricing no longer reaches the unavailable loader.
}

TEST(WorkchainAdmission, NativeClosureLimitsAndLocalFailures) {
  bool fail = true;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  auto root = vm::CellBuilder().store_ref(child).finalize();
  std::vector<td::Ref<vm::Cell>> roots{root};
  auto limited = block::NativeCellMaterializer::run(roots, {1, 1, 1});
  ASSERT_TRUE(std::holds_alternative<block::NativeClosureLimit>(limited));
  ASSERT_EQ(std::get<block::NativeClosureLimit>(limited), block::NativeClosureLimit::Cells);
  ASSERT_EQ(loads, 0u);
  auto root_limit = block::NativeCellMaterializer::run(roots, {2, 1, 0});
  ASSERT_TRUE(std::holds_alternative<block::NativeClosureLimit>(root_limit));
  ASSERT_EQ(std::get<block::NativeClosureLimit>(root_limit), block::NativeClosureLimit::Roots);
  ASSERT_EQ(loads, 0u);
  auto unavailable = block::NativeCellMaterializer::run(roots, {2, 1, 1});
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(unavailable));
  ASSERT_EQ(std::get<block::LocalUnavailable>(unavailable).code, block::LocalUnavailableCode::CellUnavailable);
  ASSERT_EQ(loads, 1u);
  fail = false;
  auto bits = block::NativeCellMaterializer::run(roots, {2, 0, 1});
  ASSERT_TRUE(std::holds_alternative<block::NativeClosureLimit>(bits));
  ASSERT_EQ(std::get<block::NativeClosureLimit>(bits), block::NativeClosureLimit::Bits);
  ASSERT_EQ(loads, 2u);
  auto retry = block::NativeCellMaterializer::run(roots, {2, 1, 1});
  ASSERT_TRUE(std::holds_alternative<block::MaterializedNativeCells>(retry));
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(unavailable));
  auto empty = block::NativeCellMaterializer::run({}, {0, 0, 0});
  ASSERT_TRUE(std::holds_alternative<block::MaterializedNativeCells>(empty));
  ASSERT_TRUE(std::get<block::MaterializedNativeCells>(empty).roots().empty());
  ASSERT_EQ(std::get<block::MaterializedNativeCells>(empty).physical_usage().cells, 0u);
  std::vector<td::Ref<vm::Cell>> zero_bits{vm::CellBuilder().finalize()};
  auto zero = block::NativeCellMaterializer::run(zero_bits, {1, 0, 1});
  ASSERT_TRUE(std::holds_alternative<block::MaterializedNativeCells>(zero));
  ASSERT_EQ(std::get<block::MaterializedNativeCells>(zero).physical_usage().bits, 0u);
}

TEST(WorkchainAdmission, NativeClosureChecksLoadedAndCachedIdentity) {
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> alias{true, leaf(), &fail, &loads};
  std::vector<td::Ref<vm::Cell>> roots{alias};
  alias->wrong_depth = true;
  auto fresh = block::NativeCellMaterializer::run(roots, {1, 1, 1});
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(fresh));
  ASSERT_EQ(std::get<block::LocalUnavailable>(fresh).code, block::LocalUnavailableCode::CellIdentity);
  roots = {leaf(), alias};
  auto cached = block::NativeCellMaterializer::run(roots, {1, 1, 2});
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(cached));
  ASSERT_EQ(std::get<block::LocalUnavailable>(cached).code, block::LocalUnavailableCode::CellIdentity);
  alias->wrong_depth = false;
  auto pruned = vm::CellBuilder::do_create_pruned_branch(leaf(), 1, 0);
  td::Ref<FallibleCell> lower{true, pruned, &fail, &loads};
  lower->effective_level = 0;
  roots = {lower};
  auto level = block::NativeCellMaterializer::run(roots, {1, 288, 1});
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(level));
  ASSERT_EQ(std::get<block::LocalUnavailable>(level).code, block::LocalUnavailableCode::CellIdentity);
  lower->effective_level.reset();
  lower->empty_data = true;
  auto missing = block::NativeCellMaterializer::run(roots, {1, 288, 1});
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(missing));
  ASSERT_EQ(std::get<block::LocalUnavailable>(missing).code, block::LocalUnavailableCode::CellIdentity);
}

TEST(WorkchainAdmission, CandidateFreshMetadataIdentity) {
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> alias{true, leaf(), &fail, &loads};
  alias->wrong_depth = true;
  block::CandidateAdmissionSession session(alias, policy({10, 1000, 1}));
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
  ASSERT_EQ(std::get<block::LocalUnavailable>(result).code, block::LocalUnavailableCode::CellIdentity);
  ASSERT_EQ(loads, 1u);
}

TEST(WorkchainAdmission, CandidateCachedMetadataIdentity) {
  bool fail = false;
  unsigned loads = 0;
  auto shared = leaf();
  td::Ref<FallibleCell> alias{true, shared, &fail, &loads};
  auto root = vm::CellBuilder().store_ref(shared).store_ref(alias).finalize();
  // Local loader metadata corruption after the parent captured its identity;
  // this is not a serialized alternative encoding with a different root hash.
  alias->wrong_depth = true;
  block::CandidateAdmissionSession session(root, policy({10, 1000, 1}));
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
  ASSERT_EQ(std::get<block::LocalUnavailable>(result).code, block::LocalUnavailableCode::CellIdentity);
  ASSERT_EQ(loads, 0u); // Cache-hit metadata can be checked without loading it.
}

TEST(WorkchainAdmission, CandidateEffectiveLevelIdentity) {
  bool fail = false;
  unsigned loads = 0;
  auto pruned = vm::CellBuilder::do_create_pruned_branch(leaf(), 1, 0);
  td::Ref<FallibleCell> lower{true, pruned, &fail, &loads};
  lower->effective_level = 0;
  block::CandidateAdmissionSession session(lower, policy({10, 1000, 1}));
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
  ASSERT_EQ(std::get<block::LocalUnavailable>(result).code, block::LocalUnavailableCode::CellIdentity);
}

TEST(WorkchainAdmission, CandidateLoadedViewPrecedesDescendants) {
  bool fail = false;
  unsigned loads = 0;
  auto pruned = vm::CellBuilder::do_create_pruned_branch(leaf(), 1, 0);
  td::Ref<FallibleCell> child{true, pruned->virtualize(0), &fail, &loads};
  child->forward_virtualization = true;
  auto source = vm::CellBuilder().store_ref(child).finalize();
  ASSERT_TRUE(source->is_virtualized());
  // Synthetic loader-contract violation: a normal in-memory parent reports
  // the view and is caught earlier; this handle deliberately masks that fact.
  td::Ref<FallibleCell> hidden{true, source, &fail, &loads};
  child->virtualization_queries = 0;
  block::CandidateAdmissionSession session(hidden, policy({10, 1000, 1}));
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
  ASSERT_EQ(std::get<block::LocalUnavailable>(result).code, block::LocalUnavailableCode::CellIdentity);
  ASSERT_EQ(loads, 1u);
  // The category also holds after a later rejection; this counter alone
  // distinguishes rejecting the loaded view before descending into its refs.
  ASSERT_EQ(child->virtualization_queries, 0u);
}

TEST(WorkchainAdmission, CandidateRebuildIgnoresAmbientVm) {
  class CountingVm final : public vm::VmStateInterface {
   public:
    unsigned creates{0}, registrations{0};
    void register_cell_create() override { ++creates; }
    void register_new_cell(td::Ref<vm::DataCell>&) override { ++registrations; }
  } vm;
  auto root = vm::CellBuilder().store_ref(leaf()).finalize();
  auto bounds = policy({10, 1000, 1});
  vm::VmStateInterface::Guard context(&vm);
  block::CandidateAdmissionSession session(root, bounds);
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::AdmittedInput>(result));
  ASSERT_TRUE(std::get<block::AdmittedInput>(result).candidate()->get_hash() == root->get_hash());
  ASSERT_EQ(vm.creates, 0u);
  ASSERT_EQ(vm.registrations, 0u);
}

TEST(WorkchainAdmission, CandidateLoaderFatalIsLocal) {
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  child->loader_exception = 3;
  block::CandidateAdmissionSession session(child, policy({10, 1000, 1}));
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
  ASSERT_EQ(std::get<block::LocalUnavailable>(result).code, block::LocalUnavailableCode::ExecutionFault);
}

TEST(WorkchainAdmission, CandidateLoaderLengthIsLocal) {
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  child->loader_exception = 8;
  block::CandidateAdmissionSession session(child, policy({10, 1000, 1}));
  const auto& result = session.evaluate();
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
  ASSERT_EQ(std::get<block::LocalUnavailable>(result).code, block::LocalUnavailableCode::Allocation);
}

TEST(WorkchainAdmission, NativeClosureExceptionBoundary) {
  bool fail = false;
  unsigned loads = 0;
  td::Ref<FallibleCell> child{true, leaf(), &fail, &loads};
  std::vector<td::Ref<vm::Cell>> roots{vm::CellBuilder().store_ref(child).finalize()};
  using Code = block::LocalUnavailableCode;
  struct Case { unsigned mode; Code expected; };
  for (auto c : {Case{1, Code::Construction}, Case{2, Code::Construction},
                 Case{3, Code::ExecutionFault}, Case{4, Code::ExecutionFault},
                 Case{5, Code::CellUnavailable}, Case{6, Code::ExecutionFault},
                 Case{7, Code::Allocation}, Case{8, Code::Allocation}}) {
    LOG(INFO) << "Native closure exception injection " << c.mode;
    child->loader_exception = c.mode;
    auto result = block::NativeCellMaterializer::run(roots, {2, 1, 1});
    ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(result));
    ASSERT_EQ(std::get<block::LocalUnavailable>(result).code, c.expected);
  }
}

TEST(WorkchainAdmission, NativeClosureVirtualizationPrecedesDescendantWork) {
  bool fail = false;
  unsigned loads = 0;
  auto pruned = vm::CellBuilder::do_create_pruned_branch(leaf(), 1, 0);
  td::Ref<FallibleCell> underlying{true, pruned, &fail, &loads};
  auto virtualized = underlying->virtualize(0);
  ASSERT_TRUE(virtualized->is_virtualized());
  std::vector<td::Ref<vm::Cell>> roots{virtualized};
  auto view = block::NativeCellMaterializer::run(roots, {2, 1000, 1});
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(view));
  ASSERT_EQ(std::get<block::LocalUnavailable>(view).code, block::LocalUnavailableCode::CellIdentity);
  ASSERT_EQ(loads, 0u);
  td::Ref<FallibleCell> child{true, virtualized, &fail, &loads};
  child->forward_virtualization = true;
  auto source = vm::CellBuilder().store_ref(child).finalize();
  ASSERT_TRUE(source->is_virtualized());
  td::Ref<FallibleCell> hidden{true, source, &fail, &loads};
  roots = {hidden};
  child->virtualization_queries = 0;
  auto loaded = block::NativeCellMaterializer::run(roots, {3, 1000, 1});
  ASSERT_TRUE(std::holds_alternative<block::LocalUnavailable>(loaded));
  ASSERT_EQ(std::get<block::LocalUnavailable>(loaded).code, block::LocalUnavailableCode::CellIdentity);
  ASSERT_EQ(loads, 1u);
  ASSERT_EQ(child->virtualization_queries, 0u);
}
