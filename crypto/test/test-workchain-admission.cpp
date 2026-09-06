#include <type_traits>

#include "block/workchain-input-admission.h"
#include "td/utils/tests.h"
#include "vm/cells/MerkleProof.h"

namespace {

static_assert(!std::is_default_constructible_v<block::AdmittedInput>);
static_assert(!std::is_constructible_v<block::AdmittedInput, td::Ref<vm::Cell>,
                                     block::WorkchainInputUsage, block::InputPolicyIdentity>);

td::Ref<vm::Cell> leaf() { return vm::CellBuilder().store_long(1, 1).finalize(); }

block::ResolvedInputPolicy policy(block::WorkchainInputLimits limits) {
  block::InputPolicyIdentity identity{leaf()->get_hash(), 0, 0x434e5431, 1, 1};
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
    if (*fail_) return td::Status::Error("injected cell acquisition failure");
    return cell_->load_cell();
  }
  bool is_virtualized() const override { return false; }
  bool is_loaded() const override { return true; } // Intentionally not evidence of availability.
  vm::CellUsageTree::NodePtr get_tree_node() const override { return {}; }
  LevelMask get_level_mask() const override { return cell_->get_level_mask(); }
 private:
  const Hash do_get_hash(td::uint32 level) const override { return cell_->get_hash(level); }
  td::uint16 do_get_depth(td::uint32 level) const override { return cell_->get_depth(level); }
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
  block::InputPolicyIdentity identity{leaf()->get_hash(), 0, 1, 1, 1};
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
