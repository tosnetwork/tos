#include "block/workchain-execution-dispatch.h"
#include "block/workchain-unknown-origin.h"
#include "workchain-proof-test-access.h"
#include "td/utils/tests.h"
#include <type_traits>

static_assert(!std::is_constructible_v<block::WorkchainProofVerifier, std::uint64_t>);
static_assert(!std::is_copy_constructible_v<block::WorkchainProofVerifier>);
static_assert(!std::is_move_constructible_v<block::WorkchainProofVerifier>);

TEST(WorkchainProofContract, UnknownOriginTripwire) {
  const auto before = block::workchain_unknown_origin_count();
  for (int code : {0, -7300, -7399}) {
    auto unknown = block::observe_workchain_execution_status(td::Status::Error(code, "same symptom"), "contract");
    ASSERT_EQ(unknown.code(), -7201);
    auto again = block::observe_workchain_execution_status(std::move(unknown), "outer-contract");
    ASSERT_EQ(again.code(), -7201); // Normalization is not a second unknown event.
  }
  ASSERT_EQ(block::workchain_unknown_origin_count() - before, 3u);
  for (int code : {-7200, -7201, -7202}) {
    auto known = block::observe_workchain_execution_status(td::Status::Error(code, "same symptom"), "contract");
    ASSERT_EQ(known.code(), code);
    ASSERT_EQ(known.message(), "same symptom");
  }
  ASSERT_TRUE(block::observe_workchain_execution_status(td::Status::OK(), "contract").is_ok());
  ASSERT_EQ(block::workchain_unknown_origin_count() - before, 3u);
}

TEST(WorkchainProofContract, UnmeteredEngineCannotFallback) {
  struct Legacy final : block::WorkchainAccountEngine {
    mutable unsigned calls{0};
    td::Result<std::uint64_t> proof_work(const td::Ref<vm::Cell>&,
        const block::InputPolicyIdentity&) const override { return 0; }
    td::Result<block::WorkchainAccountEffects> execute_accounts(const td::Ref<vm::Cell>&,
        block::WorkchainAccountReadView&) const override {
      ++calls;
      return block::WorkchainAccountEffects{};
    }
  } engine;
  block::WorkchainAccountReadView view({});
  auto proofs = block::WorkchainProofTestAccess::create(0);
  auto result = engine.execute_metered_accounts({}, view, proofs);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
  ASSERT_EQ(engine.calls, 0u);
  ASSERT_TRUE(engine.execute_accounts({}, view).is_ok());
  ASSERT_EQ(engine.calls, 1u);
}

TEST(WorkchainProofContract, UnmeteredRegistrationCannotFallback) {
  struct Parameters final : block::WorkchainEngineConfig {} parameters;
  struct Legacy final : block::RegisteredWorkchainAccountEngine {
    mutable unsigned calls{0};
    block::WorkchainEngineKey engine_key() const override { return {}; }
    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor&, const block::Config&,
        const td::Ref<vm::Cell>&) const override {
      return td::Status::Error("fixture does not resolve configurations");
    }
    td::Result<std::uint64_t> proof_work(const td::Ref<vm::Cell>&,
        const block::InputPolicyIdentity&, const block::WorkchainEngineConfig&) const override { return 0; }
    td::Result<block::WorkchainAccountEffects> execute_accounts(const td::Ref<vm::Cell>&,
        block::WorkchainAccountReadView&, const block::WorkchainEngineConfig&) const override {
      ++calls;
      return block::WorkchainAccountEffects{};
    }
  } engine;
  block::WorkchainAccountReadView view({});
  auto proofs = block::WorkchainProofTestAccess::create(0);
  auto result = engine.execute_metered_accounts({}, view, parameters, proofs);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
  ASSERT_EQ(engine.calls, 0u);
  ASSERT_TRUE(engine.execute_accounts({}, view, parameters).is_ok());
  ASSERT_EQ(engine.calls, 1u);
}
