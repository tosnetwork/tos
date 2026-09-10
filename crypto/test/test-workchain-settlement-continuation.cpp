#include "block/workchain-account-settlement.h"
#include "block/workchain-execution-dispatch.h"
#include "block/workchain-account-binding-owner.h"
#include "block/workchain-account-candidate.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include <iostream>
#include <stdexcept>
#include <type_traits>

namespace {
void require(bool value, const char* name) {
  if (!value) throw std::runtime_error(name);
}
td::Bits256 key(unsigned n) {
  auto value = td::Bits256::zero();
  value.bits().store_uint(n, 8);
  return value;
}
td::Ref<vm::Cell> number(unsigned n) { return vm::CellBuilder().store_long(n, 64).finalize(); }
void candidate_transport() {
  using Candidate = block::WorkchainAccountCandidate;
  static_assert(!std::is_default_constructible_v<Candidate>);
  static_assert(!std::is_constructible_v<Candidate, td::Ref<vm::Cell>>);
  auto input = number(7), access = number(8);
  Candidate roots{input, access};
  require(roots.candidate().get() == input.get(), "carrier.original_candidate");
  require(roots.declarations().get() == access.get(), "carrier.original_declarations");
  auto copy = roots;
  roots = Candidate{{}, {}};
  require(copy.candidate().get() == input.get() && copy.declarations().get() == access.get(),
          "carrier.independent_holder");
  require(roots.candidate().is_null() && roots.declarations().is_null(), "carrier.no_empty_defaults");
  Candidate absent_access{input, {}};
  Candidate absent_input{{}, access};
  require(absent_access.declarations().is_null(), "carrier.missing_declarations_preserved");
  require(absent_input.candidate().is_null(), "carrier.missing_candidate_preserved");
}
td::Ref<vm::Cell> account(unsigned n) {
  vm::CellBuilder b;
  b.store_long(1, 1).store_long(4, 3).store_long(2, 8).store_bits(key(n).bits(), 256)
      .store_zeroes(42).store_long(2, 64);
  require(block::CurrencyCollection(1000).store(b), "fixture.balance");
  auto state = block::encode_workchain_executor_state({number(1), {}, {}}).move_as_ok();
  b.store_long(1, 1).store_zeroes(3).store_long(1, 1).store_ref(state).store_long(0, 1);
  auto root = b.finalize();
  require(block::gen::t_Account.validate_ref(4096, root), "fixture.account");
  return root;
}
struct Engine final : block::RegisteredWorkchainAccountEngine {
  mutable unsigned calls = 0, inspections = 0;
  block::WorkchainEngineKey engine_key() const override { return {block::WorkchainFormat::Basic, 0x434e5431}; }
  td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
      const block::WorkchainExecutionDescriptor&, const block::Config&, const td::Ref<vm::Cell>&) const override {
    return td::Status::Error("private fixture does not resolve live configuration");
  }
  td::Result<std::uint64_t> proof_work(const td::Ref<vm::Cell>&, const block::InputPolicyIdentity&,
                                    const block::WorkchainEngineConfig&) const override {
    ++inspections;
    return 0;
  }
  td::Result<block::WorkchainAccountEffects> execute_accounts(const td::Ref<vm::Cell>&,
      block::WorkchainAccountReadView& view, const block::WorkchainEngineConfig&) const override {
    ++calls;  // Actual registered engine body, not a host wrapper counter.
    block::WorkchainAccountEffects effects;
    for (unsigned n : {16u, 32u}) {
      TRY_RESULT(old, view.read(key(n)));
      if (old.is_null()) return td::Status::Error("fixture missing account");
      effects.updates.push_back({key(n), number(n + 100)});
    }
    effects.receipts = number(103);
    effects.events = number(104);
    return effects;
  }
};
void owner_lifecycle(const block::ResolvedWorkchainAccountBinding& binding) {
  using Owner = block::WorkchainAccountBindingOwner;
  static_assert(!std::is_default_constructible_v<Owner>);
  static_assert(!std::is_move_constructible_v<Owner> && !std::is_copy_constructible_v<Owner>);
  static_assert(!std::is_constructible_v<Owner, block::ResolvedWorkchainAccountBinding,
      std::unique_ptr<block::ConfiguredWorkchainAccountEngine>>);
  const auto before = binding.engine_config.use_count();
  auto created = Owner::bind(binding);
  require(created.is_ok(), "owner.bind_positive");
  auto owner = created.move_as_ok();
  require(binding.engine_config.use_count() == before + 2, "owner.both_configuration_references");
  const auto* adapter = &owner->adapter();
  auto transferred = std::move(owner);
  require(!owner && &transferred->adapter() == adapter, "owner.transfer_keeps_adapter_identity");
  const auto after_adapter = Owner::release(std::move(transferred));
  require(!transferred && after_adapter == before + 1, "owner.intermediate_count_sample");
  require(binding.engine_config.use_count() == before, "owner.explicit_release_both_halves");
  require(Owner::release(nullptr) == 0, "owner.already_released");
  {
    auto scoped = Owner::bind(binding).move_as_ok();
    require(binding.engine_config.use_count() == before + 2, "owner.destructor_positive");
  }
  require(binding.engine_config.use_count() == before, "owner.destructor_releases_both_halves");
  auto missing = binding;
  missing.engine_config.reset();
  require(Owner::bind(std::move(missing)).is_error(), "owner.missing_configuration_cannot_publish");
  auto unregistered = binding;
  unregistered.executor = nullptr;
  require(Owner::bind(std::move(unregistered)).is_error(), "owner.missing_engine_cannot_publish");
  require(binding.engine_config.use_count() == before, "owner.failed_bind_consumed_argument");
  auto moved_binding = binding;
  const auto before_move = binding.engine_config.use_count();
  auto moved_owner = Owner::bind(std::move(moved_binding)).move_as_ok();
  require(!moved_binding.engine_config, "owner.move_consumes_binding");
  require(binding.engine_config.use_count() == before_move + 1, "owner.production_move_count");
  require(Owner::release(std::move(moved_owner)) == before_move, "owner.production_release_count");
  require(binding.engine_config.use_count() == before, "owner.production_release_both_halves");
}
void run(const std::string& scenario) {
  Engine engine;
  block::WorkchainResourcePolicy resources{2, {1000, 1000000, 3, 2, 2, 1},
      {1000, 1000000, 128, 65536, 64}, {32, 128, 65536, 1000, 1000000, 2}};
  if (scenario == "effects") resources.work_output.max_effect_cells = 1;
  if (scenario == "output") resources.work_output.max_output_cells = 1;
  block::InputPolicyIdentity policy_id{vm::CellHash{}, false, 0x434e5431, 7, 5, 2};
  auto resolved = block::ResolvedBatchInputPolicy::from_resolved_fields(resources, policy_id);
  require(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved), "fixture.policy");
  auto policy = std::get<block::ResolvedBatchInputPolicy>(resolved);
  block::ResolvedWorkchainAccountBinding binding{&engine, {}, {},
      std::make_shared<const block::WorkchainEngineConfig>(), number(9), policy};
  owner_lifecycle(binding);
  auto owner = block::WorkchainAccountBindingOwner::bind(binding).move_as_ok();
  const auto* adapter = &owner->adapter();
  auto other = block::ConfiguredWorkchainAccountEngine::bind(binding).move_as_ok();
  vm::AugmentedDictionary dictionary(256, block::tlb::aug_ShardAccounts);
  block::WorkchainAccountDeclarations declarations;
  for (unsigned n : {16u, 32u}) {
    auto old = account(n);
    vm::CellBuilder entry;
    entry.store_ref(old).store_zeroes(256).store_long(1, 64);
    require(dictionary.set_builder(key(n), entry), "fixture.dictionary");
    declarations.reads.push_back({key(n), td::Bits256(old->get_hash().bits())});
    declarations.writes.push_back(key(n));
  }
  auto tree = std::make_shared<vm::CellUsageTree>();
  auto old = vm::UsageCell::create(dictionary.get_wrapped_dict_root(), tree->root_ptr());
  auto zero = td::Bits256::zero();
  block::WorkchainHostIdentity identity{0, zero, zero, 2, UINT64_C(0x8000000000000000),
      zero, false, 0x434e5431, 7, 5, 2, zero, 1, 10, 20, number(42)};
  const std::vector<td::Ref<vm::Cell>> inbox;
  auto access = block::encode_workchain_account_declarations(declarations, 2, 2).move_as_ok();
  block::BatchInputAdmissionSession session(policy, number(5), access, identity, inbox);
  require(std::holds_alternative<block::AdmittedBatchInput>(session.evaluate()), "fixture.admission");
  const auto& admitted = std::get<block::AdmittedBatchInput>(session.evaluate());
  auto preflight = block::ProofAdmittedBatchInput::admit(*adapter, admitted).move_as_ok();
  require(preflight.inspected_by(*adapter), "identity.positive");
  auto wrong = block::account_engine_detail::execute(*other, old, preflight, declarations, 2, 2);
  require(wrong.is_error() && wrong.error().code() == -7201 &&
      wrong.error().message() == "proof admission belongs to another engine", "identity.wrong_instance");
  require(engine.calls == 0, "identity.before_engine");
  auto executed = block::account_engine_detail::execute(*adapter, old, preflight, declarations, 2, 2).move_as_ok();
  require(engine.calls == 1, "execute.exactly_once");
  // A fresh tracking tree isolates settlement reads from prior engine reads.
  auto settlement_tree = std::make_shared<vm::CellUsageTree>();
  unsigned settlement_loads = 0;
  settlement_tree->set_cell_load_callback([&](const vm::LoadedCell&) { ++settlement_loads; });
  auto settlement_old = vm::UsageCell::create(dictionary.get_wrapped_dict_root(), settlement_tree->root_ptr());
  auto empty_proof = vm::std_boc_serialize(vm::MerkleProof::generate(
      dictionary.get_wrapped_dict_root(), settlement_tree.get()).move_as_ok()).move_as_ok();
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = cfg.extra_currency_v2 = true;
  block::ActionPhaseConfig prices;
  prices.global_version = 16;
  prices.disable_custom_fess = prices.disable_anycast = prices.extra_currency_v2 = true;
  prices.fwd_mc = block::MsgPrices(100, 0, 0, 0, 16384, 0);
  prices.fwd_std = block::MsgPrices(200, 0, 0, 0, 16384, 0);
  std::vector<td::Ref<vm::Cell>> native_roots;
  auto native_result = block::NativeCellMaterializer::run(native_roots, {1000, 1000000, 1});
  require(std::holds_alternative<block::MaterializedNativeCells>(native_result), "fixture.native");
  const auto& native = std::get<block::MaterializedNativeCells>(native_result);
  (void)native;  // Used by the combined-entry regression control.
  auto settle = [&](block::ExecutedWorkchainAccountBatch result) {
    return block::account_settlement_detail::settle_executed(std::move(result), settlement_old, identity, preflight,
        declarations, settlement_tree->root_ptr(), 2, 2, 1, 2, key(16), key(32), td::make_refint(500),
        4096, cfg, prices, nullptr);
  };
  if (scenario == "input" || scenario == "state" || scenario == "observer") {
    auto changed = executed;
    if (scenario == "input") {
      // Keep framing, identity, declarations and inbox valid. Only the candidate
      // changes, so a later malformed-input check cannot mask the binding guard.
      block::gen::UnoV2HostInput::Record alternative;
      require(block::tlb::unpack_cell(executed.input, alternative), "fixture.input_decode");
      alternative.candidate = number(99);
      require(block::tlb::pack_cell(changed.input, alternative), "fixture.input_encode");
    }
    if (scenario == "state") changed.state_admission.reset();
    if (scenario == "observer") changed.state_admission.emplace(1000, 1000000);
    auto refused = settle(std::move(changed));
    const char* reason = scenario == "input" ? "executed input differs from settlement admission" :
        scenario == "state" ? "settlement lacks old-state admission" :
                              "settlement read outside admitted old-state footprint";
    require(refused.is_error(), "negative.expected_refusal");
    require(refused.error().code() == -7201 && refused.error().message() == td::Slice(reason),
            "negative.exact_source_guard");
    require(engine.calls == 1, "negative.no_reexecution");
    std::cout << scenario << ": exact local refusal; actual_engine_calls=" << engine.calls << '\n';
    return;
  }
  auto result = settle(std::move(executed));
  if (scenario == "effects" || scenario == "output") {
    require(result.is_error(), "budget.expected_refusal");
    require(result.error().code() == static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid),
            "budget.candidate_invalid");
    require(engine.calls == 1, "budget.no_reexecution");
    std::cout << scenario << ": typed budget refusal; actual_engine_calls=" << engine.calls << '\n';
    return;
  }
  if (result.is_error()) throw std::runtime_error(result.error().to_string());
  std::cout << scenario << ": actual_engine_calls=" << engine.calls << " inspections=" << engine.inspections << '\n';
  require(engine.calls == 1, "settlement.exactly_once");
  require(engine.inspections == 1, "settlement.single_inspection");
  require(result.ok().input->get_hash() == admitted.root()->get_hash(), "binding.input");
  require(result.ok().state.accounts->get_hash() != old->get_hash(), "settlement.changed");
  require(result.ok().state_admission && result.ok().output_admission, "settlement.budgets");
  require(settlement_loads > 0, "tracking.positive_settlement_reads");
  require(result.ok().state_usage_node.is_from_tree(settlement_tree.get()), "tracking.same_tree");
  auto proof = vm::std_boc_serialize(vm::MerkleProof::generate(
      dictionary.get_wrapped_dict_root(), settlement_tree.get()).move_as_ok()).move_as_ok();
  require(proof.as_slice() != empty_proof.as_slice(), "tracking.proof_records_settlement_reads");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    candidate_transport();
    if (argc == 2) run(argv[1]);
    else for (const char* scenario : {"once", "input", "state", "observer", "tracking", "effects", "output"}) run(scenario);
    return 0;
  }
  catch (const vm::VmError& error) { std::cerr << error.get_msg() << '\n'; return 1; }
  catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
