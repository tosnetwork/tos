#include "block/workchain-coverage.h"
#include "block/workchain-block-execution.h"
#include "block/workchain-account-dictionary.h"
#include "block/workchain-read-phase.h"
#include "block/workchain-storage-overlay.h"
#include "vm/cells/UsageCell.h"
#include "vm/cells/MerkleProof.h"
#include "vm/boc.h"
#include <iostream>
#include <cstdlib>
#include <string>

namespace {
void require(bool value, const char* name) {
  if (!value) { std::cerr << name << '\n'; std::exit(1); }
}
td::Bits256 key(unsigned n) {
  auto result = td::Bits256::zero(); result.bits().store_uint(n, 8); return result;
}
td::Ref<vm::Cell> account(unsigned n) {
  vm::CellBuilder cell;
  cell.store_long(1, 1).store_long(4, 3).store_long(2, 8).store_bits(key(n).bits(), 256)
      .store_zeroes(42).store_long(2, 64);
  require(block::CurrencyCollection(td::make_refint(0)).store(cell), "fixture.balance");
  auto data = vm::CellBuilder().store_long(n, 64).finalize();
  auto executor = block::encode_workchain_executor_state({data, {}, {}});
  require(executor.is_ok(), "fixture.executor");
  cell.store_long(1, 1).store_zeroes(3).store_long(1, 1).store_ref(executor.move_as_ok()).store_long(0, 1);
  return cell.finalize();
}
void put(vm::AugmentedDictionary& dict, unsigned n, unsigned revision) {
  vm::CellBuilder entry;
  entry.store_ref(account(n)).store_zeroes(256).store_long(revision, 64);
  require(dict.set_builder(key(n), entry), "fixture.put");
}
block::ResolvedBatchInputPolicy policy(unsigned writes = 10) {
  block::WorkchainResourcePolicy p{};
  p.admission_version = 4;
  p.input.max_cells = 100; p.input.max_bits = 100000; p.input.max_roots = 3;
  p.input.max_reads = 10; p.input.max_writes = writes; p.input.max_inbound = 9;
  p.state.max_cells = 100; p.state.max_bits = 100000;
  p.state.max_account_cells = 50; p.state.max_account_bits = 50000; p.state.max_account_depth = 32;
  p.work_output.max_effect_cells = 100; p.work_output.max_effect_bits = 100000;
  p.work_output.max_output_cells = 100; p.work_output.max_output_bits = 100000;
  auto result = block::ResolvedBatchInputPolicy::from_resolved_fields(p, {{}, false, 0, 0, 1, 4});
  require(std::holds_alternative<block::ResolvedBatchInputPolicy>(result), "fixture.policy");
  return std::get<block::ResolvedBatchInputPolicy>(result);
}
using Source = block::WorkchainCoverageSource;
using Object = block::WorkchainCoverageObject;
using Reason = block::WorkchainCoverageReason;
using Failure = block::WorkchainCoverageFailure;
using Keys = std::vector<td::Bits256>;
using Verdict = block::WorkchainBatchScanDisposition;
class FaultCell final : public vm::Cell {
 public:
  FaultCell(td::Ref<vm::Cell> root, unsigned fault, unsigned* calls)
      : root_(std::move(root)), fault_(fault), calls_(calls) {}
  td::Status set_data_cell(td::Ref<vm::DataCell>&& cell) const override { return root_->set_data_cell(std::move(cell)); }
  td::Result<LoadedCell> load_cell() const override {
    ++*calls_;
    switch (fault_) {
      case 0: return root_->load_cell();
      case 1: throw vm::VmError(vm::Excno::dict_err, "local provider fault");
      case 2: throw vm::VmNoGas{};
      case 3: throw vm::VmFatal{};
      case 4: throw vm::CellBuilder::CellCreateError{};
      case 5: throw vm::CellBuilder::CellWriteError{};
      case 6: return td::Status::Error("local provider unavailable");
      default: throw std::bad_alloc();
    }
  }
  bool is_virtualized() const override { return root_->is_virtualized(); }
  vm::CellUsageTree::NodePtr get_tree_node() const override { return root_->get_tree_node(); }
  bool is_loaded() const override { return root_->is_loaded(); }
  LevelMask get_level_mask() const override { return root_->get_level_mask(); }
 private:
  td::uint16 do_get_depth(td::uint32 level) const override { return root_->get_depth(level); }
  const Hash do_get_hash(td::uint32 level) const override { return root_->get_hash(level); }
  td::Ref<vm::Cell> root_;
  unsigned fault_;
  unsigned* calls_;
};
block::WorkchainCoverageKeys delta(td::Ref<vm::Cell> a, td::Ref<vm::Cell> b, unsigned bound = 10,
                                   Source source = Source::ReceivedCandidate, Object object = Object::CandidateClaim) {
  block::NativeStateReadMeter old(100, 100000), next(100, 100000);
  return block::rebuild_workchain_account_delta(a, b, policy(bound), old, next, source, object);
}
void deltas() {
  vm::AugmentedDictionary old(256, block::tlb::aug_ShardAccounts);
  for (unsigned n : {16, 32, 64, 128, 192, 224}) put(old, n, 1);
  auto original = old.get_wrapped_dict_root();
  {
    vm::AugmentedDictionary singleton(256, block::tlb::aug_ShardAccounts);
    put(singleton, 16, 1);
    auto wrapped = singleton.get_wrapped_dict_root();
    auto outer = vm::load_cell_slice(wrapped);
    require(outer.fetch_ulong(1) == 1, "fixture.present");
    auto leaf = outer.fetch_ref();
    auto full = vm::load_cell_slice(leaf);
    vm::dict::LabelParser label{td::make_ref<vm::CellSlice>(full), 256, 0};
    require(label.is_valid() && label.l_bits == 256, "fixture.singleton_label");
    label.skip_label();
    auto tail = *label.remainder;
    unsigned prefix = tail.cur_pos() - full.cur_pos(); // Slices share the same cell; tail follows the label.
    require(tail.fetch_ulong(5) == 0, "fixture.original_depth");
    vm::CellBuilder changed;
    changed.store_bits(full.data_bits(), prefix).store_long(1, 5).append_cellslice(tail);
    auto new_root = vm::CellBuilder().store_long(1, 1).store_ref(changed.finalize()).append_cellslice(outer).finalize();
    auto result = delta(wrapped, new_root);
    require(std::holds_alternative<Keys>(result) && std::get<Keys>(result) == Keys{key(16)}, "delta.includes_leaf_extra");
    // This intentionally invalid augmentation is not a valid transition. The
    // coverage walker detects the changed leaf; Native augmentation validation
    // remains separately required and must reject the artifact.
  }
  for (unsigned fault = 0; fault != 8; ++fault) {
    unsigned calls = 0;
    td::Ref<vm::Cell> provider = td::make_ref<FaultCell>(original, fault, &calls);
    auto result = delta(original, provider);
    require(calls > 0, "provider.observed");
    if (!fault) {
      require(std::holds_alternative<Keys>(result) && std::get<Keys>(result).empty(), "provider.positive");
    } else {
      require(std::holds_alternative<Failure>(result) && std::get<Failure>(result).disposition == Verdict::LocalUnavailable &&
              std::get<Failure>(result).reason == (fault == 7 ? Reason::AllocationFailure : Reason::MissingContent),
              "provider.local_not_candidate");
    }
  }
  for (unsigned changed : {16, 32, 64, 128, 192, 224}) {
    vm::AugmentedDictionary next(vm::load_cell_slice_ref(original), 256, block::tlb::aug_ShardAccounts);
    put(next, changed, 2); // Metadata-only: the Account body is unchanged.
    auto root = next.get_wrapped_dict_root();
    auto result = delta(original, root);
    require(std::holds_alternative<Keys>(result) && std::get<Keys>(result) == Keys{key(changed)}, "delta.metadata.exact");
    block::WorkchainAccountDictionary a(original), b(root);
    auto native = a.changed_accounts(b, 10);
    require(native.is_ok() && native.ok() == std::get<Keys>(result), "delta.native_oracle");
  }
  auto same = delta(original, original);
  require(std::holds_alternative<Keys>(same) && std::get<Keys>(same).empty(), "delta.unchanged");
  auto unavailable = delta({}, original);
  require(std::holds_alternative<Failure>(unavailable) &&
          std::get<Failure>(unavailable).disposition == Verdict::LocalUnavailable &&
          std::get<Failure>(unavailable).reason == Reason::MissingContent, "delta.old_unavailable");
  auto malformed = vm::CellBuilder().store_long(0, 1).finalize();
  auto invalid = delta(original, malformed);
  require(std::holds_alternative<Failure>(invalid) && std::get<Failure>(invalid).disposition == Verdict::CandidateInvalid &&
          std::get<Failure>(invalid).reason == Reason::Malformed, "delta.received_malformed");
  auto local_invalid = delta(original, malformed, 10, Source::AcquiredView, Object::HostRebuilt);
  require(std::holds_alternative<Failure>(local_invalid) &&
          std::get<Failure>(local_invalid).disposition == Verdict::LocalUnavailable, "delta.rebuilt_malformed");
  block::NativeStateReadMeter exhausted(1, 100000), fresh(100, 100000);
  auto charged = exhausted.load_ordinary(account(99));
  require(std::holds_alternative<td::Ref<vm::CellSlice>>(charged), "budget.precharge_positive");
  auto exceeded = block::rebuild_workchain_account_delta(original, original, policy(), exhausted, fresh,
                                                         Source::ReceivedCandidate, Object::CandidateClaim);
  require(std::holds_alternative<Failure>(exceeded) && std::get<Failure>(exceeded).reason == Reason::BudgetExceeded &&
          std::get<Failure>(exceeded).disposition == Verdict::CandidateInvalid && exhausted.usage().cells == 1,
          "delta.shared_meter_exhausted");
  auto host_exceeded = block::rebuild_workchain_account_delta(original, original, policy(), exhausted, fresh,
                                                              Source::AcquiredView, Object::HostRebuilt);
  require(std::holds_alternative<Failure>(host_exceeded) && std::get<Failure>(host_exceeded).reason == Reason::BudgetExceeded &&
          std::get<Failure>(host_exceeded).disposition == Verdict::LocalUnavailable, "delta.host_budget");
  // Different Patricia-prefix shapes, insertion and removal, independently
  // checked against Native scan_diff rather than only our expected constants.
  for (unsigned mask = 0; mask != 64; ++mask) {
    vm::AugmentedDictionary varied(256, block::tlb::aug_ShardAccounts);
    unsigned i = 0;
    for (unsigned n : {1, 16, 31, 128, 224, 255}) {
      if (mask & (1u << i)) put(varied, n, 2);
      ++i;
    }
    auto root = varied.get_wrapped_dict_root();
    auto result = delta(original, root, 12);
    block::WorkchainAccountDictionary a(original), b(root);
    auto native = a.changed_accounts(b, 12);
    require(native.is_ok() && std::holds_alternative<Keys>(result) && native.ok() == std::get<Keys>(result),
            "delta.prefix_insert_delete_oracle");
  }
  vm::AugmentedDictionary next(vm::load_cell_slice_ref(original), 256, block::tlb::aug_ShardAccounts);
  put(next, 16, 2); put(next, 224, 2);
  auto twice = delta(original, next.get_wrapped_dict_root(), 1);
  require(std::holds_alternative<Failure>(twice) && std::get<Failure>(twice).reason == Reason::KeyBound,
          "delta.bound.before_append");
  auto host_twice = delta(original, next.get_wrapped_dict_root(), 1, Source::AcquiredView, Object::HostRebuilt);
  require(std::holds_alternative<Failure>(host_twice) && std::get<Failure>(host_twice).reason == Reason::KeyBound &&
          std::get<Failure>(host_twice).disposition == Verdict::LocalUnavailable, "delta.host_bound");
  auto exact = delta(original, next.get_wrapped_dict_root());
  require(std::holds_alternative<Keys>(exact) && std::get<Keys>(exact) == Keys{key(16), key(224)}, "delta.later_account");
  auto success = block::compare_workchain_coverage(std::get<Keys>(exact), {key(16), key(224)},
                                                  {key(16), key(224)}, Object::CandidateClaim, Object::CandidateClaim);
  require(!success, "coverage.positive");
  auto d = block::compare_workchain_coverage({key(16)}, {key(16), key(224)}, {key(16), key(224)}, Object::CandidateClaim, Object::CandidateClaim);
  require(d && d->reason == Reason::DeltaMismatch && d->disposition == Verdict::CandidateInvalid, "coverage.delta_isolated");
  auto p = block::compare_workchain_coverage({key(16), key(224)}, {key(16)}, {key(16), key(224)}, Object::CandidateClaim, Object::CandidateClaim);
  require(p && p->reason == Reason::ParticipantMismatch, "coverage.participant_isolated");
  auto pruned = vm::CellBuilder::do_create_pruned_branch(original, 1);
  for (auto source : {Source::ReceivedCandidate, Source::AcquiredView}) {
    auto result = delta(original, pruned, 10, source);
    require(std::holds_alternative<Failure>(result), "delta.pruned.failure");
    auto failure = std::get<Failure>(result);
    require(failure.reason == Reason::ForbiddenPruning && failure.disposition ==
        (source == Source::ReceivedCandidate ? Verdict::CandidateInvalid : Verdict::LocalUnavailable), "delta.pruned.source");
  }
  std::vector<block::WorkchainStorageWrite> writes;
  for (unsigned n : {16, 224}) writes.push_back({key(n), td::Bits256(account(n)->get_hash().bits()),
                                               vm::CellBuilder().store_long(777, 64).finalize()});
  block::SerializeConfig cfg; cfg.global_version = 16; cfg.disable_anycast = true;
  auto overlay = block::build_workchain_storage_overlay(original, 2, 10, 20, key(8), key(9), writes, 10, cfg);
  require(overlay.is_ok(), "fixture.overlay");
  block::NativeStateReadMeter meter(100, 100000);
  auto participants = block::extract_workchain_physical_participants(overlay.ok().account_blocks, policy(), meter,
                                                                     Source::ReceivedCandidate, Object::CandidateClaim);
  require(std::holds_alternative<Keys>(participants) && std::get<Keys>(participants) == Keys{key(16), key(224)},
          "participants.physical_later_account");
  block::NativeStateReadMeter limited(100, 100000);
  auto too_many = block::extract_workchain_physical_participants(overlay.ok().account_blocks, policy(1), limited,
                                                                Source::ReceivedCandidate, Object::CandidateClaim);
  require(std::holds_alternative<Failure>(too_many) && std::get<Failure>(too_many).reason == Reason::KeyBound,
          "participants.bound");
  auto audit = [&](td::Ref<vm::Cell> new_root, Source source, Object object) {
    block::NativeStateReadMeter a(100, 100000), b(100, 100000), c(100, 100000);
    return block::check_workchain_coverage(original, new_root, overlay.ok().account_blocks, {key(16), key(224)},
                                           policy(), a, b, c, source, object, Source::ReceivedCandidate, Object::CandidateClaim);
  };
  auto completed = audit(overlay.ok().accounts, Source::ReceivedCandidate, Object::CandidateClaim);
  require(std::holds_alternative<block::WorkchainCoverageReport>(completed), "final_audit.accepted");
  auto& report = std::get<block::WorkchainCoverageReport>(completed);
  require(report.changed_accounts == Keys{key(16), key(224)} && report.physical_participants == report.changed_accounts,
          "final_audit.independent_readback");
  for (auto block_source : {Source::ReceivedCandidate, Source::AcquiredView}) {
    block::NativeStateReadMeter a(100, 100000), b(100, 100000), c(100, 100000);
    auto bad_blocks = block::check_workchain_coverage(original, overlay.ok().accounts, malformed, {key(16), key(224)},
        policy(), a, b, c, Source::AcquiredView, Object::HostRebuilt, block_source, Object::CandidateClaim);
    require(std::holds_alternative<Failure>(bad_blocks) && std::get<Failure>(bad_blocks).reason == Reason::Malformed &&
            std::get<Failure>(bad_blocks).disposition == Verdict::CandidateInvalid, "final_audit.mixed_ownership");
    block::NativeStateReadMeter d(100, 100000), e(100, 100000), f(100, 100000);
    auto pruned_blocks = vm::CellBuilder::do_create_pruned_branch(overlay.ok().account_blocks, 1);
    auto missing_blocks = block::check_workchain_coverage(original, overlay.ok().accounts, pruned_blocks, {key(16), key(224)},
        policy(), d, e, f, Source::AcquiredView, Object::HostRebuilt, block_source, Object::CandidateClaim);
    require(std::holds_alternative<Failure>(missing_blocks) && std::get<Failure>(missing_blocks).reason == Reason::ForbiddenPruning &&
            std::get<Failure>(missing_blocks).disposition == (block_source == Source::ReceivedCandidate
                ? Verdict::CandidateInvalid : Verdict::LocalUnavailable), "final_audit.mixed_acquisition");
  }
  auto mixed_sets = block::compare_workchain_coverage({key(16), key(224)}, {key(16)}, {key(16), key(224)},
                                                      Object::HostRebuilt, Object::CandidateClaim);
  require(mixed_sets && mixed_sets->reason == Reason::ParticipantMismatch &&
          mixed_sets->disposition == Verdict::CandidateInvalid, "coverage.mixed_set_ownership");
  vm::AugmentedDictionary late(vm::load_cell_slice_ref(overlay.ok().accounts), 256, block::tlb::aug_ShardAccounts);
  put(late, 192, 3);
  for (auto source : {Source::ReceivedCandidate, Source::AcquiredView}) {
    auto rejected = audit(late.get_wrapped_dict_root(), source, Object::CandidateClaim);
    require(std::holds_alternative<Failure>(rejected) && std::get<Failure>(rejected).reason == Reason::DeltaMismatch &&
            std::get<Failure>(rejected).disposition == Verdict::CandidateInvalid, "final_audit.late_mutation");
  }
  auto local = audit(late.get_wrapped_dict_root(), Source::AcquiredView, Object::HostRebuilt);
  require(std::holds_alternative<Failure>(local) && std::get<Failure>(local).reason == Reason::DeltaMismatch &&
          std::get<Failure>(local).disposition == Verdict::LocalUnavailable, "final_audit.local_contract");
  auto order = block::compare_workchain_coverage({key(16), key(224)}, {key(16), key(224)},
                                                 {key(224), key(16)}, Object::CandidateClaim, Object::CandidateClaim);
  require(order && order->reason == Reason::WriteOrder, "coverage.write_order");
  auto allocation = block::coverage_detail::collect([](auto&) { throw std::bad_alloc(); });
  require(std::holds_alternative<Failure>(allocation) && std::get<Failure>(allocation).reason == Reason::AllocationFailure &&
          std::get<Failure>(allocation).disposition == Verdict::LocalUnavailable, "coverage.allocation_failure");
  auto tree = std::make_shared<vm::CellUsageTree>();
  auto tracked = vm::UsageCell::create(original, tree->root_ptr());
  unsigned calls = 0, body_reads = 0;
  vm::CellUsageTree::ScopedReadObserver observer(tree->root_ptr(), [&](const vm::Cell& cell) {
    ++calls;
    if (cell.get_hash() == account(192)->get_hash()) ++body_reads;
  });
  auto blind = delta(tracked, late.get_wrapped_dict_root());
  require(std::holds_alternative<Keys>(blind) && std::get<Keys>(blind) == Keys{key(16), key(192), key(224)} &&
          calls > 0 && body_reads == 0, "delta.blind_write_without_body_read");
  vm::AugmentedDictionary observed(vm::load_cell_slice_ref(tracked), 256, block::tlb::aug_ShardAccounts);
  auto value = observed.lookup(key(192));
  require(value.not_null(), "fixture.observed_account");
  vm::load_cell_slice(value->prefetch_ref());
  require(body_reads > 0, "delta.body_counter_positive");
}
void phases() {
  auto raw = vm::CellBuilder().store_long(42, 64).finalize();
  auto tree = std::make_shared<vm::CellUsageTree>();
  auto tracked = vm::UsageCell::create(raw, tree->root_ptr());
  std::set<vm::CellHash> allowed{raw->get_hash()};
  auto good = block::run_workchain_read_phase(tree->root_ptr(), allowed, [&] {
    vm::load_cell_slice(tracked); vm::load_cell_slice(tracked); return td::Status::OK();
  });
  require(good.reason == block::WorkchainReadPhaseReason::Complete && good.attempts == 2, "phase.positive_repeated");
  auto bad = block::run_workchain_read_phase(tree->root_ptr(), {}, [&] {
    try { vm::load_cell_slice(tracked); } catch (...) {}
    return td::Status::OK();
  });
  require(bad.reason == block::WorkchainReadPhaseReason::OutsideFootprint && bad.attempts == 1, "phase.swallowed_sticky");
  vm::load_cell_slice(tracked); // Observer must have been removed even on failure.
  auto status = block::run_workchain_read_phase(tree->root_ptr(), allowed, [] {
    return td::Status::Error("message-only failure");
  });
  require(status.reason == block::WorkchainReadPhaseReason::CallbackFailure && status.callback_status.is_error(),
          "phase.message_only_error");
  auto missing = block::run_workchain_read_phase({}, allowed, [] { return td::Status::OK(); });
  require(missing.reason == block::WorkchainReadPhaseReason::InvalidContext, "phase.missing_tree");
  auto empty = block::run_workchain_read_phase(tree->root_ptr(), allowed, {});
  require(empty.reason == block::WorkchainReadPhaseReason::InvalidContext, "phase.empty_callback");
  auto exception = block::run_workchain_read_phase(tree->root_ptr(), allowed, []() -> td::Status {
    throw std::runtime_error("test local callback failure");
  });
  require(exception.reason == block::WorkchainReadPhaseReason::ReadException, "phase.exception");
  auto outer_tree = std::make_shared<vm::CellUsageTree>();
  auto nested = vm::UsageCell::create(tracked, outer_tree->root_ptr());
  auto nesting = block::run_workchain_read_phase(outer_tree->root_ptr(), allowed, [&] {
    vm::load_cell_slice(nested); return td::Status::OK();
  });
  require(nesting.reason == block::WorkchainReadPhaseReason::OutsideFootprint, "phase.nested_tree");
}
td::BufferSlice proof(bool observation, std::uint64_t& attempts) {
  attempts = 0;
  // Native proof generation deliberately retains loaded zero-reference cells.
  // Use non-leaves so a missing tracking event must change the proof shape.
  auto left = vm::CellBuilder().store_long(17, 64).store_ref(account(17)).finalize();
  auto right = vm::CellBuilder().store_long(29, 64).store_ref(account(29)).finalize();
  auto root = vm::CellBuilder().store_ref(left).store_ref(right).finalize();
  auto tree = std::make_shared<vm::CellUsageTree>();
  auto tracked = vm::UsageCell::create(root, tree->root_ptr());
  auto read = [&] {
    auto observed = vm::load_cell_slice(tracked);
    auto selected = observed.prefetch_ref(0);
    require(vm::load_cell_slice(selected).prefetch_ulong(64) == 17, "proof.actual_read");
    return td::Status::OK();
  };
  if (observation) {
    auto result = block::run_workchain_read_phase(tree->root_ptr(), {root->get_hash(), left->get_hash()}, read);
    require(result.reason == block::WorkchainReadPhaseReason::Complete, "proof.phase");
    attempts = result.attempts;
  } else {
    require(read().is_ok(), "proof.baseline");
  }
  auto generated = vm::MerkleProof::generate(root, tree.get());
  require(generated.is_ok(), "proof.generate");
  auto bytes = vm::std_boc_serialize(generated.move_as_ok());
  require(bytes.is_ok(), "proof.serialize");
  return bytes.move_as_ok();
}
}
int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "later") {
    vm::AugmentedDictionary old(256, block::tlb::aug_ShardAccounts), next(256, block::tlb::aug_ShardAccounts);
    for (unsigned n : {16, 224}) { put(old, n, 1); put(next, n, 2); }
    auto result = delta(old.get_wrapped_dict_root(), next.get_wrapped_dict_root());
    require(std::holds_alternative<Keys>(result) && std::get<Keys>(result) == Keys{key(16), key(224)}, "delta.later_isolated");
    std::cout << "coverage.later.completed\n";
    return 0;
  }
  require(argc == 1, "driver.arguments");
  deltas(); phases();
  std::uint64_t plain_attempts, observed_attempts;
  auto plain = proof(false, plain_attempts), observed = proof(true, observed_attempts);
  require(plain.as_slice() == observed.as_slice(), "proof.observation_bytes_equal");
  auto parsed = vm::std_boc_deserialize(plain.as_slice());
  require(parsed.is_ok(), "proof.parse");
  auto view = vm::MerkleProof::virtualize(parsed.move_as_ok());
  require(view.is_ok(), "proof.virtualize");
  try {
    auto root = vm::load_cell_slice(view.move_as_ok());
    require(vm::load_cell_slice(root.prefetch_ref(0)).prefetch_ulong(64) == 17, "proof.left_present");
    bool missing_right = false;
    try { vm::load_cell_slice(root.prefetch_ref(1)); } catch (const vm::VmVirtError&) { missing_right = true; }
    require(missing_right, "proof.right_pruned");
  } catch (const vm::VmVirtError&) {
    require(false, "proof.used_path_present");
  }
  // After byte/shape assertions so this check cannot mask the tracking controls.
  require(plain_attempts == 0 && observed_attempts == 2, "proof.observation_count");
  std::cout << "coverage.completed\n";
}
