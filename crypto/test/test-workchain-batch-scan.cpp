#include "block/workchain-batch-scan.h"
#include "vm/cells/CellBuilder.h"
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {
using Reason = block::WorkchainBatchScanReason;
using Disposition = block::WorkchainBatchScanDisposition;
using Source = block::WorkchainBatchScanSource;
template <class Root>
concept HasImplicitScanSource = requires(Root root, const block::ResolvedBatchInputPolicy& policy) {
  block::scan_workchain_batch_account_blocks(root, policy, 1);
};
static_assert(!HasImplicitScanSource<td::Ref<vm::Cell>>, "source.must_be_explicit");
void require(bool value, const char* identity) {
  if (!value) { std::cerr << identity << '\n'; std::exit(1); }
}
td::Bits256 key(unsigned n) {
  auto result = td::Bits256::zero();
  result.bits().store_uint(n, 8);
  return result;
}
td::Ref<vm::Cell> payload(unsigned n) {
  return vm::CellBuilder().store_long(n, 32).finalize();
}
td::Ref<vm::Cell> pruned_payload(td::Ref<vm::Cell> root) {
  auto pruned = vm::CellBuilder::do_create_pruned_branch(root, 1);
  require(pruned->special_type() == vm::Cell::SpecialType::PrunnedBranch &&
          pruned->get_hash(0) == root->get_hash(0), "fixture.actual_pruned_same_commitment");
  return pruned;
}
td::Ref<vm::Cell> replace_ref(td::Ref<vm::Cell> root, unsigned index, td::Ref<vm::Cell> replacement) {
  auto cs = vm::load_cell_slice(root);
  vm::CellBuilder out;
  out.store_bits(cs.data_bits(), cs.size());
  for (unsigned i = 0; i < cs.size_refs(); ++i) out.store_ref(i == index ? replacement : cs.prefetch_ref(i));
  return out.finalize();
}
block::ResolvedBatchInputPolicy policy(unsigned writes) {
  // Scanner-only fixture: preserve the former zero proof/transfer budgets;
  // explicitly supply the new wire thresholds without implying execution.
  block::WorkchainResourcePolicy p{4, {100, 100000, 3, 7, writes, 9},
      {100, 100000, 50, 50000, 32}, {0, 100, 100000, 100, 100000, 0}, {1, 32, 64}, 7};
  auto resolved = block::ResolvedBatchInputPolicy::from_resolved_fields(p, {{}, false, 0, 0, 1, 4});
  require(std::holds_alternative<block::ResolvedBatchInputPolicy>(resolved), "fixture.policy");
  return std::get<block::ResolvedBatchInputPolicy>(resolved);
}
struct Item {
  unsigned account; unsigned batch; unsigned tag; unsigned index;
  unsigned binding_account = 0;
  bool wrong_input = false;
  bool pruned_input = false;
  bool pruned_effects = false;
  bool extra_transaction = false;
  bool pruned_descendant = false;
  bool exotic_input = false;
  bool exotic_effects = false;
  unsigned block_account = 0;
  unsigned transaction_account = 0;
  unsigned transaction_lt = 0;
};
struct Allocations { unsigned calls = 0; bool fail = false; };
template <class T> struct CountAllocator {
  using value_type = T;
  Allocations* state;
  explicit CountAllocator(Allocations& value) : state(&value) {}
  template <class U> CountAllocator(const CountAllocator<U>& other) : state(other.state) {}
  T* allocate(std::size_t n) { ++state->calls; if (state->fail) throw std::bad_alloc(); return std::allocator<T>{}.allocate(n); }
  void deallocate(T* p, std::size_t n) { std::allocator<T>{}.deallocate(p, n); }
  template <class U> bool operator==(const CountAllocator<U>& other) const { return state == other.state; }
};
td::Ref<vm::Cell> transaction(Item item, unsigned lt = 1) {
  const auto input = item.exotic_input ? vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true) :
      (item.pruned_descendant ? vm::CellBuilder().store_ref(payload(item.batch)).finalize() : payload(item.batch));
  if (item.pruned_descendant) {
    const auto view = replace_ref(input, 0, pruned_payload(payload(item.batch)));
    bool special = false;
    vm::load_cell_slice_special(view, special);
    require(!special && view->get_level() > 0 &&
            view->get_hash() != view->get_hash(0), "fixture.ordinary_parent_nonzero_level");
  }
  const auto effects = item.exotic_effects ? vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true) :
      payload(item.batch + 100);
  block::gen::UnoV2HostRecord::Record record{
      input->get_hash().bits(), effects->get_hash().bits(), key(item.binding_account ? item.binding_account : item.account),
      item.index};
  vm::CellBuilder binding;
  require(block::gen::t_UnoV2HostRecord.pack(binding, record), "fixture.binding");
  vm::CellBuilder desc;
  desc.store_long(item.tag, 4).store_ref(binding.finalize());
  if (item.tag == 12) {
    // create_pruned_branch deliberately retains loaded leaves; force an actual
    // pruned cell here so this is not an ordinary-root acceptance test in disguise.
    desc.store_ref(item.pruned_input ? pruned_payload(input) :
                   (item.wrong_input ? payload(999) :
                    (item.pruned_descendant ? replace_ref(input, 0, pruned_payload(payload(item.batch))) : input)));
    desc.store_ref(item.pruned_effects ? pruned_payload(effects) : effects);
  }
  const auto update = vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize();
  vm::CellBuilder tx;
  tx.store_long(7, 4).store_bits(key(item.transaction_account ? item.transaction_account : item.account).bits(), 256)
      .store_long(item.transaction_lt ? item.transaction_lt : lt, 64).store_zeroes(371)
      .store_ref(vm::CellBuilder().store_zeroes(2).finalize()).store_zeroes(5)
      .store_ref(update).store_ref(desc.finalize());
  return tx.finalize();
}
td::Ref<vm::Cell> blocks(const std::vector<Item>& items) {
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccountBlocks);
  for (auto item : items) {
    vm::AugmentedDictionary txs(64, block::tlb::aug_AccountTransactions);
    require(txs.set_ref(td::BitArray<64>{1}, transaction(item)), "fixture.transaction_insert");
    if (item.extra_transaction) require(txs.set_ref(td::BitArray<64>{2}, transaction(item, 2)), "fixture.extra_transaction");
    vm::CellBuilder account;
    account.store_long(5, 4).store_bits(key(item.block_account ? item.block_account : item.account).bits(), 256);
    require(account.append_cellslice_bool(vm::load_cell_slice(txs.get_root_cell())), "fixture.transaction_dictionary");
    account.store_ref(vm::CellBuilder().store_long(0x72, 8).store_zeroes(512).finalize());
    require(accounts.set_builder(key(item.account), account), "fixture.account_insert");
  }
  return accounts.get_wrapped_dict_root();
}
void check(bool later_only) {
  const auto p = policy(3);
  if (later_only) {
    auto two = blocks({{1, 10, 12, 0}, {2, 20, 10, 1}});
    auto later = block::scan_workchain_batch_account_blocks(two, p, 1, Source::ReceivedCandidate);
    require(later.accounts_seen == 2 && later.distinct_batches == 2, "scan.second_account_observed");
    require(later.disposition == Disposition::CandidateInvalid && later.reason == Reason::CountMismatch,
            "scan.second_account_rejected");
    return;
  }
  auto legal = blocks({{1, 10, 12, 0}, {2, 10, 10, 1}, {3, 10, 11, 2}});
  auto ok = block::scan_workchain_batch_account_blocks(legal, p, 1, Source::ReceivedCandidate);
  require(ok.disposition == Disposition::Accepted && ok.reason == Reason::None, "legal.accepted");
  require(ok.scan_complete && ok.accounts_seen == 3 && ok.records_seen == 3 && ok.distinct_batches == 1 && ok.entries_seen == 1,
          "legal.complete_distinct_count");
  require(ok.identity.has_value() && ok.identity->input_hash == payload(10)->get_hash().bits() &&
          ok.identity->effects_hash == payload(110)->get_hash().bits(), "legal.identity_readback");
  auto wrong = block::scan_workchain_batch_account_blocks(legal, p, 2, Source::ReceivedCandidate);
  require(wrong.disposition == Disposition::CandidateInvalid && wrong.reason == Reason::CountMismatch,
          "count.independent_mismatch");
  require(!wrong.identity.has_value(), "rejection.no_published_identity");
  auto two = blocks({{1, 10, 12, 0}, {2, 20, 10, 1}});
  auto unique = block::scan_workchain_batch_account_blocks(two, p, 2, Source::ReceivedCandidate);
  require(unique.disposition == Disposition::CandidateInvalid && unique.reason == Reason::BatchMultiplicity,
          "identity.truthful_two_count");
  auto later = block::scan_workchain_batch_account_blocks(two, p, 1, Source::ReceivedCandidate);
  require(later.accounts_seen == 2 && later.distinct_batches == 2, "scan.second_account_observed");
  require(later.disposition == Disposition::CandidateInvalid && later.reason == Reason::CountMismatch,
          "scan.second_account_rejected");
  auto bounded = block::scan_workchain_batch_account_blocks(legal, policy(2), 1, Source::ReceivedCandidate);
  require(bounded.disposition == Disposition::CandidateInvalid && bounded.reason == Reason::AccountBound &&
          bounded.accounts_seen == 2 && bounded.records_seen == 2, "bound.authenticated_not_allocation");
  require(!bounded.scan_complete && bounded.distinct_batches == 1 && !bounded.identity,
          "bound.partial_count_is_not_complete");
  Allocations allocations;
  block::batch_scan_detail::Scanner<CountAllocator<block::WorkchainBatchIdentity>> scan{
      policy(1), Source::ReceivedCandidate, CountAllocator<block::WorkchainBatchIdentity>{allocations}};
  auto over = scan.run(two, 2);
  require(over.disposition == Disposition::CandidateInvalid && over.reason == Reason::AccountBound,
          "bound.before_new_identity");
  require(allocations.calls == 1, "bound.one_positive_allocation_no_second_allocation");
  allocations.fail = true;
  auto allocation = block::batch_scan_detail::run(legal, p, 1, Source::ReceivedCandidate, CountAllocator<block::WorkchainBatchIdentity>{allocations});
  require(allocation.disposition == Disposition::LocalUnavailable && allocation.reason == Reason::AllocationFailure &&
          !allocation.identity && !allocation.scan_complete, "allocation.not_candidate_bound");
  auto missing = block::scan_workchain_batch_account_blocks({}, p, 1, Source::AcquiredView);
  require(missing.disposition == Disposition::LocalUnavailable && missing.reason == Reason::MissingContent,
          "missing.local_not_candidate");
  auto malformed = block::scan_workchain_batch_account_blocks(payload(0), p, 1, Source::ReceivedCandidate);
  require(malformed.disposition == Disposition::CandidateInvalid && malformed.reason == Reason::Malformed,
          "malformed.candidate_not_local");
  auto pruned = vm::CellBuilder::create_pruned_branch(two, 1);
  auto unavailable = block::scan_workchain_batch_account_blocks(pruned, p, 1, Source::AcquiredView);
  require(unavailable.disposition == Disposition::LocalUnavailable && unavailable.reason == Reason::MissingContent,
          "pruned.local_not_candidate");
  require(pruned->get_level() > 0, "fixture.nonzero_level");
  auto candidate_pruned = block::scan_workchain_batch_account_blocks(pruned, p, 1, Source::ReceivedCandidate);
  require(candidate_pruned.disposition == Disposition::CandidateInvalid &&
          candidate_pruned.reason == Reason::ForbiddenPrunedRepresentation,
          "pruned.same_cell_candidate_source");
  const auto ordinary = payload(10);
  require(ordinary->get_level() == 0 && ordinary->get_hash() == ordinary->get_hash(0),
          "commitment.ordinary_accessors_equal");
  Item descendant{1, 10, 12, 0};
  descendant.pruned_descendant = true;
  const auto descendant_blocks = blocks({descendant});
  auto candidate_level = block::scan_workchain_batch_account_blocks(descendant_blocks, p, 1, Source::ReceivedCandidate);
  require(candidate_level.disposition == Disposition::CandidateInvalid &&
          candidate_level.reason == Reason::ForbiddenPrunedRepresentation,
          "level.same_cell_candidate_not_commitment");
  auto local_level = block::scan_workchain_batch_account_blocks(descendant_blocks, p, 1, Source::AcquiredView);
  require(local_level.disposition == Disposition::LocalUnavailable && local_level.reason == Reason::MissingContent,
          "level.same_cell_local_not_commitment");
  const auto dictionary = vm::load_cell_slice(two).prefetch_ref();
  const auto right = vm::load_cell_slice(dictionary).prefetch_ref(1);
  auto missing_right = replace_ref(two, 0, replace_ref(dictionary, 1, vm::CellBuilder::create_pruned_branch(right, 1)));
  auto incomplete = block::scan_workchain_batch_account_blocks(missing_right, p, 1, Source::AcquiredView);
  require(incomplete.accounts_seen == 1 && incomplete.disposition == Disposition::LocalUnavailable &&
          incomplete.reason == Reason::MissingContent, "scan.later_pruned_not_early_acceptance");
  auto incomplete_count = block::scan_workchain_batch_account_blocks(missing_right, p, 2, Source::AcquiredView);
  require(!incomplete_count.scan_complete && incomplete_count.distinct_batches == 1 &&
          incomplete_count.disposition == Disposition::LocalUnavailable &&
          incomplete_count.reason == Reason::MissingContent, "scan.partial_count_never_compared");
  auto no_entry = block::scan_workchain_batch_account_blocks(blocks({{1, 10, 10, 0}}), p, 1, Source::ReceivedCandidate);
  require(no_entry.disposition == Disposition::CandidateInvalid && no_entry.reason == Reason::EntryMultiplicity,
          "entry.required");
  auto entries = block::scan_workchain_batch_account_blocks(blocks({{1, 10, 12, 0}, {2, 10, 12, 1}}), p, 1, Source::ReceivedCandidate);
  require(entries.disposition == Disposition::CandidateInvalid && entries.reason == Reason::EntryMultiplicity,
          "entry.exactly_one");
  auto empty = block::scan_workchain_batch_account_blocks(blocks({}), p, 0, Source::ReceivedCandidate);
  require(empty.disposition == Disposition::CandidateInvalid && empty.reason == Reason::BatchMultiplicity,
          "identity.nonempty");
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  auto exotic = block::scan_workchain_batch_account_blocks(library, p, 1, Source::ReceivedCandidate);
  require(exotic.disposition == Disposition::CandidateInvalid && exotic.reason == Reason::Malformed,
          "available_exotic.not_missing_content");
  auto binding = block::scan_workchain_batch_account_blocks(blocks({{1, 10, 12, 0, 2}}), p, 1, Source::ReceivedCandidate);
  require(binding.disposition == Disposition::CandidateInvalid && binding.reason == Reason::ParticipantBinding,
          "binding.account_position");
  auto commitment = block::scan_workchain_batch_account_blocks(blocks({{1, 10, 12, 0, 0, true}}), p, 1, Source::ReceivedCandidate);
  require(commitment.disposition == Disposition::CandidateInvalid && commitment.reason == Reason::EntryCommitment,
          "binding.entry_actual_roots");
  // Available level-zero special roots isolate loading from the independent
  // level guard. Omitting a load must not be masked by rejecting nonzero level.
  Item special_input{1, 10, 12, 0};
  special_input.exotic_input = true;
  auto input_exotic = block::scan_workchain_batch_account_blocks(blocks({special_input}), p, 1, Source::ReceivedCandidate);
  require(input_exotic.disposition == Disposition::CandidateInvalid && input_exotic.reason == Reason::Malformed,
          "binding.available_input_must_be_loaded");
  Item special_effects{1, 10, 12, 0};
  special_effects.exotic_effects = true;
  auto effects_exotic = block::scan_workchain_batch_account_blocks(blocks({special_effects}), p, 1, Source::ReceivedCandidate);
  require(effects_exotic.disposition == Disposition::CandidateInvalid && effects_exotic.reason == Reason::Malformed,
          "binding.available_effects_must_be_loaded");
  auto pruned_input = block::scan_workchain_batch_account_blocks(blocks({{1, 10, 12, 0, 0, false, true}}), p, 1, Source::AcquiredView);
  require(pruned_input.disposition == Disposition::LocalUnavailable && pruned_input.reason == Reason::MissingContent &&
          !pruned_input.scan_complete && !pruned_input.identity, "binding.pruned_input_is_unavailable");
  auto pruned_effects = block::scan_workchain_batch_account_blocks(blocks({{1, 10, 12, 0, 0, false, false, true}}), p, 1, Source::AcquiredView);
  require(pruned_effects.disposition == Disposition::LocalUnavailable && pruned_effects.reason == Reason::MissingContent &&
          !pruned_effects.scan_complete && !pruned_effects.identity, "binding.pruned_effects_is_unavailable");
  Item extra{2, 10, 10, 1};
  extra.extra_transaction = true;
  auto repeated = block::scan_workchain_batch_account_blocks(blocks({{1, 10, 12, 0}, extra}), p, 1, Source::ReceivedCandidate);
  require(repeated.disposition == Disposition::CandidateInvalid && repeated.reason == Reason::RecordMultiplicity,
          "record.one_per_account");
  Item account_address{1, 10, 12, 0};
  account_address.block_account = 2;
  auto bad_account = block::scan_workchain_batch_account_blocks(blocks({account_address}), p, 1, Source::ReceivedCandidate);
  require(bad_account.disposition == Disposition::CandidateInvalid && bad_account.reason == Reason::Malformed,
          "framing.account_address");
  Item transaction_address{1, 10, 12, 0};
  transaction_address.transaction_account = 2;
  auto bad_transaction = block::scan_workchain_batch_account_blocks(blocks({transaction_address}), p, 1, Source::ReceivedCandidate);
  require(bad_transaction.disposition == Disposition::CandidateInvalid && bad_transaction.reason == Reason::Malformed,
          "framing.transaction_address");
  Item transaction_lt{1, 10, 12, 0};
  transaction_lt.transaction_lt = 2;
  auto bad_lt = block::scan_workchain_batch_account_blocks(blocks({transaction_lt}), p, 1, Source::ReceivedCandidate);
  require(bad_lt.disposition == Disposition::CandidateInvalid && bad_lt.reason == Reason::Malformed,
          "framing.transaction_lt");
}
}  // namespace
int main(int argc, char** argv) {
  require(argc == 1 || (argc == 2 && std::string(argv[1]) == "--later-only"), "arguments.known_case");
  check(argc == 2);
  std::cout << "batch-scan.completed\n";
}
