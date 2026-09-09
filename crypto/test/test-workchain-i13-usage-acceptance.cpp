// Reuse the exact reviewed fixture and overlay helpers without editing their
// source or running the earlier executable's main function.
#define main i13_coverage_fixture_main
#include "crypto/test/test-workchain-i13-acceptance.cpp"
#undef main

namespace {
struct UsageAssertion { int id; };
void usage_require(bool value, int id) {
  if (!value) throw UsageAssertion{id};
}
// Pruning is deliberately constructed by this test to check non-dependence on
// unused bodies. This establishes no production VmVirtError classification:
// forbidden candidate pruned structure is CandidateInvalid, whereas missing
// authenticated local state is LocalUnavailable. Source, not exception type
// alone, determines that classification.
void partial_state(unsigned scenario) {
  Fixture f;
  const std::vector<std::vector<unsigned>> pairs{{16, 128}, {32, 192}, {64, 224}};
  usage_require(scenario < pairs.size(), 50);
  const auto& selected = pairs[scenario];
  vm::MerkleProofBuilder proof_builder(f.root);
  auto complete = overlay(f, proof_builder.root(), selected);
  // Fixture-only proof shaping: expose all six dictionary entries, but do not
  // load the four unused account bodies. This lets the test distinguish an
  // unavailable account body from an unavailable dictionary path. This bounded
  // fixture preparation is not a proposed production full-shard traversal.
  vm::AugmentedDictionary metadata(vm::load_cell_slice_ref(proof_builder.root()), 256,
                                    block::tlb::aug_ShardAccounts);
  for (const auto& [id, cell] : f.accounts) usage_require(metadata.lookup(key(id)).not_null(), 50);
  auto proof = proof_builder.extract_proof().move_as_ok();
  auto partial = vm::MerkleProof::virtualize(proof).move_as_ok();
  usage_require(partial->get_hash() == f.root->get_hash(), 50);
  vm::AugmentedDictionary pruned(vm::load_cell_slice_ref(partial), 256, block::tlb::aug_ShardAccounts);
  std::vector<td::Ref<vm::Cell>> unavailable;
  for (const auto& [id, cell] : f.accounts) {
    block::tlb::ShardAccount::Record entry;
    usage_require(entry.unpack(pruned.lookup(key(id))), 50);
    usage_require(entry.account->get_hash() == cell->get_hash(), 50);
    bool body_unavailable = false;
    try { auto loaded = vm::load_cell_slice(entry.account); (void)loaded; }
    catch (const vm::VmVirtError& error) {
      usage_require(error.get_errno() == static_cast<int>(vm::Excno::virt_err) && error.virtualization == 1, 57);
      body_unavailable = true;
    }
    const bool participating = std::binary_search(selected.begin(), selected.end(), id);
    usage_require(body_unavailable == !participating, 51);
    if (body_unavailable) unavailable.push_back(entry.account);
  }
  usage_require(unavailable.size() == 4, 51);
  auto usage = std::make_shared<vm::CellUsageTree>();
  auto tracked_partial = vm::UsageCell::create(partial, usage->root_ptr());
  std::set<unsigned> observed;
  block::WorkchainStorageOverlay limited;
  try {
    vm::CellUsageTree::ScopedReadObserver observer(usage->root_ptr(), [&](const vm::Cell& cell) {
      for (const auto& [id, body] : f.accounts) {
        if (cell.get_hash() == body->get_hash()) observed.insert(id);
      }
    });
    limited = overlay(f, tracked_partial, selected);
  } catch (const vm::VmVirtError& error) {
    usage_require(error.get_errno() == static_cast<int>(vm::Excno::virt_err) && error.virtualization == 1, 57);
    std::cerr << "native_errno=" << error.get_errno() << " virtualization=" << error.virtualization << '\n';
    throw UsageAssertion{52};
  }
  usage_require(observed == std::set<unsigned>(selected.begin(), selected.end()), 53);
  block::WorkchainAccountDictionary before(partial), after(limited.accounts);
  auto changed = before.changed_accounts(after, 6).move_as_ok();
  usage_require(changed == keys(selected), 54);
  usage_require(participants(limited.account_blocks) == keys(selected), 54);
  usage_require(limited.accounts->get_hash() == complete.accounts->get_hash(), 55);
  usage_require(limited.account_blocks->get_hash() == complete.account_blocks->get_hash(), 58);
  auto full_blocks = vm::std_boc_serialize(complete.account_blocks).move_as_ok();
  auto partial_blocks = vm::std_boc_serialize(limited.account_blocks).move_as_ok();
  usage_require(full_blocks.as_slice() == partial_blocks.as_slice(), 59);
  // Old-body content is unavailable, yet unchanged references remain bound to
  // their old hashes in the returned dictionary. Case 9 of the earlier unit
  // supplies the separate full-content byte oracle for untouched entries.
  vm::AugmentedDictionary next(vm::load_cell_slice_ref(limited.accounts), 256, block::tlb::aug_ShardAccounts);
  for (const auto& [id, cell] : f.accounts) {
    if (std::binary_search(selected.begin(), selected.end(), id)) continue;
    block::tlb::ShardAccount::Record entry;
    usage_require(entry.unpack(next.lookup(key(id))), 50);
    usage_require(entry.account->get_hash() == cell->get_hash(), 56);
    bool still_unavailable = false;
    try { auto loaded = vm::load_cell_slice(entry.account); (void)loaded; }
    catch (const vm::VmVirtError& error) {
      usage_require(error.get_errno() == static_cast<int>(vm::Excno::virt_err) && error.virtualization == 1, 57);
      still_unavailable = true;
    }
    usage_require(still_unavailable, 56);
  }
  std::cout << "case=" << scenario << " available_bodies=2 pruned_bodies=4 pruned_errno=14 virtualization=1\n";
}
}
int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_FATAL);
  try {
    if (argc == 2) partial_state(static_cast<unsigned>(std::stoul(argv[1])));
    else for (unsigned i = 0; i < 3; ++i) partial_state(i);
    std::cout << "PASS I13 partial-state cases\n";
    return 0;
  } catch (const UsageAssertion& failure) {
    std::cerr << "assertion_id=" << failure.id << '\n';
    return failure.id;
  } catch (const Assertion& failure) {
    std::cerr << "fixture_assertion_id=" << static_cast<int>(failure.id) << '\n';
    return 10;
  } catch (...) { std::cerr << "Unexpected native exception\n"; return 2; }
}
