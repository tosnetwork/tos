#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/workchain-block-execution.h"
#include "block/workchain-account-dictionary.h"
#include "block/workchain-storage-overlay.h"
#include "vm/cells/UsageCell.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

namespace {
enum class Failure { Setup = 10, Delta = 40, Finish = 41, Read = 42, Usage = 43, Bytes = 44 };
struct Assertion { Failure id; const char* detail; };
void require(bool value, const char* identity, Failure failure = Failure::Setup) {
  if (!value) throw Assertion{failure, identity};
}
td::Bits256 key(unsigned value) {
  td::Bits256 result = td::Bits256::zero();
  result.bits().store_uint(value, 8);
  return result;
}
td::Ref<vm::Cell> account(unsigned id, unsigned revision) {
  require(revision == 1 || revision == 2, "fixture.revision");
  vm::CellBuilder cell;
  cell.store_long(1, 1).store_long(4, 3).store_long(2, 8).store_bits(key(id).bits(), 256)
      .store_zeroes(42).store_long(revision == 1 ? 2 : 3, 64);
  require(block::CurrencyCollection(td::make_refint(0)).store(cell), "fixture.balance");
  auto data = vm::CellBuilder().store_long(revision, 64).finalize();
  auto executor = block::encode_workchain_executor_state({data, {}, {}}).move_as_ok();
  cell.store_long(1, 1).store_zeroes(3).store_long(1, 1).store_ref(executor).store_long(0, 1);
  auto result = cell.finalize();
  require(block::gen::t_Account.validate_ref(10000, result), "fixture.account");
  return result;
}
void put(vm::AugmentedDictionary& dict, unsigned id, td::Ref<vm::Cell> root, unsigned revision) {
  vm::CellBuilder entry;
  entry.store_ref(root).store_zeroes(256).store_long(revision, 64);
  require(dict.set_builder(key(id), entry), "fixture.put");
}
struct Fixture {
  std::map<unsigned, td::Ref<vm::Cell>> accounts;
  td::Ref<vm::Cell> root;
  Fixture() {
    vm::AugmentedDictionary dict(256, block::tlb::aug_ShardAccounts);
    for (unsigned id : {16u, 32u, 64u, 128u, 192u, 224u}) {
      accounts[id] = account(id, 1);
      put(dict, id, accounts.at(id), 1);
    }
    root = dict.get_wrapped_dict_root();
  }
  std::vector<block::WorkchainAccountRead> reads(std::vector<unsigned> ids) const {
    std::vector<block::WorkchainAccountRead> result;
    for (auto id : ids) {
      auto it = accounts.find(id);
      result.push_back({key(id), it == accounts.end() ? std::nullopt
          : std::optional<td::Bits256>(it->second->get_hash().bits())});
    }
    return result;
  }
};
std::vector<td::Bits256> keys(std::vector<unsigned> ids) {
  std::vector<td::Bits256> result;
  for (auto id : ids) result.push_back(key(id));
  return result;
}
// These keys come from materialized Native AccountBlocks, never from the
// effects/declaration list or the resulting ShardAccounts dictionary.
std::vector<td::Bits256> participants(td::Ref<vm::Cell> root) {
  vm::AugmentedDictionary dict(vm::load_cell_slice_ref(root), 256, block::tlb::aug_ShardAccountBlocks);
  std::vector<td::Bits256> result;
  require(dict.check_for_each_extra([&](td::Ref<vm::CellSlice> value, td::Ref<vm::CellSlice>, td::ConstBitPtr k, int n) {
    require(n == 256, "participant.width");
    auto cell = vm::CellBuilder().append_cellslice(*value).finalize();
    require(block::gen::t_AccountBlock.validate_ref(4096, cell), "participant.native");
    block::gen::AccountBlock::Record record;
    require(tlb::unpack_cell(cell, record) && record.account_addr == k, "participant.binding");
    result.emplace_back(record.account_addr);
    return true;
  }), "participant.decode");
  return result;
}
block::WorkchainStorageOverlay overlay(const Fixture& fixture, td::Ref<vm::Cell> root,
                                       std::vector<unsigned> ids) {
  std::vector<block::WorkchainStorageWrite> writes;
  for (auto id : ids) writes.push_back({key(id), td::Bits256(fixture.accounts.at(id)->get_hash().bits()),
      vm::CellBuilder().store_long(777, 64).finalize()});
  block::SerializeConfig cfg;
  cfg.global_version = 16;
  cfg.disable_anycast = true;
  auto result = block::build_workchain_storage_overlay(root, 2, 10, 20, key(8), key(9), writes, 6, cfg);
  require(result.is_ok(), "overlay.success");
  return result.move_as_ok();
}
void coverage(std::vector<unsigned> changed, std::vector<unsigned> declared,
              std::vector<unsigned> physical, bool accept) {
  Fixture fixture;
  auto actual = overlay(fixture, fixture.root, changed);
  auto physical_result = overlay(fixture, fixture.root, physical);
  block::WorkchainAccountDictionary before(fixture.root), after(actual.accounts);
  auto delta = before.changed_accounts(after, 6);
  require(delta.is_ok(), "delta.status");
  require(delta.ok() == keys(changed), "delta.exact", Failure::Delta);
  auto access_result = block::WorkchainAccountAccess::create(fixture.reads(declared), keys(declared), 6, 6);
  require(access_result.is_ok(), "ledger.create");
  auto access = access_result.move_as_ok();
  for (auto id : declared) {
    require(before.verify_old_read(access, key(id)).is_ok(), "ledger.read");
    require(access.record_write(key(id)).is_ok(), "ledger.write");
  }
  auto observed_participants = participants(physical_result.account_blocks);
  require(observed_participants == keys(physical), "participants.exact");
  require(access.finish(delta.ok(), observed_participants).is_ok() == accept, "finish.verdict", Failure::Finish);
}
void read_binding(unsigned scenario) {
  Fixture f;
  auto declared = f.reads({16, 32, 64});
  if (scenario == 6) declared[1].old_account_hash = key(99);
  if (scenario == 7) declared[1].old_account_hash = std::nullopt;
  if (scenario == 8) declared = f.reads({16, 64});
  auto access = block::WorkchainAccountAccess::create(declared, {}, 6, 6).move_as_ok();
  block::WorkchainAccountDictionary dict(f.root);
  require(dict.verify_old_read(access, key(16)).is_ok(), "read.prerequisite");
  require(dict.verify_old_read(access, key(64)).is_ok(), "read.prerequisite");
  if (scenario == 5) {
    require(access.finish({}, {}).is_error(), "read.unused_declaration", Failure::Read);
  } else if (scenario == 8) {
    require(access.expected_read(key(32)).is_error(), "read.undeclared", Failure::Read);
  } else {
    require(dict.verify_old_read(access, key(32)).is_error(), "read.binding", Failure::Read);
  }
}
void untouched(bool direct_replacement) {
  Fixture f;
  auto tree = std::make_shared<vm::CellUsageTree>();
  auto tracked = vm::UsageCell::create(f.root, tree->root_ptr());
  std::set<unsigned> bodies_read;
  td::Ref<vm::Cell> result;
  {
    vm::CellUsageTree::ScopedReadObserver observer(tree->root_ptr(), [&](const vm::Cell& cell) {
      for (const auto& [id, body] : f.accounts) {
        if (cell.get_hash() == body->get_hash()) bodies_read.insert(id);
      }
    });
    if (direct_replacement) {
      // Counterexample to an unconditional unread-implies-unchanged claim:
      // a persistent dictionary can substitute a reference without loading it.
      vm::AugmentedDictionary dict(vm::load_cell_slice_ref(tracked), 256, block::tlb::aug_ShardAccounts);
      put(dict, 128, account(128, 2), 2);
      result = dict.get_wrapped_dict_root();
    } else {
      result = overlay(f, tracked, {16, 64}).accounts;
    }
  }
  if (direct_replacement) {
    require(bodies_read.count(128) == 0, "usage.unread_replacement", Failure::Usage);
    block::WorkchainAccountDictionary before(f.root), after(result);
    require(before.changed_accounts(after, 6).move_as_ok() == keys({128}), "usage.counterexample", Failure::Delta);
    return;
  }
  require(bodies_read == std::set<unsigned>({16, 64}), "usage.exact_bodies", Failure::Usage);
  // Fixed small-fixture byte audit is an oracle, not a proposed full-shard
  // traversal in the production verifier. It happens after tracking is stopped.
  vm::AugmentedDictionary old(vm::load_cell_slice_ref(f.root), 256, block::tlb::aug_ShardAccounts);
  vm::AugmentedDictionary next(vm::load_cell_slice_ref(result), 256, block::tlb::aug_ShardAccounts);
  for (auto id : {32u, 128u, 192u, 224u}) {
    auto old_cell = vm::CellBuilder().append_cellslice(*old.lookup(key(id))).finalize();
    auto new_cell = vm::CellBuilder().append_cellslice(*next.lookup(key(id))).finalize();
    auto old_bytes = vm::std_boc_serialize(old_cell).move_as_ok();
    auto new_bytes = vm::std_boc_serialize(new_cell).move_as_ok();
    require(old_bytes.as_slice() == new_bytes.as_slice(), "untouched.bytes", Failure::Bytes);
  }
}
void absence(bool honest) {
  Fixture f;
  auto reads = f.reads({16, 96});
  if (!honest) reads[1].old_account_hash = key(99);
  auto access = block::WorkchainAccountAccess::create(reads, {}, 6, 6).move_as_ok();
  block::WorkchainAccountDictionary dict(f.root);
  require(dict.verify_old_read(access, key(16)).is_ok(), "absence.prerequisite");
  require(dict.verify_old_read(access, key(96)).is_ok() == honest, "absence.binding", Failure::Read);
  if (honest) require(access.finish({}, {}).is_ok(), "absence.finish");
}
void dictionary_delta(unsigned scenario) {
  Fixture f;
  vm::AugmentedDictionary dict(vm::load_cell_slice_ref(f.root), 256, block::tlb::aug_ShardAccounts);
  unsigned id = 128;
  if (scenario == 13) {
    // Metadata alone changes the ShardAccount while retaining its account root.
    put(dict, id, f.accounts.at(id), 2);
  } else if (scenario == 14) {
    require(dict.lookup_delete(key(id)).not_null(), "delta.delete");
  } else {
    id = 96;
    put(dict, id, account(id, 1), 1);
  }
  block::WorkchainAccountDictionary before(f.root), after(dict.get_wrapped_dict_root());
  auto changed = before.changed_accounts(after, 6);
  require(changed.is_ok() && changed.ok() == keys({id}), "delta.kind", Failure::Delta);
}
void run(unsigned scenario) {
  switch (scenario) {
    case 0: coverage({16, 64}, {16, 64}, {16, 64}, true); break;
    case 1: coverage({16}, {16, 64}, {16, 64}, false); break;
    case 2: coverage({16, 64, 128}, {16, 64}, {16, 64}, false); break;
    case 3: coverage({16, 64}, {16, 64}, {16}, false); break;
    case 4: coverage({16, 64}, {16, 64}, {16, 64, 128}, false); break;
    case 5: case 6: case 7: case 8: read_binding(scenario); break;
    case 9: untouched(false); break;
    case 10: untouched(true); break;
    case 11: absence(true); break;
    case 12: absence(false); break;
    case 13: case 14: case 15: dictionary_delta(scenario); break;
    default: require(false, "unknown.scenario");
  }
}
}
int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_FATAL);
  try {
    if (argc == 2) run(static_cast<unsigned>(std::stoul(argv[1])));
    else for (unsigned i = 0; i <= 15; ++i) run(i);
    std::cout << "PASS I13 acceptance cases\n";
    return 0;
  } catch (const Assertion& failure) {
    std::cerr << "assertion_id=" << static_cast<int>(failure.id) << " detail=" << failure.detail << '\n';
    return static_cast<int>(failure.id);
  } catch (const vm::VmError& error) { std::cerr << error.get_msg() << "\n"; return 2; }
  catch (const std::exception& error) { std::cerr << error.what() << "\n"; return 2; }
  catch (...) { std::cerr << "Unexpected exception\n"; return 2; }
}
