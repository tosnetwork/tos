// Isolated dictionary experiment. Page vectors are not Native accounts, a
// coordinator schema, authenticated partition proofs or a CellDb transaction.
#include "uno/core/nullifier-state.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/transaction.h"
#include "vm/boc.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <vector>

namespace {
using uno_workchain::UsedNullifiers;
using uno_workchain::NullifierState;
using Key = td::Bits256;
using Pages = std::vector<UsedNullifiers>;
using Clock = std::chrono::steady_clock;

void require(bool value, const char* reason) {
  if (!value) throw std::runtime_error(reason);
}
std::uint64_t add(std::uint64_t left, std::uint64_t right) {
  if (right > std::numeric_limits<std::uint64_t>::max() - left) throw std::runtime_error("counter overflow");
  return left + right;
}
std::uint64_t number(const char* value) {
  std::uint64_t result = 0;
  require(*value != 0, "empty integer");
  for (; *value; ++value) {
    require(*value >= '0' && *value <= '9', "invalid integer");
    require(result <= std::numeric_limits<std::uint64_t>::max() / 10, "integer overflow");
    result = add(result * 10, static_cast<unsigned>(*value - '0'));
  }
  return result;
}
template <class T> T take(td::Result<T> result) {
  if (result.is_error()) throw std::runtime_error(result.move_as_error().to_string());
  return result.move_as_ok();
}
std::size_t route(const Key& key, std::size_t pages) {
  require(pages == 1 || pages == 16 || pages == 32, "unsupported experimental page count");
  if (pages == 1) return 0;
  return static_cast<unsigned char>(key.as_slice()[0]) >> (pages == 16 ? 4 : 3);
}
std::uint64_t count(const Pages& pages) {
  std::uint64_t result = 0;
  for (const auto& page : pages) result = add(result, page.size());
  return result;
}
using Claimed = std::vector<std::pair<Key, std::size_t>>;
td::Result<Pages> apply(const Pages& original, const Claimed& batch, std::uint64_t entry_limit) {
  const auto before = count(original);
  if (before > entry_limit || batch.size() > entry_limit - before) return td::Status::Error("entry budget");
  Pages next = original;
  for (const auto& [key, claimed] : batch) {
    if (claimed != route(key, original.size())) return td::Status::Error("wrong experimental page");
    if (claimed >= next.size()) return td::Status::Error("page outside vector");
    TRY_RESULT(updated, next[claimed].with_used({key}));
    next[claimed] = std::move(updated);
  }
  return next;
}
Claimed claim(const std::vector<Key>& keys, std::size_t pages) {
  Claimed result;
  for (const auto& key : keys) result.emplace_back(key, route(key, pages));
  return result;
}
Pages build(const std::vector<Key>& keys, std::size_t pages) {
  std::vector<std::vector<Key>> grouped(pages);
  for (const auto& key : keys) grouped[route(key, pages)].push_back(key);
  Pages result;
  for (const auto& group : grouped) result.push_back(take(UsedNullifiers{}.with_used(group)));
  return result;
}
std::vector<Key> keys(std::uint64_t seed, std::uint64_t size, bool concentrated) {
  require(size <= 1000000, "experiment entry bound");
  std::mt19937_64 random(seed);
  std::vector<Key> result;
  std::set<Key> distinct;
  while (result.size() < size) {
    Key key = Key::zero();
    for (auto& byte : key.as_slice()) byte = static_cast<char>(random() & 255);
    if (concentrated) {
      for (unsigned i = 0; i < 16; ++i) key.as_slice()[i] = 0;
    }
    if (distinct.insert(key).second) result.push_back(key);
  }
  return result;
}
bool same(const Pages& left, const Pages& right) {
  if (left.size() != right.size()) return false;
  for (std::size_t i = 0; i < left.size(); ++i) {
    if (left[i].size() != right[i].size()) return false;
    if (left[i].root().is_null() != right[i].root().is_null()) return false;
    if (left[i].root().not_null() && left[i].root()->get_hash() != right[i].root()->get_hash()) return false;
  }
  return true;
}
struct Metrics {
  std::uint64_t cells = 0, bits = 0;
  std::set<vm::CellHash> hashes;
};
Metrics metrics(const Pages& pages) {
  Metrics result;
  std::vector<td::Ref<vm::Cell>> pending;
  for (const auto& page : pages) if (page.root().not_null()) pending.push_back(page.root());
  while (!pending.empty()) {
    auto cell = std::move(pending.back());
    pending.pop_back();
    if (!result.hashes.insert(cell->get_hash()).second) continue;
    auto data = take(cell->load_cell()).data_cell;
    require(data.not_null() && !data->is_special(), "unexpected measurement cell");
    result.cells = add(result.cells, 1);
    result.bits = add(result.bits, data->get_bits());
    for (unsigned i = 0; i < data->get_refs_cnt(); ++i) pending.push_back(data->get_ref(i));
  }
  return result;
}

struct Envelopes {
  td::Ref<vm::Cell> accounts;
  std::uint64_t max_data_cells = 0, max_data_bits = 0, max_data_depth = 0;
  std::uint64_t account_count = 0;
};
Envelopes native_envelopes(const Pages& pages) {
  Envelopes result;
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  for (std::size_t i = 0; i < pages.size(); ++i) {
    require(i < 256, "experimental account address bound");
    auto address = Key::zero();
    address.as_slice()[31] = static_cast<char>(i);
    auto data = pages[i].root().is_null() ? vm::CellBuilder().finalize() : pages[i].root();
    vm::CellStorageStat stat;
    (void)take(stat.compute_used_storage(data));
    result.max_data_cells = std::max<std::uint64_t>(result.max_data_cells, stat.cells);
    result.max_data_bits = std::max<std::uint64_t>(result.max_data_bits, stat.bits);
    result.max_data_depth = std::max<std::uint64_t>(result.max_data_depth, data->get_depth());
    // Structurally valid Native Account only. No code, participant transaction,
    // executor wrapper, actual storage-charge calculation or coordinator schema.
    vm::CellBuilder account;
    account.store_long(1,1).store_long(4,3).store_long(2,8).store_bits(address.bits(),256)
        .store_zeroes(42).store_long(2,64);
    require(block::CurrencyCollection(0).store(account), "account balance encoding");
    account.store_long(1,1).store_zeroes(3).store_long(1,1).store_ref(data).store_long(0,1);
    auto root = account.finalize();
    require(block::gen::t_Account.validate_ref(1000000, root), "Native Account structure");
    vm::CellBuilder entry;
    entry.store_ref(root).store_zeroes(256).store_long(1,64);
    require(accounts.set_builder(address, entry), "unique account dictionary entry");
    result.account_count = add(result.account_count, 1);
  }
  result.accounts = accounts.get_wrapped_dict_root();
  return result;
}
bool data_fits(const Envelopes& envelopes, std::uint64_t cells) {
  return envelopes.max_data_cells <= cells;
}
void envelope_self_test() {
  auto input = keys(45, 4, false);
  auto original = build(input,16);
  auto envelopes = native_envelopes(original);
  require(envelopes.account_count == 16, "Native envelope omitted pages");
  require(envelopes.max_data_cells > 0, "Native data count missing");
  require(data_fits(envelopes, envelopes.max_data_cells), "exact data-cell bound rejected");
  // max_data_cells > 0 above guarantees this subtraction cannot underflow.
  require(!data_fits(envelopes, envelopes.max_data_cells - 1), "data-cell bound ignored");
  vm::AugmentedDictionary restored(vm::load_cell_slice_ref(envelopes.accounts),256,block::tlb::aug_ShardAccounts);
  for (std::size_t i = 0; i < original.size(); ++i) {
    auto address = Key::zero();
    address.as_slice()[31] = static_cast<char>(i);
    block::Account account(2, address.bits());
    require(account.unpack(restored.lookup(address),10,false), "Native account dictionary lost a page");
    auto expected = original[i].root().is_null() ? vm::CellBuilder().finalize() : original[i].root();
    require(account.data.not_null() && account.data->get_hash() == expected->get_hash(),
            "Native account data differs from its assigned page");
  }
  auto roundtrip = take(vm::std_boc_deserialize(take(vm::std_boc_serialize(envelopes.accounts)).as_slice()));
  require(roundtrip->get_hash() == envelopes.accounts->get_hash(), "Native account dictionary roundtrip");
  std::cout << "Native envelope self-test passed\n";
}
std::uint64_t rss() {
  rusage usage{};
  require(getrusage(RUSAGE_SELF, &usage) == 0 && usage.ru_maxrss >= 0, "RSS unavailable");
  return static_cast<std::uint64_t>(usage.ru_maxrss);
}
struct Run {
  std::string mode, scenario;
  std::uint64_t seed = 45, entries = 0, samples = 3;
  template <class F> void phase(std::uint64_t sample, const char* name, const Pages& shape, F operation) const {
    const auto start = Clock::now();
    operation();
    const auto elapsed = std::chrono::duration<double, std::micro>(Clock::now() - start).count();
    std::cout << mode << ',' << scenario << ',' << seed << ',' << entries << ',' << sample << ',' << name << ','
              << shape.size() << ',' << count(shape) << ',' << elapsed << ',' << rss() << '\n';
  }
};

void self_test() {
  envelope_self_test();
  auto input = keys(45, 4, false);
  Pages original = build({input[0]}, 16);
  const auto saved = original;
  auto exact = apply(original, claim({input[1], input[2]}, 16), 3);
  require(exact.is_ok() && count(exact.ok()) == 3, "exact budget did not apply");
  auto over = apply(original, claim({input[1], input[2]}, 16), 2);
  require(over.is_error(), "one-entry-over budget accepted");
  require(same(original, saved), "budget rejection mutated source");
  // The same fresh nullifier is claimed on two different pages. Without the
  // canonical route check, both dictionaries independently accept it.
  const auto owner = route(input[1], 16);
  const auto other = owner ^ 1u;
  auto wrong = apply(original, {{input[1], owner}, {input[1], other}}, 3);
  require(wrong.is_error(), "cross-page duplicate accepted");
  require(same(original, saved), "late wrong page mutated source");
  require(take(original[route(input[0], 16)].try_contains(input[0])), "original history lost");
  auto replay = apply(original, claim({input[1], input[0]}, 16), 3);
  require(replay.is_error() && same(original, saved), "late spent key mutated source");
  bool overflow = false;
  try { (void)add(std::numeric_limits<std::uint64_t>::max(), 1); }
  catch (const std::runtime_error&) { overflow = true; }
  require(overflow, "unchecked metric overflow");
  std::cout << "self-test passed: budget, routing, duplicate, atomic roots, checked counters\n";
}

void measure(const Run& run) {
  require(run.mode == "single" || run.mode == "pages16", "unknown mode");
  require(run.scenario == "idle" || run.scenario == "insert" || run.scenario == "prefix" ||
          run.scenario == "split" || run.scenario == "duplicate" || run.scenario == "refund", "unknown scenario");
  const bool concentrated = run.scenario == "prefix";
  auto all = keys(run.seed, add(run.entries, 2), concentrated);
  std::vector<Key> history(all.begin(), all.begin() + run.entries);
  std::vector<Key> fresh(all.begin() + run.entries, all.end());
  const auto page_count = run.mode == "single" ? 1u : 16u;
  Pages original = build(history, page_count);
  require(count(original) == run.entries, "construction count mismatch");
  const auto base_metrics = metrics(original);
  std::cout << "mode,scenario,seed,history_entries,sample,phase,pages,result_entries,wall_us,process_highwater_rss_kib\n";
  for (std::uint64_t sample = 0; sample < run.samples; sample = add(sample, 1)) {
    Pages loaded;
    run.phase(sample, "load_full", original, [&] {
      for (const auto& page : original) loaded.push_back(take(UsedNullifiers::from_root(page.root(), page.size())));
    });
    require(same(original, loaded), "full validation changed roots");
    run.phase(sample, "lookup_history", original, [&] {
      if (!history.empty()) {
        require(take(loaded[route(history.front(), page_count)].try_contains(history.front())), "history missing");
        require(take(loaded[route(history.back(), page_count)].try_contains(history.back())), "history tail missing");
      }
    });
    run.phase(sample, "incremental_absence", original, [&] {
      for (const auto& key : fresh) require(!take(loaded[route(key, page_count)].try_contains(key)), "fresh key used");
    });
    Pages next = loaded;
    if (run.scenario == "split") {
      run.phase(sample, "split_rebuild", next, [&] {
        next = build(history, run.mode == "single" ? 1 : 32);
      });
      require(count(next) == run.entries, "split lost entries");
      for (const auto& key : history) require(take(next[route(key, next.size())].try_contains(key)), "split lost key");
    } else if (run.scenario == "duplicate") {
      run.phase(sample, "reject_duplicate", original, [&] {
        Claimed batch = claim({fresh[0], fresh[0]}, page_count);
        if (page_count > 1) batch.back().second ^= 1u;
        auto result = apply(original, batch, add(run.entries, 2));
        require(result.is_error() && same(next, original), "duplicate did not leave roots unchanged");
      });
    } else if (run.scenario != "idle" && run.scenario != "refund") {
      run.phase(sample, "update_two", next, [&] { next = take(apply(loaded, claim(fresh, page_count), add(run.entries, 2))); });
      require(count(next) == add(run.entries, 2), "update count mismatch");
    }
    if (run.scenario == "refund") {
      // One owner ID across independent in-memory page primitives. No Native
      // prepare, reserve funds, terminal receipt, fee or atomic host commit.
      std::vector<NullifierState> states;
      for (const auto& page : loaded) states.push_back(take(NullifierState::from_roots(page.root(), {}, {}, {page.size(), 0, 0, 0})));
      std::map<std::size_t, std::vector<Key>> manifests;
      for (const auto& key : fresh) manifests[route(key, page_count)].push_back(key);
      Key owner = Key::zero();
      run.phase(sample, "reserve_primitive", original, [&] {
        for (const auto& [index, manifest] : manifests) states[index] = take(states[index].reserve(owner, manifest));
      });
      for (const auto& key : fresh) require(take(states[route(key, page_count)].try_is_reserved(key)), "reserve missing");
      run.phase(sample, "refund_primitive", original, [&] {
        for (const auto& [index, manifest] : manifests) states[index] = take(states[index].refund(owner));
      });
      for (const auto& key : fresh) {
        require(take(states[route(key, page_count)].try_is_used(key)), "refund did not consume");
        require(!take(states[route(key, page_count)].try_is_reserved(key)), "refund reservation remains");
      }
      // Serialization below remains used-set-only, not full settlement state.
      next.clear();
      for (const auto& state : states) next.push_back(take(UsedNullifiers::from_root(state.used_root(), state.used_count())));
    }
    std::vector<td::BufferSlice> bytes;
    std::uint64_t byte_count = 0;
    run.phase(sample, "serialize_all_pages", next, [&] {
      for (const auto& page : next) {
        auto encoded = page.root().is_null() ? td::BufferSlice{} : take(vm::std_boc_serialize(page.root()));
        byte_count = add(byte_count, encoded.size());
        bytes.push_back(std::move(encoded));
      }
    });
    std::uint64_t touched_bytes = 0;
    run.phase(sample, "serialize_changed_pages", next, [&] {
      for (std::size_t i = 0; i < next.size(); ++i) {
        const bool changed = next.size() != original.size() || !same(Pages{next[i]}, Pages{original[i]});
        if (changed && next[i].root().not_null()) touched_bytes = add(touched_bytes, take(vm::std_boc_serialize(next[i].root())).size());
      }
    });
    std::vector<td::Ref<vm::Cell>> roots;
    run.phase(sample, "deserialize_new_arena", next, [&] {
      for (const auto& encoded : bytes) roots.push_back(encoded.empty() ? td::Ref<vm::Cell>{} : take(vm::std_boc_deserialize(encoded.as_slice())));
    });
    Pages restored;
    run.phase(sample, "new_arena_full_validate", next, [&] {
      for (std::size_t i = 0; i < roots.size(); ++i) restored.push_back(take(UsedNullifiers::from_root(roots[i], next[i].size())));
    });
    require(same(restored, next) && same(original, loaded), "roundtrip or immutable input mismatch");
    Metrics after;
    run.phase(sample, "metrics_scan", next, [&] { after = metrics(next); });
    std::uint64_t introduced = 0;
    for (const auto& hash : after.hashes) if (!base_metrics.hashes.count(hash)) introduced = add(introduced, 1);
    std::cerr << "metrics mode=" << run.mode << " scenario=" << run.scenario << " seed=" << run.seed
              << " entries=" << run.entries << " sample=" << sample << " cells=" << after.cells
              << " bits=" << after.bits << " all_page_boc_bytes=" << byte_count << " changed_page_boc_bytes=" << touched_bytes
              << " new_unique_cells=" << introduced << " max_depth=";
    unsigned depth = 0;
    for (const auto& page : next) if (page.root().not_null()) depth = std::max<unsigned>(depth, page.root()->get_depth());
    std::cerr << depth << '\n';
    Envelopes envelopes;
    run.phase(sample, "native_account_envelopes", next, [&] { envelopes = native_envelopes(next); });
    vm::CellStorageStat account_stat;
    (void)take(account_stat.compute_used_storage(envelopes.accounts));
    td::BufferSlice account_boc;
    run.phase(sample, "native_account_dictionary_boc", next, [&] {
      account_boc = take(vm::std_boc_serialize(envelopes.accounts));
    });
    std::cerr << "native_envelopes mode=" << run.mode << " scenario=" << run.scenario
              << " entries=" << run.entries << " sample=" << sample << " accounts=" << envelopes.account_count
              << " max_data_cells=" << envelopes.max_data_cells << " max_data_bits=" << envelopes.max_data_bits
              << " max_data_depth=" << envelopes.max_data_depth << " data_fits_65536=" << data_fits(envelopes,65536)
              << " dictionary_cells=" << account_stat.cells << " dictionary_bits=" << account_stat.bits
              << " dictionary_depth=" << envelopes.accounts->get_depth() << " dictionary_boc_bytes=" << account_boc.size()
              << '\n';
  }
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--self-test") { self_test(); return 0; }
    require(argc == 6, "usage: measure-partition-state single|pages16 idle|insert|prefix|split|duplicate|refund entries samples seed");
    Run run{argv[1], argv[2], number(argv[5]), number(argv[3]), number(argv[4])};
    require(run.samples >= 1 && run.samples <= 100, "samples outside experiment bound");
    measure(run);
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "measurement failed: " << error.what() << '\n';
  } catch (vm::VmError&) {
    std::cerr << "measurement failed: VM cell exception\n";
  } catch (vm::VmVirtError&) {
    std::cerr << "measurement failed: virtualized state\n";
  } catch (vm::VmNoGas&) {
    std::cerr << "measurement failed: VM budget\n";
  } catch (vm::CellBuilder::CellCreateError&) {
    std::cerr << "measurement failed: Cell construction\n";
  } catch (vm::CellBuilder::CellWriteError&) {
    std::cerr << "measurement failed: Cell capacity\n";
  }
  return 1;
}
