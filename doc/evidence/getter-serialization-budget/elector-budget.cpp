// Measures the gas of the three elector getters a combined elector-state read runs —
// participant_list_extended, past_elections and compute_returned_stake — and the native
// work of flattening past_elections' frozen dictionaries, on the elector code and data
// saved from the local development network (elector-snapshot/).
//
// The saved state is grown along each dimension the getters walk: the open election's
// member book (N members), the retained past elections (K elections, each with F frozen
// entries, cloned from the saved past election's first frozen entry under hashed keys),
// and the credits dictionary (C credits). Each case is checked for shape before its
// numbers are printed.
//
// Usage: elector-budget <elector-dir>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "crypto/common/bitstring.h"
#include "crypto/openssl/digest.hpp"
#include "smc-envelope/SmartContract.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"
#include "vm/stack.hpp"

using namespace vm;

static void require(bool ok, const std::string& what) {
  if (!ok) {
    std::cerr << "FAILED: " << what << "\n";
    std::exit(1);
  }
}

static Ref<Cell> load_boc(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  require(f.good(), "open " + path);
  std::stringstream ss;
  ss << f.rdbuf();
  auto r = std_boc_deserialize(ss.str());
  require(r.is_ok(), "deserialize " + path);
  return r.move_as_ok();
}

static td::BitArray<256> hashed_key(const std::string& tag, int i) {
  td::BitArray<256> key;
  std::string seed = tag + std::to_string(i);
  digest::hash_str<digest::SHA256>(key.data(), seed.data(), seed.size());
  return key;
}

// A dictionary of n entries, each `value` under its own hashed 256-bit key.
static Ref<Cell> filled(Ref<CellSlice> value, const std::string& tag, int n) {
  Dictionary d{256};
  for (int i = 0; i < n; ++i) {
    auto key = hashed_key(tag, i);
    require(d.set(key.bits(), 256, value), "insert");
  }
  return d.get_root_cell();
}

static Ref<CellSlice> first_value(Ref<Cell> root, int key_bits) {
  require(root.not_null(), "dictionary is not empty");
  Dictionary d{root, key_bits};
  td::BitArray<256> key;
  auto v = d.get_minmax_key(key.bits(), key_bits);
  require(v.not_null(), "first entry");
  return v;
}

static int vm_amount_skip(CellSlice& cs) {
  unsigned len = static_cast<unsigned>(cs.fetch_ulong(4));
  require(cs.advance(len * 8), "amount");
  return 0;
}

struct Elector {
  Ref<Cell> elect;  // maybe null
  Ref<Cell> credits;
  Ref<Cell> past;
  Ref<CellSlice> rest;
};

static Elector split(Ref<Cell> data) {
  CellSlice ds = load_cell_slice(data);
  Elector e;
  require(ds.fetch_maybe_ref(e.elect) && ds.fetch_maybe_ref(e.credits) && ds.fetch_maybe_ref(e.past), "data layout");
  e.rest = td::make_ref<CellSlice>(ds);
  return e;
}

static Ref<Cell> join(const Elector& e) {
  CellBuilder b;
  require(b.store_maybe_ref(e.elect) && b.store_maybe_ref(e.credits) && b.store_maybe_ref(e.past) &&
              b.append_cellslice_bool(*e.rest),
          "rebuild data");
  return b.finalize();
}

// The open election with its member book replaced by n copies of its first member.
enum class Book { Hashed, Deepest, DeepestMaxStake };

// i ones followed by zeros: keys 0..n-1 form one path of n levels, the deepest a
// 256-bit-key dictionary allows.
static td::BitArray<256> chain_key(int i) {
  td::BitArray<256> key;
  key.set_zero();
  for (int b = 0; b < i; ++b) {
    key[b] = true;
  }
  return key;
}

// The member record with its stake (the record's only variable-width field) set to the
// largest Coins value, 2^120 - 1.
static Ref<CellSlice> with_max_stake(Ref<CellSlice> member) {
  CellSlice ms = *member;
  vm_amount_skip(ms);
  CellBuilder b;
  require(b.store_long_bool(15, 4), "stake length");
  for (int k = 0; k < 15; ++k) {
    require(b.store_long_bool(0xff, 8), "stake byte");
  }
  require(b.append_cellslice_bool(ms), "rest of the member");
  return load_cell_slice_ref(b.finalize());
}

static Ref<Cell> book_of(Ref<CellSlice> member, Book shape, int n) {
  if (shape == Book::Hashed) {
    return filled(member, "member-", n);
  }
  require(n <= 257, "a 256-bit key path holds at most 257 keys");
  auto value = shape == Book::DeepestMaxStake ? with_max_stake(member) : member;
  Dictionary d{256};
  for (int i = 0; i < n; ++i) {
    auto key = chain_key(i);
    require(d.set(key.bits(), 256, value), "insert member");
  }
  return d.get_root_cell();
}

static Ref<Cell> grow_members(Ref<Cell> elect, int n, Book shape) {
  CellSlice es = load_cell_slice(elect);
  CellSlice orig = es;
  require(es.advance(64), "elect_at, elect_close");
  vm_amount_skip(es);
  vm_amount_skip(es);
  require(es.advance(2), "failed, finished");
  int prefix_bits = static_cast<int>(orig.size() - es.size());
  Ref<Cell> members;
  require(es.fetch_maybe_ref(members), "member book");
  auto member = first_value(members, 256);
  CellSlice prefix = orig;
  require(prefix.only_first(prefix_bits, 0), "prefix");
  CellBuilder b;
  require(
      b.append_cellslice_bool(prefix) && b.store_maybe_ref(book_of(member, shape, n)) && b.append_cellslice_bool(es),
      "rebuild election");
  return b.finalize();
}

// k past elections, each the saved past election with f frozen entries; election ids
// are the saved id minus 1..k so they stay distinct and ordered.
static Ref<Cell> grow_past(Ref<Cell> past, int k, int f) {
  require(past.not_null(), "the saved state holds a past election");
  Dictionary saved{past, 32};
  td::BitArray<32> id_bits;
  auto entry = saved.get_minmax_key(id_bits.bits(), 32);
  require(entry.not_null(), "past election");
  unsigned long long saved_id = id_bits.bits().get_uint(32);

  CellSlice ps = *entry;
  CellSlice orig = ps;
  require(ps.advance(32 + 32 + 256), "unfreeze_at, stake_held, vset_hash");
  int prefix_bits = static_cast<int>(orig.size() - ps.size());
  Ref<Cell> frozen;
  require(ps.fetch_maybe_ref(frozen), "frozen dictionary");
  auto frozen_entry = first_value(frozen, 256);
  Ref<Cell> grown_frozen = filled(frozen_entry, "frozen-", f);
  CellSlice prefix = orig;
  require(prefix.only_first(prefix_bits, 0), "prefix");
  CellBuilder eb;
  require(eb.append_cellslice_bool(prefix) && eb.store_maybe_ref(grown_frozen) && eb.append_cellslice_bool(ps),
          "rebuild past election");
  auto value = load_cell_slice_ref(eb.finalize());

  Dictionary out{32};
  for (int i = 1; i <= k; ++i) {
    td::BitArray<32> key;
    key.bits().store_uint(saved_id - static_cast<unsigned long long>(i), 32);
    require(out.set(key.bits(), 32, value), "insert past election");
  }
  return out.get_root_cell();
}

static Ref<Cell> grow_credits(int c) {
  CellBuilder vb;
  require(vb.store_long_bool(5, 4) && vb.store_long_bool(1000000000LL, 40), "credit amount");
  return filled(load_cell_slice_ref(vb.finalize()), "credit-", c);
}

// The deepest credits dictionary 256-bit keys allow: key i is i ones followed by zeros, so
// the all-ones key sits at the end of a 256-level path.
static Ref<Cell> deepest_credits() {
  CellBuilder vb;
  require(vb.store_long_bool(5, 4) && vb.store_long_bool(1000000000LL, 40), "credit amount");
  auto value = load_cell_slice_ref(vb.finalize());
  Dictionary d{256};
  for (int i = 0; i <= 256; ++i) {
    td::BitArray<256> key;
    key.set_zero();
    for (int b = 0; b < i; ++b) {
      key[b] = true;
    }
    require(d.set(key.bits(), 256, value), "insert");
  }
  return d.get_root_cell();
}

static constexpr long long kAmpleGas = 1000000000LL;

static tos::SmartContract::Answer run(Ref<Cell> code, Ref<Cell> data, const char* method, Ref<Stack> args) {
  tos::SmartContract smc({std::move(code), std::move(data)});
  tos::SmartContract::Args a;
  a.set_limits(vm::GasLimits(kAmpleGas, kAmpleGas));
  a.set_stack(std::move(args));
  auto ans = smc.run_get_method(td::Slice(method), std::move(a));
  require(ans.success && ans.code == 0, std::string(method) + " runs (exit " + std::to_string(ans.code) + ")");
  return ans;
}

static Ref<Stack> no_args() {
  return td::make_ref<Stack>();
}

static Ref<Stack> wallet_arg(const td::BitArray<256>& wallet) {
  auto st = td::make_ref<Stack>();
  td::RefInt256 x{true};
  require(x.write().import_bits(wallet.cbits(), 256, false), "wallet as an integer");
  st.write().push_int(std::move(x));
  return st;
}

// Walks past_elections' result the way a native flattening would: the cons list, then
// each frozen dictionary entry by entry. Returns {elections, frozen entries}.
static std::pair<int, long long> flatten(const Stack& st) {
  require(st.depth() == 1, "past_elections returns one value");
  int elections = 0;
  long long frozen = 0;
  StackEntry cur = st[0];
  while (!cur.empty()) {
    require(cur.is_tuple() && cur.as_tuple()->size() == 2, "cons cell");
    StackEntry head = cur.as_tuple()->at(0);
    StackEntry next = cur.as_tuple()->at(1);
    require(head.is_tuple() && head.as_tuple()->size() == 8, "[id, 7 fields]");
    StackEntry dict = head.as_tuple()->at(4);
    if (!dict.empty()) {
      require(dict.is_cell(), "frozen dictionary is a cell");
      Dictionary d{dict.as_cell(), 256};
      bool ok = d.check_for_each([&](Ref<CellSlice> v, td::ConstBitPtr, int) {
        CellSlice s = *v;
        require(s.advance(256 + 64), "owner, weight");
        vm_amount_skip(s);
        require(s.advance(1) && s.empty_ext(), "banned, end");
        ++frozen;
        return true;
      });
      require(ok, "frozen dictionary walk");
    }
    ++elections;
    cur = std::move(next);
  }
  return {elections, frozen};
}

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  require(argc == 2, "usage: elector-budget <elector-dir>");
  std::string dir = argv[1];
  auto code = load_boc(dir + "/elector-code.boc");
  auto saved = split(load_boc(dir + "/elector-data.boc"));
  require(saved.elect.not_null(), "the saved state has an open election");

  std::cout << "== participant_list_extended (N members)\n";
  const char* names[] = {"hashed keys", "deepest path", "deepest path, maximum stake"};
  for (Book shape : {Book::Hashed, Book::Deepest, Book::DeepestMaxStake}) {
    for (int n : {0, 21, 99, 256}) {
      Elector e = saved;
      e.elect = grow_members(saved.elect, n, shape);
      auto ans = run(code, join(e), "participant_list_extended", no_args());
      const Stack& st = *ans.stack;
      require(st.depth() == 7, "participant_list_extended returns 7 values");
      int count = 0;
      StackEntry cur = st[2];
      while (!cur.empty()) {
        require(cur.is_tuple() && cur.as_tuple()->size() == 2, "cons cell");
        StackEntry head = cur.as_tuple()->at(0);
        StackEntry next = cur.as_tuple()->at(1);
        require(head.is_tuple() && head.as_tuple()->size() == 2, "[id, entry]");
        StackEntry inner = head.as_tuple()->at(1);
        require(inner.is_tuple() && inner.as_tuple()->size() == 6, "6-field participant");
        if (shape == Book::DeepestMaxStake) {
          auto max = (td::make_refint(1) << 120) - td::make_refint(1);
          require(td::cmp(inner.as_tuple()->at(0).as_int(), max) == 0, "maximum stake returned");
        }
        ++count;
        cur = std::move(next);
      }
      require(count == n, "participant count");
      std::cout << names[static_cast<int>(shape)] << " N=" << n << " gas=" << ans.gas_used << "\n";
    }
  }

  std::cout << "== past_elections (K elections x F frozen entries)\n";
  for (int k : {1, 2, 8, 16}) {
    for (int f : {21, 256}) {
      Elector e = saved;
      e.past = grow_past(saved.past, k, f);
      auto ans = run(code, join(e), "past_elections", no_args());
      auto t0 = std::chrono::steady_clock::now();
      auto [elections, frozen] = flatten(*ans.stack);
      auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
      require(elections == k && frozen == 1LL * k * f, "past_elections shape");
      std::cout << "K=" << k << " F=" << f << " gas=" << ans.gas_used << " frozen_entries=" << frozen
                << " native_flatten_us=" << us << "\n";
    }
  }

  std::cout << "== compute_returned_stake (C credits)\n";
  for (int c : {0, 1, 256, 4096, 65536}) {
    Elector e = saved;
    e.credits = c ? grow_credits(c) : Ref<Cell>{};
    auto data = join(e);
    auto present = run(code, data, "compute_returned_stake", wallet_arg(hashed_key("credit-", 0)));
    auto absent = run(code, data, "compute_returned_stake", wallet_arg(hashed_key("absent-", 0)));
    require(present.stack->depth() == 1 && present.stack->at(0).is_int(), "returned stake is an integer");
    long long expect = c ? 1000000000LL : 0;
    require(present.stack->at(0).as_int()->to_long() == expect, "credited wallet's amount");
    require(absent.stack->at(0).as_int()->to_long() == 0, "absent wallet owed nothing");
    std::cout << "C=" << c << " gas_present=" << present.gas_used << " gas_absent=" << absent.gas_used << "\n";
  }
  {
    Elector e = saved;
    e.credits = deepest_credits();
    td::BitArray<256> all_ones;
    all_ones.set_ones();
    auto deep = run(code, join(e), "compute_returned_stake", wallet_arg(all_ones));
    require(deep.stack->at(0).as_int()->to_long() == 1000000000LL, "deepest credit found");
    std::cout << "deepest path (257 credits, 256 levels) gas=" << deep.gas_used << "\n";
  }
  std::cout << "ALL CHECKS PASSED\n";
  return 0;
}
