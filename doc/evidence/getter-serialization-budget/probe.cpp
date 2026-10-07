// Measures how many serialization operations the lite server's result-stack
// serialization spends on the exact result shapes of the elector getter
// participant_list_extended and the config getter list_proposals, and the largest
// list that fits the lite server's budget (validator/impl/liteserver.cpp,
// vm::FakeVmStateLimits fstate(1000)). It runs the production sequence
// Stack::serialize -> finalize_to -> std_boc_serialize. Build with -DBUDGET=<n>
// to change the budget used for the "largest n" lines (default 1000).
#include <iostream>
#include <string>

#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/memo.h"
#include "vm/stack.hpp"
#ifndef BUDGET
#define BUDGET 1000
#endif
#include "vm/cells/CellBuilder.h"
using namespace vm;
static td::RefInt256 big(int i) {
  return td::make_refint(i);
}
// participant_list_extended: (elect_at, elect_close, min_stake, total_stake, l, failed, finished)
// l = cons([id, [stake, max_factor, id, adnl, algorithm_id, key_id]], ...) ; nil terminator
static Ref<Stack> elector_stack(int n, bool u256) {
  StackEntry l{};  // null
  for (int i = n - 1; i >= 0; --i) {
    auto id = u256 ? (td::make_refint(1) << 255) + td::make_refint(i) : big(i + 1);
    auto adnl = u256 ? (td::make_refint(1) << 255) + td::make_refint(i) : big(i + 7);
    auto key = u256 ? (td::make_refint(1) << 255) + td::make_refint(i) : big(i + 9);
    std::vector<StackEntry> inner{
        td::make_refint(11000000000000LL), td::make_refint(196608), id, adnl, td::make_refint(1), key};
    std::vector<StackEntry> pair{id, StackEntry{make_tuple_ref(std::move(inner))}};
    std::vector<StackEntry> cons{StackEntry{make_tuple_ref(std::move(pair))}, std::move(l)};
    l = StackEntry{make_tuple_ref(std::move(cons))};
  }
  auto st = td::make_ref<Stack>();
  auto& s = st.write();
  s.push_smallint(1700000000);
  s.push_smallint(1700000100);
  s.push_int(td::make_refint(10000000000000LL));
  s.push_int(td::make_refint(n * 11000000000000LL));
  s.push(std::move(l));
  s.push_smallint(0);
  s.push_smallint(0);
  return st;
}
// list_proposals: cons([phash, [expires, critical, [param_id, param_val, param_hash], vset_id, voters, weight, rounds, losses, wins]])
static Ref<Stack> proposals_stack_v(int n, int voters) {
  StackEntry l{};
  for (int i = n - 1; i >= 0; --i) {
    StackEntry vl{};
    for (int v = voters - 1; v >= 0; --v) {
      std::vector<StackEntry> c{td::make_refint(v), std::move(vl)};
      vl = StackEntry{make_tuple_ref(std::move(c))};
    }
    std::vector<StackEntry> p3{td::make_refint(100), StackEntry{}, td::make_refint(-1)};
    std::vector<StackEntry> pr{td::make_refint(1900000000),
                               td::make_refint(0),
                               StackEntry{make_tuple_ref(std::move(p3))},
                               td::make_refint(5),
                               vl,
                               td::make_refint(77),
                               td::make_refint(3),
                               td::make_refint(0),
                               td::make_refint(0)};
    std::vector<StackEntry> pair{(td::make_refint(1) << 255) + td::make_refint(i),
                                 StackEntry{make_tuple_ref(std::move(pr))}};
    std::vector<StackEntry> cons{StackEntry{make_tuple_ref(std::move(pair))}, std::move(l)};
    l = StackEntry{make_tuple_ref(std::move(cons))};
  }
  auto st = td::make_ref<Stack>();
  st.write().push(std::move(l));
  return st;
}
struct Counter : vm::VmStateInterface {
  long long ops = 0;
  bool register_op(int u) override {
    ops += u;
    return true;
  }
};
static void count(const char* what, Ref<Stack> st) {
  Counter c;
  vm::VmStateInterface::Guard g(&c);
  CellBuilder cb;
  Ref<Cell> cell;
  bool ok = st->serialize(cb) && cb.finalize_to(cell);
  long long after_ser = c.ops;
  auto r = std_boc_serialize(cell);
  std::cout << what << " serialize_ops=" << after_ser << " total_with_boc=" << c.ops << " ok=" << ok << "\n";
}
static Ref<Stack> proposals_stack(int n) {
  return proposals_stack_v(n, 0);
}
static bool ls_serializes(Ref<Stack> st, size_t* bytes) {
  vm::FakeVmStateLimits fstate(BUDGET);
  vm::VmStateInterface::Guard guard(&fstate);
  CellBuilder cb;
  Ref<Cell> cell;
  try {
    if (!(st->serialize(cb) && cb.finalize_to(cell)))
      return false;
  } catch (...) {
    return false;
  }
  auto r = std_boc_serialize(cell);
  if (r.is_error())
    return false;
  *bytes = r.ok().size();
  return true;
}
int main() {
  for (int n : {1, 2, 76, 77}) {
    std::string w = "elector n=" + std::to_string(n);
    count(w.c_str(), elector_stack(n, true));
  }
  for (int n : {1, 2, 49, 50}) {
    std::string w = "proposals n=" + std::to_string(n);
    count(w.c_str(), proposals_stack(n));
  }
  for (int v : {0, 1, 5, 21}) {
    std::string w = "proposals n=1 voters=" + std::to_string(v);
    count(w.c_str(), proposals_stack_v(1, v));
  }
  for (int v : {21}) {
    int last = -1;
    for (int n = 0; n <= 60; n++) {
      Counter c;
      vm::VmStateInterface::Guard g(&c);
      CellBuilder cb;
      Ref<Cell> cell;
      proposals_stack_v(n, v)->serialize(cb);
      if (c.ops <= 1000)
        last = n;
    }
    std::cout << "largest proposals with 21 voters each within 1000 ops: " << last << "\n";
  }

  for (bool u256 : {false, true}) {
    int last_ok = -1;
    for (int n = 0; n <= 300; n++) {
      size_t b = 0;
      if (ls_serializes(elector_stack(n, u256), &b))
        last_ok = n;
      else
        break;
    }
    std::cout << "participant_list_extended u256=" << u256 << " largest n the liteserver serializes: " << last_ok
              << "\n";
  }
  int last_ok = -1;
  for (int n = 0; n <= 300; n++) {
    size_t b = 0;
    if (ls_serializes(proposals_stack(n), &b))
      last_ok = n;
    else
      break;
  }
  std::cout << "list_proposals (unvoted) largest n: " << last_ok << "\n";
  for (int n : {0, 1, 21, 38, 39, 98, 99, 100, 256}) {
    size_t b = 0;
    bool ok = ls_serializes(elector_stack(n, true), &b);
    std::cout << " n=" << n << " ok=" << ok << " boc_bytes=" << b << " is_list(null)=" << StackEntry{}.is_list()
              << "\n";
  }
}
