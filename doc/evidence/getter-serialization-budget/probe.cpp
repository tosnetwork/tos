// Measures how many serialization operations the lite server's result-stack
// serialization spends on the results of the elector getter participant_list_extended
// and the config getter list_proposals, and the largest list that fits the lite
// server's budget (validator/impl/liteserver.cpp, vm::FakeVmStateLimits fstate(1000)).
// It runs the production sequence Stack::serialize -> finalize_to -> std_boc_serialize.
//
// Two independent sources are measured and must agree:
//   1. Synthetic stacks of the documented shapes, every tuple built directly from its
//      components and its arity asserted.
//   2. The real getters, executed on real contract code and data: the elector's account
//      saved from a running network (its member dictionary re-filled to N entries cloned
//      from a real one), and the genesis configuration contract with proposal sets
//      written by the sandbox exporter.
//
// Usage: probe <elector-dir> <config-dir>. <elector-dir> holds elector-code.boc,
// elector-data.boc and elector-real-dump.txt (the lite client's answer at the same block);
// <config-dir> holds config-code.boc and config-data-<case>.boc from the exporter.
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
#include "vm/memo.h"
#include "vm/stack.hpp"

using namespace vm;

static constexpr int kBudget = 1000;

static void require(bool ok, const std::string& what) {
  if (!ok) {
    std::cerr << "FAILED: " << what << "\n";
    std::exit(1);
  }
}

// --- Shape checks, applied to synthetic and real results alike -------------------

static const std::vector<StackEntry>& tuple_of(const StackEntry& e, size_t arity, const char* what) {
  require(e.is_tuple(), std::string(what) + " is a tuple");
  require(e.as_tuple()->size() == arity,
          std::string(what) + " has arity " + std::to_string(arity) + ", got " + std::to_string(e.as_tuple()->size()));
  // The tuple is kept alive by e.
  return *e.as_tuple().operator->();
}

// Walks a cons list (null-terminated pairs), checking each node, and returns its length.
template <typename F>
static int walk_list(const StackEntry& list, F&& check_head) {
  int n = 0;
  StackEntry cur = list;
  while (!cur.empty()) {
    const auto& cons = tuple_of(cur, 2, "cons cell");
    check_head(cons[0]);
    StackEntry next = cons[1];
    cur = std::move(next);
    ++n;
  }
  return n;
}

static int check_participants(const Stack& st) {
  require(st.depth() == 7, "participant_list_extended returns 7 values");
  for (int i : {0, 1, 3, 4, 5, 6}) {
    require(st[i].is_int(), "scalar result is an integer");
  }
  return walk_list(st[2], [](const StackEntry& head) {
    const auto& pair = tuple_of(head, 2, "[id, entry]");
    require(pair[0].is_int(), "participant id is an integer");
    const auto& inner = tuple_of(pair[1], 6, "[stake, max_factor, id, adnl, algorithm_id, key_id]");
    for (const auto& x : inner) {
      require(x.is_int(), "participant field is an integer");
    }
  });
}

struct ProposalShape {
  int proposals = 0;
  int voters = 0;
};

static ProposalShape check_proposals(const Stack& st) {
  require(st.depth() == 1, "list_proposals returns one value");
  ProposalShape shape;
  shape.proposals = walk_list(st[0], [&](const StackEntry& head) {
    const auto& pair = tuple_of(head, 2, "[phash, proposal]");
    require(pair[0].is_int(), "proposal hash is an integer");
    const auto& pr = tuple_of(pair[1], 9, "unpacked proposal");
    tuple_of(pr[2], 3, "[param_id, param_val, param_hash]");
    shape.voters += walk_list(pr[4], [](const StackEntry& v) { require(v.is_int(), "voter index is an integer"); });
  });
  return shape;
}

// --- Synthetic stacks -------------------------------------------------------------

static StackEntry cons(StackEntry head, StackEntry tail) {
  return StackEntry{std::vector<StackEntry>{std::move(head), std::move(tail)}};
}

static td::RefInt256 u256(int i) {
  return (td::make_refint(1) << 255) + td::make_refint(i);
}

// participant_list_extended: (elect_at, elect_close, min_stake, total_stake, l, failed, finished)
// l = cons([id, [stake, max_factor, id, adnl, algorithm_id, key_id]], ...)
static Ref<Stack> elector_stack(int n) {
  StackEntry l{};
  for (int i = n - 1; i >= 0; --i) {
    StackEntry inner{std::vector<StackEntry>{td::make_refint(11000000000000LL), td::make_refint(196608), u256(i),
                                             u256(i + 7), td::make_refint(1), u256(i + 9)}};
    StackEntry pair{std::vector<StackEntry>{u256(i), std::move(inner)}};
    l = cons(std::move(pair), std::move(l));
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

// list_proposals: cons([phash, [expires, critical, [param_id, param_val, param_hash], vset_id,
//                              voters, weight, rounds, losses, wins]], ...)
static Ref<Stack> proposals_stack(int n, int voters) {
  StackEntry l{};
  for (int i = n - 1; i >= 0; --i) {
    StackEntry vl{};
    for (int v = voters - 1; v >= 0; --v) {
      vl = cons(td::make_refint(v), std::move(vl));
    }
    StackEntry p3{std::vector<StackEntry>{td::make_refint(100), StackEntry{}, StackEntry{}}};
    StackEntry pr{std::vector<StackEntry>{td::make_refint(1900000000), td::make_refint(0), std::move(p3), u256(5),
                                          std::move(vl), td::make_refint(77), td::make_refint(3), td::make_refint(0),
                                          td::make_refint(0)}};
    StackEntry pair{std::vector<StackEntry>{u256(i), std::move(pr)}};
    l = cons(std::move(pair), std::move(l));
  }
  auto st = td::make_ref<Stack>();
  st.write().push(std::move(l));
  return st;
}

// --- Measurement ------------------------------------------------------------------

struct Counter : vm::VmStateInterface {
  long long ops = 0;
  bool register_op(int u) override {
    ops += u;
    return true;
  }
};

struct Cost {
  long long serialize_ops = 0;
  long long with_boc = 0;
};

static Cost cost(const Ref<Stack>& st) {
  Counter c;
  vm::VmStateInterface::Guard g(&c);
  CellBuilder cb;
  Ref<Cell> cell;
  require(st->serialize(cb) && cb.finalize_to(cell), "unlimited serialization succeeds");
  Cost r;
  r.serialize_ops = c.ops;
  require(std_boc_serialize(cell).is_ok(), "boc serialization succeeds");
  r.with_boc = c.ops;
  return r;
}

// The lite server's sequence under its budget.
static bool ls_serializes(const Ref<Stack>& st, long long budget = kBudget) {
  vm::FakeVmStateLimits fstate(budget);
  vm::VmStateInterface::Guard guard(&fstate);
  CellBuilder cb;
  Ref<Cell> cell;
  try {
    if (!(st->serialize(cb) && cb.finalize_to(cell))) {
      return false;
    }
  } catch (...) {
    return false;
  }
  return std_boc_serialize(cell).is_ok();
}

// --- Real getters -----------------------------------------------------------------

static Ref<Cell> load_boc(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  require(f.good(), "open " + path);
  std::stringstream ss;
  ss << f.rdbuf();
  auto r = std_boc_deserialize(ss.str());
  require(r.is_ok(), "deserialize " + path);
  return r.move_as_ok();
}

static constexpr long long kAmpleGas = 1000000000LL;

struct Run {
  Ref<Stack> stack;
  long long gas_used = 0;
};

static Run run_getter(Ref<Cell> code, Ref<Cell> data, const char* method) {
  tos::SmartContract smc({std::move(code), std::move(data)});
  tos::SmartContract::Args args;
  args.set_limits(vm::GasLimits(kAmpleGas, kAmpleGas));
  auto ans = smc.run_get_method(td::Slice(method), std::move(args));
  require(ans.success && ans.code == 0, std::string(method) + " runs (exit " + std::to_string(ans.code) + ")");
  return {ans.stack, ans.gas_used};
}

// The elector's data with its active election's member book replaced by n members, each
// a copy of the first real member under its own key. Only the member book is touched;
// participant_list_extended reads nothing else that depends on it.
static Ref<Cell> elector_data_with(Ref<Cell> data, int n) {
  CellSlice ds = load_cell_slice(data);
  Ref<Cell> elect;
  require(ds.fetch_maybe_ref(elect) && elect.not_null(), "an election is open in the saved data");

  CellSlice es = load_cell_slice(elect);
  CellSlice orig = es;
  require(es.advance(64), "elect_at, elect_close");
  for (int k = 0; k < 2; ++k) {  // min_stake, total_stake (VarUInteger 16)
    unsigned len = static_cast<unsigned>(es.fetch_ulong(4));
    require(es.advance(len * 8), "amount");
  }
  require(es.advance(2), "failed, finished");
  int prefix_bits = static_cast<int>(orig.size() - es.size());
  Ref<Cell> members;
  require(es.fetch_maybe_ref(members) && members.not_null(), "the member book holds a member");

  Dictionary book{members, 256};
  td::BitArray<256> first_key;
  auto first = book.get_minmax_key(first_key.bits(), 256);
  require(first.not_null(), "first member");

  Dictionary grown{256};
  for (int i = 0; i < n; ++i) {
    // Spread keys like real 256-bit ids, so the dictionary has a realistic shape and the
    // getter's gas is representative.
    td::BitArray<256> key;
    std::string seed = "member-" + std::to_string(i);
    digest::hash_str<digest::SHA256>(key.data(), seed.data(), seed.size());
    require(grown.set(key.bits(), 256, first), "insert member");
  }

  CellSlice prefix = orig;
  require(prefix.only_first(prefix_bits, 0), "prefix");
  CellBuilder eb;
  require(eb.append_cellslice_bool(prefix) && eb.store_maybe_ref(grown.get_root_cell()) && eb.append_cellslice_bool(es),
          "rebuild election");
  CellBuilder db;
  require(db.store_maybe_ref(eb.finalize()) && db.append_cellslice_bool(ds), "rebuild data");
  return db.finalize();
}

static std::string squash(std::string s) {
  std::string out;
  bool space = false;
  for (char c : s) {
    if (c == ' ' || c == '\n' || c == '\t') {
      space = true;
      continue;
    }
    if (space && !out.empty()) {
      out += ' ';
    }
    space = false;
    out += c;
  }
  return out;
}

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  require(argc == 3, "usage: probe <elector-dir> <config-dir>");
  std::string dir = argv[1];
  std::string config_dir = argv[2];

  std::cout << "== synthetic, budget " << kBudget << "\n";
  int last_p = -1;
  for (int n = 0; n <= 300; ++n) {
    auto st = elector_stack(n);
    require(check_participants(*st) == n, "synthetic participant count");
    auto c = cost(st);
    require(c.serialize_ops == 10LL * n + 8, "participants cost 10N+8 at N=" + std::to_string(n));
    require(c.with_boc == c.serialize_ops, "boc serialization adds no ops");
    if (ls_serializes(st)) {
      require(last_p == n - 1, "fit is monotone");
      last_p = n;
    }
  }
  std::cout << "participants: ops = 10N+8 for N in 0..300; largest N the lite server serializes: " << last_p << "\n";
  // With the budget out of the way, depth is not what stops serialization.
  require(ls_serializes(elector_stack(300), 1000000000LL), "300 participants serialize under a 10^9 budget");
  require(ls_serializes(proposals_stack(300, 21), 1000000000LL), "300 voted proposals serialize under a 10^9 budget");
  std::cout << "with a 10^9 budget: 300 participants and 300 proposals with 21 voters each serialize\n";

  for (int v : {0, 1, 5, 21}) {
    int last = -1;
    for (int n = 0; n <= 100; ++n) {
      auto st = proposals_stack(n, v);
      auto shape = check_proposals(*st);
      require(shape.proposals == n && shape.voters == n * v, "synthetic proposal shape");
      auto c = cost(st);
      require(c.serialize_ops == 16LL * n + 2LL * n * v + 2, "proposals cost 16P+2V+2");
      require(c.with_boc == c.serialize_ops, "boc serialization adds no ops");
      if (ls_serializes(st)) {
        last = n;
      }
    }
    std::cout << "proposals, " << v << " voters each: ops = 16P+2V+2; largest P: " << last << "\n";
  }

  std::cout << "== real elector getter\n";
  auto ecode = load_boc(dir + "/elector-code.boc");
  auto edata = load_boc(dir + "/elector-data.boc");
  auto saved = run_getter(ecode, edata, "participant_list_extended");
  int saved_n = check_participants(*saved.stack);
  std::ifstream df(dir + "/elector-real-dump.txt");
  std::stringstream dss;
  dss << df.rdbuf();
  std::string lite = squash(dss.str());
  std::ostringstream mine;
  mine << "result: ";
  saved.stack->dump(mine, 3);
  require(squash(mine.str()) == lite, "emulated result equals the lite server's answer at the saved block");
  auto sc = cost(saved.stack);
  require(sc.serialize_ops == 10LL * saved_n + 8, "saved election costs 10N+8");
  std::cout << "saved election: N=" << saved_n << " ops=" << sc.serialize_ops << " gas=" << saved.gas_used
            << " (equals the lite server's own answer)\n";

  int last_real = -1;
  for (int n : {1, 2, 21, 64, 98, 99, 100, 101, 256}) {
    auto run = run_getter(ecode, elector_data_with(edata, n), "participant_list_extended");
    require(check_participants(*run.stack) == n, "real participant count");
    auto c = cost(run.stack);
    require(c.serialize_ops == 10LL * n + 8, "real participants cost 10N+8");
    require(c.serialize_ops == cost(elector_stack(n)).serialize_ops, "real equals synthetic");
    bool fits = ls_serializes(run.stack);
    if (fits) {
      last_real = n;
    }
    std::cout << "real N=" << n << " ops=" << c.serialize_ops << " fits=" << fits << " gas=" << run.gas_used << "\n";
  }
  require(last_real == last_p, "real and synthetic limits agree");

  std::cout << "== real config getter\n";
  auto ccode = load_boc(config_dir + "/config-code.boc");
  struct Case {
    const char* name;
    int proposals;
    int voters_each;
  };
  for (Case k : {Case{"unvoted-0", 0, 0}, Case{"unvoted-1", 1, 0}, Case{"unvoted-2", 2, 0}, Case{"unvoted-61", 61, 0},
                 Case{"unvoted-62", 62, 0}, Case{"unvoted-63", 63, 0}, Case{"valued-1", 1, 0}, Case{"valued-61", 61, 0},
                 Case{"valued-62", 62, 0}, Case{"valued-63", 63, 0}, Case{"voters21-1", 1, 21},
                 Case{"voters21-16", 16, 21}, Case{"voters21-17", 17, 21}, Case{"voters21-18", 18, 21}}) {
    auto run = run_getter(ccode, load_boc(config_dir + "/config-data-" + k.name + ".boc"), "list_proposals");
    auto shape = check_proposals(*run.stack);
    require(shape.proposals == k.proposals && shape.voters == k.proposals * k.voters_each,
            std::string("real proposal shape ") + k.name);
    auto c = cost(run.stack);
    require(c.serialize_ops == 16LL * shape.proposals + 2LL * shape.voters + 2, "real proposals cost 16P+2V+2");
    require(c.serialize_ops == cost(proposals_stack(k.proposals, k.voters_each)).serialize_ops,
            "real equals synthetic");
    std::cout << k.name << " P=" << shape.proposals << " V=" << shape.voters << " ops=" << c.serialize_ops
              << " fits=" << ls_serializes(run.stack) << " gas=" << run.gas_used << "\n";
  }
  std::cout << "ALL CHECKS PASSED\n";
  return 0;
}
