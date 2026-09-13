#include "validator/auth/native-history.h"

#include "owner-fixture.h"
using namespace p0_owner_fixture;
namespace {
Hash file_hash(const Bytes& bytes) {
  Hash out{};
  check(crypto_hash_sha256(out.data(), bytes.data(), bytes.size()) == 0, "fixture-file-hash");
  return out;
}
struct Entry {
  std::uint32_t index, sequence;
  Hash root, file;
};
td::Ref<vm::Cell> history_state(td::Ref<vm::Cell> base, std::uint32_t sequence, const std::vector<Entry>& entries) {
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  check(tlb::unpack_cell(base, state) && tlb::unpack_cell(state.custom->prefetch_ref(), extra),
        "history-fixture-state");
  vm::AugmentedDictionary dict(32, block::tlb::aug_OldMcBlocksInfo);
  for (const auto& entry : entries) {
    vm::CellBuilder b;
    b.store_long(0, 1)
        .store_long(1, 64)
        .store_long(entry.sequence, 32)
        .store_bytes(td::Slice(entry.root.data(), entry.root.size()))
        .store_bytes(td::Slice(entry.file.data(), entry.file.size()));
    check(dict.set_builder(td::BitArray<32>{entry.index}, b), "history-fixture-entry");
  }
  vm::CellBuilder wrapped;
  check(dict.append_dict_to_bool(wrapped), "history-fixture-dictionary");
  extra.r1.prev_blocks = vm::load_cell_slice_ref(wrapped.finalize());
  td::Ref<vm::Cell> custom;
  check(tlb::pack_cell(custom, extra), "history-fixture-extra");
  vm::CellBuilder option;
  option.store_long(1, 1).store_ref(custom);
  state.custom = vm::load_cell_slice_ref(option.finalize());
  state.seq_no = sequence;
  td::Ref<vm::Cell> root;
  check(tlb::pack_cell(root, state), "history-fixture-pack");
  return root;
}
struct Case {
  td::Ref<vm::Cell> root;
  Anchor head;
  ChainContext chain;
  Bytes block;
  HistoryReadBudget budget;
  unsigned source = 0;
};
struct Query {
  std::uint32_t at;
  const char* error = "-";
  Anchor result;
};
td::Ref<vm::Cell> alter_block(td::Ref<vm::Cell> root, unsigned mode) {
  block::gen::Block::Record block;
  check(tlb::unpack_cell(root, block), "changed-block");
  if (mode == 1)
    block.global_id = 43;
  if (mode == 2) {
    block::gen::BlockInfo::Record info;
    check(tlb::unpack_cell(block.info, info), "changed-block-info");
    info.seq_no = 98;
    check(tlb::pack_cell(block.info, info), "changed-block-info-pack");
  }
  if (mode == 3)
    block.state_update = vm::CellBuilder().finalize();
  if (mode == 5) {
    auto full_update = vm::CellBuilder::create_merkle_update(vm::CellBuilder().store_long(1, 2).finalize(),
                                                             vm::CellBuilder().store_long(2, 2).finalize());
    auto original = vm::load_cell_slice_special(full_update);
    vm::CellBuilder ordinary;
    ordinary.store_bits(original.prefetch_bits(original.size()));
    for (unsigned i = 0; i < original.size_refs(); ++i)
      ordinary.store_ref(original.prefetch_ref(i));
    block.state_update = ordinary.finalize();
  }
  if (mode == 4) {
    block::gen::BlockExtra::Record extra;
    check(tlb::unpack_cell(block.extra, extra), "changed-block-extra");
    extra.rand_seed = td::Bits256(td::ConstBitPtr(h(881).data()));
    check(tlb::pack_cell(block.extra, extra), "changed-block-extra-pack");
  }
  check(tlb::pack_cell(root, block), "changed-block-pack");
  return root;
}
td::Ref<vm::Cell> capabilities(td::Ref<vm::Cell> root, std::uint32_t version, std::uint64_t flags) {
  block::gen::ShardStateUnsplit::Record state;
  block::gen::McStateExtra::Record extra;
  block::gen::ConfigParams::Record cp;
  check(tlb::unpack_cell(root, state) && tlb::unpack_cell(state.custom->prefetch_ref(), extra) &&
            tlb::csr_unpack(extra.config, cp),
        "capability-fixture");
  vm::Dictionary config(cp.config, 32);
  vm::CellBuilder cap;
  cap.store_long(0xc4, 8).store_long(version, 32).store_long(flags, 64);
  check(config.set_ref(td::BitArray<32>{8}, cap.finalize()), "capability-fixture-entry");
  cp.config = config.get_root_cell();
  vm::CellBuilder params;
  check(tlb::pack(params, cp), "capability-fixture-params");
  extra.config = vm::load_cell_slice_ref(params.finalize());
  td::Ref<vm::Cell> custom;
  check(tlb::pack_cell(custom, extra), "capability-fixture-extra");
  vm::CellBuilder opt;
  opt.store_long(1, 1).store_ref(custom);
  state.custom = vm::load_cell_slice_ref(opt.finalize());
  check(tlb::pack_cell(root, state), "capability-fixture-state");
  return root;
}
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 3, "arguments");
    std::filesystem::path input(argv[1]), out(argv[2]);
    check(std::filesystem::create_directory(out), "fresh-output");
    auto f = fixture(input);
    auto zero = history_state(mcstate(f), 0, {});
    Anchor genesis{0, hash(zero), file_hash(boc(zero)), hash(zero)};
    f.chain.genesis_root = genesis.root_;
    f.chain.genesis_file = genesis.file_;
    Entry zero_entry{0, 0, genesis.root_, genesis.file_};
    auto old_state = history_state(mcstate(f), 99, {zero_entry});
    auto block = block_for(cell(read(input / "accept.boc")), old_state, f);
    auto previous_state = history_state(mcstate(f), 98, {zero_entry});
    check(hash(previous_state) != hash(old_state), "history-distinct-state-fixture");
    vm::CellUsageTree used;
    auto change = vm::MerkleUpdate::generate(previous_state, old_state, &used);
    check(change.is_ok(), "history-changing-update-fixture");
    block::gen::Block::Record changed_block;
    check(tlb::unpack_cell(block, changed_block), "history-changing-block-fixture");
    changed_block.state_update = change.move_as_ok();
    check(tlb::pack_cell(block, changed_block), "history-changing-block-pack");
    auto raw = boc(block);
    Anchor old{99, hash(block), file_hash(raw), hash(old_state)};
    Entry old_entry{99, 99, old.root_, old.file_};
    auto head_state = history_state(mcstate(f), 100, {zero_entry, old_entry});
    Case base{head_state, {100, h(800), h(801), hash(head_state)}, f.chain, raw, {}};
    unsigned count = 0;
    auto run = [&](const Case& c, const char* label, std::vector<Query> queries, unsigned expected_reads,
                   const char* open_error = "-") {
      unsigned reads = 0;
      auto source = [&](const tos::BlockIdExt& id, std::size_t maximum) -> Result<Bytes> {
        ++reads;
        check(id.seqno() == 99 && id.is_masterchain() && maximum <= 67108864, "history-source-contract");
        if (c.source == 1 || (c.source == 2 && reads > 1))
          return Error{"archive-offline"};
        return c.block;
      };
      auto history = NativeFinalizedHistory::open(c.root, c.head, c.chain, source, c.budget);
      auto folder = out / std::to_string(count++);
      check(std::filesystem::create_directory(folder), "case-dir");
      write(folder / "state", boc(c.root));
      write(folder / "head", value(encode(c.head), "head"));
      write(folder / "block", c.block);
      Writer w;
      w.integer(c.chain.network);
      w.bytes(c.chain.genesis_root);
      w.bytes(c.chain.genesis_file);
      w.bytes(c.chain.chain_domain);
      write(folder / "chain", w.data);
      std::ofstream meta(folder / "case");
      meta << c.budget.blocks << ' ' << c.budget.bytes << ' ' << c.source << ' ' << expected_reads << ' ' << label
           << ' ' << open_error << ' ' << queries.size() << '\n';
      auto failed = [&](const char* expected, const char* actual) {
        std::cerr << "DETAIL " << label << " expected=" << expected << " actual=" << actual << '\n';
        check(false, label);
      };
      if (std::string(open_error) != "-") {
        if (history.ok() || history.error().code != open_error)
          failed(open_error, history.ok() ? "accepted" : history.error().code.c_str());
      } else {
        if (!history.ok())
          failed("accepted", history.error().code.c_str());
        unsigned i = 0;
        for (const auto& q : queries) {
          auto result = history.value().finalized_anchor(q.at);
          meta << q.at << ' ' << q.error << '\n';
          if (std::string(q.error) == "-") {
            if (!result.ok() || result.value() != q.result)
              failed("expected-anchor", result.ok() ? "wrong-anchor" : result.error().code.c_str());
            write(folder / ("result" + std::to_string(i)), value(encode(q.result), "expected"));
          } else if (result.ok() || result.error().code != q.error)
            failed(q.error, result.ok() ? "accepted" : result.error().code.c_str());
          ++i;
        }
      }
      check(reads == expected_reads, label);
    };
    run(base, "history-current-head", {{100, "-", base.head}}, 0);
    run(base, "history-genesis", {{0, "-", genesis}}, 0);
    run(base, "history-native-old-block", {{99, "-", old}}, 1);
    auto c = base;
    c.budget.blocks = 1;
    c.budget.bytes = raw.size();
    c.source = 2;
    run(c, "history-cache-and-exact-budget", {{99, "-", old}, {99, "-", old}}, 1);
    c = base;
    c.budget = {0, 0};
    run(c, "history-known-anchor-no-io", {{100, "-", base.head}, {0, "-", genesis}}, 0);
    run(base, "history-unknown-coordinate", {{98, "finalized-anchor-unavailable", {}}}, 0);
    run(base, "history-future-coordinate", {{101, "history-future", {}}}, 0);
    run(base, "history-sentinel-coordinate", {{UINT32_MAX, "history-future", {}}}, 0);
    c = base;
    c.head.state_ = h(700);
    run(c, "history-state-substitution", {}, 0, "history-anchor");
    c = base;
    c.head.seqno_ = 101;
    run(c, "history-state-coordinate", {}, 0, "history-native-state");
    c = base;
    c.chain.genesis_root = h(700);
    run(c, "history-genesis-root", {}, 0, "history-genesis");
    c = base;
    c.chain.genesis_file = h(700);
    run(c, "history-genesis-file", {}, 0, "history-genesis");
    c = base;
    c.chain.network = 43;
    run(c, "history-chain-network", {}, 0, "history-network");
    c = base;
    c.chain.chain_domain = h(700);
    run(c, "history-chain-domain", {}, 0, "history-domain");
    c = base;
    c.chain.genesis_root = {};
    run(c, "history-zero-genesis", {}, 0, "chain-context");
    c = base;
    c.head.root_ = {};
    run(c, "history-zero-anchor-root", {}, 0, "history-anchor");
    c = base;
    c.head.file_ = {};
    run(c, "history-zero-anchor-file", {}, 0, "history-anchor");
    auto indexed = [&](Entry entry, Bytes body = Bytes{}) {
      Case changed = base;
      changed.root = history_state(mcstate(f), 100, {zero_entry, entry});
      changed.head.state_ = hash(changed.root);
      if (!body.empty())
        changed.block = std::move(body);
      return changed;
    };
    auto entry = old_entry;
    entry.sequence = 98;
    c = indexed(entry);
    run(c, "history-index-sequence-binding", {{99, "finalized-anchor-unavailable", {}}}, 0);
    entry = old_entry;
    entry.root = {};
    c = indexed(entry);
    run(c, "history-zero-block-root", {{99, "finalized-anchor-unavailable", {}}}, 0);
    entry = old_entry;
    entry.file = {};
    c = indexed(entry);
    run(c, "history-zero-block-file", {{99, "finalized-anchor-unavailable", {}}}, 0);
    c = base;
    c.root = history_state(mcstate(f), 100, {old_entry});
    c.head.state_ = hash(c.root);
    run(c, "history-missing-genesis-entry", {}, 0, "history-native-state");
    c = base;
    auto alternate = vm::std_boc_serialize(block, 31);
    check(alternate.is_ok(), "alternate-boc");
    auto bytes = alternate.ok().as_slice();
    c.block = Bytes(bytes.ubegin(), bytes.uend());
    run(c, "history-original-file-binding", {{99, "history-file-hash", {}}}, 1);
    auto other = alter_block(block, 4);
    entry = old_entry;
    entry.file = file_hash(boc(other));
    c = indexed(entry, boc(other));
    run(c, "history-independent-root-binding", {{99, "history-block-root", {}}}, 1);
    for (unsigned mode = 1; mode <= 3; ++mode) {
      auto changed = alter_block(block, mode);
      auto body = boc(changed);
      entry = old_entry;
      entry.root = hash(changed);
      entry.file = file_hash(body);
      c = indexed(entry, body);
      run(c,
          mode == 1   ? "history-block-network"
          : mode == 2 ? "history-block-sequence"
                      : "history-update-kind",
          {{99, mode == 3 ? "history-state-update" : "history-block-context", {}}}, 1);
    }
    other = alter_block(block, 5);
    entry = old_entry;
    entry.root = hash(other);
    entry.file = file_hash(boc(other));
    c = indexed(entry, boc(other));
    run(c, "history-ordinary-update-is-not-merkle", {{99, "history-state-update", {}}}, 1);
    c = base;
    c.root = capabilities(c.root, 15, 1024);
    c.head.state_ = hash(c.root);
    run(c, "history-version-gate", {}, 0, "history-capability");
    c = base;
    c.root = capabilities(c.root, 16, 0);
    c.head.state_ = hash(c.root);
    run(c, "history-capability-gate", {}, 0, "history-capability");
    c = base;
    c.source = 1;
    run(c, "history-storage-error", {{99, "archive-offline", {}}}, 1);
    c = base;
    c.block.clear();
    run(c, "history-empty-block", {{99, "history-block-bound", {}}}, 1);
    c = base;
    c.budget.blocks = 0;
    run(c, "history-block-count-bound", {{99, "history-resource", {}}}, 0);
    c = base;
    c.budget.bytes = 0;
    run(c, "history-total-byte-bound", {{99, "history-resource", {}}}, 0);
    c = base;
    c.budget.bytes = raw.size() - 1;
    run(c, "history-source-oversize", {{99, "history-block-bound", {}}}, 1);
    Bytes malformed{0, 1, 2, 3};
    entry = old_entry;
    entry.file = file_hash(malformed);
    c = indexed(entry, malformed);
    run(c, "history-malformed-boc", {{99, "history-boc", {}}}, 1);
    c = base;
    c.root = zero;
    c.head = genesis;
    run(c, "history-zerostate-context", {{0, "-", genesis}}, 0);
    c = base;
    c.root = zero;
    c.head = genesis;
    c.head.root_ = h(333);
    c.chain.genesis_root = c.head.root_;
    run(c, "history-zerostate-root-is-state", {}, 0, "history-genesis");
    std::ofstream(out / "complete") << count << '\n';
    std::cout << "PASS: authenticated native history " << count << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
