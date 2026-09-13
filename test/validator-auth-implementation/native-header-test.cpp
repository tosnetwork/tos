#include "native-history-fixture.h"
namespace {
td::Ref<vm::Cell> replace_ref(td::Ref<vm::Cell> root, unsigned index, td::Ref<vm::Cell> next) {
  vm::CellSlice s{vm::NoVm{}, root};
  vm::CellBuilder b;
  b.store_bits(s.prefetch_bits(s.size()));
  for (unsigned i = 0; i < s.size_refs(); ++i)
    b.store_ref(i == index ? next : s.prefetch_ref(i));
  return b.finalize(s.is_special());
}
td::Ref<vm::Cell> proof_replace(td::Ref<vm::Cell> proof, unsigned index, td::Ref<vm::Cell> next) {
  auto root = vm::load_cell_slice_special(proof).prefetch_ref();
  return vm::CellBuilder::create_merkle_proof(replace_ref(root, index, next));
}
td::Ref<vm::Cell> alter_info(td::Ref<vm::Cell> root, unsigned mode) {
  block::gen::Block::Record b;
  block::gen::BlockInfo::Record info;
  check(tlb::unpack_cell(root, b) && tlb::unpack_cell(b.info, info), "fixture-info");
  if (mode == 1) {
    info.not_master = true;
    info.master_ref = info.prev_ref;
  } else {
    vm::CellBuilder shard;
    shard.store_long(0, 2).store_long(mode == 3 ? 1 : 0, 6).store_long(mode == 2 ? 0 : -1, 32).store_long(0, 64);
    info.shard = vm::load_cell_slice_ref(shard.finalize());
  }
  check(tlb::pack_cell(b.info, info) && tlb::pack_cell(root, b), "fixture-info-pack");
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
    f.chain.genesis_root = hash(zero);
    f.chain.genesis_file = file_hash(boc(zero));
    Entry z{0, 0, f.chain.genesis_root, f.chain.genesis_file};
    auto state = history_state(mcstate(f), 99, {z});
    auto previous = history_state(mcstate(f), 98, {z});
    auto block = block_for(cell(read(input / "accept.boc")), state, f);
    auto update = vm::CellBuilder::create_merkle_update(previous, state);
    block = replace_ref(block, 2, update);
    auto proof = value(native_header_proof(block), "fixture-header-generation");
    Anchor old{99, hash(block), file_hash(boc(block)), hash(state)};
    auto history_state_root = history_state(mcstate(f), 100, {z, {99, 99, old.root_, old.file_}});
    Case base{history_state_root, {100, h(800), h(801), hash(history_state_root)}, f.chain, boc(block), {0, 0}};
    unsigned count = 0;
    auto run = [&](const Case& c, td::Ref<vm::Cell> witness, std::uint32_t at, const char* label, const char* error,
                   const Anchor& expected = Anchor{}) {
      unsigned reads = 0;
      auto history = value(NativeFinalizedHistory::open(
                               c.root, c.head, c.chain,
                               [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> {
                                 ++reads;
                                 return Error{"archive-offline"};
                               },
                               c.budget),
                           "fixture-history-open");
      auto folder = out / std::to_string(count++);
      check(std::filesystem::create_directory(folder), "case-dir");
      write(folder / "state", boc(c.root));
      write(folder / "head", value(encode(c.head), "head"));
      write(folder / "proof", boc(witness));
      write(folder / "block", c.block);
      Writer w;
      w.integer(c.chain.network);
      w.bytes(c.chain.genesis_root);
      w.bytes(c.chain.genesis_file);
      w.bytes(c.chain.chain_domain);
      write(folder / "chain", w.data);
      std::ofstream(folder / "case") << at << ' ' << label << ' ' << error << '\n';
      for (unsigned n = 0; n < 2; ++n) {
        auto result = history.authenticate_header(at, witness);
        if (std::string(error) == "-") {
          if (!result.ok() || result.value() != expected) {
            std::cerr << "DETAIL " << label << " got " << (result.ok() ? "wrong-anchor" : result.error().code) << '\n';
            check(false, label);
          }
          write(folder / "result", value(encode(expected), "anchor"));
        } else if (result.ok() || result.error().code != error) {
          std::cerr << "DETAIL " << label << " expected " << error << " got "
                    << (result.ok() ? "accepted" : result.error().code) << '\n';
          check(false, label);
        }
        check(reads == 0, label);
      }
    };
    run(base, proof, 99, "header-native-old-state", "-", old);
    // A different native BOC encoding must not become the authenticated file ID.
    auto c = base;
    auto alternate = vm::std_boc_serialize(block, 31);
    check(alternate.is_ok(), "fixture-alternate-boc");
    c.block = Bytes(alternate.ok().as_slice().ubegin(), alternate.ok().as_slice().uend());
    run(c, proof, 99, "header-authenticated-file-id", "-", old);
    run(base, proof, 0, "header-no-genesis-proof", "header-coordinate");
    run(base, proof, 101, "header-no-future-proof", "header-coordinate");
    run(base, proof, UINT32_MAX, "header-no-sentinel-proof", "header-coordinate");
    run(base, proof, 98, "header-missing-index", "header-index");
    run(base, proof, 100, "header-independent-root", "header-root");
    auto indexed = [&](td::Ref<vm::Cell> b, Entry entry) {
      auto changed = base;
      changed.root = history_state(mcstate(f), 100, {z, entry});
      changed.head.state_ = hash(changed.root);
      changed.block = boc(b);
      return changed;
    };
    for (unsigned mode = 0; mode < 3; ++mode) {
      Entry e{99, 99, old.root_, old.file_};
      if (mode == 0)
        e.sequence = 98;
      if (mode == 1)
        e.root = {};
      if (mode == 2)
        e.file = {};
      run(indexed(block, e), proof, 99,
          mode == 0   ? "header-index-sequence"
          : mode == 1 ? "header-index-root"
                      : "header-index-file",
          "header-index");
    }
    for (unsigned mode = 1; mode <= 5; ++mode) {
      auto b = mode <= 2 ? alter_block(block, mode) : alter_info(block, mode - 2);
      auto p = value(native_header_proof(b), "fixture-changed-header");
      const char* labels[]{
          "", "header-network", "header-sequence", "header-not-master", "header-workchain", "header-full-shard"};
      run(indexed(b, {99, 99, hash(b), file_hash(boc(b))}), p, 99, labels[mode], "header-context");
    }
    auto full = vm::MerkleProof::generate(block, [](const auto&) { return false; });
    check(full.is_ok(), "fixture-full-proof");
    run(base, full.ok(), 99, "header-no-extra-state", "header-surface");
    auto block_slice = vm::load_cell_slice(block);
    for (unsigned index : {1u, 3u}) {
      auto p = proof_replace(proof, index, block_slice.prefetch_ref(index));
      run(base, p, 99, index == 1 ? "header-value-flow-pruned" : "header-block-extra-pruned", "header-surface");
    }
    auto raw_root = vm::load_cell_slice_special(proof).prefetch_ref();
    auto info = vm::load_cell_slice(raw_root).prefetch_ref(0);
    auto full_info = vm::load_cell_slice(block).prefetch_ref(0);
    auto revealed_info = replace_ref(info, 0, vm::load_cell_slice(full_info).prefetch_ref(0));
    run(base, proof_replace(proof, 0, revealed_info), 99, "header-predecessor-pruned", "header-surface");
    auto partial_update = vm::load_cell_slice(raw_root).prefetch_ref(2);
    for (unsigned index : {0u, 1u}) {
      auto p = proof_replace(proof, 2, replace_ref(partial_update, index, index == 0 ? previous : state));
      run(base, p, 99, index == 0 ? "header-old-state-pruned" : "header-new-state-pruned", "header-surface");
    }
    run(base, block, 99, "header-proof-kind", "header-surface");
    auto opened = vm::MerkleProof::virtualize(proof);
    check(opened.is_ok(), "fixture-open-proof");
    // A head proof uses the trusted full head anchor, including its resulting state.
    auto head_block = block_for(cell(read(input / "accept.boc")), history_state_root, f);
    block::gen::Block::Record hb;
    block::gen::BlockInfo::Record hi;
    check(tlb::unpack_cell(head_block, hb) && tlb::unpack_cell(hb.info, hi), "fixture-head");
    hi.seq_no = 100;
    check(tlb::pack_cell(hb.info, hi) && tlb::pack_cell(head_block, hb), "fixture-head-pack");
    c = base;
    c.block = boc(head_block);
    c.head.root_ = hash(head_block);
    c.head.file_ = file_hash(c.block);
    auto head_proof = value(native_header_proof(head_block), "fixture-head-proof");
    run(c, head_proof, 100, "header-current-head", "-", c.head);
    head_block = replace_ref(head_block, 2, update);
    c.block = boc(head_block);
    c.head.root_ = hash(head_block);
    c.head.file_ = file_hash(c.block);
    head_proof = value(native_header_proof(head_block), "fixture-head-other-state");
    run(c, head_proof, 100, "header-head-state-binding", "header-head-state");
    // Native updates with intrinsic level-one pruned children need both hashes.
    auto intrinsic = vm::CellBuilder::do_create_pruned_branch(previous, 1);
    auto native_update = vm::CellBuilder::create_merkle_update(intrinsic, state);
    auto intrinsic_block = replace_ref(block, 2, native_update);
    auto intrinsic_proof = value(native_header_proof(intrinsic_block), "fixture-intrinsic-proof");
    Anchor intrinsic_anchor{99, hash(intrinsic_block), file_hash(boc(intrinsic_block)), hash(state)};
    run(indexed(intrinsic_block, {99, 99, intrinsic_anchor.root_, intrinsic_anchor.file_}), intrinsic_proof, 99,
        "header-native-pruned-update", "-", intrinsic_anchor);
    std::ofstream(out / "complete") << count << '\n';
    std::cout << "PASS: native header authentication " << count << " cases\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
