#pragma once
#include "validator/auth/native-history.h"

#include "owner-fixture.h"
using namespace p0_owner_fixture;
namespace {
td::Ref<vm::Cell> replace_ref(td::Ref<vm::Cell> root, unsigned index, td::Ref<vm::Cell> next) {
  vm::CellSlice s{vm::NoVm{}, root};
  vm::CellBuilder b;
  b.store_bits(s.prefetch_bits(s.size()));
  for (unsigned i = 0; i < s.size_refs(); ++i)
    b.store_ref(i == index ? next : s.prefetch_ref(i));
  return b.finalize(s.is_special());
}
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
[[maybe_unused]] td::Ref<vm::Cell> alter_block(td::Ref<vm::Cell> root, unsigned mode) {
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
[[maybe_unused]] td::Ref<vm::Cell> capabilities(td::Ref<vm::Cell> root, std::uint32_t version, std::uint64_t flags) {
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
