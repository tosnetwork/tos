#include "block/block-auto.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "vm/cells/MerkleProof.h"

#include "native-history.h"
namespace tos::auth {
namespace {
Hash hash(td::Slice raw) {
  Hash h{};
  std::copy(raw.ubegin(), raw.uend(), h.begin());
  return h;
}
bool terminal(td::Ref<vm::Cell> cell, unsigned depth) {
  vm::CellSlice s{vm::NoVm{}, cell};
  auto mask = cell->get_level_mask().get_mask();
  return s.special_type() == vm::Cell::SpecialType::PrunnedBranch && s.size_refs() == 0 &&
         (depth == 0 ? mask == 1 : (mask == 2 || mask == 3));
}
// Inspect a fixed surface before any proof virtualization or native TL-B decode.
// At most eleven occurrences, depth three; no recursive peer-controlled walk.
bool surface(td::Ref<vm::Cell> proof) {
  if (proof.is_null() || proof->is_virtualized() || proof->get_level() != 0)
    return false;
  vm::CellSlice outer{vm::NoVm{}, proof};
  if (outer.special_type() != vm::Cell::SpecialType::MerkleProof || outer.size() != 280 || outer.size_refs() != 1)
    return false;
  vm::CellSlice root{vm::NoVm{}, outer.prefetch_ref()};
  if (root.is_special() || root.size() != 64 || root.size_refs() != 4)
    return false;
  if (!terminal(root.prefetch_ref(1), 0) || !terminal(root.prefetch_ref(3), 0))
    return false;
  vm::CellSlice info{vm::NoVm{}, root.prefetch_ref(0)};
  if (info.is_special() || info.size_refs() < 1 || info.size_refs() > 3)
    return false;
  for (unsigned i = 0; i < info.size_refs(); ++i)
    if (!terminal(info.prefetch_ref(i), 0))
      return false;
  vm::CellSlice update{vm::NoVm{}, root.prefetch_ref(2)};
  if (update.special_type() != vm::Cell::SpecialType::MerkleUpdate || update.size() != 552 || update.size_refs() != 2)
    return false;
  return terminal(update.prefetch_ref(0), 1) && terminal(update.prefetch_ref(1), 1);
}
td::Ref<vm::Cell> prune_refs(td::Ref<vm::Cell> cell, unsigned depth) {
  vm::CellSlice s{vm::NoVm{}, cell};
  vm::CellBuilder b;
  b.store_bits(s.prefetch_bits(s.size()));
  for (unsigned i = 0; i < s.size_refs(); ++i)
    b.store_ref(vm::CellBuilder::do_create_pruned_branch(s.prefetch_ref(i), depth + 1));
  return b.finalize(s.is_special());
}
}  // namespace
Result<td::Ref<vm::Cell>> native_header_proof(td::Ref<vm::Cell> block) {
  try {
    if (block.is_null() || block->get_level() != 0 || block->is_virtualized())
      return Error{"header-block"};
    block::gen::Block::Record record;
    block::gen::BlockInfo::Record info;
    if (!tlb::unpack_cell(block, record) || !tlb::unpack_cell(record.info, info))
      return Error{"header-block"};
    vm::CellSlice update{vm::NoVm{}, record.state_update};
    if (update.special_type() != vm::Cell::SpecialType::MerkleUpdate || update.size_ext() != 0x20228)
      return Error{"header-state-update"};
    vm::CellSlice s{vm::NoVm{}, block};
    vm::CellBuilder b;
    b.store_bits(s.prefetch_bits(s.size()))
        .store_ref(prune_refs(record.info, 0))
        .store_ref(vm::CellBuilder::do_create_pruned_branch(record.value_flow, 1))
        .store_ref(prune_refs(record.state_update, 1))
        .store_ref(vm::CellBuilder::do_create_pruned_branch(record.extra, 1));
    auto proof = vm::CellBuilder::create_merkle_proof(b.finalize());
    if (!surface(proof))
      return Error{"header-surface"};
    auto opened = vm::MerkleProof::virtualize(proof);
    if (opened.is_error() || opened.ok()->get_hash() != block->get_hash())
      return Error{"header-generation"};
    return td::Ref<vm::Cell>(proof);
  } catch (const vm::VmError&) {
    return Error{"header-block"};
  } catch (const vm::VmVirtError&) {
    return Error{"header-pruned"};
  } catch (const vm::CellBuilder::CellWriteError&) {
    return Error{"header-generation"};
  } catch (const vm::CellBuilder::CellCreateError&) {
    return Error{"header-generation"};
  }
}
Result<Anchor> NativeFinalizedHistory::authenticate_header(std::uint32_t at, td::Ref<vm::Cell> proof) const {
  try {
    if (at == 0 || at > head_.seqno_ || at == UINT32_MAX)
      return Error{"header-coordinate"};
    tos::BlockIdExt id;
    if (at == head_.seqno_) {
      id = {{tos::masterchainId, tos::shardIdAll, at},
            td::Bits256(td::ConstBitPtr(head_.root_.data())),
            td::Bits256(td::ConstBitPtr(head_.file_.data()))};
    } else if (!config_->get_old_mc_block_id(at, id) || id.seqno() != at || !id.is_masterchain() ||
               id.id.shard != tos::shardIdAll || id.root_hash.is_zero() || id.file_hash.is_zero()) {
      return Error{"header-index"};
    }
    if (!surface(proof))
      return Error{"header-surface"};
    auto root = vm::MerkleProof::virtualize(proof);
    if (root.is_error() || root.ok()->get_hash().as_slice() != id.root_hash.as_slice())
      return Error{"header-root"};
    block::gen::Block::Record record;
    block::gen::BlockInfo::Record info;
    if (!tlb::unpack_cell(root.ok(), record) || !tlb::unpack_cell(record.info, info))
      return Error{"header-block"};
    block::ShardId shard(info.shard);
    if (record.global_id != chain_.network || info.seq_no != at || info.not_master || shard.workchain_id != -1 ||
        shard.shard_pfx_len != 0)
      return Error{"header-context"};
    vm::CellSlice update{vm::NoVm{}, record.state_update};
    update.advance(8 + 256);
    Hash state{};
    if (!update.fetch_bytes(td::MutableSlice(state.data(), state.size())) || state == Hash{})
      return Error{"header-state"};
    if (at == head_.seqno_ && state != head_.state_)
      return Error{"header-head-state"};
    return Anchor{at, hash(id.root_hash.as_slice()), hash(id.file_hash.as_slice()), state};
  } catch (const vm::VmError&) {
    return Error{"header-block"};
  } catch (const vm::VmVirtError&) {
    return Error{"header-pruned"};
  }
}
}  // namespace tos::auth
