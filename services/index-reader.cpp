/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include "block/block-auto.h"
#include "block/mc-config.h"
#include "validator/interfaces/block.h"

#include "index-reader.h"

namespace tos::services {
using validator::RootDb;
td::Result<validator::ConstBlockHandle> IndexReader::masterchain(uint32_t seqno) {
  return query<validator::ConstBlockHandle>([seqno](auto db, auto promise) {
    td::actor::send_closure(db, &RootDb::get_block_by_seqno, AccountIdPrefixFull(masterchainId, shardIdAll), seqno,
                            std::move(promise));
  });
}
td::Result<validator::BlockHandle> IndexReader::handle(BlockIdExt id) {
  return query<validator::BlockHandle>(
      [id](auto db, auto promise) { td::actor::send_closure(db, &RootDb::get_block_handle, id, std::move(promise)); });
}
td::Result<td::Ref<vm::Cell>> IndexReader::block(validator::ConstBlockHandle handle) {
  TRY_RESULT(data, query<td::Ref<validator::BlockData>>([handle](auto db, auto promise) {
               td::actor::send_closure(db, &RootDb::get_block_data, handle, std::move(promise));
             }));
  if (data.is_null() || data->root_cell().is_null() ||
      data->root_cell()->get_hash().as_slice() != handle->id().root_hash.as_slice()) {
    return td::Status::Error("source block root hash mismatch");
  }
  return data->root_cell();
}
td::Result<td::Ref<vm::Cell>> IndexReader::state(validator::ConstBlockHandle handle) {
  return query<td::Ref<vm::Cell>>([handle](auto db, auto promise) {
    td::actor::send_closure(db, &RootDb::get_block_state_root, handle, std::move(promise));
  });
}
td::Result<BlockIdExt> IndexReader::tip() {
  TRY_RESULT(unit, query<td::Unit>([](auto db, auto promise) {
               td::actor::send_closure(db, &RootDb::try_catch_up_with_primary, validator::CatchUpMode::Force,
                                       std::move(promise));
             }));
  (void)unit;
  // The shard client cursor only advances after every referenced shard block
  // has been applied. An archive's maximum height can include unprocessed data.
  return query<BlockIdExt>(
      [](auto db, auto promise) { td::actor::send_closure(db, &RootDb::get_shard_client_state, std::move(promise)); });
}
td::Result<std::vector<BlockIdExt>> index_shard_heads(td::Ref<vm::Cell> root) {
  block::gen::Block::Record block;
  block::gen::BlockExtra::Record extra;
  block::gen::McBlockExtra::Record master;
  block::ShardConfig shards;
  if (!(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.extra, extra) && extra.custom.not_null() &&
        extra.custom->size_refs() == 1 && tlb::unpack_cell(extra.custom->prefetch_ref(), master) &&
        shards.unpack(master.shard_hashes))) {
    return td::Status::Error("cannot decode masterchain shard heads");
  }
  std::vector<BlockIdExt> result;
  for (auto &id : shards.get_shard_hash_ids(true)) {
    if (id.workchain == 0) {
      auto shard = shards.get_shard_hash(id.shard_full(), true);
      if (shard.is_null())
        return td::Status::Error("missing shard descriptor");
      result.push_back(shard->top_block_id());
    }
    if (result.size() > 4096)
      return td::Status::Error("too many shard heads in one masterchain interval");
  }
  return result;
}
}  // namespace tos::services
