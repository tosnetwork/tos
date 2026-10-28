/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include "block/block-auto.h"
#include "block/mc-config.h"
#include "common/errorcode.h"
#include "validator/fabric.h"
#include "validator/interfaces/block.h"

#include "index-reader.h"

namespace tos::services {
using validator::RootDb;

td::Result<RawBlock> raw_block(td::Result<td::BufferSlice> read) {
  if (read.is_error()) {
    if (read.error().message() == td::Slice(kFileOverReadLimit)) {
      return RawBlock{td::BufferSlice(), true};
    }
    return read.move_as_error();
  }
  auto data = read.move_as_ok();
  if (data.size() > kPrefetchBlockBytesMax) {
    // A reader that ignored the limit: keep nothing of it.
    return RawBlock{td::BufferSlice(), true};
  }
  // Buffers under this size are carved from a shared per-thread slab, which a
  // retained slice would keep alive whole. Anything larger is allocated for
  // the one entry the archive read.
  constexpr size_t kOwnBufferBytes = 512;
  if (data.size() < kOwnBufferBytes) {
    td::BufferSlice own(kOwnBufferBytes);
    own.as_slice().copy_from(data.as_slice());
    own.truncate(data.size());
    data = std::move(own);
  }
  return RawBlock{std::move(data), false};
}

size_t raw_block_charge(const td::Result<RawBlock>& result) {
  if (result.is_error()) {
    return kSourceResultOverheadBytes;
  }
  return result.ok().data.size() + kSourceResultOverheadBytes;
}

td::Result<td::Ref<validator::BlockData>> decode_block(const BlockIdExt& id, td::BufferSlice data) {
  return validator::create_block(id, std::move(data));
}

td::Result<validator::ConstBlockHandle> IndexReader::masterchain(uint32_t seqno, Context context) {
  return query<validator::ConstBlockHandle>(
      [seqno](auto db, auto promise) {
        td::actor::send_closure(db, &RootDb::get_block_by_seqno, AccountIdPrefixFull(masterchainId, shardIdAll), seqno,
                                std::move(promise));
      },
      context);
}
td::Result<validator::BlockHandle> IndexReader::handle(BlockIdExt id, Context context) {
  return query<validator::BlockHandle>(
      [id](auto db, auto promise) { td::actor::send_closure(db, &RootDb::get_block_handle, id, std::move(promise)); },
      context);
}
td::Result<std::shared_ptr<SourceReply<RawBlock>>> IndexReader::submit_block(validator::ConstBlockHandle handle,
                                                                             Context context) {
  return submit_raw_block(
      [handle](auto db, td::Promise<td::BufferSlice> promise) {
        td::actor::send_closure(db, &RootDb::get_block_file, handle, static_cast<td::uint32>(kPrefetchBlockBytesMax),
                                std::move(promise));
      },
      context);
}
td::Result<td::Ref<validator::BlockData>> IndexReader::read_block(validator::ConstBlockHandle handle) {
  return query<td::Ref<validator::BlockData>>([handle](auto db, auto promise) {
    td::actor::send_closure(db, &RootDb::get_block_data, handle, std::move(promise));
  });
}
td::Result<td::Ref<vm::Cell>> IndexReader::checked_root(const validator::ConstBlockHandle& handle,
                                                        const td::Ref<validator::BlockData>& data) {
  if (data.is_null() || data->root_cell().is_null() ||
      data->root_cell()->get_hash().as_slice() != handle->id().root_hash.as_slice()) {
    return td::Status::Error("source block root hash mismatch");
  }
  return data->root_cell();
}
td::Result<td::Ref<vm::Cell>> IndexReader::block(validator::ConstBlockHandle handle) {
  TRY_RESULT(data, read_block(handle));
  return checked_root(handle, data);
}
td::Result<std::vector<BlockIdExt>> IndexReader::shard_heads(validator::ConstBlockHandle master) {
  TRY_RESULT(root, block(std::move(master)));
  return index_shard_heads(std::move(root));
}
td::Result<std::optional<std::vector<BlockIdExt>>> IndexReader::prefetch_shard_heads(validator::ConstBlockHandle master,
                                                                                     Context context) {
  TRY_RESULT(reply, submit_block(master, context));
  TRY_RESULT(raw, take(*reply, false));
  if (raw.too_large) {
    return std::nullopt;
  }
  // The reply keeps its charge for the raw bytes until the heads are out;
  // the decoded block lives only inside this call.
  TRY_RESULT(heads, decoded_shard_heads(master, std::move(raw.data)));
  return std::optional<std::vector<BlockIdExt>>(std::move(heads));
}
td::Result<std::vector<BlockIdExt>> IndexReader::decoded_shard_heads(const validator::ConstBlockHandle& master,
                                                                     td::BufferSlice data) {
  TRY_RESULT(block, decode_block(master->id(), std::move(data)));
  TRY_RESULT(root, checked_root(master, block));
  return index_shard_heads(std::move(root));
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
