/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include "block/block.h"
#include "vm/cells.h"

namespace block {
using td::Ref;

td::Status check_block_header_proof(td::Ref<vm::Cell> root, tos::BlockIdExt blkid,
                                    tos::Bits256* store_state_hash_to = nullptr, bool check_state_hash = false,
                                    td::uint32* save_utime = nullptr, tos::LogicalTime* save_lt = nullptr);
td::Status check_shard_proof(tos::BlockIdExt blk, tos::BlockIdExt shard_blk, td::Slice shard_proof);
td::Status check_account_proof(td::Slice proof, tos::BlockIdExt shard_blk, const block::StdAddress& addr,
                               td::Ref<vm::Cell> root, tos::LogicalTime* last_trans_lt = nullptr,
                               tos::Bits256* last_trans_hash = nullptr, td::uint32* save_utime = nullptr,
                               tos::LogicalTime* save_lt = nullptr);
td::Result<td::Bits256> check_state_proof(tos::BlockIdExt blkid, td::Slice proof);
td::Result<Ref<vm::Cell>> check_extract_state_proof(tos::BlockIdExt blkid, td::Slice proof, td::Slice data);

struct AccountState {
  tos::BlockIdExt blk;
  tos::BlockIdExt shard_blk;
  td::BufferSlice shard_proof;
  td::BufferSlice proof;
  td::BufferSlice state;
  bool is_virtualized{false};

  struct Info {
    td::Ref<vm::Cell> root, true_root;
    tos::LogicalTime last_trans_lt{0};
    tos::Bits256 last_trans_hash;
    tos::LogicalTime gen_lt{0};
    td::uint32 gen_utime{0};
  };

  td::Result<Info> validate(tos::BlockIdExt ref_blk, block::StdAddress addr) const;
};

struct Transaction {
  tos::BlockIdExt blkid;
  tos::LogicalTime lt;
  tos::Bits256 hash;
  td::Ref<vm::Cell> root;

  struct Info {
    tos::BlockIdExt blkid;
    td::uint32 now;
    tos::LogicalTime prev_trans_lt;
    tos::Bits256 prev_trans_hash;
    td::Ref<vm::Cell> transaction;
  };
  td::Result<Info> validate();
};

struct TransactionList {
  tos::LogicalTime lt;
  tos::Bits256 hash;
  std::vector<tos::BlockIdExt> blkids;
  td::BufferSlice transactions_boc;

  struct Info {
    tos::LogicalTime lt;
    tos::Bits256 hash;
    std::vector<Transaction::Info> transactions;
  };

  td::Result<Info> validate() const;
};

struct BlockTransaction {
  tos::BlockIdExt blkid;
  td::Ref<vm::Cell> root;
  td::Ref<vm::Cell> proof;

  struct Info {
    tos::BlockIdExt blkid;
    td::uint32 now;
    tos::LogicalTime lt;
    tos::Bits256 hash;
    td::Ref<vm::Cell> transaction;
  };
  td::Result<Info> validate(bool check_proof) const;
};

struct BlockTransactionList {
  tos::BlockIdExt blkid;
  td::BufferSlice transactions_boc;
  td::BufferSlice proof_boc;
  tos::LogicalTime start_lt;
  td::Bits256 start_addr;
  bool reverse_mode;
  int req_count;

  struct Info {
    tos::BlockIdExt blkid;
    std::vector<BlockTransaction::Info> transactions;
  };

  td::Result<Info> validate(bool check_proof) const;
};

}  // namespace block
