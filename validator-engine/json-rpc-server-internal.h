/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include "json-rpc-server.h"

#include "auto/tl/lite_api.h"
#include "auto/tl/lite_api.hpp"
#include "tl/tl_object_parse.h"
#include "tl-utils/lite-utils.hpp"
#include "block/block.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/check-proof.h"
#include "block/mc-config.h"
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/SmartContract.h"
#include "tos/lite-tl.hpp"
#include "vm/cellops.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"
#include "vm/boc.h"
#include "vm/cells/CellString.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "td/utils/crypto.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"
#include <limits>

namespace tos {

// ─── Shared: parse address parameter ────────────────────────────────────

inline td::Result<block::StdAddress> parse_address_param(td::JsonObject& params) {
  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) return td::Status::Error("Missing 'address'");
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_r.ok()))) return td::Status::Error("Invalid address");
  return addr;
}

// ─── Shared: block ID JSON formatters ───────────────────────────────────

inline std::string format_block_id_json(const tos::lite_api::tosNode_blockIdExt& blk) {
  return PSTRING()
      << "{\"@type\":\"ton.blockIdExt\""
      << ",\"workchain\":" << blk.workchain_
      << ",\"shard\":\"" << blk.shard_ << "\""
      << ",\"seqno\":" << blk.seqno_
      << ",\"root_hash\":\"" << td::base64_encode(blk.root_hash_.as_slice()) << "\""
      << ",\"file_hash\":\"" << td::base64_encode(blk.file_hash_.as_slice()) << "\""
      << "}";
}

inline std::string format_zero_state_json(const tos::lite_api::tosNode_zeroStateIdExt& zs) {
  return PSTRING()
      << "{\"@type\":\"ton.blockIdExt\""
      << ",\"workchain\":" << zs.workchain_
      << ",\"shard\":\"-9223372036854775808\""
      << ",\"seqno\":0"
      << ",\"root_hash\":\"" << td::base64_encode(zs.root_hash_.as_slice()) << "\""
      << ",\"file_hash\":\"" << td::base64_encode(zs.file_hash_.as_slice()) << "\""
      << "}";
}

// ─── Shared: ParsedAccountState ─────────────────────────────────────────

struct ParsedAccountState {
  td::int64 balance = 0;
  std::string state_str = "uninit";  // "active", "uninit", "frozen"
  std::string code_b64;
  std::string data_b64;
  std::string frozen_hash;
  td::uint64 last_trans_lt = 0;
  std::string last_trans_hash_b64;
  td::uint32 sync_utime = 0;
  td::Ref<vm::Cell> code_cell;  // for wallet detection
  td::Ref<vm::Cell> data_cell;
  td::Ref<vm::Cell> extra_currencies_cell;
  td::Ref<vm::Cell> state_cell;
  tos::UnixTime storage_last_paid{0};
  block::StorageUsed storage_used;

  // Block ID from liteserver response (for real block_id in JSON)
  td::int32 blk_workchain = -1;
  td::int64 blk_shard = static_cast<td::int64>(0x8000000000000000ULL);
  td::uint32 blk_seqno = 0;
  std::string blk_root_hash_b64;
  std::string blk_file_hash_b64;

  static td::Result<ParsedAccountState> parse(
      tos::tl_object_ptr<tos::lite_api::liteServer_accountState>& f,
      const block::StdAddress& addr) {
    ParsedAccountState res;

    // Capture block ID from the liteserver response
    if (f->id_) {
      res.blk_workchain = f->id_->workchain_;
      res.blk_shard = f->id_->shard_;
      res.blk_seqno = f->id_->seqno_;
      res.blk_root_hash_b64 = td::base64_encode(f->id_->root_hash_.as_slice());
      res.blk_file_hash_b64 = td::base64_encode(f->id_->file_hash_.as_slice());
    }

    // Validate proof and extract last_trans_lt, last_trans_hash, gen_utime
    auto blk_id = tos::create_block_id(f->id_);
    auto shard_blk_id = tos::create_block_id(f->shardblk_);
    block::AccountState as;
    as.blk = blk_id;
    as.shard_blk = shard_blk_id;
    as.shard_proof = f->shard_proof_.clone();
    as.proof = f->proof_.clone();
    as.state = f->state_.clone();
    auto info_r = as.validate(blk_id, addr);
    if (info_r.is_ok()) {
      auto info = info_r.move_as_ok();
      res.last_trans_lt = info.last_trans_lt;
      res.last_trans_hash_b64 = td::base64_encode(info.last_trans_hash.as_slice());
      res.sync_utime = info.gen_utime;

      // Parse Account cell from validated root
      if (info.root.not_null()) {
        block::gen::Account::Record_account account;
        if (tlb::unpack_cell(info.root, account)) {
          block::gen::StorageInfo::Record storage_info;
          if (tlb::csr_unpack(account.storage_stat, storage_info)) {
            res.storage_last_paid = storage_info.last_paid;
            block::gen::StorageUsed::Record storage_used;
            if (tlb::csr_unpack(storage_info.used, storage_used)) {
              unsigned long long u = 0;
              u |= res.storage_used.cells = block::tlb::t_VarUInteger_7.as_uint(*storage_used.cells);
              u |= res.storage_used.bits = block::tlb::t_VarUInteger_7.as_uint(*storage_used.bits);
              if (u == std::numeric_limits<td::uint64>::max()) {
                return td::Status::Error("Failed to unpack StorageStat");
              }
            }
          }

          block::gen::AccountStorage::Record storage;
          if (tlb::csr_unpack(account.storage, storage)) {
            auto balance_cs = storage.balance.write();
            auto coins = block::tlb::t_Tomis.as_integer_skip(balance_cs);
            if (coins.not_null()) res.balance = coins->to_long();
            res.extra_currencies_cell = storage.balance->prefetch_ref();

            auto tag = block::gen::t_AccountState.get_tag(*storage.state);
            if (tag == block::gen::AccountState::account_active) {
              res.state_str = "active";
              block::gen::AccountState::Record_account_active active;
              if (tlb::csr_unpack(storage.state, active)) {
                res.state_cell = vm::CellBuilder().append_cellslice(active.x).finalize();
                block::gen::StateInit::Record si;
                if (tlb::csr_unpack(active.x, si)) {
                  si.code->prefetch_maybe_ref(res.code_cell);
                  si.data->prefetch_maybe_ref(res.data_cell);
                  if (res.code_cell.not_null()) {
                    auto boc = vm::std_boc_serialize(res.code_cell);
                    if (boc.is_ok()) res.code_b64 = td::base64_encode(boc.ok().as_slice());
                  }
                  if (res.data_cell.not_null()) {
                    auto boc = vm::std_boc_serialize(res.data_cell);
                    if (boc.is_ok()) res.data_b64 = td::base64_encode(boc.ok().as_slice());
                  }
                }
              }
            } else if (tag == block::gen::AccountState::account_frozen) {
              res.state_str = "frozen";
              block::gen::AccountState::Record_account_frozen frozen;
              if (tlb::csr_unpack(storage.state, frozen)) {
                res.frozen_hash = td::base64_encode(frozen.state_hash.as_slice());
              }
            }
          }
        }
      }
    }
    return res;
  }

  std::string to_address_info_json() const {
    return PSTRING()
        << "{\"@type\":\"raw.fullAccountState\""
        << ",\"balance\":" << td::JsonString(td::Slice(PSTRING() << balance))
        << ",\"code\":" << td::JsonString(td::Slice(code_b64))
        << ",\"data\":" << td::JsonString(td::Slice(data_b64))
        << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
        << ",\"lt\":\"" << last_trans_lt << "\""
        << ",\"hash\":" << td::JsonString(td::Slice(last_trans_hash_b64)) << "}"
        << ",\"block_id\":{\"@type\":\"ton.blockIdExt\""
        << ",\"workchain\":" << blk_workchain
        << ",\"shard\":\"" << blk_shard << "\""
        << ",\"seqno\":" << blk_seqno
        << ",\"root_hash\":\"" << blk_root_hash_b64 << "\""
        << ",\"file_hash\":\"" << blk_file_hash_b64 << "\"}"
        << ",\"sync_utime\":" << sync_utime
        << ",\"extra_currencies\":[]"
        << ",\"state\":" << td::JsonString(td::Slice(state_str))
        << ",\"frozen_hash\":" << td::JsonString(td::Slice(frozen_hash))
        << "}";
  }

  std::string to_extended_info_json(const std::string& addr_str) const {
    return PSTRING()
        << "{\"@type\":\"fullAccountState\""
        << ",\"address\":{\"@type\":\"accountAddress\",\"account_address\":"
        << td::JsonString(td::Slice(addr_str)) << "}"
        << ",\"balance\":" << balance
        << ",\"extra_currencies\":[]"
        << ",\"last_transaction_id\":{\"@type\":\"internal.transactionId\""
        << ",\"lt\":\"" << last_trans_lt << "\""
        << ",\"hash\":" << td::JsonString(td::Slice(last_trans_hash_b64)) << "}"
        << ",\"block_id\":{\"@type\":\"ton.blockIdExt\""
        << ",\"workchain\":" << blk_workchain
        << ",\"shard\":\"" << blk_shard << "\""
        << ",\"seqno\":" << blk_seqno
        << ",\"root_hash\":\"" << blk_root_hash_b64 << "\""
        << ",\"file_hash\":\"" << blk_file_hash_b64 << "\"}"
        << ",\"sync_utime\":" << sync_utime
        << ",\"account_state\":{\"@type\":\"raw.accountState\""
        << ",\"code\":" << td::JsonString(td::Slice(code_b64))
        << ",\"data\":" << td::JsonString(td::Slice(data_b64))
        << ",\"frozen_hash\":" << td::JsonString(td::Slice(frozen_hash)) << "}"
        << ",\"revision\":0}";
  }
};

}  // namespace tos
