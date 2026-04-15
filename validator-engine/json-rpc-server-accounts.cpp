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
#include "json-rpc-server-internal.h"

#include "auto/tl/lite_api.hpp"
#include "tl/tl_object_parse.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/check-proof.h"
#include "vm/cells/CellString.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "td/utils/crypto.h"
#include <limits>

namespace tos {

// ─── ParsedAccountState implementation ─────────────────────────────────

td::Result<ParsedAccountState> ParsedAccountState::parse(
    tos::tl_object_ptr<tos::lite_api::liteServer_accountState>& f,
    const block::StdAddress& addr) {
  ParsedAccountState res;

  if (f->id_) {
    res.blk_workchain = f->id_->workchain_;
    res.blk_shard = f->id_->shard_;
    res.blk_seqno = f->id_->seqno_;
    res.blk_root_hash_b64 = td::base64_encode(f->id_->root_hash_.as_slice());
    res.blk_file_hash_b64 = td::base64_encode(f->id_->file_hash_.as_slice());
  }

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

std::string ParsedAccountState::to_address_info_json() const {
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

std::string ParsedAccountState::to_extended_info_json(const std::string& addr_str) const {
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

// ─── getAddressInformation ──────────────────────────────────────────────

void JsonRpcServer::handle_getAddressInformation(td::JsonObject &params, std::string req_id,
                                                 td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return result
  auto do_get_account = [addr, addr_str = std::move(addr_str), self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
        std::move(query),
        td::PromiseCreator::lambda(
            [addr, addr_str = std::move(addr_str), req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(parsed.ok().to_address_info_json(), req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
              R.move_as_ok(), true);
          if (mc.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse mcInfo: " << mc.error(), req_id));
            return;
          }
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
}

void JsonRpcServer::handle_getExtendedAddressInformation(td::JsonObject &params, std::string req_id,
                                                         td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return result
  auto do_get_account = [addr, addr_str = std::move(addr_str), self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
        std::move(query),
        td::PromiseCreator::lambda(
            [addr, addr_str = std::move(addr_str), req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(parsed.ok().to_extended_info_json(addr_str), req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
              R.move_as_ok(), true);
          if (mc.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse mcInfo: " << mc.error(), req_id));
            return;
          }
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
}

// ─── getAddressBalance ──────────────────────────────────────────────────

void JsonRpcServer::handle_getAddressBalance(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return balance
  auto do_get_account = [addr, self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
        std::move(query),
        td::PromiseCreator::lambda(
            [addr, req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(
          PSTRING() << "\"" << parsed.ok().balance << "\"", req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
              R.move_as_ok(), true);
          if (mc.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse mcInfo: " << mc.error(), req_id));
            return;
          }
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
}

// ─── getAddressState ────────────────────────────────────────────────────

void JsonRpcServer::handle_getAddressState(td::JsonObject &params, std::string req_id,
                                           td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return state string
  auto do_get_account = [addr, self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
            std::move(block_id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr)),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
        std::move(query),
        td::PromiseCreator::lambda(
            [addr, req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      auto state_json = PSTRING() << td::JsonString(td::Slice(parsed.ok().state_str));
      promise_inner.set_value(make_json_ok(state_json, req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error(), req_id));
            return;
          }
          auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
              R.move_as_ok(), true);
          if (mc.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse mcInfo: " << mc.error(), req_id));
            return;
          }
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
}

}  // namespace tos
