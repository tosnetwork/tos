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
#include "vm/cp0.h"
#include "vm/vm.h"

namespace tos {

void JsonRpcServer::handle_getTokenData(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  vm::CellBuilder cb;
  vm::Stack empty_stack;
  if (!empty_stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }
  auto params_boc = std::make_shared<td::BufferSlice>(params_boc_r.move_as_ok());

  auto do_query_token = [addr, params_boc, req_id = std::move(req_id),
                         self_id = actor_id(this), promise = std::move(promise)](
      td::int32 blk_wc, td::int64 blk_shard, td::int32 blk_seqno,
      td::Bits256 blk_root, td::Bits256 blk_file) mutable {

        auto saved_wc = blk_wc;
        auto saved_shard = blk_shard;
        auto saved_seqno = blk_seqno;
        auto saved_root = blk_root;
        auto saved_file = blk_file;

        td::int64 jetton_method_id = (td::crc16(td::Slice("get_jetton_data")) & 0xffff) | 0x10000;
        auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
            blk_wc, blk_shard, blk_seqno, blk_root, blk_file);
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(blk),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr),
                jetton_method_id, params_boc->clone()),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [addr, params_boc, self_id,
                 saved_wc, saved_shard, saved_seqno, saved_root, saved_file,
                 req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          auto parse_address_from_slice = [](const vm::StackEntry& entry) -> std::string {
            if (entry.type() != vm::StackEntry::t_slice) return "";
            auto cs = entry.as_slice();
            if (cs->size() < 2) return "";
            auto tag = cs->prefetch_ulong(2);
            if (tag == 0) return "";
            if (tag != 2) return "";
            vm::CellSlice tmp(*cs);
            tmp.advance(2);
            if (tmp.size() < 1) return "";
            auto has_anycast = tmp.fetch_ulong(1);
            if (has_anycast) {
              if (tmp.size() < 5) return "";
              auto depth = (int)tmp.fetch_ulong(5);
              tmp.advance(depth);
            }
            if (tmp.size() < 8 + 256) return "";
            auto workchain = (td::int8)tmp.fetch_long(8);
            td::Bits256 address;
            tmp.fetch_bits_to(address.bits(), 256);
            block::StdAddress a(workchain, address);
            a.bounceable = true;
            a.testnet = false;
            return a.rserialize(true);
          };

          auto cell_to_b64 = [](const vm::StackEntry& entry) -> std::string {
            if (!entry.is_cell()) return "";
            auto boc = vm::std_boc_serialize(entry.as_cell());
            if (boc.is_error()) return "";
            return td::base64_encode(boc.ok().as_slice());
          };

          if (R.is_ok()) {
            auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                R.move_as_ok(), true);
            if (F.is_ok()) {
              auto f = F.move_as_ok();
              if (f->exit_code_ == 0 && !f->result_.empty()) {
                auto cell_r = vm::std_boc_deserialize(f->result_.as_slice());
                if (cell_r.is_ok()) {
                  auto stk = td::make_ref<vm::Stack>();
                  auto result_cell = cell_r.move_as_ok();
                  vm::CellSlice cs = vm::load_cell_slice(result_cell);
                  if (stk.write().deserialize(cs) && stk->depth() >= 5) {
                    auto& wallet_code_e = stk->at(0);
                    auto& content_e = stk->at(1);
                    auto& admin_addr_e = stk->at(2);
                    auto& mintable_e = stk->at(3);
                    auto& total_supply_e = stk->at(4);

                    if (total_supply_e.is_int()) {
                      auto total_supply_str = total_supply_e.as_int()->to_dec_string();
                      bool mintable = mintable_e.is_int() && mintable_e.as_int()->to_long() != 0;
                      auto admin_addr_str = parse_address_from_slice(admin_addr_e);
                      auto content_b64 = cell_to_b64(content_e);
                      auto wallet_code_b64 = cell_to_b64(wallet_code_e);

                      td::StringBuilder sb;
                      sb << "{\"@type\":\"ext.tokens.jettonMasterData\""
                         << ",\"total_supply\":" << td::JsonString(td::Slice(total_supply_str))
                         << ",\"mintable\":" << (mintable ? "true" : "false")
                         << ",\"admin_address\":" << td::JsonString(td::Slice(admin_addr_str))
                         << ",\"jetton_content\":" << td::JsonString(td::Slice(content_b64))
                         << ",\"jetton_wallet_code\":" << td::JsonString(td::Slice(wallet_code_b64))
                         << "}";
                      promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
                      return;
                    }
                  }
                }
              }
            }
          }

          auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
              saved_wc, saved_shard, saved_seqno, saved_root, saved_file);
          td::int64 nft_method_id = (td::crc16(td::Slice("get_nft_data")) & 0xffff) | 0x10000;
          auto nft_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                  0x04, std::move(blk),
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      addr.workchain, addr.addr),
                  nft_method_id, params_boc->clone()),
              true);
          auto nft_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(nft_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(nft_query),
              td::PromiseCreator::lambda(
                  [addr, params_boc, self_id,
                   saved_wc, saved_shard, saved_seqno, saved_root, saved_file,
                   req_id = std::move(req_id), promise = std::move(promise),
                   parse_address_from_slice, cell_to_b64](
                      td::Result<td::BufferSlice> R2) mutable {

            auto try_collection = [&addr, &params_boc, &self_id,
                                   saved_wc, saved_shard, saved_seqno, saved_root, saved_file,
                                   &parse_address_from_slice, &cell_to_b64](
                std::string req_id, td::Promise<HttpReturn> promise) mutable {
              auto blk3 = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
                  saved_wc, saved_shard, saved_seqno, saved_root, saved_file);
              td::int64 coll_method_id = (td::crc16(td::Slice("get_collection_data")) & 0xffff) | 0x10000;
              auto coll_inner = tos::serialize_tl_object(
                  tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                      0x04, std::move(blk3),
                      tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                          addr.workchain, addr.addr),
                      coll_method_id, params_boc->clone()),
                  true);
              auto coll_query = tos::serialize_tl_object(
                  tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(coll_inner)), true);

              td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
                  std::move(coll_query),
                  td::PromiseCreator::lambda(
                      [req_id = std::move(req_id), promise = std::move(promise),
                       parse_address_from_slice, cell_to_b64](
                          td::Result<td::BufferSlice> R3) mutable {
                if (R3.is_error()) {
                  promise.set_value(make_json_error(409,
                      "Smart contract is not a Jetton or NFT", req_id));
                  return;
                }
                auto F3 = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                    R3.move_as_ok(), true);
                if (F3.is_error()) {
                  promise.set_value(make_json_error(409,
                      "Smart contract is not a Jetton or NFT", req_id));
                  return;
                }
                auto f3 = F3.move_as_ok();
                if (f3->exit_code_ != 0 || f3->result_.empty()) {
                  promise.set_value(make_json_error(409,
                      "Smart contract is not a Jetton or NFT", req_id));
                  return;
                }
                auto cell_r = vm::std_boc_deserialize(f3->result_.as_slice());
                if (cell_r.is_error()) {
                  promise.set_value(make_json_error(409,
                      "Smart contract is not a Jetton or NFT", req_id));
                  return;
                }
                auto stk = td::make_ref<vm::Stack>();
                auto result_cell = cell_r.move_as_ok();
                vm::CellSlice cs = vm::load_cell_slice(result_cell);
                if (!stk.write().deserialize(cs) || stk->depth() < 3) {
                  promise.set_value(make_json_error(409,
                      "Smart contract is not a Jetton or NFT", req_id));
                  return;
                }

                auto& owner_e = stk->at(0);
                auto& content_e = stk->at(1);
                auto& next_item_e = stk->at(2);

                td::int64 next_item_index = next_item_e.is_int() ? next_item_e.as_int()->to_long() : 0;
                auto owner_str = parse_address_from_slice(owner_e);
                auto content_b64 = cell_to_b64(content_e);

                td::StringBuilder sb;
                sb << "{\"@type\":\"ext.tokens.nftCollectionData\""
                   << ",\"next_item_index\":" << next_item_index
                   << ",\"collection_content\":" << td::JsonString(td::Slice(content_b64))
                   << ",\"owner_address\":" << td::JsonString(td::Slice(owner_str))
                   << "}";
                promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
              }));
            };

            if (R2.is_error()) {
              try_collection(std::move(req_id), std::move(promise));
              return;
            }
            auto F2 = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                R2.move_as_ok(), true);
            if (F2.is_error()) {
              try_collection(std::move(req_id), std::move(promise));
              return;
            }
            auto f2 = F2.move_as_ok();
            if (f2->exit_code_ != 0 || f2->result_.empty()) {
              try_collection(std::move(req_id), std::move(promise));
              return;
            }

            auto cell_r = vm::std_boc_deserialize(f2->result_.as_slice());
            if (cell_r.is_error()) {
              try_collection(std::move(req_id), std::move(promise));
              return;
            }
            auto stk = td::make_ref<vm::Stack>();
            auto result_cell = cell_r.move_as_ok();
            vm::CellSlice cs = vm::load_cell_slice(result_cell);
            if (!stk.write().deserialize(cs) || stk->depth() < 5) {
              try_collection(std::move(req_id), std::move(promise));
              return;
            }

            auto& content_e = stk->at(0);
            auto& owner_e = stk->at(1);
            auto& collection_e = stk->at(2);
            auto& index_e = stk->at(3);
            auto& init_e = stk->at(4);

            bool init_val = init_e.is_int() && init_e.as_int()->to_long() != 0;
            td::int64 index_val = index_e.is_int() ? index_e.as_int()->to_long() : 0;
            auto collection_str = parse_address_from_slice(collection_e);
            auto owner_str = parse_address_from_slice(owner_e);
            auto content_b64 = cell_to_b64(content_e);

            td::StringBuilder sb;
            sb << "{\"@type\":\"ext.tokens.nftItemData\""
               << ",\"init\":" << (init_val ? "true" : "false")
               << ",\"index\":" << index_val
               << ",\"collection_address\":" << td::JsonString(td::Slice(collection_str))
               << ",\"owner_address\":" << td::JsonString(td::Slice(owner_str))
               << ",\"individual_content\":" << td::JsonString(td::Slice(content_b64))
               << "}";
            promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
          }));
        }));
  };

  // The step-1 lookupBlock /
  // getMasterchainInfo callbacks below drop the HTTP promise on error
  // (`return;` without settle). `promise` was captured by-move into
  // `do_query_token` and into the deeply-nested jetton→NFT→collection
  // fallback cascade — refactoring the whole cascade to a shared slot
  // should be handled as a separate focused change. Residual behavior:
  // a malformed seqno or transient liteserver failure in step 1 results
  // in the HTTP connection hanging until the per-request timeout
  // (default 30s, see Options::request_timeout). Below the request
  // timeout, the connection is bounded; above it, the timeout fires
  // and the client gets a clean disconnect.
  //
  // Track the shared-slot refactor as a deferred follow-up rather than
  // mixing it into this multi-callback path.
  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_query_token = std::move(do_query_token)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) {
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_query_token(lb->id_->workchain_, lb->id_->shard_, lb->id_->seqno_,
                         lb->id_->root_hash_, lb->id_->file_hash_);
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_query_token = std::move(do_query_token)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            return;
          }
          auto mc = mc_r.move_as_ok();
          do_query_token(mc->last_->workchain_, mc->last_->shard_, mc->last_->seqno_,
                         mc->last_->root_hash_, mc->last_->file_hash_);
        });
  }
}

}  // namespace tos
