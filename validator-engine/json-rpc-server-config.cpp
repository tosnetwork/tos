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
#include "td/utils/crypto.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "block/check-proof.h"
#include "block/mc-config.h"

namespace tos {

void JsonRpcServer::handle_getConfigParam(td::JsonObject &params, std::string req_id,
                                          td::Promise<HttpReturn> promise) {
  auto config_id_r = params.get_required_int_field("param");
  if (config_id_r.is_error()) {
    config_id_r = params.get_required_int_field("config_id");
  }
  if (config_id_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'param' parameter", req_id));
    return;
  }
  int config_id = config_id_r.ok();

  // Optional seqno: query config at a specific MC block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  // Step 2 lambda: query config at a resolved block
  auto do_query_config = [config_id, req_id = std::move(req_id),
                          self_id = actor_id(this), promise = std::move(promise)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id) mutable {
        std::vector<td::int32> param_list = {config_id};
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(
                0x10000, std::move(block_id), std::move(param_list)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [config_id, req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getConfigParam failed: " << R.error(), req_id));
            return;
          }
          auto data = R.move_as_ok();

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(
              std::move(data), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse configInfo: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();

          // Extract config from proofs
          auto blk_id = tos::create_block_id(f->id_);
          auto state_r = block::check_extract_state_proof(
              blk_id, f->state_proof_.as_slice(), f->config_proof_.as_slice());
          if (state_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "state proof error: " << state_r.error(), req_id));
            return;
          }

          auto cfg_r = block::Config::extract_from_state(state_r.move_as_ok(), 0);
          if (cfg_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "config extract error: " << cfg_r.error(), req_id));
            return;
          }
          auto cfg = cfg_r.move_as_ok();

          auto param_cell = cfg->get_config_param(config_id);
          if (param_cell.is_null()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "config param " << config_id << " not found", req_id));
            return;
          }

          // Serialize cell to BOC, then base64
          auto boc_r = vm::std_boc_serialize(param_cell);
          if (boc_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "BOC serialize error: " << boc_r.error(), req_id));
            return;
          }
          auto b64 = td::base64_encode(boc_r.ok().as_slice());

          promise.set_value(make_json_ok(
              PSTRING() << "{\"config\":{\"bytes\":" << td::JsonString(td::Slice(b64)) << "}}",
              req_id));
        }));
  };  // end of do_query_config

  // Step 1: resolve block
  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_query_config = std::move(do_query_config)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) return;
          do_query_config(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_query_config = std::move(do_query_config)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) return;
          do_query_config(std::move(mc_r.move_as_ok()->last_));
        });
  }
}

// ─── getLibraries ──────────────────────────────────────────────────────────

void JsonRpcServer::handle_getLibraries(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  // Parse library_list — a JSON array of base64-encoded 256-bit hashes
  auto list_val = params.extract_field("library_list");
  if (list_val.type() != td::JsonValue::Type::Array) {
    promise.set_value(make_json_error(-32602,
        "Missing or invalid 'library_list' (expected JSON array)", req_id));
    return;
  }
  auto &arr = list_val.get_array();
  std::vector<td::Bits256> hashes;
  hashes.reserve(arr.size());
  for (auto &elem : arr) {
    if (elem.type() != td::JsonValue::Type::String) {
      promise.set_value(make_json_error(-32602,
          "library_list entries must be base64 strings", req_id));
      return;
    }
    auto decoded_r = td::base64_decode(elem.get_string());
    if (decoded_r.is_error() || decoded_r.ok().size() != 32) {
      promise.set_value(make_json_error(-32602,
          "Invalid base64 hash in library_list (expected 32 bytes)", req_id));
      return;
    }
    td::Bits256 hash;
    hash.as_slice().copy_from(decoded_r.ok());
    hashes.push_back(hash);
  }

  if (hashes.empty()) {
    promise.set_value(make_json_ok(
        "{\"@type\":\"smc.libraryResult\",\"result\":[]}", req_id));
    return;
  }

  // Construct liteServer.getLibraries(library_list)
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getLibraries>(std::move(hashes)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getLibraries failed: " << R.error(), req_id));
          return;
        }
        auto lib_r = tos::fetch_tl_object<tos::lite_api::liteServer_libraryResult>(
            R.move_as_ok(), true);
        if (lib_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse libraryResult: " << lib_r.error(), req_id));
          return;
        }
        auto lib = lib_r.move_as_ok();

        td::StringBuilder sb;
        sb << "{\"@type\":\"smc.libraryResult\",\"result\":[";
        for (size_t i = 0; i < lib->result_.size(); i++) {
          if (i > 0) sb << ",";
          auto &entry = lib->result_[i];
          auto hash_b64 = td::base64_encode(entry->hash_.as_slice());
          auto data_b64 = td::base64_encode(entry->data_.as_slice());
          sb << "{\"hash\":" << td::JsonString(td::Slice(hash_b64))
             << ",\"data\":" << td::JsonString(td::Slice(data_b64)) << "}";
        }
        sb << "]}";
        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
      });
}

// ─── getConfigAll ────────────────────────────────────────────────────────
// Retrieves the full blockchain configuration (all config params).
// Uses liteServer.getConfigAll which is a distinct TL method from getConfigParams.
// Accepts optional "seqno" parameter to query config at a specific mc block.

void JsonRpcServer::handle_getConfigAll(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  // Optional seqno parameter — if provided, we look up that specific block
  td::int32 seqno = 0;
  auto seqno_r = params.get_optional_int_field("seqno");
  if (seqno_r.is_ok() && seqno_r.ok() > 0) {
    seqno = static_cast<td::int32>(seqno_r.ok());
  }

  // Step 1: Get masterchain info (or lookup specific block by seqno)
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [seqno, req_id = std::move(req_id), self_id, promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo failed: " << R.error(), req_id));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse masterchainInfo: " << mc_r.error(), req_id));
          return;
        }
        auto mc = mc_r.move_as_ok();

        // If specific seqno requested, look up that block first
        if (seqno > 0) {
          auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
              -1, static_cast<td::int64>(-1LL << 63), seqno);
          auto lookup_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
                  1, std::move(block_id), 0, 0),
              true);
          auto lookup_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(lookup_query),
              td::PromiseCreator::lambda(
                  [req_id = std::move(req_id), self_id, promise = std::move(promise)](
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

            // Step 2: getConfigAll with the resolved block ID
            auto inner = tos::serialize_tl_object(
                tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                    0, std::move(lb->id_)),
                true);
            auto query = tos::serialize_tl_object(
                tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

            td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
                std::move(query),
                td::PromiseCreator::lambda(
                    [req_id = std::move(req_id), promise = std::move(promise)](
                        td::Result<td::BufferSlice> R) mutable {
              if (R.is_error()) {
                promise.set_value(make_json_error(-32603,
                    PSTRING() << "getConfigAll failed: " << R.error(), req_id));
                return;
              }
              auto F = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(
                  R.move_as_ok(), true);
              if (F.is_error()) {
                promise.set_value(make_json_error(-32603,
                    PSTRING() << "parse configInfo: " << F.error(), req_id));
                return;
              }
              auto f = F.move_as_ok();

              auto blk_id = tos::create_block_id(f->id_);
              auto state_r = block::check_extract_state_proof(
                  blk_id, f->state_proof_.as_slice(), f->config_proof_.as_slice());
              if (state_r.is_error()) {
                promise.set_value(make_json_error(-32603,
                    PSTRING() << "state proof error: " << state_r.error(), req_id));
                return;
              }

              auto cfg_r = block::Config::extract_from_state(state_r.move_as_ok(), 0);
              if (cfg_r.is_error()) {
                promise.set_value(make_json_error(-32603,
                    PSTRING() << "config extract error: " << cfg_r.error(), req_id));
                return;
              }
              auto cfg = cfg_r.move_as_ok();

              // Serialize all config params as an object mapping param_id -> base64 BOC
              td::StringBuilder sb;
              sb << "{\"@type\":\"configInfo\""
                 << ",\"config\":{\"@type\":\"tvm.cell\"";
              // Serialize the full config cell as a BOC
              auto config_root = cfg->get_root_cell();
              if (config_root.not_null()) {
                auto boc_r = vm::std_boc_serialize(config_root);
                if (boc_r.is_ok()) {
                  sb << ",\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())));
                }
              }
              sb << "}";

              // Also include individual config params for convenience
              sb << ",\"config_params\":{";
              bool first_param = true;
              cfg->foreach_config_param([&](int id, td::Ref<vm::Cell> cell) -> bool {
                if (!first_param) sb << ",";
                first_param = false;
                auto boc_r = vm::std_boc_serialize(cell);
                if (boc_r.is_ok()) {
                  sb << "\"" << id << "\":{\"bytes\":"
                     << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())))
                     << "}";
                } else {
                  sb << "\"" << id << "\":null";
                }
                return true;
              });
              sb << "}}";
              promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
            }));
          }));
          return;
        }

        // No seqno — use latest masterchain block
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                0, std::move(mc->last_)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getConfigAll failed: " << R.error(), req_id));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse configInfo: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();

          auto blk_id = tos::create_block_id(f->id_);
          auto state_r = block::check_extract_state_proof(
              blk_id, f->state_proof_.as_slice(), f->config_proof_.as_slice());
          if (state_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "state proof error: " << state_r.error(), req_id));
            return;
          }

          auto cfg_r = block::Config::extract_from_state(state_r.move_as_ok(), 0);
          if (cfg_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "config extract error: " << cfg_r.error(), req_id));
            return;
          }
          auto cfg = cfg_r.move_as_ok();

          td::StringBuilder sb;
          sb << "{\"@type\":\"configInfo\""
             << ",\"config\":{\"@type\":\"tvm.cell\"";
          auto config_root = cfg->get_root_cell();
          if (config_root.not_null()) {
            auto boc_r = vm::std_boc_serialize(config_root);
            if (boc_r.is_ok()) {
              sb << ",\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())));
            }
          }
          sb << "}";

          sb << ",\"config_params\":{";
          bool first_param = true;
          cfg->foreach_config_param([&](int id, td::Ref<vm::Cell> cell) -> bool {
            if (!first_param) sb << ",";
            first_param = false;
            auto boc_r = vm::std_boc_serialize(cell);
            if (boc_r.is_ok()) {
              sb << "\"" << id << "\":{\"bytes\":"
                 << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())))
                 << "}";
            } else {
              sb << "\"" << id << "\":null";
            }
            return true;
          });
          sb << "}}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
      });
}

}  // namespace tos
