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
#include "vm/cells/CellString.h"

namespace tos {

// Hard cap on the number of input stack entries a runGetMethod request may
// carry. A get-method's input stack is tiny in practice (a handful of args);
// the TVM's own stack limits are far below this. The cap bounds the per-entry
// base64-decode + BOC-deserialize work an attacker can pack into a single
// (≤4 MiB) request, independent of whether the per-IP rate gate is enabled.
static constexpr std::size_t kMaxRunMethodStackEntries = 256;

void JsonRpcServer::handle_runGetMethod(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_r.ok()))) {
    promise.set_value(make_json_error(-32602, "Invalid address", req_id));
    return;
  }

  auto method_r = params.get_required_string_field("method");
  if (method_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'method'", req_id));
    return;
  }
  auto method_name = method_r.move_as_ok();
  td::int64 method_id = (td::crc16(td::Slice(method_name)) & 0xffff) | 0x10000;

  // Parse optional stack parameter (array of ["type", "value"] pairs)
  vm::Stack stack;
  auto stack_r = params.extract_field("stack");
  if (stack_r.type() == td::JsonValue::Type::Array) {
    auto& arr = stack_r.get_array();
    if (arr.size() > kMaxRunMethodStackEntries) {
      promise.set_value(make_json_error(
          -32602, "too many stack entries", req_id));
      return;
    }
    for (auto& entry : arr) {
      if (entry.type() != td::JsonValue::Type::Array) continue;
      auto& pair = entry.get_array();
      if (pair.size() < 2) continue;
      if (pair[0].type() != td::JsonValue::Type::String) continue;
      auto type_str = pair[0].get_string().str();
      if (type_str == "num" || type_str == "tvm.Number") {
        std::string val_str;
        if (pair[1].type() == td::JsonValue::Type::String) {
          val_str = pair[1].get_string().str();
        } else if (pair[1].type() == td::JsonValue::Type::Number) {
          val_str = pair[1].get_number().str();
        } else {
          continue;
        }
        auto num = td::string_to_int256(val_str);
        if (num.not_null()) {
          stack.push(vm::StackEntry(std::move(num)));
        }
      } else if (type_str == "cell" || type_str == "tvm.Cell") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              stack.push(vm::StackEntry(cell.move_as_ok()));
            }
          }
        }
      } else if (type_str == "slice" || type_str == "tvm.Slice") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              auto cell_root = cell.move_as_ok();
              // Bare load_cell_slice_ref
              // throws on PrunedBranch / Library / Merkle* roots — JSON-RPC
              // input is attacker-controlled. Use the special-aware loader
              // to detect special cells and skip silently (matches the
              // existing "decode-error → drop" convention for this loop).
              if (cell_root.not_null()) {
                try {
                  bool special = false;
                  (void)vm::load_cell_slice_special(cell_root, special);
                  if (!special) {
                    stack.push(vm::StackEntry(vm::load_cell_slice_ref(cell_root)));
                  }
                } catch (...) {
                  // Stay silent — the surrounding loop ignores per-entry
                  // failures and the resulting empty stack will produce an
                  // explicit RPC error downstream if invalid.
                }
              }
            }
          }
        }
      }
    }
  }

  // Serialize stack as params
  vm::CellBuilder cb;
  if (!stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }

  // Optional seqno: query at a specific MC block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto params_boc = params_boc_r.move_as_ok();

  // Hold promise + req_id in a shared
  // slot so the step-1 (block-resolve) outer callback can settle the HTTP
  // promise on lookupBlock / masterchain-info errors. Previously promise
  // was captured by-move into `do_run_method`; the outer lambda dropped
  // errors with `return;` and the connection hung until HTTP timeout.
  // Shared state is sequential (single actor), so no settle-twice race.
  struct Slot {
    td::Promise<HttpReturn> promise;
    std::string req_id;
    std::string cors;
    bool settled{false};
    void settle_error(int code, const std::string& msg) {
      if (settled) return;
      settled = true;
      promise.set_value(make_json_error(code, msg, req_id, cors));
    }
  };
  auto slot = std::make_shared<Slot>();
  slot->promise = std::move(promise);
  slot->req_id = std::move(req_id);
  slot->cors = opts_.cors_origin;

  // Step 2 lambda: runSmcMethod at a resolved block. Now captures `slot`
  // (shared) instead of consuming promise/req_id.
  auto do_run_method = [cors = opts_.cors_origin, addr, method_id, params_boc = std::move(params_boc),
                        slot, self_id = actor_id(this)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id) mutable {
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(block_id),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr),
                method_id, std::move(params_boc)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603, PSTRING() << "runSmcMethod: " << R.error());
            return;
          }

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            slot->settle_error(-32603, PSTRING() << "parse runMethodResult: " << F.error());
            return;
          }
          auto f = F.move_as_ok();

          // An unreadable result is an error, never an empty stack.
          auto body = render_run_method_result(*f, RunResultFormat::Legacy);
          if (body.is_error()) {
            slot->settle_error(body.error().code(), body.error().message().str());
            return;
          }
          if (!slot->settled) {
            slot->settled = true;
            slot->promise.set_value(make_json_ok(body.move_as_ok(), slot->req_id, cors));
          }
        }));
  };  // end of do_run_method

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
        [do_run_method = std::move(do_run_method), slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "lookupBlock: " << R.error());
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "parse lookupBlock result: " << lb_r.error());
            return;
          }
          do_run_method(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_run_method = std::move(do_run_method), slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error());
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "parse getMasterchainInfo: " << mc_r.error());
            return;
          }
          do_run_method(std::move(mc_r.move_as_ok()->last_));
        });
  }
}

// ─── runGetMethodStd ─────────────────────────────────────────────────────
// Standardized version of runGetMethod. Same parameters (address, method, stack)
// but returns results in the TVM stack entry format with typed entries
// (tvm.stackEntryNumber, tvm.stackEntryCell, tvm.stackEntrySlice, etc.)
// rather than the legacy ["num", "value"] array format.

void JsonRpcServer::handle_runGetMethodStd(td::JsonObject &params, std::string req_id,
                                           td::Promise<HttpReturn> promise) {
  auto addr_r = params.get_required_string_field("address");
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_r.ok()))) {
    promise.set_value(make_json_error(-32602, "Invalid address", req_id));
    return;
  }

  auto method_r = params.get_required_string_field("method");
  if (method_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'method'", req_id));
    return;
  }
  auto method_name = method_r.move_as_ok();
  td::int64 method_id = (td::crc16(td::Slice(method_name)) & 0xffff) | 0x10000;

  // Parse optional stack parameter (array of ["type", "value"] pairs)
  vm::Stack stack;
  auto stack_r = params.extract_field("stack");
  if (stack_r.type() == td::JsonValue::Type::Array) {
    auto& arr = stack_r.get_array();
    if (arr.size() > kMaxRunMethodStackEntries) {
      promise.set_value(make_json_error(
          -32602, "too many stack entries", req_id));
      return;
    }
    for (auto& entry : arr) {
      if (entry.type() != td::JsonValue::Type::Array) continue;
      auto& pair = entry.get_array();
      if (pair.size() < 2) continue;
      if (pair[0].type() != td::JsonValue::Type::String) continue;
      auto type_str = pair[0].get_string().str();
      if (type_str == "num" || type_str == "tvm.Number") {
        std::string val_str;
        if (pair[1].type() == td::JsonValue::Type::String) {
          val_str = pair[1].get_string().str();
        } else if (pair[1].type() == td::JsonValue::Type::Number) {
          val_str = pair[1].get_number().str();
        } else {
          continue;
        }
        auto num = td::string_to_int256(val_str);
        if (num.not_null()) {
          stack.push(vm::StackEntry(std::move(num)));
        }
      } else if (type_str == "cell" || type_str == "tvm.Cell") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              stack.push(vm::StackEntry(cell.move_as_ok()));
            }
          }
        }
      } else if (type_str == "slice" || type_str == "tvm.Slice") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              auto cell_root = cell.move_as_ok();
              // Bare load_cell_slice_ref
              // throws on PrunedBranch / Library / Merkle* roots — JSON-RPC
              // input is attacker-controlled. Use the special-aware loader
              // to detect special cells and skip silently (matches the
              // existing "decode-error → drop" convention for this loop).
              if (cell_root.not_null()) {
                try {
                  bool special = false;
                  (void)vm::load_cell_slice_special(cell_root, special);
                  if (!special) {
                    stack.push(vm::StackEntry(vm::load_cell_slice_ref(cell_root)));
                  }
                } catch (...) {
                  // Stay silent — the surrounding loop ignores per-entry
                  // failures and the resulting empty stack will produce an
                  // explicit RPC error downstream if invalid.
                }
              }
            }
          }
        }
      }
    }
  }

  // Serialize stack as params
  vm::CellBuilder cb;
  if (!stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }

  // Optional seqno: query at a specific MC block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto params_boc = params_boc_r.move_as_ok();

  // Use the same shared-slot lifetime pattern as legacy runGetMethod above.
  struct Slot {
    td::Promise<HttpReturn> promise;
    std::string req_id;
    std::string cors;
    bool settled{false};
    void settle_error(int code, const std::string& msg) {
      if (settled) return;
      settled = true;
      promise.set_value(make_json_error(code, msg, req_id, cors));
    }
  };
  auto slot = std::make_shared<Slot>();
  slot->promise = std::move(promise);
  slot->req_id = std::move(req_id);
  slot->cors = opts_.cors_origin;

  // Step 2 lambda: runSmcMethod at a resolved block
  auto do_run_method = [cors = opts_.cors_origin, addr, method_id, params_boc = std::move(params_boc),
                        slot, self_id = actor_id(this)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id) mutable {
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(block_id),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr),
                method_id, std::move(params_boc)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603, PSTRING() << "runSmcMethod: " << R.error());
            return;
          }

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            slot->settle_error(-32603, PSTRING() << "parse runMethodResult: " << F.error());
            return;
          }
          auto f = F.move_as_ok();

          // An unreadable result is an error, never an empty stack.
          auto body = render_run_method_result(*f, RunResultFormat::Std);
          if (body.is_error()) {
            slot->settle_error(body.error().code(), body.error().message().str());
            return;
          }
          if (!slot->settled) {
            slot->settled = true;
            slot->promise.set_value(make_json_ok(body.move_as_ok(), slot->req_id, cors));
          }
        }));
  };  // end of do_run_method

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
        [do_run_method = std::move(do_run_method), slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "lookupBlock: " << R.error());
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "parse lookupBlock result: " << lb_r.error());
            return;
          }
          do_run_method(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_run_method = std::move(do_run_method), slot](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "getMasterchainInfo: " << R.error());
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            slot->settle_error(-32603,
                PSTRING() << "parse getMasterchainInfo: " << mc_r.error());
            return;
          }
          do_run_method(std::move(mc_r.move_as_ok()->last_));
        });
  }
}

}  // namespace tos
