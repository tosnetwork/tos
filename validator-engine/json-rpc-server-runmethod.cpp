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

namespace tos {

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
              stack.push(vm::StackEntry(vm::load_cell_slice_ref(cell.move_as_ok())));
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

  // Step 2 lambda: runSmcMethod at a resolved block
  auto do_run_method = [addr, method_id, params_boc = std::move(params_boc),
                        req_id = std::move(req_id), self_id = actor_id(this),
                        promise = std::move(promise)](
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
                [req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "runSmcMethod: " << R.error(), req_id));
            return;
          }

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse runMethodResult: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();

          // Parse result stack
          std::string stack_json = "[]";
          if (!f->result_.empty()) {
            auto cell_r = vm::std_boc_deserialize(f->result_.as_slice());
            if (cell_r.is_ok()) {
              auto stk = td::make_ref<vm::Stack>();
              auto result_cell = cell_r.move_as_ok();
              vm::CellSlice cs = vm::load_cell_slice(result_cell);
              if (stk.write().deserialize(cs)) {
                // Convert stack to JSON array of ["num", "value"] entries
                td::StringBuilder sb;
                sb << "[";
                for (int i = 0; i < (int)stk->depth(); i++) {
                  if (i > 0) sb << ",";
                  auto& entry = stk->at(i);
                  if (entry.is_int()) {
                    auto val = entry.as_int();
                    sb << "[\"num\"," << td::JsonString(td::Slice(val->to_dec_string())) << "]";
                  } else if (entry.is_cell()) {
                    auto boc = vm::std_boc_serialize(entry.as_cell());
                    if (boc.is_ok()) {
                      sb << "[\"cell\",{\"bytes\":"
                         << td::JsonString(td::Slice(td::base64_encode(boc.ok().as_slice())))
                         << "}]";
                    } else {
                      sb << "[\"unsupported\"]";
                    }
                  } else {
                    sb << "[\"unsupported\"]";
                  }
                }
                sb << "]";
                stack_json = sb.as_cslice().str();
              }
            }
          }

          // Build block_id from liteserver response
          std::string block_id_json = "null";
          if (f->id_) {
            block_id_json = PSTRING()
                << "{\"@type\":\"ton.blockIdExt\""
                << ",\"workchain\":" << f->id_->workchain_
                << ",\"shard\":\"" << f->id_->shard_ << "\""
                << ",\"seqno\":" << f->id_->seqno_
                << ",\"root_hash\":\"" << td::base64_encode(f->id_->root_hash_.as_slice()) << "\""
                << ",\"file_hash\":\"" << td::base64_encode(f->id_->file_hash_.as_slice()) << "\""
                << "}";
          }

          auto result = PSTRING()
              << "{\"gas_used\":0"
              << ",\"stack\":" << stack_json
              << ",\"exit_code\":" << f->exit_code_
              << ",\"last_transaction_id\":null"
              << ",\"block_id\":" << block_id_json
              << "}";

          promise.set_value(make_json_ok(result, req_id));
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
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) return;
          do_run_method(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) return;
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
              stack.push(vm::StackEntry(vm::load_cell_slice_ref(cell.move_as_ok())));
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

  // Step 2 lambda: runSmcMethod at a resolved block
  auto do_run_method = [addr, method_id, params_boc = std::move(params_boc),
                        req_id = std::move(req_id), self_id = actor_id(this),
                        promise = std::move(promise)](
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
                [req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "runSmcMethod: " << R.error(), req_id));
            return;
          }

          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse runMethodResult: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();

          // Parse result stack into standardized typed format
          std::string stack_json = "[]";
          if (!f->result_.empty()) {
            auto cell_r = vm::std_boc_deserialize(f->result_.as_slice());
            if (cell_r.is_ok()) {
              auto stk = td::make_ref<vm::Stack>();
              auto result_cell = cell_r.move_as_ok();
              vm::CellSlice cs = vm::load_cell_slice(result_cell);
              if (stk.write().deserialize(cs)) {
                // Convert stack to standardized TVM stack entries
                td::StringBuilder sb;
                sb << "[";
                for (int i = 0; i < (int)stk->depth(); i++) {
                  if (i > 0) sb << ",";
                  auto& entry = stk->at(i);
                  if (entry.is_int()) {
                    auto val = entry.as_int();
                    sb << "{\"@type\":\"tvm.stackEntryNumber\""
                       << ",\"number\":{\"@type\":\"tvm.numberDecimal\""
                       << ",\"number\":" << td::JsonString(td::Slice(val->to_dec_string()))
                       << "}}";
                  } else if (entry.is_cell()) {
                    auto boc = vm::std_boc_serialize(entry.as_cell());
                    if (boc.is_ok()) {
                      sb << "{\"@type\":\"tvm.stackEntryCell\""
                         << ",\"cell\":{\"@type\":\"tvm.cell\""
                         << ",\"bytes\":" << td::JsonString(td::Slice(
                                td::base64_encode(boc.ok().as_slice())))
                         << "}}";
                    } else {
                      sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                    }
                  } else if (entry.type() == vm::StackEntry::t_slice) {
                    // Serialize slice as a cell for portability
                    vm::CellBuilder cb2;
                    auto slice = entry.as_slice();
                    if (cb2.append_cellslice_bool(slice)) {
                      auto boc = vm::std_boc_serialize(cb2.finalize());
                      if (boc.is_ok()) {
                        sb << "{\"@type\":\"tvm.stackEntrySlice\""
                           << ",\"slice\":{\"@type\":\"tvm.slice\""
                           << ",\"bytes\":" << td::JsonString(td::Slice(
                                  td::base64_encode(boc.ok().as_slice())))
                           << "}}";
                      } else {
                        sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                      }
                    } else {
                      sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                    }
                  } else {
                    sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                  }
                }
                sb << "]";
                stack_json = sb.as_cslice().str();
              }
            }
          }

          // Note: liteServer.runMethodResult does not include gas_used;
          // report 0 for compatibility (same as existing runGetMethod handler).
          auto result = PSTRING()
              << "{\"@type\":\"smc.runResult\""
              << ",\"gas_used\":0"
              << ",\"stack\":" << stack_json
              << ",\"exit_code\":" << f->exit_code_
              << "}";

          promise.set_value(make_json_ok(result, req_id));
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
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) return;
          do_run_method(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) return;
          do_run_method(std::move(mc_r.move_as_ok()->last_));
        });
  }
}

}  // namespace tos
