/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "auto/tl/lite_api.hpp"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/stack.hpp"

#include "json-rpc-server-parse.h"
#include "json-rpc-server-runresult.h"

namespace tos {

// ─── Shared stack entry serializers ─────────────────────────────────────
// Recursively serialize a TVM StackEntry to the legacy ["type", value] format
// used by runGetMethod, and the typed {@type: "tvm.stackEntry..."} format
// used by runGetMethodStd.

static void serialize_stack_entry_legacy(td::StringBuilder &sb, const vm::StackEntry &entry);

static void serialize_stack_entries_legacy(td::StringBuilder &sb, const td::Ref<vm::Tuple> &tuple) {
  sb << "[";
  for (unsigned i = 0; i < tuple->size(); i++) {
    if (i > 0)
      sb << ",";
    serialize_stack_entry_legacy(sb, tuple->at(i));
  }
  sb << "]";
}

static void serialize_stack_entry_legacy(td::StringBuilder &sb, const vm::StackEntry &entry) {
  if (entry.is_int()) {
    auto val = entry.as_int();
    sb << "[\"num\"," << td::JsonString(td::Slice(val->to_dec_string())) << "]";
  } else if (entry.is_cell()) {
    auto boc = vm::std_boc_serialize(entry.as_cell());
    if (boc.is_ok()) {
      sb << "[\"cell\",{\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc.ok().as_slice()))) << "}]";
    } else {
      sb << "[\"unsupported\"]";
    }
  } else if (entry.type() == vm::StackEntry::t_slice) {
    vm::CellBuilder cb2;
    auto slice = entry.as_slice();
    if (slice.not_null() && cb2.append_cellslice_bool(slice)) {
      auto boc = vm::std_boc_serialize(cb2.finalize());
      if (boc.is_ok()) {
        sb << "[\"slice\",{\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc.ok().as_slice()))) << "}]";
      } else {
        sb << "[\"unsupported\"]";
      }
    } else {
      sb << "[\"unsupported\"]";
    }
  } else if (entry.is_tuple()) {
    auto tuple = entry.as_tuple();
    sb << "[\"tuple\",{\"elements\":";
    serialize_stack_entries_legacy(sb, tuple);
    sb << "}]";
  } else if (entry.is_list()) {
    // Lists in TVM are nested cons-pairs; flatten to an array
    sb << "[\"list\",{\"elements\":[";
    auto cur = entry;
    bool first = true;
    while (cur.is_tuple()) {
      auto t = cur.as_tuple();
      if (t->size() != 2)
        break;
      if (!first)
        sb << ",";
      first = false;
      serialize_stack_entry_legacy(sb, (*t)[0]);
      cur = (*t)[1];
    }
    sb << "]}]";
  } else if (entry.is_null()) {
    sb << "[\"null\"]";
  } else {
    sb << "[\"unsupported\"]";
  }
}

static void serialize_stack_entry_std(td::StringBuilder &sb, const vm::StackEntry &entry);

static void serialize_stack_entries_std(td::StringBuilder &sb, const td::Ref<vm::Tuple> &tuple) {
  sb << "[";
  for (unsigned i = 0; i < tuple->size(); i++) {
    if (i > 0)
      sb << ",";
    serialize_stack_entry_std(sb, tuple->at(i));
  }
  sb << "]";
}

static void serialize_stack_entry_std(td::StringBuilder &sb, const vm::StackEntry &entry) {
  if (entry.is_int()) {
    auto val = entry.as_int();
    sb << "{\"@type\":\"tvm.stackEntryNumber\""
       << ",\"number\":{\"@type\":\"tvm.numberDecimal\""
       << ",\"number\":" << td::JsonString(td::Slice(val->to_dec_string())) << "}}";
  } else if (entry.is_cell()) {
    auto boc = vm::std_boc_serialize(entry.as_cell());
    if (boc.is_ok()) {
      sb << "{\"@type\":\"tvm.stackEntryCell\""
         << ",\"cell\":{\"@type\":\"tvm.cell\""
         << ",\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc.ok().as_slice()))) << "}}";
    } else {
      sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
    }
  } else if (entry.type() == vm::StackEntry::t_slice) {
    vm::CellBuilder cb2;
    auto slice = entry.as_slice();
    if (slice.not_null() && cb2.append_cellslice_bool(slice)) {
      auto boc = vm::std_boc_serialize(cb2.finalize());
      if (boc.is_ok()) {
        sb << "{\"@type\":\"tvm.stackEntrySlice\""
           << ",\"slice\":{\"@type\":\"tvm.slice\""
           << ",\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc.ok().as_slice()))) << "}}";
      } else {
        sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
      }
    } else {
      sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
    }
  } else if (entry.is_tuple()) {
    auto tuple = entry.as_tuple();
    sb << "{\"@type\":\"tvm.stackEntryTuple\""
       << ",\"tuple\":{\"@type\":\"tvm.tuple\",\"elements\":";
    serialize_stack_entries_std(sb, tuple);
    sb << "}}";
  } else if (entry.is_list()) {
    sb << "{\"@type\":\"tvm.stackEntryList\""
       << ",\"list\":{\"@type\":\"tvm.list\",\"elements\":[";
    auto cur = entry;
    bool first = true;
    while (cur.is_tuple()) {
      auto t = cur.as_tuple();
      if (t->size() != 2)
        break;
      if (!first)
        sb << ",";
      first = false;
      serialize_stack_entry_std(sb, (*t)[0]);
      cur = (*t)[1];
    }
    sb << "]}}";
  } else if (entry.is_null()) {
    sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
  } else {
    sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
  }
}

std::string format_block_id_json(const tos::lite_api::tosNode_blockIdExt &blk) {
  return PSTRING() << "{\"@type\":\"tos.blockIdExt\""
                   << ",\"workchain\":" << blk.workchain_ << ",\"shard\":\"" << blk.shard_ << "\""
                   << ",\"seqno\":" << blk.seqno_ << ",\"root_hash\":\"" << td::base64_encode(blk.root_hash_.as_slice())
                   << "\""
                   << ",\"file_hash\":\"" << td::base64_encode(blk.file_hash_.as_slice()) << "\""
                   << "}";
}

td::Result<std::string> render_run_method_result(const lite_api::liteServer_runMethodResult &answer,
                                                 RunResultFormat format) {
  auto stk_r = resolve_run_method_result_stack(answer.exit_code_, answer.result_.as_slice());
  if (stk_r.is_error()) {
    return td::Status::Error(-32603, PSTRING() << "result stack (exit_code " << answer.exit_code_ << ", result_bytes "
                                               << answer.result_.size() << "): " << stk_r.error());
  }
  auto stk = stk_r.move_as_ok();
  td::StringBuilder stack_sb;
  stack_sb << "[";
  for (int i = 0; i < (int)stk->depth(); i++) {
    if (i > 0)
      stack_sb << ",";
    if (format == RunResultFormat::Std) {
      serialize_stack_entry_std(stack_sb, stk->at(i));
    } else {
      serialize_stack_entry_legacy(stack_sb, stk->at(i));
    }
  }
  stack_sb << "]";
  std::string block_id_json = "null";
  if (answer.id_) {
    block_id_json = format_block_id_json(*answer.id_);
  }
  // liteServer.runMethodResult carries no gas figure; both endpoints report 0.
  return PSTRING() << "{\"@type\":\"smc.runResult\"" << ",\"gas_used\":0" << ",\"stack\":" << stack_sb.as_cslice()
                   << ",\"exit_code\":" << answer.exit_code_ << ",\"last_transaction_id\":null"
                   << ",\"block_id\":" << block_id_json << "}";
}

}  // namespace tos
