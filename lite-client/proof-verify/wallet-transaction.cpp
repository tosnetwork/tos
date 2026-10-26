/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <array>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/format.h"
#include "vm/boc.h"
#include "vm/dict.h"

#include "wallet-transaction.h"

namespace tos::proofverify {
namespace {

std::string quote(td::Slice text) {
  return PSTRING() << td::JsonString(text);
}

class Object {
 public:
  Object& raw(const char* key, td::Slice value) {
    text_ += first_ ? "" : ",";
    first_ = false;
    text_ += quote(td::Slice(key)) + ":";
    text_.append(value.data(), value.size());
    return *this;
  }
  Object& str(const char* key, td::Slice value) {
    return raw(key, quote(value));
  }
  template <class T>
  Object& num(const char* key, T value) {
    return raw(key, std::to_string(value));
  }
  Object& boolean(const char* key, bool value) {
    return raw(key, value ? td::Slice("true") : td::Slice("false"));
  }
  std::string finish() const {
    return "{" + text_ + "}";
  }

 private:
  std::string text_;
  bool first_{true};
};

std::string hex(td::Slice bytes) {
  return td::hex_encode(bytes);
}

// Bound count/bytes before the native cell allocator runs. Bound graph depth
// before materializing cells; the native decoder additionally validates exotic
// cells and their virtual depths/hashes. Opaque message bodies stay opaque.
td::Status preflight(td::Slice bytes) {
  if (bytes.empty() || bytes.size() > kMaxWalletTransactionBytes) {
    return td::Status::Error("wallet transaction byte limit");
  }
  vm::BagOfCells::Info header;
  if (header.parse_serialized_header(bytes) <= 0 || !header.valid || header.root_count != 1 ||
      header.absent_count != 0 || header.cell_count < 1 || header.cell_count > kMaxWalletTransactionCells ||
      header.total_size != bytes.size() || header.data_offset > bytes.size() ||
      header.data_size > bytes.size() - header.data_offset || header.ref_byte_size < 1 || header.ref_byte_size > 4) {
    return td::Status::Error("wallet transaction BOC header");
  }
  auto data = bytes.substr(static_cast<std::size_t>(header.data_offset), static_cast<std::size_t>(header.data_size));
  struct Links {
    std::array<int, 4> refs{};
    int count{0};
  };
  std::vector<Links> links(static_cast<std::size_t>(header.cell_count));
  std::size_t offset = 0;
  for (int i = 0; i < header.cell_count; ++i) {
    vm::CellSerializationInfo cell;
    TRY_STATUS(cell.init(data.substr(offset), header.ref_byte_size));
    if (cell.refs_cnt < 0 || cell.refs_cnt > 4 || cell.end_offset > data.size() - offset) {
      return td::Status::Error("wallet transaction cell bounds");
    }
    links[i].count = cell.refs_cnt;
    for (int j = 0; j < cell.refs_cnt; ++j) {
      auto reference = header.read_ref(data.ubegin() + offset + cell.refs_offset + j * header.ref_byte_size);
      if (reference <= static_cast<unsigned>(i) || reference >= static_cast<unsigned>(header.cell_count)) {
        return td::Status::Error("wallet transaction reference bounds");
      }
      links[i].refs[j] = static_cast<int>(reference);
    }
    offset += cell.end_offset;
  }
  if (offset != data.size()) {
    return td::Status::Error("wallet transaction cell bytes");
  }
  std::vector<int> depths(links.size());
  for (int i = header.cell_count - 1; i >= 0; --i) {
    int depth = 0;
    for (int j = 0; j < links[i].count; ++j) {
      if (depths[links[i].refs[j]] >= kMaxWalletTransactionDepth) {
        return td::Status::Error("wallet transaction graph depth");
      }
      depth = std::max(depth, depths[links[i].refs[j]] + 1);
    }
    depths[i] = depth;
  }
  return td::Status::OK();
}

std::string address_json(td::Ref<vm::CellSlice> address) {
  tos::WorkchainId workchain;
  tos::StdSmcAddress hash;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(std::move(address), workchain, hash)) {
    return "null";
  }
  return quote(std::to_string(workchain) + ":" + hex(hash.as_slice()));
}

td::Result<td::Ref<vm::Cell>> body_cell(td::Ref<vm::CellSlice> field) {
  if (field.is_null() || field->size() < 1) {
    return td::Status::Error("wallet message body selector");
  }
  vm::CellSlice body{*field};
  if (body.fetch_ulong(1)) {
    if (body.size() != 0 || body.size_refs() != 1) {
      return td::Status::Error("wallet message body reference");
    }
    return body.fetch_ref();
  }
  vm::CellBuilder builder;
  if (!builder.append_cellslice_bool(body)) {
    return td::Status::Error("wallet inline message body");
  }
  return builder.finalize();
}

td::Result<std::string> message_json(td::Ref<vm::Cell> cell) {
  td::Ref<vm::CellSlice> info, init, body;
  if (cell.is_null() || !block::gen::t_Message_Any.cell_unpack_message(cell, info, init, body) || info.is_null()) {
    return td::Status::Error("wallet transaction message");
  }
  TRY_RESULT(payload, body_cell(std::move(body)));
  Object result;
  result.str("hash", hex(cell->get_hash(0).as_slice())).str("body_hash", hex(payload->get_hash(0).as_slice()));
  switch (block::gen::CommonMsgInfo().get_tag(*info)) {
    case block::gen::CommonMsgInfo::int_msg_info: {
      block::gen::CommonMsgInfo::Record_int_msg_info value;
      block::CurrencyCollection currency;
      if (!tlb::csr_unpack(std::move(info), value) || !currency.unpack(value.value)) {
        return td::Status::Error("wallet internal message");
      }
      result.str("kind", "internal")
          .raw("source", address_json(value.src))
          .raw("destination", address_json(value.dest))
          .str("value", currency.tomis->to_dec_string())
          .boolean("other_currencies", currency.extra.not_null())
          .boolean("bounced", value.bounced)
          .boolean("bounce", value.bounce)
          .str("created_lt", std::to_string(value.created_lt))
          .num("created_at", value.created_at);
      break;
    }
    case block::gen::CommonMsgInfo::ext_in_msg_info: {
      block::gen::CommonMsgInfo::Record_ext_in_msg_info value;
      if (!tlb::csr_unpack(std::move(info), value)) {
        return td::Status::Error("wallet external input message");
      }
      result.str("kind", "external_in").raw("destination", address_json(value.dest));
      break;
    }
    case block::gen::CommonMsgInfo::ext_out_msg_info: {
      block::gen::CommonMsgInfo::Record_ext_out_msg_info value;
      if (!tlb::csr_unpack(std::move(info), value)) {
        return td::Status::Error("wallet external output message");
      }
      result.str("kind", "external_out").raw("source", address_json(value.src));
      break;
    }
    default:
      return td::Status::Error("wallet message type");
  }
  return result.finish();
}

td::Result<std::string> compute_json(td::Ref<vm::CellSlice> phase) {
  if (phase.is_null()) {
    return td::Status::Error("wallet transaction compute phase");
  }
  auto slice = *phase;
  if (block::gen::t_TrComputePhase.get_tag(slice) == block::gen::TrComputePhase::tr_phase_compute_vm) {
    block::gen::TrComputePhase::Record_tr_phase_compute_vm value;
    if (!block::gen::t_TrComputePhase.unpack(slice, value)) {
      return td::Status::Error("wallet VM compute phase");
    }
    return Object{}
        .boolean("skipped", false)
        .boolean("success", value.success)
        .num("exit_code", value.r1.exit_code)
        .finish();
  }
  block::gen::TrComputePhase::Record_tr_phase_compute_skipped value;
  if (!block::gen::t_TrComputePhase.unpack(slice, value)) {
    return td::Status::Error("wallet skipped compute phase");
  }
  return Object{}.boolean("skipped", true).num("reason", static_cast<int>(value.reason)).finish();
}

td::Result<std::string> action_json(td::Ref<vm::CellSlice> field) {
  if (field.is_null() || field->size() != 1) {
    return td::Status::Error("wallet transaction action selector");
  }
  if (!field->prefetch_ulong(1)) {
    if (field->size_refs() != 0) {
      return td::Status::Error("wallet absent action phase");
    }
    return std::string("null");
  }
  block::gen::TrActionPhase::Record value;
  if (field->size_refs() != 1 || !block::gen::t_TrActionPhase.cell_unpack(field->prefetch_ref(), value)) {
    return td::Status::Error("wallet transaction action phase");
  }
  return Object{}
      .boolean("success", value.success)
      .boolean("valid", value.valid)
      .boolean("no_funds", value.no_funds)
      .num("result_code", value.result_code)
      .num("skipped_actions", value.skipped_actions)
      .num("messages_created", value.msgs_created)
      .finish();
}

}  // namespace

td::Result<std::string> verify_wallet_transaction(td::Slice account_hash, td::uint64 logical_time,
                                                  td::Slice transaction_hash, td::Slice bytes) {
  if (account_hash.size() != 32 || transaction_hash.size() != 32 || logical_time == 0) {
    return td::Status::Error("wallet transaction binding");
  }
  TRY_STATUS(preflight(bytes));
  vm::BagOfCells boc;
  TRY_RESULT(consumed, boc.deserialize(bytes, 1));
  auto root = boc.get_root_cell();
  if (consumed != static_cast<long long>(bytes.size()) || root.is_null() || root->get_level() != 0 ||
      root->get_depth() > kMaxWalletTransactionDepth || root->get_hash(0).as_slice() != transaction_hash) {
    return td::Status::Error("wallet transaction hash");
  }
  // Unpacking is lazy across references. Validate the full transaction schema
  // first, including state updates, nonordinary descriptions and dictionary
  // leaves. Any message body remains opaque. The independent operation budget
  // also bounds repeated visits through shared subgraphs.
  if (!block::gen::t_Transaction.validate_ref(65536, root)) {
    return td::Status::Error("wallet transaction layout");
  }
  block::gen::Transaction::Record tx;
  if (!tlb::unpack_cell(root, tx) || tx.account_addr.as_slice() != account_hash || tx.lt != logical_time ||
      tx.prev_trans_lt >= tx.lt || (tx.prev_trans_lt == 0) != tx.prev_trans_hash.is_zero() ||
      tx.outmsg_cnt > kMaxWalletTransactionMessages) {
    return td::Status::Error("wallet transaction fields");
  }
  block::CurrencyCollection fees;
  if (!fees.unpack(tx.total_fees)) {
    return td::Status::Error("wallet transaction fees");
  }
  Object result;
  result.str("interface", "tos-wallet-transaction/1")
      .str("account", "0:" + hex(account_hash))
      .str("hash", hex(transaction_hash))
      .str("lt", std::to_string(tx.lt))
      .str("previous_hash", hex(tx.prev_trans_hash.as_slice()))
      .str("previous_lt", std::to_string(tx.prev_trans_lt))
      .num("timestamp", tx.now)
      .str("fees", fees.tomis->to_dec_string())
      .boolean("other_fee_currencies", fees.extra.not_null());
  if (tx.r1.in_msg->prefetch_ulong(1)) {
    TRY_RESULT(input, message_json(tx.r1.in_msg->prefetch_ref()));
    result.raw("in_msg", input);
  } else {
    result.raw("in_msg", "null");
  }
  vm::Dictionary dictionary{tx.r1.out_msgs, 15};
  int count = 0;
  if (!dictionary.check_for_each([&](auto, auto, int) { return ++count <= tx.outmsg_cnt; }) || count != tx.outmsg_cnt) {
    return td::Status::Error("wallet transaction output count");
  }
  std::string outputs = "[";
  for (int i = 0; i < tx.outmsg_cnt; ++i) {
    auto cell = dictionary.lookup_ref(td::BitArray<15>{i});
    if (cell.is_null()) {
      return td::Status::Error("wallet transaction output index");
    }
    TRY_RESULT(output, message_json(std::move(cell)));
    outputs += i ? "," : "";
    outputs += output;
  }
  result.raw("out_msgs", outputs + "]");
  if (block::gen::t_TransactionDescr.get_tag(vm::load_cell_slice(tx.description)) ==
      block::gen::TransactionDescr::trans_ord) {
    block::gen::TransactionDescr::Record_trans_ord description;
    if (!tlb::unpack_cell(tx.description, description)) {
      return td::Status::Error("wallet ordinary transaction description");
    }
    TRY_RESULT(compute, compute_json(description.compute_ph));
    TRY_RESULT(action, action_json(description.action));
    result.str("type", "ordinary")
        .boolean("aborted", description.aborted)
        .boolean("destroyed", description.destroyed)
        .raw("compute", compute)
        .raw("action", action);
  } else {
    result.str("type", "other");
  }
  auto rendered = result.finish();
  if (rendered.size() > kMaxWalletTransactionResultBytes) {
    return td::Status::Error("wallet transaction result limit");
  }
  return rendered;
}

}  // namespace tos::proofverify
