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

namespace tos {

namespace {

void append_message_summary(td::StringBuilder &sb, td::Ref<vm::Cell> message_cell) {
  sb << "{";
  if (message_cell.is_null()) {
    sb << "\"kind\":\"unknown\"}";
    return;
  }
  sb << "\"hash\":\"" << td::base64_encode(message_cell->get_hash(0).as_slice()) << "\"";
  td::Ref<vm::CellSlice> info_cs, init_cs, body_cs;
  if (!block::gen::t_Message_Any.cell_unpack_message(
          message_cell, info_cs, init_cs, body_cs) || info_cs.is_null()) {
    sb << ",\"kind\":\"unknown\"}";
    return;
  }
  auto tag = block::gen::CommonMsgInfo().get_tag(*info_cs);
  if (tag != block::gen::CommonMsgInfo::int_msg_info) {
    sb << ",\"kind\":\"external\"}";
    return;
  }
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(std::move(info_cs), info)) {
    sb << ",\"kind\":\"unknown\"}";
    return;
  }
  tos::WorkchainId source_wc, destination_wc;
  tos::StdSmcAddress source, destination;
  block::CurrencyCollection value;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(info.src, source_wc, source) ||
      !block::tlb::t_MsgAddressInt.extract_std_address(info.dest, destination_wc, destination) ||
      !value.unpack(info.value)) {
    sb << ",\"kind\":\"internal\"}";
    return;
  }
  block::StdAddress source_address(source_wc, source);
  block::StdAddress destination_address(destination_wc, destination);
  sb << ",\"kind\":\"internal\""
     << ",\"source\":" << td::JsonString(source_address.rserialize(true))
     << ",\"destination\":" << td::JsonString(destination_address.rserialize(true))
     << ",\"value\":\"" << value.tomis->to_dec_string() << "\""
     << ",\"bounced\":" << (info.bounced ? "true" : "false")
     << ",\"created_lt\":\"" << info.created_lt << "\""
     << ",\"created_at\":" << info.created_at << "}";
}

void append_transaction_messages(td::StringBuilder &sb,
                                 const block::gen::Transaction::Record &tx) {
  sb << ",\"in_msg\":";
  if (tx.r1.in_msg->prefetch_long(1) == -1) {
    append_message_summary(sb, tx.r1.in_msg->prefetch_ref());
  } else {
    sb << "null";
  }
  sb << ",\"out_msgs\":[";
  vm::Dictionary dictionary{tx.r1.out_msgs, 15};
  bool first = true;
  for (int index = 0; index < tx.outmsg_cnt; ++index) {
    auto message = dictionary.lookup_ref(td::BitArray<15>{index});
    if (message.is_null()) {
      continue;
    }
    if (!first) {
      sb << ",";
    }
    first = false;
    append_message_summary(sb, message);
  }
  sb << "]";
}

void append_compute_phase(td::StringBuilder &sb, td::Ref<vm::CellSlice> phase) {
  sb << ",\"compute\":";
  if (phase.is_null()) {
    sb << "null";
    return;
  }
  auto tag = block::gen::t_TrComputePhase.get_tag(*phase);
  if (tag == block::gen::TrComputePhase::tr_phase_compute_vm) {
    block::gen::TrComputePhase::Record_tr_phase_compute_vm compute;
    auto slice = *phase;
    if (block::gen::t_TrComputePhase.unpack(slice, compute)) {
      sb << "{\"skipped\":false"
         << ",\"success\":" << (compute.success ? "true" : "false")
         << ",\"exit_code\":" << compute.r1.exit_code
         << ",\"vm_steps\":" << compute.r1.vm_steps
         << ",\"account_activated\":"
         << (compute.account_activated ? "true" : "false") << "}";
      return;
    }
  } else {
    block::gen::TrComputePhase::Record_tr_phase_compute_skipped skipped;
    auto slice = *phase;
    if (block::gen::t_TrComputePhase.unpack(slice, skipped)) {
      sb << "{\"skipped\":true,\"skip_reason\":"
         << static_cast<int>(skipped.reason) << "}";
      return;
    }
  }
  sb << "null";
}

void append_action_phase(td::StringBuilder &sb, td::Ref<vm::CellSlice> maybe_action) {
  sb << ",\"action\":";
  if (maybe_action.is_null()) {
    sb << "null";
    return;
  }
  auto action_cell = maybe_action->prefetch_ref();
  block::gen::TrActionPhase::Record action;
  if (action_cell.is_null() ||
      !block::gen::t_TrActionPhase.cell_unpack(std::move(action_cell), action)) {
    sb << "null";
    return;
  }
  sb << "{\"success\":" << (action.success ? "true" : "false")
     << ",\"valid\":" << (action.valid ? "true" : "false")
     << ",\"no_funds\":" << (action.no_funds ? "true" : "false")
     << ",\"result_code\":" << action.result_code
     << ",\"total_actions\":" << action.tot_actions
     << ",\"skipped_actions\":" << action.skipped_actions
     << ",\"messages_created\":" << action.msgs_created << "}";
}

void append_transaction_execution(td::StringBuilder &sb,
                                  const block::gen::Transaction::Record &tx) {
  auto tag = block::gen::t_TransactionDescr.get_tag(vm::load_cell_slice(tx.description));
  sb << ",\"transaction_type\":";
  switch (tag) {
    case block::gen::TransactionDescr::trans_ord: {
      block::gen::TransactionDescr::Record_trans_ord description;
      if (!tlb::unpack_cell(tx.description, description)) {
        sb << "\"ordinary\",\"aborted\":null,\"destroyed\":null";
        return;
      }
      sb << "\"ordinary\""
         << ",\"aborted\":" << (description.aborted ? "true" : "false")
         << ",\"destroyed\":" << (description.destroyed ? "true" : "false");
      append_compute_phase(sb, description.compute_ph);
      append_action_phase(sb, description.action);
      return;
    }
    case block::gen::TransactionDescr::trans_storage:
      sb << "\"storage\"";
      return;
    case block::gen::TransactionDescr::trans_tick_tock: {
      block::gen::TransactionDescr::Record_trans_tick_tock description;
      if (!tlb::unpack_cell(tx.description, description)) {
        sb << "\"tick_tock\"";
        return;
      }
      sb << (description.is_tock ? "\"tock\"" : "\"tick\"")
         << ",\"aborted\":" << (description.aborted ? "true" : "false")
         << ",\"destroyed\":" << (description.destroyed ? "true" : "false");
      append_compute_phase(sb, description.compute_ph);
      append_action_phase(sb, description.action);
      return;
    }
    case block::gen::TransactionDescr::trans_split_prepare:
      sb << "\"split_prepare\"";
      return;
    case block::gen::TransactionDescr::trans_split_install:
      sb << "\"split_install\"";
      return;
    case block::gen::TransactionDescr::trans_merge_prepare:
      sb << "\"merge_prepare\"";
      return;
    case block::gen::TransactionDescr::trans_merge_install:
      sb << "\"merge_install\"";
      return;
    default:
      sb << "\"unknown\"";
  }
}

}  // namespace

// ─── getBlockTransactions ────────────────────────────────────────────────

void JsonRpcServer::handle_getBlockTransactions(td::JsonObject &params, std::string req_id,
                                                td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  auto shard_r = params.get_required_string_field("shard");
  auto seqno_r = params.get_required_int_field("seqno");
  if (wc_r.is_error() || shard_r.is_error() || seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        "Missing 'workchain', 'shard', or 'seqno'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);
  td::int32 seqno = seqno_r.ok();

  td::int32 count = 40;
  auto count_r = params.get_optional_int_field("count");
  if (count_r.is_ok() && count_r.ok() > 0) {
    count = std::min(static_cast<td::int32>(count_r.ok()), static_cast<td::int32>(256));
  }

  // Parse optional after_lt and after_account for pagination. Older clients
  // sent the account cursor under the misleading `after_hash` name, so keep
  // that alias while preferring the accurately named field.
  td::int64 after_lt = 0;
  td::Bits256 after_account = td::Bits256::zero();
  td::int32 mode = 0x07;  // account + lt + hash in results
  auto after_lt_r = params.get_optional_string_field("after_lt");
  auto after_account_r = params.get_optional_string_field("after_account");
  if (after_account_r.is_error() || after_account_r.ok().empty()) {
    after_account_r = params.get_optional_string_field("after_hash");
  }
  if (after_lt_r.is_ok() && !after_lt_r.ok().empty()) {
    after_lt = std::strtoll(after_lt_r.ok().c_str(), nullptr, 10);
    mode |= 0x80;  // AFTER_MASK — use after cursor
    if (after_account_r.is_ok() && !after_account_r.ok().empty()) {
      auto decoded = td::base64_decode(after_account_r.ok());
      if (decoded.is_error() || decoded.ok().size() != 32) {
        decoded = td::hex_decode(after_account_r.ok());
      }
      if (decoded.is_ok() && decoded.ok().size() == 32) {
        after_account.as_slice().copy_from(decoded.ok());
      }
    }
  }

  // Step 1: lookup block
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(workchain, shard, seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [cors = opts_.cors_origin, req_id = std::move(req_id), self_id, count, mode, after_lt, after_account,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id, cors));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id, cors));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto resolved_id = std::move(lb->id_);
        auto resolved_id_json = format_block_id_json(*resolved_id);

        // Step 2: list block transactions
        tos::tl_object_ptr<tos::lite_api::liteServer_transactionId3> after;
        if (mode & 0x80) {
          after = tos::create_tl_object<tos::lite_api::liteServer_transactionId3>(
              after_account, after_lt);
        }

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_listBlockTransactions>(
                std::move(resolved_id), mode, count, std::move(after),
                false, false),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, req_id = std::move(req_id), id_json = std::move(resolved_id_json),
                 promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "listBlockTransactions: " << R.error(), req_id, cors));
            return;
          }
          auto bt_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockTransactions>(
              R.move_as_ok(), true);
          if (bt_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse blockTransactions: " << bt_r.error(), req_id, cors));
            return;
          }
          auto bt = bt_r.move_as_ok();

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.transactions\""
             << ",\"id\":" << id_json
             << ",\"req_count\":" << bt->req_count_
             << ",\"incomplete\":" << (bt->incomplete_ ? "true" : "false")
             << ",\"transactions\":[";
          for (size_t i = 0; i < bt->ids_.size(); i++) {
            if (i > 0) sb << ",";
            auto& tid = bt->ids_[i];
            sb << "{\"@type\":\"blocks.shortTxId\"";
            if (tid->mode_ & 0x01) {
              sb << ",\"account\":\"" << tid->account_.to_hex() << "\"";
            }
            if (tid->mode_ & 0x02) {
              sb << ",\"lt\":\"" << tid->lt_ << "\"";
            }
            if (tid->mode_ & 0x04) {
              sb << ",\"hash\":\"" << td::base64_encode(tid->hash_.as_slice()) << "\"";
            }
            sb << "}";
          }
          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
        }));
      });
}

// ─── getBlockTransactionsExt ─────────────────────────────────────────────
// Returns full transaction BOCs per block (richer than getBlockTransactions)

void JsonRpcServer::handle_getBlockTransactionsExt(td::JsonObject &params, std::string req_id,
                                                   td::Promise<HttpReturn> promise) {
  auto wc_r = params.get_required_int_field("workchain");
  auto shard_r = params.get_required_string_field("shard");
  auto seqno_r = params.get_required_int_field("seqno");
  if (wc_r.is_error() || shard_r.is_error() || seqno_r.is_error()) {
    promise.set_value(make_json_error(-32602,
        "Missing 'workchain', 'shard', or 'seqno'", req_id));
    return;
  }
  td::int32 workchain = wc_r.ok();
  td::int64 shard = std::strtoll(shard_r.ok().c_str(), nullptr, 10);
  td::int32 seqno = seqno_r.ok();

  td::int32 count = 40;
  auto count_r = params.get_optional_int_field("count");
  if (count_r.is_ok() && count_r.ok() > 0) {
    count = std::min(static_cast<td::int32>(count_r.ok()), static_cast<td::int32>(256));
  }

  // Parse optional after_lt and after_account for pagination (with the old
  // `after_hash` alias retained for compatibility).
  td::int64 after_lt = 0;
  td::Bits256 after_account = td::Bits256::zero();
  td::int32 mode = 0x07;  // account + lt + hash
  auto after_lt_r = params.get_optional_string_field("after_lt");
  auto after_account_r = params.get_optional_string_field("after_account");
  if (after_account_r.is_error() || after_account_r.ok().empty()) {
    after_account_r = params.get_optional_string_field("after_hash");
  }
  if (after_lt_r.is_ok() && !after_lt_r.ok().empty()) {
    after_lt = std::strtoll(after_lt_r.ok().c_str(), nullptr, 10);
    mode |= 0x80;  // AFTER_MASK
    if (after_account_r.is_ok() && !after_account_r.ok().empty()) {
      auto decoded = td::base64_decode(after_account_r.ok());
      if (decoded.is_error() || decoded.ok().size() != 32) {
        decoded = td::hex_decode(after_account_r.ok());
      }
      if (decoded.is_ok() && decoded.ok().size() == 32) {
        after_account.as_slice().copy_from(decoded.ok());
      }
    }
  }

  // Step 1: lookup block
  auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(workchain, shard, seqno);
  auto lookup_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
          1, std::move(block_id), 0, 0),
      true);
  auto lookup_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(lookup_query),
      [cors = opts_.cors_origin, req_id = std::move(req_id), self_id, count, mode, after_lt, after_account,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "lookupBlock: " << R.error(), req_id, cors));
          return;
        }
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id, cors));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto resolved_id = std::move(lb->id_);
        auto resolved_id_json = format_block_id_json(*resolved_id);

        // Step 2: list block transactions (extended)
        tos::tl_object_ptr<tos::lite_api::liteServer_transactionId3> after;
        if (mode & 0x80) {
          after = tos::create_tl_object<tos::lite_api::liteServer_transactionId3>(
              after_account, after_lt);
        }

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_listBlockTransactionsExt>(
                std::move(resolved_id), mode, count, std::move(after),
                false, false),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, req_id = std::move(req_id), id_json = std::move(resolved_id_json),
                 promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "listBlockTransactionsExt: " << R.error(), req_id, cors));
            return;
          }
          auto bt_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockTransactionsExt>(
              R.move_as_ok(), true);
          if (bt_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse blockTransactionsExt: " << bt_r.error(), req_id, cors));
            return;
          }
          auto bt = bt_r.move_as_ok();

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.transactionsExt\""
             << ",\"id\":" << id_json
             << ",\"req_count\":" << bt->req_count_
             << ",\"incomplete\":" << (bt->incomplete_ ? "true" : "false")
             << ",\"transactions\":[";

          // Parse individual transactions from the BOC
          if (!bt->transactions_.empty()) {
            auto roots_r = vm::std_boc_deserialize_multi(bt->transactions_.as_slice());
            if (roots_r.is_ok()) {
              auto roots = roots_r.move_as_ok();
              for (size_t i = 0; i < roots.size(); i++) {
                if (i > 0) sb << ",";
                sb << "{\"@type\":\"raw.transaction\"";

                // Serialize individual transaction as base64 BOC
                auto boc_r = vm::std_boc_serialize(roots[i]);
                if (boc_r.is_ok()) {
                  sb << ",\"data\":\"" << td::base64_encode(boc_r.ok().as_slice()) << "\"";
                }

                // Extract basic fields from Transaction TLB
                block::gen::Transaction::Record tx;
                if (tlb::unpack_cell(roots[i], tx)) {
                  sb << ",\"account\":\"" << tx.account_addr.to_hex() << "\""
                     << ",\"lt\":\"" << tx.lt << "\""
                     << ",\"utime\":" << tx.now;
                  auto hash = roots[i]->get_hash(0);
                  sb << ",\"hash\":\"" << td::base64_encode(hash.as_slice()) << "\"";
                  // Parsed fields for wallet tracking
                  block::CurrencyCollection total_fees;
                  if (total_fees.unpack(tx.total_fees)) {
                    sb << ",\"fee\":\"" << total_fees.tomis->to_dec_string() << "\"";
                  }
                  if (tx.r1.in_msg->prefetch_long(1) == -1) {
                    auto msg_cell = tx.r1.in_msg->prefetch_ref();
                    if (msg_cell.not_null()) {
                      sb << ",\"in_msg_hash\":\""
                         << td::base64_encode(msg_cell->get_hash(0).as_slice()) << "\"";
                    }
                  }
                  append_transaction_messages(sb, tx);
                  append_transaction_execution(sb, tx);
                }
                sb << "}";
              }
            }
          }

          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
        }));
      });
}

// ─── getTransactions ────────────────────────────────────────────────────

void JsonRpcServer::handle_getTransactions(td::JsonObject &params, std::string req_id,
                                           td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  td::int32 limit = 10;
  auto limit_r = params.get_optional_int_field("limit");
  if (limit_r.is_ok() && limit_r.ok() > 0) {
    limit = std::min(static_cast<td::int32>(limit_r.ok()), static_cast<td::int32>(100));
  }

  // lt and hash are optional — when omitted, auto-lookup from account state
  td::int64 lt = 0;
  td::Bits256 hash = td::Bits256::zero();
  bool has_lt = false;
  bool has_hash = false;

  auto lt_r = params.get_optional_string_field("lt");
  if (lt_r.is_ok() && !lt_r.ok().empty()) {
    lt = std::strtoll(lt_r.ok().c_str(), nullptr, 10);
    has_lt = true;
  }

  auto hash_r = params.get_optional_string_field("hash");
  if (hash_r.is_ok() && !hash_r.ok().empty()) {
    auto hash_decoded = td::base64_decode(hash_r.ok());
    if (hash_decoded.is_ok() && hash_decoded.ok().size() == 32) {
      hash.as_slice().copy_from(hash_decoded.ok());
      has_hash = true;
    } else {
      auto hex_r = td::hex_decode(td::Slice(hash_r.ok()));
      if (hex_r.is_ok() && hex_r.ok().size() == 32) {
        hash.as_slice().copy_from(hex_r.ok());
        has_hash = true;
      }
    }
  }

  // Shared result formatter: parse transactionList into a JSON array
  auto format_result = [cors = opts_.cors_origin](td::Result<td::BufferSlice> R, std::string req_id,
                          td::Promise<HttpReturn> promise) {
    if (R.is_error()) {
      promise.set_value(make_json_error(-32603,
          PSTRING() << "getTransactions: " << R.error(), req_id, cors));
      return;
    }
    auto tl_r = tos::fetch_tl_object<tos::lite_api::liteServer_transactionList>(
        R.move_as_ok(), true);
    if (tl_r.is_error()) {
      promise.set_value(make_json_error(-32603,
          PSTRING() << "parse transactionList: " << tl_r.error(), req_id, cors));
      return;
    }
    auto tl = tl_r.move_as_ok();

    td::StringBuilder sb;
    sb << "[";
    if (!tl->transactions_.empty()) {
      auto root_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
      if (root_r.is_ok()) {
        auto roots = root_r.move_as_ok();
        for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
          if (i > 0) sb << ",";
          sb << "{\"@type\":\"raw.transaction\"";
          sb << ",\"block_id\":" << format_block_id_json(*tl->ids_[i]);
          auto boc_r = vm::std_boc_serialize(roots[i]);
          if (boc_r.is_ok()) {
            sb << ",\"data\":\"" << td::base64_encode(boc_r.ok().as_slice()) << "\"";
          }
          block::gen::Transaction::Record tx;
          if (tlb::unpack_cell(roots[i], tx)) {
            sb << ",\"utime\":" << tx.now;
            auto hash = roots[i]->get_hash(0);
            sb << ",\"transaction_id\":{\"@type\":\"internal.transactionId\""
               << ",\"lt\":\"" << tx.lt << "\""
               << ",\"hash\":\"" << td::base64_encode(hash.as_slice()) << "\"}";
            // Parsed fields for wallet tracking
            block::CurrencyCollection total_fees;
            if (total_fees.unpack(tx.total_fees)) {
              sb << ",\"fee\":\"" << total_fees.tomis->to_dec_string() << "\"";
            }
            sb << ",\"account\":\"" << tx.account_addr.to_hex() << "\"";
            if (tx.r1.in_msg->prefetch_long(1) == -1) {
              auto msg_cell = tx.r1.in_msg->prefetch_ref();
              if (msg_cell.not_null()) {
                sb << ",\"in_msg_hash\":\""
                   << td::base64_encode(msg_cell->get_hash(0).as_slice()) << "\"";
              }
            }
            append_transaction_messages(sb, tx);
            append_transaction_execution(sb, tx);
          }
          sb << "}";
        }
      }
    }
    sb << "]";
    promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
  };

  // lt and hash must be used together when provided
  if (has_lt != has_hash) {
    promise.set_value(make_json_error(-32602, "lt and hash should be used together", req_id));
    return;
  }

  // If both lt and hash provided, query directly
  if (has_lt && has_hash) {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
            limit,
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr),
            lt, hash),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    send_liteserver_query(std::move(query),
        [req_id = std::move(req_id), promise = std::move(promise),
         format_result](td::Result<td::BufferSlice> R) mutable {
          format_result(std::move(R), std::move(req_id), std::move(promise));
        });
    return;
  }

  // No lt/hash — first get account state to find last_trans_lt/hash
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [cors = opts_.cors_origin, addr, limit, req_id = std::move(req_id), self_id,
       promise = std::move(promise), format_result](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id, cors));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc_r.error(), req_id, cors));
          return;
        }
        auto mc = mc_r.move_as_ok();

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, addr, limit, req_id = std::move(req_id), self_id,
                 promise = std::move(promise), format_result](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id, cors));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id, cors));
            return;
          }
          auto f = F.move_as_ok();
          auto parsed = ParsedAccountState::parse(f, addr);
          if (parsed.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse account: " << parsed.error(), req_id, cors));
            return;
          }
          auto ps = parsed.move_as_ok();

          if (ps.last_trans_lt == 0) {
            promise.set_value(make_json_ok("[]", req_id, cors));
            return;
          }

          td::Bits256 last_hash;
          auto hash_dec = td::base64_decode(ps.last_trans_hash_b64);
          if (hash_dec.is_ok() && hash_dec.ok().size() == 32) {
            last_hash.as_slice().copy_from(hash_dec.ok());
          }

          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  limit,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      addr.workchain, addr.addr),
                  static_cast<td::int64>(ps.last_trans_lt), last_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [req_id = std::move(req_id), promise = std::move(promise),
                   format_result](td::Result<td::BufferSlice> R) mutable {
            format_result(std::move(R), std::move(req_id), std::move(promise));
          }));
        }));
      });
}

// ─── Transaction lookup helpers ─────────────────────────────────────────
// Shared by tryLocateTx, tryLocateResultTx, tryLocateSourceTx.

// Parse the three common parameters: source, destination, created_lt.
struct LocateParams {
  block::StdAddress source;
  block::StdAddress destination;
  td::uint64 created_lt;
};

static td::Result<LocateParams> parse_locate_params(td::JsonObject &params) {
  auto src_r = params.get_required_string_field("source");
  if (src_r.is_error()) return td::Status::Error("Missing 'source'");
  auto dst_r = params.get_required_string_field("destination");
  if (dst_r.is_error()) return td::Status::Error("Missing 'destination'");
  auto lt_r = params.get_required_string_field("created_lt");
  if (lt_r.is_error()) return td::Status::Error("Missing 'created_lt'");

  LocateParams lp;
  if (!lp.source.parse_addr(td::Slice(src_r.ok())))
    return td::Status::Error("Invalid 'source' address");
  if (!lp.destination.parse_addr(td::Slice(dst_r.ok())))
    return td::Status::Error("Invalid 'destination' address");
  lp.created_lt = std::strtoull(lt_r.ok().c_str(), nullptr, 10);
  if (lp.created_lt == 0)
    return td::Status::Error("Invalid 'created_lt' (must be > 0)");
  return lp;
}

// Extract source address from a message cell.  Returns false if the message
// is not an internal message or cannot be parsed.
static bool msg_get_src_addr(td::Ref<vm::Cell> msg_cell, block::StdAddress &out) {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) return false;
  auto tag = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (tag != block::gen::CommonMsgInfo::int_msg_info) return false;
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(message.info, info)) return false;
  block::gen::MsgAddressInt::Record_addr_std addr;
  if (!tlb::csr_unpack(info.src, addr)) return false;
  out.workchain = addr.workchain_id;
  out.addr = addr.address;
  return true;
}

// Extract destination address from a message cell.
static bool msg_get_dst_addr(td::Ref<vm::Cell> msg_cell, block::StdAddress &out) {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) return false;
  auto tag = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (tag != block::gen::CommonMsgInfo::int_msg_info) return false;
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(message.info, info)) return false;
  block::gen::MsgAddressInt::Record_addr_std addr;
  if (!tlb::csr_unpack(info.dest, addr)) return false;
  out.workchain = addr.workchain_id;
  out.addr = addr.address;
  return true;
}

// Extract created_lt from a message cell (internal messages only).
static bool msg_get_created_lt(td::Ref<vm::Cell> msg_cell, td::uint64 &out) {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) return false;
  auto tag = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (tag != block::gen::CommonMsgInfo::int_msg_info) return false;
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(message.info, info)) return false;
  out = info.created_lt;
  return true;
}

// Build a "blocks.transaction" JSON result from a matching transaction root cell
// and its block ID.
static std::string format_located_tx_json(
    const block::StdAddress &source,
    const block::StdAddress &destination,
    td::Ref<vm::Cell> tx_root,
    const tos::lite_api::tosNode_blockIdExt &blk) {
  block::gen::Transaction::Record tx;
  td::uint64 lt = 0;
  if (tlb::unpack_cell(tx_root, tx)) {
    lt = tx.lt;
  }
  auto hash_b64 = td::base64_encode(tx_root->get_hash(0).as_slice());

  return PSTRING()
      << "{\"@type\":\"blocks.transaction\""
      << ",\"source\":" << td::JsonString(td::Slice(source.rserialize(true)))
      << ",\"destination\":" << td::JsonString(td::Slice(destination.rserialize(true)))
      << ",\"lt\":\"" << lt << "\""
      << ",\"hash\":\"" << hash_b64 << "\""
      << ",\"block_id\":" << format_block_id_json(blk)
      << "}";
}

// ─── tryLocateTx ────────────────────────────────────────────────────────
// Locate a transaction on the destination account that has an incoming
// message matching (source, created_lt).

void JsonRpcServer::handle_tryLocateTx(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto lp_r = parse_locate_params(params);
  if (lp_r.is_error()) {
    promise.set_value(make_json_error(-32602, lp_r.error().message().str(), req_id));
    return;
  }
  auto lp = lp_r.move_as_ok();

  // Step 1: Get account state to find last transaction lt/hash
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [cors = opts_.cors_origin, lp, req_id = std::move(req_id), self_id,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id, cors));
          return;
        }
        auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc.error(), req_id, cors));
          return;
        }

        // Get account state for destination to find last transaction
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    lp.destination.workchain, lp.destination.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, lp, req_id = std::move(req_id), self_id,
                 promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id, cors));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id, cors));
            return;
          }
          auto f = F.move_as_ok();

          // Validate and extract last_trans_lt, last_trans_hash
          auto blk_id = tos::create_block_id(f->id_);
          auto shard_blk_id = tos::create_block_id(f->shardblk_);
          block::AccountState as;
          as.blk = blk_id;
          as.shard_blk = shard_blk_id;
          as.shard_proof = f->shard_proof_.clone();
          as.proof = f->proof_.clone();
          as.state = f->state_.clone();
          auto info_r = as.validate(blk_id, lp.destination);
          if (info_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "validate account state: " << info_r.error(), req_id, cors));
            return;
          }
          auto info = info_r.move_as_ok();
          if (info.last_trans_lt == 0) {
            promise.set_value(make_json_error(-32603,
                "Destination account has no transactions", req_id, cors));
            return;
          }

          // Step 2: Get last 20 transactions for the destination account
          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  20,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      lp.destination.workchain, lp.destination.addr),
                  static_cast<td::int64>(info.last_trans_lt), info.last_trans_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [cors, lp, req_id = std::move(req_id),
                   promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "getTransactions: " << R.error(), req_id, cors));
              return;
            }
            auto tl_r = tos::fetch_tl_object<tos::lite_api::liteServer_transactionList>(
                R.move_as_ok(), true);
            if (tl_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "parse transactionList: " << tl_r.error(), req_id, cors));
              return;
            }
            auto tl = tl_r.move_as_ok();

            if (tl->transactions_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "Transaction not found in recent history", req_id, cors));
              return;
            }

            auto roots_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
            if (roots_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "Failed to deserialize transactions BOC", req_id, cors));
              return;
            }
            auto roots = roots_r.move_as_ok();

            // Search for a transaction whose in_msg has matching source + created_lt
            for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
              block::gen::Transaction::Record tx;
              if (!tlb::unpack_cell(roots[i], tx)) continue;

              // Check in_msg (Maybe ^Message)
              auto is_just = tx.r1.in_msg->prefetch_long(1);
              if (is_just != -1) continue;  // no in_msg

              auto msg_cell = tx.r1.in_msg->prefetch_ref();
              if (msg_cell.is_null()) continue;

              block::StdAddress msg_src;
              td::uint64 msg_lt = 0;
              if (!msg_get_src_addr(msg_cell, msg_src)) continue;
              if (!msg_get_created_lt(msg_cell, msg_lt)) continue;

              if (msg_src.workchain == lp.source.workchain &&
                  msg_src.addr == lp.source.addr &&
                  msg_lt == lp.created_lt) {
                // Found the matching transaction
                promise.set_value(make_json_ok(
                    format_located_tx_json(lp.source, lp.destination, roots[i], *tl->ids_[i]),
                    req_id, cors));
                return;
              }
            }

            promise.set_value(make_json_error(-32603,
                "Transaction not found in recent history (searched 20 transactions)", req_id, cors));
          }));
        }));
      });
}

// ─── tryLocateResultTx ──────────────────────────────────────────────────
// Given an outgoing message (source account sent at created_lt), find the
// resulting transaction on the destination that processed it.

void JsonRpcServer::handle_tryLocateResultTx(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto lp_r = parse_locate_params(params);
  if (lp_r.is_error()) {
    promise.set_value(make_json_error(-32602, lp_r.error().message().str(), req_id));
    return;
  }
  auto lp = lp_r.move_as_ok();

  // Step 1: Get account state for the DESTINATION to find its last transaction
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [cors = opts_.cors_origin, lp, req_id = std::move(req_id), self_id,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id, cors));
          return;
        }
        auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc.error(), req_id, cors));
          return;
        }

        // Get account state for destination
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    lp.destination.workchain, lp.destination.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, lp, req_id = std::move(req_id), self_id,
                 promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id, cors));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id, cors));
            return;
          }
          auto f = F.move_as_ok();

          auto blk_id = tos::create_block_id(f->id_);
          auto shard_blk_id = tos::create_block_id(f->shardblk_);
          block::AccountState as;
          as.blk = blk_id;
          as.shard_blk = shard_blk_id;
          as.shard_proof = f->shard_proof_.clone();
          as.proof = f->proof_.clone();
          as.state = f->state_.clone();
          auto info_r = as.validate(blk_id, lp.destination);
          if (info_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "validate account state: " << info_r.error(), req_id, cors));
            return;
          }
          auto info = info_r.move_as_ok();
          if (info.last_trans_lt == 0) {
            promise.set_value(make_json_error(-32603,
                "Destination account has no transactions", req_id, cors));
            return;
          }

          // Step 2: Get destination transactions and search for one whose in_msg
          // matches source + created_lt (same as tryLocateTx — the "result" tx is
          // the transaction that RECEIVED the message sent from source at created_lt)
          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  20,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      lp.destination.workchain, lp.destination.addr),
                  static_cast<td::int64>(info.last_trans_lt), info.last_trans_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [cors, lp, req_id = std::move(req_id),
                   promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "getTransactions: " << R.error(), req_id, cors));
              return;
            }
            auto tl_r = tos::fetch_tl_object<tos::lite_api::liteServer_transactionList>(
                R.move_as_ok(), true);
            if (tl_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "parse transactionList: " << tl_r.error(), req_id, cors));
              return;
            }
            auto tl = tl_r.move_as_ok();

            if (tl->transactions_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "Transaction not found in recent history", req_id, cors));
              return;
            }

            auto roots_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
            if (roots_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "Failed to deserialize transactions BOC", req_id, cors));
              return;
            }
            auto roots = roots_r.move_as_ok();

            // Search: the result tx is on destination with in_msg from source at created_lt
            for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
              block::gen::Transaction::Record tx;
              if (!tlb::unpack_cell(roots[i], tx)) continue;

              auto is_just = tx.r1.in_msg->prefetch_long(1);
              if (is_just != -1) continue;

              auto msg_cell = tx.r1.in_msg->prefetch_ref();
              if (msg_cell.is_null()) continue;

              block::StdAddress msg_src;
              td::uint64 msg_lt = 0;
              if (!msg_get_src_addr(msg_cell, msg_src)) continue;
              if (!msg_get_created_lt(msg_cell, msg_lt)) continue;

              if (msg_src.workchain == lp.source.workchain &&
                  msg_src.addr == lp.source.addr &&
                  msg_lt == lp.created_lt) {
                promise.set_value(make_json_ok(
                    format_located_tx_json(lp.source, lp.destination, roots[i], *tl->ids_[i]),
                    req_id, cors));
                return;
              }
            }

            promise.set_value(make_json_error(-32603,
                "Result transaction not found in recent history (searched 20 transactions)", req_id, cors));
          }));
        }));
      });
}

// ─── tryLocateSourceTx ──────────────────────────────────────────────────
// Given an incoming message (destination received at created_lt), find the
// source transaction that sent it.  We search the source account's
// transactions for one that has an outgoing message to destination with
// matching created_lt.

void JsonRpcServer::handle_tryLocateSourceTx(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto lp_r = parse_locate_params(params);
  if (lp_r.is_error()) {
    promise.set_value(make_json_error(-32602, lp_r.error().message().str(), req_id));
    return;
  }
  auto lp = lp_r.move_as_ok();

  // Step 1: Get account state for the SOURCE to find its last transaction
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [cors = opts_.cors_origin, lp, req_id = std::move(req_id), self_id,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id, cors));
          return;
        }
        auto mc = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc.error(), req_id, cors));
          return;
        }

        // Get account state for source
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    lp.source.workchain, lp.source.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, lp, req_id = std::move(req_id), self_id,
                 promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id, cors));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id, cors));
            return;
          }
          auto f = F.move_as_ok();

          auto blk_id = tos::create_block_id(f->id_);
          auto shard_blk_id = tos::create_block_id(f->shardblk_);
          block::AccountState as;
          as.blk = blk_id;
          as.shard_blk = shard_blk_id;
          as.shard_proof = f->shard_proof_.clone();
          as.proof = f->proof_.clone();
          as.state = f->state_.clone();
          auto info_r = as.validate(blk_id, lp.source);
          if (info_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "validate account state: " << info_r.error(), req_id, cors));
            return;
          }
          auto info = info_r.move_as_ok();
          if (info.last_trans_lt == 0) {
            promise.set_value(make_json_error(-32603,
                "Source account has no transactions", req_id, cors));
            return;
          }

          // Step 2: Get source transactions and search for one whose out_msgs
          // contains a message to destination with matching created_lt
          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  20,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      lp.source.workchain, lp.source.addr),
                  static_cast<td::int64>(info.last_trans_lt), info.last_trans_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [cors, lp, req_id = std::move(req_id),
                   promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "getTransactions: " << R.error(), req_id, cors));
              return;
            }
            auto tl_r = tos::fetch_tl_object<tos::lite_api::liteServer_transactionList>(
                R.move_as_ok(), true);
            if (tl_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "parse transactionList: " << tl_r.error(), req_id, cors));
              return;
            }
            auto tl = tl_r.move_as_ok();

            if (tl->transactions_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "Transaction not found in recent history", req_id, cors));
              return;
            }

            auto roots_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
            if (roots_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "Failed to deserialize transactions BOC", req_id, cors));
              return;
            }
            auto roots = roots_r.move_as_ok();

            // Search: look for a source tx with an out_msg to destination at created_lt
            for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
              block::gen::Transaction::Record tx;
              if (!tlb::unpack_cell(roots[i], tx)) continue;

              if (tx.outmsg_cnt == 0) continue;

              // Iterate out_msgs dictionary
              vm::Dictionary dict{tx.r1.out_msgs, 15};
              for (int k = 0; k < tx.outmsg_cnt && k < 100; k++) {
                auto out_msg_ref = dict.lookup_ref(td::BitArray<15>{k});
                if (out_msg_ref.is_null()) continue;

                block::StdAddress msg_dst;
                td::uint64 msg_lt = 0;
                if (!msg_get_dst_addr(out_msg_ref, msg_dst)) continue;
                if (!msg_get_created_lt(out_msg_ref, msg_lt)) continue;

                if (msg_dst.workchain == lp.destination.workchain &&
                    msg_dst.addr == lp.destination.addr &&
                    msg_lt == lp.created_lt) {
                  // Found: the source transaction that sent this message
                  promise.set_value(make_json_ok(
                      format_located_tx_json(lp.source, lp.destination, roots[i], *tl->ids_[i]),
                      req_id, cors));
                  return;
                }
              }
            }

            promise.set_value(make_json_error(-32603,
                "Source transaction not found in recent history (searched 20 transactions)", req_id, cors));
          }));
        }));
      });
}


// ─── getTransactionsStd ──────────────────────────────────────────────────
// Returns raw.transactions object (with @type, transactions[], previous_transaction_id)
// as specified by the HTTP API v2 schema TransactionsStd type.

void JsonRpcServer::handle_getTransactionsStd(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  td::int32 limit = 10;
  auto limit_r = params.get_optional_int_field("limit");
  if (limit_r.is_ok() && limit_r.ok() > 0) {
    limit = std::min(static_cast<td::int32>(limit_r.ok()), static_cast<td::int32>(100));
  }

  td::int64 lt = 0;
  td::Bits256 hash = td::Bits256::zero();
  bool has_lt = false;
  bool has_hash = false;

  auto lt_r = params.get_optional_string_field("lt");
  if (lt_r.is_ok() && !lt_r.ok().empty()) {
    lt = std::strtoll(lt_r.ok().c_str(), nullptr, 10);
    has_lt = true;
  }

  auto hash_r = params.get_optional_string_field("hash");
  if (hash_r.is_ok() && !hash_r.ok().empty()) {
    auto hash_decoded = td::base64_decode(hash_r.ok());
    if (hash_decoded.is_ok() && hash_decoded.ok().size() == 32) {
      hash.as_slice().copy_from(hash_decoded.ok());
      has_hash = true;
    } else {
      auto hex_r = td::hex_decode(td::Slice(hash_r.ok()));
      if (hex_r.is_ok() && hex_r.ok().size() == 32) {
        hash.as_slice().copy_from(hex_r.ok());
        has_hash = true;
      }
    }
  }

  if (has_lt != has_hash) {
    promise.set_value(make_json_error(-32602, "lt and hash should be used together", req_id));
    return;
  }

  // Formatter: raw.transactions object with @type, transactions[], previous_transaction_id
  auto format_std = [cors = opts_.cors_origin](td::Result<td::BufferSlice> R, std::string req_id,
                       td::Promise<HttpReturn> promise) {
    if (R.is_error()) {
      promise.set_value(make_json_error(-32603,
          PSTRING() << "getTransactions: " << R.error(), req_id, cors));
      return;
    }
    auto tl_r = tos::fetch_tl_object<tos::lite_api::liteServer_transactionList>(
        R.move_as_ok(), true);
    if (tl_r.is_error()) {
      promise.set_value(make_json_error(-32603,
          PSTRING() << "parse transactionList: " << tl_r.error(), req_id, cors));
      return;
    }
    auto tl = tl_r.move_as_ok();

    td::StringBuilder sb;
    sb << "{\"@type\":\"raw.transactions\""
       << ",\"transactions\":[";
    td::uint64 prev_lt = 0;
    std::string prev_hash_b64;
    if (!tl->transactions_.empty()) {
      auto root_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
      if (root_r.is_ok()) {
        auto roots = root_r.move_as_ok();
        for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
          if (i > 0) sb << ",";
          sb << "{\"@type\":\"raw.transaction\"";
          block::gen::Transaction::Record tx;
          if (tlb::unpack_cell(roots[i], tx)) {
            sb << ",\"utime\":" << tx.now;
            auto tx_hash = roots[i]->get_hash(0);
            auto boc_r = vm::std_boc_serialize(roots[i]);
            if (boc_r.is_ok()) {
              sb << ",\"data\":\"" << td::base64_encode(boc_r.ok().as_slice()) << "\"";
            }
            sb << ",\"transaction_id\":{\"@type\":\"internal.transactionId\""
               << ",\"lt\":\"" << tx.lt << "\""
               << ",\"hash\":\"" << td::base64_encode(tx_hash.as_slice()) << "\"}";
            // Parsed fields for wallet tracking
            block::CurrencyCollection total_fees;
            if (total_fees.unpack(tx.total_fees)) {
              sb << ",\"fee\":\"" << total_fees.tomis->to_dec_string() << "\"";
            }
            sb << ",\"account\":\"" << tx.account_addr.to_hex() << "\"";
            if (tx.r1.in_msg->prefetch_long(1) == -1) {
              auto msg_cell = tx.r1.in_msg->prefetch_ref();
              if (msg_cell.not_null()) {
                sb << ",\"in_msg_hash\":\""
                   << td::base64_encode(msg_cell->get_hash(0).as_slice()) << "\"";
              }
            }
            append_transaction_messages(sb, tx);
            append_transaction_execution(sb, tx);
            if (i == roots.size() - 1 || i == tl->ids_.size() - 1) {
              prev_lt = tx.prev_trans_lt;
              prev_hash_b64 = td::base64_encode(tx.prev_trans_hash.as_slice());
            }
          }
          sb << "}";
        }
      }
    }
    sb << "]"
       << ",\"previous_transaction_id\":{\"@type\":\"internal.transactionId\""
       << ",\"lt\":\"" << prev_lt << "\""
       << ",\"hash\":\"" << prev_hash_b64 << "\"}"
       << "}";
    promise.set_value(make_json_ok(sb.as_cslice().str(), req_id, cors));
  };

  // If lt/hash provided, query directly
  if (has_lt && has_hash) {
    auto inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
            limit,
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                addr.workchain, addr.addr),
            lt, hash),
        true);
    auto query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

    send_liteserver_query(std::move(query),
        [req_id = std::move(req_id), promise = std::move(promise),
         format_std](td::Result<td::BufferSlice> R) mutable {
          format_std(std::move(R), std::move(req_id), std::move(promise));
        });
    return;
  }

  // No lt/hash — first get account state to find last_trans_lt/hash
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [cors = opts_.cors_origin, addr, limit, req_id = std::move(req_id), self_id,
       promise = std::move(promise), format_std](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo: " << R.error(), req_id, cors));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse mcInfo: " << mc_r.error(), req_id, cors));
          return;
        }
        auto mc = mc_r.move_as_ok();

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [cors, addr, limit, req_id = std::move(req_id), self_id,
                 promise = std::move(promise), format_std](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "getAccountState: " << R.error(), req_id, cors));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse accountState: " << F.error(), req_id, cors));
            return;
          }
          auto f = F.move_as_ok();
          auto parsed = ParsedAccountState::parse(f, addr);
          if (parsed.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse account: " << parsed.error(), req_id, cors));
            return;
          }
          auto ps = parsed.move_as_ok();

          if (ps.last_trans_lt == 0) {
            promise.set_value(make_json_ok(
                "{\"@type\":\"raw.transactions\",\"transactions\":[]"
                ",\"previous_transaction_id\":{\"@type\":\"internal.transactionId\""
                ",\"lt\":\"0\",\"hash\":\"\"}}",
                req_id, cors));
            return;
          }

          td::Bits256 last_hash;
          auto hash_dec = td::base64_decode(ps.last_trans_hash_b64);
          if (hash_dec.is_ok() && hash_dec.ok().size() == 32) {
            last_hash.as_slice().copy_from(hash_dec.ok());
          }

          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  limit,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      addr.workchain, addr.addr),
                  static_cast<td::int64>(ps.last_trans_lt), last_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [req_id = std::move(req_id), promise = std::move(promise),
                   format_std](td::Result<td::BufferSlice> R) mutable {
            format_std(std::move(R), std::move(req_id), std::move(promise));
          }));
        }));
      });
}

}  // namespace tos
