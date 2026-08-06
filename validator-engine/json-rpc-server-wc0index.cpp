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
//
// wc=0 in-process wallet index — JSON-RPC read handlers.
// See doc/tos-wc0-wallet-index.md. The writer (block-apply hook) lands in a
// later phase; until then these return empty lists.
//
#include <algorithm>
#include <charconv>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "td/utils/StringBuilder.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

#include "json-rpc-server-internal.h"
#include "wallet-index.h"

namespace tos {

namespace {

// Optional "limit" param: default 100, clamped to [1, 1000]. The index can be
// inflated by third parties (anyone can send notification/spam transactions at
// an account), so responses must stay bounded regardless of index size.
size_t parse_limit_param(td::JsonObject &params) {
  size_t limit = 100;
  auto limit_r = params.get_optional_int_field("limit");
  if (limit_r.is_ok() && limit_r.ok() > 0) {
    limit = std::min<size_t>(static_cast<size_t>(limit_r.ok()), 1000);
  }
  return limit;
}

// The index only covers basechain (wc=0) accounts; a -1:X query must not be
// answered with entries belonging to the wc=0 account with the same hash.
bool is_indexed_workchain(const block::StdAddress &addr) {
  return addr.workchain == 0;
}

td::Result<uint64_t> parse_uint64(td::Slice value, td::Slice field) {
  uint64_t result = 0;
  auto first = value.begin();
  auto last = value.end();
  auto parsed = std::from_chars(first, last, result);
  if (value.empty() || parsed.ec != std::errc() || parsed.ptr != last) {
    return td::Status::Error(PSTRING() << "Invalid '" << field << "' (expected uint64 string)");
  }
  return result;
}

std::string format_account_event(uint64_t lt, td::Ref<vm::Cell> cell) {
  auto hash = cell->get_hash(0);
  auto hash_hex = hash.to_hex();
  td::StringBuilder sb;
  sb << "{\"@type\":\"wallet.accountEvent\""
     << ",\"event_id\":\"" << lt << ":" << hash_hex << "\""
     << ",\"lt\":\"" << lt << "\""
     << ",\"hash\":\"" << hash_hex << "\"";

  block::gen::Transaction::Record tx;
  if (tlb::unpack_cell(cell, tx)) {
    sb << ",\"timestamp\":" << tx.now;
    block::CurrencyCollection total_fees;
    if (total_fees.unpack(tx.total_fees)) {
      sb << ",\"fee\":\"" << total_fees.tomis->to_dec_string() << "\"";
    }

    // V1 deliberately exposes only native TOS value movements. Extra
    // currencies and token-contract payloads are not interpreted here.
    sb << ",\"transfers\":[";
    bool first_transfer = true;
    auto append_transfer = [&](td::Ref<vm::Cell> message_cell, td::Slice direction) {
      td::Ref<vm::CellSlice> info_cs, init_cs, body_cs;
      if (message_cell.is_null() ||
          !block::gen::t_Message_Any.cell_unpack_message(message_cell, info_cs, init_cs, body_cs) ||
          info_cs.is_null() ||
          block::gen::CommonMsgInfo().get_tag(*info_cs) != block::gen::CommonMsgInfo::int_msg_info) {
        return;
      }
      block::gen::CommonMsgInfo::Record_int_msg_info info;
      if (!tlb::csr_unpack(std::move(info_cs), info)) {
        return;
      }
      tos::WorkchainId source_wc, destination_wc;
      tos::StdSmcAddress source, destination;
      block::CurrencyCollection value;
      if (!block::tlb::t_MsgAddressInt.extract_std_address(info.src, source_wc, source) ||
          !block::tlb::t_MsgAddressInt.extract_std_address(info.dest, destination_wc, destination) ||
          !value.unpack(info.value)) {
        return;
      }
      if (!first_transfer) {
        sb << ",";
      }
      first_transfer = false;
      block::StdAddress source_address(source_wc, source);
      block::StdAddress destination_address(destination_wc, destination);
      sb << "{\"@type\":\"wallet.nativeTransfer\""
         << ",\"direction\":" << td::JsonString(direction)
         << ",\"source\":" << td::JsonString(source_address.rserialize(true))
         << ",\"destination\":" << td::JsonString(destination_address.rserialize(true)) << ",\"amount\":\""
         << value.tomis->to_dec_string() << "\""
         << ",\"bounced\":" << (info.bounced ? "true" : "false") << "}";
    };

    if (tx.r1.in_msg->prefetch_long(1) == -1) {
      append_transfer(tx.r1.in_msg->prefetch_ref(), "incoming");
    }
    vm::Dictionary out_messages{tx.r1.out_msgs, 15};
    for (int index = 0; index < tx.outmsg_cnt; ++index) {
      append_transfer(out_messages.lookup_ref(td::BitArray<15>{index}), "outgoing");
    }
    sb << "]";
  }
  auto boc_r = vm::std_boc_serialize(cell);
  if (boc_r.is_ok()) {
    sb << ",\"raw_transaction\":\"" << td::base64_encode(boc_r.ok().as_slice()) << "\"";
  }
  sb << "}";
  return sb.as_cslice().str();
}

struct AccountEventId {
  uint64_t lt;
  td::Bits256 hash;
};

td::Result<AccountEventId> parse_event_id(td::Slice value) {
  auto separator = value.find(':');
  if (separator == td::Slice::npos) {
    return td::Status::Error("Invalid 'event_id' (expected <lt>:<64-char-hex-hash>)");
  }
  TRY_RESULT(lt, parse_uint64(value.substr(0, separator), "event_id"));
  auto hash_text = value.substr(separator + 1);
  auto decoded = td::hex_decode(hash_text);
  if (decoded.is_error() || decoded.ok().size() != 32) {
    return td::Status::Error("Invalid 'event_id' (expected <lt>:<64-char-hex-hash>)");
  }
  AccountEventId id{lt, td::Bits256::zero()};
  id.hash.as_slice().copy_from(decoded.ok());
  return id;
}

}  // namespace

void JsonRpcServer::handle_getAccountJettons(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto limit = parse_limit_param(params);

  td::StringBuilder sb;
  sb << "{\"@type\":\"wallet.accountJettons\",\"jettons\":[";
  auto *db = tos_wallet_index::wallet_index_db();
  bool first = true;
  if (db != nullptr && is_indexed_workchain(addr)) {
    // Entries are state-verified by the writer (master-acknowledged wallets only);
    // the client resolves the live balance via get_wallet_data (runGetMethod).
    auto status =
        db->for_each_jetton(addr.addr, limit, [&](const td::Bits256 &master, td::Ref<vm::Cell> value) -> td::Status {
          td::Bits256 jetton_wallet = td::Bits256::zero();
          unsigned long long last_lt = 0;
          if (value.not_null()) {
            auto cs = vm::load_cell_slice(value);
            if (cs.size() >= 256 + 64) {
              cs.fetch_bits_to(jetton_wallet.bits(), 256);
              last_lt = cs.fetch_ulong(64);
            }
          }
          if (!first) {
            sb << ",";
          }
          first = false;
          sb << "{\"jetton_master\":\"0:" << master.to_hex() << "\",\"jetton_wallet\":\"0:" << jetton_wallet.to_hex()
             << "\",\"last_lt\":\"" << last_lt << "\"}";
          return td::Status::OK();
        });
    if (status.is_error()) {
      promise.set_value(make_json_error(-32603, status.message().str(), req_id));
      return;
    }
  }
  sb << "]}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}

void JsonRpcServer::handle_getAccountEvents(td::JsonObject &params, std::string req_id,
                                            td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto limit = parse_limit_param(params);

  uint64_t before_lt = 0;
  bool has_before_lt = false;
  auto before_r = params.get_optional_string_field("before_lt");
  if (before_r.is_ok() && !before_r.ok().empty()) {
    auto parsed = parse_uint64(before_r.ok(), "before_lt");
    if (parsed.is_error() || parsed.ok() == 0) {
      promise.set_value(make_json_error(-32602, "Invalid 'before_lt' (expected positive uint64 string)", req_id));
      return;
    }
    before_lt = parsed.move_as_ok();
    has_before_lt = true;
  }

  td::StringBuilder sb;
  sb << "{\"@type\":\"wallet.accountEvents\",\"events\":[";
  auto *db = tos_wallet_index::wallet_index_db();
  bool first = true;
  size_t seen = 0;
  uint64_t last_lt = 0;
  if (db != nullptr && is_indexed_workchain(addr)) {
    // Read one extra entry to determine whether the continuation cursor exists.
    auto append = [&](uint64_t lt, td::Ref<vm::Cell> cell) -> td::Status {
      ++seen;
      if (seen > limit) {
        return td::Status::OK();
      }
      if (!first) {
        sb << ",";
      }
      first = false;
      last_lt = lt;
      sb << format_account_event(lt, std::move(cell));
      return td::Status::OK();
    };
    auto status = has_before_lt ? db->for_each_event_before(addr.addr, before_lt, limit + 1, append)
                                : db->for_each_event(addr.addr, limit + 1, append);
    if (status.is_error()) {
      promise.set_value(make_json_error(-32603, status.message().str(), req_id));
      return;
    }
  }
  sb << "],\"next_from\":";
  if (seen > limit) {
    sb << "\"" << last_lt << "\"";
  } else {
    sb << "null";
  }
  sb << "}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}

void JsonRpcServer::handle_getAccountEvent(td::JsonObject &params, std::string req_id,
                                           td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  auto id_r = params.get_required_string_field("event_id");
  if (addr_r.is_error() || id_r.is_error()) {
    promise.set_value(
        make_json_error(-32602, addr_r.is_error() ? addr_r.error().message().str() : "Missing 'event_id'", req_id));
    return;
  }
  auto parsed_id = parse_event_id(id_r.ok());
  if (parsed_id.is_error()) {
    promise.set_value(make_json_error(-32602, parsed_id.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  if (!is_indexed_workchain(addr)) {
    promise.set_value(make_json_error(-32004, "Account event not found", req_id));
    return;
  }
  auto *db = tos_wallet_index::wallet_index_db();
  if (db == nullptr) {
    promise.set_value(make_json_error(-32004, "Account event not found", req_id));
    return;
  }
  auto id = parsed_id.move_as_ok();
  auto event_r = db->get_event(addr.addr, id.lt);
  if (event_r.is_error() || event_r.ok()->get_hash(0).as_slice() != id.hash.as_slice()) {
    promise.set_value(make_json_error(-32004, "Account event not found", req_id));
    return;
  }
  promise.set_value(make_json_ok(format_account_event(id.lt, event_r.move_as_ok()), req_id));
}

void JsonRpcServer::handle_getAccountNfts(td::JsonObject &params, std::string req_id, td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto limit = parse_limit_param(params);

  td::StringBuilder sb;
  sb << "{\"@type\":\"wallet.accountNfts\",\"nfts\":[";
  auto *db = tos_wallet_index::wallet_index_db();
  bool first = true;
  if (db != nullptr && is_indexed_workchain(addr)) {
    auto status =
        db->for_each_nft(addr.addr, limit, [&](const td::Bits256 &nft, td::Ref<vm::Cell> value) -> td::Status {
          bool has_collection = false;
          td::Bits256 collection = td::Bits256::zero();
          unsigned long long last_lt = 0;
          if (value.not_null()) {
            auto cs = vm::load_cell_slice(value);
            if (cs.size() >= 1) {
              has_collection = cs.fetch_ulong(1) != 0;
              if (has_collection && cs.size() >= 256 + 64) {
                cs.fetch_bits_to(collection.bits(), 256);
              }
              if (cs.size() >= 64) {
                last_lt = cs.fetch_ulong(64);
              }
            }
          }
          if (!first) {
            sb << ",";
          }
          first = false;
          sb << "{\"nft_item\":\"0:" << nft.to_hex() << "\",\"collection\":";
          if (has_collection) {
            sb << "\"0:" << collection.to_hex() << "\"";
          } else {
            sb << "null";
          }
          sb << ",\"last_lt\":\"" << last_lt << "\"}";
          return td::Status::OK();
        });
    if (status.is_error()) {
      promise.set_value(make_json_error(-32603, status.message().str(), req_id));
      return;
    }
  }
  sb << "]}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}

}  // namespace tos
