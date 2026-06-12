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
#include "json-rpc-server-internal.h"
#include "wallet-index.h"

#include "td/utils/StringBuilder.h"
#include "vm/cellslice.h"

#include <algorithm>

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
    auto status = db->for_each_jetton(
        addr.addr, limit, [&](const td::Bits256 &master, td::Ref<vm::Cell> value) -> td::Status {
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
          sb << "{\"jetton_master\":\"0:" << master.to_hex() << "\",\"jetton_wallet\":\"0:"
             << jetton_wallet.to_hex() << "\",\"last_lt\":\"" << last_lt << "\"}";
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

  td::StringBuilder sb;
  sb << "{\"@type\":\"wallet.accountEvents\",\"events\":[";
  auto *db = tos_wallet_index::wallet_index_db();
  bool first = true;
  if (db != nullptr && is_indexed_workchain(addr)) {
    // Newest first (keys store ~lt), at most `limit` entries.
    auto status = db->for_each_event(
        addr.addr, limit, [&](uint64_t lt, td::Ref<vm::Cell> cell) -> td::Status {
          if (!first) {
            sb << ",";
          }
          first = false;
          std::string hash = cell.is_null() ? std::string() : cell->get_hash().to_hex();
          sb << "{\"lt\":\"" << lt << "\",\"hash\":\"" << hash << "\"}";
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

void JsonRpcServer::handle_getAccountNfts(td::JsonObject &params, std::string req_id,
                                          td::Promise<HttpReturn> promise) {
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
    auto status = db->for_each_nft(
        addr.addr, limit, [&](const td::Bits256 &nft, td::Ref<vm::Cell> value) -> td::Status {
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
