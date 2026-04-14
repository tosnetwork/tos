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

// ─── packAddress ────────────────────────────────────────────────────────

void JsonRpcServer::handle_packAddress(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto addr_str_r = params.get_required_string_field("address");
  if (addr_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  auto addr_str = addr_str_r.move_as_ok();

  // Parse raw address (workchain:hex)
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_str))) {
    promise.set_value(make_json_error(-32602, "Invalid raw address", req_id));
    return;
  }

  // Pack into user-friendly base64url form (bounceable, no testnet flag)
  addr.bounceable = true;
  addr.testnet = false;
  auto packed = addr.rserialize(true);  // base64url
  if (packed.empty()) {
    promise.set_value(make_json_error(-32603, "Failed to serialize address", req_id));
    return;
  }

  auto packed_json = PSTRING() << td::JsonString(td::Slice(packed));
  promise.set_value(make_json_ok(packed_json, req_id));
}

// ─── unpackAddress ──────────────────────────────────────────────────────

void JsonRpcServer::handle_unpackAddress(td::JsonObject &params, std::string req_id,
                                         td::Promise<HttpReturn> promise) {
  auto addr_str_r = params.get_required_string_field("address");
  if (addr_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  auto addr_str = addr_str_r.move_as_ok();

  // Parse user-friendly address
  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_str))) {
    promise.set_value(make_json_error(-32602, "Invalid address", req_id));
    return;
  }

  // Return raw form: workchain:hex_hash
  auto raw = PSTRING() << addr.workchain << ":" << addr.addr.to_hex();
  auto raw_json = PSTRING() << td::JsonString(td::Slice(raw));
  promise.set_value(make_json_ok(raw_json, req_id));
}

// ─── detectAddress ──────────────────────────────────────────────────────

void JsonRpcServer::handle_detectAddress(td::JsonObject &params, std::string req_id,
                                         td::Promise<HttpReturn> promise) {
  auto addr_str_r = params.get_required_string_field("address");
  if (addr_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'address'", req_id));
    return;
  }
  auto addr_str = addr_str_r.move_as_ok();

  block::StdAddress addr;
  if (!addr.parse_addr(td::Slice(addr_str))) {
    promise.set_value(make_json_error(-32602, "Invalid address", req_id));
    return;
  }

  auto raw = PSTRING() << addr.workchain << ":" << addr.addr.to_hex();

  // Generate user-friendly forms
  auto gen_friendly = [&](bool bounceable, bool testnet) -> std::string {
    block::StdAddress a = addr;
    a.bounceable = bounceable;
    a.testnet = testnet;
    return a.rserialize(true);  // base64url
  };

  auto bounceable = gen_friendly(true, false);
  auto non_bounceable = gen_friendly(false, false);
  auto bounceable_test = gen_friendly(true, true);
  auto non_bounceable_test = gen_friendly(false, true);

  td::StringBuilder sb;
  sb << "{\"raw_form\":" << td::JsonString(td::Slice(raw))
     << ",\"bounceable\":{\"b64\":" << td::JsonString(td::Slice(bounceable))
     << ",\"b64url\":" << td::JsonString(td::Slice(bounceable)) << "}"
     << ",\"non_bounceable\":{\"b64\":" << td::JsonString(td::Slice(non_bounceable))
     << ",\"b64url\":" << td::JsonString(td::Slice(non_bounceable)) << "}"
     << ",\"given_type\":" << td::JsonString(td::Slice(
          addr.bounceable ? "friendly_bounceable" : "friendly_non_bounceable"))
     << ",\"test_only\":" << (addr.testnet ? "true" : "false")
     << "}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}


// ─── detectHash ──────────────────────────────────────────────────────────
// Pure utility method (no backend query). Accepts a hash in base64, base64url,
// or hex form, decodes it to raw bytes, and returns all three encodings.
// Aligned with ton-http-api-cpp DetectHashHandler / DetectHashResult.

static td::Result<std::string> decode_hash_input(const std::string& hash) {
  if (hash.empty()) {
    return td::Status::Error("empty hash");
  }
  // base64 (44 chars with padding)
  if (hash.length() == 44) {
    auto r = td::base64_decode(hash);
    if (r.is_ok()) return r.move_as_ok();
    auto r2 = td::base64url_decode(hash);
    if (r2.is_ok()) return r2.move_as_ok();
  }
  // base64url without padding (43 chars)
  if (hash.length() == 43) {
    auto r = td::base64url_decode(hash);
    if (r.is_ok()) return r.move_as_ok();
  }
  // hex (64 chars)
  if (hash.length() == 64) {
    auto r = td::hex_decode(td::Slice(hash));
    if (r.is_ok()) return r.move_as_ok();
  }
  return td::Status::Error(PSTRING() << "invalid hash: '" << hash << "'");
}

void JsonRpcServer::handle_detectHash(td::JsonObject &params, std::string req_id,
                                      td::Promise<HttpReturn> promise) {
  auto hash_str_r = params.get_required_string_field("hash");
  if (hash_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'hash'", req_id));
    return;
  }
  auto hash_str = hash_str_r.move_as_ok();

  auto decoded_r = decode_hash_input(hash_str);
  if (decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, decoded_r.error().message().str(), req_id));
    return;
  }
  auto raw_bytes = decoded_r.move_as_ok();

  auto b64 = td::base64_encode(td::Slice(raw_bytes));
  auto b64url = td::base64url_encode(td::Slice(raw_bytes));
  auto hex = td::hex_encode(td::Slice(raw_bytes));

  td::StringBuilder sb;
  sb << "{\"@type\":\"ext.utils.detectedHash\""
     << ",\"b64\":" << td::JsonString(td::Slice(b64))
     << ",\"b64url\":" << td::JsonString(td::Slice(b64url))
     << ",\"hex\":" << td::JsonString(td::Slice(hex))
     << "}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}

void JsonRpcServer::handle_readyz(td::Promise<HttpReturn> promise) {
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfoExt>(0), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  auto threshold = opts_.readyz_threshold;
  auto cors = opts_.cors_origin;
  send_liteserver_query(std::move(query),
      [promise = std::move(promise), threshold, cors](td::Result<td::BufferSlice> R) mutable {
        auto make_readyz_response = [&](int status_code, std::string status_text, std::string body) -> HttpReturn {
          auto response = http::HttpResponse::create("HTTP/1.1", status_code,
              std::move(status_text), false, false).move_as_ok();
          response->add_header({"Content-Type", "application/json"});
          response->add_header({"Access-Control-Allow-Origin", cors});
          response->add_header({"Transfer-Encoding", "Chunked"});
          response->complete_parse_header();
          auto payload = response->create_empty_payload().move_as_ok();
          payload->add_chunk(td::BufferSlice(std::move(body)));
          payload->complete_parse();
          return {std::move(response), std::move(payload)};
        };

        if (R.is_error()) {
          promise.set_value(make_readyz_response(503, "Service Unavailable",
              PSTRING() << "{\"ready\":false,\"error\":"
                        << td::JsonString(td::Slice(PSTRING() << R.error())) << "}"));
          return;
        }

        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfoExt>(
            R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_readyz_response(503, "Service Unavailable",
              "{\"ready\":false,\"error\":\"parse error\"}"));
          return;
        }
        auto mc = mc_r.move_as_ok();

        td::int32 last_utime = mc->last_utime_;
        td::int32 now = mc->now_;
        td::int32 sync_lag = now > last_utime ? now - last_utime : 0;
        bool ready = sync_lag < threshold;

        auto body = PSTRING()
            << "{\"ready\":" << (ready ? "true" : "false")
            << ",\"sync_lag_seconds\":" << sync_lag
            << ",\"last_block_utime\":" << last_utime
            << ",\"node_time\":" << now
            << ",\"last_block\":" << format_block_id_json(*mc->last_)
            << "}";

        promise.set_value(make_readyz_response(
            ready ? 200 : 503,
            ready ? "OK" : "Service Unavailable",
            std::move(body)));
      });
}

}  // namespace tos
