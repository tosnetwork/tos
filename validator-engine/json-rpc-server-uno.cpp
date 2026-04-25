/*
    This file is part of TOS Blockchain.

    Uno Workchain JSON-RPC handlers that live ON the validator-engine side
    (as members of JsonRpcServer) because they need access to
    `send_liteserver_query(...)` and emit structured JSON-RPC responses.

    Companion to `uno/rpc/handlers.{h,cpp}` which hosts the read-only
    `uno_*` registry (uno_chainInfo, uno_getAnchor, etc.). The two methods
    in this file are intercepted BEFORE that registry in
    `json-rpc-server.cpp`'s dispatcher:

      * uno_getMineState  — reads {epoch, target_hex, remaining} from the
        live UnoShardState via the `MineStateFn` accessor installed by
        `init_uno_workchain`. Mirrors the shape `tosctl-uno mine`'s
        `fetch_mine_state()` expects (see tosctl/uno/src/mine.rs).

      * uno_sendMineUno   — accepts a hex-encoded MineUno BoC blob, runs
        `decode_mine_uno_bytes()` for syntactic validation, wraps the
        decoded root cell as an `ext_in_msg` targeting the wc=2 executor
        account, and submits it through `liteServer_sendMessage` exactly
        like `eth_sendRawTransaction`. Returns the canonical_mine_uno_hash
        hex on successful submission.

    The wc=2 ext_in_msg layout mirrors EVM's `build_evm_external_message`
    (see evm/core/external-message.cpp) with three differences:
      * workchain_id  = 2  (not 1)
      * dest address  = kUnoExecutorAddressBytes (not kEvmExecutorAddress)
      * body          = the raw MineUno root cell deserialised from the
                         caller-supplied BoC (not a chunked RLP chain).
        The MineUno envelope is already cell-shaped (§1 wire format),
        unlike RLP bytes which must be chunk-encoded to fit the 1023-bit
        cell limit.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "json-rpc-server-internal.h"

#include "uno/core/mine_uno.h"
#include "uno/core/workchain.h"
#include "uno/rpc/handlers.h"

#include "auto/tl/lite_api.h"
#include "http/http-server.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "td/utils/JsonBuilder.h"
#include "td/utils/buffer.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

namespace tos {

// ---------------------------------------------------------------------------
// Hex helpers (self-contained; mirror the pair in json-rpc-server-send.cpp
// without pulling that TU's eth-specific deps in).
// ---------------------------------------------------------------------------

namespace {

int hex_nibble(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool decode_hex(const std::string& in, std::string& out_bytes) {
  const char* p = in.c_str();
  size_t n = in.size();
  if (n >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { p += 2; n -= 2; }
  if (n % 2 != 0) return false;
  out_bytes.resize(n / 2);
  for (size_t i = 0; i < n / 2; ++i) {
    int hi = hex_nibble(p[2 * i]);
    int lo = hex_nibble(p[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out_bytes[i] = static_cast<char>((hi << 4) | lo);
  }
  return true;
}

std::string encode_hex_lower(const uint8_t* data, size_t len) {
  static const char* H = "0123456789abcdef";
  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[2 * i]     = H[(data[i] >> 4) & 0x0f];
    out[2 * i + 1] = H[data[i] & 0x0f];
  }
  return out;
}

// Local mirror of `JsonRpcServer::make_raw_json_response` (which is a
// private static member). Reproduced here so this TU can synthesise an
// HTTP 200 JSON response without needing friend access. Same headers,
// same chunked-encoding setup the rest of the server uses.
std::pair<std::unique_ptr<http::HttpResponse>,
          std::shared_ptr<http::HttpPayload>>
build_raw_json_response(const std::string& body, const std::string& cors_origin) {
  auto response = http::HttpResponse::create(
      "HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();
  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(body));
  payload->complete_parse();
  return {std::move(response), std::move(payload)};
}

// Local mirror of `JsonRpcServer::make_eth_json_error` so we can return
// JSON-RPC 2.0 spec-shape errors without friending the server class.
// `id` should be the verbatim id substring from the request envelope
// (already JSON-quoted if a string, or "null" / numeric as appropriate).
std::pair<std::unique_ptr<http::HttpResponse>,
          std::shared_ptr<http::HttpPayload>>
build_jsonrpc_error(int code, const std::string& message,
                    std::string id, const std::string& cors_origin) {
  if (id.empty()) id = "null";
  std::string body;
  body.reserve(96 + message.size());
  body += "{\"jsonrpc\":\"2.0\",\"id\":";
  body += id;
  body += ",\"error\":{\"code\":";
  body += std::to_string(code);
  body += ",\"message\":";
  // Reuse td::JsonString for proper JSON escaping.
  td::StringBuilder sb;
  sb << td::JsonString(td::Slice(message));
  body += sb.as_cslice().str();
  body += "}}";
  return build_raw_json_response(body, cors_origin);
}

}  // namespace

// ---------------------------------------------------------------------------
// uno_getMineState
//
// Params: [] (no args).
// Result: {"epoch": u32, "target": <64-hex>, "remaining": u64}.
//
// `target` is the 32-byte big-endian PoW threshold serialised as a
// lowercase hex string with no 0x prefix — matches `tosctl-uno mine`'s
// `fetch_mine_state()` which `hex::decode`s the string directly.
// ---------------------------------------------------------------------------

std::pair<std::unique_ptr<http::HttpResponse>,
          std::shared_ptr<http::HttpPayload>>
handle_uno_get_mine_state(std::string req_id,
                          const std::string& cors_origin) {
  auto snap = uno_workchain::get_mine_state_snapshot();
  if (!snap) {
    // Accessor not yet bound — UnoState singleton missing. Mirror the
    // shape used by uno/rpc/handlers.cpp's `kErrStateUnavailable`.
    return build_jsonrpc_error(
        -32010, "uno mine state unavailable (init_uno_workchain not run)",
        req_id, cors_origin);
  }
  if (!snap->hydrated) {
    // LiveUnoState has not yet been hydrated from a persisted wc=2
    // ShardState cell, so the (epoch, target, remaining) fields are
    // construction defaults — they may lag the real chain state.
    // Refusing here is fail-closed: tosctl-uno mine receives an explicit
    // error and aborts, instead of building a proof against a stale
    // snapshot that would later be rejected as EpochRaceDetected.
    // Hydration fires automatically on the first wc=2 compute-phase tx
    // after restart; clients should retry shortly.
    return build_jsonrpc_error(
        -32011,
        "uno mine state not yet hydrated (no wc=2 tx since startup) — retry shortly",
        req_id, cors_origin);
  }

  std::string target_hex = encode_hex_lower(snap->target.data(), 32);

  std::string body;
  body.reserve(128);
  body += "{\"jsonrpc\":\"2.0\",\"id\":";
  body += req_id.empty() ? std::string("null") : req_id;
  body += ",\"result\":{";
  body += "\"epoch\":" + std::to_string(static_cast<unsigned long long>(snap->epoch));
  body += ",\"target\":\"" + target_hex + "\"";
  body += ",\"remaining\":" + std::to_string(static_cast<unsigned long long>(snap->remaining));
  body += "}}";
  return build_raw_json_response(body, cors_origin);
}

// ---------------------------------------------------------------------------
// uno_sendMineUno
//
// Params: [hex_boc]  — hex-encoded MineUno BoC (same blob a client would
// otherwise submit via `tos-lite-client sendfile`).
// Result: "<tx_hash_hex>"   (64-char lowercase hex of
//         `canonical_mine_uno_hash(tx)`).
//
// Pipeline (mirror of `eth_sendRawTransaction`):
//   1. Decode hex → bytes.
//   2. Run `decode_mine_uno_bytes()` for syntactic / structural validation.
//   3. Re-deserialise the BoC root cell for use as message body.
//   4. Build a wc=2 ext_in_msg wrapping it, serialise to BoC.
//   5. Wrap in `liteServer_sendMessage(body)` and dispatch via
//      `send_liteserver_query`. The collator side's ExtMessagePool picks
//      it up and feeds it into the next wc=2 block's compute phase.
// ---------------------------------------------------------------------------

void JsonRpcServer::handle_uno_sendMineUno(td::JsonValue& params_val,
                                            std::string req_id,
                                            td::Promise<HttpReturn> promise) {
  // --- 1. Extract hex param (cheap; before the rate-limit consume so
  //        malformed-shape calls don't drain the token bucket). ---
  std::string raw_hex;
  if (params_val.type() == td::JsonValue::Type::Array) {
    auto& arr = params_val.get_array();
    if (!arr.empty() && arr[0].type() == td::JsonValue::Type::String) {
      raw_hex = arr[0].get_string().str();
    }
  }
  if (raw_hex.empty()) {
    promise.set_value(make_eth_json_error(
        -32602, "uno_sendMineUno: expected [string hex_boc]",
        req_id, opts_.cors_origin));
    return;
  }

  // Codex audit (round 3, finding #1): hard size cap BEFORE hex/BoC/MineUno
  // decode. The post-decode rate-limit token at step 2b deliberately runs
  // AFTER decode (per round-12 design — junk hex shouldn't drain the
  // honest-miner bucket), but that left the decode CPU cost uncapped.
  // Reject oversized blobs cheaply here.
  if (raw_hex.size() > uno_workchain::max_uno_send_mine_uno_hex_size()) {
    promise.set_value(make_eth_json_error(
        -32600, "uno_sendMineUno: hex_boc exceeds max size",
        req_id, opts_.cors_origin));
    return;
  }

  std::string raw_bytes;
  if (!decode_hex(raw_hex, raw_bytes)) {
    promise.set_value(make_eth_json_error(
        -32602, "uno_sendMineUno: hex_boc is not valid hex",
        req_id, opts_.cors_origin));
    return;
  }
  if (raw_bytes.empty()) {
    promise.set_value(make_eth_json_error(
        -32602, "uno_sendMineUno: empty BoC", req_id, opts_.cors_origin));
    return;
  }

  // --- 2. Decode MineUno for syntactic validation + hash derivation ---
  auto decode_r = uno_workchain::decode_mine_uno_bytes(
      td::Slice(raw_bytes.data(), raw_bytes.size()));
  if (auto* err = std::get_if<uno_workchain::MineUnoDecodeError>(&decode_r)) {
    promise.set_value(make_eth_json_error(
        -32602, std::string("uno_sendMineUno: decode failed: ") + err->reason,
        req_id, opts_.cors_origin));
    return;
  }

  // --- 2b. Rate-limit (dedicated MineUno bucket; consumed AFTER cheap
  //         shape + hex + BoC + MineUno decode rejects so junk hex,
  //         empty BoCs, and non-MineUno blobs do NOT drain the honest
  //         miner token budget). Caps how many submit-paths a single
  //         source can drive per second. Without this, an attacker can
  //         forge PI fields (pow_hash=0, header-matching) to bypass
  //         apply_mine_uno's cheap pre-FFI checks and force every
  //         validator to pay full STARK verification cost (~50ms+) per
  //         invalid proof. Separate bucket from uno_sendTransfer so
  //         flooders can't starve honest Transfers. ---
  if (!uno_workchain::try_consume_uno_send_mine_uno_token()) {
    promise.set_value(make_eth_json_error(
        -32005, "uno_sendMineUno: rate limit exceeded — try again shortly",
        req_id, opts_.cors_origin));
    return;
  }
  auto& tx = std::get<uno_workchain::MineUno>(decode_r);
  td::Bits256 tx_hash = uno_workchain::canonical_mine_uno_hash(tx);
  std::string tx_hash_hex = encode_hex_lower(
      reinterpret_cast<const uint8_t*>(tx_hash.data()), 32);

  // --- 3. Re-deserialise the caller BoC into a root cell for use as
  //        the ext_in_msg body. decode_mine_uno_bytes already proved
  //        this succeeds, but MineUno consumes the CellSlice, so we
  //        run a fresh deserialise here to hand the root cell to the
  //        message builder. Cheap — same BoC, <1 KB bookkeeping. ---
  auto root_r = vm::std_boc_deserialize(
      td::Slice(raw_bytes.data(), raw_bytes.size()));
  if (root_r.is_error()) {
    promise.set_value(make_eth_json_error(
        -32602,
        PSTRING() << "uno_sendMineUno: std_boc_deserialize failed: "
                  << root_r.error(),
        req_id, opts_.cors_origin));
    return;
  }
  auto root_cell = root_r.move_as_ok();
  if (root_cell.is_null()) {
    promise.set_value(make_eth_json_error(
        -32602, "uno_sendMineUno: null root cell from BoC",
        req_id, opts_.cors_origin));
    return;
  }

  // --- 4. Build the wc=2 ext_in_msg cell. TLB mirrors
  //        `build_evm_external_message()` exactly; only the destination
  //        workchain_id and executor address differ. ---
  td::Ref<vm::Cell> ext_msg;
  try {
    vm::CellBuilder cb;
    // CommonMsgInfo: ext_in_msg_info$10
    cb.store_long(0b10, 2);
    // src: addr_none$00
    cb.store_long(0b00, 2);
    // dest: addr_std$10, anycast=Nothing$0
    cb.store_long(0b100, 3);
    // workchain_id: int8 = 2
    cb.store_long(uno_workchain::kWorkchainId, 8);
    // address: bits256 = kUnoExecutorAddressBytes (0x00…01)
    cb.store_bytes(
        reinterpret_cast<const char*>(uno_workchain::kUnoExecutorAddressBytes),
        32);
    // import_fee: Grams = 0 (VarUInteger 16; 4-bit length = 0)
    cb.store_long(0, 4);
    // init: Maybe (Either StateInit ^StateInit) = nothing$0
    cb.store_long(0, 1);
    // body: Either X ^X = right$1 (body as reference)
    cb.store_long(1, 1);
    cb.store_ref(root_cell);
    ext_msg = cb.finalize();
  } catch (const std::exception& e) {
    promise.set_value(make_eth_json_error(
        -32603,
        PSTRING() << "uno_sendMineUno: failed to build ext_in_msg cell: "
                  << e.what(),
        req_id, opts_.cors_origin));
    return;
  } catch (...) {
    promise.set_value(make_eth_json_error(
        -32603, "uno_sendMineUno: failed to build ext_in_msg cell",
        req_id, opts_.cors_origin));
    return;
  }
  if (ext_msg.is_null()) {
    promise.set_value(make_eth_json_error(
        -32603, "uno_sendMineUno: null ext_in_msg cell",
        req_id, opts_.cors_origin));
    return;
  }

  // --- 5. Serialise ext_in_msg to BoC ---
  td::Result<td::BufferSlice> boc_r;
  try {
    boc_r = vm::std_boc_serialize(ext_msg);
  } catch (const std::exception& e) {
    promise.set_value(make_eth_json_error(
        -32603,
        PSTRING() << "uno_sendMineUno: BoC serialize threw: " << e.what(),
        req_id, opts_.cors_origin));
    return;
  } catch (...) {
    promise.set_value(make_eth_json_error(
        -32603, "uno_sendMineUno: BoC serialize threw", req_id,
        opts_.cors_origin));
    return;
  }
  if (boc_r.is_error()) {
    promise.set_value(make_eth_json_error(
        -32603,
        PSTRING() << "uno_sendMineUno: BoC serialize failed: " << boc_r.error(),
        req_id, opts_.cors_origin));
    return;
  }
  auto boc = boc_r.move_as_ok();

  // --- 6. Submit via liteServer_sendMessage (same pipe as eth_sendRawTransaction) ---
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_sendMessage>(std::move(boc)),
      true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)),
      true);

  // Echo the canonical mine-uno hash as the RPC result on success.
  std::string tx_hash_quoted = "\"" + tx_hash_hex + "\"";

  send_liteserver_query(
      std::move(query),
      [req_id = std::move(req_id),
       tx_hash_quoted = std::move(tx_hash_quoted),
       cors = opts_.cors_origin,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          std::string err_msg = std::string("uno_sendMineUno: submission failed: ") +
                                R.error().message().str();
          promise.set_value(build_jsonrpc_error(
              -32603, err_msg, req_id, cors));
          return;
        }
        // Response (liteServer_sendMsgStatus) is ignored — EVM path does the
        // same. The collator side has already accepted the message into its
        // ExtMessagePool; surface the canonical hash so wallets can poll.
        std::string body;
        body.reserve(64);
        body += "{\"jsonrpc\":\"2.0\",\"id\":";
        body += req_id.empty() ? std::string("null") : req_id;
        body += ",\"result\":";
        body += tx_hash_quoted;
        body += "}";
        promise.set_value(build_raw_json_response(body, cors));
      });
}

}  // namespace tos
