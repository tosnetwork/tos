// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// net harness, transport operations: FEC parameters as a peer announces them (fec/), the RaptorQ, online
// and round-robin codes (tdfec/), and RLDP2 transfers on one RldpConnection (rldp2/).
#include <array>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "auto/tl/tos_api.hpp"
#include "fec/fec.h"
#include "rldp2/FecHelper.h"
#include "rldp2/OutboundTransfer.h"
#include "rldp2/RldpConnection.h"
#include "rldp2/rldp-inbound-budget.h"
#include "td/fec/fec.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "td/utils/overloaded.h"
#include "tl-utils/tl-utils.hpp"

#include "net-common.h"

namespace conformance::net {

namespace tos_api = tos::tos_api;

namespace {

// RaptorQ is specified for at most 56403 source symbols; the harness stays well inside it so that a
// precalculation finishes quickly. Symbol ids of RaptorQ are 24-bit.
constexpr std::size_t kMaxSourceSymbols = 10000;
constexpr std::size_t kMaxSymbolSize = 2048;
constexpr td::uint32 kMaxSymbolId = (1u << 24) - 1;
constexpr std::size_t kMaxRequestedSymbols = 1024;
// Decoded data up to this size is in the effect as bytes; larger data only as its digest.
constexpr std::size_t kMaxInlineData = 4096;

std::string sha256_hex(td::Slice data) {
  return hex(td::sha256(data));
}

std::string data_json(td::Slice data) {
  return "\"data_sha256\":" + quote(sha256_hex(data)) +
         ",\"data\":" + (data.size() <= kMaxInlineData ? quote(hex(data)) : std::string("null"));
}

std::string parameters_json(std::size_t data_size, std::size_t symbol_size, std::size_t symbols_count) {
  return "{\"data_size\":" + std::to_string(data_size) + ",\"symbol_size\":" + std::to_string(symbol_size) +
         ",\"symbols_count\":" + std::to_string(symbols_count) + "}";
}

enum class Algorithm { raptorq, online, round_robin };

td::Result<Algorithm> algorithm_field(td::JsonObject &ctx) {
  TRY_RESULT(name, ctx.get_required_string_field("algorithm"));
  if (name == "raptorq") {
    return Algorithm::raptorq;
  }
  if (name == "online") {
    return Algorithm::online;
  }
  if (name == "round_robin") {
    return Algorithm::round_robin;
  }
  return td::Status::Error("algorithm: raptorq, online or round_robin");
}

// Code parameters the node only ever derives itself (an encoder's own, or FecType::create's): the codes
// abort on inconsistent ones, so they are bounded here.
td::Status check_code_parameters(std::size_t data_size, std::size_t symbol_size, std::size_t symbols_count) {
  if (data_size == 0 || data_size > kMaxBytes) {
    return td::Status::Error("data_size: 1..1048576 required");
  }
  if (symbol_size == 0 || symbol_size > kMaxSymbolSize) {
    return td::Status::Error("symbol_size: 1..2048 required");
  }
  const auto count = (data_size + symbol_size - 1) / symbol_size;
  if (count > kMaxSourceSymbols) {
    return td::Status::Error("at most 10000 source symbols");
  }
  if (symbols_count != count) {
    return td::Status::Error("symbols_count must be ceil(data_size / symbol_size)");
  }
  return td::Status::OK();
}

td::Result<std::vector<td::uint32>> symbol_ids(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(list_value, array_field(ctx, field, kMaxRequestedSymbols));
  std::vector<td::uint32> ids;
  for (auto &item : list_value.get_array()) {
    if (item.type() != td::JsonValue::Type::Number) {
      return td::Status::Error(PSLICE() << field << ": integers required");
    }
    auto id = td::to_integer_safe<td::uint32>(item.get_number());
    if (id.is_error() || id.ok() > kMaxSymbolId) {
      return td::Status::Error(PSLICE() << field << ": symbol ids 0..2^24-1 required");
    }
    ids.push_back(id.ok());
  }
  return ids;
}

std::string symbols_json(td::fec::Encoder &encoder, const std::vector<td::uint32> &ids) {
  std::string out = "[";
  for (auto id : ids) {
    if (encoder.get_info().ready_symbol_count <= id) {
      encoder.prepare_more_symbols();
    }
    auto symbol = encoder.gen_symbol(id);
    out += (out.size() > 1 ? "," : "") + std::string("{\"id\":") + std::to_string(symbol.id) +
           ",\"data\":" + quote(hex(symbol.data.as_slice())) + "}";
  }
  return out + "]";
}

}  // namespace

// fec::FecType::create on announced parameters (the check every FEC receiver runs before it allocates a
// decoder), and whether the decoder of the accepted type can then be created.
td::Result<std::string> op_fec_type(td::JsonObject &ctx) {
  TRY_RESULT(bytes, hex_field(ctx, "fec_type", 64));
  auto tl = tos::fetch_tl_object<tos_api::fec_Type>(td::Slice(bytes), true);
  if (tl.is_error()) {
    return refused(tl_error(tl.error()));
  }
  auto type = tos::fec::FecType::create(tl.move_as_ok());
  if (type.is_error()) {
    return refused(type.error());
  }
  auto decoder = type.ok().create_decoder();
  return "{\"outcome\":\"fec_type\",\"parameters\":" +
         parameters_json(type.ok().size(), type.ok().symbol_size(), type.ok().symbols_count()) +
         ",\"decoder\":" + (decoder.is_ok() ? std::string("\"ok\"") : quote(reason_class(decoder.error().message()))) +
         ",\"canonical\":" + quote(hex(tos::serialize_tl_object(type.ok().tl(), true).as_slice())) + "}";
}

td::Result<std::string> op_fec_encode(td::JsonObject &ctx) {
  TRY_RESULT(algorithm, algorithm_field(ctx));
  TRY_RESULT(data, hex_field(ctx, "data"));
  TRY_RESULT(symbol_size, uint32_field(ctx, "symbol_size"));
  TRY_RESULT(ids, symbol_ids(ctx, "symbol_ids"));
  if (data.empty()) {
    return td::Status::Error("data: at least one byte required");
  }
  if (symbol_size == 0) {
    return td::Status::Error("symbol_size: 1..2048 required");
  }
  TRY_STATUS(check_code_parameters(data.size(), symbol_size, (data.size() + symbol_size - 1) / symbol_size));
  std::string parameters;
  std::string symbols;
  switch (algorithm) {
    case Algorithm::raptorq: {
      auto encoder = td::fec::RaptorQEncoder::create(td::BufferSlice(data), symbol_size);
      auto p = encoder->get_parameters();
      parameters = parameters_json(p.data_size, p.symbol_size, p.symbols_count);
      symbols = symbols_json(*encoder, ids);
      break;
    }
    case Algorithm::online: {
      auto encoder = td::fec::OnlineEncoder::create(td::BufferSlice(data), symbol_size);
      auto p = encoder->get_parameters();
      parameters = parameters_json(p.data_size, p.symbol_size, p.symbols_count);
      symbols = symbols_json(*encoder, ids);
      break;
    }
    case Algorithm::round_robin: {
      auto encoder = td::fec::RoundRobinEncoder::create(td::BufferSlice(data), symbol_size);
      auto p = encoder->get_parameters();
      parameters = parameters_json(p.data_size, p.symbol_size, p.symbols_count);
      symbols = symbols_json(*encoder, ids);
      break;
    }
  }
  return "{\"outcome\":\"encoded\",\"parameters\":" + parameters + ",\"symbols\":" + symbols + "}";
}

td::Result<std::string> op_fec_decode(td::JsonObject &ctx) {
  TRY_RESULT(algorithm, algorithm_field(ctx));
  TRY_RESULT(data_size, uint32_field(ctx, "data_size"));
  TRY_RESULT(symbol_size, uint32_field(ctx, "symbol_size"));
  TRY_RESULT(symbols_count, uint32_field(ctx, "symbols_count"));
  TRY_STATUS(check_code_parameters(data_size, symbol_size, symbols_count));
  TRY_RESULT(list_value, array_field(ctx, "symbols", kMaxItems));
  std::vector<td::uint32> regenerate;
  const bool has_regenerate = ctx.has_field("regenerate");
  if (has_regenerate) {
    TRY_RESULT_ASSIGN(regenerate, symbol_ids(ctx, "regenerate"));
  }
  std::vector<td::fec::Symbol> symbols;
  for (auto &item : list_value.get_array()) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("symbols: objects required");
    }
    auto &obj = item.get_object();
    TRY_RESULT(id, uint32_field(obj, "id"));
    TRY_RESULT(bytes, hex_field(obj, "data", kMaxSymbolSize + 1));
    symbols.push_back(td::fec::Symbol{id, td::BufferSlice(bytes)});
  }
  std::unique_ptr<td::fec::Decoder> decoder;
  switch (algorithm) {
    case Algorithm::raptorq: {
      auto created = td::fec::RaptorQDecoder::create({data_size, symbol_size, symbols_count});
      if (created.is_error()) {
        return refused(created.error());
      }
      decoder = created.move_as_ok();
      break;
    }
    case Algorithm::online: {
      auto created = td::fec::OnlineDecoder::create({data_size, symbol_size, symbols_count});
      if (created.is_error()) {
        return refused(created.error());
      }
      decoder = created.move_as_ok();
      break;
    }
    case Algorithm::round_robin: {
      auto created = td::fec::RoundRobinDecoder::create({data_size, symbol_size, symbols_count});
      if (created.is_error()) {
        return refused(created.error());
      }
      decoder = created.move_as_ok();
      break;
    }
  }
  std::string added = "[";
  for (auto &symbol : symbols) {
    auto status = decoder->add_symbol(std::move(symbol));
    added += (added.size() > 1 ? "," : "") +
             (status.is_ok() ? std::string("\"ok\"") : quote(reason_class(status.message())));
  }
  added += "]";
  const bool may_try = decoder->may_try_decode();
  std::string result;
  std::string regenerated = "null";
  // Decoding is attempted whatever may_try_decode says, as a receiver that ignores it would; the decoders
  // refuse an early attempt themselves.
  auto decoded = decoder->try_decode(has_regenerate);
  if (decoded.is_error()) {
    result = "\"reason\":" + quote(reason_class(decoded.error().message())) + ",\"data_sha256\":null,\"data\":null";
  } else {
    result = "\"reason\":null," + data_json(decoded.ok().data.as_slice());
    if (has_regenerate) {
      if (decoded.ok().encoder == nullptr) {
        return td::Status::Error("the decoder returned no encoder");
      }
      regenerated = symbols_json(*decoded.ok_ref().encoder, regenerate);
    }
  }
  return "{\"outcome\":\"decode\",\"added\":" + added + ",\"may_try_decode\":" + json_bool(may_try) + "," + result +
         ",\"regenerated\":" + regenerated + "}";
}

td::Result<std::string> op_rldp2_fec_helper(td::JsonObject &ctx) {
  TRY_RESULT(symbols_count, uint32_field(ctx, "symbols_count"));
  TRY_RESULT(received, uint32_field(ctx, "received_symbols_count"));
  // The helper's arithmetic is 32-bit; the sender keeps both counts far below 2^31.
  if (symbols_count > (1u << 30) || received > (1u << 30)) {
    return td::Status::Error("counts: at most 2^30");
  }
  tos::rldp2::FecHelper helper;
  helper.symbols_count = symbols_count;
  helper.received_symbols_count = received;
  return "{\"outcome\":\"fec_helper\",\"fec_symbols_count\":" + std::to_string(helper.get_fec_symbols_count()) +
         ",\"left_fec_symbols_count\":" + std::to_string(helper.get_left_fec_symbols_count()) + "}";
}

td::Result<std::string> op_rldp2_budget(td::JsonObject &ctx) {
  TRY_RESULT(data_size, decimal_field(ctx, "data_size"));
  TRY_RESULT(symbol_size, decimal_field(ctx, "symbol_size"));
  TRY_RESULT(symbols_count, decimal_field(ctx, "symbols_count"));
  auto reservation = tos::rldp2::rldp_decoder_reservation_bytes(data_size, symbol_size, symbols_count);
  auto solver = tos::rldp2::rldp_solver_working_bytes(symbol_size, symbols_count);
  return "{\"outcome\":\"budget\",\"reservation_bytes\":" +
         (reservation ? decimal_text(reservation.value()) : std::string("null")) +
         ",\"solver_bytes\":" + (solver ? decimal_text(solver.value()) : std::string("null")) +
         ",\"part_size\":" + std::to_string(tos::rldp2::OutboundTransfer::part_size()) +
         ",\"symbol_size\":" + std::to_string(tos::rldp2::OutboundTransfer::symbol_size()) +
         ",\"default_mtu\":" + std::to_string(tos::rldp2::RldpConnection::DEFAULT_MTU) + "}";
}

namespace {

class RecordingCallback : public tos::rldp2::ConnectionCallback {
 public:
  void send_raw(td::BufferSlice small_datagram) override {
    sent.push_back(std::move(small_datagram));
  }
  void receive(tos::rldp2::TransferId transfer_id, td::Result<td::BufferSlice> r_data) override {
    std::string entry = "{\"transfer_id\":" + quote(hex(transfer_id.as_slice()));
    if (r_data.is_error()) {
      entry += ",\"reason\":" + quote(reason_class(r_data.error().message())) + ",\"size\":null," +
               "\"data_sha256\":null,\"data\":null}";
    } else {
      entry += ",\"reason\":null,\"size\":" + std::to_string(r_data.ok().size()) + "," +
               data_json(r_data.ok().as_slice()) + "}";
    }
    received.push_back(std::move(entry));
  }
  void on_sent(tos::rldp2::TransferId transfer_id, td::Result<td::Unit> state) override {
    sent_done.push_back("{\"transfer_id\":" + quote(hex(transfer_id.as_slice())) + ",\"reason\":" +
                        (state.is_ok() ? std::string("null") : quote(reason_class(state.error().message()))) + "}");
  }
  void on_part_completed(tos::rldp2::TransferId transfer_id, td::uint32 part, td::uint64 decoded_bytes) override {
    parts.push_back("{\"transfer_id\":" + quote(hex(transfer_id.as_slice())) + ",\"part\":" + std::to_string(part) +
                    ",\"decoded_bytes\":" + std::to_string(decoded_bytes) + "}");
  }

  std::vector<td::BufferSlice> sent;
  std::vector<std::string> received;
  std::vector<std::string> sent_done;
  std::vector<std::string> parts;
};

std::string join(const std::vector<std::string> &items) {
  std::string out = "[";
  for (const auto &item : items) {
    out += (out.size() > 1 ? "," : "") + item;
  }
  return out + "]";
}

td::Result<std::shared_ptr<tos::rldp2::RldpInboundBudget>> budget_from(td::JsonObject &ctx) {
  if (!ctx.has_field("budget")) {
    return std::make_shared<tos::rldp2::RldpInboundBudget>(tos::rldp2::rldp_max_active_decoders,
                                                           tos::rldp2::rldp_max_inbound_bytes);
  }
  td::JsonValue holder;
  TRY_RESULT_ASSIGN(holder, ctx.extract_required_field("budget", td::JsonValue::Type::Object));
  TRY_RESULT(decoders, decimal_field(holder.get_object(), "max_decoders"));
  TRY_RESULT(bytes, decimal_field(holder.get_object(), "max_bytes"));
  return std::make_shared<tos::rldp2::RldpInboundBudget>(decoders, bytes);
}

}  // namespace

// Raw RLDP2 datagrams fed one by one to a fresh RldpConnection (receive_raw, then run). The effect lists, per
// datagram that caused any, the transfers delivered, the parts completed and the rldp2.complete answers;
// rldp2.confirm acknowledgements are left out, because when they are due depends on the clock.
td::Result<std::string> op_rldp2_receive(td::JsonObject &ctx) {
  TRY_RESULT(packets_value, array_field(ctx, "packets", kMaxItems));
  TRY_RESULT(budget, budget_from(ctx));
  std::vector<std::string> packets;
  std::size_t total = 0;
  for (auto &item : packets_value.get_array()) {
    if (item.type() != td::JsonValue::Type::String) {
      return td::Status::Error("packets: hex strings required");
    }
    auto text = item.get_string().str();
    if (text.size() % 2 != 0 || text.find_first_not_of("0123456789abcdef") != std::string::npos) {
      return td::Status::Error("packets: lowercase hex required");
    }
    auto bytes = td::hex_decode(text);
    if (bytes.is_error()) {
      return td::Status::Error("packets: lowercase hex required");
    }
    total += bytes.ok().size();
    if (total > 8 * kMaxBytes) {
      return td::Status::Error("packets: at most 8 MiB in all");
    }
    packets.push_back(bytes.move_as_ok());
  }
  tos::rldp2::RldpPeerIdentity peer{};
  tos::rldp2::RldpConnection connection(peer);
  connection.set_inbound_budget(budget);
  if (ctx.has_field("default_mtu")) {
    TRY_RESULT(mtu, decimal_field(ctx, "default_mtu"));
    connection.set_default_mtu(mtu);
  }
  if (ctx.has_field("requests")) {
    TRY_RESULT(requests_value, array_field(ctx, "requests", 256));
    for (auto &item : requests_value.get_array()) {
      if (item.type() != td::JsonValue::Type::Object) {
        return td::Status::Error("requests: objects required");
      }
      TRY_RESULT(transfer_id, bits256_field(item.get_object(), "transfer_id"));
      TRY_RESULT(max_size, decimal_field(item.get_object(), "max_size"));
      if (!connection.set_receive_limits(transfer_id, td::Timestamp::in(3600.0), max_size)) {
        return td::Status::Error("requests: refused by set_receive_limits");
      }
    }
  }
  std::string events = "[";
  for (std::size_t i = 0; i < packets.size(); i++) {
    RecordingCallback callback;
    connection.receive_raw(td::BufferSlice(packets[i]));
    connection.run(callback);
    std::vector<std::string> complete;
    for (auto &raw : callback.sent) {
      auto parsed = tos::fetch_tl_object<tos_api::rldp2_MessagePart>(raw.as_slice(), true);
      if (parsed.is_error()) {
        return td::Status::Error("the connection sent a datagram it cannot parse itself");
      }
      if (parsed.ok()->get_id() == tos_api::rldp2_complete::ID) {
        complete.push_back(quote(hex(raw.as_slice())));
      }
    }
    if (callback.received.empty() && callback.parts.empty() && complete.empty()) {
      continue;
    }
    events += std::string(events.size() > 1 ? "," : "") + "{\"index\":" + std::to_string(i) +
              ",\"received\":" + join(callback.received) + ",\"parts\":" + join(callback.parts) +
              ",\"complete\":" + join(complete) + "}";
  }
  events += "]";
  return "{\"outcome\":\"transfers\",\"events\":" + events +
         ",\"inbound_transfers\":" + std::to_string(connection.inbound_transfer_count()) +
         ",\"completed_transfers\":" + std::to_string(connection.completed_transfer_count()) + "}";
}

// RldpConnection::send of one transfer and the datagrams its first run emits: the transfer's framing, part
// split and symbol stream as a peer receives them.
td::Result<std::string> op_rldp2_send(td::JsonObject &ctx) {
  TRY_RESULT(transfer_id, bits256_field(ctx, "transfer_id"));
  TRY_RESULT(data, hex_field(ctx, "data", 4 * kMaxBytes));
  if (transfer_id.is_zero()) {
    // A zero id makes the connection draw a random one.
    return td::Status::Error("transfer_id: a non-zero id required");
  }
  if (data.empty()) {
    return td::Status::Error("data: at least one byte required");
  }
  tos::rldp2::RldpPeerIdentity peer{};
  tos::rldp2::RldpConnection connection(peer);
  RecordingCallback callback;
  connection.send(transfer_id, td::BufferSlice(data));
  connection.run(callback);
  std::string packets = "[";
  for (auto &raw : callback.sent) {
    auto parsed = tos::fetch_tl_object<tos_api::rldp2_MessagePart>(raw.as_slice(), true);
    if (parsed.is_error()) {
      return td::Status::Error("the connection sent a datagram it cannot parse itself");
    }
    std::string entry;
    tos_api::downcast_call(
        *parsed.ok(),
        td::overloaded(
            [&](tos_api::rldp2_messagePart &part) {
              td::int32 data_size = 0;
              td::int32 fec_symbol_size = 0;
              td::int32 symbols_count = 0;
              tos_api::downcast_call(*part.fec_type_, [&](auto &fec) {
                data_size = fec.data_size_;
                fec_symbol_size = fec.symbol_size_;
                symbols_count = fec.symbols_count_;
              });
              entry = "{\"type\":\"part\",\"fec_type\":" + std::to_string(part.fec_type_->get_id()) +
                      ",\"part\":" + std::to_string(part.part_) +
                      ",\"total_size\":" + decimal_text(static_cast<td::uint64>(part.total_size_)) +
                      ",\"seqno\":" + std::to_string(part.seqno_) +
                      ",\"fec\":" + parameters_json(data_size, fec_symbol_size, symbols_count) +
                      ",\"symbol_sha256\":" + quote(sha256_hex(part.data_.as_slice())) +
                      ",\"sha256\":" + quote(sha256_hex(raw.as_slice())) + "}";
            },
            [&](auto &other) { entry = "{\"type\":\"other\",\"sha256\":" + quote(sha256_hex(raw.as_slice())) + "}"; }));
    packets += (packets.size() > 1 ? "," : "") + entry;
  }
  packets += "]";
  return "{\"outcome\":\"sent\",\"packets\":" + packets +
         ",\"outbound_transfers\":" + std::to_string(connection.outbound_transfer_count()) + "}";
}

}  // namespace conformance::net
