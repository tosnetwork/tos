// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// net harness: the network wire layer a peer implementation must match byte for byte, run through the
// node's own code (schema/harness/net-v1.schema.json). The field "op" selects one operation:
//
//   keys        public_key, private_key, sign, verify, encrypt, decrypt, shared_secret, adnl_id
//               (keys/keys.cpp, keys/encryptor.cpp, the ADNL id text form)
//   adnl        adnl_address_list, adnl_message, adnl_packet, adnl_datagram, adnl_channel, preauth_source,
//               preauth_gate (net-adnl.cpp)
//   overlay     overlay_id, overlay_node, overlay_certificate, overlay_member_certificate,
//               overlay_member_flags, overlay_privacy_rules (net-overlay.cpp)
//   transport   fec_type, fec_encode, fec_decode, rldp2_fec_helper, rldp2_budget, rldp2_receive,
//               rldp2_send (net-transport.cpp)
//
// A refusal by node code is {"outcome": "refused", "reason": <class>}; the class comes from the node's
// message by the fixed table kReasonRules, so two implementations agree on the class, not the wording.
// A message no rule matches is "unclassified". Inputs that are the local node's own configuration
// (its private keys, encoder parameters the node never takes from a peer) and inputs outside the bounds
// below are harness errors instead.
#include <algorithm>
#include <cstring>
#include <string>
#include <utility>

#include "adnl/adnl-node-id.hpp"
#include "auto/tl/tos_api.hpp"
#include "crypto/Ed25519.h"
#include "keys/encryptor.h"
#include "keys/keys.hpp"
#include "td/utils/misc.h"
#include "tl-utils/tl-utils.hpp"

#include "common.h"
#include "net-common.h"

namespace conformance::net {

namespace {

struct ReasonRule {
  const char *text;
  const char *reason;
};

// First match wins, so specific texts come before general ones.
constexpr ReasonRule kReasonRules[] = {
    // TL decoding (generated parsers and the boxed fetch).
    {"Not enough data to read", "tl_truncated"},
    {"Too much data to fetch", "tl_trailing_data"},
    {"Unknown constructor found", "tl_unknown_constructor"},
    {"Wrong constructor found", "tl_unknown_constructor"},
    {"Wrong vector length", "tl_bad_length"},
    {"can't be negative", "tl_negative_flags"},
    // Datagram routing and decryption.
    {"message too short", "datagram_short"},
    {"unknown dst", "unknown_destination"},
    {"unknown channel", "unknown_channel"},
    {"message is too short", "ciphertext_short"},
    {"sha256 mismatch after decryption", "digest_mismatch"},
    // Keys and signatures.
    {"Wrong signature", "invalid_signature"},
    {"Failed to compute modulo inverse", "degenerate_public_key"},
    {"Failed to compute shared secret", "degenerate_public_key"},
    {"can no sign channel messages", "signing_unsupported"},
    {"Fail decryptor", "key_unusable"},
    {"Fail encryptor", "key_unusable"},
    {"overlay id can not be used for encryption", "encryption_unsupported"},
    {"overlay signature must be empty", "overlay_signature_invalid"},
    {"overlay update rule should be", "overlay_signature_invalid"},
    {"bad public key", "not_ed25519"},
    {"Wrong length of adnl id", "adnl_id_length"},
    {"Invalid first byte", "adnl_id_prefix"},
    {"Hash mismatch", "adnl_id_checksum"},
    {"Wrong character in the string", "adnl_id_encoding"},
    {"Wrong padding", "adnl_id_encoding"},
    {"Nonzero padding", "adnl_id_encoding"},
    // ADNL packets.
    {"bad flags", "packet_bad_flags"},
    {"both flags one_message and mult_messages", "packet_message_flags"},
    {"flag one_message is set", "packet_message_flags"},
    {"source and short source mismatch", "packet_source_mismatch"},
    {"bad addr list", "packet_address_list_empty"},
    {"too big addr list", "address_list_oversize"},
    {"src not set", "source_missing"},
    {"no full src in packet", "source_unknown"},
    {"bad channel packet destination", "channel_source_mismatch"},
    // Pre-authentication admission.
    {"pre-authentication source limit exceeded", "source_limit"},
    {"rate limit exceeded", "rate_limited"},
    {"process decrypt budget exceeded", "process_budget"},
    {"local decrypt budget exceeded", "local_budget"},
    // Overlay.
    {"invalid overlay node flags or certificate", "overlay_node_invalid"},
    // FEC parameters and symbols.
    {"symbol_size below floor", "fec_symbol_size_small"},
    {"symbol_size is too big", "fec_symbol_size_large"},
    {"too many symbols", "fec_too_many_symbols"},
    {"wrong symbols_count", "fec_symbols_count"},
    {"only RaptorQ is allowed", "fec_not_raptorq"},
    {"K is too big", "fec_too_many_symbols"},
    {"Symbol has invalid length", "symbol_length"},
    {"Too big symbol id", "symbol_id_range"},
    {"Need more symbols", "need_more_symbols"},
    {"Not ready", "need_more_symbols"},
    {"Narrow cast failed", "fec_negative"},
};

std::string key_type(td::int32 id) {
  switch (id) {
    case tos::tos_api::pub_ed25519::ID:
    case tos::tos_api::pk_ed25519::ID:
      return "ed25519";
    case tos::tos_api::pub_aes::ID:
    case tos::tos_api::pk_aes::ID:
      return "aes";
    case tos::tos_api::pub_unenc::ID:
    case tos::tos_api::pk_unenc::ID:
      return "unenc";
    case tos::tos_api::pub_overlay::ID:
    case tos::tos_api::pk_overlay::ID:
      return "overlay";
    default:
      return "unknown";
  }
}

// A public key as a peer sends it: a TL refusal is the node's verdict on the bytes, so it is returned
// inside the result; only a field that is not bounded hex is a harness error.
td::Result<td::Result<tos::PublicKey>> wire_public_key(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(bytes, hex_field(ctx, field, 4096));
  auto tl = tos::fetch_tl_object<tos::tos_api::PublicKey>(td::Slice(bytes), true);
  if (tl.is_error()) {
    return td::Result<tos::PublicKey>(tl_error(tl.error()));
  }
  return td::Result<tos::PublicKey>(tos::PublicKey{tl.ok()});
}

// The local node's own private key: a malformed one is a harness error, not a verdict.
td::Result<tos::PrivateKey> local_private_key(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(bytes, hex_field(ctx, field, 4096));
  auto tl = tos::fetch_tl_object<tos::tos_api::PrivateKey>(td::Slice(bytes), true);
  if (tl.is_error()) {
    return td::Status::Error(PSLICE() << field << ": not a TL PrivateKey: " << tl.error().message());
  }
  return tos::PrivateKey{tl.ok()};
}

std::string serialized(const tos::PublicKey &key) {
  return hex(tos::serialize_tl_object(key.tl(), true).as_slice());
}

}  // namespace

std::string reason_class(td::Slice message) {
  const std::string text = message.str();
  for (const auto &rule : kReasonRules) {
    if (text.find(rule.text) != std::string::npos) {
      return rule.reason;
    }
  }
  return "unclassified";
}

std::string refused(const td::Status &status) {
  return refused_text(status.message());
}

std::string refused_text(td::Slice message) {
  return "{\"outcome\":\"refused\",\"reason\":" + quote(reason_class(message)) + "}";
}

std::string hex(td::Slice bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char c : bytes) {
    out += kDigits[c >> 4];
    out += kDigits[c & 15];
  }
  return out;
}

std::string quote(td::Slice text) {
  return conformance::json_quote(text);
}

std::string json_bool(bool value) {
  return conformance::json_bool(value);
}

std::string decimal_text(td::uint64 value) {
  return "\"" + std::to_string(value) + "\"";
}

td::Result<std::string> hex_field(td::JsonObject &obj, td::Slice field, std::size_t max_bytes) {
  TRY_RESULT(text, obj.get_required_string_field(field));
  if (text.size() % 2 != 0 || text.size() / 2 > max_bytes) {
    return td::Status::Error(PSLICE() << field << ": hex of even length up to " << max_bytes << " bytes required");
  }
  for (char c : text) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return td::Status::Error(PSLICE() << field << ": lowercase hex required");
    }
  }
  auto bytes = td::hex_decode(text);
  if (bytes.is_error()) {
    return td::Status::Error(PSLICE() << field << ": lowercase hex required");
  }
  return bytes.move_as_ok();
}

td::Result<td::Bits256> bits256_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(bytes, hex_field(obj, field, 32));
  if (bytes.size() != 32) {
    return td::Status::Error(PSLICE() << field << ": 32 bytes required");
  }
  td::Bits256 bits;
  std::memcpy(bits.data(), bytes.data(), 32);
  return bits;
}

td::Result<td::int32> int32_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(value, obj.get_required_long_field(field));
  if (value < -2147483648LL || value > 2147483647LL) {
    return td::Status::Error(PSLICE() << field << ": 32-bit signed integer required");
  }
  return static_cast<td::int32>(value);
}

td::Result<td::uint32> uint32_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(value, obj.get_required_long_field(field));
  if (value < 0 || value > 0xffffffffLL) {
    return td::Status::Error(PSLICE() << field << ": 0..2^32-1 required");
  }
  return static_cast<td::uint32>(value);
}

td::Result<td::uint64> decimal_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(text, obj.get_required_string_field(field));
  if (text.empty() || text.size() > 20 || text.find_first_not_of("0123456789") != std::string::npos ||
      (text.size() > 1 && text[0] == '0')) {
    return td::Status::Error(PSLICE() << field << ": canonical unsigned decimal required");
  }
  auto value = td::to_integer_safe<td::uint64>(text);
  if (value.is_error()) {
    return td::Status::Error(PSLICE() << field << ": value out of range");
  }
  return value.move_as_ok();
}

td::Result<double> number_field(td::JsonObject &obj, td::Slice field) {
  return obj.get_required_double_field(field);
}

td::Result<bool> bool_field(td::JsonObject &obj, td::Slice field) {
  return obj.get_required_bool_field(field);
}

td::Result<td::JsonValue> array_field(td::JsonObject &obj, td::Slice field, std::size_t max_items) {
  TRY_RESULT(value, obj.extract_required_field(field, td::JsonValue::Type::Array));
  if (value.get_array().size() > max_items) {
    return td::Status::Error(PSLICE() << field << ": at most " << max_items << " items");
  }
  return std::move(value);
}

td::Status tl_error(const td::Status &status) {
  return td::Status::Error(PSLICE() << "TL: " << status.message());
}

// ---------------------------------------------------------------------------------------------------------
// keys

td::Result<std::string> op_public_key(td::JsonObject &ctx) {
  TRY_RESULT(key, wire_public_key(ctx, "public_key"));
  if (key.is_error()) {
    return refused(key.error());
  }
  const auto &pub = key.ok();
  auto adnl = tos::adnl::AdnlNodeIdFull::create(pub.tl());
  std::string adnl_text = "null";
  if (adnl.is_ok()) {
    auto short_id = adnl.ok().compute_short_id();
    adnl_text = quote(short_id.serialize());
  }
  return "{\"outcome\":\"public_key\",\"key_type\":" + quote(key_type(pub.tl()->get_id())) +
         ",\"short_id\":" + quote(hex(pub.compute_short_id().as_slice())) +
         ",\"serialized\":" + quote(serialized(pub)) + ",\"serialized_size\":" + std::to_string(pub.serialized_size()) +
         ",\"adnl_id_text\":" + adnl_text + "}";
}

td::Result<std::string> op_private_key(td::JsonObject &ctx) {
  TRY_RESULT(key, local_private_key(ctx, "private_key"));
  auto pub = key.compute_public_key();
  return "{\"outcome\":\"private_key\",\"key_type\":" + quote(key_type(key.tl()->get_id())) +
         ",\"public_key\":" + quote(serialized(pub)) +
         ",\"short_id\":" + quote(hex(key.compute_short_id().as_slice())) + "}";
}

td::Result<std::string> op_sign(td::JsonObject &ctx) {
  TRY_RESULT(key, local_private_key(ctx, "private_key"));
  TRY_RESULT(message, hex_field(ctx, "message"));
  TRY_RESULT(decryptor, key.create_decryptor());
  auto signature = decryptor->sign(td::Slice(message));
  if (signature.is_error()) {
    return refused(signature.error());
  }
  return "{\"outcome\":\"signature\",\"signature\":" + quote(hex(signature.ok().as_slice())) + "}";
}

td::Result<std::string> op_verify(td::JsonObject &ctx) {
  TRY_RESULT(message, hex_field(ctx, "message"));
  TRY_RESULT(signature, hex_field(ctx, "signature", 4096));
  TRY_RESULT(key, wire_public_key(ctx, "public_key"));
  if (key.is_error()) {
    return refused(key.error());
  }
  TRY_RESULT(encryptor, key.ok().create_encryptor());
  auto status = encryptor->check_signature(td::Slice(message), td::Slice(signature));
  if (status.is_error()) {
    return refused(status);
  }
  return std::string("{\"outcome\":\"verified\"}");
}

td::Result<std::string> op_encrypt(td::JsonObject &ctx) {
  TRY_RESULT(data, hex_field(ctx, "data"));
  TRY_RESULT(key, wire_public_key(ctx, "public_key"));
  if (key.is_error()) {
    return refused(key.error());
  }
  if (key.ok().is_ed25519()) {
    // EncryptorEd25519 draws a fresh ephemeral key for every message; its output is not a function of
    // the context. Its receive side is the decrypt operation.
    return td::Status::Error("public_key: ed25519 encryption is randomised; pin it with decrypt");
  }
  TRY_RESULT(encryptor, key.ok().create_encryptor());
  auto out = encryptor->encrypt(td::Slice(data));
  if (out.is_error()) {
    return refused(out.error());
  }
  return "{\"outcome\":\"ciphertext\",\"ciphertext\":" + quote(hex(out.ok().as_slice())) + "}";
}

td::Result<std::string> op_decrypt(td::JsonObject &ctx) {
  TRY_RESULT(key, local_private_key(ctx, "private_key"));
  TRY_RESULT(ciphertext, hex_field(ctx, "ciphertext"));
  TRY_RESULT(decryptor, key.create_decryptor());
  auto out = decryptor->decrypt(td::Slice(ciphertext));
  if (out.is_error()) {
    return refused(out.error());
  }
  return "{\"outcome\":\"plaintext\",\"plaintext\":" + quote(hex(out.ok().as_slice())) + "}";
}

td::Result<std::string> op_shared_secret(td::JsonObject &ctx) {
  TRY_RESULT(key, local_private_key(ctx, "private_key"));
  TRY_RESULT(peer, wire_public_key(ctx, "public_key"));
  if (peer.is_error()) {
    return refused(peer.error());
  }
  TRY_RESULT(local, key.export_as_ed25519());
  if (!peer.ok().is_ed25519()) {
    return td::Status::Error("public_key: the shared secret is defined for ed25519 keys only");
  }
  auto secret = td::Ed25519::compute_shared_secret(peer.ok().ed25519_value().export_key(), local);
  if (secret.is_error()) {
    return refused(secret.error());
  }
  return "{\"outcome\":\"secret\",\"secret\":" + quote(hex(td::Slice(secret.ok()))) + "}";
}

td::Result<std::string> op_adnl_id(td::JsonObject &ctx) {
  if (ctx.has_field("text") == ctx.has_field("id")) {
    return td::Status::Error("exactly one of text and id");
  }
  tos::adnl::AdnlNodeIdShort id;
  if (ctx.has_field("id")) {
    TRY_RESULT(bits, bits256_field(ctx, "id"));
    id = tos::adnl::AdnlNodeIdShort{bits};
  } else {
    TRY_RESULT(text, ctx.get_required_string_field("text"));
    if (text.size() > 256) {
      return td::Status::Error("text: at most 256 characters");
    }
    auto parsed = tos::adnl::AdnlNodeIdShort::parse(text);
    if (parsed.is_error()) {
      return refused(parsed.error());
    }
    id = parsed.move_as_ok();
  }
  return "{\"outcome\":\"adnl_id\",\"id\":" + quote(hex(id.as_slice())) + ",\"text\":" + quote(id.serialize()) + "}";
}

namespace {

using OpFn = td::Result<std::string> (*)(td::JsonObject &);

struct OpEntry {
  const char *name;
  OpFn fn;
};

constexpr OpEntry kOps[] = {
    {"public_key", op_public_key},
    {"private_key", op_private_key},
    {"sign", op_sign},
    {"verify", op_verify},
    {"encrypt", op_encrypt},
    {"decrypt", op_decrypt},
    {"shared_secret", op_shared_secret},
    {"adnl_id", op_adnl_id},
    {"adnl_address_list", op_adnl_address_list},
    {"adnl_message", op_adnl_message},
    {"adnl_packet", op_adnl_packet},
    {"adnl_datagram", op_adnl_datagram},
    {"adnl_channel", op_adnl_channel},
    {"preauth_source", op_preauth_source},
    {"preauth_gate", op_preauth_gate},
    {"overlay_id", op_overlay_id},
    {"overlay_node", op_overlay_node},
    {"overlay_certificate", op_overlay_certificate},
    {"overlay_member_certificate", op_overlay_member_certificate},
    {"overlay_member_flags", op_overlay_member_flags},
    {"overlay_privacy_rules", op_overlay_privacy_rules},
    {"fec_type", op_fec_type},
    {"fec_encode", op_fec_encode},
    {"fec_decode", op_fec_decode},
    {"rldp2_fec_helper", op_rldp2_fec_helper},
    {"rldp2_budget", op_rldp2_budget},
    {"rldp2_receive", op_rldp2_receive},
    {"rldp2_send", op_rldp2_send},
};

td::Result<std::string> run_net(td::JsonObject &ctx) {
  TRY_RESULT(op, ctx.get_required_string_field("op"));
  for (const auto &entry : kOps) {
    if (op == entry.name) {
      return entry.fn(ctx);
    }
  }
  return td::Status::Error("unknown op");
}

}  // namespace

}  // namespace conformance::net

CONFORMANCE_REGISTER_HARNESS(net, conformance::net::run_net);
