// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Shared pieces of the net harness (harness-net.cpp and the net-*.cpp operation files): context
// decoding with bounds, lowercase-hex output, and the fixed refusal-class table.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/int_types.h"

namespace tos::adnl {
class AdnlPacket;
class AdnlMessage;
class AdnlAddressList;
}  // namespace tos::adnl

namespace conformance::net {

// Largest byte input of any field. The largest wire object a node accepts is a reassembled ADNL message
// (about 1 MiB), so nothing a peer can send is cut by this bound.
constexpr std::size_t kMaxBytes = 1u << 20;
// Largest list in a context (packets of an RLDP transfer, symbols of a FEC decode, gate events).
constexpr std::size_t kMaxItems = 4096;

// The class of a refusal by node code, from the first rule whose text occurs in the message;
// "unclassified" when none does.
std::string reason_class(td::Slice message);
std::string refused(const td::Status &status);
std::string refused_text(td::Slice message);

std::string hex(td::Slice bytes);
std::string quote(td::Slice text);
std::string json_bool(bool value);
std::string decimal_text(td::uint64 value);

// Field decoding. Every failure is a harness error: the context did not say what it must.
td::Result<std::string> hex_field(td::JsonObject &obj, td::Slice field, std::size_t max_bytes = kMaxBytes);
td::Result<td::Bits256> bits256_field(td::JsonObject &obj, td::Slice field);
td::Result<td::int32> int32_field(td::JsonObject &obj, td::Slice field);
td::Result<td::uint32> uint32_field(td::JsonObject &obj, td::Slice field);
td::Result<td::uint64> decimal_field(td::JsonObject &obj, td::Slice field);
td::Result<double> number_field(td::JsonObject &obj, td::Slice field);
td::Result<bool> bool_field(td::JsonObject &obj, td::Slice field);
td::Result<td::JsonValue> array_field(td::JsonObject &obj, td::Slice field, std::size_t max_items);

// A TL refusal in the node's own words, so it is classified like every other refusal.
td::Status tl_error(const td::Status &status);

// Canonical summaries shared by several operations.
std::string message_json(const tos::adnl::AdnlMessage &message);
std::string address_list_json(const tos::adnl::AdnlAddressList &list);
std::string packet_json(const tos::adnl::AdnlPacket &packet, const std::string &signature_check);
// "valid", the refusal class of the signature check, or "null" (no full source key to check against).
std::string packet_signature_check(const tos::adnl::AdnlPacket &packet);

// Operations, grouped by component. Each returns an effect object or a harness error.
td::Result<std::string> op_public_key(td::JsonObject &ctx);
td::Result<std::string> op_private_key(td::JsonObject &ctx);
td::Result<std::string> op_sign(td::JsonObject &ctx);
td::Result<std::string> op_verify(td::JsonObject &ctx);
td::Result<std::string> op_encrypt(td::JsonObject &ctx);
td::Result<std::string> op_decrypt(td::JsonObject &ctx);
td::Result<std::string> op_shared_secret(td::JsonObject &ctx);
td::Result<std::string> op_adnl_id(td::JsonObject &ctx);

td::Result<std::string> op_adnl_address_list(td::JsonObject &ctx);
td::Result<std::string> op_adnl_message(td::JsonObject &ctx);
td::Result<std::string> op_adnl_packet(td::JsonObject &ctx);
td::Result<std::string> op_adnl_datagram(td::JsonObject &ctx);
td::Result<std::string> op_adnl_channel(td::JsonObject &ctx);
td::Result<std::string> op_preauth_source(td::JsonObject &ctx);
td::Result<std::string> op_preauth_gate(td::JsonObject &ctx);

td::Result<std::string> op_overlay_id(td::JsonObject &ctx);
td::Result<std::string> op_overlay_node(td::JsonObject &ctx);
td::Result<std::string> op_overlay_broadcast(td::JsonObject &ctx);
td::Result<std::string> op_overlay_certificate(td::JsonObject &ctx);
td::Result<std::string> op_overlay_member_certificate(td::JsonObject &ctx);
td::Result<std::string> op_overlay_member_flags(td::JsonObject &ctx);
td::Result<std::string> op_overlay_privacy_rules(td::JsonObject &ctx);

td::Result<std::string> op_fec_type(td::JsonObject &ctx);
td::Result<std::string> op_fec_encode(td::JsonObject &ctx);
td::Result<std::string> op_fec_decode(td::JsonObject &ctx);
td::Result<std::string> op_rldp2_fec_helper(td::JsonObject &ctx);
td::Result<std::string> op_rldp2_budget(td::JsonObject &ctx);
td::Result<std::string> op_rldp2_receive(td::JsonObject &ctx);
td::Result<std::string> op_rldp2_send(td::JsonObject &ctx);

}  // namespace conformance::net
