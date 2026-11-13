// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// net harness, overlay operations: overlay ids, signed overlay node records, broadcast certificates,
// member certificates, member flags and privacy rules, through the node's own overlay/ code.
#include <limits>
#include <map>
#include <string>
#include <utility>

#include "auto/tl/tos_api.hpp"
#include "keys/encryptor.h"
#include "overlay/overlay-id.hpp"
#include "overlay/overlay-member-flags.h"
#include "overlay/overlays.h"
#include "tl-utils/tl-utils.hpp"

#include "net-common.h"

namespace conformance::net {

namespace overlay = tos::overlay;
namespace tos_api = tos::tos_api;

namespace {

// Member certificates expire against the wall clock; a context may only use expiry times whose verdict
// cannot change while the fixtures are in use.
constexpr td::int32 kLatestPastExpiry = 1000000000;

std::string bits(const td::Bits256 &value) {
  return hex(value.as_slice());
}

std::string serialized_key(const tos::PublicKey &key) {
  return hex(tos::serialize_tl_object(key.tl(), true).as_slice());
}

std::string check_result(overlay::BroadcastCheckResult result) {
  switch (result) {
    case overlay::BroadcastCheckResult::Forbidden:
      return "forbidden";
    case overlay::BroadcastCheckResult::NeedCheck:
      return "need_check";
    case overlay::BroadcastCheckResult::Allowed:
      return "allowed";
  }
  return "unknown";
}

template <class T>
td::Result<td::Result<tos::tl_object_ptr<T>>> wire_object(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(bytes, hex_field(ctx, field));
  auto parsed = tos::fetch_tl_object<T>(td::BufferSlice(bytes), true);
  if (parsed.is_error()) {
    return td::Result<tos::tl_object_ptr<T>>(tl_error(parsed.error()));
  }
  return td::Result<tos::tl_object_ptr<T>>(parsed.move_as_ok());
}

std::string signature_verdict(const tos::PublicKey &key, td::Slice message, td::Slice signature) {
  auto encryptor = key.create_encryptor();
  if (encryptor.is_error()) {
    return quote(reason_class(encryptor.error().message()));
  }
  auto status = encryptor.ok()->check_signature(message, signature);
  return status.is_ok() ? std::string("\"valid\"") : quote(reason_class(status.message()));
}

std::string member_certificate_json(const overlay::OverlayMemberCertificate &cert,
                                    const tos::adnl::AdnlNodeIdShort &node) {
  if (cert.empty()) {
    return "{\"empty\":true,\"issued_by\":null,\"slot\":null,\"expire_at\":" + std::to_string(cert.expire_at()) +
           ",\"to_sign\":null,\"signature\":null,\"signature_check\":null,\"canonical\":" +
           quote(hex(tos::serialize_tl_object(cert.tl(), true).as_slice())) + "}";
  }
  auto to_sign = cert.to_sign_data(node);
  return "{\"empty\":false,\"issued_by\":" + quote(serialized_key(cert.issued_by())) +
         ",\"slot\":" + std::to_string(cert.slot()) + ",\"expire_at\":" + std::to_string(cert.expire_at()) +
         ",\"to_sign\":" + quote(hex(to_sign.as_slice())) + ",\"signature\":" + quote(hex(cert.signature())) +
         ",\"signature_check\":" + signature_verdict(cert.issued_by(), to_sign.as_slice(), cert.signature()) +
         ",\"canonical\":" + quote(hex(tos::serialize_tl_object(cert.tl(), true).as_slice())) + "}";
}

}  // namespace

td::Result<std::string> op_overlay_id(td::JsonObject &ctx) {
  TRY_RESULT(name, hex_field(ctx, "name"));
  overlay::OverlayIdFull full{td::BufferSlice(name)};
  return "{\"outcome\":\"overlay_id\",\"short_id\":" + quote(bits(full.compute_short_id().bits256_value())) +
         ",\"public_key\":" + quote(serialized_key(full.pubkey())) + "}";
}

// OverlayNode::create on a received overlay.node, then the node's signature over overlay.node.toSign.
td::Result<std::string> op_overlay_node(td::JsonObject &ctx) {
  TRY_RESULT(tl, wire_object<tos_api::overlay_node>(ctx, "node"));
  if (tl.is_error()) {
    return refused(tl.error());
  }
  auto node = overlay::OverlayNode::create(tl.ok());
  if (node.is_error()) {
    return refused(node.error());
  }
  auto &n = node.ok_ref();
  auto check = n.check_signature();
  const auto adnl_id = n.adnl_id_short();
  return "{\"outcome\":\"overlay_node\",\"adnl_short_id\":" + quote(bits(adnl_id.bits256_value())) +
         ",\"overlay\":" + quote(bits(n.overlay_id().bits256_value())) + ",\"flags\":" + std::to_string(n.flags()) +
         ",\"version\":" + std::to_string(n.version()) + ",\"to_sign\":" + quote(hex(n.to_sign().as_slice())) +
         ",\"signature_check\":" + (check.is_ok() ? std::string("\"valid\"") : quote(reason_class(check.message()))) +
         ",\"receives_regular\":" + json_bool(overlay::OverlayMemberFlags::receives_regular(n.flags())) +
         ",\"receives_plumtree\":" + json_bool(overlay::OverlayMemberFlags::receives_plumtree(n.flags())) +
         ",\"certificate\":" + member_certificate_json(*n.certificate(), adnl_id) +
         ",\"canonical\":" + quote(hex(tos::serialize_tl_object(n.tl(), true).as_slice())) + "}";
}

// Certificate::create, to_sign and check, as a broadcast's certificate is checked for its source.
td::Result<std::string> op_overlay_certificate(td::JsonObject &ctx) {
  TRY_RESULT(overlay_id, bits256_field(ctx, "overlay_id"));
  TRY_RESULT(issued_to, bits256_field(ctx, "issued_to"));
  TRY_RESULT(unix_time, int32_field(ctx, "unix_time"));
  TRY_RESULT(size, uint32_field(ctx, "size"));
  TRY_RESULT(is_fec, bool_field(ctx, "is_fec"));
  TRY_RESULT(tl, wire_object<tos_api::overlay_Certificate>(ctx, "certificate"));
  if (tl.is_error()) {
    return refused(tl.error());
  }
  auto cert = overlay::Certificate::create(tl.ok());
  if (cert.is_error()) {
    return refused(cert.error());
  }
  if (cert.ok() == nullptr) {
    return std::string(
        "{\"outcome\":\"certificate\",\"empty\":true,\"issuer\":null,\"to_sign\":null,\"check\":null,"
        "\"canonical\":null}");
  }
  const auto &c = *cert.ok();
  const overlay::OverlayIdShort overlay_short{overlay_id};
  const tos::PublicKeyHash node{issued_to};
  return "{\"outcome\":\"certificate\",\"empty\":false,\"issuer\":" + quote(bits(c.issuer_hash().bits256_value())) +
         ",\"to_sign\":" + quote(hex(c.to_sign(overlay_short, node).as_slice())) +
         ",\"check\":" + quote(check_result(c.check(node, overlay_short, unix_time, size, is_fec))) +
         ",\"canonical\":" + quote(hex(tos::serialize_tl_object(c.tl(), true).as_slice())) + "}";
}

// A member certificate as validate_peer_certificate reads it: its fields, the data its issuer signs for
// the node, the issuer's signature over that data, and whether it has expired at an explicit time.
td::Result<std::string> op_overlay_member_certificate(td::JsonObject &ctx) {
  TRY_RESULT(node_id, bits256_field(ctx, "node"));
  TRY_RESULT(now, int32_field(ctx, "now"));
  TRY_RESULT(tl, wire_object<tos_api::overlay_MemberCertificate>(ctx, "certificate"));
  if (tl.is_error()) {
    return refused(tl.error());
  }
  overlay::OverlayMemberCertificate cert{tl.ok().get()};
  if (!cert.empty() && cert.expire_at() > kLatestPastExpiry &&
      cert.expire_at() != std::numeric_limits<td::int32>::max()) {
    return td::Status::Error("certificate: expire_at must be at most 1000000000 or 2147483647 (wall-clock verdict)");
  }
  const tos::adnl::AdnlNodeIdShort node{node_id};
  return "{\"outcome\":\"member_certificate\",\"certificate\":" + member_certificate_json(cert, node) +
         ",\"expired\":" + json_bool(cert.is_expired(static_cast<double>(now))) + "}";
}

td::Result<std::string> op_overlay_member_flags(td::JsonObject &ctx) {
  TRY_RESULT(flags, uint32_field(ctx, "flags"));
  TRY_RESULT(enabled, bool_field(ctx, "plumtree_enabled"));
  TRY_RESULT(original_sender, bool_field(ctx, "original_sender"));
  using Flags = overlay::OverlayMemberFlags;
  return "{\"outcome\":\"member_flags\",\"valid\":" + json_bool(Flags::valid(flags)) +
         ",\"receives_regular\":" + json_bool(Flags::receives_regular(flags)) +
         ",\"receives_plumtree\":" + json_bool(Flags::receives_plumtree(flags)) +
         ",\"public_flags\":" + std::to_string(Flags::public_flags(flags, enabled, original_sender)) + "}";
}

td::Result<std::string> op_overlay_privacy_rules(td::JsonObject &ctx) {
  TRY_RESULT(max_size, uint32_field(ctx, "max_unauth_size"));
  TRY_RESULT(flags, uint32_field(ctx, "flags"));
  TRY_RESULT(keys_value, array_field(ctx, "authorized_keys", 1024));
  TRY_RESULT(source, bits256_field(ctx, "source"));
  TRY_RESULT(size, uint32_field(ctx, "size"));
  TRY_RESULT(is_fec, bool_field(ctx, "is_fec"));
  TRY_RESULT(is_any_sender, bool_field(ctx, "is_any_sender"));
  std::map<tos::PublicKeyHash, td::uint32> authorized;
  for (auto &item : keys_value.get_array()) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("authorized_keys: objects required");
    }
    auto &entry = item.get_object();
    TRY_RESULT(key, bits256_field(entry, "key"));
    TRY_RESULT(limit, uint32_field(entry, "max_size"));
    if (!authorized.emplace(tos::PublicKeyHash{key}, limit).second) {
      return td::Status::Error("authorized_keys: repeated key");
    }
  }
  overlay::OverlayPrivacyRules rules(max_size, flags, std::move(authorized));
  return "{\"outcome\":\"privacy_rules\",\"check\":" +
         quote(check_result(rules.check_rules(tos::PublicKeyHash{source}, size, is_fec, is_any_sender))) +
         ",\"max_broadcast_size\":" + std::to_string(rules.max_broadcast_size()) + "}";
}

}  // namespace conformance::net
