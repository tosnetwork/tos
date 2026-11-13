# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""net harness: the network wire layer (schema/harness/net-v1.schema.json).

The context field "op" selects the operation; each op has its own required keys, and its effect is one
of the outcomes below or {"outcome": "refused", "reason": <class>}. Byte strings are lowercase hex, 32-byte
ids 64 lowercase hex digits. Refusal classes inside an effect (a packet's signature check, a channel's
received datagram, a gate's results, a decoder's per-symbol verdicts) come from the same fixed table.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

import fixture_types as t

NAME = "net"

ID_RE = re.compile(r"^[0-9a-f]{64}$")
DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
MAX_BYTES = 1 << 20
MAX_ITEMS = 4096
I32 = (-(1 << 31), (1 << 31) - 1)
U32 = (0, (1 << 32) - 1)

# The classes of kReasonRules in ref/harness-net.cpp; "unclassified" is any other message.
REASONS = frozenset(
    {
        "tl_truncated",
        "tl_trailing_data",
        "tl_unknown_constructor",
        "tl_bad_length",
        "tl_negative_flags",
        "datagram_short",
        "unknown_destination",
        "unknown_channel",
        "ciphertext_short",
        "digest_mismatch",
        "invalid_signature",
        "degenerate_public_key",
        "signing_unsupported",
        "key_unusable",
        "encryption_unsupported",
        "overlay_signature_invalid",
        "not_ed25519",
        "adnl_id_length",
        "adnl_id_prefix",
        "adnl_id_checksum",
        "adnl_id_encoding",
        "packet_bad_flags",
        "packet_message_flags",
        "packet_source_mismatch",
        "packet_address_list_empty",
        "address_list_oversize",
        "source_missing",
        "source_unknown",
        "channel_source_mismatch",
        "source_limit",
        "rate_limited",
        "process_budget",
        "local_budget",
        "overlay_node_invalid",
        "fec_symbol_size_small",
        "fec_symbol_size_large",
        "fec_too_many_symbols",
        "fec_symbols_count",
        "fec_not_raptorq",
        "symbol_length",
        "symbol_id_range",
        "need_more_symbols",
        "fec_negative",
        "unclassified",
    }
)

OP_REQUIRED: dict[str, frozenset[str]] = {
    "public_key": frozenset({"public_key"}),
    "private_key": frozenset({"private_key"}),
    "sign": frozenset({"private_key", "message"}),
    "verify": frozenset({"public_key", "message", "signature"}),
    "encrypt": frozenset({"public_key", "data"}),
    "decrypt": frozenset({"private_key", "ciphertext"}),
    "shared_secret": frozenset({"private_key", "public_key"}),
    "adnl_id": frozenset(),
    "adnl_address_list": frozenset({"address_list"}),
    "adnl_message": frozenset({"message"}),
    "adnl_packet": frozenset({"contents"}),
    "adnl_datagram": frozenset({"private_key", "datagram"}),
    "adnl_channel": frozenset({"local_channel_key", "peer_channel_key", "local_id", "peer_id"}),
    "preauth_source": frozenset({"address"}),
    "preauth_gate": frozenset({"max_sources", "source", "process", "local", "events"}),
    "overlay_id": frozenset({"name"}),
    "overlay_node": frozenset({"node"}),
    "overlay_certificate": frozenset(
        {"certificate", "overlay_id", "issued_to", "unix_time", "size", "is_fec"}
    ),
    "overlay_member_certificate": frozenset({"certificate", "node", "now"}),
    "overlay_member_flags": frozenset({"flags", "plumtree_enabled", "original_sender"}),
    "overlay_privacy_rules": frozenset(
        {
            "max_unauth_size",
            "flags",
            "authorized_keys",
            "source",
            "size",
            "is_fec",
            "is_any_sender",
        }
    ),
    "fec_type": frozenset({"fec_type"}),
    "fec_encode": frozenset({"algorithm", "data", "symbol_size", "symbol_ids"}),
    "fec_decode": frozenset({"algorithm", "data_size", "symbol_size", "symbols_count", "symbols"}),
    "rldp2_fec_helper": frozenset({"symbols_count", "received_symbols_count"}),
    "rldp2_budget": frozenset({"data_size", "symbol_size", "symbols_count"}),
    "rldp2_receive": frozenset({"packets"}),
    "rldp2_send": frozenset({"transfer_id", "data"}),
}
OP_OPTIONAL: dict[str, frozenset[str]] = {
    "adnl_id": frozenset({"id", "text"}),
    "adnl_channel": frozenset({"datagram", "send"}),
    "fec_decode": frozenset({"regenerate"}),
    "rldp2_receive": frozenset({"budget", "default_mtu", "requests"}),
}

CONTEXT_REQUIRED = frozenset({"op"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED.union(*OP_REQUIRED.values()).union(*OP_OPTIONAL.values())


def hex_bytes(value: object, where: str, max_bytes: int = MAX_BYTES) -> None:
    t.text(value, t.HEX_RE, where)
    if len(str(value)) > 2 * max_bytes:
        raise t.FixtureError(f"{where}: more than {max_bytes} bytes")


def ident(value: object, where: str) -> None:
    t.text(value, ID_RE, where)


def decimal(value: object, where: str) -> None:
    t.text(value, DECIMAL_RE, where)
    if int(str(value)) >= 1 << 64:
        raise t.FixtureError(f"{where}: above 2^64-1")


def i32(value: object, where: str) -> None:
    t.integer(value, where, *I32)


def u32(value: object, where: str) -> None:
    t.integer(value, where, *U32)


def ip_address(value: object, where: str) -> None:
    item = t.obj(value, where)
    t.keys(item, {"ip", "port"}, {"ip", "port"}, where)
    t.any_text(item["ip"], f"{where}.ip")
    if len(str(item["ip"])) > 64:
        raise t.FixtureError(f"{where}.ip: at most 64 characters")
    t.integer(item["port"], f"{where}.port", 1, 65535)


def gate_budget(value: object, where: str) -> None:
    item = t.obj(value, where)
    keys = {"burst", "period", "in_flight_limit"}
    t.keys(item, keys, keys, where)
    t.integer(item["burst"], f"{where}.burst", 1, 4096)
    period = item["period"]
    if not isinstance(period, (int, float)) or isinstance(period, bool) or not 60 <= period <= 1e9:
        raise t.FixtureError(f"{where}.period: 60..1e9 required")
    u32(item["in_flight_limit"], f"{where}.in_flight_limit")


def gate_events(value: object, where: str) -> None:
    for i, raw in enumerate(t.array(value, where, MAX_ITEMS)):
        at = f"{where}[{i}]"
        item = t.obj(raw, at)
        if "admit" in item:
            t.keys(item, {"admit"}, {"admit"}, at)
            ip_address(item["admit"], f"{at}.admit")
        else:
            t.keys(item, {"release"}, {"release"}, at)
            t.integer(item["release"], f"{at}.release", 0, MAX_ITEMS)


def authorized_keys(value: object, where: str) -> None:
    for i, raw in enumerate(t.array(value, where, 1024)):
        item = t.obj(raw, f"{where}[{i}]")
        t.keys(item, {"key", "max_size"}, {"key", "max_size"}, f"{where}[{i}]")
        ident(item["key"], f"{where}[{i}].key")
        u32(item["max_size"], f"{where}[{i}].max_size")


def symbol_ids(value: object, where: str) -> None:
    for i, raw in enumerate(t.array(value, where, 1024)):
        t.integer(raw, f"{where}[{i}]", 0, (1 << 24) - 1)


def symbols(value: object, where: str) -> None:
    for i, raw in enumerate(t.array(value, where, MAX_ITEMS)):
        item = t.obj(raw, f"{where}[{i}]")
        t.keys(item, {"id", "data"}, {"id", "data"}, f"{where}[{i}]")
        u32(item["id"], f"{where}[{i}].id")
        hex_bytes(item["data"], f"{where}[{i}].data", 2049)


def packets(value: object, where: str) -> None:
    for i, raw in enumerate(t.array(value, where, MAX_ITEMS)):
        hex_bytes(raw, f"{where}[{i}]")


def requests(value: object, where: str) -> None:
    for i, raw in enumerate(t.array(value, where, 256)):
        item = t.obj(raw, f"{where}[{i}]")
        t.keys(item, {"transfer_id", "max_size"}, {"transfer_id", "max_size"}, f"{where}[{i}]")
        ident(item["transfer_id"], f"{where}[{i}].transfer_id")
        decimal(item["max_size"], f"{where}[{i}].max_size")


def rldp_budget(value: object, where: str) -> None:
    item = t.obj(value, where)
    t.keys(item, {"max_decoders", "max_bytes"}, {"max_decoders", "max_bytes"}, where)
    decimal(item["max_decoders"], f"{where}.max_decoders")
    decimal(item["max_bytes"], f"{where}.max_bytes")


def boolean(value: object, where: str) -> None:
    _ = t.boolean(value, where)


def algorithm(value: object, where: str) -> None:
    if value not in ("raptorq", "online", "round_robin"):
        raise t.FixtureError(f"{where}: raptorq, online or round_robin")


def text(value: object, where: str) -> None:
    t.any_text(value, where)
    if len(str(value)) > 256:
        raise t.FixtureError(f"{where}: at most 256 characters")


FIELD_CHECKS: dict[str, Callable[[object, str], None]] = {
    "public_key": hex_bytes,
    "private_key": hex_bytes,
    "message": hex_bytes,
    "signature": hex_bytes,
    "data": hex_bytes,
    "ciphertext": hex_bytes,
    "id": ident,
    "text": text,
    "address_list": hex_bytes,
    "contents": hex_bytes,
    "datagram": hex_bytes,
    "send": hex_bytes,
    "local_channel_key": ident,
    "peer_channel_key": ident,
    "local_id": ident,
    "peer_id": ident,
    "address": ip_address,
    "max_sources": u32,
    "source": ident,
    "process": gate_budget,
    "local": gate_budget,
    "events": gate_events,
    "name": hex_bytes,
    "node": hex_bytes,
    "certificate": hex_bytes,
    "overlay_id": ident,
    "issued_to": ident,
    "unix_time": i32,
    "now": i32,
    "size": u32,
    "is_fec": boolean,
    "flags": u32,
    "plumtree_enabled": boolean,
    "original_sender": boolean,
    "max_unauth_size": u32,
    "authorized_keys": authorized_keys,
    "is_any_sender": boolean,
    "fec_type": hex_bytes,
    "algorithm": algorithm,
    "symbol_size": u32,
    "symbol_ids": symbol_ids,
    "data_size": u32,
    "symbols_count": u32,
    "symbols": symbols,
    "regenerate": symbol_ids,
    "received_symbols_count": u32,
    "packets": packets,
    "budget": rldp_budget,
    "default_mtu": decimal,
    "requests": requests,
    "transfer_id": ident,
}

# Fields whose type depends on the op: the member certificate's node is an id (the overlay node record is
# bytes), the gate's source a budget (the privacy rules' source an id), the RLDP2 budget's sizes 64-bit
# decimals.
OP_FIELD_KINDS: dict[tuple[str, str], Callable[[object, str], None]] = {
    ("overlay_member_certificate", "node"): ident,
    ("preauth_gate", "source"): gate_budget,
    ("rldp2_budget", "data_size"): decimal,
    ("rldp2_budget", "symbol_size"): decimal,
    ("rldp2_budget", "symbols_count"): decimal,
}

EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "public_key": frozenset(
        {"outcome", "key_type", "short_id", "serialized", "serialized_size", "adnl_id_text"}
    ),
    "private_key": frozenset({"outcome", "key_type", "public_key", "short_id"}),
    "signature": frozenset({"outcome", "signature"}),
    "verified": frozenset({"outcome"}),
    "ciphertext": frozenset({"outcome", "ciphertext"}),
    "plaintext": frozenset({"outcome", "plaintext"}),
    "secret": frozenset({"outcome", "secret"}),
    "adnl_id": frozenset({"outcome", "id", "text"}),
    "address_list": frozenset({"outcome", "address_list"}),
    "message": frozenset({"outcome", "message", "canonical"}),
    "packet": frozenset({"outcome", "packet"}),
    "received": frozenset({"outcome", "from_short", "packet"}),
    "channel": frozenset({"outcome", "in_id", "out_id", "received", "sent"}),
    "source": frozenset({"outcome", "source"}),
    "gate": frozenset({"outcome", "results", "sources", "held"}),
    "overlay_id": frozenset({"outcome", "short_id", "public_key"}),
    "overlay_node": frozenset(
        {
            "outcome",
            "adnl_short_id",
            "overlay",
            "flags",
            "version",
            "to_sign",
            "signature_check",
            "receives_regular",
            "receives_plumtree",
            "certificate",
            "canonical",
        }
    ),
    "certificate": frozenset({"outcome", "empty", "issuer", "to_sign", "check", "canonical"}),
    "member_certificate": frozenset({"outcome", "certificate", "expired"}),
    "member_flags": frozenset(
        {"outcome", "valid", "receives_regular", "receives_plumtree", "public_flags"}
    ),
    "privacy_rules": frozenset({"outcome", "check", "max_broadcast_size"}),
    "fec_type": frozenset({"outcome", "parameters", "decoder", "canonical"}),
    "encoded": frozenset({"outcome", "parameters", "symbols"}),
    "decode": frozenset(
        {
            "outcome",
            "added",
            "may_try_decode",
            "reason",
            "data_sha256",
            "data",
            "regenerated",
        }
    ),
    "fec_helper": frozenset({"outcome", "fec_symbols_count", "left_fec_symbols_count"}),
    "budget": frozenset(
        {
            "outcome",
            "reservation_bytes",
            "solver_bytes",
            "part_size",
            "symbol_size",
            "default_mtu",
        }
    ),
    "transfers": frozenset({"outcome", "events", "inbound_transfers", "completed_transfers"}),
    "sent": frozenset({"outcome", "packets", "outbound_transfers"}),
    "refused": frozenset({"outcome", "reason"}),
}

# Keys whose value anywhere in an effect is hex bytes (or null), a 32-byte id, or a refusal class / verdict.
EFFECT_HEX = frozenset(
    {
        "serialized",
        "public_key",
        "signature",
        "ciphertext",
        "plaintext",
        "canonical",
        "from",
        "data",
        "to_sign",
        "sent",
        "issued_by",
    }
)
EFFECT_IDS = frozenset(
    {
        "short_id",
        "id",
        "from_short",
        "in_id",
        "out_id",
        "adnl_short_id",
        "overlay",
        "issuer",
        "key",
        "peer_key",
        "query_id",
        "hash",
        "transfer_id",
        "data_sha256",
        "symbol_sha256",
        "sha256",
    }
)
VERDICT_WORDS = frozenset(
    {"valid", "admitted", "released", "ok", "allowed", "need_check", "forbidden"}
)
VERDICT_KEYS = frozenset({"reason", "signature_check", "check", "decoder"})
VERDICT_LISTS = frozenset({"results", "added"})


def verdict(value: object, where: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or (value not in REASONS and value not in VERDICT_WORDS):
        raise t.FixtureError(f"{where}: unknown verdict {value!r}")


def scan(value: object, where: str, depth: int = 0) -> None:
    """Value checks by key name, through every nested object and list of an effect."""
    if depth > 8:
        raise t.FixtureError(f"{where}: nested too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            at = f"{where}.{key}"
            if key in EFFECT_HEX and item is not None:
                hex_bytes(item, at, 8 * MAX_BYTES)
            elif key in EFFECT_IDS and item is not None and key != "id":
                ident(item, at)
            elif key in VERDICT_KEYS:
                verdict(item, at)
            elif key in VERDICT_LISTS:
                for i, entry in enumerate(t.array(item, at)):
                    verdict(entry, f"{at}[{i}]")
            else:
                scan(item, at, depth + 1)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            scan(item, f"{where}[{i}]", depth + 1)


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    op = ctx.get("op")
    if not isinstance(op, str) or op not in OP_REQUIRED:
        raise t.FixtureError(f"{where}.op: invalid {op!r}")
    required = {"op"} | set(OP_REQUIRED[op])
    t.keys(ctx, required, required | set(OP_OPTIONAL.get(op, frozenset())), where)
    for key, value in ctx.items():
        if key == "op":
            continue
        check = OP_FIELD_KINDS.get((op, key), FIELD_CHECKS[key])
        check(value, f"{where}.{key}")
    if op == "adnl_id" and ("id" in ctx) == ("text" in ctx):
        raise t.FixtureError(f"{where}: exactly one of id and text")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    outcome = t.outcome_shape(eff, EFFECT_SHAPES, where)
    if outcome == "refused":
        if eff["reason"] not in REASONS:
            raise t.FixtureError(f"{where}.reason: unknown class {eff['reason']!r}")
        return
    if outcome == "adnl_id":
        ident(eff["id"], f"{where}.id")
    scan(dict(eff), where)
