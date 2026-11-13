#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Contexts of the net harness, and the cross-checks of its frozen fixtures.

    net_contexts.py contexts --reference <conformance-ref-cli> --rtos <rtos checkout> --out <dir>
    net_contexts.py create --reference <conformance-ref-cli> --contexts <dir> <vectors/net>
    net_contexts.py check <vectors/net>

`contexts` writes one `<family>.contexts.jsonl` per family, for `conformance.py create`. Wire objects are
built here as TL bytes (constructor ids read from the generated tl/generate/auto/tl/tos_api.h); every
value that needs node code -- a signature, a ciphertext, a channel id, a FEC symbol, the bytes a packet
signature covers -- comes from the reference itself through the net harness, so the contexts are valid
or invalid exactly where the authoring intends. Randomness is a fixed seed: running `contexts` twice
gives byte-identical files.

Expectations are partial effects in `metadata.note` as {"expect": {...}}: recorded values of migrated
known-answer data (the RFC 8032 Ed25519 sign vectors vendored under third-party/, the ADNL id of
test/test-adnl.cpp, the RTOS overlay node vectors) and the verdict each authored negative is written to
reach. `check` re-reads the frozen families and requires every expectation to hold, plus relations
between fixtures that no single effect shows: a ciphertext decrypts to what was encrypted, both ends of
a channel agree on its ids and the received packet is the one sent, FEC decoding returns the encoded
data, an RLDP2 datagram built here is byte-identical to the one the node's sender emits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, cast

Json = dict[str, Any]

ROOT = Path(__file__).resolve().parents[3]
TL_HEADER = ROOT / "tl" / "generate" / "auto" / "tl" / "tos_api.h"
RFC8032_VECTORS = (
    ROOT
    / "third-party/openssl/cloudflare-quiche/quiche/deps/boringssl/src/crypto/curve25519/ed25519_tests.txt"
)
RTOS_OVERLAY_VECTORS = Path("adnl/src/overlay/testdata/tos-overlay-node-vectors.txt")
REFERENCE_TIMEOUT_SECONDS = 600
NO_BLOBS = 1 << 24
RFC8032_COUNT = 64
IDENTITY_Y = b"\x01" + b"\0" * 31
LOW_ORDER_Y = b"\xec" + b"\xff" * 30 + b"\x7f"

# The known answer of test/test-adnl.cpp: an ADNL id in its text form and the 32 bytes it names.
TEST_ADNL_TEXT = "WQUA224U42HFSKN63K6NU23X42VK4IJRLFGG65CU62JAOL6U47HRCHD"
TEST_ADNL_ID = "a1406b5ca73472c94df6d5e6d35bbf355571098aca637ba2a7b490397ea73e78"

# The family a fixture file belongs to, and its source (metadata.source is per file).
FAMILY_SOURCES = {
    "keys": "authored",
    "ed25519-rfc8032": "migrated:rfc8032/ed25519-sign",
    "adnl-id": "authored",
    "adnl-id-test-adnl": "migrated:test/test-adnl",
    "adnl-address-list": "authored",
    "adnl-message": "authored",
    "adnl-packet": "authored",
    "adnl-packet-flags": "authored",
    "adnl-datagram": "authored",
    "adnl-channel": "authored",
    "preauth": "authored",
    "overlay-id": "authored",
    "overlay-node": "authored",
    "overlay-node-rtos": "migrated:rtos/overlay-node",
    "overlay-certificate": "authored",
    "overlay-member-certificate": "authored",
    "overlay-policy": "authored",
    "fec-type": "authored",
    "fec-raptorq": "authored",
    "fec-raptorq-sweep": "authored",
    "fec-online": "authored",
    "fec-round-robin": "authored",
    "rldp2": "authored",
    "overlay-broadcast": "authored",
    "overlay-broadcast-inbound": "authored",
}


class NetContextError(Exception):
    """Material, a derivation or a frozen family is not what this script requires."""


def fail(message: str) -> None:
    raise NetContextError(message)


# ---------------------------------------------------------------------------------------------------------
# TL encoding of the wire objects the contexts carry.


def load_tl_ids(path: Path) -> dict[str, int]:
    text = path.read_text()
    ids: dict[str, int] = {}
    for match in re.finditer(
        r"class (\w+) final : public \w+ \{.*?static const std::int32_t ID = (-?\d+);", text, re.S
    ):
        ids[match.group(1)] = int(match.group(2))
    if len(ids) < 100:
        fail(f"{path}: constructor ids not found")
    return ids


TL_IDS: dict[str, int] = {}


def ctor(name: str) -> bytes:
    if not TL_IDS:
        TL_IDS.update(load_tl_ids(TL_HEADER))
    if name not in TL_IDS:
        fail(f"no TL constructor {name}")
    return struct.pack("<i", TL_IDS[name])


def i32(value: int) -> bytes:
    return struct.pack("<i", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def i64(value: int) -> bytes:
    return struct.pack("<q", value)


def tl_bytes(data: bytes) -> bytes:
    if len(data) < 254:
        head = bytes([len(data)])
    elif len(data) < 1 << 24:
        head = b"\xfe" + struct.pack("<I", len(data))[:3]
    else:
        fail("TL string too long")
        head = b""
    out = head + data
    return out + b"\x00" * (-len(out) % 4)


def vector(items: Sequence[bytes]) -> bytes:
    return i32(len(items)) + b"".join(items)


def pub_ed25519(key: bytes) -> bytes:
    return ctor("pub_ed25519") + key


def pub_aes(key: bytes) -> bytes:
    return ctor("pub_aes") + key


def pub_unenc(data: bytes) -> bytes:
    return ctor("pub_unenc") + tl_bytes(data)


def pub_overlay(name: bytes) -> bytes:
    return ctor("pub_overlay") + tl_bytes(name)


def pk_ed25519(key: bytes) -> bytes:
    return ctor("pk_ed25519") + key


def pk_aes(key: bytes) -> bytes:
    return ctor("pk_aes") + key


def pk_unenc(data: bytes) -> bytes:
    return ctor("pk_unenc") + tl_bytes(data)


def pk_overlay(name: bytes) -> bytes:
    return ctor("pk_overlay") + tl_bytes(name)


def addr_udp(ip: int, port: int) -> bytes:
    return ctor("adnl_address_udp") + u32(ip) + i32(port)


def addr_udp6(ip: bytes, port: int) -> bytes:
    return ctor("adnl_address_udp6") + ip + i32(port)


def addr_tunnel(to: bytes, pubkey: bytes) -> bytes:
    return ctor("adnl_address_tunnel") + to + pubkey


def addr_reverse() -> bytes:
    return ctor("adnl_address_reverse")


def addr_quic(ip: int, port: int) -> bytes:
    return ctor("adnl_address_quic") + u32(ip) + i32(port)


def address_list_bare(
    addrs: Sequence[bytes],
    version: int,
    reinit_date: int = 0,
    priority: int = 0,
    expire_at: int = 0,
) -> bytes:
    return vector(addrs) + i32(version) + i32(reinit_date) + i32(priority) + i32(expire_at)


def address_list(addrs: Sequence[bytes], version: int, **kwargs: int) -> bytes:
    return ctor("adnl_addressList") + address_list_bare(addrs, version, **kwargs)


def msg_create_channel(key: bytes, date: int) -> bytes:
    return ctor("adnl_message_createChannel") + key + i32(date)


def msg_confirm_channel(key: bytes, peer_key: bytes, date: int) -> bytes:
    return ctor("adnl_message_confirmChannel") + key + peer_key + i32(date)


def msg_custom(data: bytes) -> bytes:
    return ctor("adnl_message_custom") + tl_bytes(data)


def msg_nop() -> bytes:
    return ctor("adnl_message_nop")


def msg_reinit(date: int) -> bytes:
    return ctor("adnl_message_reinit") + i32(date)


def msg_query(query_id: bytes, data: bytes) -> bytes:
    return ctor("adnl_message_query") + query_id + tl_bytes(data)


def msg_answer(query_id: bytes, data: bytes) -> bytes:
    return ctor("adnl_message_answer") + query_id + tl_bytes(data)


def msg_part(digest: bytes, total_size: int, offset: int, data: bytes) -> bytes:
    return ctor("adnl_message_part") + digest + i32(total_size) + i32(offset) + tl_bytes(data)


F_FROM = 0x1
F_FROM_SHORT = 0x2
F_ONE = 0x4
F_MULT = 0x8
F_ADDR = 0x10
F_PRIO_ADDR = 0x20
F_SEQNO = 0x40
F_CONFIRM = 0x80
F_RECV_VER = 0x100
F_RECV_PRIO_VER = 0x200
F_REINIT = 0x400
F_SIGNATURE = 0x800
F_PRIORITY = 0x1000


def packet_contents(
    flags: int,
    *,
    rand1: bytes = b"\x01" * 7,
    rand2: bytes = b"\x02" * 15,
    from_key: bytes = b"",
    from_short: bytes = b"",
    message: bytes = b"",
    messages: Sequence[bytes] = (),
    address: bytes = b"",
    priority_address: bytes = b"",
    seqno: int = 0,
    confirm_seqno: int = 0,
    recv_version: int = 0,
    recv_priority_version: int = 0,
    reinit_date: int = 0,
    dst_reinit_date: int = 0,
    signature: bytes = b"",
) -> bytes:
    """adnl.packetContents with the fields its flags select, in schema order."""
    out = ctor("adnl_packetContents") + tl_bytes(rand1) + u32(flags)
    if flags & F_FROM:
        out += from_key
    if flags & F_FROM_SHORT:
        out += from_short
    if flags & F_ONE:
        out += message
    if flags & F_MULT:
        out += vector(messages)
    if flags & F_ADDR:
        out += address
    if flags & F_PRIO_ADDR:
        out += priority_address
    if flags & F_SEQNO:
        out += i64(seqno)
    if flags & F_CONFIRM:
        out += i64(confirm_seqno)
    if flags & F_RECV_VER:
        out += i32(recv_version)
    if flags & F_RECV_PRIO_VER:
        out += i32(recv_priority_version)
    if flags & F_REINIT:
        out += i32(reinit_date) + i32(dst_reinit_date)
    if flags & F_SIGNATURE:
        out += tl_bytes(signature)
    return out + tl_bytes(rand2)


def fec_type(name: str, data_size: int, symbol_size: int, symbols_count: int) -> bytes:
    return ctor(name) + i32(data_size) + i32(symbol_size) + i32(symbols_count)


def rldp2_part(
    transfer_id: bytes, fec: bytes, part: int, total_size: int, seqno: int, data: bytes
) -> bytes:
    return (
        ctor("rldp2_messagePart")
        + transfer_id
        + fec
        + i32(part)
        + i64(total_size)
        + i32(seqno)
        + tl_bytes(data)
    )


def rldp2_complete(transfer_id: bytes, part: int) -> bytes:
    return ctor("rldp2_complete") + transfer_id + i32(part)


def rldp2_confirm(transfer_id: bytes, part: int, max_seqno: int, mask: int, count: int) -> bytes:
    return ctor("rldp2_confirm") + transfer_id + i32(part) + i32(max_seqno) + i32(mask) + i32(count)


# ---------------------------------------------------------------------------------------------------------
# Reference calls used to derive contexts (never to fill a fixture: create does that).


class Reference:
    def __init__(self, path: str) -> None:
        self.path = path

    def run(self, contexts: Sequence[Json]) -> list[Json]:
        if not contexts:
            return []
        stdin = "".join(json.dumps(ctx, sort_keys=True) + "\n" for ctx in contexts)
        result = subprocess.run(
            [self.path, "net"],
            input=stdin,
            capture_output=True,
            text=True,
            check=True,
            timeout=REFERENCE_TIMEOUT_SECONDS,
        )
        lines = result.stdout.splitlines()
        if len(lines) != len(contexts):
            fail(f"reference answered {len(lines)} of {len(contexts)} contexts")
        answers = [cast(Json, json.loads(line)) for line in lines]
        for ctx, answer in zip(contexts, answers, strict=True):
            if "harness_error" in answer:
                fail(
                    f"reference refused a derivation context ({ctx['op']}): {answer['harness_error']}"
                )
        return answers

    def one(self, ctx: Json) -> Json:
        return self.run([ctx])[0]

    def value(self, ctx: Json, outcome: str, key: str) -> Any:
        answer = self.one(ctx)
        if answer.get("outcome") != outcome:
            fail(f"derivation {ctx['op']} gave {answer}")
        return answer[key]

    def public_key(self, private_tl: bytes) -> bytes:
        return bytes.fromhex(
            self.value(
                {"op": "private_key", "private_key": private_tl.hex()}, "private_key", "public_key"
            )
        )

    def short_id(self, public_tl: bytes) -> bytes:
        return bytes.fromhex(
            self.value(
                {"op": "public_key", "public_key": public_tl.hex()}, "public_key", "short_id"
            )
        )

    def sign(self, private_tl: bytes, message: bytes) -> bytes:
        ctx = {"op": "sign", "private_key": private_tl.hex(), "message": message.hex()}
        return bytes.fromhex(self.value(ctx, "signature", "signature"))

    def aes_encrypt(self, secret: bytes, data: bytes) -> bytes:
        ctx = {"op": "encrypt", "public_key": pub_aes(secret).hex(), "data": data.hex()}
        return bytes.fromhex(self.value(ctx, "ciphertext", "ciphertext"))

    def shared_secret(self, private_tl: bytes, public_tl: bytes) -> bytes:
        ctx = {
            "op": "shared_secret",
            "private_key": private_tl.hex(),
            "public_key": public_tl.hex(),
        }
        return bytes.fromhex(self.value(ctx, "secret", "secret"))

    def ed25519_encrypt(self, receiver_public: bytes, ephemeral_seed: bytes, data: bytes) -> bytes:
        """EncryptorEd25519::encrypt with a chosen ephemeral key, from node functions only.

        The node's Ed25519 encryption is the ephemeral public key followed by the AES encryption of the data
        under the shared secret of the ephemeral key and the receiver's key (keys/encryptor.cpp derives the
        same key and IV from the secret and the digest in both); the shared secret and the AES encryption
        come from the reference.
        """
        ephemeral = pk_ed25519(ephemeral_seed)
        ephemeral_public = self.public_key(ephemeral)[4:]
        secret = self.shared_secret(ephemeral, receiver_public)
        return ephemeral_public + self.aes_encrypt(secret, data)

    def to_sign(self, contents: bytes) -> bytes:
        answer = self.one({"op": "adnl_packet", "contents": contents.hex()})
        if answer.get("outcome") != "packet":
            fail(f"unsigned packet refused: {answer}")
        return bytes.fromhex(answer["packet"]["to_sign"])


def seed_bytes(label: str, length: int = 32) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"net-fixture:{label}:{counter}".encode()).digest()
        counter += 1
    return out[:length]


def flip(data: bytes, index: int = 0, mask: int = 1) -> bytes:
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


class Family:
    def __init__(self, name: str) -> None:
        self.name = name
        self.entries: list[Json] = []
        self.ids: set[str] = set()

    def add(self, fixture_id: str, context: Json, expect: Json | None = None, **extra: Any) -> None:
        if fixture_id in self.ids:
            fail(f"{self.name}: duplicate fixture id {fixture_id}")
        self.ids.add(fixture_id)
        entry: Json = {"fixture_id": fixture_id, "context": context}
        note: Json = {}
        if expect is not None:
            note["expect"] = expect
        note.update(extra)
        if note:
            entry["note"] = json.dumps(note, sort_keys=True)
        self.entries.append(entry)


def refused(reason: str) -> Json:
    return {"outcome": "refused", "reason": reason}


# ---------------------------------------------------------------------------------------------------------
# keys


def add_keys(fam: Family, ref: Reference) -> None:
    alice = pk_ed25519(seed_bytes("alice"))
    bob = pk_ed25519(seed_bytes("bob"))
    alice_pub = ref.public_key(alice)
    bob_pub = ref.public_key(bob)
    aes_secret = seed_bytes("aes-secret")
    for name, key in (
        ("ed25519", alice_pub),
        ("aes", pub_aes(aes_secret)),
        ("unenc-empty", pub_unenc(b"")),
        ("unenc-253", pub_unenc(b"\x07" * 253)),
        ("unenc-254", pub_unenc(b"\x07" * 254)),
        ("overlay", pub_overlay(b"overlay-name")),
        ("overlay-empty", pub_overlay(b"")),
    ):
        fam.add(f"public-key/{name}", {"op": "public_key", "public_key": key.hex()})
    fam.add(
        "public-key/truncated",
        {"op": "public_key", "public_key": alice_pub[:-1].hex()},
        refused("tl_truncated"),
    )
    fam.add(
        "public-key/trailing",
        {"op": "public_key", "public_key": (alice_pub + b"\0").hex()},
        refused("tl_trailing_data"),
    )
    fam.add(
        "public-key/unknown-constructor",
        {"op": "public_key", "public_key": (ctor("adnl_message_nop") + b"\0" * 32).hex()},
        refused("tl_unknown_constructor"),
    )
    # A string length beyond the data: three-byte and seven-byte length forms.
    fam.add(
        "public-key/string-past-end",
        {"op": "public_key", "public_key": (ctor("pub_unenc") + b"\xfe\xff\xff\x00").hex()},
        refused("tl_truncated"),
    )
    fam.add(
        "public-key/string-length-64-bit",
        {"op": "public_key", "public_key": (ctor("pub_unenc") + b"\xff" * 8).hex()},
        refused("tl_truncated"),
    )
    fam.add("public-key/empty", {"op": "public_key", "public_key": ""}, refused("tl_truncated"))
    for name, key in (
        ("ed25519", alice),
        ("aes", pk_aes(aes_secret)),
        ("unenc", pk_unenc(b"plain")),
        ("overlay", pk_overlay(b"overlay-name")),
    ):
        fam.add(f"private-key/{name}", {"op": "private_key", "private_key": key.hex()})
    for size in (0, 1, 32, 1000, 65536):
        message = seed_bytes(f"message-{size}", size)
        fam.add(
            f"sign/ed25519-{size}",
            {"op": "sign", "private_key": alice.hex(), "message": message.hex()},
        )
        signature = ref.sign(alice, message)
        fam.add(
            f"verify/ed25519-{size}",
            {
                "op": "verify",
                "public_key": alice_pub.hex(),
                "message": message.hex(),
                "signature": signature.hex(),
            },
            {"outcome": "verified"},
        )
        if size:
            fam.add(
                f"verify/ed25519-{size}-message-flipped",
                {
                    "op": "verify",
                    "public_key": alice_pub.hex(),
                    "message": flip(message).hex(),
                    "signature": signature.hex(),
                },
                refused("invalid_signature"),
            )
    message = b"wire message"
    signature = ref.sign(alice, message)
    for name, sig, key in (
        ("signature-flipped-first", flip(signature, 0), alice_pub),
        ("signature-flipped-last", flip(signature, 63, 0x80), alice_pub),
        ("signature-63-bytes", signature[:63], alice_pub),
        ("signature-65-bytes", signature + b"\0", alice_pub),
        ("signature-empty", b"", alice_pub),
        ("other-key", signature, bob_pub),
        # s >= the group order: the upper bits of the last byte set.
        ("signature-s-high", signature[:32] + b"\xff" * 32, alice_pub),
    ):
        fam.add(
            f"verify/ed25519-{name}",
            {
                "op": "verify",
                "public_key": key.hex(),
                "message": message.hex(),
                "signature": sig.hex(),
            },
            refused("invalid_signature"),
        )
    # A public key that is not a curve point (y = 2 has no x on the curve).
    not_a_point = b"\x02" + b"\0" * 31
    fam.add(
        "verify/ed25519-not-a-point",
        {
            "op": "verify",
            "public_key": pub_ed25519(not_a_point).hex(),
            "message": message.hex(),
            "signature": signature.hex(),
        },
        refused("invalid_signature"),
    )
    fam.add(
        "verify/aes",
        {
            "op": "verify",
            "public_key": pub_aes(aes_secret).hex(),
            "message": message.hex(),
            "signature": signature.hex(),
        },
        refused("signing_unsupported"),
    )
    fam.add(
        "verify/unenc-accepts-anything",
        {
            "op": "verify",
            "public_key": pub_unenc(b"x").hex(),
            "message": message.hex(),
            "signature": signature.hex(),
        },
        {"outcome": "verified"},
    )
    dht_key = seed_bytes("dht-key") + tl_bytes(b"nodes") + i32(0)
    overlay_rule = ctor("dht_updateRule_overlayNodes")
    for name, desc, sig, expect in (
        (
            "key-description",
            ctor("dht_keyDescription")
            + dht_key
            + pub_overlay(b"ov")
            + overlay_rule
            + tl_bytes(b""),
            b"",
            {"outcome": "verified"},
        ),
        (
            "key-description-signed",
            ctor("dht_keyDescription")
            + dht_key
            + pub_overlay(b"ov")
            + overlay_rule
            + tl_bytes(b""),
            b"\x01",
            refused("overlay_signature_invalid"),
        ),
        (
            "key-description-inner-signature",
            ctor("dht_keyDescription")
            + dht_key
            + pub_overlay(b"ov")
            + overlay_rule
            + tl_bytes(b"\x01"),
            b"",
            refused("overlay_signature_invalid"),
        ),
        (
            "key-description-other-rule",
            ctor("dht_keyDescription")
            + dht_key
            + pub_overlay(b"ov")
            + ctor("dht_updateRule_anybody")
            + tl_bytes(b""),
            b"",
            refused("overlay_signature_invalid"),
        ),
        ("not-a-key-description", b"wire message", b"", refused("tl_unknown_constructor")),
    ):
        fam.add(
            f"verify/overlay-{name}",
            {
                "op": "verify",
                "public_key": pub_overlay(b"ov").hex(),
                "message": desc.hex(),
                "signature": sig.hex(),
            },
            expect,
        )
    fam.add(
        "verify/truncated-key",
        {
            "op": "verify",
            "public_key": alice_pub[:20].hex(),
            "message": message.hex(),
            "signature": signature.hex(),
        },
        refused("tl_truncated"),
    )
    fam.add(
        "sign/aes",
        {"op": "sign", "private_key": pk_aes(aes_secret).hex(), "message": "00"},
        refused("signing_unsupported"),
    )
    fam.add(
        "sign/unenc",
        {"op": "sign", "private_key": pk_unenc(b"").hex(), "message": "00"},
        {"signature": ""},
    )
    fam.add(
        "sign/overlay",
        {"op": "sign", "private_key": pk_overlay(b"o").hex(), "message": "00"},
        refused("key_unusable"),
    )
    for size in (0, 1, 31, 32, 33, 1000):
        data = seed_bytes(f"aes-data-{size}", size)
        fam.add(
            f"encrypt/aes-{size}",
            {"op": "encrypt", "public_key": pub_aes(aes_secret).hex(), "data": data.hex()},
        )
        ciphertext = ref.aes_encrypt(aes_secret, data)
        fam.add(
            f"decrypt/aes-{size}",
            {
                "op": "decrypt",
                "private_key": pk_aes(aes_secret).hex(),
                "ciphertext": ciphertext.hex(),
            },
            {"outcome": "plaintext", "plaintext": data.hex()},
            encrypted_by=f"encrypt/aes-{size}",
        )
        if size:
            fam.add(
                f"decrypt/aes-{size}-body-flipped",
                {
                    "op": "decrypt",
                    "private_key": pk_aes(aes_secret).hex(),
                    "ciphertext": flip(ciphertext, 32).hex(),
                },
                refused("digest_mismatch"),
            )
        fam.add(
            f"decrypt/aes-{size}-digest-flipped",
            {
                "op": "decrypt",
                "private_key": pk_aes(aes_secret).hex(),
                "ciphertext": flip(ciphertext, 5).hex(),
            },
            refused("digest_mismatch"),
        )
    fam.add(
        "decrypt/aes-31-bytes",
        {"op": "decrypt", "private_key": pk_aes(aes_secret).hex(), "ciphertext": "00" * 31},
        refused("ciphertext_short"),
    )
    fam.add(
        "encrypt/unenc",
        {"op": "encrypt", "public_key": pub_unenc(b"").hex(), "data": "0102"},
        {"ciphertext": "0102"},
    )
    fam.add(
        "encrypt/overlay",
        {"op": "encrypt", "public_key": pub_overlay(b"o").hex(), "data": "01"},
        refused("encryption_unsupported"),
    )
    fam.add(
        "decrypt/unenc",
        {"op": "decrypt", "private_key": pk_unenc(b"").hex(), "ciphertext": "0102"},
        {"plaintext": "0102"},
    )
    fam.add(
        "decrypt/overlay",
        {"op": "decrypt", "private_key": pk_overlay(b"o").hex(), "ciphertext": "01"},
        refused("key_unusable"),
    )
    for size in (0, 1, 100, 1500):
        data = seed_bytes(f"ed-data-{size}", size)
        ciphertext = ref.ed25519_encrypt(bob_pub, seed_bytes(f"ephemeral-{size}"), data)
        fam.add(
            f"decrypt/ed25519-{size}",
            {"op": "decrypt", "private_key": bob.hex(), "ciphertext": ciphertext.hex()},
            {"outcome": "plaintext", "plaintext": data.hex()},
        )
        # The digest is of the plaintext only, so an empty plaintext decrypts under any key.
        fam.add(
            f"decrypt/ed25519-{size}-other-key",
            {"op": "decrypt", "private_key": alice.hex(), "ciphertext": ciphertext.hex()},
            refused("digest_mismatch") if size else {"outcome": "plaintext", "plaintext": ""},
        )
        fam.add(
            f"decrypt/ed25519-{size}-ephemeral-flipped",
            {"op": "decrypt", "private_key": bob.hex(), "ciphertext": flip(ciphertext, 3).hex()},
        )
    fam.add(
        "decrypt/ed25519-63-bytes",
        {"op": "decrypt", "private_key": bob.hex(), "ciphertext": "00" * 63},
        refused("ciphertext_short"),
    )
    fam.add(
        "decrypt/ed25519-64-bytes-not-a-point",
        {"op": "decrypt", "private_key": bob.hex(), "ciphertext": (not_a_point + b"\0" * 32).hex()},
    )
    fam.add(
        "shared-secret/alice-bob",
        {"op": "shared_secret", "private_key": alice.hex(), "public_key": bob_pub.hex()},
    )
    fam.add(
        "shared-secret/bob-alice",
        {"op": "shared_secret", "private_key": bob.hex(), "public_key": alice_pub.hex()},
    )
    fam.add(
        "shared-secret/self",
        {"op": "shared_secret", "private_key": alice.hex(), "public_key": alice_pub.hex()},
    )
    fam.add(
        "shared-secret/not-a-point",
        {
            "op": "shared_secret",
            "private_key": alice.hex(),
            "public_key": pub_ed25519(not_a_point).hex(),
        },
    )
    # y = 1 (the neutral element) has no Montgomery form; y = p - 1 maps to u = 0, a low-order point.
    for name, y in (("identity", IDENTITY_Y), ("low-order", LOW_ORDER_Y)):
        fam.add(
            f"shared-secret/{name}",
            {"op": "shared_secret", "private_key": alice.hex(), "public_key": pub_ed25519(y).hex()},
            refused("degenerate_public_key"),
        )
        fam.add(
            f"decrypt/ed25519-ephemeral-{name}",
            {"op": "decrypt", "private_key": bob.hex(), "ciphertext": (y + b"\0" * 40).hex()},
            refused("degenerate_public_key"),
        )


def add_rfc8032(fam: Family) -> None:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in RFC8032_VECTORS.read_text().splitlines():
        if not line or line.startswith("#"):
            if current:
                records.append(current)
                current = {}
            continue
        key, _, value = line.partition(":")
        current[key.strip()] = value.strip()
    if current:
        records.append(current)
    records = [r for r in records if {"PRIV", "PUB", "MESSAGE", "SIG"} <= r.keys()]
    if len(records) < RFC8032_COUNT:
        fail(f"{RFC8032_VECTORS}: only {len(records)} vectors")
    for i, record in enumerate(records[:RFC8032_COUNT]):
        seed = bytes.fromhex(record["PRIV"])[:32]
        public = bytes.fromhex(record["PUB"])
        message = bytes.fromhex(record["MESSAGE"])
        signature = bytes.fromhex(record["SIG"])
        if len(seed) != 32 or len(public) != 32 or len(signature) != 64:
            fail(f"vector {i}: unexpected sizes")
        fam.add(
            f"{i:03d}/private-key",
            {"op": "private_key", "private_key": pk_ed25519(seed).hex()},
            {"public_key": pub_ed25519(public).hex()},
        )
        fam.add(
            f"{i:03d}/sign",
            {"op": "sign", "private_key": pk_ed25519(seed).hex(), "message": message.hex()},
            {"signature": signature.hex()},
        )
        fam.add(
            f"{i:03d}/verify",
            {
                "op": "verify",
                "public_key": pub_ed25519(public).hex(),
                "message": message.hex(),
                "signature": signature.hex(),
            },
            {"outcome": "verified"},
        )


# ---------------------------------------------------------------------------------------------------------
# ADNL


def add_adnl_id(fam: Family, migrated: Family) -> None:
    migrated.add(
        "parse",
        {"op": "adnl_id", "text": TEST_ADNL_TEXT},
        {"id": TEST_ADNL_ID, "text": TEST_ADNL_TEXT.lower()},
    )
    migrated.add(
        "serialize", {"op": "adnl_id", "id": TEST_ADNL_ID}, {"text": TEST_ADNL_TEXT.lower()}
    )
    for name, ident in (
        ("zero", "00" * 32),
        ("ones", "ff" * 32),
        ("seed", seed_bytes("adnl-id").hex()),
    ):
        fam.add(f"serialize/{name}", {"op": "adnl_id", "id": ident})
    fam.add(
        "parse/lower-case", {"op": "adnl_id", "text": TEST_ADNL_TEXT.lower()}, {"id": TEST_ADNL_ID}
    )
    fam.add(
        "parse/short", {"op": "adnl_id", "text": TEST_ADNL_TEXT[:-1]}, refused("adnl_id_length")
    )
    fam.add(
        "parse/long", {"op": "adnl_id", "text": TEST_ADNL_TEXT + "A"}, refused("adnl_id_length")
    )
    fam.add("parse/empty", {"op": "adnl_id", "text": ""}, refused("adnl_id_length"))
    # The checksum covers the id, so changing one character of the id part breaks it.
    changed = (
        TEST_ADNL_TEXT[:10] + ("A" if TEST_ADNL_TEXT[10] != "A" else "B") + TEST_ADNL_TEXT[11:]
    )
    fam.add("parse/checksum", {"op": "adnl_id", "text": changed}, refused("adnl_id_checksum"))
    fam.add("parse/prefix", {"op": "adnl_id", "text": "A" + TEST_ADNL_TEXT[1:]})
    fam.add(
        "parse/not-base32",
        {"op": "adnl_id", "text": "1" * len(TEST_ADNL_TEXT)},
        refused("adnl_id_encoding"),
    )


def add_address_lists(fam: Family, ref: Reference) -> None:
    loopback = 0x7F000001
    v6 = bytes.fromhex("20010db8000000000000000000000001")
    tunnel_to = seed_bytes("tunnel-to")
    alice_pub = ref.public_key(pk_ed25519(seed_bytes("alice")))
    cases: list[tuple[str, bytes, Json | None]] = [
        (
            "udp",
            address_list(
                [addr_udp(loopback, 30303)], 1, reinit_date=1700000000, expire_at=1800000000
            ),
            None,
        ),
        ("udp6", address_list([addr_udp6(v6, 443)], 2), None),
        ("tunnel", address_list([addr_tunnel(tunnel_to, alice_pub)], 3), None),
        ("reverse", address_list([addr_reverse()], 4), None),
        ("quic", address_list([addr_quic(0x0A000001, 4433)], 5), None),
        ("quic-port-out-of-range", address_list([addr_quic(0x0A000001, 70000)], 5), None),
        (
            "mixed-order",
            address_list(
                [addr_quic(0x0A000001, 1), addr_reverse(), addr_udp(loopback, 2), addr_udp6(v6, 3)],
                6,
                priority=7,
            ),
            None,
        ),
        ("no-addresses", address_list([], 0), None),
        (
            "version-minus-one",
            address_list([addr_udp(loopback, 1)], -1),
            {"address_list": {"empty": True}},
        ),
        (
            "negative-fields",
            address_list([addr_udp(0xFFFFFFFF, -1)], 9, reinit_date=-5, priority=-1, expire_at=-2),
            None,
        ),
        ("eight-udp", address_list([addr_udp(loopback + i, 1000 + i) for i in range(8)], 1), None),
        (
            "nine-udp",
            address_list([addr_udp(loopback + i, 1000 + i) for i in range(9)], 1),
            refused("address_list_oversize"),
        ),
    ]
    # A tunnel address with an unencrypted key of L bytes adds 44 + L bytes to the 24 of the list: the node's
    # limit of 128 is reached at L = 60.
    for length, expect in ((59, None), (60, None), (61, refused("address_list_oversize"))):
        cases.append(
            (
                f"tunnel-unenc-{length}",
                address_list([addr_tunnel(tunnel_to, pub_unenc(b"\x01" * length))], 1),
                expect,
            )
        )
    for name, data, expect in cases:
        fam.add(name, {"op": "adnl_address_list", "address_list": data.hex()}, expect)
    good = address_list([addr_udp(loopback, 1)], 1)
    fam.add(
        "truncated",
        {"op": "adnl_address_list", "address_list": good[:-2].hex()},
        refused("tl_truncated"),
    )
    fam.add(
        "trailing",
        {"op": "adnl_address_list", "address_list": (good + b"\0\0\0\0").hex()},
        refused("tl_trailing_data"),
    )
    fam.add(
        "unknown-address",
        {"op": "adnl_address_list", "address_list": address_list([msg_nop()], 1).hex()},
        refused("tl_unknown_constructor"),
    )
    fam.add(
        "negative-count",
        {
            "op": "adnl_address_list",
            "address_list": (ctor("adnl_addressList") + i32(-1) + b"\0" * 16).hex(),
        },
        refused("tl_bad_length"),
    )


def add_messages(fam: Family) -> None:
    key = seed_bytes("channel-key")
    peer = seed_bytes("channel-peer")
    query_id = seed_bytes("query-id")
    cases = [
        ("create-channel", msg_create_channel(key, 1700000000)),
        ("confirm-channel", msg_confirm_channel(key, peer, -1)),
        ("custom-empty", msg_custom(b"")),
        ("custom-253", msg_custom(b"\x05" * 253)),
        ("custom-254", msg_custom(b"\x05" * 254)),
        ("custom-1024", msg_custom(seed_bytes("custom", 1024))),
        ("nop", msg_nop()),
        ("reinit", msg_reinit(1700000001)),
        ("query", msg_query(query_id, b"query body")),
        ("answer", msg_answer(query_id, b"")),
        ("part", msg_part(seed_bytes("part-hash"), 4096, 1024, b"\x09" * 100)),
        ("part-negative-sizes", msg_part(seed_bytes("part-hash"), -1, -1024, b"")),
    ]
    for name, data in cases:
        fam.add(name, {"op": "adnl_message", "message": data.hex()})
    fam.add(
        "truncated",
        {"op": "adnl_message", "message": msg_reinit(1)[:-1].hex()},
        refused("tl_truncated"),
    )
    fam.add(
        "unknown",
        {"op": "adnl_message", "message": pub_aes(key).hex()},
        refused("tl_unknown_constructor"),
    )
    fam.add("empty", {"op": "adnl_message", "message": ""}, refused("tl_truncated"))
    fam.add(
        "trailing",
        {"op": "adnl_message", "message": (msg_nop() + b"\0" * 4).hex()},
        refused("tl_trailing_data"),
    )


class Peer:
    """A node identity: its private key and full and short ADNL ids."""

    def __init__(self, ref: Reference, label: str) -> None:
        self.private = pk_ed25519(seed_bytes(label))
        self.public = ref.public_key(self.private)
        self.short = ref.short_id(self.public)


def signed_packet(ref: Reference, sender: Peer, flags: int, **fields: Any) -> bytes:
    """A packet with a full source and its signature over the bytes the node signs."""
    unsigned = packet_contents((flags | F_FROM) & ~F_SIGNATURE, from_key=sender.public, **fields)
    signature = ref.sign(sender.private, ref.to_sign(unsigned))
    return packet_contents(
        flags | F_FROM | F_SIGNATURE, from_key=sender.public, signature=signature, **fields
    )


def add_packets(fam: Family, ref: Reference) -> None:
    alice = Peer(ref, "alice")
    bob = Peer(ref, "bob")
    addr = address_list([addr_udp(0x7F000001, 30303)], 1700000000, reinit_date=1700000000)
    prio = address_list([addr_udp(0x0A000002, 30304)], 1700000005)
    one = msg_custom(b"hello")
    cases: list[tuple[str, bytes, Json | None]] = [
        ("minimal", packet_contents(0), {"packet": {"signature_check": None}}),
        (
            "from-short-only",
            packet_contents(F_FROM_SHORT | F_ONE, from_short=alice.short, message=one),
            None,
        ),
        (
            "signed-one-message",
            signed_packet(ref, alice, F_ONE, message=one),
            {"packet": {"signature_check": "valid"}},
        ),
        (
            "signed-many-messages",
            signed_packet(
                ref, alice, F_MULT, messages=[msg_nop(), msg_reinit(5), msg_custom(b"x" * 300)]
            ),
            {"packet": {"signature_check": "valid"}},
        ),
        (
            "signed-everything",
            signed_packet(
                ref,
                alice,
                F_FROM_SHORT
                | F_ONE
                | F_ADDR
                | F_PRIO_ADDR
                | F_SEQNO
                | F_CONFIRM
                | F_RECV_VER
                | F_RECV_PRIO_VER
                | F_REINIT,
                from_short=alice.short,
                message=one,
                address=addr[4:],
                priority_address=prio[4:],
                seqno=(1 << 63) - 1,
                confirm_seqno=1,
                recv_version=7,
                recv_priority_version=-7,
                reinit_date=1700000000,
                dst_reinit_date=1690000000,
            ),
            {"packet": {"signature_check": "valid"}},
        ),
        (
            "signed-priority-flag",
            signed_packet(ref, alice, F_ONE | F_PRIORITY, message=one),
            {"packet": {"priority": True}},
        ),
        (
            "signed-zero-messages",
            signed_packet(ref, alice, F_MULT, messages=[]),
            {"packet": {"signature_check": "valid"}},
        ),
        ("rand-empty", packet_contents(F_ONE, rand1=b"", rand2=b"", message=msg_nop()), None),
        (
            "rand-long",
            packet_contents(F_ONE, rand1=b"\x01" * 300, rand2=b"\x02" * 254, message=msg_nop()),
            None,
        ),
        ("seqno-negative", packet_contents(F_SEQNO | F_CONFIRM, seqno=-1, confirm_seqno=-2), None),
    ]
    signed = signed_packet(ref, alice, F_ONE, message=one)
    unsigned = packet_contents(F_FROM | F_ONE, from_key=alice.public, message=one)
    cases += [
        ("unsigned-full-source", unsigned, {"packet": {"signature_check": "invalid_signature"}}),
        (
            "signed-by-other-key",
            packet_contents(
                F_FROM | F_ONE | F_SIGNATURE,
                from_key=alice.public,
                message=one,
                signature=ref.sign(bob.private, ref.to_sign(unsigned)),
            ),
            {"packet": {"signature_check": "invalid_signature"}},
        ),
        (
            "signature-over-other-message",
            packet_contents(
                F_FROM | F_ONE | F_SIGNATURE,
                from_key=alice.public,
                message=msg_custom(b"other"),
                signature=ref.sign(alice.private, ref.to_sign(unsigned)),
            ),
            {"packet": {"signature_check": "invalid_signature"}},
        ),
        ("bad-flags", packet_contents(0x2000), refused("packet_bad_flags")),
        ("negative-flags", packet_contents(0x80000000), refused("tl_negative_flags")),
        (
            "one-and-many",
            packet_contents(F_ONE | F_MULT, message=msg_nop(), messages=[msg_nop()]),
            refused("packet_message_flags"),
        ),
        (
            "source-mismatch",
            packet_contents(F_FROM | F_FROM_SHORT, from_key=alice.public, from_short=bob.short),
            refused("packet_source_mismatch"),
        ),
        (
            "source-not-ed25519",
            packet_contents(F_FROM, from_key=pub_aes(alice.short)),
            refused("not_ed25519"),
        ),
        (
            "address-list-empty",
            packet_contents(F_ADDR, address=address_list_bare([addr_udp(1, 1)], -1)),
            refused("packet_address_list_empty"),
        ),
        (
            "priority-address-list-empty",
            packet_contents(F_PRIO_ADDR, priority_address=address_list_bare([], -1)),
            refused("packet_address_list_empty"),
        ),
        (
            "address-list-oversize",
            packet_contents(
                F_ADDR, address=address_list_bare([addr_udp(i, i) for i in range(9)], 1)
            ),
            refused("address_list_oversize"),
        ),
        ("truncated", signed[:-3], refused("tl_truncated")),
        ("trailing", signed + b"\0" * 4, refused("tl_trailing_data")),
        ("not-a-packet", msg_nop(), refused("tl_unknown_constructor")),
    ]
    for name, data, expect in cases:
        fam.add(name, {"op": "adnl_packet", "contents": data.hex()}, expect)


def add_packet_flags(fam: Family, ref: Reference) -> None:
    """Packet flag combinations: every combination of the six source, message and address-list flags,
    each with six seeded combinations of the seven others, every selected field filled with a seeded
    value. A combination with a full source is signed over the bytes the node signs."""
    rng = random.Random(1300)
    alice = Peer(ref, "alice")
    for low in range(0x40):
        for high in sorted(rng.sample(range(0x80), 6)):
            flags = low | (high << 6)
            fields: dict[str, Any] = {
                "rand1": bytes(rng.randrange(256) for _ in range(rng.choice((7, 15)))),
                "rand2": bytes(rng.randrange(256) for _ in range(rng.choice((7, 15)))),
                "from_short": alice.short,
                "message": msg_reinit(rng.randrange(1 << 31)),
                "messages": [msg_nop(), msg_custom(bytes([rng.randrange(256)]))],
                "address": address_list_bare(
                    [addr_udp(rng.randrange(1 << 32), rng.randrange(65536))],
                    rng.randrange(1, 1 << 31),
                ),
                "priority_address": address_list_bare(
                    [addr_udp6(bytes(16), 1)], rng.randrange(1, 1 << 31)
                ),
                "seqno": rng.randrange(1 << 63),
                "confirm_seqno": rng.randrange(1 << 63),
                "recv_version": rng.randrange(-(1 << 31), 1 << 31),
                "recv_priority_version": rng.randrange(-(1 << 31), 1 << 31),
                "reinit_date": rng.randrange(1 << 31),
                "dst_reinit_date": rng.randrange(1 << 31),
            }
            if flags & F_FROM and not (flags & F_ONE and flags & F_MULT):
                data = signed_packet(ref, alice, flags & ~F_SIGNATURE, **fields)
            else:
                data = packet_contents(
                    flags, from_key=alice.public, signature=b"\x00" * 64, **fields
                )
            fam.add(f"flags-{flags:04x}", {"op": "adnl_packet", "contents": data.hex()})


def datagram(ref: Reference, receiver: Peer, contents: bytes, label: str) -> bytes:
    return receiver.short + ref.ed25519_encrypt(
        receiver.public, seed_bytes(f"ephemeral-{label}"), contents
    )


def add_datagrams(fam: Family, ref: Reference) -> None:
    alice = Peer(ref, "alice")
    bob = Peer(ref, "bob")
    one = msg_custom(b"to bob")
    good = signed_packet(ref, alice, F_ONE | F_SEQNO, message=one, seqno=1)
    cases: list[tuple[str, bytes, Json | None]] = [
        (
            "signed",
            datagram(ref, bob, good, "signed"),
            {"outcome": "received", "from_short": alice.short.hex()},
        ),
        (
            "signed-with-address-list",
            datagram(
                ref,
                bob,
                signed_packet(
                    ref,
                    alice,
                    F_ADDR | F_MULT,
                    address=address_list_bare([addr_udp(1, 2)], 3),
                    messages=[one, one],
                ),
                "addr",
            ),
            {"outcome": "received"},
        ),
        (
            "other-destination",
            alice.short + datagram(ref, bob, good, "other")[32:],
            refused("unknown_destination"),
        ),
        ("31-bytes", bob.short[:31], refused("datagram_short")),
        ("only-destination", bob.short, refused("ciphertext_short")),
        ("ciphertext-63-bytes", bob.short + b"\0" * 63, refused("ciphertext_short")),
        (
            "body-flipped",
            flip(datagram(ref, bob, good, "flip"), 32 + 64 + 5),
            refused("digest_mismatch"),
        ),
        (
            "not-a-packet",
            datagram(ref, bob, msg_nop(), "nopacket"),
            refused("tl_unknown_constructor"),
        ),
        (
            "bad-flags",
            datagram(ref, bob, packet_contents(0x4000), "badflags"),
            refused("packet_bad_flags"),
        ),
        (
            "no-source",
            datagram(ref, bob, packet_contents(F_ONE, message=one), "nosrc"),
            refused("source_missing"),
        ),
        (
            "short-source-only",
            datagram(
                ref,
                bob,
                packet_contents(F_FROM_SHORT | F_ONE, from_short=alice.short, message=one),
                "short",
            ),
            refused("source_unknown"),
        ),
        (
            "unsigned",
            datagram(
                ref,
                bob,
                packet_contents(F_FROM | F_ONE, from_key=alice.public, message=one),
                "unsigned",
            ),
            refused("invalid_signature"),
        ),
        (
            "signature-of-other-packet",
            datagram(
                ref,
                bob,
                packet_contents(
                    F_FROM | F_ONE | F_SIGNATURE,
                    from_key=alice.public,
                    message=msg_custom(b"to carol"),
                    signature=ref.sign(
                        alice.private,
                        ref.to_sign(
                            packet_contents(F_FROM | F_ONE, from_key=alice.public, message=one)
                        ),
                    ),
                ),
                "wrongsig",
            ),
            refused("invalid_signature"),
        ),
    ]
    for name, data, expect in cases:
        fam.add(
            name,
            {"op": "adnl_datagram", "private_key": bob.private.hex(), "datagram": data.hex()},
            expect,
        )


def channel_context(
    local: Peer, peer: Peer, local_key: bytes, peer_key_public: bytes, **extra: str
) -> Json:
    ctx: Json = {
        "op": "adnl_channel",
        "local_channel_key": local_key.hex(),
        "peer_channel_key": peer_key_public.hex(),
        "local_id": local.short.hex(),
        "peer_id": peer.short.hex(),
    }
    ctx.update(extra)
    return ctx


def add_channels(fam: Family, ref: Reference) -> None:
    alice = Peer(ref, "alice")
    bob = Peer(ref, "bob")
    alice_ck = seed_bytes("alice-channel")
    bob_ck = seed_bytes("bob-channel")
    alice_cpub = ref.public_key(pk_ed25519(alice_ck))[4:]
    bob_cpub = ref.public_key(pk_ed25519(bob_ck))[4:]
    packet = packet_contents(
        F_FROM_SHORT | F_ONE | F_SEQNO,
        from_short=alice.short,
        message=msg_custom(b"over channel"),
        seqno=2,
    )
    fam.add("alice-ids", channel_context(alice, bob, alice_ck, bob_cpub))
    fam.add("bob-ids", channel_context(bob, alice, bob_ck, alice_cpub))
    fam.add("same-id", channel_context(alice, alice, alice_ck, bob_cpub))
    # Alice sends one packet; the datagram her channel emits is what Bob's channel receives.
    sent = ref.value(
        channel_context(alice, bob, alice_ck, bob_cpub, send=packet.hex()), "channel", "sent"
    )
    fam.add("alice-sends", channel_context(alice, bob, alice_ck, bob_cpub, send=packet.hex()))
    wire = bytes.fromhex(sent)
    fam.add(
        "bob-receives",
        channel_context(bob, alice, bob_ck, alice_cpub, datagram=wire.hex()),
        sent_by="alice-sends",
    )
    fam.add(
        "bob-receives-and-answers",
        channel_context(
            bob,
            alice,
            bob_ck,
            alice_cpub,
            datagram=wire.hex(),
            send=packet_contents(
                F_FROM_SHORT | F_ONE, from_short=bob.short, message=msg_nop()
            ).hex(),
        ),
    )
    fam.add(
        "bob-unknown-channel",
        channel_context(bob, alice, bob_ck, alice_cpub, datagram=flip(wire, 0).hex()),
        {"received": {"reason": "unknown_destination"}},
    )
    fam.add(
        "bob-short",
        channel_context(bob, alice, bob_ck, alice_cpub, datagram=wire[:31].hex()),
        {"received": {"reason": "datagram_short"}},
    )
    fam.add(
        "bob-body-flipped",
        channel_context(bob, alice, bob_ck, alice_cpub, datagram=flip(wire, 70).hex()),
        {"received": {"reason": "digest_mismatch"}},
    )
    fam.add(
        "bob-ciphertext-short",
        channel_context(bob, alice, bob_ck, alice_cpub, datagram=wire[:60].hex()),
        {"received": {"reason": "ciphertext_short"}},
    )
    for name, contents, reason in (
        ("not-a-packet", msg_nop(), "tl_unknown_constructor"),
        ("bad-flags", packet_contents(0x2000), "packet_bad_flags"),
        (
            "wrong-source",
            packet_contents(F_FROM_SHORT, from_short=bob.short),
            "channel_source_mismatch",
        ),
    ):
        wire_bad = bytes.fromhex(
            ref.value(
                channel_context(alice, bob, alice_ck, bob_cpub, send=contents.hex()),
                "channel",
                "sent",
            )
        )
        fam.add(
            f"bob-{name}",
            channel_context(bob, alice, bob_ck, alice_cpub, datagram=wire_bad.hex()),
            {"received": {"reason": reason}},
        )
    fam.add(
        "bob-no-source",
        channel_context(
            bob,
            alice,
            bob_ck,
            alice_cpub,
            datagram=ref.value(
                channel_context(alice, bob, alice_ck, bob_cpub, send=packet_contents(0).hex()),
                "channel",
                "sent",
            ),
        ),
    )
    fam.add("peer-key-not-a-point", channel_context(alice, bob, alice_ck, b"\x02" + b"\0" * 31))
    fam.add(
        "peer-key-identity",
        channel_context(alice, bob, alice_ck, IDENTITY_Y),
        refused("degenerate_public_key"),
    )


def addr(ip: str, port: int = 1) -> Json:
    return {"ip": ip, "port": port}


def add_preauth(fam: Family) -> None:
    for name, ip, port in (
        ("ipv4", "192.0.2.10", 30303),
        ("ipv4-port-1", "192.0.2.10", 1),
        ("ipv4-port-65535", "192.0.2.10", 65535),
        ("ipv6", "2001:db8:1:2:3:4:5:6", 443),
        ("ipv6-loopback", "::1", 1),
        ("ipv4-mapped", "::ffff:192.0.2.1", 7),
    ):
        fam.add(f"source/{name}", {"op": "preauth_source", "address": addr(ip, port)})
    roomy = {"burst": 1000, "period": 3600.0, "in_flight_limit": 1000}

    def gate(
        name: str,
        events: list[Json],
        *,
        max_sources: int = 4,
        source: Json | None = None,
        process: Json | None = None,
        local: Json | None = None,
        expect: Json | None = None,
    ) -> None:
        fam.add(
            f"gate/{name}",
            {
                "op": "preauth_gate",
                "max_sources": max_sources,
                "source": source or roomy,
                "process": process or roomy,
                "local": local or roomy,
                "events": events,
            },
            expect,
        )

    a = addr("192.0.2.1", 1)
    gate("one", [{"admit": a}], expect={"results": ["admitted"]})
    gate(
        "rate-limit",
        [{"admit": a}, {"admit": addr("192.0.2.1", 2)}, {"admit": a}],
        source={"burst": 2, "period": 3600.0, "in_flight_limit": 0},
        expect={"results": ["admitted", "admitted", "rate_limited"]},
    )
    gate(
        "rate-limit-not-refunded",
        [{"admit": a}, {"release": 0}, {"admit": a}],
        source={"burst": 1, "period": 3600.0, "in_flight_limit": 0},
        expect={"results": ["admitted", "released", "rate_limited"]},
    )
    gate(
        "source-limit-all-in-flight",
        [{"admit": addr(f"192.0.2.{i}")} for i in range(1, 4)],
        max_sources=2,
        expect={"results": ["admitted", "admitted", "source_limit"]},
    )
    gate(
        "source-limit-replaces-idle",
        [
            {"admit": addr("192.0.2.1")},
            {"admit": addr("192.0.2.2")},
            {"release": 0},
            {"admit": addr("192.0.2.3")},
            {"admit": addr("192.0.2.1")},
        ],
        max_sources=2,
        expect={"results": ["admitted", "admitted", "released", "admitted", "source_limit"]},
    )
    gate(
        "least-recently-used",
        [
            {"admit": addr("192.0.2.1")},
            {"admit": addr("192.0.2.2")},
            {"release": 0},
            {"release": 1},
            {"admit": addr("192.0.2.1")},
            {"release": 4},
            {"admit": addr("192.0.2.3")},
            {"admit": addr("192.0.2.1")},
        ],
        max_sources=2,
    )
    gate(
        "ipv6-same-64",
        [
            {"admit": addr("2001:db8::1")},
            {"admit": addr("2001:db8::ffff:2")},
            {"admit": addr("2001:db8:0:1::1")},
        ],
        max_sources=1,
        expect={"results": ["admitted", "admitted", "source_limit"]},
    )
    gate(
        "process-budget",
        [
            {"admit": addr("192.0.2.1")},
            {"admit": addr("192.0.2.2")},
            {"release": 0},
            {"admit": addr("192.0.2.3")},
        ],
        process={"burst": 1000, "period": 3600.0, "in_flight_limit": 1},
        expect={"results": ["admitted", "process_budget", "released", "admitted"]},
    )
    gate(
        "process-rate",
        [{"admit": addr("192.0.2.1")}, {"admit": addr("192.0.2.2")}],
        process={"burst": 1, "period": 3600.0, "in_flight_limit": 10},
        expect={"results": ["admitted", "process_budget"]},
    )
    gate(
        "local-budget",
        [
            {"admit": addr("192.0.2.1")},
            {"admit": addr("192.0.2.2")},
            {"release": 0},
            {"admit": addr("192.0.2.2")},
        ],
        local={"burst": 1000, "period": 3600.0, "in_flight_limit": 1},
        expect={"results": ["admitted", "local_budget", "released", "admitted"]},
    )
    gate(
        "local-refusal-charges-source-rate",
        [{"admit": a}, {"admit": a}, {"release": 0}, {"admit": a}],
        source={"burst": 2, "period": 3600.0, "in_flight_limit": 0},
        local={"burst": 1000, "period": 3600.0, "in_flight_limit": 1},
        expect={"results": ["admitted", "local_budget", "released", "rate_limited"]},
    )
    gate("no-events", [], expect={"results": [], "sources": 0})


# ---------------------------------------------------------------------------------------------------------
# overlay


def overlay_node_tl(
    id_key: bytes, overlay: bytes, flags: int, version: int, signature: bytes, cert: bytes
) -> bytes:
    return (
        ctor("overlay_node")
        + id_key
        + overlay
        + i32(flags)
        + i32(version)
        + tl_bytes(signature)
        + cert
    )


def node_to_sign(short: bytes, overlay: bytes, flags: int, version: int) -> bytes:
    return ctor("overlay_node_toSign") + short + overlay + i32(flags) + i32(version)


def member_cert(
    issuer_pub: bytes, flags: int, slot: int, expire_at: int, signature: bytes
) -> bytes:
    return (
        ctor("overlay_memberCertificate")
        + issuer_pub
        + i32(flags)
        + i32(slot)
        + i32(expire_at)
        + tl_bytes(signature)
    )


def member_cert_id(node: bytes, flags: int, slot: int, expire_at: int) -> bytes:
    return ctor("overlay_memberCertificateId") + node + i32(flags) + i32(slot) + i32(expire_at)


EMPTY_MEMBER_CERT_NAME = "overlay_emptyMemberCertificate"
NEVER = 2147483647


def add_overlay_ids(fam: Family) -> None:
    for name, data in (
        ("empty", b""),
        ("short", b"x"),
        ("253", b"\x11" * 253),
        ("254", b"\x11" * 254),
        # The name of a shard's public overlay: tosNode.shardPublicOverlayId of the masterchain.
        (
            "shard-public-overlay",
            ctor("tosNode_shardPublicOverlayId")
            + i32(-1)
            + i64(-(1 << 63))
            + seed_bytes("zero-state"),
        ),
    ):
        fam.add(name, {"op": "overlay_id", "name": data.hex()})


def add_overlay_nodes(fam: Family, ref: Reference) -> None:
    alice = Peer(ref, "alice")
    root = Peer(ref, "root")
    overlay = seed_bytes("overlay")
    version = 1700000000

    def node(
        flags: int,
        *,
        cert: bytes | None = None,
        sign_flags: int | None = None,
        signer: Peer = alice,
    ) -> bytes:
        to_sign = node_to_sign(
            alice.short, overlay, flags if sign_flags is None else sign_flags, version
        )
        signature = ref.sign(signer.private, to_sign)
        return overlay_node_tl(
            alice.public, overlay, flags, version, signature, cert or ctor(EMPTY_MEMBER_CERT_NAME)
        )

    def cert(flags: int, slot: int, expire_at: int, *, flip_sig: bool = False) -> bytes:
        signature = ref.sign(root.private, member_cert_id(alice.short, flags, slot, expire_at))
        return member_cert(
            root.public, flags, slot, expire_at, flip(signature) if flip_sig else signature
        )

    for flags in (0, 1, 2, 3):
        fam.add(
            f"flags-{flags}",
            {"op": "overlay_node", "node": node(flags).hex()},
            {"signature_check": "valid"},
        )
    for flags in (4, 8, -1, -(1 << 31)):
        fam.add(
            f"flags-invalid-{flags & 0xFFFFFFFF:08x}",
            {"op": "overlay_node", "node": node(flags).hex()},
            refused("overlay_node_invalid"),
        )
    fam.add(
        "flags-not-signed",
        {"op": "overlay_node", "node": node(1, sign_flags=0).hex()},
        {"signature_check": "invalid_signature"},
    )
    fam.add(
        "other-signer",
        {"op": "overlay_node", "node": node(0, signer=root).hex()},
        {"signature_check": "invalid_signature"},
    )
    fam.add(
        "unsigned",
        {
            "op": "overlay_node",
            "node": overlay_node_tl(
                alice.public, overlay, 0, version, b"", ctor(EMPTY_MEMBER_CERT_NAME)
            ).hex(),
        },
        {"signature_check": "invalid_signature"},
    )
    fam.add(
        "id-not-ed25519",
        {
            "op": "overlay_node",
            "node": overlay_node_tl(
                pub_aes(alice.short), overlay, 0, version, b"", ctor(EMPTY_MEMBER_CERT_NAME)
            ).hex(),
        },
        refused("not_ed25519"),
    )
    fam.add(
        "member-certificate",
        {"op": "overlay_node", "node": node(0, cert=cert(0, 1, NEVER)).hex()},
        {"certificate": {"signature_check": "valid"}},
    )
    fam.add(
        "member-certificate-bad-signature",
        {"op": "overlay_node", "node": node(0, cert=cert(0, 1, NEVER, flip_sig=True)).hex()},
        {"certificate": {"signature_check": "invalid_signature"}},
    )
    fam.add(
        "truncated", {"op": "overlay_node", "node": node(0)[:-1].hex()}, refused("tl_truncated")
    )
    fam.add(
        "not-a-node",
        {"op": "overlay_node", "node": msg_nop().hex()},
        refused("tl_unknown_constructor"),
    )


def add_overlay_node_rtos(fam: Family, ref: Reference, rtos: Path) -> None:
    lines = dict(line.split("=", 1) for line in (rtos / RTOS_OVERLAY_VECTORS).read_text().split())
    fam.add(
        "node",
        {"op": "overlay_node", "node": lines["node"]},
        {"canonical": lines["node"], "flags": 2, "version": 1700000000},
        to_sign_vector=lines["to_sign"],
    )
    # The flag rule of the RTOS node tests: flags 0..3 are valid and signed, any other value is refused.
    key = pk_ed25519(bytes([71]) * 32)
    public = ref.public_key(key)
    short = ref.short_id(public)
    overlay = bytes([93]) * 32
    for flags in (0, 1, 2, 3, 4, -1):
        signature = ref.sign(key, node_to_sign(short, overlay, flags, 1700000000))
        tl = overlay_node_tl(
            public, overlay, flags, 1700000000, signature, ctor(EMPTY_MEMBER_CERT_NAME)
        )
        expect = (
            {"signature_check": "valid"} if 0 <= flags <= 3 else refused("overlay_node_invalid")
        )
        fam.add(f"flags-{flags & 0xFFFFFFFF:x}", {"op": "overlay_node", "node": tl.hex()}, expect)
        if 0 <= flags <= 3:
            flipped = overlay_node_tl(
                public, overlay, flags ^ 1, 1700000000, signature, ctor(EMPTY_MEMBER_CERT_NAME)
            )
            fam.add(
                f"flags-{flags:x}-flipped",
                {"op": "overlay_node", "node": flipped.hex()},
                {"signature_check": "invalid_signature"},
            )
            bad = overlay_node_tl(
                public, overlay, flags, 1700000000, flip(signature), ctor(EMPTY_MEMBER_CERT_NAME)
            )
            fam.add(
                f"flags-{flags:x}-signature-flipped",
                {"op": "overlay_node", "node": bad.hex()},
                {"signature_check": "invalid_signature"},
            )


def certificate_v1(issuer_pub: bytes, expire_at: int, max_size: int, signature: bytes) -> bytes:
    return (
        ctor("overlay_certificate")
        + issuer_pub
        + i32(expire_at)
        + i32(max_size)
        + tl_bytes(signature)
    )


def certificate_v2(
    issuer_pub: bytes, expire_at: int, max_size: int, flags: int, signature: bytes
) -> bytes:
    return (
        ctor("overlay_certificateV2")
        + issuer_pub
        + i32(expire_at)
        + i32(max_size)
        + i32(flags)
        + tl_bytes(signature)
    )


def cert_id_v1(overlay: bytes, node: bytes, expire_at: int, max_size: int) -> bytes:
    return ctor("overlay_certificateId") + overlay + node + i32(expire_at) + i32(max_size)


def cert_id_v2(overlay: bytes, node: bytes, expire_at: int, max_size: int, flags: int) -> bytes:
    return (
        ctor("overlay_certificateIdV2")
        + overlay
        + node
        + i32(expire_at)
        + i32(max_size)
        + i32(flags)
    )


def add_overlay_certificates(fam: Family, ref: Reference) -> None:
    root = Peer(ref, "root")
    node = Peer(ref, "alice").short
    overlay = seed_bytes("overlay")
    expire = 1800000000
    # Overlays::max_simple_broadcast_size() is 768: a V1 certificate above it allows FEC, at or below it does
    # not (cert_default_flags), and either way it is trusted.
    signed_v1 = {
        size: certificate_v1(
            root.public,
            expire,
            size,
            ref.sign(root.private, cert_id_v1(overlay, node, expire, size)),
        )
        for size in (768, 769, 1 << 20)
    }

    def ctx(
        cert: bytes,
        unix_time: int = 1700000000,
        size: int = 100,
        is_fec: bool = False,
        issued_to: bytes = node,
    ) -> Json:
        return {
            "op": "overlay_certificate",
            "certificate": cert.hex(),
            "overlay_id": overlay.hex(),
            "issued_to": issued_to.hex(),
            "unix_time": unix_time,
            "size": size,
            "is_fec": is_fec,
        }

    fam.add("v1-768", ctx(signed_v1[768]), {"check": "allowed"})
    fam.add("v1-768-fec", ctx(signed_v1[768], is_fec=True), {"check": "forbidden"})
    fam.add("v1-769-fec", ctx(signed_v1[769], is_fec=True, size=769), {"check": "allowed"})
    fam.add("v1-size-at-max", ctx(signed_v1[768], size=768), {"check": "allowed"})
    fam.add("v1-size-above-max", ctx(signed_v1[768], size=769), {"check": "forbidden"})
    fam.add("v1-at-expiry", ctx(signed_v1[768], unix_time=expire), {"check": "allowed"})
    fam.add("v1-after-expiry", ctx(signed_v1[768], unix_time=expire + 1), {"check": "forbidden"})
    fam.add("v1-other-node", ctx(signed_v1[768], issued_to=root.short), {"check": "forbidden"})
    fam.add("v1-1mib", ctx(signed_v1[1 << 20], size=1 << 20, is_fec=True), {"check": "allowed"})
    # Flags 3 are the V1 default of a certificate above 768 bytes (AllowFec | Trusted): such a V2 certificate
    # is checked against the V1 id, so a signature over the V2 id fails.
    for flags, expect in ((0, "need_check"), (1, "need_check"), (2, "allowed"), (3, "forbidden")):
        signature = ref.sign(root.private, cert_id_v2(overlay, node, expire, 100000, flags))
        cert = certificate_v2(root.public, expire, 100000, flags, signature)
        fam.add(f"v2-flags-{flags}", ctx(cert), {"check": expect})
        fam.add(f"v2-flags-{flags}-fec", ctx(cert, is_fec=True))
    v1_id_signature = ref.sign(root.private, cert_id_v1(overlay, node, expire, 100000))
    fam.add(
        "v2-flags-3-signed-as-v1",
        ctx(certificate_v2(root.public, expire, 100000, 3, v1_id_signature), is_fec=True),
        {"check": "allowed"},
    )
    # A V2 certificate whose flags equal the V1 default is signed (and re-serialized) as V1.
    default_flags = 2
    v1_signature = ref.sign(root.private, cert_id_v1(overlay, node, expire, 100))
    fam.add(
        "v2-default-flags-signed-as-v1",
        ctx(certificate_v2(root.public, expire, 100, default_flags, v1_signature)),
        {"check": "allowed"},
    )
    v2_signature = ref.sign(root.private, cert_id_v2(overlay, node, expire, 100, default_flags))
    fam.add(
        "v2-default-flags-signed-as-v2",
        ctx(certificate_v2(root.public, expire, 100, default_flags, v2_signature)),
        {"check": "forbidden"},
    )
    fam.add(
        "bad-signature",
        ctx(certificate_v1(root.public, expire, 768, flip(bytes(64))), size=1),
        {"check": "forbidden"},
    )
    fam.add("negative-max-size", ctx(certificate_v1(root.public, expire, -1, b""), size=1))
    fam.add(
        "issuer-unenc",
        ctx(certificate_v1(pub_unenc(b"anyone"), expire, 768, b"")),
        {"check": "allowed"},
    )
    fam.add(
        "issuer-overlay",
        ctx(certificate_v1(pub_overlay(b"o"), expire, 768, b"")),
        {"check": "forbidden"},
    )
    fam.add(
        "issuer-aes",
        ctx(certificate_v1(pub_aes(bytes(32)), expire, 768, b"")),
        {"check": "forbidden"},
    )
    fam.add("empty", ctx(ctor("overlay_emptyCertificate")), {"empty": True})
    fam.add("truncated", ctx(signed_v1[768][:-4]), refused("tl_truncated"))
    fam.add("not-a-certificate", ctx(msg_nop()), refused("tl_unknown_constructor"))


def add_member_certificates(fam: Family, ref: Reference) -> None:
    root = Peer(ref, "root")
    alice = Peer(ref, "alice")

    def ctx(cert: bytes, now: int = 1700000000, node: bytes = alice.short) -> Json:
        return {
            "op": "overlay_member_certificate",
            "certificate": cert.hex(),
            "node": node.hex(),
            "now": now,
        }

    for flags, slot in ((0, 0), (1, 4), (-1, -1), (0, 1 << 30)):
        signature = ref.sign(root.private, member_cert_id(alice.short, flags, slot, NEVER))
        cert = member_cert(root.public, flags, slot, NEVER, signature)
        fam.add(
            f"flags-{flags & 0xFFFFFFFF:x}-slot-{slot & 0xFFFFFFFF:x}",
            ctx(cert),
            {"certificate": {"signature_check": "valid"}, "expired": False},
        )
        fam.add(
            f"flags-{flags & 0xFFFFFFFF:x}-slot-{slot & 0xFFFFFFFF:x}-other-node",
            ctx(cert, node=root.short),
            {"certificate": {"signature_check": "invalid_signature"}},
        )
    old = 999999990
    signature = ref.sign(root.private, member_cert_id(alice.short, 0, 0, old))
    cert = member_cert(root.public, 0, 0, old, signature)
    for name, now, expired in (
        ("before-expiry", old, False),
        ("grace", old + 3, False),
        ("expired", old + 4, True),
    ):
        fam.add(
            f"expiry-{name}",
            ctx(cert, now=now),
            {"expired": expired, "certificate": {"signature_check": "valid"}},
        )
    fam.add(
        "empty",
        ctx(ctor(EMPTY_MEMBER_CERT_NAME)),
        {"certificate": {"empty": True, "signature_check": None}, "expired": False},
    )
    fam.add(
        "issuer-unenc",
        ctx(member_cert(pub_unenc(b""), 0, 0, NEVER, b"")),
        {"certificate": {"signature_check": "valid"}},
    )
    fam.add("truncated", ctx(cert[:-1]), refused("tl_truncated"))
    fam.add(
        "not-a-certificate",
        ctx(ctor("overlay_emptyCertificate")),
        refused("tl_unknown_constructor"),
    )


def add_overlay_policy(fam: Family) -> None:
    for flags in (0, 1, 2, 3, 4, 7, 0x80000000, 0xFFFFFFFF):
        for enabled in (False, True):
            for original in (False, True):
                fam.add(
                    f"member-flags/{flags:x}-{int(enabled)}{int(original)}",
                    {
                        "op": "overlay_member_flags",
                        "flags": flags,
                        "plumtree_enabled": enabled,
                        "original_sender": original,
                    },
                )
    key = seed_bytes("authorized")
    other = seed_bytes("stranger")
    for name, source, size, is_fec, any_sender, flags in (
        ("authorized-within", key, 1000, False, False, 0),
        ("authorized-at-limit", key, 2000, True, True, 0),
        ("authorized-above", key, 2001, False, False, 3),
        ("stranger-small", other, 100, False, False, 0),
        ("stranger-trusted", other, 100, False, False, 2),
        ("stranger-at-limit", other, 512, False, False, 0),
        ("stranger-above", other, 513, False, False, 3),
        ("stranger-fec", other, 100, True, False, 0),
        ("stranger-fec-allowed", other, 100, True, False, 1),
        ("stranger-any-sender", other, 1, False, True, 3),
    ):
        fam.add(
            f"privacy/{name}",
            {
                "op": "overlay_privacy_rules",
                "max_unauth_size": 512,
                "flags": flags,
                "authorized_keys": [{"key": key.hex(), "max_size": 2000}],
                "source": source.hex(),
                "size": size,
                "is_fec": is_fec,
                "is_any_sender": any_sender,
            },
        )
    fam.add(
        "privacy/no-keys",
        {
            "op": "overlay_privacy_rules",
            "max_unauth_size": 0,
            "flags": 0,
            "authorized_keys": [],
            "source": other.hex(),
            "size": 0,
            "is_fec": False,
            "is_any_sender": False,
        },
    )


# ---------------------------------------------------------------------------------------------------------
# FEC and RLDP2


def add_fec_types(fam: Family) -> None:
    def add(name: str, data: bytes, expect: Json | None = None) -> None:
        fam.add(name, {"op": "fec_type", "fec_type": data.hex()}, expect)

    rq = "fec_raptorQ"
    add("raptorq-one-symbol", fec_type(rq, 1, 768, 1))
    add("raptorq-768", fec_type(rq, 768, 768, 1))
    add("raptorq-769", fec_type(rq, 769, 768, 2))
    add("raptorq-2048", fec_type(rq, 2048 * 3, 2048, 3))
    add("raptorq-rldp-part", fec_type(rq, 2000000, 768, 2605))
    add("raptorq-k-56403", fec_type(rq, 768 * 56403, 768, 56403), {"decoder": "ok"})
    add(
        "raptorq-k-56404",
        fec_type(rq, 768 * 56404, 768, 56404),
        {"decoder": "fec_too_many_symbols"},
    )
    # data_size is a 32-bit int on the wire, below 768 * 2^24: the "too many symbols" bound of FecType::create
    # cannot be reached, and the largest announced transfer stops at the decoder's own limit instead.
    add(
        "raptorq-max-data",
        fec_type(rq, (1 << 31) - 1, 2048, 1 << 20),
        {"decoder": "fec_too_many_symbols"},
    )
    add("raptorq-empty", fec_type(rq, 0, 768, 0))
    add("raptorq-symbol-767", fec_type(rq, 767, 767, 1), refused("fec_symbol_size_small"))
    add("raptorq-symbol-0", fec_type(rq, 0, 0, 0), refused("fec_symbol_size_small"))
    add("raptorq-symbol-2049", fec_type(rq, 2049, 2049, 1), refused("fec_symbol_size_large"))
    add("raptorq-count-low", fec_type(rq, 769, 768, 1), refused("fec_symbols_count"))
    add("raptorq-count-high", fec_type(rq, 768, 768, 2), refused("fec_symbols_count"))
    add("raptorq-negative-size", fec_type(rq, -1, 768, 0), refused("fec_negative"))
    add("raptorq-negative-count", fec_type(rq, 768, 768, -1), refused("fec_negative"))
    add("online", fec_type("fec_online", 768, 768, 1), refused("fec_not_raptorq"))
    add("round-robin", fec_type("fec_roundRobin", 768, 768, 1), refused("fec_not_raptorq"))
    add("truncated", fec_type(rq, 768, 768, 1)[:-1], refused("tl_truncated"))
    add("not-a-type", msg_nop(), refused("tl_unknown_constructor"))


def add_fec_code(fam: Family, ref: Reference, algorithm: str, sweep: bool = False) -> None:
    """Encode, then decode from symbol subsets the encoder produced."""

    def encode(name: str, data: bytes, symbol_size: int, ids: list[int]) -> Json:
        ctx = {
            "op": "fec_encode",
            "algorithm": algorithm,
            "data": data.hex(),
            "symbol_size": symbol_size,
            "symbol_ids": ids,
        }
        fam.add(f"encode/{name}", ctx)
        return ref.one(ctx)

    def decode(
        name: str,
        data: bytes,
        symbol_size: int,
        symbols: list[Json],
        expect: Json | None,
        regenerate: list[int] | None = None,
        **extra: Any,
    ) -> None:
        ctx: Json = {
            "op": "fec_decode",
            "algorithm": algorithm,
            "data_size": len(data),
            "symbol_size": symbol_size,
            "symbols_count": (len(data) + symbol_size - 1) // symbol_size,
            "symbols": symbols,
        }
        if regenerate is not None:
            ctx["regenerate"] = regenerate
        fam.add(f"decode/{name}", ctx, expect, **extra)

    def ok(data: bytes) -> Json:
        return {"reason": None, "data_sha256": hashlib.sha256(data).hexdigest()}

    if sweep:
        rng = random.Random(4400)
        for i in range(60):
            symbol_size = rng.choice((1, 3, 16, 64, 200, 768, 1024))
            size = rng.randrange(1, min(40, 4000 // symbol_size + 2) * symbol_size + 1)
            data = bytes(rng.randrange(256) for _ in range(size))
            k = (size + symbol_size - 1) // symbol_size
            pool = list(range(k + 30)) + [rng.randrange(1 << 20, 1 << 24) for _ in range(5)]
            ids = sorted(rng.sample(pool, min(len(pool), k + rng.randrange(0, 3))))
            encoded = encode(f"sweep-{i:02d}", data, symbol_size, ids)
            decode(
                f"sweep-{i:02d}",
                data,
                symbol_size,
                encoded["symbols"],
                None,
                encoded_by=f"encode/sweep-{i:02d}",
                data_sha256=hashlib.sha256(data).hexdigest(),
            )
        return

    for symbol_size, size in (
        (768, 1),
        (768, 767),
        (768, 768),
        (768, 769),
        (768, 768 * 4 + 5),
        (16, 1000),
        (1, 9),
        (2048, 2048 * 2),
    ):
        data = seed_bytes(f"{algorithm}-{symbol_size}-{size}", size)
        k = (size + symbol_size - 1) // symbol_size
        ids = list(range(k))
        name = f"s{symbol_size}-n{size}"
        encoded = encode(f"{name}-source", data, symbol_size, ids)
        if algorithm == "raptorq":
            expect: Json | None = ok(data)
        elif algorithm == "round_robin":
            # The round-robin encoder cuts its last symbol short when the data is not a multiple of the
            # symbol size, and its decoder refuses a short symbol: such data never decodes.
            expect = ok(data) if size % symbol_size == 0 else {"reason": "need_more_symbols"}
        else:
            # The online code needs more than K symbols.
            expect = {"reason": "need_more_symbols"}
        decode(
            f"{name}-source",
            data,
            symbol_size,
            encoded["symbols"],
            expect,
            regenerate=[0, k, k + 7] if algorithm != "online" else None,
        )
        repair_ids = list(range(k, 2 * k + 12))
        repaired = encode(f"{name}-repair", data, symbol_size, repair_ids)
        decode(
            f"{name}-repair-only",
            data,
            symbol_size,
            repaired["symbols"],
            ok(data) if algorithm == "raptorq" else None,
        )
        if algorithm == "online":
            many = encode(f"{name}-many", data, symbol_size, list(range(3 * k + 40)))
            decode(f"{name}-many", data, symbol_size, many["symbols"], None)
        if k > 1:
            decode(
                f"{name}-one-short",
                data,
                symbol_size,
                encoded["symbols"][:-1],
                {"reason": "need_more_symbols"} if algorithm != "online" else None,
            )
    data = seed_bytes(f"{algorithm}-edge", 2000)
    first = encode("edge-ids", data, 768, [0, 1, 2, 1 << 21, (1 << 24) - 1])
    decode("edge-ids", data, 768, first["symbols"][:1] + first["symbols"][3:], None)
    decode(
        "wrong-symbol-length",
        data,
        768,
        [{"id": 0, "data": "00" * 767}],
        {"added": ["symbol_length"]},
    )
    decode("no-symbols", data, 768, [], None)
    decode("duplicate-symbols", data, 768, [first["symbols"][0]] * 3, None)
    if algorithm == "raptorq":
        decode(
            "symbol-id-2-pow-24",
            data,
            768,
            [{"id": 1 << 24, "data": "00" * 768}],
            {"added": ["symbol_id_range"]},
        )
        decode(
            "corrupted-symbol",
            data,
            768,
            [
                first["symbols"][0],
                {"id": 1, "data": flip(bytes.fromhex(first["symbols"][1]["data"])).hex()},
                first["symbols"][2],
            ],
            None,
        )


def add_rldp2(fam: Family, ref: Reference) -> None:
    for count, received in (
        (0, 0),
        (1, 0),
        (1, 5),
        (1, 6),
        (10, 14),
        (10, 15),
        (10, 16),
        (100, 1000),
        (1 << 30, 1 << 30),
    ):
        fam.add(
            f"fec-helper/{count}-{received}",
            {"op": "rldp2_fec_helper", "symbols_count": count, "received_symbols_count": received},
        )
    for name, data_size, symbol_size, count in (
        ("one-symbol", 1, 768, 1),
        ("part", 2000000, 768, 2605),
        ("zero", 0, 0, 0),
        ("count-overflow", 0, 768, (1 << 64) - 1),
        ("symbol-overflow", 0, (1 << 64) - 1, 1),
        ("data-overflow", (1 << 64) - 1, 768, 1),
    ):
        fam.add(
            f"budget/{name}",
            {
                "op": "rldp2_budget",
                "data_size": str(data_size),
                "symbol_size": str(symbol_size),
                "symbols_count": str(count),
            },
        )
    transfer = seed_bytes("transfer")
    for size in (1, 768, 769, 7680):
        data = seed_bytes(f"rldp2-{size}", size)
        fam.add(
            f"send/{size}", {"op": "rldp2_send", "transfer_id": transfer.hex(), "data": data.hex()}
        )
    # Receive: datagrams built here from the node's own RaptorQ symbols. `check` compares them with the
    # datagrams the node's sender emits for the same transfer.
    rq = "fec_raptorQ"

    def symbols(data: bytes, ids: list[int]) -> list[bytes]:
        answer = ref.one(
            {
                "op": "fec_encode",
                "algorithm": "raptorq",
                "data": data.hex(),
                "symbol_size": 768,
                "symbol_ids": ids,
            }
        )
        return [bytes.fromhex(s["data"]) for s in answer["symbols"]]

    def parts(
        tid: bytes, data: bytes, ids: list[int], total: int | None = None, fec: bytes | None = None
    ) -> list[str]:
        k = (len(data) + 767) // 768
        ft = fec or fec_type(rq, len(data), 768, k)
        return [
            rldp2_part(tid, ft, 0, len(data) if total is None else total, i, s).hex()
            for i, s in zip(ids, symbols(data, ids), strict=True)
        ]

    def recv(name: str, packets: list[str], expect: Json | None = None, **extra: Any) -> None:
        ctx: Json = {"op": "rldp2_receive", "packets": packets}
        note_keys = ("sent_by", "data_sha256")
        notes = {k: v for k, v in extra.items() if k in note_keys}
        ctx.update({k: v for k, v in extra.items() if k not in note_keys})
        fam.add(f"receive/{name}", ctx, expect, **notes)

    for size in (1, 768, 769, 7680):
        data = seed_bytes(f"rldp2-{size}", size)
        k = (size + 767) // 768
        recv(
            f"{size}-in-order",
            parts(transfer, data, list(range(k))),
            sent_by=f"send/{size}",
            data_sha256=hashlib.sha256(data).hexdigest(),
        )
    data = seed_bytes("rldp2-3000", 3000)
    k = 4
    recv("repair-only", parts(transfer, data, list(range(k, k + 6))))
    recv("reversed", parts(transfer, data, list(reversed(range(k)))))
    recv(
        "duplicate-after-completion",
        parts(transfer, data, list(range(k))) + parts(transfer, data, [0]),
    )
    recv("missing-one", parts(transfer, data, list(range(k - 1))), {"events": []})
    recv(
        "two-transfers",
        parts(transfer, data, list(range(k)))
        + parts(seed_bytes("transfer-2"), data, list(range(k))),
    )
    recv(
        "too-big-default-mtu",
        parts(transfer, seed_bytes("rldp2-7681", 7681), list(range(11))),
        {"events": [], "inbound_transfers": 0},
    )
    big = seed_bytes("rldp2-7681", 7681)
    recv("raised-mtu", parts(transfer, big, list(range(11))), default_mtu="7681")
    recv(
        "request-limit",
        parts(transfer, big, list(range(11))),
        requests=[{"transfer_id": transfer.hex(), "max_size": "8000"}],
    )
    recv(
        "request-limit-too-small",
        parts(transfer, big, list(range(11))),
        {"events": []},
        requests=[{"transfer_id": transfer.hex(), "max_size": "7000"}],
    )
    recv(
        "online-type",
        parts(transfer, data, list(range(k)), fec=fec_type("fec_online", 3000, 768, 4)),
        {"events": [], "inbound_transfers": 0},
    )
    recv(
        "symbol-size-1024",
        [rldp2_part(transfer, fec_type(rq, 3000, 1024, 3), 0, 3000, 0, b"\0" * 1024).hex()],
        {"events": [], "inbound_transfers": 0},
    )
    recv(
        "part-1-first",
        [rldp2_part(transfer, fec_type(rq, 3000, 768, 4), 1, 3000, 0, b"\0" * 768).hex()],
        {"events": [], "inbound_transfers": 0},
    )
    recv(
        "part-size-mismatch",
        [rldp2_part(transfer, fec_type(rq, 2000, 768, 3), 0, 3000, 0, b"\0" * 768).hex()],
        {"events": [], "inbound_transfers": 0},
    )
    recv(
        "total-size-negative",
        [rldp2_part(transfer, fec_type(rq, 3000, 768, 4), 0, -1, 0, b"\0" * 768).hex()],
        {"events": [], "inbound_transfers": 0},
    )
    recv(
        "seqno-negative",
        [rldp2_part(transfer, fec_type(rq, 3000, 768, 4), 0, 3000, -1, b"\0" * 768).hex()],
        {"events": [], "inbound_transfers": 0},
    )
    recv(
        "symbol-short",
        [rldp2_part(transfer, fec_type(rq, 3000, 768, 4), 0, 3000, 0, b"\0" * 767).hex()],
    )
    recv(
        "symbol-id-2-pow-24",
        [rldp2_part(transfer, fec_type(rq, 3000, 768, 4), 0, 3000, 1 << 24, b"\0" * 768).hex()],
    )
    recv("complete-unknown", [rldp2_complete(transfer, 0).hex()], {"events": []})
    recv("confirm-unknown", [rldp2_confirm(transfer, 0, 1, 1, 1).hex()], {"events": []})
    recv("garbage", ["00", msg_nop().hex(), ""], {"events": []})
    recv(
        "budget-exhausted",
        parts(transfer, data, list(range(k))),
        {"events": [], "inbound_transfers": 0},
        budget={"max_decoders": "2", "max_bytes": "1000"},
    )
    recv("empty", [], {"events": []})


# ---------------------------------------------------------------------------------------------------------
# Commands


# ---------------------------------------------------------------------------------------------------------
# overlay broadcasts: the node's overlay actors for a fixed-member overlay, its wall clock fixed at `now`

BROADCAST_NOW = 1_700_000_000
BROADCAST_NAME = b"conformance-broadcast"
# AllowFec | Trusted: every member may send every kind of broadcast without a certificate.
BROADCAST_RULE_FLAGS = 3


def broadcast_members(count: int) -> list[bytes]:
    return [pk_ed25519(seed_bytes(f"broadcast-member-{i}")) for i in range(count)]


def broadcast_ctx(mode: str, members: int = 2, **fields: Any) -> Json:
    ctx: Json = {
        "op": "overlay_broadcast",
        "now": BROADCAST_NOW,
        "name": BROADCAST_NAME.hex(),
        "members": [key.hex() for key in broadcast_members(members)],
        "mode": mode,
        "max_unauth_size": 1 << 20,
        "flags": BROADCAST_RULE_FLAGS,
        "authorized_keys": [],
    }
    ctx.update(fields)
    return ctx


def broadcast_send(data: bytes, flags: int = 0, fec: bool = False) -> Json:
    return {"data": data.hex(), "flags": flags, "fec": fec}


def overlay_message_prefix() -> bytes:
    """overlay.message for the broadcast overlay: the bytes before every broadcast object."""
    overlay_short = hashlib.sha256(pub_overlay_full(BROADCAST_NAME)).digest()
    return ctor("overlay_message") + overlay_short


def pub_overlay_full(name: bytes) -> bytes:
    # OverlayIdFull's key is pub.overlay of the name (overlay/overlay-id.hpp).
    return pub_overlay(name)


def tl_bytes_at(data: bytes, at: int) -> tuple[bytes, int]:
    """A TL bytes field at `at`: its value and the offset after its padding."""
    if data[at] < 254:
        length, start = data[at], at + 1
    else:
        length, start = int.from_bytes(data[at + 1 : at + 4], "little"), at + 4
    end = start + length
    return data[start:end], end + (-(end - at) % 4)


class SimpleBroadcast:
    """overlay.broadcast inside an overlay.message, with an empty certificate."""

    def __init__(self, message: bytes) -> None:
        if message[36:40] != ctor("overlay_broadcast") or message[76:80] != ctor(
            "overlay_emptyCertificate"
        ):
            fail("not a simple broadcast with an empty certificate")
        self.prefix = message[:36]
        self.src = message[40:76]
        self.flags = struct.unpack("<i", message[80:84])[0]
        self.data, at = tl_bytes_at(message, 84)
        self.date = struct.unpack("<i", message[at : at + 4])[0]
        self.signature, end = tl_bytes_at(message, at + 4)
        if end != len(message):
            fail("trailing bytes after a simple broadcast")

    def build(self) -> bytes:
        return (
            self.prefix
            + ctor("overlay_broadcast")
            + self.src
            + ctor("overlay_emptyCertificate")
            + i32(self.flags)
            + tl_bytes(self.data)
            + i32(self.date)
            + tl_bytes(self.signature)
        )

    def to_sign(self) -> bytes:
        """overlay.broadcast.toSign of the fields, as the authoring reads the scheme."""
        source = b"\0" * 32 if self.flags & 1 else hashlib.sha256(self.src).digest()
        broadcast_id = hashlib.sha256(
            ctor("overlay_broadcast_id")
            + source
            + hashlib.sha256(self.data).digest()
            + i32(self.flags)
        ).digest()
        return ctor("overlay_broadcast_toSign") + broadcast_id + i32(self.date)


def emitted_to(answer: Json, kind: str, dst: int = 1) -> bytes:
    for item in cast(list[Json], answer["emitted"]):
        if item["type"] == kind and item["dst"] == dst:
            return bytes.fromhex(cast(str, item["canonical"]))
    fail(f"no {kind} to member {dst} in {answer}")
    return b""


def flip_last(data: bytes, back: int) -> bytes:
    return flip(data, len(data) - back)


def add_overlay_broadcasts(fam: Family, inbound: Family, ref: Reference) -> None:
    """Broadcasts sent by member 0, and messages a member receives built from what the node sent.

    Notes: `delivered_to` lists the members whose application must receive the broadcast (each once),
    `messages_to` those that must receive it as a plain message, `data_sha256` the digest every delivery
    must carry, `replay_of` the sender fixture whose emitted message an inbound one repeats unchanged.
    """
    members = broadcast_members(8)
    member0 = ref.short_id(ref.public_key(members[0])).hex()
    hello = b"hello, overlay"
    every = list(range(8))

    def sender(fixture_id: str, ctx: Json, data: bytes, delivered_to: list[int]) -> None:
        extra: Json = {"delivered_to": delivered_to}
        if delivered_to:
            extra["data_sha256"] = hashlib.sha256(data).hexdigest()
        fam.add(fixture_id, ctx, None, **extra)

    def send_ctx(
        mode: str,
        data: bytes,
        members_count: int = 2,
        flags: int = 0,
        fec: bool = False,
        **rules: Any,
    ) -> Json:
        return broadcast_ctx(
            mode,
            members=members_count,
            broadcast=broadcast_send(data, flags=flags, fec=fec),
            **rules,
        )

    sender("simple/hello", send_ctx("simple", hello), hello, [0, 1])
    # The privacy rules forbid AnySender for a key they do not authorize (OverlayPrivacyRules::check_rules).
    sender("simple/any-sender", send_ctx("simple", hello, flags=1), hello, [])
    any_authorized = send_ctx(
        "simple", hello, flags=1, authorized_keys=[{"key": member0, "max_size": 1 << 20}]
    )
    sender("simple/any-sender-authorized", any_authorized, hello, [0, 1])
    # Neither trusted nor authorized: the receiver asks its application, which accepts.
    need_check = send_ctx("simple", hello)
    need_check["flags"] = 0
    sender("simple/need-check", need_check, hello, [0, 1])
    sender("simple/768", send_ctx("simple", b"s" * 768), b"s" * 768, [0, 1])
    sender("simple/empty", send_ctx("simple", b""), b"", [])
    sender(
        "simple/over-unauthorized-size",
        send_ctx("simple", b"nine byte", max_unauth_size=8, flags=0),
        b"nine byte",
        [],
    )
    authorized = send_ctx(
        "simple",
        hello,
        max_unauth_size=0,
        authorized_keys=[{"key": member0, "max_size": 1 << 20}],
    )
    authorized["flags"] = 0
    sender("simple/authorized-key", authorized, hello, [0, 1])
    sender("fec/50", send_ctx("fec", b"f" * 50, fec=True), b"f" * 50, [0, 1])
    sender("fec/1500", send_ctx("fec", b"g" * 1500, fec=True), b"g" * 1500, [0, 1])
    no_fec = send_ctx("fec", b"f" * 50, fec=True)
    no_fec["flags"] = 0
    sender("fec/not-allowed", no_fec, b"f" * 50, [])
    sender("twostep/simple", send_ctx("twostep", hello, fec=True), hello, [0, 1])
    sender("twostep/fec-6", send_ctx("twostep", b"t" * 600, 6, fec=True), b"t" * 600, every[:6])
    sender(
        "twostep/fec-8-any-sender",
        send_ctx("twostep", b"u" * 2000, 8, flags=1, fec=True),
        b"u" * 2000,
        every,
    )
    sender(
        "twostep/below-fec-size",
        send_ctx("twostep", b"t" * 512, 6, fec=True),
        b"t" * 512,
        every[:6],
    )
    sender("twostep/old-simple", send_ctx("twostep", hello), hello, [0, 1])
    # Plumtree: with one neighbour the sender pushes lazily (IHave) and repairs on a timer.
    sender("plumtree/simple", send_ctx("plumtree", hello), hello, [0])
    sender("plumtree/fec", send_ctx("plumtree", b"p" * 6000, fec=True), b"p" * 6000, [0])
    answers = {e["fixture_id"]: ref.one(cast(Json, e["context"])) for e in fam.entries}

    stranger = hashlib.sha256(b"net-fixture:broadcast-stranger").hexdigest()

    def receive(
        fixture_id: str,
        mode: str,
        message: bytes,
        delivered_to: list[int],
        drops: list[str],
        times: int = 1,
        src: str | None = None,
        messages_to: list[int] | None = None,
        replay_of: str | None = None,
        **fields: Any,
    ) -> None:
        ctx = broadcast_ctx(mode, **fields)
        ctx["inbound"] = [
            {"src": src or member0, "dst": 1, "message": message.hex()} for _ in range(times)
        ]
        extra: Json = {"delivered_to": delivered_to, "messages_to": messages_to or []}
        if replay_of is not None:
            extra["replay_of"] = replay_of
        inbound.add(fixture_id, ctx, {"drops": drops}, **extra)

    simple = emitted_to(answers["simple/hello"], "overlay.broadcast")
    receive("simple/replay", "simple", simple, [0, 1], [], replay_of="simple/hello")
    receive("simple/twice", "simple", simple, [0, 1], [], times=2, replay_of="simple/hello")
    receive("simple/signature-flipped", "simple", flip_last(simple, 8), [], ["invalid_signature"])
    data_flipped = SimpleBroadcast(simple)
    data_flipped.data = flip(data_flipped.data, 0)
    receive("simple/data-flipped", "simple", data_flipped.build(), [], ["invalid_signature"])
    other_src = SimpleBroadcast(simple)
    other_src.src = ref.public_key(members[1])
    receive("simple/source-not-the-signer", "simple", other_src.build(), [], ["invalid_signature"])
    receive(
        "simple/from-non-member", "simple", simple, [], ["overlay_unknown_source"], src=stranger
    )
    # The receiver accepts dates within 20 s of its clock (OverlayImpl::check_date); a date outside is
    # dropped without a log line.
    for label, offset, accepted in (
        ("19-s-old", -19, True),
        ("21-s-old", -21, False),
        ("20-s-new", 20, True),
        ("21-s-new", 21, False),
    ):
        redated = SimpleBroadcast(simple)
        redated.date = BROADCAST_NOW + offset
        redated.signature = ref.sign(members[0], redated.to_sign())
        receive(f"simple/date-{label}", "simple", redated.build(), [0, 1] if accepted else [], [])
    any_sender = SimpleBroadcast(simple)
    any_sender.flags = 1
    any_sender.signature = ref.sign(members[0], any_sender.to_sign())
    receive("simple/any-sender-resigned", "simple", any_sender.build(), [], [])
    # The 768-byte bound applies to the sender only: a received one-byte-longer broadcast is accepted.
    for size in (768, 769):
        sized = SimpleBroadcast(simple)
        sized.data = b"s" * size
        sized.signature = ref.sign(members[0], sized.to_sign())
        receive(f"simple/data-{size}-resigned", "simple", sized.build(), [0, 1], [])
    # Not a broadcast object: the overlay hands it to the application as a message.
    receive("simple/truncated", "simple", simple[:-4], [], [], messages_to=[1])
    receive("simple/to-twostep-overlay", "twostep", simple, [0, 1], [])

    fec = emitted_to(answers["fec/50"], "overlay.broadcastFec")
    receive("fec/replay", "fec", fec, [0, 1], [], replay_of="fec/50")
    receive("fec/signature-flipped", "fec", flip_last(fec, 8), [], ["invalid_signature"])
    receive("fec/data-hash-flipped", "fec", flip(fec, 80), [], ["invalid_signature"])
    receive("fec/to-overlay-without-fec", "fec", fec, [], [], flags=0)

    twostep = emitted_to(answers["twostep/simple"], "overlay.broadcastTwostepSimple")
    receive("twostep/replay", "twostep", twostep, [1], [], replay_of="twostep/simple")
    receive(
        "twostep/signature-flipped", "twostep", flip_last(twostep, 8), [], ["invalid_signature"]
    )
    receive("twostep/data-flipped", "twostep", flip(twostep, 120), [], ["invalid_signature"])
    receive("twostep/to-simple-overlay", "simple", twostep, [], ["broadcast_disabled"])
    receive(
        "twostep/from-non-member", "twostep", twostep, [], ["overlay_unknown_source"], src=stranger
    )

    ihave = emitted_to(answers["plumtree/simple"], "overlay.broadcastPlumtreeIHave")
    # An IHave only announces: the receiver asks for the broadcast after its repair timeout.
    receive("plumtree/ihave-replay", "plumtree", ihave, [], [], replay_of="plumtree/simple")
    receive("plumtree/ihave-signature-flipped", "plumtree", flip_last(ihave, 8), [], [])
    receive("plumtree/ihave-to-simple-overlay", "simple", ihave, [], ["broadcast_disabled"])


def command_contexts(
    reference: str, rtos: Path | None, out: Path, only: set[str] | None = None
) -> dict[str, int]:
    """Writes the contexts of every family, or of the families in `only` (and those built with them)."""
    ref = Reference(reference)
    TL_IDS.update(load_tl_ids(TL_HEADER))
    families = {name: Family(name) for name in FAMILY_SOURCES}
    f = families
    builders: list[tuple[tuple[str, ...], Any]] = [
        (("keys",), lambda: add_keys(f["keys"], ref)),
        (("ed25519-rfc8032",), lambda: add_rfc8032(f["ed25519-rfc8032"])),
        (
            ("adnl-id", "adnl-id-test-adnl"),
            lambda: add_adnl_id(f["adnl-id"], f["adnl-id-test-adnl"]),
        ),
        (("adnl-address-list",), lambda: add_address_lists(f["adnl-address-list"], ref)),
        (("adnl-message",), lambda: add_messages(f["adnl-message"])),
        (("adnl-packet",), lambda: add_packets(f["adnl-packet"], ref)),
        (("adnl-packet-flags",), lambda: add_packet_flags(f["adnl-packet-flags"], ref)),
        (("adnl-datagram",), lambda: add_datagrams(f["adnl-datagram"], ref)),
        (("adnl-channel",), lambda: add_channels(f["adnl-channel"], ref)),
        (("preauth",), lambda: add_preauth(f["preauth"])),
        (("overlay-id",), lambda: add_overlay_ids(f["overlay-id"])),
        (("overlay-node",), lambda: add_overlay_nodes(f["overlay-node"], ref)),
        (
            ("overlay-node-rtos",),
            lambda: add_overlay_node_rtos(f["overlay-node-rtos"], ref, rtos_path(rtos)),
        ),
        (("overlay-certificate",), lambda: add_overlay_certificates(f["overlay-certificate"], ref)),
        (
            ("overlay-member-certificate",),
            lambda: add_member_certificates(f["overlay-member-certificate"], ref),
        ),
        (("overlay-policy",), lambda: add_overlay_policy(f["overlay-policy"])),
        (("fec-type",), lambda: add_fec_types(f["fec-type"])),
        (("fec-raptorq",), lambda: add_fec_code(f["fec-raptorq"], ref, "raptorq")),
        (
            ("fec-raptorq-sweep",),
            lambda: add_fec_code(f["fec-raptorq-sweep"], ref, "raptorq", sweep=True),
        ),
        (("fec-online",), lambda: add_fec_code(f["fec-online"], ref, "online")),
        (("fec-round-robin",), lambda: add_fec_code(f["fec-round-robin"], ref, "round_robin")),
        (("rldp2",), lambda: add_rldp2(f["rldp2"], ref)),
        (
            ("overlay-broadcast", "overlay-broadcast-inbound"),
            lambda: add_overlay_broadcasts(
                f["overlay-broadcast"], f["overlay-broadcast-inbound"], ref
            ),
        ),
    ]
    if only is not None and not only <= set(FAMILY_SOURCES):
        fail(f"unknown families {sorted(only - set(FAMILY_SOURCES))}")
    for names, build in builders:
        if only is None or set(names) & only:
            build()
        else:
            for name in names:
                del families[name]
    out.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for name, fam in families.items():
        if not fam.entries:
            fail(f"{name}: no contexts")
        path = out / f"{name}.contexts.jsonl"
        path.write_text(
            "".join(
                json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in fam.entries
            )
        )
        counts[name] = len(fam.entries)
    return counts


def rtos_path(rtos: Path | None) -> Path:
    if rtos is None:
        fail("overlay-node-rtos needs --rtos")
        return Path()
    return rtos


def command_create(
    reference: str, contexts: Path, vectors: Path, only: set[str] | None = None
) -> None:
    """Fill every contexts file (or those of `only`) through runner/conformance.py create."""
    runner = Path(__file__).resolve().parent.parent / "runner" / "conformance.py"
    for family, source in FAMILY_SOURCES.items():
        if only is not None and family not in only:
            continue
        path = contexts / f"{family}.contexts.jsonl"
        if not path.is_file():
            fail(f"{path}: missing")
        out = vectors / "fixtures" / f"{family}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        # Every byte field is hex; create's blob store would take a long one for base64, so none is moved.
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(runner),
                "create",
                "--reference",
                reference,
                "--harness",
                "net",
                "--family",
                family,
                "--source",
                source,
                "--blob-threshold",
                str(NO_BLOBS),
                str(path),
                str(out),
            ],
            check=True,
            timeout=REFERENCE_TIMEOUT_SECONDS,
        )


def subset_holds(effects: Any, expect: Any, where: str = "") -> list[str]:
    if isinstance(expect, dict):
        if not isinstance(effects, dict):
            return [f"{where or '.'}: expected an object"]
        problems: list[str] = []
        for key, value in cast(Json, expect).items():
            if key not in effects:
                problems.append(f"{where}.{key}: missing")
            else:
                problems += subset_holds(effects[key], value, f"{where}.{key}")
        return problems
    if effects != expect:
        return [f"{where}: {effects!r} != {expect!r}"]
    return []


def load(directory: Path, family: str) -> dict[str, Json]:
    path = directory / "fixtures" / f"{family}.jsonl"
    records: dict[str, Json] = {}
    for line in path.read_text().splitlines():
        record = cast(Json, json.loads(line))
        records[cast(str, record["metadata"]["fixture_id"])] = record
    return records


def broadcast_problems(senders: dict[str, Json], inbound: dict[str, Json]) -> list[str]:
    """The delivery notes of the broadcast families, and inbound replays equal to what was sent."""
    problems: list[str] = []
    for name, records in (("overlay-broadcast", senders), ("overlay-broadcast-inbound", inbound)):
        for fixture_id, record in records.items():
            note = cast(Json, json.loads(record["metadata"].get("note", "{}")))
            effects = cast(Json, record["effects"])
            delivered = cast(list[Json], effects.get("delivered", []))
            for kind, key in (("broadcast", "delivered_to"), ("message", "messages_to")):
                if key not in note:
                    continue
                got = sorted(cast(int, d["member"]) for d in delivered if d["kind"] == kind)
                if got != sorted(cast(list[int], note[key])):
                    problems.append(
                        f"{name}/{fixture_id}: {kind} delivered to {got}, not {note[key]}"
                    )
            if "data_sha256" in note and any(
                d["data_sha256"] != note["data_sha256"]
                for d in delivered
                if d["kind"] == "broadcast"
            ):
                problems.append(f"{name}/{fixture_id}: a delivery is not the sent data")
            if "replay_of" in note:
                sent = senders[cast(str, note["replay_of"])]["effects"]["emitted"]
                message = record["context"]["inbound"][0]["message"]
                if message not in [m["canonical"] for m in sent if m["src"] == 0 and m["dst"] == 1]:
                    problems.append(f"{name}/{fixture_id}: not a message {note['replay_of']} sent")
    return problems


def command_check(directory: Path) -> list[str]:
    problems: list[str] = []
    fams = {name: load(directory, name) for name in FAMILY_SOURCES}
    for name, records in fams.items():
        for fixture_id, record in records.items():
            meta = cast(Json, record["metadata"])
            if "note" in meta:
                note = cast(Json, json.loads(cast(str, meta["note"])))
                problems += [
                    f"{name}/{fixture_id}: {p}"
                    for p in subset_holds(record["effects"], note.get("expect", {}))
                ]
                if "data_sha256" in note and name.startswith("fec-"):
                    if record["effects"].get("data_sha256") != note["data_sha256"]:
                        problems.append(
                            f"{name}/{fixture_id}: decoded data is not the encoded data"
                        )
    keys = fams["keys"]
    ab = keys["shared-secret/alice-bob"]["effects"]
    ba = keys["shared-secret/bob-alice"]["effects"]
    if ab.get("outcome") != "secret" or ab != ba:
        problems.append("keys: the shared secret is not symmetric")
    for fixture_id, record in keys.items():
        note = json.loads(record["metadata"].get("note", "{}"))
        if "encrypted_by" in note:
            enc = keys[note["encrypted_by"]]
            if enc["effects"].get("ciphertext") != record["context"]["ciphertext"]:
                problems.append(f"keys/{fixture_id}: ciphertext is not the frozen encryption")
            if enc["context"]["data"] != record["effects"].get("plaintext"):
                problems.append(f"keys/{fixture_id}: does not decrypt to the encrypted data")
    rtos_node = fams["overlay-node-rtos"]["node"]
    to_sign = cast(str, rtos_node["effects"]["to_sign"])
    vector_to_sign = cast(str, json.loads(rtos_node["metadata"]["note"])["to_sign_vector"])
    # The vector signs for id 33..33; the node's own id is the hash of its key. The rest must be equal.
    if to_sign[:8] + "33" * 32 + to_sign[72:] != vector_to_sign:
        problems.append("overlay-node-rtos/node: toSign framing differs from the RTOS vector")
    channel = fams["adnl-channel"]
    alice, bob = channel["alice-ids"]["effects"], channel["bob-ids"]["effects"]
    if alice["in_id"] != bob["out_id"] or alice["out_id"] != bob["in_id"]:
        problems.append("adnl-channel: the two ends do not agree on the channel ids")
    sent = channel["alice-sends"]
    received = channel["bob-receives"]
    if received["context"]["datagram"] != sent["effects"]["sent"]:
        problems.append("adnl-channel/bob-receives: not the datagram alice sent")
    packet = (
        received["effects"]["received"].get("packet") if received["effects"]["received"] else None
    )
    if packet is None or packet["canonical"] != sent["context"]["send"]:
        problems.append("adnl-channel/bob-receives: the received packet is not the one sent")
    rldp = fams["rldp2"]
    for fixture_id, record in rldp.items():
        note = json.loads(record["metadata"].get("note", "{}"))
        if "sent_by" not in note:
            continue
        emitted = [
            p["sha256"] for p in rldp[note["sent_by"]]["effects"]["packets"] if p["type"] == "part"
        ]
        built = [hashlib.sha256(bytes.fromhex(p)).hexdigest() for p in record["context"]["packets"]]
        if not emitted or emitted[: len(built)] != built:
            problems.append(
                f"rldp2/{fixture_id}: datagrams differ from the ones the node's sender emits"
            )
        delivered = [r for e in record["effects"]["events"] for r in e["received"]]
        if len(delivered) != 1 or delivered[0]["data_sha256"] != note.get("data_sha256"):
            problems.append(f"rldp2/{fixture_id}: the transfer was not delivered intact")
    problems += broadcast_problems(fams["overlay-broadcast"], fams["overlay-broadcast-inbound"])
    for fam_name in ("fec-raptorq", "fec-online", "fec-round-robin"):
        fam = fams[fam_name]
        for fixture_id, record in fam.items():
            regenerated = record["effects"].get("regenerated")
            if not regenerated:
                continue
            # decode/<name>-source regenerates ids that encode/<name>-source and encode/<name>-repair produced.
            stem = fixture_id.removeprefix("decode/").removesuffix("-source")
            by_id: dict[int, str] = {}
            for part in ("source", "repair"):
                encoded = fam.get(f"encode/{stem}-{part}")
                if encoded is not None:
                    by_id.update({s["id"]: s["data"] for s in encoded["effects"]["symbols"]})
            for symbol in regenerated:
                if by_id.get(symbol["id"]) != symbol["data"]:
                    problems.append(
                        f"{fam_name}/{fixture_id}: regenerated symbol {symbol['id']} is not the encoded one"
                    )
    return problems


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("contexts")
    make.add_argument("--reference", required=True)
    make.add_argument("--rtos", type=Path, help="needed for overlay-node-rtos")
    make.add_argument("--out", required=True, type=Path)
    make.add_argument("--only", action="append", help="build only these families")
    create = sub.add_parser("create")
    create.add_argument("--reference", required=True)
    create.add_argument("--contexts", required=True, type=Path)
    create.add_argument("vectors", type=Path)
    create.add_argument("--only", action="append", help="fill only these families")
    check = sub.add_parser("check")
    check.add_argument("directory", type=Path)
    args = parser.parse_args(None if argv is None else list(argv))
    if args.command == "contexts":
        only = set(cast(list[str], args.only)) if args.only else None
        print(
            json.dumps(command_contexts(args.reference, args.rtos, args.out, only), sort_keys=True)
        )
        return 0
    if args.command == "create":
        command_create(
            args.reference,
            args.contexts,
            args.vectors,
            set(cast(list[str], args.only)) if args.only else None,
        )
        return 0
    problems = command_check(args.directory)
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"net cross-check: {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
