"""Versioned encrypted portable backup, with bounded scrypt and AES-256-GCM."""

import hashlib
import json
import os

from backend import PROFILE, KeyHandle
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAX_BACKUP_BYTES = 16384


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError("unknown or missing backup field")


def decode_hex(value, size):
    if type(value) is not str or len(value) != size * 2:
        raise ValueError("incorrect backup field length")
    return bytes.fromhex(value)


def association(network, account, root):
    if type(network) is not int or not -(1 << 31) <= network < 1 << 31:
        raise ValueError("invalid network")
    from pytosiq_core import Address

    result = {}
    for label, value in [("account", account), ("root", root)]:
        addr = Address(value)
        if addr.anycast is not None or addr.wc not in (-1, 0):
            raise ValueError("unsupported backup address")
        result[label] = addr.to_str(is_user_friendly=False)
    return dict(network=network, **result)


def derive(password, salt, n, r, p):
    if type(password) is not bytes or not 12 <= len(password) <= 1024:
        raise ValueError("backup password must be 12..1024 UTF-8 bytes")
    if (
        type(n) is not int
        or n not in (32768, 65536)
        or type(r) is not int
        or r != 8
        or type(p) is not int
        or p != 1
    ):
        raise ValueError("unsupported or unbounded scrypt parameters")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password)


def encrypt(handle, password, network, account, root):
    if handle.closed:
        raise ValueError("key handle is closed")
    salt, nonce = os.urandom(16), os.urandom(12)
    metadata = dict(
        version=1,
        profile=PROFILE,
        key_encoding="falcon-original-encoded-v1",
        public_key=handle.public_key.hex(),
        fingerprint=hashlib.sha256(handle.public_key).hexdigest(),
        association=association(network, account, root),
        kdf=dict(name="scrypt", n=32768, r=8, p=1, salt=salt.hex()),
        aead=dict(name="AES-256-GCM", nonce=nonce.hex()),
    )
    ciphertext = AESGCM(derive(password, salt, 32768, 8, 1)).encrypt(
        nonce, bytes(handle._secret), canonical(metadata)
    )
    return canonical(dict(metadata=metadata, encrypted_secret_key=ciphertext.hex()))


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate backup field")
        out[key] = value
    return out


def restore(raw, password, backend, expected_association=None):
    if type(raw) is not bytes or len(raw) > MAX_BACKUP_BYTES:
        raise ValueError("backup too large")
    document = json.loads(raw, object_pairs_hook=unique)
    exact(document, ["metadata", "encrypted_secret_key"])
    m = document["metadata"]
    exact(
        m,
        [
            "version",
            "profile",
            "key_encoding",
            "public_key",
            "fingerprint",
            "association",
            "kdf",
            "aead",
        ],
    )
    if (
        type(m["version"]) is not int
        or m["version"] != 1
        or m["profile"] != PROFILE
        or m["key_encoding"] != "falcon-original-encoded-v1"
    ):
        raise ValueError("unknown backup profile/version")
    a = m["association"]
    exact(a, ["network", "account", "root"])
    if association(**a) != a or (expected_association is not None and a != expected_association):
        raise ValueError("backup association mismatch")
    k, e = m["kdf"], m["aead"]
    exact(k, ["name", "n", "r", "p", "salt"])
    exact(e, ["name", "nonce"])
    if k["name"] != "scrypt" or e["name"] != "AES-256-GCM":
        raise ValueError("unknown backup protection")
    public = decode_hex(m["public_key"], 897)
    if (
        not backend.validate_public_key(public)
        or m["fingerprint"] != hashlib.sha256(public).hexdigest()
    ):
        raise ValueError("incorrect public key identity")
    salt, nonce = decode_hex(k["salt"], 16), decode_hex(e["nonce"], 12)
    ciphertext = decode_hex(document["encrypted_secret_key"], 1297)
    plain = bytearray(
        AESGCM(derive(password, salt, k["n"], k["r"], k["p"])).decrypt(
            nonce, ciphertext, canonical(m)
        )
    )
    handle = None
    try:
        handle = KeyHandle(plain, public)
        # Restored key possession is verified before allowing strict migration.
        backend.sign(handle, b"TOS-FALCON512-BACKUP-CHECK-v1")
        return handle
    except Exception:
        if handle is not None:
            handle.close()
        raise
    finally:
        for i in range(len(plain)):
            plain[i] = 0
