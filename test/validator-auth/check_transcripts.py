#!/usr/bin/env python3
"""Check the isolated candidate-authentication transcripts with second implementations.

Every Ed25519 signature the experiment emits is re-verified with libsodium, and each
one is paired with a negative control so a verifier that accepts everything cannot
pass. The optional OpenSSL ML-DSA check is a separate, explicitly requested
interoperability measurement.

This covers the isolated experiment only. The live Simplex entrypoints are covered by
test-certificate-conformance, which runs the production parsers under real
post-quantum keys, and whose signing preimages are independently reconstructed by
test/validator/consensus/check-simplex-preimages.py.
"""

import argparse
import ctypes
import ctypes.util
import json
import subprocess
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sodium_verifier():
    name = ctypes.util.find_library("sodium")
    require(bool(name), "libsodium is required; do not silently skip independent verification")
    library = ctypes.CDLL(name)
    library.sodium_init.restype = ctypes.c_int
    require(library.sodium_init() >= 0, "libsodium initialization failed")
    fn = library.crypto_sign_verify_detached
    fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p]
    fn.restype = ctypes.c_int

    def verify(key, message, signature):
        if len(key) != 32 or len(signature) != 64:
            return False
        return (
            fn(
                ctypes.create_string_buffer(signature),
                ctypes.create_string_buffer(message),
                len(message),
                ctypes.create_string_buffer(key),
            )
            == 0
        )

    return verify


def der(tag_number, contents):
    n = len(contents)
    length = (
        bytes([n])
        if n < 128
        else bytes([0x80 + (n.bit_length() + 7) // 8])
        + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )
    return bytes([tag_number]) + length + contents


def openssl_mldsa(key, message, signature, expect_valid):
    # AlgorithmIdentifier id-ml-dsa-44, no parameters; raw public key BIT STRING.
    oid = der(6, bytes.fromhex("608648016503040311"))
    spki = der(0x30, der(0x30, oid) + der(3, b"\0" + key))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, data in [("key.der", spki), ("message", message), ("signature", signature)]:
            (root / name).write_bytes(data)
        command = [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-keyform",
            "DER",
            "-inkey",
            str(root / "key.der"),
            "-in",
            str(root / "message"),
            "-sigfile",
            str(root / "signature"),
            "-pkeyopt",
            "context-string:TOS-VAL-AUTH-EXPERIMENT/v1",
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        require(
            (result.returncode == 0) == expect_valid,
            "independent ML-DSA result differs: " + result.stderr[:200],
        )


def check(experimental: Path, mldsa: bool):
    verify = sodium_verifier()
    independent_ed, pq_checked, checks, signatures = 0, 0, [], []
    for line in experimental.read_text().splitlines():
        fields = line.split("\t")
        if fields[0] == "PASS":
            checks.append(fields[1])
        if fields[0] != "VECTOR":
            continue
        require(len(fields) == 6, "malformed experimental transcript")
        _, label, scheme, key, message, signature = fields
        key, message, signature = map(bytes.fromhex, (key, message, signature))
        require(
            message.startswith(b"TOS-VALIDATOR-AUTH-EXPERIMENT/v1"),
            "an experiment used an unmarked transcript",
        )
        if scheme == "ed25519":
            require(
                verify(key, message, signature), "libsodium rejects experimental Ed25519 signature"
            )
            require(
                not verify(key, message + b"x", signature),
                "experimental independent negative control did not fail",
            )
            independent_ed += 2
        elif scheme == "mldsa44":
            require(len(key) == 1312 and len(signature) == 2420, "wrong ML-DSA profile")
            if mldsa:
                openssl_mldsa(key, message, signature, True)
                openssl_mldsa(key, message + b"x", signature, False)
                pq_checked += 2
        else:
            raise ValueError("unknown transcript scheme")
        signatures.append((label, scheme))
    require(len(checks) >= 300 and len(signatures) == 5, "missing isolated signature evidence")
    return {
        "success": True,
        "experimental_assertions": len(checks),
        "independent_ed25519_checks": independent_ed,
        "independent_mldsa_checks": pq_checked,
        "scope": "isolated candidate authentication, not the live consensus entrypoints",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experimental", type=Path)
    parser.add_argument("--openssl-mldsa", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.experimental, args.openssl_mldsa)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result))
