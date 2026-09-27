#!/usr/bin/env python3
"""Rebuild what Simplex consensus signs, from the TL schema, and compare it byte for byte.

The C++ test that emits these transcripts produces both the preimage and the signature with
the same serializer, so on its own it cannot notice the serializer changing underneath it.
This rebuilds each preimage here -- constructor tags from the schema text, the session
envelope by hand -- and requires an exact match, so a change to what a validator signs shows
up as a failure rather than as a quietly different byte string.

With --openssl-mldsa (OpenSSL 3.5 or newer), each signature is additionally verified by a
second ML-DSA-44 implementation under the frozen Simplex context, with a negative control.
"""

import argparse
import json
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

SIGN_CONTEXT = "TOS-CONSENSUS-SIMPLEX-v1"

SCHEMAS = {
    "dataToSign": "consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign",
    "candidateId": "consensus.candidateId slot:int hash:int256 = consensus.CandidateId",
    "notarize": "consensus.simplex.notarizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote",
    "finalize": "consensus.simplex.finalizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote",
    "skip": "consensus.simplex.skipVote slot:int = consensus.simplex.UnsignedVote",
}

PUBLIC_KEY_BYTES = 1312
SIGNATURE_BYTES = 2420


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tag(name):
    return struct.pack("<I", zlib.crc32(SCHEMAS[name].encode("ascii")))


def tl_bytes(inner):
    require(len(inner) < 254, "transcript inner object is larger than this encoder handles")
    sized = bytes([len(inner)]) + inner
    return sized + bytes((-len(sized)) % 4)


def envelope(session, inner):
    return tag("dataToSign") + session + tl_bytes(inner)


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
            "context-string:" + SIGN_CONTEXT,
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        require(
            (result.returncode == 0) == expect_valid,
            "independent ML-DSA result differs: " + result.stderr[:200],
        )


def check(transcript_text, mldsa):
    vectors = {}
    for line in transcript_text.splitlines():
        fields = line.split("\t")
        if fields[0] != "VECTOR":
            continue
        require(len(fields) == 5, "malformed transcript line")
        _, label, key, message, signature = fields
        require(label not in vectors, "duplicate transcript label " + label)
        vectors[label] = tuple(bytes.fromhex(x) for x in (key, message, signature))
    require(
        set(vectors) == {"notarize", "finalize", "skip", "proposal"},
        "the transcript must cover every signing domain, found " + repr(sorted(vectors)),
    )

    # The candidate id the proposal signs is the one the votes carry, so it is recovered
    # once and every other preimage is rebuilt around it.
    _, proposal_message, _ = vectors["proposal"]
    # 4 bytes of constructor tag, 32 of session id, then the TL `bytes` length prefix.
    candidate_id = proposal_message[4 + 32 + 1 :][:40]
    require(candidate_id[:4] == tag("candidateId"), "the proposal does not sign a candidate id")
    slot = struct.unpack("<I", candidate_id[4:8])[0]
    require(envelope(proposal_message[4:36], candidate_id) == proposal_message, "proposal preimage")

    session = proposal_message[4:36]
    for name in ("notarize", "finalize"):
        require(
            envelope(session, tag(name) + candidate_id) == vectors[name][1], name + " vote preimage"
        )
    require(
        envelope(session, tag("skip") + struct.pack("<I", slot)) == vectors["skip"][1],
        "skip vote preimage",
    )

    independent = 0
    for label, (key, message, signature) in vectors.items():
        require(len(key) == PUBLIC_KEY_BYTES, label + ": public key is not ML-DSA-44")
        require(len(signature) == SIGNATURE_BYTES, label + ": signature is not ML-DSA-44")
        if mldsa:
            openssl_mldsa(key, message, signature, True)
            openssl_mldsa(key, message + b"x", signature, False)
            independent += 2

    return {
        "success": True,
        "domains": sorted(vectors),
        "slot": slot,
        "independent_mldsa_checks": independent,
        "scope": "what the live Simplex entrypoints sign, rebuilt from the TL schema",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="test-certificate-conformance")
    parser.add_argument("--openssl-mldsa", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = subprocess.run([str(args.binary)], capture_output=True, text=True, timeout=600)
    require(result.returncode == 0, "the conformance binary failed: " + result.stderr[-2000:])
    report = check(result.stdout, args.openssl_mldsa)
    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
