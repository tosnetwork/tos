#!/usr/bin/env python3
"""Official submission KATs and the unmodified upstream conformance suite.

All seeds and secret keys in this fixture are published PUBLIC TEST DATA.
The expected answers come from the official archive, not TOS regeneration.
"""

import argparse
import ctypes
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RSP = Path(__file__).with_name("official") / "falcon512-KAT.rsp"
RSP_SHA256 = "dd75c946fdedef4ec46a2bee7e10c65c9126f1a839b9ced6921fd45f7354b5cd"
KAT_SHA1 = "a57400cbaee7109358859a56c735a3cf048a9da2"
SUITE_SHA256 = "a1c5772cc6a6227c37f385313e020bc296243295e24a57f7b35e7b3241c64bdd"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def records(raw):
    require(hashlib.sha256(raw).hexdigest() == RSP_SHA256, "official KAT SHA-256 mismatch")
    require(hashlib.sha1(raw).hexdigest() == KAT_SHA1, "upstream KAT SHA-1 mismatch")
    blocks = raw.decode("ascii").strip().split("\n\n")
    require(blocks[0] == "# Falcon-512" and len(blocks) == 101, "missing official KAT records")
    result = []
    for index, block in enumerate(blocks[1:]):
        row = {}
        for line in block.splitlines():
            key, value = line.split(" = ", 1)
            require(key not in row, "duplicate KAT field")
            row[key] = value
        require(
            set(row) == {"count", "seed", "mlen", "msg", "pk", "sk", "smlen", "sm"},
            "unexpected KAT fields",
        )
        for field in ("count", "mlen", "smlen"):
            require(str(int(row[field])) == row[field], "noncanonical KAT integer")
            row[field] = int(row[field])
        for field in ("seed", "msg", "pk", "sk", "sm"):
            require(re.fullmatch(r"(?:[0-9A-F]{2})+", row[field]), "noncanonical KAT hex")
            row[field] = bytes.fromhex(row[field])
        require(row["count"] == index and row["mlen"] == 33 * (index + 1), "KAT ordering")
        require(
            len(row["seed"]) == 48
            and len(row["pk"]) == 897
            and len(row["sk"]) == 1281
            and len(row["msg"]) == row["mlen"]
            and len(row["sm"]) == row["smlen"],
            "KAT lengths",
        )
        require(row["pk"][0] == 9 and row["sk"][0] == 0x59, "KAT key profile")
        signed, length = row["sm"], row["mlen"]
        require(int.from_bytes(signed[:2], "big") == len(signed) - length - 42, "KAT framing")
        require(signed[42 : 42 + length] == row["msg"], "KAT embedded message")
        require(signed[42 + length] == 0x29, "KAT signed-message header")
        # The submission's signed-message API stores nonce, message and an
        # embedded 0x29 signature. The external API uses detached 0x39 format.
        # This is framing extraction, with no coefficient changes or padding.
        row["signature"] = b"\x39" + signed[2:42] + signed[43 + length :]
        result.append(row)
    return result


def check_api(library, rows):
    lib = ctypes.CDLL(str(library.resolve()))
    verify = lib.falcon_verify
    verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    verify.restype = ctypes.c_int
    make_public = lib.falcon_make_public
    make_public.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    make_public.restype = ctypes.c_int
    scratch = (ctypes.c_uint64 * 513)()  # >= FALCON_TMPSIZE_VERIFY(9) = 4097
    for row in rows:
        signature, public, message = row["signature"], row["pk"], row["msg"]

        def accepted(payload):
            return (
                verify(
                    signature,
                    len(signature),
                    1,  # Explicit original COMPRESSED, not the TOS PADDED profile.
                    public,
                    len(public),
                    payload,
                    len(payload),
                    scratch,
                    ctypes.sizeof(scratch),
                )
                == 0
            )

        require(accepted(message), f"official signature rejected at count {row['count']}")
        altered = bytes([message[0] ^ 1]) + message[1:]
        require(not accepted(altered), f"altered message accepted at count {row['count']}")
        derived = ctypes.create_string_buffer(897)
        require(
            make_public(derived, 897, row["sk"], 1281, scratch, ctypes.sizeof(scratch)) == 0
            and derived.raw == public,
            f"official secret/public key mismatch at count {row['count']}",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rows = records(RSP.read_bytes())
    suite_source = ROOT / "third-party/falcon-reference/test_falcon.c"
    require(
        hashlib.sha256(suite_source.read_bytes()).hexdigest() == SUITE_SHA256,
        "upstream suite source was modified",
    )
    check_api(args.library, rows)
    args.out.mkdir(parents=True, exist_ok=True)
    run = subprocess.run(
        [str(args.suite.resolve())], capture_output=True, text=True, timeout=180, check=False
    )
    (args.out / "test_falcon.log").write_text(run.stdout + run.stderr)
    require(run.returncode == 0, "official conformance suite failed")
    hashes = {"512": KAT_SHA1, "1024": "affdeb3aa83bf9a2039fa9c17d65fd3e3b9828e2"}
    for size, digest in hashes.items():
        require(
            re.search(rf"Test NIST KAT \({size}\): \.{{100}} {digest} done\.", run.stdout),
            f"official {size} KAT skipped, incomplete or digest mismatch",
        )
    require("skipped" not in run.stdout.lower(), "official suite skipped a test")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report = dict(
        success=True,
        source_commit=commit,
        kat_source="https://falcon-sign.info/falcon-round3.zip",
        kat_archive_sha256="d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47",
        rsp_sha256=RSP_SHA256,
        official_falcon512_records=len(rows),
        original_compressed_verifications=len(rows),
        altered_message_rejections=len(rows),
        official_secret_public_key_matches=len(rows),
        upstream_suite_source_sha256=SUITE_SHA256,
        upstream_suite_exit=run.returncode,
        upstream_regenerated_kat_records={"512": 100, "1024": 100},
        upstream_regenerated_kat_sha1=hashes,
        scope="official original-Falcon answers; TOS PADDED and VM tests run separately",
        qualification="upstream conformance evidence; not an independent implementation or audit",
    )
    (args.out / "official-kat.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
