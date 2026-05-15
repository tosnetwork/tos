#!/usr/bin/env python3
"""
Compute the canonical wc=3 `stdlib_hash` for an rt.jar file.

This is the value that:
  * gets committed to ConfigParam 85 (via the Fift word
    `jvm-config-param-cell-with-stdlib`, which internally calls
    `JvmConfig::default_activation_with_stdlib`)
  * the production Avata runtime computes from its on-disk rt.jar
    (via `jvm_workchain::hash_boot_classpath`)
  * operators pass to `tosctl jw deploy-contract --stdlib-hash <hex>`

All three MUST agree.  Phase DD landed the shared algorithm in
`jvm/core/config-param.cpp::compute_canonical_stdlib_hash`; this
script is the off-chain mirror — same wire format, byte-for-byte.

Wire format:
    sha256(
        "TOS-JVM-AVATA-BOOTCLASSPATH-v1"
        || u64_be(rt_jar_bytes.size())
        || rt_jar_bytes
        || u64_be(1)                  # entry_count = single-entry classpath
    )

Usage:
    compute-stdlib-hash.py <path-to-rt.jar>
    # → prints the 64-char lowercase hex digest

Pinned by the C++ test
`Test_JvmWorkchainCore_StdlibHashAlgorithmAlignment` — any drift
between this script and the C++ helper breaks that test.
"""

import hashlib
import pathlib
import struct
import sys


DOMAIN_TAG = b"TOS-JVM-AVATA-BOOTCLASSPATH-v1"
ENTRY_COUNT_SINGLE = 1


def compute_canonical_stdlib_hash(rt_jar_bytes: bytes) -> bytes:
    """Return the canonical 32-byte stdlib_hash for `rt_jar_bytes`."""
    h = hashlib.sha256()
    h.update(DOMAIN_TAG)
    # Length prefix (8-byte big-endian) before the entry bytes.
    h.update(struct.pack(">Q", len(rt_jar_bytes)))
    h.update(rt_jar_bytes)
    # Trailing entry count: anchors the single-entry classpath
    # against any future multi-entry layout that might concatenate
    # to the same byte stream.
    h.update(struct.pack(">Q", ENTRY_COUNT_SINGLE))
    return h.digest()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(
            "usage: compute-stdlib-hash.py <path-to-rt.jar>\n"
        )
        return 2
    path = pathlib.Path(argv[1])
    if not path.exists():
        sys.stderr.write(f"input not found: {path}\n")
        return 1
    digest = compute_canonical_stdlib_hash(path.read_bytes())
    sys.stdout.write(digest.hex() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
