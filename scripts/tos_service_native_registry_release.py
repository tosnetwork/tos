#!/usr/bin/env python3
"""The native registry's frozen release, read from its manifest.

Every deployment entry point that ships the registry must refuse an artifact
whose code hash is not the one the release manifest pins. The hash lives in
one place, the manifest; this module reads it so no script carries a copy that
drifts when the registry is re-frozen.

Standard library only, so the check can run where the deployment tooling's
dependencies are not installed.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RELEASE_MANIFEST = REPO / "crypto/smartcont/tos-service-native-registry-v1.release.json"
FROZEN_CODE_BASE64 = REPO / "crypto/smartcont/tos-service-native-registry-v1.boc.base64"

CODE_HASH_PREFIX = "tvm-cell-sha256:"
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def release_code_hash(manifest_path: Path = RELEASE_MANIFEST) -> str:
    """The code hash the release manifest pins, as 64 lower-case hex characters."""
    manifest = json.loads(manifest_path.read_text())
    value = manifest.get("code_hash")
    if not isinstance(value, str) or not value.startswith(CODE_HASH_PREFIX):
        raise RuntimeError(f"{manifest_path}: code_hash must start with {CODE_HASH_PREFIX!r}")
    digest = value[len(CODE_HASH_PREFIX) :]
    if not HEX_256.match(digest):
        raise RuntimeError(f"{manifest_path}: code_hash is not 64 hex characters")
    return digest


def frozen_code_bytes(path: Path = FROZEN_CODE_BASE64) -> bytes:
    """The frozen registry BOC, decoded from its committed base64 file."""
    return base64.b64decode(b"".join(path.read_bytes().split()), validate=True)


def require_code_hash(actual_hex: str, expected_hex: str) -> None:
    """Refuse a registry artifact whose code hash is not the released one."""
    if actual_hex.lower() != expected_hex.lower():
        raise RuntimeError(
            f"frozen code hash mismatch: artifact {actual_hex}, release manifest {expected_hex}"
        )
