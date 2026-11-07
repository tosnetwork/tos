#!/usr/bin/env python3
"""Rebuild Service Actor; check or explicitly update the SDK's frozen bytecode.

Two frozen copies are checked: the SDK constant SERVICE_ACTOR_CODE_B64 (by root
cell hash) and the release artifact named by tos-service-actor-v1.release.json
(byte for byte). --write refreshes both; the release manifest is refreshed by
hand, and scripts/test-tos-service-actor-v1.sh refuses any drift between them.
"""

import argparse
import base64
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUNC = Path(os.environ.get("FUNC_PATH", ROOT / "build/crypto/func"))
FIFT = Path(os.environ.get("FIFT_PATH", ROOT / "build/crypto/fift"))
SOURCE = ROOT / "crypto/smartcont/service-actor-code.fc"
STDLIB = ROOT / "crypto/smartcont/stdlib.fc"
RUST = ROOT / "tosctl/src/node-control/contracts/src/service_actor.rs"
ARTIFACT = ROOT / "crypto/smartcont/tos-service-actor-v1.boc.base64"


def encode_artifact(boc: bytes) -> str:
    """The artifact's line format: base64 wrapped at 76 columns, newline-terminated."""
    text = base64.b64encode(boc).decode("ascii")
    return "".join(text[i : i + 76] + "\n" for i in range(0, len(text), 76))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="replace the embedded SDK bytecode")
    args = parser.parse_args()
    for tool in (FUNC, FIFT):
        if not tool.is_file():
            raise SystemExit(f"missing compiler tool: {tool} (set FUNC_PATH/FIFT_PATH to override)")
    rust_source = RUST.read_text()
    match = re.search(
        r'pub const SERVICE_ACTOR_CODE_B64: &str = "([A-Za-z0-9+/=]+)";',
        rust_source,
    )
    if not match:
        raise SystemExit("SERVICE_ACTOR_CODE_B64 was not found in Rust source")
    embedded = base64.b64decode(match.group(1), validate=True)

    with tempfile.TemporaryDirectory(prefix="service-actor-bytecode-") as raw_tmp:
        tmp = Path(raw_tmp)
        fift_source = tmp / "service-actor.fif"
        boc = tmp / "service-actor.boc"
        subprocess.run(
            [str(FUNC), "-APS", "-W", str(boc), "-o", str(fift_source), str(STDLIB), str(SOURCE)],
            cwd=ROOT,
            check=True,
        )
        env = os.environ.copy()
        env["FIFTPATH"] = str(ROOT / "crypto/fift/lib")
        subprocess.run([str(FIFT), str(fift_source)], cwd=ROOT, env=env, check=True)
        generated = boc.read_bytes()
        embedded_boc = tmp / "embedded.boc"
        embedded_boc.write_bytes(embedded)
        hash_script = tmp / "hashes.fif"
        hash_script.write_text(
            f'"{boc}" file>B B>boc hashu . cr "{embedded_boc}" file>B B>boc hashu . cr\n'
        )
        hashes = subprocess.run(
            [str(FIFT), str(hash_script)],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()

    if args.write:
        encoded = base64.b64encode(generated).decode("ascii")
        RUST.write_text(rust_source[: match.start(1)] + encoded + rust_source[match.end(1) :])
        ARTIFACT.write_text(encode_artifact(generated))
        print(f"Service Actor bytecode updated (repr_hash={hashes[0]})")
        return

    # BOC containers may legitimately differ in index/CRC flags; the root
    # cell representation hash is the bytecode identity used on chain.
    if len(hashes) != 2 or hashes[0] != hashes[1]:
        raise SystemExit(
            "Service Actor bytecode is stale: rebuild SERVICE_ACTOR_CODE_B64 "
            f"(generated {len(generated)} bytes, embedded {len(embedded)} bytes)"
        )
    # The release artifact is what the manifest pins, so its exact bytes count.
    if not ARTIFACT.is_file():
        raise SystemExit(f"Service Actor release artifact is missing: {ARTIFACT}")
    frozen = base64.b64decode(b"".join(ARTIFACT.read_bytes().split()), validate=True)
    if frozen != generated:
        raise SystemExit(
            "Service Actor release artifact is stale: the frozen artifact differs from the "
            f"rebuild (generated {len(generated)} bytes, frozen {len(frozen)} bytes)"
        )
    print(f"Service Actor bytecode synchronized (repr_hash={hashes[0]})")


if __name__ == "__main__":
    main()
