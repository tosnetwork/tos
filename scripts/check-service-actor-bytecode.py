#!/usr/bin/env python3
"""Rebuild Service Actor and fail unless its BOC equals the Rust constant."""

import base64
import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FUNC = Path(os.environ.get("FUNC", ROOT / "build-remove-workchains-full/crypto/func"))
FIFT = Path(os.environ.get("FIFT", ROOT / "build-remove-workchains-full/crypto/fift"))
SOURCE = ROOT / "crypto/smartcont/service-actor-code.fc"
STDLIB = ROOT / "crypto/smartcont/stdlib.fc"
RUST = ROOT / "tosctl/src/node-control/contracts/src/service_actor.rs"


def main() -> None:
    for tool in (FUNC, FIFT):
        if not tool.is_file():
            raise SystemExit(f"missing compiler tool: {tool} (set FUNC/FIFT to override)")
    match = re.search(
        r'pub const SERVICE_ACTOR_CODE_B64: &str = "([A-Za-z0-9+/=]+)";',
        RUST.read_text(),
    )
    if not match:
        raise SystemExit("SERVICE_ACTOR_CODE_B64 was not found in Rust source")
    embedded = base64.b64decode(match.group(1), validate=True)

    with tempfile.TemporaryDirectory(prefix="service-actor-bytecode-") as raw_tmp:
        tmp = Path(raw_tmp)
        fift_source = tmp / "service-actor.fif"
        boc = tmp / "service-actor.boc"
        subprocess.run(
            [str(FUNC), "-APS", str(STDLIB), str(SOURCE), "-W", str(boc), "-o", str(fift_source)],
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
            f'"{boc}" file>B B>boc hashu . cr '
            f'"{embedded_boc}" file>B B>boc hashu . cr\n'
        )
        hashes = subprocess.run(
            [str(FIFT), str(hash_script)], cwd=ROOT, env=env, check=True,
            capture_output=True, text=True,
        ).stdout.split()

    # BOC containers may legitimately differ in index/CRC flags; the root
    # cell representation hash is the bytecode identity used on chain.
    if len(hashes) != 2 or hashes[0] != hashes[1]:
        raise SystemExit(
            "Service Actor bytecode is stale: rebuild SERVICE_ACTOR_CODE_B64 "
            f"(generated {len(generated)} bytes, embedded {len(embedded)} bytes)"
        )
    print(f"Service Actor bytecode synchronized (repr_hash={hashes[0]})")


if __name__ == "__main__":
    main()
