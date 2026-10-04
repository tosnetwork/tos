#!/usr/bin/env python3
"""Rebuild a FunC contract and write its BOC into the Rust constant that embeds it.

tosctl deploys Dispute, Proof Attestation and Service Actor from base64
constants, and the sandbox suites run those constants, so an edit to the FunC
source reaches neither until the constant is regenerated. With --check the
script only compares root cell hashes and fails if the constant is stale.

Usage: update-embedded-contract-code.py [--check] [name ...]
FUNC and FIFT default to build/crypto/func and build/crypto/fift.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = {
    "dispute": ("crypto/smartcont/dispute-code.fc", "DISPUTE_CODE_B64",
                "tosctl/src/node-control/contracts/src/dispute.rs"),
    "proof-attestation": ("crypto/smartcont/proof-attestation-code.fc", "PROOF_ATTESTATION_CODE_B64",
                          "tosctl/src/node-control/contracts/src/proof_attestation.rs"),
    "service-actor": ("crypto/smartcont/service-actor-code.fc", "SERVICE_ACTOR_CODE_B64",
                      "tosctl/src/node-control/contracts/src/service_actor.rs"),
}


def tool(name: str) -> Path:
    path = Path(os.environ.get(name.upper(), ROOT / "build/crypto" / name))
    if not path.is_file():
        raise SystemExit(f"missing {name}: {path} (set {name.upper()})")
    return path


def compile_boc(source: Path, work: Path) -> bytes:
    fif, boc = work / "code.fif", work / "code.boc"
    subprocess.run([str(tool("func")), "-APS", str(ROOT / "crypto/smartcont/stdlib.fc"), str(source),
                    "-W", str(boc), "-o", str(fif)], cwd=ROOT, check=True)
    env = dict(os.environ, FIFTPATH=str(ROOT / "crypto/fift/lib"))
    subprocess.run([str(tool("fift")), str(fif)], cwd=ROOT, env=env, check=True)
    return boc.read_bytes()


def root_hash(boc: bytes, work: Path) -> str:
    path = work / "hash.boc"
    path.write_bytes(boc)
    script = work / "hash.fif"
    script.write_text(f'"{path}" file>B B>boc hashu . cr\n')
    env = dict(os.environ, FIFTPATH=str(ROOT / "crypto/fift/lib"))
    out = subprocess.run([str(tool("fift")), str(script)], cwd=ROOT, env=env, check=True,
                         capture_output=True, text=True)
    return out.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("names", nargs="*", default=sorted(CONTRACTS))
    args = parser.parse_args()
    stale = []
    for name in args.names:
        source, constant, rust = CONTRACTS[name]
        rust_path = ROOT / rust
        text = rust_path.read_text()
        pattern = re.compile(rf'pub const {constant}: &str = "(?P<b64>[A-Za-z0-9+/=]+)";')
        found = pattern.search(text)
        if not found:
            raise SystemExit(f"{constant} not found in {rust}")
        with tempfile.TemporaryDirectory(prefix="embedded-contract-") as raw:
            work = Path(raw)
            generated = compile_boc(ROOT / source, work)
            embedded = base64.b64decode(found.group("b64"), validate=True)
            same = root_hash(generated, work) == root_hash(embedded, work)
        if same:
            print(f"{name}: current")
            continue
        if args.check:
            stale.append(name)
            print(f"{name}: STALE ({constant} does not match {source})")
            continue
        encoded = base64.b64encode(generated).decode()
        rust_path.write_text(pattern.sub(f'pub const {constant}: &str = "{encoded}";', text, count=1))
        print(f"{name}: updated {constant}")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
