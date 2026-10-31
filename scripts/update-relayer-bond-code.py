#!/usr/bin/env python3
"""Reproduce the BR1 code identity from this checkout's FunC sources."""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import from_boc  # noqa: E402

SOURCE = ROOT / "crypto/smartcont/relayer-bond-code.fc"
ARTIFACT = ROOT / "crypto/smartcont/relayer-bond-v1.boc.base64"
MANIFEST = ROOT / "crypto/smartcont/relayer-bond-v1.release.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="br1-release-") as directory:
        d = Path(directory)
        asm, boc = d / "bond.fif", d / "bond.boc"
        subprocess.run(
            [
                os.environ.get("FUNC_PATH", str(ROOT / "build/crypto/func")),
                "-SPA",
                "-o",
                str(asm),
                str(ROOT / "crypto/smartcont/stdlib.fc"),
                str(SOURCE),
            ],
            check=True,
            capture_output=True,
        )
        runner = d / "run.fif"
        runner.write_text(
            f'"Asm.fif" include\n"PQ.fif" include\n"{asm}" include\n2 boc+>B "{boc}" B>file\n'
        )
        subprocess.run(
            [
                os.environ.get("FIFT_PATH", str(ROOT / "build/crypto/fift")),
                "-I",
                f"{ROOT}/crypto/fift/lib:{ROOT}/crypto/smartcont",
                "-s",
                str(runner),
            ],
            check=True,
            capture_output=True,
        )
        data = boc.read_bytes()
    files = [
        "crypto/smartcont/relayer-bond-code.fc",
        "crypto/smartcont/pq-bytes.fc",
        "crypto/smartcont/pq.fc",
        "crypto/smartcont/stdlib.fc",
        "crypto/fift/lib/PQ.fif",
    ]
    manifest = dict(
        schema="tos.relayer-bond.code.v1",
        activation_approved=False,
        code_hash=from_boc(data).hash.hex(),
        boc_sha256=hashlib.sha256(data).hexdigest(),
        boc_bytes=len(data),
        source_sha256={p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in files},
    )
    outputs = {
        ARTIFACT: base64.b64encode(data).decode() + "\n",
        MANIFEST: json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    }
    for path, text in outputs.items():
        if args.check:
            if not path.exists() or path.read_text() != text:
                raise SystemExit(f"stale code release: {path.relative_to(ROOT)}")
        else:
            path.write_text(text)
    print(json.dumps({"code_hash": manifest["code_hash"], "reproduced": True}))


if __name__ == "__main__":
    main()
