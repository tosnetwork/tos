#!/usr/bin/env python3
"""Offline C04 PQ genesis fixture with the public test keys from Fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/tostester/src"))
from tostester.install import Install  # noqa: E402
from tostester.zerostate import NetworkConfig, PqInitialValidator, create_zerostate  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    install = Install(args.build_dir.resolve(), ROOT)
    descriptors = []
    public_rows = []
    with tempfile.TemporaryDirectory(prefix="c04-pq-seeds-") as raw:
        scratch = Path(raw)
        scratch.chmod(0o700)
        for i in range(4):
            seed = bytes([0x31 + i]) * 32
            key_path = scratch / f"validator-{i}.seed"
            proc = subprocess.run(
                [str(install.pq_consensus_key_exe), "import", str(key_path)],
                input=seed.hex() + "\n", text=True, capture_output=True, check=True,
            )
            key_id = re.search(r"^key_id\s+([0-9a-f]{64})$", proc.stdout, re.MULTILINE)
            public = re.search(r"^public\s+([0-9a-f]{2624})$", proc.stdout, re.MULTILINE)
            if key_id is None or public is None:
                raise RuntimeError("PQ key tool did not return key_id and public key")
            descriptor = PqInitialValidator(
                validator_id=hashlib.sha256(f"pq-finality-validator-{i}".encode()).digest(),
                key_id=bytes.fromhex(key_id.group(1)),
                public_key=bytes.fromhex(public.group(1)),
                adnl_id=hashlib.sha256(f"pq-finality-adnl-{i}".encode()).digest(),
            )
            descriptors.append(descriptor)
            public_rows.append({
                "index": i,
                "validator_id": descriptor.validator_id.hex(),
                "key_id": descriptor.key_id.hex(),
                "public_key_sha256": digest(descriptor.public_key),
                "adnl_id": descriptor.adnl_id.hex(),
                "genesis_weight": 17,
            })
    state_dir = out / "state"
    state_dir.mkdir(exist_ok=True)
    zero = create_zerostate(
        install, state_dir,
        NetworkConfig(global_id=-239, shard_validators=4),
        [], descriptors,
    )
    # The generated wallet key is unrelated to this public proof fixture.
    (state_dir / "main-wallet.pk").unlink(missing_ok=True)
    boc = zero.masterchain.file.read_bytes()
    metadata = {
        "source_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                                        capture_output=True, check=True).stdout.strip(),
        "global_id": -239,
        "masterchain_boc_sha256": digest(boc),
        "masterchain_boc_bytes": len(boc),
        "root_hash": zero.masterchain.root_hash.hex(),
        "file_hash": zero.masterchain.file_hash.hex(),
        "signers": public_rows,
    }
    (out / "fixture.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print("C04_REAL_GENESIS_OK root=" + metadata["root_hash"] + " boc_sha256=" + metadata["masterchain_boc_sha256"])


if __name__ == "__main__":
    main()
