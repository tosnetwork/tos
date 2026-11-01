#!/usr/bin/env python3
"""Exercise the real public verifier ELF through the sealed Python stdio boundary."""

import argparse
import base64
import copy
import dataclasses
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from native_process import NativeRPC, PinnedProgram  # noqa: E402
from relay_client import Client, ClientError  # noqa: E402
from relay_core import Refused, Release, encode  # noqa: E402
from tor_transport import TorProxy  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_bytes())
    release = Release(**fixture["release"])
    binary = args.provider.resolve(strict=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory).resolve()
        program = PinnedProgram(binary, digest, directory)
        try:
            client = Client.from_bond(
                release,
                base64.b64decode(fixture["bond_init_b64"]),
                NativeRPC(program),
                tor=TorProxy(),
            )
            if client._verify(encode(fixture["envelope"])) != fixture["envelope"]["terms"]:
                raise AssertionError("real stdio verifier changed signed terms")
            changed = copy.deepcopy(fixture["envelope"])
            changed["terms"]["amount"] += 1
            try:
                client._verify(encode(changed))
            except ClientError:
                pass
            else:
                raise AssertionError("real stdio verifier accepted tampered quote")
            for field in ("bond_code_hash", "policy_hash", "worker_key_hash"):
                altered = dataclasses.replace(release, **{field: "aa" * 32})
                try:
                    Client.from_bond(
                        altered,
                        base64.b64decode(fixture["bond_init_b64"]),
                        NativeRPC(program),
                        tor=TorProxy(),
                    )
                except Refused:
                    pass
                else:
                    raise AssertionError("real stdio verifier accepted substituted identity")
            if list(directory.iterdir()):
                raise AssertionError("public verifier accessed or created custody files")
        finally:
            program.close()
    print("PASS: real ELF identity/quote verification from empty custody; tampering refused")


if __name__ == "__main__":
    main()
