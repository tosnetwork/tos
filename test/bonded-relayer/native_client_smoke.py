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
from native_process import NativeRPC, PinnedProgram, Unavailable  # noqa: E402
from relay_client import Client, ClientError  # noqa: E402
from relay_core import Refused, Release, encode  # noqa: E402
from tor_transport import TorProxy  # noqa: E402

NATIVE_REFUSAL = "native verification refused"


def native_refusal(error: BaseException) -> bool:
    """True only for the provider's own verification refusal, reached directly or as the
    cause of the client's wrapper. A crash, timeout, binding error (`Unavailable`) or any
    other refusal is not evidence that a signature or pin check refused."""
    for candidate in (error, error.__cause__):
        if (
            type(candidate) is Refused
            and str(candidate) == NATIVE_REFUSAL
            and not isinstance(candidate, Unavailable)
        ):
            return True
    return False


def check_native_refusal_predicate():
    # Negative controls: none of these may count as a native refusal.
    for name, cause in (
        ("unavailable", Unavailable("native response binding mismatch")),
        ("timeout", TimeoutError("native call deadline")),
        ("crash", RuntimeError("native process exited with signal 11")),
        ("other refusal", Refused("JSON outside byte bound")),
    ):
        wrapped = ClientError("quote authentication unavailable")
        wrapped.__cause__ = cause
        if native_refusal(cause) or native_refusal(wrapped):
            raise AssertionError(f"{name} would satisfy the native-refusal assertion")
    wrapped = ClientError("quote authentication unavailable")
    wrapped.__cause__ = Refused(NATIVE_REFUSAL)
    if not (native_refusal(Refused(NATIVE_REFUSAL)) and native_refusal(wrapped)):
        raise AssertionError("the native refusal itself is not recognized")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    check_native_refusal_predicate()
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
            except ClientError as error:
                if not native_refusal(error):
                    raise AssertionError("tampered quote failed for another reason") from error
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
                except Refused as error:
                    if not native_refusal(error):
                        raise AssertionError(
                            f"substituted {field} failed for another reason"
                        ) from error
                else:
                    raise AssertionError("real stdio verifier accepted substituted identity")
            if list(directory.iterdir()):
                raise AssertionError("public verifier accessed or created custody files")
        finally:
            program.close()
    print("PASS: real ELF identity/quote verification from empty custody; tampering refused")


if __name__ == "__main__":
    main()
