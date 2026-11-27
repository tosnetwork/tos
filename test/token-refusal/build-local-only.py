#!/usr/bin/env python3
"""Materialize a deliberately refusing wallet for local integration tests only.

No release file is written. The unchanged minter and bridge embed this wallet
when the caller compiles the private staging directory. Never deploy on a
public network. The wallet itself refuses execution outside global id 3.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

SOURCE_SHA256 = "4e0f79b01e4d385e9c72ffa228dfd1ec58b2295ff8773719ce670d4f1f2c4ca3"
TEST_WALLET_CODE_HASH = "cf5c98a11cf3de09b1cf702fa1eba38d870c822abb866320bba2da59dac013df"
REJECT_OWNER = hashlib.sha256(b"LOCAL-ONLY-TEST-REFUSAL-RECIPIENT-v1").hexdigest()
INTERNAL = (
    "() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {"
)
AUTH = """  throw_unless(error::unauthorized_incoming_transfer,
          equal_slices(calculate_user_token_wallet_address(from_address, w_master, w_code), sender_address));"""


def wallet_source(source):
    if hashlib.sha256(source.encode()).hexdigest() != SOURCE_SHA256:
        raise ValueError("production wallet source differs from the reviewed test base")
    if source.count(INTERNAL) != 1 or source.count("() receive_reported_tokens(") != 1:
        raise ValueError("refusal hook must match exactly once")
    source = source.replace(
        INTERNAL,
        'int local_test_global_id() asm "GLOBALID";\n'
        + INTERNAL
        + "\n  throw_unless(1979, local_test_global_id() == 3);",
    )
    prefix, separator, receiver = source.partition("() receive_reported_tokens(")
    return (
        prefix
        + separator
        + receiver.replace(
            AUTH,
            AUTH
            + "\n  ;; LOCAL ONLY: genuine receiver compute refusal, after sender authentication.\n  (int test_wc, int test_owner) = parse_std_addr(w_owner);\n  throw_if(1980, (test_wc == 0) & (test_owner == 0x"
            + REJECT_OWNER
            + "));",
            1,
        )
    )


def stage(root, output, global_id):
    if global_id != 3:
        raise ValueError("test wallet is restricted to local global id 3")
    if output.is_relative_to(root) or "local-only-test" not in output.name:
        raise ValueError(
            "test artifacts must stay in a named private local-only-test directory outside the checkout"
        )
    if output.exists():
        raise ValueError("output must be new; never overwrite a release or prior build")
    source = root / "crosschain/token-bridge/tvm/contracts"
    wallet = wallet_source((source / "token-wallet.fc").read_text())
    output.mkdir(parents=True, mode=0o700)
    for path in source.iterdir():
        if path.suffix in (".fc", ".fif") and path.name != "token-wallet.fc":
            shutil.copyfile(path, output / path.name)
    # A distinct source-chain slot leaves the existing test asset untouched.
    params = root / "crosschain/token-bridge/tvm/params"
    selected = [p for p in params.glob("*.fc") if "CONFIG_PARAM_ID = 81;" in p.read_text()]
    if len(selected) != 1:
        raise ValueError("expected one source-chain parameters file for slot 81")
    shutil.copyfile(selected[0], output / "params.fc")
    (output / "token-wallet-local-only-test.fc").write_text(wallet)
    # Existing bridge build scripts include this filename. It is only staged,
    # never installed in the source tree or published as a release artifact.
    (output / "token-wallet.fc").write_text(wallet)
    manifest = {
        "label": "LOCAL-ONLY-TEST-REFUSAL-v1",
        "global_id": 3,
        "production_wallet_source_sha256": SOURCE_SHA256,
        "refusal_exit": 1980,
        "wrong_network_exit": 1979,
        "reject_owner": "0:" + REJECT_OWNER,
        "wallet_source_sha256": hashlib.sha256(wallet.encode()).hexdigest(),
    }
    (output / "LOCAL-ONLY-TEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def verify_code_hash(actual):
    if actual != TEST_WALLET_CODE_HASH:
        raise ValueError("compiled test wallet code differs from its pinned real build")


def compile_wallet(root, output, func, fift):
    subprocess.run(
        [
            str(func),
            "-PS",
            "-o",
            "local-only-test-token-wallet.fif",
            "token-wallet-local-only-test.fc",
        ],
        cwd=output,
        check=True,
        capture_output=True,
        timeout=120,
    )
    script = output / "hash-local-only-test-token-wallet.fif"
    script.write_text(
        '"Asm.fif" include "local-only-test-token-wallet.fif" include hashu 256 u>B ." HASH " Bx. cr\n'
    )
    result = subprocess.run(
        [
            str(fift),
            "-I",
            f"{root / 'crypto/fift/lib'}:{root / 'crypto/smartcont'}:{output}",
            "-s",
            str(script),
        ],
        cwd=output,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    hashes = re.findall(r"HASH\s+(?:0x)?([0-9a-fA-F]{64})", result.stdout)
    if len(hashes) != 1:
        raise ValueError("test wallet compiler did not return exactly one code hash")
    actual = hashes[0].lower()
    verify_code_hash(actual)
    path = output / "LOCAL-ONLY-TEST.json"
    marker = json.loads(path.read_text())
    marker["wallet_code_hash"] = actual
    path.write_text(json.dumps(marker, indent=2) + "\n")
    return marker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--global-id", type=int, required=True)
    parser.add_argument("--func", type=Path, required=True)
    parser.add_argument("--fift", type=Path, required=True)
    args = parser.parse_args()
    root, output = args.source_root.resolve(), args.output.resolve()
    stage(root, output, args.global_id)
    print(json.dumps(compile_wallet(root, output, args.func.resolve(), args.fift.resolve())))


if __name__ == "__main__":
    main()
