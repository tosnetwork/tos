#!/usr/bin/env python3
"""Disposable three-validator RPC integration using public genesis allocations.

No wallet signing, key possession, release readiness or production admission claim.
The generated accounts contain synthetic public key bytes and receive test funds only.
"""

import argparse
import base64
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc  # noqa: E402


def chain(raw):
    result = None
    for offset in reversed(range(0, len(raw), 127)):
        next_cell = Cell().raw(raw[offset : offset + 127])
        if result is not None:
            next_cell.ref(result)
        result = next_cell
    return result


def fixtures(build, out):
    manifest = json.loads((build / "generated/explorer-pq-registry.json").read_text())
    assert manifest["quantum_wallet_network_tag"] == "42" * 32
    codes = {
        entry["family"]: from_boc((build / ("generated/" + entry["family"] + ".boc")).read_bytes())
        for entry in manifest["codes"]
    }
    public_key = bytes((i % 256 for i in range(1312)))
    namespace = int("42" * 32, 16)
    module = (
        Cell()
        .uint(1, 8)
        .sint(1, 32)
        .uint(namespace, 256)
        .uint(1, 8)
        .uint(456, 256)
        .uint(2, 8)
        .ref(chain(public_key))
    )
    module_init = Cell().uint(6, 5).ref(codes["quantum_module_v1"]).ref(module)
    fee_key = Cell().uint(1, 32).uint(8, 32).uint(3, 32).uint(0, 384)
    fee = (
        Cell()
        .uint(1, 8)
        .uint(1, 8)
        .uint(0, 256)
        .uint(1700000000, 32)
        .uint(3600, 32)
        .uint(4, 16)
        .ref(fee_key)
    )
    auth = (
        Cell()
        .uint(4, 8)
        .uint(2, 2)
        .uint(2, 16)
        .uint(2**64 - 1, 64)
        .uint(42, 64)
        .uint(43, 64)
        .ref(module_init)
        .ref(fee)
    )
    wallet = (
        Cell().uint(0, 1).uint(2**32 - 1, 32).uint(2**32 - 1, 32).uint(0, 256).uint(0, 1).ref(auth)
    )
    wallet_init = Cell().uint(6, 5).ref(codes["quantum_wallet_v4"]).ref(wallet)
    wallet_hash = int.from_bytes(wallet_init.hash, "big")
    module_hash = int.from_bytes(module_init.hash, "big")
    prefix = (
        Cell()
        .uint(0x41553252, 32)
        .sint(1, 32)
        .uint(namespace, 256)
        .addr((0, wallet_hash))
        .uint(module_hash, 256)
        .uint(2, 8)
    )
    parties = Cell().addr((0, wallet_hash)).uint(module_hash, 256)
    vault = (
        Cell()
        .uint(3, 8)
        .uint(1048576, 32)
        .uint(123, 256)
        .uint(1700000000, 32)
        .addr((0, module_hash))
        .uint(int.from_bytes(parties.hash, "big"), 256)
        .ref(fee_key)
        .ref(prefix)
    )
    high = (
        Cell()
        .uint(123, 32)
        .uint(0, 2)
        .uint(2**64 - 1, 64)
        .uint(3600, 22)
        .ref(Cell().uint(1312, 32).ref(chain(public_key)))
    )
    states = {
        "quantum_module_v1": module,
        "quantum_wallet_v4": wallet,
        "quantum_fee_vault_v3": vault,
        "pq_highload_mldsa44_v1": high,
        "mldsa44_auth_module_v1": Cell().sint(1, 32).ref(chain(public_key)),
        "falcon512_padded_auth_module_v1": Cell().sint(1, 32).uint(1, 16).ref(chain(bytes(897))),
    }
    # Additional active contracts exercise unknown-code and malformed recognized-code semantics.
    unknown = Cell().uint(1, 1)
    extras = {
        "unknown_code": (unknown, module),
        "malformed_module": (codes["mldsa44_auth_module_v1"], Cell().uint(1, 1)),
    }
    script = [
        '"Fift.fif" include',
        '"TosUtil.fif" include',
        '"State.fif" include',
        "0 setworkchain",
        "1 setglobalid",
    ]
    addresses = {}
    for name, (code, data) in list(
        (name, (codes[name], data)) for name, data in states.items()
    ) + list(extras.items()):
        code_path, data_path = out / (name + "-code.boc"), out / (name + "-data.boc")
        code_path.write_bytes(code.boc())
        data_path.write_bytes(data.boc())
        state_init = Cell().uint(6, 5).ref(code).ref(data)
        addresses[name] = "0:" + state_init.hash.hex()
        script += [
            f'"{code_path}" file>B B>boc',
            f'"{data_path}" file>B B>boc',
            "empty_cell 1000000000000 0 0 2 register_smc",
            f'0x{state_init.hash.hex()} = not abort"fixture address mismatch"',
        ]
    script.append('create_state 31 boc+>B "basestate0.boc" B>file')
    script_path = out / "accounts.fif"
    script_path.write_text("\n".join(script) + "\n")
    with (out / "genesis-build.log").open("w") as log:
        subprocess.run(
            [
                str(build / "crypto/create-state"),
                "-n",
                "-I",
                str(ROOT / "crypto/fift/lib") + ":" + str(ROOT / "crypto/smartcont"),
                "-s",
                str(script_path),
            ],
            cwd=out,
            stdout=log,
            stderr=log,
            check=True,
            timeout=30,
        )
    return addresses


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rpc-port", type=int, default=48545)
    parser.add_argument("--base-port", type=int, default=44000)
    parser.add_argument("--legacy-config", action="store_true")
    args = parser.parse_args()
    build, out = args.build_dir.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    attempts = out / ("attempt-" + str(time.time_ns()))
    attempts.mkdir()
    out = attempts
    addresses = {} if args.legacy_config else fixtures(build, out)
    (out / "addresses.json").write_text(json.dumps(addresses, indent=2) + "\n")
    records = []

    def request(method, params, *, rest=False, node=0, expected=200):
        body = params if rest else {"jsonrpc": "2.0", "id": 7, "method": method, "params": params}
        data = json.dumps(body).encode()
        url = f"http://127.0.0.1:{args.rpc_port + node}/" + (method if rest else "jsonRPC")
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    url, data=data, headers={"Content-Type": "application/json"}
                ),
                timeout=35,
            ) as response:
                status, raw = response.status, response.read(17 << 20)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(17 << 20)
        value = json.loads(raw)
        records.append(
            {
                "method": method,
                "params": params,
                "rest": rest,
                "node": node,
                "http_status": status,
                "response_bytes": len(raw),
                "response_sha256": hashlib.sha256(raw).hexdigest(),
                "response": value,
            }
        )
        assert status == expected, (method, status, value.get("error"), value.get("error_info"))
        return value

    env = dict(os.environ, TOS_BUILD_DIR=str(build), PYTHONUNBUFFERED="1")
    env.pop("TOS_GLOBAL_VERSION", None)
    env.pop("TOS_AUTH_NETWORK_TAG", None)
    command = [
        sys.executable,
        str(ROOT / "scripts/localnet-jsonrpc.py"),
        "--validators",
        "3",
        "--workdir",
        str(out / "network"),
        "--rpc",
        f"127.0.0.1:{args.rpc_port}",
        "--control",
        f"127.0.0.1:{args.rpc_port + 200}",
        "--base-port",
        str(args.base_port),
        "--boot-timeout",
        "180",
    ]
    if not args.legacy_config:
        command.extend(
            ["--quantum-admission-candidate", "--basechain-fixture", str(out / "basestate0.boc")]
        )
    with (out / "network.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True
        )
        try:
            deadline = time.monotonic() + 180
            while True:
                if process.poll() is not None:
                    raise RuntimeError(
                        f"localnet exited {process.returncode}; see {out / 'network.log'}"
                    )
                try:
                    ids = [
                        request("getMasterchainInfo", {}, node=node)["result"]["last"]
                        for node in range(3)
                    ]
                    if min(value["seqno"] for value in ids) >= 3:
                        break
                except (OSError, AssertionError, KeyError):
                    pass
                assert time.monotonic() < deadline, "three-validator startup timeout"
                time.sleep(0.5)
            seqno = min(value["seqno"] for value in ids) - 1
            # Resolve a historic full ID from the existing header endpoint.
            signature = request(
                "getMasterchainBlockSignatures", {"seqno": seqno, "with_proof": True}
            )["result"]
            block = signature["id"]
            assert signature["verification"]["status"] == "node_verified"
            assert signature["verification"]["scope"] == "anchored_finality"
            assert 2 <= len(signature["signatures"]) <= 3
            assert signature["session_id"] == signature["verification"]["expected_session_id"]
            assert int(signature["verification"]["verified_weight"]) >= int(
                signature["verification"]["quorum_threshold"]
            )
            for node in range(3):
                same = request(
                    "getMasterchainBlockSignatures", {"block_id": block}, rest=True, node=node
                )["result"]
                assert (
                    same["id"] == block and same["signing_payload"] == signature["signing_payload"]
                )
                assert "proof" not in same
            fork = dict(block, file_hash=base64.b64encode(bytes(32)).decode())
            wrong = request("getMasterchainBlockSignatures", {"block_id": fork}, expected=409)
            assert wrong["error_info"]["reason"] == "BLOCK_ID_MISMATCH"
            # Pin one newer observation so the basechain genesis is available everywhere.
            observation = request("getMasterchainInfo", {})["result"]["last"]
            for name, address in addresses.items():
                params = {
                    "address": address,
                    "block_id": observation,
                    "include_pq": True,
                    "with_proof": True,
                }
                if name == "malformed_module":
                    bad = request("getAccountCapability", params, expected=500)
                    assert bad["error_info"]["reason"] == "STATE_INVALID"
                    continue
                first = request("getAccountCapability", params)["result"]
                second = request("getWalletInformation", params, rest=True)["result"]
                pq = first["pq_authorization"]
                assert pq == second["pq_authorization"]
                assert pq["state_verified"] is True
                assert pq["observed_masterchain_block"] == observation
                assert (pq["recognition"] == "unknown_code") == (name == "unknown_code")
                if name != "unknown_code":
                    assert pq["code_family"] == name and pq["public_state"]["kind"] == name
                # Default classification still uses the original path.
                legacy = request(
                    "getAccountCapability", {"address": address, "seqno": observation["seqno"]}
                )["result"]
                assert "pq_authorization" not in legacy
            absent_account = request(
                "getAccountCapability",
                {"address": "0:" + "0" * 64, "block_id": observation, "include_pq": True},
            )["result"]["pq_authorization"]
            assert (
                absent_account["recognition"] == "no_active_code"
                and absent_account["public_state"] is None
            )
            for param in (8, 43, 47, 48):
                typed = request(
                    "getConfigParam",
                    {
                        "param": param,
                        "block_id": observation,
                        "include_decoded": True,
                        "with_proof": True,
                    },
                )["result"]
                same = request(
                    "getConfigParam",
                    {"param": param, "block_id": observation, "include_decoded": True},
                    rest=True,
                )["result"]
                assert typed["decoded"] == same["decoded"]
                assert typed["decoded"]["observation"]["vm_version"] == (
                    16 if args.legacy_config else 18
                )
                assert typed["decoded"]["observation"]["block_id"] == observation
            if args.legacy_config:
                absent_policy = request(
                    "getConfigParam",
                    {"param": 48, "block_id": observation, "include_decoded": True},
                )["result"]
                assert (
                    absent_policy["decoded"]["presence"] == "absent"
                    and absent_policy["decoded"]["value"] is None
                )
                request(
                    "getConfigParam", {"param": 48, "seqno": observation["seqno"]}, expected=500
                )
            # The current generated TL store writes a bare blockIdExt and a
            # count-prefixed bare vector. Pin Config 8 to compare exact replies.
            query_bytes = struct.pack(
                "<Iiiqi",
                589251042,
                0x10000,
                observation["workchain"],
                int(observation["shard"]),
                observation["seqno"],
            )
            query_bytes += base64.b64decode(observation["root_hash"]) + base64.b64decode(
                observation["file_hash"]
            )
            query_bytes += struct.pack("<ii", 1, 8)
            query = base64.b64encode(query_bytes).decode()
            first = request("getProofQuery", {"query": query})["result"]
            second = request("getProofQuery", {"query": query}, rest=True)["result"]
            assert first == second and base64.b64decode(first["reply"], validate=True)

        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
            (out / "rpc-evidence.json").write_text(json.dumps(records, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": "passed",
                "requests": len(records),
                "evidence": str(out / "rpc-evidence.json"),
            }
        )
    )


if __name__ == "__main__":
    main()
