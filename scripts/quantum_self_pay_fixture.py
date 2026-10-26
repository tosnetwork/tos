"""Public self-pay accounts for an isolated candidate chain, never production keys."""

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

from pytosiq_core import Builder
from pytosiq_core.boc.deserialize import Boc

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = bytes.fromhex("42" * 32)
GLOBAL_ID = 1


def source_commit():
    # Container checkout ownership can differ from the executing user. Trust
    # only the checkout whose harness is already executing, for this read alone.
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT}", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        timeout=10,
    ).strip()


def require(value, message):
    if not value:
        raise ValueError(message)


def quoted(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def one_cell(encoded):
    roots = Boc(encoded).deserialize()
    require(len(roots) == 1, "single root required")
    cell = roots[0]
    require(not cell.is_exotic and cell.level_mask.mask == 0, "ordinary root required")
    return cell


def byte_chain(value):
    require(0 < len(value) <= 1312, "public key byte length")
    tail = None
    for offset in reversed(range(0, len(value), 127)):
        builder = Builder().store_bytes(value[offset : offset + 127])
        if tail is not None:
            builder.store_ref(tail)
        tail = builder.end_cell()
    return tail


def accounts(code, primary, rescue):
    require(len(primary) == 1312 and len(rescue) == 32, "public key lengths")
    authority = (
        Builder()
        .store_uint(1, 8)
        .store_int(GLOBAL_ID, 32)
        .store_bytes(NAMESPACE)
        .store_uint(1, 8)
        .store_ref(byte_chain(primary))
        .store_bytes(rescue)
        .store_uint(1, 8)
        .end_cell()
    )
    result = {}
    for wallet_id, (name, status, balance) in enumerate(
        [
            ("active", "active", 10**15),
            ("prefunded", "uninitialized", 10**10),
            ("absent", "absent", 0),
        ]
    ):
        data = (
            Builder()
            .store_uint(1, 8)
            .store_uint(0, 32)
            .store_uint(wallet_id, 32)
            .store_uint(0, 16)
            .store_uint(0, 64)
            .store_uint(0, 64)
            .store_uint(0, 64)
            .store_ref(authority)
            .end_cell()
        )
        state_init = Builder().store_uint(6, 5).store_ref(code).store_ref(data).end_cell()
        identity = (
            Builder()
            .store_uint(0x51534931, 32)
            .store_bytes(state_init.hash)
            .store_ref(state_init)
            .end_cell()
        )
        result[name] = {
            "wallet_id": wallet_id,
            "status": status,
            "balance": balance,
            "address": "0:" + state_init.hash.hex(),
            "data_hash": data.hash.hex(),
            "data_boc": base64.b64encode(data.to_boc()).decode(),
            "state_init_boc": base64.b64encode(state_init.to_boc()).decode(),
            "identity_boc": base64.b64encode(identity.to_boc()).decode(),
        }
    return result


def compile_wallet(build, out):
    asm = out / "wallet.fif"
    code = out / "wallet.boc"
    subprocess.run(
        [
            str(build / "crypto/func"),
            "-SPA",
            "-o",
            str(asm),
            str(ROOT / "crypto/smartcont/stdlib.fc"),
            str(ROOT / "crypto/smartcont/wallet-quantum-self-pay.fc"),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    runner = out / "wallet.run.fif"
    runner.write_text(
        '"Asm.fif" include\n' + quoted(asm) + " include\n2 boc+>B " + quoted(code) + " B>file\n"
    )
    subprocess.run(
        [
            str(build / "crypto/fift"),
            "-I",
            str(ROOT / "crypto/fift/lib"),
            "-s",
            str(runner),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return one_cell(code.read_bytes())


def build_fixture(public_input, build, out):
    require(not out.exists(), "fresh output required")
    vector_bytes = public_input.read_bytes()
    vector = json.loads(vector_bytes)
    if vector["schema"] == "tos-quantum-self-pay-v1":
        require(
            vector["primary_seed"] == "11" * 32 and vector["rescue_seed"] == "22" * 48,
            "public deterministic test keys required",
        )
    else:
        require(vector["schema"] == "tos-quantum-self-pay-genesis-v1", "self-pay input schema")
        require(
            vector["global_id"] == GLOBAL_ID and vector["namespace"] == NAMESPACE.hex(),
            "isolated candidate network required",
        )
    out.mkdir(parents=True)
    code = compile_wallet(build, out)
    require(code.hash.hex() == vector["wallet_code_hash"], "source/vector code mismatch")
    require(
        code.hash == one_cell(base64.b64decode(vector["wallet_code"], validate=True)).hash,
        "vector code mismatch",
    )
    primary = bytes.fromhex(vector["primary_key"])
    rescue = bytes.fromhex(vector["rescue_key"])
    records = accounts(code, primary, rescue)
    if vector["schema"] == "tos-quantum-self-pay-genesis-v1":
        require(records == vector["accounts"], "frozen public identities differ from regeneration")
    lines = [
        '"Fift.fif" include',
        '"TosUtil.fif" include',
        '"State.fif" include',
        "0 setworkchain",
        "1 setglobalid",
    ]
    for name, record in records.items():
        data_path = out / (name + "-data.boc")
        data_path.write_bytes(base64.b64decode(record["data_boc"], validate=True))
        mode = {"active": 2, "uninitialized": 1, "absent": 0}[record["status"]]
        lines.extend(
            [
                quoted(out / "wallet.boc") + " file>B B>boc",
                quoted(data_path) + " file>B B>boc",
                f"empty_cell {record['balance']} 0 0 {mode} register_smc",
                f'0x{record["address"].split(":")[1]} = not abort"self-pay address mismatch"',
            ]
        )
    lines.append('create_state 31 boc+>B "basestate0.boc" B>file')
    script = out / "basechain.fif"
    script.write_text("\n".join(lines) + "\n")
    with (out / "create-state.log").open("w") as log:
        subprocess.run(
            [
                str(build / "crypto/create-state"),
                "-n",
                "-I",
                str(ROOT / "crypto/fift/lib") + ":" + str(ROOT / "crypto/smartcont"),
                "-s",
                str(script),
            ],
            cwd=out,
            check=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    fixture = {
        "schema": "tos-quantum-self-pay-genesis-v1",
        "scope": "PUBLIC TEST ONLY; genesis allocation is not deployment or custody acceptance",
        "global_id": GLOBAL_ID,
        "namespace": NAMESPACE.hex(),
        "wallet_code": base64.b64encode(code.to_boc()).decode(),
        "wallet_code_hash": code.hash.hex(),
        "primary_key": primary.hex(),
        "rescue_key": rescue.hex(),
        "accounts": records,
        "provenance": {
            "source_commit": source_commit(),
            "public_input_sha256": hashlib.sha256(vector_bytes).hexdigest(),
            "public_input_schema": vector["schema"],
            "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "binaries": {
                name: hashlib.sha256((build / "crypto" / name).read_bytes()).hexdigest()
                for name in ("func", "fift", "create-state")
            },
        },
    }
    (out / "public-self-pay-accounts.json").write_text(json.dumps(fixture, indent=2) + "\n")
    return fixture


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", required=True, type=Path, help="Public vectors or frozen genesis fixture"
    )
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    build_fixture(args.input.resolve(), args.build_dir.resolve(), args.out.resolve())
