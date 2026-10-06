"""Reproduce public native-mnemonic fee enrollment with independent KDF/tree code."""

import argparse
import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vector-index", type=int, default=1)
    parser.add_argument("--tree-id", default="a5" * 32)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/tos-native-mnemonic/tests/fixtures/native-pq.json"
    data = json.loads(source.read_text())
    assert 0 <= args.vector_index < len(data["vectors"]), "unknown public mnemonic vector"
    vector = data["vectors"][args.vector_index]
    context = data["context"]
    tree_id = bytes.fromhex(args.tree_id)
    assert len(tree_id) == 32, "tree ID must be 32 bytes"
    label = b"TOS-FEE-LMS-SHA256-M32-v1"
    info = bytes([1, len(label)]) + label + bytes.fromhex(context["network_hex"])
    info += context["global_id"].to_bytes(4, "big", signed=True)
    info += context["account_index"].to_bytes(4, "big")
    info += context["key_generation"].to_bytes(4, "big") + tree_id
    prk = hmac.digest(b"TOS-WALLET-DUALROOT-KDF-v1", bytes.fromhex(vector["master_hex"]), "sha256")
    t1 = hmac.digest(prk, info + b"\x01", "sha256")
    seed = (t1 + hmac.digest(prk, t1 + info + b"\x02", "sha256"))[:48]
    tree = args.output / "PUBLIC-TEST-ONLY-tree"
    command = [os.environ["LMS_TOOL"], "keygen", seed[:32].hex(), seed[32:].hex(), "20", str(tree)]
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=1200)
    key = bytes.fromhex(result.stdout.strip())
    nodes = tree.read_bytes()
    assert len(nodes) == 64 * 1024 * 1024
    assert key[28:] == nodes[32:64]
    index = 1 << 20
    path = bytearray()
    for _ in range(20):
        path.extend(nodes[(index ^ 1) * 32 : (index ^ 1) * 32 + 32])
        index >>= 1
    fixture = {
        "scope": "Public test mnemonic/master/fee seed only; never use for funds.",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "context": context,
        "phrase": vector["phrase"],
        "password": vector["password"],
        "master_hex": vector["master_hex"],
        "tree_id_hex": tree_id.hex(),
        "fee_seed_hex": seed.hex(),
        "public_key_hex": key.hex(),
        "leaf": 0,
        "path_hex": path.hex(),
        "public_tree_sha256": hashlib.sha256(nodes).hexdigest(),
    }
    (args.output / "native-fee-recovery.json").write_text(json.dumps(fixture, indent=2) + "\n")
    (args.output / "command.json").write_text(
        json.dumps({"command": command, "exit": result.returncode}, indent=2) + "\n"
    )
    print("Independent public fee recovery fixture generated")


if __name__ == "__main__":
    main()
