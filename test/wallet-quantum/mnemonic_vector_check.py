"""Independently check public native mnemonic -> master -> PQ seed fixtures."""

import hashlib
import hmac
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tosctl/src/tos-native-mnemonic/tests/fixtures/native-pq.json"


def main():
    root = json.loads(FIXTURE.read_text())
    context = root["context"]
    suffix = (
        bytes.fromhex(context["network_hex"])
        + context["global_id"].to_bytes(4, "big", signed=True)
        + context["account_index"].to_bytes(4, "big")
        + context["key_generation"].to_bytes(4, "big")
    )
    count = 0
    for vector in root["vectors"]:
        phrase = " ".join(vector["phrase"].lower().split())
        entropy = hmac.digest(phrase.encode(), vector["password"].encode(), "sha512")
        assert (
            hashlib.pbkdf2_hmac("sha512", entropy, b"TOS seed version", 100_000 // 256, 64)[0] == 0
        )
        master = hashlib.pbkdf2_hmac("sha512", entropy, b"TOS default seed", 100_000, 64)[:32]
        assert master.hex() == vector["master_hex"]
        prk = hmac.digest(b"TOS-WALLET-DUALROOT-KDF-v1", master, "sha256")
        for label, size in [(b"ML-DSA-44", 32), (b"SLH-DSA-SHA2-128s", 48)]:
            info = bytes([1, len(label)]) + label + suffix
            last, output = b"", b""
            for index in range(1, 3):
                last = hmac.digest(prk, last + info + bytes([index]), "sha256")
                output += last
            assert output[:size].hex() == vector["derived"][label.decode()]
            count += 1
    assert len(root["vectors"]) == 2 and count == 4
    print("Two native mnemonic/master vectors and four PQ seed vectors match Python hashlib/hmac")


if __name__ == "__main__":
    main()
