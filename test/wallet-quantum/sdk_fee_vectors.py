"""Independent fee wire vectors; public synthetic signatures test framing only."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
from cells import Cell  # noqa: E402
from test_identity import chain  # noqa: E402
from test_pop import challenge as pop  # noqa: E402
from test_preparation import request as prepare  # noqa: E402
from test_receiver_auth import request as auth  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    cases = []
    for kind, value in [
        (1, 5_000_000_000),
        (2, 5_000_000_000),
        (3, 50_000_000_000),
        (1, (1 << 120) - 1),
    ]:
        if kind == 1:
            req = auth(role=2, body=Cell().uint(0x45584543, 32).ref(Cell()))
        elif kind == 2:
            req = pop(101, 111, 222, role=2, policy=2)
        else:
            plan = Cell().coins(10**10).coins(2 * 10**10)
            for i in (1, 2, 3):
                plan.ref(Cell().uint(i, 8))
            req = prepare(101, plan)
        payload = (
            Cell()
            .uint({1: 0x53554233, 2: 0x50505333, 3: 0x46505233}[kind], 32)
            .ref(req)
            .ref(chain(bytes([0xA5]) * 7856))
        )
        intent = (
            Cell()
            .uint(0x46454534, 32)
            .raw(b"TOS-RESCUE-FEE-v1")
            .uint(kind, 8)
            .addr((0, 103))
            .uint(104, 256)
            .uint(8, 32)
            .uint(1_780_000_600, 32)
            .coins(value)
            .ref(payload)
        )
        sig = bytearray([0xA5] * 2832)
        for offset, word in [(0, 0), (4, 8), (8, 3), (2188, 8)]:
            sig[offset : offset + 4] = word.to_bytes(4, "big")
        external = Cell().ref(intent).ref(chain(sig))
        cases.append(
            dict(
                kind=kind,
                value=str(value),
                intent_hash=intent.hash.hex(),
                external_hash=external.hash.hex(),
            )
        )
    args.output.write_text(json.dumps(cases, indent=2) + "\n")


if __name__ == "__main__":
    main()
