"""Regenerate independent wire vectors; byte-filled signatures are framing fixtures only."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
from cells import Cell  # noqa: E402
from test_identity import chain  # noqa: E402
from test_receiver_auth import request  # noqa: E402
from test_rescue_e2e import digest  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    items = []
    for role, kind, replacement in [
        (1, 0, False),
        (2, 0, False),
        (2, 1, False),
        (2, 1, True),
        (2, 3, False),
        (2, 4, False),
    ]:
        body = Cell().uint({0: 0x45584543, 1: 0x434F4E46, 3: 0x4C4F434B, 4: 0x4D494752}[kind], 32)
        if kind == 0:
            body.ref(Cell())
        elif kind == 1:
            body.uint(2, 2).maybe(
                Cell().ref(Cell().uint(1, 8)).ref(Cell().uint(2, 8)) if replacement else None
            )
        elif kind == 3:
            body.uint(1, 8)
        elif kind == 4:
            for i in range(1, 4):
                body.ref(Cell().uint(i, 8))
        req = request(role=role, kind=kind, body=body)
        signature = bytes([0xA5]) * (2420 if role == 1 else 7856)
        submit = Cell().uint(0x53554233, 32).ref(req).ref(chain(signature))
        items.append(
            dict(
                role=role,
                kind=kind,
                replacement=replacement,
                request_hash=req.hash.hex(),
                digest=digest(req).hex(),
                submission_hash=submit.hash.hex(),
            )
        )
    args.output.write_text(json.dumps(items, indent=2) + "\n")


if __name__ == "__main__":
    main()
