"""Independent POP framing vectors; byte-filled signatures are not valid signatures."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
from cells import Cell  # noqa: E402
from test_identity import chain  # noqa: E402
from test_pop import challenge  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    vectors = []
    for role in (1, 2):
        for policy in (1, 2):
            req = challenge(101, 111, 222, role=role, policy=policy)
            digest = Cell().raw(b"TOS-POP1").ref(req).hash
            sig = bytes([0xA5]) * (2420 if role == 1 else 7856)
            sub = Cell().uint(0x50505333, 32).ref(req).ref(chain(sig))
            vectors.append(
                dict(
                    role=role,
                    policy=policy,
                    request_hash=req.hash.hex(),
                    digest=digest.hex(),
                    submission_hash=sub.hash.hex(),
                )
            )
    args.output.write_text(json.dumps(vectors, indent=2) + "\n")


if __name__ == "__main__":
    main()
