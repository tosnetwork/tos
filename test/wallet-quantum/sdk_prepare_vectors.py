"""Independent preparation wire vectors; synthetic witnesses/signatures test encoding only."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
from cells import Cell  # noqa: E402
from test_identity import chain  # noqa: E402
from test_preparation import request  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    cases = []
    for a, b in [(1, 1), (10**10, 2 * 10**10), (1 << 64, (1 << 120) - 1)]:
        plan = Cell().coins(a).coins(b)
        for i in (1, 2, 3):
            plan.ref(Cell().uint(i, 8))
        req = request(101, plan)
        submit = Cell().uint(0x46505233, 32).ref(req).ref(chain(bytes([0xA5]) * 7856))
        cases.append(
            dict(
                module_amount=str(a),
                vault_amount=str(b),
                request_hash=req.hash.hex(),
                submission_hash=submit.hash.hex(),
            )
        )
    args.output.write_text(json.dumps(cases, indent=2) + "\n")


if __name__ == "__main__":
    main()
