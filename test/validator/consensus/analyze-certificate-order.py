#!/usr/bin/env python3
"""Count same-node SkipCert/NotarCert installation order in a consensus log."""

import argparse
import json
import re
from pathlib import Path


CERTIFICATE = re.compile(
    r"consensus\.(?P<node>\d+)\.(?P<instance>\d+)\.SimplexPool.*"
    r"Obtained certificate for (?:(?P<notar>NotarizeVote\{id=\{(?P<notar_slot>\d+))"
    r"|(?P<skip>SkipVote\{slot=(?P<skip_slot>\d+)))"
)


def summarize(path: Path) -> dict:
    first: dict[tuple[int, int, int], dict[str, int]] = {}
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        match = CERTIFICATE.search(line)
        if match is None:
            continue
        key = (
            int(match["node"]),
            int(match["instance"]),
            int(match["notar_slot"] or match["skip_slot"]),
        )
        kind = "notar" if match["notar"] else "skip"
        first.setdefault(key, {}).setdefault(kind, line_number)

    dual = {key: order for key, order in first.items() if len(order) == 2}
    skip_first = [key for key, order in dual.items() if order["skip"] < order["notar"]]
    notar_first = [key for key, order in dual.items() if order["notar"] < order["skip"]]
    return {
        "path": str(path),
        "node_slot_notar": sum("notar" in order for order in first.values()),
        "node_slot_skip": sum("skip" in order for order in first.values()),
        "node_slot_dual": len(dual),
        "skip_before_notar": len(skip_first),
        "notar_before_skip": len(notar_first),
        "skip_first_examples": [list(key) for key in sorted(skip_first)[:5]],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, nargs="+")
    args = parser.parse_args()
    print(json.dumps([summarize(path) for path in args.log], indent=2))


if __name__ == "__main__":
    main()
