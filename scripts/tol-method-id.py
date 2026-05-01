#!/usr/bin/env python3
"""Compute Tol auto-derived public get-method ids.

Tol's auto-derived get method id is:

    crc16(method_name) | 0x10000

where crc16 is the same CCITT-style implementation exposed by
`"name".crc16()` in Tol and `td::crc16(..., init=0)` in the compiler.
"""

from __future__ import annotations

import argparse
import binascii
import json


def tol_method_id(name: str) -> int:
    return (binascii.crc_hqx(name.encode("utf-8"), 0) & 0xFFFF) | 0x10000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="+", help="Tol get-method name")
    parser.add_argument("--json", action="store_true", help="print JSON records")
    args = parser.parse_args()

    records = [
        {"name": name, "method_id": tol_method_id(name), "hex": f"0x{tol_method_id(name):x}"}
        for name in args.name
    ]
    if args.json:
        print(json.dumps(records, indent=2))
    else:
        for record in records:
            print(f"{record['name']} {record['method_id']} {record['hex']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
