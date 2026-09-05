#!/usr/bin/env python3
"""Freeze CMake's PredictionMarket FunC output as a canonical base64 BOC."""

from __future__ import annotations

import argparse
import pathlib
import re


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("generated_cpp", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = args.generated_cpp.read_text(encoding="utf-8").strip()
    match = re.fullmatch(
        r'with_tvm_code\("prediction-market", "([A-Za-z0-9+/=]+)"\);', source
    )
    if match is None:
        raise SystemExit("generated C++ is not one canonical prediction-market embedding")
    expected = match.group(1) + "\n"
    current = args.output.read_text(encoding="ascii") if args.output.exists() else ""
    if args.check:
        if current != expected:
            raise SystemExit("frozen PredictionMarket BOC is stale")
        return
    args.output.write_text(expected, encoding="ascii")


if __name__ == "__main__":
    main()
