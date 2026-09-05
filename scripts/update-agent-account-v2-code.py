#!/usr/bin/env python3
"""Synchronize the Rust Agent Account V2 BOC with CMake's FunC output."""

from __future__ import annotations

import argparse
import pathlib
import re


CPP_PATTERN = re.compile(
    r'with_tvm_code\("agent-account", "(?P<boc>[A-Za-z0-9+/=]+)"\);'
)
RUST_PATTERN = re.compile(
    r'pub const AGENT_ACCOUNT_V2_CODE_B64: &str = "[A-Za-z0-9+/=]+";'
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("generated_cpp", type=pathlib.Path)
    parser.add_argument("rust_source", type=pathlib.Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    cpp = args.generated_cpp.read_text(encoding="utf-8")
    match = CPP_PATTERN.fullmatch(cpp.strip())
    if match is None:
        raise SystemExit("generated C++ is not one canonical agent-account embedding")
    replacement = f'pub const AGENT_ACCOUNT_V2_CODE_B64: &str = "{match.group("boc")}";'

    source = args.rust_source.read_text(encoding="utf-8")
    updated, count = RUST_PATTERN.subn(replacement, source)
    if count != 1:
        raise SystemExit(f"expected exactly one Rust V2 BOC constant, found {count}")
    if args.check:
        if updated != source:
            raise SystemExit("embedded Agent Account V2 BOC is stale")
        return
    args.rust_source.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
