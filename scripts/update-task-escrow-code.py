#!/usr/bin/env python3
"""Synchronize the Rust Task Escrow BOC with CMake's FunC output.

tosctl deploys Task Escrow from TASK_ESCROW_CODE_B64 and the sandbox tests run
it, so an edit to crypto/smartcont/task-escrow-code.fc reaches neither until
this constant is regenerated. Usage, after building the generated file
(ninja -C build crypto/smartcont/auto/task-escrow-code.cpp):

  update-task-escrow-code.py build/crypto/smartcont/auto/task-escrow-code.cpp \
      tosctl/src/node-control/contracts/src/task_escrow.rs [--check]
"""

from __future__ import annotations

import argparse
import pathlib
import re

CPP_PATTERN = re.compile(r'with_tvm_code\("task-escrow", "(?P<boc>[A-Za-z0-9+/=]+)"\);')
RUST_PATTERN = re.compile(r'pub const TASK_ESCROW_CODE_B64: &str = "[A-Za-z0-9+/=]+";')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("generated_cpp", type=pathlib.Path)
    parser.add_argument("rust_source", type=pathlib.Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    cpp = args.generated_cpp.read_text(encoding="utf-8")
    match = CPP_PATTERN.fullmatch(cpp.strip())
    if match is None:
        raise SystemExit("generated C++ is not one canonical task-escrow embedding")
    replacement = f'pub const TASK_ESCROW_CODE_B64: &str = "{match.group("boc")}";'

    source = args.rust_source.read_text(encoding="utf-8")
    updated, count = RUST_PATTERN.subn(replacement, source)
    if count != 1:
        raise SystemExit(f"expected exactly one Rust Task Escrow BOC constant, found {count}")
    if args.check:
        if updated != source:
            raise SystemExit("embedded Task Escrow BOC is stale")
        return
    args.rust_source.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
