#!/usr/bin/env python3
"""Forbid treating a transport key hash as a validator identity."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


DIRECT_BITS_EXPRESSION = re.compile(
    r"\bValidatorId\s*[({][^;]{0,500}?bits256_value\s*\(", re.MULTILINE
)
BITS_ASSIGNMENT = re.compile(
    r"\b(?:auto|(?:td::)?Bits256)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"[^;]{0,500}?bits256_value\s*\([^;]*;",
    re.MULTILINE,
)
SOURCE_SUFFIXES = frozenset({".cpp", ".cc", ".cxx", ".h", ".hh", ".hpp"})

# A classical validator descriptor is born from an Ed25519 key hash. This one
# conversion is the protocol definition, not a membership lookup. Keep it exact
# so a second site cannot hide behind the exception.
CLASSICAL_DESCRIPTOR_SITE = Path("crypto/block/validator-set.cpp")


def violations(root: Path) -> list[str]:
    found: list[str] = []
    approved_classical_conversions = 0
    for source_root in (root / "validator", root / "crypto"):
        if not source_root.is_dir():
            raise RuntimeError(
                f"validator-id key-hash check failed: scan root does not exist: {source_root}"
            )
        for path in sorted(source_root.rglob("*")):
            if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
                continue
            text = path.read_text(errors="replace")
            for match in DIRECT_BITS_EXPRESSION.finditer(text):
                relative = path.relative_to(root)
                if (
                    relative == CLASSICAL_DESCRIPTOR_SITE
                    and "classical_validator_id(" in text[max(0, match.start() - 200) : match.start()]
                    and "compute_short_id()" in match.group(0)
                ):
                    approved_classical_conversions += 1
                    continue
                line = text.count("\n", 0, match.start()) + 1
                excerpt = " ".join(match.group(0).split())
                found.append(f"{relative}:{line}: direct expression: {excerpt}")
            for assignment in BITS_ASSIGNMENT.finditer(text):
                name = assignment.group("name")
                construction = re.compile(
                    r"\bValidatorId\s*[({]\s*"
                    + re.escape(name)
                    + r"\s*[)}]"
                ).search(text, assignment.end())
                if construction is None:
                    continue
                line = text.count("\n", 0, construction.start()) + 1
                found.append(
                    f"{path.relative_to(root)}:{line}: named bits256_value result "
                    f"'{name}' enters ValidatorId"
                )
    if approved_classical_conversions != 1:
        found.append(
            "classical validator-id conversion inventory changed: "
            f"expected=1 actual={approved_classical_conversions}"
        )
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    found = violations(args.root.resolve())
    if found:
        raise RuntimeError(
            "validator-id key-hash check failed: a transport key hash was constructed "
            "as ValidatorId; use local_consensus_descriptor so PQ custody decides "
            "membership:\n  "
            + "\n  ".join(found)
        )
    print(
        "validator-id key-hash check passed: no unapproved .bits256_value() or "
        "->bits256_value() expression, nor a named local assigned from one, enters a "
        "ValidatorId construction"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
