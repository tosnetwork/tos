#!/usr/bin/env python3
"""Keep tostester's config-contract data cell aligned with production Genesis."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
EXPECTED_DATA = "<bconfigdictref,dictnewdict,b>"
EXPECTED_LOADER = (
    "varcs=get_data().begin_parse();"
    "varres=(cs~load_ref(),cs~load_dict());"
    "cs.end_parse();returnres;"
)


def fail(message: str) -> None:
    raise SystemExit(f"CONFIG_GENESIS_DATA_LAYOUT_FAILURE: {message}")


def code_without_comments(value: str) -> str:
    return re.sub(r"\s+", "", re.sub(r"//[^\n]*|;;[^\n]*", "", value))


def genesis_data(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    section = source.split('"auto/config-code.fif" include', 1)
    if len(section) != 2:
        fail(f"{path}: missing config-code include")
    match = re.search(r"<b\s+configdict\s+ref,[\s\S]*?b>\s*//\s*data", section[1])
    if match is None:
        fail(f"{path}: missing config-contract data cell")
    return code_without_comments(match.group(0).split("b>", 1)[0] + "b>")


production = ROOT / "crypto/smartcont/gen-zerostate.fif"
harness = ROOT / "test/tostester/src/tostester/zerostate.py"
for path in (production, harness):
    actual = genesis_data(path)
    if actual != EXPECTED_DATA:
        fail(f"{path.relative_to(ROOT)} config data differs: expected={EXPECTED_DATA} actual={actual}")

contract = ROOT / "crypto/smartcont/config-code.fc"
source = contract.read_text(encoding="utf-8")
match = re.search(r"\(cell,\s*cell\)\s+load_data\(\)\s+inline\s*\{([^}]*)\}", source)
if match is None:
    fail("config-code.fc load_data() definition is missing")
actual_loader = code_without_comments(match.group(1))
if actual_loader != EXPECTED_LOADER:
    fail(f"config-code.fc load_data() changed: expected={EXPECTED_LOADER} actual={actual_loader}")

print("CONFIG_GENESIS_DATA_LAYOUT_OK: production and harness data match load_data()")
