#!/usr/bin/env python3
"""Check the branch-CI-visible source half of PQ validator-set admission.

The contract sandbox tests prove behaviour. This guard keeps the two node-side
rules visible in the configure-only source-guard job on branch pushes too.
"""

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"CONFIG_VALIDATOR_SET_PARITY_FAILURE: {message}")


if len(sys.argv) != 2:
    fail("expected repository root argument")
root = Path(sys.argv[1])
contract = (root / "crypto/smartcont/config-code.fc").read_text()
node = (root / "crypto/block/mc-config.cpp").read_text()
quorum = (root / "tos/quorum.h").read_text()
sandbox = (root / "tosctl/src/node-control/contracts/tests/elector_sandbox.rs").read_text()
vector_file = root / "test/pq-native/validator-set-cases.txt"

match = re.search(r"\(int, int\) check_validator_set\(cell vset\) \{(.*?)\n\}", contract, re.S)
if not match:
    fail("check_validator_set body is absent")
body = match.group(1)

if "kMaxTotalValidatorWeight = UINT64_MAX / 3" not in quorum or "checked_add_validator_weight" not in node:
    fail("node validator-weight rule changed; compare the contract bound again")
if "seen_adnl_addrs.insert(adnl_addr)" not in node:
    fail("node ADNL uniqueness rule changed; compare the contract check again")

required = {
    "node's UINT64_MAX/3 weight bound": r"throw_if\(9,\s*total_weight\s*>\s*6148914691236517205\s*\)",
    "ADNL identity from parsed descriptor": r"pq::parse_descriptor\(descr\).*?adnl_addr\)",
    "ADNL uniqueness lookup": r"seen_adnl\.udict_get\?\(256,\s*adnl_addr\)",
    "duplicate-ADNL refusal": r"throw_if\(9,\s*duplicate_adnl\)",
    "remembered ADNL identity": r"seen_adnl~udict_set_builder\(256,\s*adnl_addr,\s*begin_cell\(\)\)",
}
for label, pattern in required.items():
    if not re.search(pattern, body, re.S):
        fail(f"check_validator_set no longer records {label}")

install = re.search(r"\(cell, int\) install_param\(cell cfg_dict, int param_id, cell param_val\) inline_ref \{(.*?)\n\}", contract, re.S)
if not install:
    fail("governance install_param body is absent")
install_body = install.group(1)
governance_checks = {
    "ConfigParams 34-37 route": r"param_id\s*>=\s*34.*?param_id\s*<=\s*37",
    "full PQ descriptor check": r"check_validator_set\(param_val\)",
    "consumed check result": r"valid\s*=\s*t_until\s*>\s*t_since",
    "refusal before install": r"ifnot\s*\(valid\).*?return\s*\(cfg_dict,\s*false\)",
}
for label, pattern in governance_checks.items():
    if not re.search(pattern, install_body, re.S):
        fail(f"governance install_param no longer records {label}")

vector_tests = (
    "node_validator_set_vectors_match_the_elector_install_path",
    "node_validator_set_vectors_match_the_governance_install_path",
)
for name in vector_tests:
    if not re.search(rf"#\[test\]\s*fn {name}\s*\(", sandbox):
        fail(f"shared node-vector sandbox test {name} is absent")
if "validator-set-cases.txt" not in sandbox or "read_single_root_boc" not in sandbox:
    fail("sandbox no longer decodes the shared node validator-set BOCs")
if not vector_file.exists():
    fail("shared node validator-set BOC table is absent")
rows = [line.split(maxsplit=2) for line in vector_file.read_text().splitlines()]
if len(rows) != 22 or any(len(row) != 3 for row in rows):
    fail(f"shared node validator-set BOC table has {len(rows)} rows, expected 22 complete rows")
required_cases = {
    "valid",
    "duplicate-validator-id",
    "duplicate-key-id",
    "duplicate-public-key",
    "duplicate-adnl",
    "key-id-mismatch",
    "unknown-algorithm",
    "short-key",
    "long-key",
    "malformed-key-encoding",
    "wrong-descriptor-tag",
    "descriptor-trailing-bit",
    "zero-validator-id",
    "zero-adnl",
    "zero-weight",
    "weight-over-protocol-cap",
    "declared-weight-mismatch",
    "zero-total-weight",
    "declared-count-mismatch",
    "index-gap",
    "zero-main-count",
    "main-exceeds-total",
}
actual_cases = {row[0] for row in rows}
if len(actual_cases) != len(rows) or actual_cases != required_cases:
    fail(
        "shared node validator-set case inventory changed: "
        f"missing={sorted(required_cases - actual_cases)} unexpected={sorted(actual_cases - required_cases)}"
    )
valid = [(name, verdict) for name, verdict, _ in rows if verdict == "accept"]
if valid != [("valid", "accept")]:
    fail(f"shared node validator-set BOC positive control changed: {valid}")

print("CONFIG_VALIDATOR_SET_PARITY_OK: Elector and governance record ADNL/weight rules; both sandbox tests decode the 22 shared node vectors")
