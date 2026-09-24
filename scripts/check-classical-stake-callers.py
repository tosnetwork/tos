#!/usr/bin/env python3
"""Inventory retained literal Fift election-tool dependencies.

This is deliberately narrower than "all classical stake producers": it
discovers references to the two base Fift tools and their library word in
source files, including the retained test-only codec. Rust legacy vectors
and prose are not callers.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

MARKERS = (
    "validator-elect-req.fif",
    "validator-elect-signed.fif",
    "validator-legacy-elect-req.fif",
    "validator-legacy-elect-signed.fif",
    "ValidatorLegacy.fif",
    "validator-elect-req>B",
    "single-nominator-legacy-elect-signed.fif",
    "liquid-controller-legacy-elect-signed.fif",
)
EXPECTED: dict[str, dict[str, int]] = {
    "crypto/test/fift/fixtures/ValidatorLegacy.fif": {
        "validator-elect-req>B": 1,
    },
    "crypto/test/fift/fixtures/single-nominator-legacy-elect-signed.fif": {
        "ValidatorLegacy.fif": 1,
        "validator-elect-req>B": 1,
    },
    "crypto/test/fift/fixtures/liquid-controller-legacy-elect-signed.fif": {
        "ValidatorLegacy.fif": 1,
        "validator-elect-req>B": 1,
    },
    "crypto/test/fift/fixtures/validator-legacy-elect-req.fif": {
        "ValidatorLegacy.fif": 1,
        "validator-elect-req>B": 1,
    },
    "crypto/test/fift/fixtures/validator-legacy-elect-signed.fif": {
        "ValidatorLegacy.fif": 1,
        "validator-elect-req>B": 1,
    },
    "crypto/test/fift/validator-proposal-invalid-signature.fif": {"ValidatorLegacy.fif": 1},
    "crypto/test/fift.cpp": {"ValidatorLegacy.fif": 2},
    "crypto/test/test-smartcont.cpp": {
        "ValidatorLegacy.fif": 2,
        "validator-legacy-elect-req.fif": 1,
        "validator-legacy-elect-signed.fif": 1,
        "single-nominator-legacy-elect-signed.fif": 1,
        "liquid-controller-legacy-elect-signed.fif": 1,
    },
}
SUFFIXES = {".py", ".fif", ".fc", ".cpp", ".rs"}
# This source guard quotes the retired Fift filenames to forbid their use in
# Stage A; it is not an executable Fift caller. Exclude only this known guard
# so an unrelated new script containing the literal still fails the inventory.
NON_CALLER_SOURCE_GUARDS = {
    "scripts/check-pq-election-fixture-source.py",
    # This guard quotes the retired names only to forbid them in the
    # multi-nominator lifecycle route; it does not invoke either Fift tool.
    "scripts/check-nominator-pool-pq-route.py",
}


def fail(message: str) -> None:
    raise RuntimeError(f"CLASSICAL_STAKE_CALLERS_FAILURE: {message}")


def discover(root: Path) -> dict[str, dict[str, int]]:
    found = {}
    for directory in ("crypto", "scripts", "tosctl/src"):
        for path in (root / directory).rglob("*"):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            if relative == "scripts/check-classical-stake-callers.py" or relative in NON_CALLER_SOURCE_GUARDS:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            matches = {}
            for marker in MARKERS:
                # A test-local `legacy-validator-elect-req>B` is not a call to
                # the product `validator-elect-req>B` word.
                count = (
                    len(re.findall(r"(?<![A-Za-z0-9_-])validator-elect-req>B", source))
                    if marker == "validator-elect-req>B"
                    else source.count(marker)
                )
                if count:
                    matches[marker] = count
            if matches:
                found[relative] = matches
    return found


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[1]
    retired_operator = root / "crypto/smartcont/single-nominator-pool/validator-elect-signed.fif"
    if retired_operator.exists():
        fail("retired single-nominator Ed25519 operator script is still executable")
    retired_liquid_operator = root / "crypto/smartcont/liquid-staking/controller-elect-signed.fif"
    if retired_liquid_operator.exists():
        fail("retired liquid-staking Ed25519 operator script is still packaged")
    retired_base_request = root / "crypto/smartcont/validator-elect-req.fif"
    if retired_base_request.exists():
        fail("retired base Ed25519 request script is still packaged")
    retired_base_signed = root / "crypto/smartcont/validator-elect-signed.fif"
    if retired_base_signed.exists():
        fail("retired base Ed25519 signed-body script is still packaged")
    if (root / "crypto/fift/lib/Validator.fif").exists():
        fail("retired classical Validator.fif library is still packaged")
    fift_loader = (root / "crypto/fift/utils.cpp").read_text(encoding="utf-8")
    if '"/Validator.fif"' in fift_loader or "load_Validator_fif" in fift_loader:
        fail("memory Fift loader still preloads the retired product Validator.fif")
    for directory in ("crypto/smartcont", "scripts", "tosctl/src"):
        for path in (root / directory).rglob("*"):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            if path.name == "check-classical-stake-callers.py":
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"(?<![A-Za-z0-9_-])validator-elect-body(?:\+stake)?(?![A-Za-z0-9_+])", source):
                fail(f"product source regained a classical validator-elect body word: {path.relative_to(root)}")
    smartcont_test = (root / "crypto/test/test-smartcont.cpp").read_text(encoding="utf-8")
    base_request_fixture = "test/fift/fixtures/validator-legacy-elect-req.fif"
    base_signed_fixture = "test/fift/fixtures/validator-legacy-elect-signed.fif"
    for fixture in (base_request_fixture, base_signed_fixture):
        if smartcont_test.count(fixture) != 1:
            fail(f"test-smartcont no longer loads exactly one test-only {fixture}")
    legacy_fixture = "test/fift/fixtures/single-nominator-legacy-elect-signed.fif"
    if smartcont_test.count(legacy_fixture) != 1:
        fail("test-smartcont no longer loads exactly one test-only single-nominator legacy fixture")
    liquid_fixture = "test/fift/fixtures/liquid-controller-legacy-elect-signed.fif"
    if smartcont_test.count(liquid_fixture) != 1:
        fail("test-smartcont no longer loads exactly one test-only liquid-controller legacy fixture")
    proposal_smoke = (root / "crypto/test/fift/validator-proposal-test.fif").read_text(encoding="utf-8")
    if '"Proposal.fif" include' not in proposal_smoke or "proposal-query-id" not in proposal_smoke:
        fail("proposal smoke no longer exercises the Proposal.fif helper")
    if '"Validator.fif" include' in proposal_smoke or any(
        marker in proposal_smoke
        for marker in ("validator-elect-req>B", "validator-elect-body", "parse-val-pubkey", "parse-val-signature")
    ):
        fail("proposal smoke has regained a classical validator-stake dependency")
    parity = (root / "crypto/test/fift/validator-proposal-legacy-parity.fif").read_text(encoding="utf-8")
    if '"Validator.fif" include' in parity or re.search(r"(?<![A-Za-z0-9_-])validator-elect-req>B", parity):
        fail("legacy parity has regained the product Validator.fif stake codec")
    for word in (
        "legacy-parse-val-signature",
        "legacy-validator-elect-req>B",
        "legacy-validator-elect-body",
        "legacy-validator-elect-body+stake",
    ):
        uses = re.findall(rf"(?<![A-Za-z0-9_-]){re.escape(word)}(?![A-Za-z0-9_+])", parity)
        if sum(line.strip() == f"}} : {word}" for line in parity.splitlines()) != 1 or len(uses) < 2:
            fail(f"legacy parity no longer defines and exercises its test-local {word} codec")
    actual = discover(root)
    missing = sorted(set(EXPECTED) - set(actual))
    unexpected = sorted(set(actual) - set(EXPECTED))
    wrong = {
        path: {"expected": EXPECTED[path], "actual": actual[path]}
        for path in sorted(set(EXPECTED) & set(actual))
        if actual[path] != EXPECTED[path]
    }
    if missing or unexpected or wrong:
        fail(f"literal Fift caller inventory changed: missing={missing} unexpected={unexpected} wrong={wrong}")
    document = (root / "doc/pq-native/T2-PQ-LAUNCH-GATE-MIGRATION.md").read_text()
    undocumented = sorted(path for path in EXPECTED if f"`{path}`" not in document)
    if undocumented:
        fail(f"retained literal Fift callers absent from migration map: {undocumented}")
    print(
        f"CLASSICAL_STAKE_CALLERS_OK: {len(EXPECTED)} exact source files retain the inventoried "
        "validator-elect Fift path/word literals; the single-nominator operator path is absent, "
        "both retired pool operator paths, both base election scripts, and product Validator.fif are absent; "
        "no scanned product .py/.fif/.fc/.cpp/.rs source names a classical stake body word; "
        "the base Fift byte tests load test-only "
        "fixtures, proposal smoke has no classical stake dependency, the parity codec is test-local, "
        "and the migration map names each"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
