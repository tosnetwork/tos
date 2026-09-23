#!/usr/bin/env python3
"""Keep signed Simplex ancestry separate from Pool's proposal-base selection."""

from pathlib import Path
import re
import sys


def fail(reason: str) -> None:
    print(f"SIMPLEX_EXACT_ANCESTOR_FAILURE: {reason}", file=sys.stderr)
    raise SystemExit(1)


root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
for name in ("bus.h", "bus.cpp", "pool.cpp", "state-resolver.cpp"):
    source = (root / "validator/consensus/simplex" / name).read_text()
    for forbidden in ("QuerySlotSkipped", "SkippedSlotResolution", "select_skipped_slot_resolution"):
        if forbidden in source:
            fail(f"{name} retains unsafe {forbidden}")

resolver = (root / "validator/consensus/simplex/state-resolver.cpp").read_text()
start = re.search(r"td::actor::Task<ResolvedState>\s+resolve_state_inner\(ParentId id\)\s*\{", resolver)
if start is None:
    fail("resolve_state_inner not found")
end = resolver.find("// ===== Block finalization =====", start.end())
if end < 0:
    fail("resolve_state_inner boundary not found")
body = resolver[start.start():end]
if not re.search(r"publish<ResolveCandidate>\(\*id\)\.wrap\(\)", body):
    fail("exact candidate resolution is not fail-closed")
if "available_base" in body:
    fail("exact ancestry substitutes available_base")
if "cannot resolve exact ancestor" not in body:
    fail("exact resolution diagnostic missing")
if not re.search(r"candidate->id\s*!=\s*\*id", body):
    fail("resolved candidate id is not checked")

candidate_resolver = (root / "validator/consensus/simplex/candidate-resolver.cpp").read_text()
for required in ("DEFAULT_CANDIDATE_RESOLVE_MAX_ATTEMPTS = 16", "TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS"):
    if required not in candidate_resolver:
        fail(f"candidate resolution retry bound missing: {required}")

print("SIMPLEX_EXACT_ANCESTOR_OK")
