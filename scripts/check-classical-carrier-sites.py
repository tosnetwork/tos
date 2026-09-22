#!/usr/bin/env python3
"""Keep the classical finality-carrier inventory equal to the source tree."""

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
MANIFEST = ROOT / "test" / "pq-native" / "classical-carrier-sites.tsv"
SELF = Path(__file__).resolve()
SOURCE_SUFFIXES = {".cpp", ".h", ".hpp", ".rs", ".tl", ".ts"}
EXCLUDED_PARTS = {".git", "build", "target"}
STATUSES = {"definition", "historical", "placeholder", "reachable"}

# These named markers cover the C++ factories/codecs, persisted TL-B tags,
# node/lite TL variants, generic production consumers, and Rust carrier paths.
# Occurrences rather than lines are counted so checked-in generated sources
# cannot hide two carrier sites on one minified line.
MARKERS = {
    "cpp_factory": re.compile(
        r"\bBlockSignatureSet::create_(?:ordinary|simplex(?:_approve)?)\s*\("
    ),
    "cpp_fetch": re.compile(r"\bBlockSignatureSet::fetch\s*\("),
    "verify": re.compile(r"\bcheck_(?:approve_)?signatures\s*\("),
    "cpp_class": re.compile(r"\bBlockSignatureSet(?:Ordinary|Simplex)\b"),
    "tlb_tag": re.compile(r"\bblock_signatures(?:_simplex)?#1[12]\b"),
    "node_tl": re.compile(r"\btosNode\.signatureSet\.(?:ordinary|simplex)\b"),
    "lite_tl": re.compile(r"\bliteServer\.signatureSet\.(?:ordinary|simplex)\b"),
    "cpp_node_tl": re.compile(r"\btosNode_signatureSet_(?:ordinary|simplex)\b"),
    "cpp_lite_tl": re.compile(r"\bliteServer_signatureSet_(?:ordinary|simplex)\b"),
    "rust_generated_tl": re.compile(
        r"\b(?:TosNode|LiteServer)_SignatureSet_(?:Ordinary|Simplex)\b"
    ),
    "rust_variant": re.compile(r"\bBlockSignaturesVariant::(?:Ordinary|Simplex)\b"),
    "rust_simplex": re.compile(r"\bBlockSignaturesSimplex\b"),
    "rust_ordinary": re.compile(
        r"\bBlockSignatures::(?:new|default|with_params|construct_from|read_from|write_to)\b"
    ),
    "rust_tag": re.compile(r"\bBLOCK_SIGNATURES(?:_SIMPLEX)?_TAG\b"),
    "raw_tag_write": re.compile(
        r"^(?![^\n]*block_signatures)[^\n]*\bstore_long_bool\b[^\n]*\b0x(?:11|12)\b", re.MULTILINE
    ),
    "carrier_io": re.compile(
        r"\b(?:sig_set|sig_set_|signatures|signatures_)->(?:serialize|tl|tl_lite)\s*\("
    ),
}


def tracked_files() -> tuple[set[str], list[str]]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        return set(), [f"classical-carrier check failed: cannot enumerate tracked files: {detail}"]
    return set(result.stdout.decode(errors="surrogateescape").split("\0")) - {""}, []


def actual_sites(tracked: set[str]) -> Counter[tuple[str, str]]:
    result: Counter[tuple[str, str]] = Counter()
    for relative in sorted(tracked):
        path = ROOT / relative
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if path == SELF or path == MANIFEST or any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        text = path.read_text(errors="replace")
        for marker, pattern in MARKERS.items():
            count = sum(1 for _ in pattern.finditer(text))
            if count:
                result[(relative, marker)] = count
    return result


def declared_sites(tracked: set[str]) -> tuple[dict[tuple[str, str], int], list[str]]:
    if not MANIFEST.is_file():
        return {}, [f"classical-carrier check failed: missing inventory {MANIFEST}"]
    declared: dict[tuple[str, str], int] = {}
    errors: list[str] = []
    for line_no, raw in enumerate(MANIFEST.read_text().splitlines(), start=1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t", 4)
        if len(fields) != 5:
            errors.append(f"classical-carrier check failed: malformed inventory row {line_no}")
            continue
        file, marker, count_text, status, _why = fields
        if file not in tracked:
            errors.append(f"classical-carrier check failed: {file} is not tracked by git")
        key = (file, marker)
        if marker != "*" and marker not in MARKERS:
            errors.append(f"classical-carrier check failed: {file} has unknown marker {marker}")
        if key in declared:
            errors.append(
                f"classical-carrier check failed: duplicate inventory row for {file} {marker}"
            )
            continue
        if status not in STATUSES:
            errors.append(f"classical-carrier check failed: {file} has unknown status {status}")
        try:
            declared[key] = int(count_text)
        except ValueError:
            errors.append(
                f"classical-carrier check failed: {file} has invalid site count {count_text}"
            )
    return declared, errors


def main() -> int:
    tracked, errors = tracked_files()
    actual = actual_sites(tracked)
    declared, declared_errors = declared_sites(tracked)
    errors.extend(declared_errors)

    # This disk-manager helper used to manufacture a tosNode_sessionId with a
    # zero config hash and had no callers. It was not a validator-session
    # derivation; keep the misleading dead entry point retired.
    for relative in ("validator/manager-disk.cpp", "validator/manager-disk.hpp"):
        if "get_validator_set_id" in (ROOT / relative).read_text():
            errors.append(
                f"classical-carrier check failed: dead disk-manager session helper returned in {relative}"
            )

    covered: set[tuple[str, str]] = set()
    for (file, marker), expected_count in declared.items():
        if marker == "*":
            matching = {key: count for key, count in actual.items() if key[0] == file}
            found = sum(matching.values()) if matching else None
            covered.update(matching)
        else:
            found = actual.get((file, marker))
            covered.add((file, marker))
        if found is None:
            errors.append(
                f"classical-carrier check failed: {file} no longer contains marker {marker}; "
                "update the inventory"
            )
        elif found != expected_count:
            errors.append(
                f"classical-carrier check failed: {file} marker {marker} has {found} sites, "
                f"inventory says {expected_count}"
            )

    for (file, marker), count in sorted(actual.items()):
        if (file, marker) not in covered:
            errors.append(
                f"classical-carrier check failed: {file} contains unlisted marker {marker} ({count} sites) "
                "and is not in the inventory"
            )

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"classical-carrier inventory matches the tree: entries={len(actual)} sites={sum(actual.values())}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
