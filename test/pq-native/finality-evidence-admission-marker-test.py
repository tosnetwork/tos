#!/usr/bin/env python3
"""Prove every whitespace-insensitive admission marker fails when removed."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "scripts/check-finality-evidence-admission.sh"
FUNCTION = "require_whitespace_insensitive_marker"


def fail(message: str) -> None:
    print(f"FINALITY_ADMISSION_MARKER_MUTATION_FAILURE: {message}", file=sys.stderr)
    raise SystemExit(1)


def marker_contracts() -> list[tuple[str, str, str]]:
    logical_source = GUARD.read_text(encoding="utf-8").replace("\\\n", " ")
    contracts: list[tuple[str, str, str]] = []
    for line in logical_source.splitlines():
        if not line.startswith(f"{FUNCTION} "):
            continue
        tokens = shlex.split(line)
        if len(tokens) != 4:
            fail(f"could not parse marker declaration: {line}")
        contracts.append((tokens[1], tokens[2], tokens[3]))
    if len(contracts) != 16:
        fail(f"expected 16 whitespace-insensitive marker contracts, found {len(contracts)}")
    return contracts


def run_guard(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(GUARD), str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def whitespace_tolerant_pattern(marker: str) -> re.Pattern[str]:
    return re.compile(r"\s*".join(re.escape(character) for character in marker))


def main() -> int:
    contracts = marker_contracts()
    with tempfile.TemporaryDirectory(prefix="finality-admission-markers-") as temporary:
        fixture = Path(temporary)
        shutil.copytree(ROOT / "validator", fixture / "validator")
        baseline = run_guard(fixture)
        if baseline.returncode != 0:
            fail(f"baseline guard failed:\n{baseline.stderr}{baseline.stdout}")

        for relative, marker, description in contracts:
            path = fixture / relative
            original = path.read_text(encoding="utf-8")
            pattern = whitespace_tolerant_pattern(marker)
            matches = list(pattern.finditer(original))
            if len(matches) != 1:
                fail(
                    f"marker must identify exactly one property before mutation: "
                    f"{relative} marker={marker!r} matches={len(matches)}"
                )
            path.write_text(
                pattern.sub("/* removed by mutation gate */", original, count=1),
                encoding="utf-8",
            )
            mutated = run_guard(fixture)
            path.write_text(original, encoding="utf-8")
            expected = f"FINALITY_ADMISSION_SOURCE_FAILURE: {description} ({relative})"
            if mutated.returncode == 0:
                fail(f"removing {relative} marker {marker!r} left the guard green")
            if expected not in mutated.stderr:
                fail(
                    f"removing {relative} marker {marker!r} did not name its property; "
                    f"stderr={mutated.stderr!r}"
                )

    print(
        "FINALITY_ADMISSION_MARKER_MUTATION_OK: all 16 whitespace-insensitive markers "
        "failed by name when their guarded property was removed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
