#!/usr/bin/env python3
"""Static use-after-move guard.

Several defects in this tree are evaluation-order or moved-from-state bugs that the
shipped compiler happens to get right, so a behavioural test built with it cannot go
red for them. This guard runs clang-tidy over a pinned set of files instead.

Each pass names one check, a pinned file list and a pinned header filter. Before the
pass's verdict is trusted, a positive control is run with exactly the pass's flags and
must produce exactly the expected diagnostics: a pass whose check, header filter or
tool is silently broken therefore fails instead of reporting a clean tree.

The guard fails closed on an empty list, a listed file missing from
compile_commands.json, a missing tool, a translation unit that does not parse, a
control with the wrong diagnostic count or any exit status but the expected one, a
timeout, a production run with any exit status but 0 (whatever it printed), and an
unreviewed suppression comment.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

CONTROL_DIR = "test/static-analysis"
# clang-tidy's exit status when --warnings-as-errors promotes a finding. A control must
# end with exactly this status; a clean production run must end with 0.
CONTROL_EXIT = 1
CONTROL_HEADER_PATTERN = CONTROL_DIR + r"/[^/]+\.h"


@dataclass(frozen=True)
class Control:
    source: str
    # Expected diagnostics as (path relative to the source dir, count).
    expected: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class Pass:
    name: str
    check: str
    list_file: str
    control: Control


PASSES = (
    Pass(
        name="A",
        check="bugprone-use-after-move",
        list_file="scripts/use-after-move-guard-files.txt",
        control=Control(
            source=f"{CONTROL_DIR}/use-after-move-control.cpp",
            expected=(
                (f"{CONTROL_DIR}/use-after-move-control.cpp", 1),
                (f"{CONTROL_DIR}/use-after-move-control.h", 1),
            ),
        ),
    ),
    Pass(
        name="B",
        check="clang-analyzer-cplusplus.Move",
        list_file="scripts/analyzer-move-guard-files.txt",
        control=Control(
            source=f"{CONTROL_DIR}/analyzer-move-control.cpp",
            expected=((f"{CONTROL_DIR}/analyzer-move-control.cpp", 1),),
        ),
    ),
)

DIAGNOSTIC_RE = re.compile(
    r"^(?:(?P<file>[^\n]+?):(?P<line>\d+):(?P<col>\d+): )?"
    r"(?P<severity>warning|error): (?P<message>.*) \[(?P<checks>[^\]]+)\]$"
)
NOLINT_RE = re.compile(r"NOLINT(?P<kind>NEXTLINE|BEGIN|END)?(?P<args>\([^)]*\))?")


class GuardError(Exception):
    pass


@dataclass
class Diagnostic:
    file: str
    line: int
    col: int
    severity: str
    message: str
    check: str

    def render(self) -> str:
        where = f"{self.file}:{self.line}:{self.col}" if self.file else "<no location>"
        return f"{where}: {self.severity}: {self.message} [{self.check}]"


@dataclass
class ListEntry:
    path: str
    suppressions: int


@dataclass
class TidyResult:
    target: str
    returncode: int
    diagnostics: list[Diagnostic] = field(default_factory=list)
    output: str = ""


def posix_ere_escape(text: str) -> str:
    # clang-tidy compiles the header filter as a POSIX extended regular expression.
    return re.sub(r"([.\[\]()*+?{}|^$\\])", r"\\\1", text)


def read_list(source_dir: Path, list_file: str) -> list[ListEntry]:
    path = source_dir / list_file
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GuardError(f"cannot read {list_file}: {error}") from error
    entries: list[ListEntry] = []
    seen: set[str] = set()
    for number, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        suppressions = 0
        for extra in parts[1:]:
            match = re.fullmatch(r"suppressions=(\d+)", extra)
            if match is None:
                raise GuardError(f"{list_file}:{number}: unknown field {extra!r}")
            suppressions = int(match.group(1))
        rel = parts[0]
        if rel in seen:
            raise GuardError(f"{list_file}:{number}: {rel} is listed twice")
        seen.add(rel)
        if not (source_dir / rel).is_file():
            raise GuardError(f"{list_file}:{number}: {rel} does not exist")
        entries.append(ListEntry(rel, suppressions))
    if not any(entry.path.endswith(".cpp") for entry in entries):
        raise GuardError(f"{list_file} lists no translation unit; an empty pass proves nothing")
    return entries


def header_filter(source_dir: Path, headers: list[str]) -> str:
    alternatives = [posix_ere_escape(header) for header in headers]
    alternatives.append(CONTROL_HEADER_PATTERN)
    return f"^{posix_ere_escape(str(source_dir))}/({'|'.join(alternatives)})$"


def load_compile_database(build_dir: Path) -> set[str]:
    path = build_dir / "compile_commands.json"
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise GuardError(f"cannot read {path}: {error}") from error
    files: set[str] = set()
    for entry in entries:
        files.add(os.path.realpath(os.path.join(entry["directory"], entry["file"])))
    return files


def parse_diagnostics(output: str, source_dir: Path) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for raw in output.splitlines():
        match = DIAGNOSTIC_RE.match(raw.strip())
        if match is None:
            continue
        file = match.group("file") or ""
        if file:
            resolved = Path(os.path.realpath(file))
            try:
                file = str(resolved.relative_to(source_dir))
            except ValueError:
                file = str(resolved)
        diagnostics.append(
            Diagnostic(
                file=file,
                line=int(match.group("line") or 0),
                col=int(match.group("col") or 0),
                severity=match.group("severity"),
                message=match.group("message"),
                check=match.group("checks").split(",")[0],
            )
        )
    return diagnostics


def run_tidy(
    command: list[str], target: str, timeout: float, source_dir: Path, cwd: Path
) -> TidyResult:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise GuardError(f"clang-tidy timed out after {timeout:g} s on {target}") from None
    return TidyResult(target, process.returncode, parse_diagnostics(output, source_dir), output)


def tidy_command(tidy: str, check: str, filter_regex: str) -> list[str]:
    return [
        tidy,
        "--config={}",
        f"--checks=-*,{check}",
        f"--header-filter={filter_regex}",
        f"--warnings-as-errors={check}",
        "--quiet",
    ]


def unanalysed(result: TidyResult, check: str) -> list[str]:
    """Errors from anything but the pass's check: the unit was not (fully) analysed."""
    return [
        f"{result.target}: not analysed: {diagnostic.render()}"
        for diagnostic in result.diagnostics
        if diagnostic.check != check and diagnostic.severity == "error"
    ]


def judge(result: TidyResult, check: str) -> list[str]:
    """Every problem a production run shows. Clean means exit 0 and no finding at all.

    Any other exit status is a failure even when the run printed something that parses
    as a diagnostic: an unrelated warning followed by a crash is not a clean unit.
    """
    problems = unanalysed(result, check)
    for diagnostic in result.diagnostics:
        if diagnostic.check == check:
            problems.append(f"use after move: {diagnostic.render()}")
    if result.returncode != 0:
        tail = "\n".join(result.output.strip().splitlines()[-5:])
        problems.append(f"{result.target}: clang-tidy exited {result.returncode}:\n{tail}")
    return problems


def run_control(
    tidy: str, guard_pass: Pass, filter_regex: str, source_dir: Path, timeout: float
) -> list[str]:
    control = guard_pass.control
    command = tidy_command(tidy, guard_pass.check, filter_regex)
    command += [
        str(source_dir / control.source),
        "--",
        "-std=c++20",
        f"-I{source_dir / CONTROL_DIR}",
    ]
    result = run_tidy(command, control.source, timeout, source_dir, source_dir)
    problems = unanalysed(result, guard_pass.check)
    found: dict[str, int] = {}
    for diagnostic in result.diagnostics:
        if diagnostic.check == guard_pass.check:
            found[diagnostic.file] = found.get(diagnostic.file, 0) + 1
    expected = dict(control.expected)
    if found != expected or result.returncode != CONTROL_EXIT:
        problems.append(
            f"pass {guard_pass.name} control {control.source}: expected {expected} "
            f"{guard_pass.check} diagnostics and exit {CONTROL_EXIT}, got {found} "
            f"(exit {result.returncode})"
        )
    else:
        print(
            f"pass {guard_pass.name} control: {sum(found.values())} {guard_pass.check} "
            f"diagnostics as expected in {', '.join(sorted(found))}"
        )
    return problems


def audit_suppressions(source_dir: Path, entries: list[ListEntry], check: str) -> list[str]:
    problems = []
    for entry in entries:
        text = (source_dir / entry.path).read_text(encoding="utf-8", errors="replace")
        reviewed = 0
        for number, line in enumerate(text.splitlines(), 1):
            for match in NOLINT_RE.finditer(line):
                kind = match.group("kind") or ""
                args = match.group("args")
                where = f"{entry.path}:{number}"
                if kind in ("BEGIN", "END"):
                    problems.append(f"{where}: NOLINT{kind} is not allowed in a guarded file")
                    continue
                if args is None:
                    problems.append(f"{where}: NOLINT{kind} without a check name")
                    continue
                names = [name.strip() for name in args[1:-1].split(",") if name.strip()]
                if not any(fnmatch.fnmatchcase(check, name) for name in names):
                    continue
                if kind == "NEXTLINE" and names == [check]:
                    reviewed += 1
                else:
                    problems.append(f"{where}: {match.group(0)} suppresses {check} too broadly")
        if reviewed != entry.suppressions:
            problems.append(
                f"{entry.path}: {reviewed} NOLINTNEXTLINE({check}) comments, "
                f"the reviewed count is {entry.suppressions}"
            )
    return problems


def check_header_users(source_dir: Path, entries: list[ListEntry]) -> list[str]:
    units = [e.path for e in entries if e.path.endswith(".cpp")]
    problems = []
    for header in (e.path for e in entries if not e.path.endswith(".cpp")):
        include = f'#include "{Path(header).name}"'
        users = [u for u in units if include in (source_dir / u).read_text(encoding="utf-8")]
        if not users:
            problems.append(f"{header}: no listed translation unit includes it")
    return problems


def run_pass(
    guard_pass: Pass,
    source_dir: Path,
    build_dir: Path,
    database: set[str],
    tidy: str,
    jobs: int,
    timeout: float,
) -> list[str]:
    entries = read_list(source_dir, guard_pass.list_file)
    headers = [e.path for e in entries if not e.path.endswith(".cpp")]
    units = [e.path for e in entries if e.path.endswith(".cpp")]
    filter_regex = header_filter(source_dir, headers)
    print(f"pass {guard_pass.name}: {guard_pass.check}, {len(units)} units, filter {filter_regex}")

    problems = audit_suppressions(source_dir, entries, guard_pass.check)
    problems += check_header_users(source_dir, entries)
    for unit in units:
        if os.path.realpath(source_dir / unit) not in database:
            problems.append(f"{unit}: not in {build_dir / 'compile_commands.json'}")
    if problems:
        return problems

    problems += run_control(tidy, guard_pass, filter_regex, source_dir, timeout)
    if problems:
        return problems

    command = tidy_command(tidy, guard_pass.check, filter_regex) + ["-p", str(build_dir)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(
                run_tidy, command + [str(source_dir / u)], u, timeout, source_dir, build_dir
            ): u
            for u in units
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except GuardError as error:
                problems.append(str(error))
                continue
            unit_problems = judge(result, guard_pass.check)
            problems += unit_problems
            if not unit_problems:
                print(f"pass {guard_pass.name}: {result.target}: clean")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--clang-tidy", default="clang-tidy-21")
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args()

    try:
        if args.jobs < 1:
            raise GuardError("--jobs must be at least 1")
        if args.timeout <= 0:
            raise GuardError("--timeout must be positive")
        tidy = shutil.which(args.clang_tidy)
        if tidy is None:
            raise GuardError(f"clang-tidy not found: {args.clang_tidy}")
        source_dir = Path(os.path.realpath(args.source_dir))
        build_dir = Path(os.path.realpath(args.build_dir))
        database = load_compile_database(build_dir)
        problems: list[str] = []
        for guard_pass in PASSES:
            problems += run_pass(
                guard_pass, source_dir, build_dir, database, tidy, args.jobs, args.timeout
            )
    except GuardError as error:
        print(f"USE_AFTER_MOVE_GUARD_FAILURE: {error}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(f"USE_AFTER_MOVE_GUARD_FAILURE: {problem}", file=sys.stderr)
        return 1
    print("USE_AFTER_MOVE_GUARD_OK: every pass control reported and every listed file is clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
