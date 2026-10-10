#!/usr/bin/env python3
"""Pre-PR C/C++ static analysis gate.

Runs the Clang Static Analyzer and clang-tidy, through CodeChecker, over every
translation unit a change reaches, once on the working tree (HEAD) and once on
the merge base (BASE), with identical tools and options. A blocking finding whose
key occurs more often at HEAD than at BASE fails the change. Findings already on
the merge base are not the change's, so the gate does not depend on fixing the
tree's inherited debt first, and there is no stored baseline to go stale.

The key is (checker, path relative to its checkout, CodeChecker report hash),
counted as a multiset after collapsing the same report reached through several
translation units. Report hashes do not depend on the checkout path, and two
identical findings in one function share a hash, so a second occurrence is new
only because it is counted. The guarantee is exactly that: a blocking finding
whose key occurs more often at HEAD than at BASE fails the change.

The gate fails closed. Before trusting a result it proves the instrument works:
pinned tool versions and executables, a rule set that agrees with .clang-tidy,
positive controls that must report exactly their marked lines, one result record
per analysed compilation and analyzer, and a BASE side that cannot read HEAD
sources. Anything it cannot establish is exit 2, never "no new findings".

Exit status: 0 no new blocking finding, 1 new blocking finding, 2 refused.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_REFUSED = 2

CODECHECKER_VERSION = "6.29.1"
LLVM_VERSION = "21.1.8"
DEFAULT_LLVM_BIN = "/usr/lib/llvm-21/bin"

# The rule set. Blocking checks were mostly real when measured on this tree;
# advisory checks are printed but never fail a change. Not run at all, because
# every finding they produced here was false: core.uninitialized.Assign and
# cplusplus.NewDeleteLeaks.
CLANG_TIDY_BLOCKING = frozenset(
    {
        "bugprone-dangling-handle",
        "bugprone-undefined-memory-manipulation",
        "bugprone-unused-return-value",
        "bugprone-use-after-move",
    }
)
CLANG_TIDY_ADVISORY = frozenset(
    {
        "bugprone-infinite-loop",
        "bugprone-move-forwarding-reference",
        "bugprone-unhandled-self-assignment",
    }
)
CLANGSA_BLOCKING = frozenset({"cplusplus.Move"})
CLANGSA_ADVISORY = frozenset(
    {
        "core.BitwiseShift",
        "core.CallAndMessage",
        "core.DivideZero",
        "core.FixedAddressDereference",
        "core.NonNullParamChecker",
        "core.NullDereference",
        "core.StackAddressEscape",
        "core.UndefinedBinaryOperatorResult",
        "core.VLASize",
        "core.uninitialized.ArraySubscript",
        "core.uninitialized.Branch",
        "core.uninitialized.CapturedBlockVariable",
        "core.uninitialized.NewArraySize",
        "core.uninitialized.UndefReturn",
        "cplusplus.NewDelete",
        "unix.API",
        "unix.BlockInCriticalSection",
        "unix.Chroot",
        "unix.Errno",
        "unix.Malloc",
        "unix.MallocSizeof",
        "unix.MismatchedDeallocator",
        "unix.StdCLibraryFunctions",
        "unix.Stream",
        "unix.Vfork",
        "unix.cstring.BadSizeArg",
        "unix.cstring.NotNullTerminated",
        "unix.cstring.NullArg",
    }
)
CLANG_TIDY_OPTIONS = {
    "bugprone-unused-return-value.CheckedReturnTypes": r"^::td::Status$;^::td::Result$",
    "bugprone-unused-return-value.AllowCastToVoid": "true",
}
ANALYZERS = ("clangsa", "clang-tidy")
EXPECTED_CHECKERS = {
    "clangsa": CLANGSA_BLOCKING | CLANGSA_ADVISORY,
    "clang-tidy": CLANG_TIDY_BLOCKING | CLANG_TIDY_ADVISORY,
}
BLOCKING = CLANG_TIDY_BLOCKING | CLANGSA_BLOCKING

SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})
HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"})
EXCLUDED_PREFIXES = ("third-party/",)
CONTROL_DIR = "test/static-analysis/gate"
# Controls are not built and are analysed by their own invocation, never as a change.
EXCLUDED_PREFIXES += ("test/static-analysis/",)
UNCOVERED_HEADERS = "scripts/static-analysis-uncovered-headers.txt"
# Changing any of these can change what CMake generates at configure time, which
# ninja cannot trace; the merge base then needs a build of its own.
CONFIGURE_INPUT_RE = re.compile(r"(^|/)CMakeLists\.txt$|\.cmake$|\.in$")
REFUSED_ARGUMENTS = ("-include", "-imacros", "-include-pch")
ACCEPTED_PARSE_STATUS = (0, 2)
EXPECT_RE = re.compile(r"//\s*expect:\s*(?P<checks>[\w.\-, ]+?)\s*$")


class Refusal(Exception):
    """The gate cannot establish a result; exit 2."""


@dataclass(frozen=True)
class Entry:
    """One compilation from compile_commands.json, as an argument vector."""

    directory: str
    file: str
    arguments: tuple[str, ...]

    @property
    def output(self) -> str:
        args = self.arguments
        for index, arg in enumerate(args):
            if arg == "-o" and index + 1 < len(args):
                return os.path.normpath(os.path.join(self.directory, args[index + 1]))
            if arg.startswith("-o") and len(arg) > 2:
                return os.path.normpath(os.path.join(self.directory, arg[2:]))
        raise Refusal(f"compilation of {self.file} has no -o output; cannot identify it")

    def command(self) -> str:
        return shlex.join(self.arguments)

    def as_json(self) -> dict[str, str]:
        return {"directory": self.directory, "file": self.file, "command": self.command()}


@dataclass
class Change:
    head_paths: set[str] = field(default_factory=set)  # added/modified/renamed-to/untracked
    base_paths: set[str] = field(default_factory=set)  # modified/deleted/renamed-from
    all_paths: set[str] = field(default_factory=set)  # every changed path, any language
    changed_lines: dict[str, set[int]] = field(default_factory=dict)  # HEAD path -> lines


@dataclass
class Report:
    checker: str
    analyzer: str
    path: str
    line: int
    column: int
    report_hash: str
    message: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.checker, self.path, self.report_hash)


# --- process handling -------------------------------------------------------


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command in its own process group, killing the whole group on any exit path."""
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError as error:
        raise Refusal(f"cannot run {command[0]}: {error}") from None
    try:
        stdout, stderr = process.communicate(input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(process)
        raise Refusal(f"{command[0]} timed out after {timeout:g} s") from None
    except BaseException:
        kill_group(process)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def kill_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate()


def json_output(text: str, what: str) -> object:
    """CodeChecker prints log lines, which also start with "[", before its JSON."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(("{", "[")):
            try:
                return json.loads("\n".join(lines[index:]))
            except ValueError:
                continue
    raise Refusal(f"cannot read {what}: {text.strip()[:200]}")


def git(root: Path, *args: str) -> str:
    result = run(["git", "-C", str(root), *args])
    if result.returncode != 0:
        raise Refusal(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


# --- tools ------------------------------------------------------------------


@dataclass(frozen=True)
class Tools:
    clang: str
    clangxx: str
    clang_tidy: str
    scan_deps: str
    codechecker: str
    codechecker_python: str

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["CC_ANALYZER_BIN"] = f"clangsa:{self.clang};clang-tidy:{self.clang_tidy}"
        env.pop("CC_ANALYZERS_FROM_PATH", None)
        return env


def resolve_tools(llvm_bin: Path, codechecker: str | None) -> Tools:
    clang = llvm_bin / "clang"
    clangxx = llvm_bin / "clang++"
    clang_tidy = llvm_bin / "clang-tidy"
    scan_deps = llvm_bin / "clang-scan-deps"
    for tool in (clang, clangxx, clang_tidy, scan_deps):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise Refusal(f"missing tool {tool}")
        result = run([str(tool), "--version"])
        if result.returncode != 0 or f"version {LLVM_VERSION}" not in result.stdout:
            raise Refusal(f"{tool} is not LLVM {LLVM_VERSION}: {result.stdout.strip()[:200]}")
    found = codechecker or shutil.which("CodeChecker")
    if not found:
        raise Refusal("CodeChecker not found; install codechecker==" + CODECHECKER_VERSION)
    try:
        shebang = Path(found).read_text(errors="replace").splitlines()[0]
    except (OSError, IndexError):
        raise Refusal(f"cannot read {found}") from None
    if not shebang.startswith("#!") or not Path(shebang[2:].strip()).is_file():
        raise Refusal(f"{found} has no usable interpreter line")
    tools = Tools(
        str(clang), str(clangxx), str(clang_tidy), str(scan_deps), found, shebang[2:].strip()
    )
    version = run([found, "version", "-o", "json"], env=tools.env())
    try:
        reported = json_output(version.stdout, "the CodeChecker version")["analyzer"][
            "base_package_version"
        ]
    except (KeyError, TypeError):
        raise Refusal(f"cannot read the CodeChecker version: {version.stdout[:200]}") from None
    if reported != CODECHECKER_VERSION:
        raise Refusal(f"CodeChecker {reported} found, {CODECHECKER_VERSION} required")
    analyzers = run([found, "analyzers", "-o", "json"], env=tools.env())
    try:
        listed = {
            row["name"]: row for row in json_output(analyzers.stdout, "CodeChecker analyzers")
        }
    except (KeyError, TypeError):
        raise Refusal(f"cannot read CodeChecker analyzers: {analyzers.stdout[:200]}") from None
    for name, path in (("clangsa", tools.clang), ("clang-tidy", tools.clang_tidy)):
        row = listed.get(name, {})
        if os.path.realpath(str(row.get("path", ""))) != os.path.realpath(path):
            raise Refusal(f"CodeChecker uses {row.get('path')} for {name}, expected {path}")
        if row.get("version") != LLVM_VERSION:
            raise Refusal(f"CodeChecker reports {name} {row.get('version')}, need {LLVM_VERSION}")
    return tools


def check_rule_set(root: Path, tools: Tools) -> None:
    """The .clang-tidy that clangd reads must agree with the tier tables exactly."""
    listed = run([tools.clang_tidy, "--list-checks"], cwd=root)
    if listed.returncode != 0:
        raise Refusal(f"clang-tidy --list-checks failed: {listed.stderr.strip()[:200]}")
    lines = listed.stdout.splitlines()
    if not lines or lines[0].strip() != "Enabled checks:":
        raise Refusal("unexpected clang-tidy --list-checks output")
    enabled = {line.strip() for line in lines[1:] if line.strip()}
    if enabled != EXPECTED_CHECKERS["clang-tidy"]:
        raise Refusal(
            ".clang-tidy disagrees with the rule set: "
            f"extra {sorted(enabled - EXPECTED_CHECKERS['clang-tidy'])}, "
            f"missing {sorted(EXPECTED_CHECKERS['clang-tidy'] - enabled)}"
        )
    dumped = run([tools.clang_tidy, "--dump-config"], cwd=root)
    if dumped.returncode != 0:
        raise Refusal(f"clang-tidy --dump-config failed: {dumped.stderr.strip()[:200]}")
    options: dict[str, str] = {}
    for line in dumped.stdout.splitlines():
        match = re.match(r"^\s+([\w.\-]+):\s*(.*)$", line)
        if match:
            value = match.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            options[match.group(1)] = value
    for key, expected in CLANG_TIDY_OPTIONS.items():
        if options.get(key) != expected:
            raise Refusal(f".clang-tidy sets {key}={options.get(key)!r}, expected {expected!r}")


def fingerprint() -> str:
    material = json.dumps(
        {
            "codechecker": CODECHECKER_VERSION,
            "llvm": LLVM_VERSION,
            "checkers": {name: sorted(checks) for name, checks in EXPECTED_CHECKERS.items()},
            "blocking": sorted(BLOCKING),
            "options": CLANG_TIDY_OPTIONS,
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode()).hexdigest()[:16]


# --- compilation database ---------------------------------------------------


def load_database(build_dir: Path, root: Path) -> list[Entry]:
    cache = build_dir / "CMakeCache.txt"
    try:
        home = re.search(r"^CMAKE_HOME_DIRECTORY:INTERNAL=(.*)$", cache.read_text(), re.M)
    except OSError:
        raise Refusal(f"{cache} is missing; configure a build for this checkout") from None
    if not home or os.path.realpath(home.group(1)) != os.path.realpath(root):
        raise Refusal(
            f"{build_dir} was configured for {home.group(1) if home else '?'}, not {root}; "
            "configure a build for this checkout"
        )
    path = build_dir / "compile_commands.json"
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise Refusal(f"cannot read {path}: {error}") from None
    if not isinstance(raw, list) or not raw:
        raise Refusal(f"{path} is empty")
    entries = []
    for item in raw:
        try:
            directory, file = item["directory"], item["file"]
            arguments = item.get("arguments") or shlex.split(item["command"])
        except (KeyError, TypeError, ValueError):
            raise Refusal(f"malformed entry in {path}: {str(item)[:200]}") from None
        entry = Entry(directory, os.path.normpath(os.path.join(directory, file)), tuple(arguments))
        refuse_unsupported(entry)
        entries.append(entry)
    outputs = collections.Counter(entry.output for entry in entries)
    duplicates = [output for output, count in outputs.items() if count > 1]
    if duplicates:
        raise Refusal(f"two compilations write the same output, e.g. {duplicates[0]}")
    return entries


def refuse_unsupported(entry: Entry) -> None:
    for arg in entry.arguments:
        if arg.startswith("@") or any(arg.startswith(flag) for flag in REFUSED_ARGUMENTS):
            raise Refusal(
                f"{entry.file}: unsupported argument {arg} (response file or forced include)"
            )
        if arg.endswith((".pch", ".gch")):
            raise Refusal(f"{entry.file}: precompiled header {arg} is not supported")
        if " " in arg and not arg.startswith("-D"):
            raise Refusal(f"{entry.file}: argument with a space is not supported: {arg}")


def configured_checkout(build_dir: Path) -> Path:
    cache = build_dir / "CMakeCache.txt"
    try:
        home = re.search(r"^CMAKE_HOME_DIRECTORY:INTERNAL=(.*)$", cache.read_text(), re.M)
    except OSError:
        raise Refusal(f"{cache} is missing") from None
    if not home:
        raise Refusal(f"{cache} names no source directory")
    return Path(home.group(1)).resolve()


def check_clean_at(checkout: Path, commit: str) -> None:
    """The merge-base build must describe exactly that commit: same HEAD, nothing modified."""
    if git(checkout, "rev-parse", "HEAD").strip() != commit:
        raise Refusal(f"{checkout} is not at the merge base {commit[:12]}")
    dirty = git(checkout, "status", "--porcelain").strip()
    if dirty:
        raise Refusal(f"{checkout} has local changes: {dirty.splitlines()[0]}")


def relative(path: str, root: Path) -> str | None:
    """Path of an absolute, normalised path inside root (already resolved), or None."""
    base = str(root)
    if path == base:
        return "."
    if path.startswith(base + "/"):
        return path[len(base) + 1 :]
    return None


def is_excluded(rel: str) -> bool:
    return rel.startswith(EXCLUDED_PREFIXES)


def analysable(entries: list[Entry], root: Path, build_dir: Path) -> list[Entry]:
    """Project compilations: under the checkout, not generated, not third-party."""
    keep = []
    for entry in entries:
        rel = relative(entry.file, root)
        if rel is None or is_excluded(rel) or relative(entry.file, build_dir) is not None:
            continue
        keep.append(entry)
    return keep


def rewrite_entry(entry: Entry, head_root: Path, base_root: Path, build_dir: Path) -> Entry:
    """Point every source path at the BASE worktree; leave build-directory paths alone."""
    head = str(head_root.resolve())
    build = str(build_dir.resolve())

    def move(text: str) -> str:
        def replace(match: re.Match[str]) -> str:
            path = match.group(0)
            if path == build or path.startswith(build + "/"):
                return path
            return str(base_root) + path[len(head) :]

        return re.sub(re.escape(head) + r"(?=/|$)[^\s:=,]*", replace, text)

    return Entry(
        move(entry.directory), move(entry.file), tuple(move(arg) for arg in entry.arguments)
    )


# --- change set -------------------------------------------------------------


def is_cpp(path: str) -> bool:
    return Path(path).suffix in SOURCE_SUFFIXES | HEADER_SUFFIXES


def collect_change(root: Path, merge_base: str) -> Change:
    change = Change()
    status = git(root, "diff", "--merge-base", merge_base, "--name-status", "-M", "-z")
    fields = status.split("\0")
    index = 0
    while index < len(fields) and fields[index]:
        code = fields[index]
        kind = code[0]
        if kind in "RC":
            old, new = fields[index + 1], fields[index + 2]
            index += 3
            change.all_paths.update((old, new))
            if kind == "R":
                change.base_paths.add(old)
            change.head_paths.add(new)
        else:
            path = fields[index + 1]
            index += 2
            change.all_paths.add(path)
            if kind == "A":
                change.head_paths.add(path)
            elif kind == "D":
                change.base_paths.add(path)
            elif kind in "MT":
                change.head_paths.add(path)
                change.base_paths.add(path)
            else:
                raise Refusal(f"unexpected git status {code} for {path}")
    for path in git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0"):
        if path:
            change.all_paths.add(path)
            change.head_paths.add(path)
            if is_cpp(path):
                change.changed_lines[path] = all_lines(root / path)
    diff = git(root, "diff", "--merge-base", merge_base, "-U0", "-M", "--no-color", "--no-ext-diff")
    current = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:]
            current = target[2:] if target.startswith("b/") else None
            if current is not None:
                change.changed_lines.setdefault(current, set())
        elif line.startswith("@@") and current is not None:
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise Refusal(f"cannot parse diff hunk header {line!r}")
            start, count = int(match.group(1)), int(match.group(2) or "1")
            if count == 0:
                # A pure deletion: the lines around the cut are what the change touched.
                change.changed_lines[current].update({max(start, 1), start + 1})
            else:
                change.changed_lines[current].update(range(start, start + count))
    return change


def all_lines(path: Path) -> set[int]:
    try:
        return set(range(1, len(path.read_text(errors="replace").splitlines()) + 2))
    except OSError:
        return set()


# --- dependency scan --------------------------------------------------------


def scan_dependencies(
    entries: list[Entry], tools: Tools, work: Path, side: str
) -> dict[Entry, set[str]]:
    database = work / f"{side}-scan.json"
    database.write_text(json.dumps([entry.as_json() for entry in entries]))
    result = run(
        [tools.scan_deps, "-compilation-database", str(database), "-format", "make"],
        timeout=1800,
    )
    if result.returncode != 0:
        raise Refusal(f"{side}: clang-scan-deps failed: {result.stderr.strip()[:400]}")
    by_output = {entry.output: entry for entry in entries}
    deps: dict[Entry, set[str]] = {}
    text = result.stdout.replace("\\\n", " ")
    for line in text.splitlines():
        if not line.strip():
            continue
        if "\\ " in line:
            raise Refusal(f"{side}: a dependency path contains a space")
        target, sep, rest = line.partition(": ")
        if not sep:
            raise Refusal(f"{side}: cannot parse clang-scan-deps line {line[:120]!r}")
        entry = None
        for candidate_dir in {e.directory for e in entries}:
            entry = by_output.get(os.path.normpath(os.path.join(candidate_dir, target)))
            if entry is not None:
                break
        if entry is None or entry in deps:
            raise Refusal(
                f"{side}: clang-scan-deps reported an unknown or repeated target {target}"
            )
        deps[entry] = {os.path.normpath(path) for path in rest.split()}
    if len(deps) != len(entries):
        raise Refusal(f"{side}: clang-scan-deps covered {len(deps)} of {len(entries)} compilations")
    return deps


# --- generated files --------------------------------------------------------


def ninja_query(build_dir: Path, target: str) -> tuple[str | None, list[str], list[str]] | None:
    """(rule, explicit inputs, implicit inputs) of a ninja output, or None for a plain file."""
    result = run(["ninja", "-C", str(build_dir), "-t", "query", target])
    if result.returncode != 0:
        if "unknown target" in result.stderr:
            return None
        raise Refusal(f"ninja -t query {target} failed: {result.stderr.strip()[:200]}")
    rule = None
    explicit: list[str] = []
    implicit: list[str] = []
    section = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if line.startswith("  input:"):
            rule = stripped.split(":", 1)[1].strip()
            section = "input"
        elif line.startswith("  outputs:"):
            section = "outputs"
        elif section == "input" and line.startswith("    "):
            if stripped.startswith("|| "):
                continue
            if stripped.startswith("| "):
                implicit.append(stripped[2:])
            else:
                explicit.append(stripped)
    return rule, explicit, implicit


def trace_generated(
    build_dir: Path, root: Path, generated: set[str], changed: set[str]
) -> list[str]:
    """Problems that stop generated files from being shared with the BASE side.

    Custom-command outputs are traced back to source files. A generator executable
    is treated as opaque except for the sources of its own objects; a change to a
    library it links is assumed not to change what it generates.
    """
    problems = []
    changed_abs = {str((root / path).resolve()) for path in changed}
    seen: set[str] = set()
    queue = sorted(generated)
    while queue:
        target = queue.pop()
        if target in seen:
            continue
        seen.add(target)
        absolute = target if os.path.isabs(target) else os.path.normpath(str(build_dir / target))
        if absolute in changed_abs:
            problems.append(f"generator input {relative(absolute, root)} is changed")
            continue
        queried = ninja_query(build_dir, target)
        if queried is None:
            # A plain source file, or a file CMake writes at configure time; the
            # latter is covered by refusing any change to the CMake configuration.
            continue
        rule, explicit, implicit = queried
        if rule is None:
            continue
        if "_LINKER" in rule:
            for obj in explicit:
                compiled = ninja_query(build_dir, obj)
                if compiled is None or compiled[0] is None:
                    problems.append(f"cannot trace object {obj} of {target}")
                    continue
                for source in compiled[1]:
                    src = (
                        source
                        if os.path.isabs(source)
                        else os.path.normpath(str(build_dir / source))
                    )
                    if src in changed_abs:
                        problems.append(f"generator source {relative(src, root)} is changed")
            continue
        queue.extend(explicit + implicit)
    return problems


def generated_files(
    deps: dict[Entry, set[str]], root: Path, build_dir: Path
) -> tuple[set[str], set[str]]:
    """(build-directory files, git-ignored files inside the checkout) that compilations read."""
    reached = set().union(*deps.values()) if deps else set()
    in_build = {path for path in reached if relative(path, build_dir) is not None}
    candidates = sorted(
        rel
        for path in reached
        if (rel := relative(path, root)) is not None and relative(path, build_dir) is None
    )
    ignored: set[str] = set()
    if candidates:
        result = run(
            ["git", "-C", str(root), "check-ignore", "--stdin"], input_text="\n".join(candidates)
        )
        if result.returncode not in (0, 1):
            raise Refusal(f"git check-ignore failed: {result.stderr.strip()[:200]}")
        ignored = {line for line in result.stdout.splitlines() if line}
    return in_build, ignored


def check_generated_fresh(build_dir: Path, targets: set[str]) -> None:
    if not targets:
        return
    result = run(["ninja", "-C", str(build_dir), "-n", *sorted(targets)], timeout=600)
    if result.returncode != 0:
        raise Refusal(f"ninja -n failed: {(result.stdout + result.stderr).strip()[:300]}")
    if "no work to do" not in result.stdout:
        raise Refusal(
            "generated files are older than their inputs; build the tree first "
            f"(ninja -C {build_dir})"
        )


def check_contained(deps: dict[Entry, set[str]], head_root: Path, build_dir: Path) -> None:
    """No BASE compilation may read a HEAD source; the build directory is shared."""
    for entry, paths in deps.items():
        for path in paths:
            if relative(path, head_root) is not None and relative(path, build_dir) is None:
                raise Refusal(f"BASE compilation of {entry.file} reads HEAD file {path}")


# --- CodeChecker ------------------------------------------------------------


def analyzer_arguments() -> list[str]:
    args = ["--analyzers", *ANALYZERS, "--disable-all"]
    for checks in EXPECTED_CHECKERS.values():
        for check in sorted(checks):
            args += ["-e", check]
    args.append("--checker-config")
    for key, value in CLANG_TIDY_OPTIONS.items():
        check, option = key.rsplit(".", 1)
        args.append(f"clang-tidy:{check}:{option}={value}")
    return args


def action_names(entries: list[Entry], tools: Tools) -> dict[str, Entry]:
    """CodeChecker's own result-file stem for every compilation, from its own code."""
    program = (
        "import json, os, sys\n"
        "from codechecker_analyzer.util import analyzer_action_hash\n"
        "rows = json.load(sys.stdin)\n"
        "print(json.dumps([analyzer_action_hash(r['file'], r['directory'], r['command'])"
        " for r in rows]))\n"
    )
    result = run(
        [tools.codechecker_python, "-c", program],
        input_text=json.dumps([entry.as_json() for entry in entries]),
    )
    try:
        hashes = json.loads(result.stdout)
    except ValueError:
        hashes = None
    if result.returncode != 0 or not isinstance(hashes, list) or len(hashes) != len(entries):
        raise Refusal(f"cannot compute CodeChecker action hashes: {result.stderr.strip()[:300]}")
    names: dict[str, Entry] = {}
    for entry, digest in zip(entries, hashes):
        for analyzer in ANALYZERS:
            name = f"{os.path.basename(entry.file)}_{analyzer}_{digest}"
            if name in names:
                raise Refusal(
                    f"two compilations of {entry.file} are indistinguishable to CodeChecker"
                )
            names[name] = entry
    return names


def analyze(
    entries: list[Entry], tools: Tools, out: Path, jobs: int, timeout: int, label: str
) -> None:
    if out.exists():
        raise Refusal(f"{label}: report directory {out} already exists")
    database = out.parent / f"{out.name}-compile.json"
    database.write_text(json.dumps([entry.as_json() for entry in entries]))
    expected = action_names(entries, tools)
    result = run(
        [
            tools.codechecker,
            "analyze",
            str(database),
            "-o",
            str(out),
            *analyzer_arguments(),
            "--timeout",
            str(timeout),
            "-j",
            str(jobs),
        ],
        env=tools.env(),
    )
    if result.returncode != 0:
        tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-8:])
        raise Refusal(f"{label}: CodeChecker analyze exited {result.returncode}\n{tail}")
    account(out, expected, len(entries), label)


def account(out: Path, expected: dict[str, Entry], count: int, label: str) -> None:
    """One successful result per compilation and analyzer, and nothing else."""
    present = {path.name[: -len(".plist")] for path in out.glob("*.plist")}
    failed = (
        sorted(path.name for path in (out / "failed").glob("*"))
        if (out / "failed").exists()
        else []
    )
    if failed:
        raise Refusal(f"{label}: {len(failed)} failed analyses, e.g. {failed[0]}")
    missing = sorted(set(expected) - present)
    extra = sorted(present - set(expected))
    if missing or extra:
        raise Refusal(
            f"{label}: result records differ, missing {missing[:3]}, unexpected {extra[:3]}"
        )
    try:
        tool = json.loads((out / "metadata.json").read_text())["tools"][0]
        analyzers = tool["analyzers"]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        raise Refusal(f"{label}: metadata.json is missing or malformed") from None
    for name in ANALYZERS:
        try:
            stats = analyzers[name]["analyzer_statistics"]
            enabled = {check for check, on in analyzers[name]["checkers"].items() if on}
        except (KeyError, TypeError, AttributeError):
            raise Refusal(f"{label}: metadata.json has no statistics for {name}") from None
        if stats.get("failed") != 0 or stats.get("successful") != count:
            raise Refusal(
                f"{label}: {name} analysed {stats.get('successful')}/{count}, failed {stats.get('failed')}"
            )
        if stats.get("version") != LLVM_VERSION:
            raise Refusal(f"{label}: {name} ran version {stats.get('version')}")
        if enabled != EXPECTED_CHECKERS[name]:
            raise Refusal(
                f"{label}: {name} enabled checkers differ: extra {sorted(enabled - EXPECTED_CHECKERS[name])}, "
                f"missing {sorted(EXPECTED_CHECKERS[name] - enabled)}"
            )


def parse_reports(
    out: Path, tools: Tools, side_root: Path, build_dir: Path, label: str
) -> list[Report]:
    target = out.parent / f"{out.name}-reports.json"
    result = run(
        [tools.codechecker, "parse", str(out), "-e", "json", "-o", str(target)], env=tools.env()
    )
    if result.returncode not in ACCEPTED_PARSE_STATUS:
        raise Refusal(f"{label}: CodeChecker parse exited {result.returncode}")
    try:
        document = json.loads(target.read_text())
        rows = document["reports"]
        if not isinstance(rows, list):
            raise TypeError
    except (OSError, ValueError, KeyError, TypeError):
        raise Refusal(f"{label}: parse output is missing or malformed") from None
    reports = []
    for row in rows:
        try:
            original = row["file"]["original_path"]
            rel = relative(original, side_root)
            if rel is None:
                build_rel = relative(original, build_dir)
                rel = f"<build>/{build_rel}" if build_rel is not None else original
            reports.append(
                Report(
                    checker=str(row["checker_name"]),
                    analyzer=str(row["analyzer_name"]),
                    path=rel,
                    line=int(row["line"]),
                    column=int(row["column"]),
                    report_hash=str(row["report_hash"]),
                    message=str(row.get("message", "")),
                )
            )
        except (KeyError, TypeError, ValueError):
            raise Refusal(f"{label}: malformed report {str(row)[:200]}") from None
    if result.returncode == 0 and reports:
        raise Refusal(f"{label}: parse exited 0 but printed {len(reports)} reports")
    if result.returncode == 2 and not reports:
        raise Refusal(f"{label}: parse exited 2 but the report list is empty")
    return reports


def count(reports: list[Report]) -> collections.Counter[tuple[str, str, str]]:
    """Multiset of keys, after collapsing one report reached through several compilations."""
    unique = {(r.checker, r.path, r.report_hash, r.line, r.column) for r in reports}
    return collections.Counter((checker, path, digest) for checker, path, digest, _, _ in unique)


# --- controls ---------------------------------------------------------------


def run_controls(root: Path, tools: Tools, work: Path, jobs: int, timeout: int) -> int:
    control_dir = root / CONTROL_DIR
    files = sorted(control_dir.glob("*.cpp"))
    if not files:
        raise Refusal(f"no positive controls in {CONTROL_DIR}")
    expected: collections.Counter[tuple[str, int, str]] = collections.Counter()
    entries = []
    covered: set[str] = set()
    for path in files:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            match = EXPECT_RE.search(line)
            if match:
                for check in (c.strip() for c in match.group("checks").split(",")):
                    expected[(path.name, number, check)] += 1
                    covered.add(check)
        output = work / "controls-obj" / (path.name + ".o")
        entries.append(
            Entry(
                str(work),
                str(path),
                (tools.clangxx, "-std=c++20", "-c", str(path), "-o", str(output)),
            )
        )
    if not BLOCKING <= covered:
        raise Refusal(f"blocking checks without a positive control: {sorted(BLOCKING - covered)}")
    out = work / "controls"
    analyze(entries, tools, out, jobs, timeout, "controls")
    seen: collections.Counter[tuple[str, int, str]] = collections.Counter(
        (Path(r.path).name, r.line, r.checker)
        for r in parse_reports(out, tools, root, work, "controls")
    )
    if seen != expected:
        raise Refusal(
            "positive controls did not report exactly their marked lines: "
            f"missing {sorted((expected - seen).elements())}, unexpected {sorted((seen - expected).elements())}"
        )
    return sum(expected.values())


# --- suppressions -----------------------------------------------------------

NOLINT_RE = re.compile(r"NOLINT(?P<kind>NEXTLINE|BEGIN|END)?(?P<checks>\([^)]*\))?(?P<rest>.*)")
CODECHECKER_RE = re.compile(
    r"codechecker_(?P<kind>suppress|false_positive|intentional|confirmed)\s*(?P<checks>\[[^\]]*\])?(?P<rest>.*)"
)


@dataclass(frozen=True)
class Suppression:
    path: str
    line: int
    text: str
    covers: frozenset[int]


def find_suppressions(path: str, lines: list[str]) -> tuple[list[Suppression], list[str]]:
    found: list[Suppression] = []
    problems: list[str] = []
    open_ranges: list[int] = []
    known = EXPECTED_CHECKERS["clang-tidy"] | EXPECTED_CHECKERS["clangsa"]
    for number, line in enumerate(lines, start=1):
        for regex in (NOLINT_RE, CODECHECKER_RE):
            for match in regex.finditer(line):
                kind = match.group("kind") or ""
                where = f"{path}:{number}"
                if regex is NOLINT_RE:
                    if kind == "END":
                        if open_ranges:
                            start = open_ranges.pop()
                            found.append(
                                Suppression(
                                    path,
                                    start,
                                    lines[start - 1].strip(),
                                    frozenset(range(start, number + 1)),
                                )
                            )
                        continue
                    checks_text = (match.group("checks") or "")[1:-1]
                    covers = {"": {number}, "NEXTLINE": {number + 1}, "BEGIN": set()}[kind]
                else:
                    checks_text = (match.group("checks") or "")[1:-1]
                    covers = {number + 1}
                checks = {c.strip() for c in checks_text.split(",") if c.strip()}
                rest = match.group("rest").strip().lstrip(":").strip().removesuffix("*/").strip()
                if regex is CODECHECKER_RE and kind == "confirmed":
                    continue
                if not checks:
                    problems.append(f"{where}: suppression without an exact check name")
                elif checks - known or any("*" in c or c == "all" for c in checks):
                    problems.append(
                        f"{where}: suppression names {sorted(checks)}, not exact enabled checks"
                    )
                elif not rest:
                    problems.append(f"{where}: suppression without a reason")
                if kind == "BEGIN":
                    open_ranges.append(number)
                else:
                    found.append(Suppression(path, number, line.strip(), frozenset(covers)))
    for start in open_ranges:
        problems.append(f"{path}:{start}: NOLINTBEGIN without NOLINTEND")
    return found, problems


def audit_suppressions(root: Path, change: Change) -> list[Suppression]:
    accepted: list[Suppression] = []
    problems: list[str] = []
    for path, changed in sorted(change.changed_lines.items()):
        if not is_cpp(path) or is_excluded(path) or not (root / path).is_file():
            continue
        lines = (root / path).read_text(errors="replace").splitlines()
        found, issues = find_suppressions(path, lines)
        for suppression in found:
            if suppression.line in changed or suppression.covers & changed:
                accepted.append(suppression)
        relevant = {s.line for s in found if s.line in changed or s.covers & changed}
        for issue in issues:
            line = int(issue.split(":", 2)[1])
            if line in changed or line in relevant:
                problems.append(issue)
    if problems:
        raise Refusal("suppression audit failed:\n  " + "\n  ".join(problems))
    return accepted


# --- selection --------------------------------------------------------------


def load_uncovered(root: Path) -> set[str]:
    path = root / UNCOVERED_HEADERS
    try:
        text = path.read_text()
    except OSError:
        raise Refusal(f"{UNCOVERED_HEADERS} is missing") from None
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}


def select(
    entries: list[Entry],
    deps: dict[Entry, set[str]],
    root: Path,
    sources: set[str],
    headers: set[str],
) -> tuple[set[Entry], set[str]]:
    """Compilations of changed sources or including a changed header; and headers no one includes."""
    chosen = {entry for entry in entries if relative(entry.file, root) in sources}
    orphans = set()
    for header in headers:
        absolute = os.path.normpath(str(root / header))
        includers = {entry for entry, paths in deps.items() if absolute in paths}
        if not includers:
            orphans.add(header)
        chosen |= includers
    return chosen, orphans


def identity(entry: Entry, side_root: Path, side_build: Path) -> tuple[str, str]:
    """A compilation's identity with its checkout, build directory and output factored out."""

    def neutral(text: str) -> str:
        # The build directory may sit inside the checkout, so replace it first.
        return text.replace(str(side_build), "<build>").replace(str(side_root), "<root>")

    arguments = list(entry.arguments)
    for index, arg in enumerate(arguments):
        if arg == "-o" and index + 1 < len(arguments):
            arguments[index + 1] = "<output>"
        elif arg.startswith("-o") and len(arg) > 2:
            arguments[index] = "-o<output>"
    return (neutral(entry.file), shlex.join(neutral(arg) for arg in arguments[1:]))


# --- main -------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="origin/main", help="branch the change merges into")
    parser.add_argument("--build-dir", type=Path, help="build of this checkout (default: build)")
    parser.add_argument("--base-build-dir", type=Path, help="separate build of the merge base")
    parser.add_argument("--llvm-bin", type=Path, default=Path(DEFAULT_LLVM_BIN))
    parser.add_argument("--codechecker", help="CodeChecker executable (default: from PATH)")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument(
        "--timeout", type=int, default=1800, help="seconds per compilation and analyzer"
    )
    parser.add_argument("--full", action="store_true", help="analyse every project compilation")
    parser.add_argument("--keep-temp", action="store_true", help="keep the work directory")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    try:
        return gate(root, args)
    except Refusal as error:
        print(f"static-analysis: REFUSED: {error}", file=sys.stderr)
        return EXIT_REFUSED


def gate(root: Path, args: argparse.Namespace) -> int:
    build_dir = (args.build_dir or root / "build").resolve()
    if args.jobs < 1 or args.timeout < 1:
        raise Refusal("--jobs and --timeout must be positive")
    tools = resolve_tools(args.llvm_bin, args.codechecker)
    check_rule_set(root, tools)
    print(
        f"static-analysis: rule set {fingerprint()}, CodeChecker {CODECHECKER_VERSION}, LLVM {LLVM_VERSION}"
    )
    merge_base = git(root, "merge-base", args.base, "HEAD").strip()
    change = collect_change(root, merge_base)
    work = Path(tempfile.mkdtemp(prefix="tos-static-analysis-")).resolve()
    base_root = work / "base"
    worktree_added = False
    try:
        controls = run_controls(root, tools, work, args.jobs, args.timeout)
        print(f"static-analysis: positive controls reported all {controls} marked findings")
        suppressions = audit_suppressions(root, change)

        head_all = load_database(build_dir, root)
        head_entries = analysable(head_all, root, build_dir)
        cpp_head = {p for p in change.head_paths if is_cpp(p) and not is_excluded(p)}
        cpp_base = {p for p in change.base_paths if is_cpp(p) and not is_excluded(p)}
        if not args.full and not cpp_head and not cpp_base:
            print("static-analysis: no C/C++ change; 0 compilations analysed")
            return EXIT_CLEAN

        head_sources = {p for p in cpp_head if Path(p).suffix in SOURCE_SUFFIXES}
        known = {relative(entry.file, root) for entry in head_entries}
        unknown = sorted(p for p in head_sources if p not in known)
        if unknown:
            raise Refusal(
                f"changed sources missing from compile_commands.json: {unknown}; reconfigure"
            )

        head_deps = scan_dependencies(head_entries, tools, work, "HEAD")
        in_build, ignored = generated_files(head_deps, root, build_dir)
        generated = set(in_build) | {str(root / p) for p in ignored}
        check_generated_fresh(
            build_dir, {p for p in generated if ninja_query(build_dir, p) is not None}
        )

        if args.full:
            head_selected, orphans = set(head_entries), set()
        else:
            head_selected, orphans = select(
                head_entries,
                head_deps,
                root,
                head_sources,
                {p for p in cpp_head if Path(p).suffix in HEADER_SUFFIXES},
            )
        uncovered = load_uncovered(root)
        refused = sorted(orphans - uncovered)
        if refused:
            raise Refusal(
                f"changed headers no compilation includes: {refused}; list them in {UNCOVERED_HEADERS}"
            )

        if args.base_build_dir:
            # A build of another checkout, which must sit cleanly at the merge base.
            base_build = args.base_build_dir.resolve()
            base_root = configured_checkout(base_build)
            check_clean_at(base_root, merge_base)
            base_all = load_database(base_build, base_root)
            base_entries = analysable(base_all, base_root, base_build)
            base_deps = scan_dependencies(base_entries, tools, work, "BASE")
            base_in_build, base_ignored = generated_files(base_deps, base_root, base_build)
            base_generated = set(base_in_build) | {str(base_root / p) for p in base_ignored}
            check_generated_fresh(
                base_build,
                {p for p in base_generated if ninja_query(base_build, p) is not None},
            )
        else:
            base_build = build_dir
            if any(CONFIGURE_INPUT_RE.search(p) for p in change.all_paths):
                raise Refusal(
                    "the change touches CMake configuration; pass --base-build-dir with a "
                    f"build of a clean checkout at {merge_base[:12]}"
                )
            git(root, "worktree", "add", "--detach", "--quiet", str(base_root), merge_base)
            worktree_added = True
            problems = trace_generated(build_dir, root, generated, change.all_paths)
            if problems:
                raise Refusal(
                    "generated files cannot be shared with the merge base: "
                    + "; ".join(sorted(set(problems))[:5])
                    + "; pass --base-build-dir"
                )
            for rel in sorted(ignored):
                destination = base_root / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / rel, destination)
            base_entries = [
                rewrite_entry(entry, root, base_root, build_dir)
                for entry in head_entries
                if (base_root / relative(entry.file, root)).is_file()
            ]
            base_deps = scan_dependencies(base_entries, tools, work, "BASE")
        check_contained(base_deps, root, base_build)

        if args.full:
            base_selected = set(base_entries)
        else:
            base_selected, _ = select(
                base_entries,
                base_deps,
                base_root,
                {p for p in cpp_base if Path(p).suffix in SOURCE_SUFFIXES},
                {p for p in cpp_base if Path(p).suffix in HEADER_SUFFIXES},
            )
        head_ids = {identity(e, root, build_dir): e for e in head_entries}
        base_ids = {identity(e, base_root, base_build): e for e in base_entries}
        if len(head_ids) != len(head_entries) or len(base_ids) != len(base_entries):
            raise Refusal("two compilations differ only in their output path")
        wanted = {identity(e, root, build_dir) for e in head_selected} | {
            identity(e, base_root, base_build) for e in base_selected
        }
        head_run = sorted((head_ids[i] for i in wanted if i in head_ids), key=lambda e: e.output)
        base_run = sorted((base_ids[i] for i in wanted if i in base_ids), key=lambda e: e.output)
        print(
            f"static-analysis: HEAD {len(head_run)} compilations, BASE {len(base_run)} (merge base {merge_base[:12]})"
        )
        for header in sorted(orphans & uncovered):
            print(f"static-analysis: UNCOVERED {header} (no compilation includes it)")

        head_reports = base_reports = []
        if head_run:
            analyze(head_run, tools, work / "head", args.jobs, args.timeout, "HEAD")
            head_reports = parse_reports(work / "head", tools, root, build_dir, "HEAD")
        if base_run:
            analyze(base_run, tools, work / "base-reports", args.jobs, args.timeout, "BASE")
            base_reports = parse_reports(
                work / "base-reports", tools, base_root, base_build, "BASE"
            )
        return judge(head_reports, base_reports, suppressions)
    finally:
        if worktree_added:
            run(["git", "-C", str(root), "worktree", "remove", "--force", str(base_root)])
        if args.keep_temp:
            print(f"static-analysis: work directory kept at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


def judge(
    head_reports: list[Report], base_reports: list[Report], suppressions: list[Suppression]
) -> int:
    new = count(head_reports) - count(base_reports)
    examples = {}
    for report in head_reports:
        examples.setdefault(report.key, report)
    blocking = sorted(key for key in new if key[0] in BLOCKING)
    advisory = sorted(key for key in new if key[0] not in BLOCKING)
    for suppression in suppressions:
        print(
            f"static-analysis: suppression {suppression.path}:{suppression.line}: {suppression.text}"
        )
    for label, keys in (("ADVISORY", advisory), ("BLOCKING", blocking)):
        for key in keys:
            report = examples[key]
            print(
                f"static-analysis: {label} {report.path}:{report.line}:{report.column}: "
                f"{report.message} [{report.checker}] (+{new[key]})"
            )
    print(f"static-analysis: {len(blocking)} new blocking, {len(advisory)} new advisory")
    return EXIT_FINDINGS if blocking else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
