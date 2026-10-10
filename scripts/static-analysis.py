#!/usr/bin/env python3
"""Pre-PR C/C++ static analysis gate.

Runs the Clang Static Analyzer and clang-tidy, through CodeChecker, over every
translation unit a change reaches, once on the working tree (HEAD) and once on
the merge base (BASE), with identical tools and options. BASE is a separate
checkout that sits cleanly at the merge base and has its own build, so each
side's generated files, compile commands and dependencies are its own. A
blocking finding whose key occurs more often at HEAD than at BASE fails the
change. Findings already on the merge base are not the change's, so the gate
does not depend on fixing the tree's inherited debt first, and there is no
stored baseline to go stale.

The key is (checker, path relative to its checkout, CodeChecker report hash),
counted as a multiset after collapsing the same report reached through several
translation units. Report hashes do not depend on the checkout path, and two
identical findings in one function share a hash, so a second occurrence is new
only because it is counted. The guarantee is exactly that: a blocking finding
whose key occurs more often at HEAD than at BASE fails the change.

The gate fails closed. Before trusting a result it proves the instrument works:
pinned tool versions and executables, a rule set that agrees with .clang-tidy,
positive controls that must report exactly their marked lines, builds that ninja
considers up to date, compilations that read nothing outside their own checkout,
build directory and the compiler's system directories, and one result record per
analysed compilation and analyzer. Anything it cannot establish is exit 2, never
"no new findings".

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
    "bugprone-unused-return-value.AllowCastToVoid": "false",
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
REFUSED_ARGUMENTS = ("-include", "-imacros", "-include-pch")
ACCEPTED_PARSE_STATUS = (0, 2)
PARSE_SCHEMA_VERSION = 1
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


def install_signal_handlers() -> None:
    """Turn SIGTERM and SIGHUP into an exception.

    By default they end the interpreter without unwinding, which would leave every
    analyzer process group the gate started running on its own. As an exception
    they unwind through run(), which kills the group, and through the work
    directory cleanup. SIGKILL cannot be caught.
    """

    def terminate(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, terminate)


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
    if version.returncode != 0:
        raise Refusal(f"CodeChecker version exited {version.returncode}")
    try:
        reported = json_output(version.stdout, "the CodeChecker version")["analyzer"][
            "base_package_version"
        ]
    except (KeyError, TypeError):
        raise Refusal(f"cannot read the CodeChecker version: {version.stdout[:200]}") from None
    if reported != CODECHECKER_VERSION:
        raise Refusal(f"CodeChecker {reported} found, {CODECHECKER_VERSION} required")
    analyzers = run([found, "analyzers", "-o", "json"], env=tools.env())
    if analyzers.returncode != 0:
        raise Refusal(f"CodeChecker analyzers exited {analyzers.returncode}")
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
    """Project compilations: sources in the checkout or generated into the build.

    Third-party sources, and third-party build products, are not the project's.
    The build directory is checked first because it may sit inside the checkout.
    """
    keep = []
    for entry in entries:
        in_build = relative(entry.file, build_dir)
        rel = in_build if in_build is not None else relative(entry.file, root)
        if rel is None or is_excluded(rel):
            continue
        keep.append(entry)
    return keep


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
    # Paths come from the NUL-delimited name-status output, not from display
    # headers that Git may quote or prefix differently. Diff one literal path
    # at a time, without textconv or binary filtering, so user preferences and
    # attributes cannot hide a changed suppression. Treat a rename destination
    # as an addition: its suppressions must be audited at the new path too.
    for path in sorted(change.head_paths):
        if not is_cpp(path) or path in change.changed_lines:
            continue
        changed = change.changed_lines.setdefault(path, set())
        diff = git(
            root,
            "--literal-pathspecs",
            "diff",
            "--merge-base",
            merge_base,
            "-U0",
            "--no-renames",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--text",
            "--",
            path,
        )
        for line in diff.splitlines():
            if not line.startswith("@@"):
                continue
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise Refusal(f"cannot parse diff hunk header {line!r}")
            start, count = int(match.group(1)), int(match.group(2) or "1")
            if count == 0:
                # A pure deletion: the lines around the cut are what the change touched.
                changed.update({max(start, 1), start + 1})
            else:
                changed.update(range(start, start + count))
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


def ninja_outputs(build_dir: Path) -> dict[str, str]:
    """Every output the build graph knows, as {absolute path: name ninja uses}."""
    result = run(["ninja", "-C", str(build_dir), "-t", "targets", "all"], timeout=600)
    if result.returncode != 0:
        raise Refusal(f"ninja -t targets failed in {build_dir}: {result.stderr.strip()[:200]}")
    outputs = {}
    for line in result.stdout.splitlines():
        name, sep, _ = line.rpartition(": ")
        if not sep or not name:
            raise Refusal(f"cannot parse ninja target line {line[:120]!r}")
        absolute = name if os.path.isabs(name) else os.path.join(str(build_dir), name)
        outputs[os.path.normpath(absolute)] = name
    return outputs


def bring_up_to_date(build_dir: Path, generated: set[str], label: str) -> None:
    """Have ninja build every generated file the compilations read.

    ninja's own graph decides, so generator headers, linked libraries, restat
    rules and a pending CMake re-run all count. A dry run cannot answer this here:
    CMake's glob verification step is always dirty in a dry run, so ninja -n never
    reports a clean tree. A file the graph does not produce is written by CMake
    at configure time and is refreshed by that re-run. If the build reconfigures
    itself, the compilation database already read is stale and the gate stops.
    """
    outputs = ninja_outputs(build_dir)
    targets = sorted(outputs[path] for path in generated if path in outputs) or ["build.ninja"]
    database = build_dir / "compile_commands.json"
    try:
        before = database.read_bytes()
    except OSError:
        raise Refusal(f"{label}: {database} is missing") from None
    result = run(["ninja", "-C", str(build_dir), *targets], timeout=7200)
    if result.returncode != 0:
        tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-6:])
        raise Refusal(f"{label}: building the generated files failed in {build_dir}\n{tail}")
    try:
        after = database.read_bytes()
    except OSError:
        raise Refusal(f"{label}: {database} disappeared during the build") from None
    if after != before:
        raise Refusal(f"{label}: {build_dir} reconfigured itself; run the gate again")


def system_directories(tools: Tools) -> list[str]:
    """The compiler's own include search directories, resolved."""
    result = run([tools.clangxx, "-E", "-x", "c++", "-v", "/dev/null"])
    if result.returncode != 0:
        raise Refusal(f"cannot list the compiler's include directories: {result.stderr[:200]}")
    lines = result.stderr.splitlines()
    try:
        start = lines.index("#include <...> search starts here:") + 1
        end = lines.index("End of search list.", start)
    except ValueError:
        raise Refusal("unexpected output from the compiler's -v include listing") from None
    directories = [os.path.realpath(line.strip()) for line in lines[start:end] if line.strip()]
    if not directories:
        raise Refusal("the compiler reports no system include directories")
    return directories


def check_contained(
    deps: dict[Entry, set[str]],
    side: tuple[Path, Path],
    other: tuple[Path, Path],
    system: list[str],
    label: str,
) -> None:
    """Every file a compilation reads resolves into its own checkout, build or system dirs.

    The most specific matching directory decides, so the other side's checkout or
    build is refused even where it nests inside this side's, as a worktree inside
    the main checkout does, and this side's own files are allowed where it nests
    inside the other's.
    """
    own = [os.path.realpath(str(side[0])), os.path.realpath(str(side[1]))]
    theirs = [os.path.realpath(str(other[0])), os.path.realpath(str(other[1]))]
    if set(own) & set(theirs):
        raise Refusal(f"{label}: the two sides share a checkout or build directory")
    bases = [(base, True) for base in own + system] + [(base, False) for base in theirs]

    def permitted(real: str) -> bool:
        matches = [
            (len(base), ok) for base, ok in bases if real == base or real.startswith(base + "/")
        ]
        return bool(matches) and max(matches)[1]

    resolved: dict[str, bool] = {}
    for entry, paths in deps.items():
        for path in paths:
            if path not in resolved:
                resolved[path] = permitted(os.path.realpath(path))
            if not resolved[path]:
                raise Refusal(
                    f"{label}: compilation of {entry.file} reads {path} "
                    f"({os.path.realpath(path)}), outside its checkout, build and system directories"
                )


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
    if document.get("version") != PARSE_SCHEMA_VERSION:
        raise Refusal(f"{label}: parse output version {document.get('version')!r} is not supported")
    reports = [read_report(row, side_root, build_dir, label) for row in rows]
    if result.returncode == 0 and reports:
        raise Refusal(f"{label}: parse exited 0 but printed {len(reports)} reports")
    if result.returncode == 2 and not reports:
        raise Refusal(f"{label}: parse exited 2 but the report list is empty")
    return reports


def read_report(row: object, side_root: Path, build_dir: Path, label: str) -> Report:
    """One parsed report, every field checked; an unknown checker is not "advisory"."""

    def bad(why: str) -> Refusal:
        return Refusal(f"{label}: {why} in report {str(row)[:200]}")

    if not isinstance(row, dict):
        raise bad("not an object")
    analyzer, checker = row.get("analyzer_name"), row.get("checker_name")
    if analyzer not in ANALYZERS:
        raise bad(f"unknown analyzer {analyzer!r}")
    if checker not in EXPECTED_CHECKERS[analyzer]:
        raise bad(f"checker {checker!r} is not enabled for {analyzer}")
    line, column = row.get("line"), row.get("column")
    if type(line) is not int or type(column) is not int or line < 1 or column < 1:
        raise bad("line or column is not a positive integer")
    digest = row.get("report_hash")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]+", digest):
        raise bad("report_hash is not a hex string")
    location = row.get("file")
    original = location.get("original_path") if isinstance(location, dict) else None
    if not isinstance(original, str) or not os.path.isabs(original):
        raise bad("file.original_path is not an absolute path")
    message = row.get("message", "")
    if not isinstance(message, str):
        raise bad("message is not a string")
    # The build directory first: it may sit inside the checkout under a name that
    # differs between the sides.
    normal = os.path.normpath(original)
    build_rel = relative(normal, build_dir)
    if build_rel is not None:
        path = f"<build>/{build_rel}"
    else:
        path = relative(normal, side_root) or original
    return Report(checker, analyzer, path, line, column, digest, message)


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

# A later directive is a separate suppression, never part of the preceding
# reason. clang-tidy recognises multiple NOLINTs in one comment; consuming the
# whole line would let a valid first directive conceal a bare NOLINT or range.
SUPPRESSION_START = r"NOLINT|codechecker_(?:suppress|false_positive|intentional|confirmed)"
SUPPRESSION_REST = rf"(?P<rest>.*?)(?={SUPPRESSION_START}|$)"
NOLINT_RE = re.compile(
    r"NOLINT(?P<kind>NEXTLINE|BEGIN|END)?(?P<checks>\([^)]*\))?" + SUPPRESSION_REST
)
CODECHECKER_RE = re.compile(
    r"codechecker_(?P<kind>suppress|false_positive|intentional|confirmed)"
    r"\s*(?P<checks>\[[^\]]*\])?" + SUPPRESSION_REST
)


@dataclass(frozen=True)
class Suppression:
    path: str
    line: int
    text: str
    covers: frozenset[int]


def find_suppressions(
    path: str, lines: list[str]
) -> tuple[list[Suppression], list[str], list[str]]:
    """(line suppressions, their problems, problems that hold for the whole file).

    Only three forms exist: same-line NOLINT(check): reason, NOLINTNEXTLINE(check):
    reason, and a codechecker_<kind> [check] reason comment on the line above. A
    NOLINTBEGIN/NOLINTEND range can cover lines far from where it is written, so
    any range in a changed file is refused, whatever its checks and reason.
    """
    found: list[Suppression] = []
    problems: list[str] = []
    file_problems: list[str] = []
    known = EXPECTED_CHECKERS["clang-tidy"] | EXPECTED_CHECKERS["clangsa"]
    for number, line in enumerate(lines, start=1):
        for regex in (NOLINT_RE, CODECHECKER_RE):
            for match in regex.finditer(line):
                kind = match.group("kind") or ""
                where = f"{path}:{number}"
                if regex is NOLINT_RE and kind in ("BEGIN", "END"):
                    file_problems.append(f"{where}: NOLINT{kind} ranges are not allowed")
                    continue
                if regex is CODECHECKER_RE and kind == "confirmed":
                    continue
                covers = {number} if regex is NOLINT_RE and kind == "" else {number + 1}
                checks_text = (match.group("checks") or "")[1:-1]
                checks = {c.strip() for c in checks_text.split(",") if c.strip()}
                rest = match.group("rest").strip().lstrip(":").strip().removesuffix("*/").strip()
                if not checks:
                    problems.append(f"{where}: suppression without an exact check name")
                elif checks - known or any("*" in c or c == "all" for c in checks):
                    problems.append(
                        f"{where}: suppression names {sorted(checks)}, not exact enabled checks"
                    )
                elif not rest:
                    problems.append(f"{where}: suppression without a reason")
                found.append(Suppression(path, number, line.strip(), frozenset(covers)))
    return found, problems, file_problems


def audit_suppressions(root: Path, change: Change) -> list[Suppression]:
    accepted: list[Suppression] = []
    problems: list[str] = []
    for path, changed in sorted(change.changed_lines.items()):
        if not is_cpp(path) or is_excluded(path) or not (root / path).is_file():
            continue
        lines = (root / path).read_text(errors="replace").splitlines()
        found, issues, file_issues = find_suppressions(path, lines)
        problems.extend(file_issues)
        for suppression in found:
            if suppression.line in changed or suppression.covers & changed:
                accepted.append(suppression)
        relevant = {s.line for s in found if s.line in changed or s.covers & changed}
        for issue in issues:
            line = int(issue[len(path) + 1 :].split(":", 1)[0])
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


def identity(entry: Entry, side_root: Path, side_build: Path) -> tuple[str, str, str]:
    """A compilation's identity with its checkout, build directory and output factored out.

    The working directory is part of it: the same relative -I in two directories
    names two different include trees.
    """

    def neutral(text: str) -> str:
        # The build directory may sit inside the checkout, so replace it first.
        return text.replace(str(side_build), "<build>").replace(str(side_root), "<root>")

    arguments = list(entry.arguments)
    for index, arg in enumerate(arguments):
        if arg == "-o" and index + 1 < len(arguments):
            arguments[index + 1] = "<output>"
        elif arg.startswith("-o") and len(arg) > 2:
            arguments[index] = "-o<output>"
    return (
        neutral(entry.file),
        neutral(os.path.normpath(entry.directory)),
        shlex.join(neutral(arg) for arg in arguments[1:]),
    )


def representatives(
    entries: list[Entry], side_root: Path, side_build: Path
) -> dict[tuple[str, str], Entry]:
    """One compilation per identity.

    A source built with identical arguments for several targets (a shared test
    main, say) differs only in its output; CodeChecker cannot tell such runs
    apart and they analyse identically, so the one with the first output stands
    for all of them.
    """
    chosen: dict[tuple[str, str], Entry] = {}
    for entry in sorted(entries, key=lambda e: e.output):
        chosen.setdefault(identity(entry, side_root, side_build), entry)
    return chosen


# --- main -------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="origin/main", help="branch the change merges into")
    parser.add_argument("--build-dir", type=Path, help="build of this checkout (default: build)")
    parser.add_argument(
        "--base-build-dir",
        type=Path,
        required=True,
        help="build of a separate checkout that sits cleanly at the merge base",
    )
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
    install_signal_handlers()
    try:
        return gate(root, args)
    except Refusal as error:
        print(f"static-analysis: REFUSED: {error}", file=sys.stderr)
        return EXIT_REFUSED


@dataclass
class Side:
    """One checkout and its own build, as the analysis sees them."""

    label: str
    root: Path
    build: Path
    entries: list[Entry]
    deps: dict[Entry, set[str]]
    generated: set[str]

    def generated_by_key(self) -> dict[str, str]:
        """Generated files keyed by their place in the checkout or the build."""
        keyed = {}
        for path in self.generated:
            in_build = relative(path, self.build)
            keyed[
                f"<build>/{in_build}" if in_build is not None else str(relative(path, self.root))
            ] = path
        return keyed


def prepare_side(label: str, root: Path, build: Path, tools: Tools, work: Path) -> Side:
    entries = analysable(load_database(build, root), root, build)
    generated = side_generated(scan_dependencies(entries, tools, work, label), root, build)
    bring_up_to_date(build, generated, label)
    # Regenerated files may include different headers; scan what is there now.
    deps = scan_dependencies(entries, tools, work, label)
    if side_generated(deps, root, build) != generated:
        raise Refusal(f"{label}: the build changed which generated files are read; run again")
    return Side(label, root, build, entries, deps, generated)


def generated_changes(head: Side, base: Side) -> tuple[set[str], set[str]]:
    """Generated files whose content differs between the sides, as each side's paths.

    A change to a generator input (a schema, a contract, the CMake configuration)
    reaches the analysis only through what is generated from it, so the
    generated files themselves are compared; one missing on a side differs too.
    """
    head_files, base_files = head.generated_by_key(), base.generated_by_key()
    changed_head, changed_base = set(), set()
    for key in sorted(set(head_files) | set(base_files)):
        one, two = head_files.get(key), base_files.get(key)
        try:
            same = (
                one is not None
                and two is not None
                and Path(one).read_bytes() == Path(two).read_bytes()
            )
        except OSError as error:
            raise Refusal(f"cannot compare generated file {key}: {error}") from None
        if not same:
            if one is not None:
                changed_head.add(one)
            if two is not None:
                changed_base.add(two)
    return changed_head, changed_base


def side_generated(deps: dict[Entry, set[str]], root: Path, build: Path) -> set[str]:
    in_build, ignored = generated_files(deps, root, build)
    return set(in_build) | {os.path.normpath(str(root / p)) for p in ignored}


def select_side(
    side: Side, changed: set[str], uncovered: set[str], generated: set[str] = frozenset()
) -> tuple[set[Entry], set[str]]:
    """The side's compilations a change reaches, refusing what it cannot reach.

    Changed generated files (absolute paths) select every compilation that reads
    them, which for a generated source includes its own compilation.
    """
    sources = {p for p in changed if Path(p).suffix in SOURCE_SUFFIXES}
    headers = {p for p in changed if Path(p).suffix in HEADER_SUFFIXES}
    known = {relative(entry.file, side.root) for entry in side.entries}
    missing = sorted(p for p in sources if p not in known)
    if missing:
        raise Refusal(
            f"{side.label}: changed sources missing from {side.build}/compile_commands.json: "
            f"{missing}; reconfigure that build"
        )
    chosen, orphans = select(side.entries, side.deps, side.root, sources, headers)
    for path in generated:
        # A compilation's dependencies include its own source file.
        chosen |= {entry for entry, paths in side.deps.items() if path in paths}
    refused = sorted(orphans - uncovered)
    if refused:
        raise Refusal(
            f"{side.label}: changed headers no compilation includes: {refused}; "
            f"list them in {UNCOVERED_HEADERS}"
        )
    return chosen, orphans


def choose(
    head: Side,
    base: Side,
    changed: tuple[set[str], set[str]],
    generated: tuple[set[str], set[str]],
    uncovered: set[str],
    full: bool,
) -> tuple[list[Entry], list[Entry], set[str]]:
    """(HEAD compilations, BASE compilations, uncovered headers) to analyse.

    Coverage is validated on both sides in every mode, so --full cannot hide a
    changed source missing from a database or a header nothing includes. A
    compilation whose identity exists on one side only (added, removed, or built
    with different arguments) is selected on the side that has it, whether or
    not any file changed.
    """
    head_selected, head_orphans = select_side(head, changed[0], uncovered, generated[0])
    base_selected, base_orphans = select_side(base, changed[1], uncovered, generated[1])
    if full:
        head_selected, base_selected = set(head.entries), set(base.entries)
    head_ids = representatives(head.entries, head.root, head.build)
    base_ids = representatives(base.entries, base.root, base.build)
    configurations = (head_ids.keys() - base_ids.keys()) | (base_ids.keys() - head_ids.keys())
    if configurations:
        print(f"static-analysis: {len(configurations)} compilations differ between the sides")
        if 2 * len(configurations) > max(len(head_ids), len(base_ids)):
            print("static-analysis: the two builds look differently configured")
    wanted = (
        {identity(e, head.root, head.build) for e in head_selected}
        | {identity(e, base.root, base.build) for e in base_selected}
        | configurations
    )
    head_run = sorted((head_ids[i] for i in wanted if i in head_ids), key=lambda e: e.output)
    base_run = sorted((base_ids[i] for i in wanted if i in base_ids), key=lambda e: e.output)
    return head_run, base_run, head_orphans | base_orphans


def gate(root: Path, args: argparse.Namespace) -> int:
    build_dir = (args.build_dir or root / "build").resolve()
    base_build = args.base_build_dir.resolve()
    if args.jobs < 1 or args.timeout < 1:
        raise Refusal("--jobs and --timeout must be positive")
    tools = resolve_tools(args.llvm_bin, args.codechecker)
    check_rule_set(root, tools)
    print(
        f"static-analysis: rule set {fingerprint()}, CodeChecker {CODECHECKER_VERSION}, LLVM {LLVM_VERSION}"
    )
    merge_base = git(root, "merge-base", args.base, "HEAD").strip()
    base_root = configured_checkout(base_build)
    check_clean_at(base_root, merge_base)
    change = collect_change(root, merge_base)
    work = Path(tempfile.mkdtemp(prefix="tos-static-analysis-")).resolve()
    try:
        controls = run_controls(root, tools, work, args.jobs, args.timeout)
        print(f"static-analysis: positive controls reported all {controls} marked findings")
        suppressions = audit_suppressions(root, change)
        cpp_head = {p for p in change.head_paths if is_cpp(p) and not is_excluded(p)}
        cpp_base = {p for p in change.base_paths if is_cpp(p) and not is_excluded(p)}

        # Both sides are always prepared: a change with no C/C++ file can still
        # change generated C/C++, which only comparing the built sides reveals.
        system = system_directories(tools)
        head = prepare_side("HEAD", root, build_dir, tools, work)
        base = prepare_side("BASE", base_root, base_build, tools, work)
        check_contained(head.deps, (root, build_dir), (base_root, base_build), system, "HEAD")
        check_contained(base.deps, (base_root, base_build), (root, build_dir), system, "BASE")
        generated_head, generated_base = generated_changes(head, base)
        for path in sorted(generated_head | generated_base):
            print(f"static-analysis: generated file differs between the sides: {path}")

        head_run, base_run, orphans = choose(
            head,
            base,
            (cpp_head, cpp_base),
            (generated_head, generated_base),
            load_uncovered(root),
            args.full,
        )
        print(
            f"static-analysis: HEAD {len(head_run)} compilations, BASE {len(base_run)} "
            f"(merge base {merge_base[:12]} in {base_root})"
        )
        for header in sorted(orphans):
            print(f"static-analysis: UNCOVERED {header} (no compilation includes it)")

        head_reports: list[Report] = []
        base_reports: list[Report] = []
        if head_run:
            analyze(head_run, tools, work / "head", args.jobs, args.timeout, "HEAD")
            head_reports = parse_reports(work / "head", tools, root, build_dir, "HEAD")
        if base_run:
            analyze(base_run, tools, work / "base", args.jobs, args.timeout, "BASE")
            base_reports = parse_reports(work / "base", tools, base_root, base_build, "BASE")
        return judge(head_reports, base_reports, suppressions)
    finally:
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
