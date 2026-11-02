#!/usr/bin/env python3
"""Hold the tosctl Nix package's inputs to their one list, assembly/nix/tosctl/inputs.json.

Two checks, both fail-closed:

1. The CI workflow's trigger paths are exactly the ones inputs.json implies: the Nix files,
   every source entry (directories as "dir/**"), the exclusions as negations, and the
   workflow itself. Editing docs or an unrelated contract does not start the VM run, and a
   new source entry cannot be left untriggered.
2. Every include_str!/include_bytes! target of the crates the package builds or tests
   resolves inside the package source. Only a string literal or
   concat!(env!("CARGO_MANIFEST_DIR"), "...") is resolved; any other expression is an error.
   A test-only include of a crate whose tests the package does not run must be listed in
   inputs.json "test_only_includes" with a reason; the list is checked for stale entries.

usage: check-inputs.py [REPOSITORY_ROOT]
"""

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[3]).resolve()
INPUTS = ROOT / "assembly/nix/tosctl/inputs.json"
WORKFLOW = ROOT / ".github/workflows/tosctl-nixos.yml"
WORKSPACE = ROOT / "tosctl/src"
# include!, include_str! and include_bytes! all read a file at compile time; a #[path]
# attribute makes a module's source another file.
INCLUDE = re.compile(r"\binclude(?:_str|_bytes)?!\s*\(")
PATH_ATTRIBUTE = re.compile(r'#\[\s*path\s*=\s*"((?:[^"\\]|\\.)*)"\s*\]')
LITERAL = re.compile(r'\s*"((?:[^"\\]|\\.)*)"\s*\)')
MANIFEST = re.compile(
    r'\s*concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)\s*\)'
)


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def expected_paths(inputs):
    positive = list(inputs["nix_files"])
    for entry in inputs["source"]:
        positive.append(entry + "/**" if (ROOT / entry).is_dir() else entry)
    positive.append(WORKFLOW.relative_to(ROOT).as_posix())
    negative = []
    for entry in inputs["exclude"]:
        negative.append("!" + entry + ("/**" if (ROOT / entry).is_dir() else ""))
    for entry in inputs["source"]:
        if (ROOT / entry).is_dir():
            negative += [f"!{entry}/**/*{suffix}" for suffix in inputs["exclude_suffixes"]]
    return positive, negative


def workflow_paths():
    lines = WORKFLOW.read_text().splitlines()
    starts = [i for i, line in enumerate(lines) if re.fullmatch(r"\s+paths: &inputs\s*", line)]
    require(len(starts) == 1, "workflow must define exactly one 'paths: &inputs' list")
    paths = []
    for line in lines[starts[0] + 1 :]:
        if re.fullmatch(r"\s+#.*", line):
            continue
        match = re.fullmatch(r"\s+- '([^']+)'\s*", line)
        if not match:
            break
        paths.append(match.group(1))
    require(paths, "the workflow 'paths: &inputs' list is empty")
    require(
        sum(1 for line in lines if re.fullmatch(r"\s+paths: \*inputs\s*", line)) == 1,
        "the push trigger must reuse the same '*inputs' list",
    )
    return paths


def check_workflow(inputs):
    positive, negative = expected_paths(inputs)
    actual = workflow_paths()
    split = next((i for i, path in enumerate(actual) if path.startswith("!")), len(actual))
    require(
        all(path.startswith("!") for path in actual[split:]),
        "workflow negations must follow every positive path",
    )
    require(
        sorted(actual[:split]) == sorted(positive),
        f"workflow positive paths differ from inputs.json:\n  expected {sorted(positive)}\n"
        f"  actual   {sorted(actual[:split])}",
    )
    require(
        sorted(actual[split:]) == sorted(negative),
        f"workflow negations differ from inputs.json:\n  expected {sorted(negative)}\n"
        f"  actual   {sorted(actual[split:])}",
    )
    return len(actual)


def covered(path, inputs):
    relative = path.relative_to(ROOT).as_posix()
    inside = any(relative == e or relative.startswith(e + "/") for e in inputs["source"])
    excluded = any(relative == e or relative.startswith(e + "/") for e in inputs["exclude"])
    suffix = any(relative.endswith(s) for s in inputs["exclude_suffixes"])
    return inside and not excluded and not suffix and path.exists()


def packages():
    """Packages reachable through local path dependencies, by name: workspace members and
    path dependencies outside the member list (for example a build-dependency)."""
    workspace = tomllib.loads((WORKSPACE / "Cargo.toml").read_text())
    shared = workspace.get("workspace", {}).get("dependencies", {})
    found, pending = {}, [WORKSPACE / member for member in workspace["workspace"]["members"]]
    seen = set()
    while pending:
        directory = pending.pop().resolve()
        if directory in seen:
            continue
        seen.add(directory)
        manifest = tomllib.loads((directory / "Cargo.toml").read_text())

        def local(table):
            names = set()
            for name, spec in manifest.get(table, {}).items():
                base = directory
                if isinstance(spec, dict) and spec.get("workspace"):
                    spec, base = shared.get(name, {}), WORKSPACE
                if isinstance(spec, dict) and "path" in spec:
                    names.add(spec.get("package", name))
                    pending.append(base / spec["path"])
            return names

        found[manifest["package"]["name"]] = {
            "directory": directory,
            # Optional path dependencies are kept: over-approximating the closure only adds
            # files to check, it cannot let one escape.
            "normal": local("dependencies") | local("build-dependencies"),
            "dev": local("dev-dependencies"),
        }
    return found


def closure(found, tested):
    """Packages compiled by `cargo build -p tosctl` plus `cargo test` of the tested ones."""
    built, tests, pending = set(), set(tested), ["tosctl", *tested]
    while pending:
        name = pending.pop()
        require(name in found, f"package {name} is not reachable by a local path")
        if name in built:
            continue
        built.add(name)
        pending += found[name]["normal"]
        if name in tests:
            pending += found[name]["dev"]
    return built, tests


def sources(package, tested):
    directory = package["directory"]
    targets = ["src", "build.rs"] + (["tests", "examples", "benches"] if tested else [])
    for target in targets:
        path = directory / target
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from sorted(path.rglob("*.rs"))


def includes(path):
    text = path.read_text()
    for match in PATH_ATTRIBUTE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if not text[: match.start()].rsplit("\n", 1)[-1].lstrip().startswith("//"):
            yield line, (path.parent / match.group(1)).resolve()
    for match in INCLUDE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if text[: match.start()].rsplit("\n", 1)[-1].lstrip().startswith("//"):
            continue
        rest = text[match.end() :]
        literal = LITERAL.match(rest)
        manifest = MANIFEST.match(rest)
        if literal:
            yield line, (path.parent / literal.group(1)).resolve()
        elif manifest:
            yield line, None, manifest.group(1)
        else:
            yield line, False


def inside_cfg_test_block(path, line):
    """True when `line` lies inside an item marked `#[cfg(test)]` and opened by `mod NAME {`."""
    lines = path.read_text().splitlines()
    for index, text in enumerate(lines):
        if text.strip() != "#[cfg(test)]" or index + 1 >= len(lines):
            continue
        if not re.fullmatch(r"\s*(pub(\(crate\))?\s+)?mod\s+\w+\s*\{\s*", lines[index + 1]):
            continue
        depth, start = 0, index + 1
        for end in range(start, len(lines)):
            depth += lines[end].count("{") - lines[end].count("}")
            if depth == 0:
                if start < line - 1 <= end:
                    return True
                break
    return False


def module_file(declaring, name):
    """The file a `mod NAME;` in `declaring` loads, per the Rust module path rules."""
    base = declaring.parent
    if declaring.name not in ("lib.rs", "main.rs", "mod.rs"):
        base = base / declaring.stem
    for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
        if candidate.is_file():
            return candidate.resolve()
    return None


class References:
    """Every place that makes another file compile: `mod NAME;`, `#[path = ...] mod` and
    include!/include_str!/include_bytes!. A line is test-only when it lies in a
    #[cfg(test)] module, or when every reference to its file is itself test-only."""

    def __init__(self, files):
        self.by_target = {}
        for source in files:
            lines = source.read_text().splitlines()
            for index, text in enumerate(lines):
                previous = lines[index - 1].strip() if index else ""
                declared = re.fullmatch(r"\s*(?:pub(?:\(crate\))?\s+)?mod\s+(\w+)\s*;\s*", text)
                if declared and not previous.startswith("#[path"):
                    target = module_file(source, declared.group(1))
                    if target:
                        self.add(target, source, index + 1, previous == "#[cfg(test)]")
            for line, *target in includes(source):
                if target and target[0]:
                    before = lines[line - 2].strip() if line >= 2 else ""
                    self.add(target[0], source, line, before == "#[cfg(test)]")

    def add(self, target, source, line, marked):
        self.by_target.setdefault(target.resolve(), []).append((source.resolve(), line, marked))

    def test_only_line(self, source, line, seen=frozenset()):
        return inside_cfg_test_block(source, line) or self.test_only_file(source, seen)

    def test_only_file(self, path, seen=frozenset()):
        path = path.resolve()
        if path in seen:
            return False
        references = self.by_target.get(path, [])
        return bool(references) and all(
            marked or self.test_only_line(source, line, seen | {path})
            for source, line, marked in references
        )


def check_includes(inputs):
    found = packages()
    built, tested = closure(found, inputs["tested_packages"])
    allowed = {(a["file"], a["target"]): a for a in inputs.get("test_only_includes", [])}
    used, failures, count, pending, scanned = set(), [], 0, [], {}
    for name in sorted(built):
        package = found[name]
        queue, visited = list(sources(package, name in tested)), set()
        while queue:
            source = queue.pop(0).resolve()
            if source in visited or not source.is_file():
                continue
            visited.add(source)
            scanned.setdefault(package["directory"], set()).add(source)
            for line, *target in includes(source):
                count += 1
                where = f"{source.relative_to(ROOT)}:{line}"
                if target == [False]:
                    failures.append(f"{where}: include argument is not a literal path")
                    continue
                if target[0] is None:
                    resolved = (package["directory"] / target[1].lstrip("/")).resolve()
                else:
                    resolved = target[0]
                require(resolved.is_relative_to(ROOT), f"{where}: include outside the repository")
                if resolved.suffix == ".rs":
                    queue.append(resolved)
                if covered(resolved, inputs):
                    continue
                key = (source.relative_to(ROOT).as_posix(), resolved.relative_to(ROOT).as_posix())
                if key in allowed and name not in tested:
                    used.add(key)
                    pending.append((source, line, where, package["directory"]))
                    continue
                failures.append(f"{where}: {key[1]} is not in the package source")
    # Resolved over every Rust file of the crate plus the files the scan followed into.
    for source, line, where, directory in pending:
        files = set(p.resolve() for p in directory.rglob("*.rs")) | scanned.get(directory, set())
        if not References(files).test_only_line(source, line):
            failures.append(f"{where}: allow-listed include is not test-only code")
    stale = sorted(set(allowed) - used)
    require(not stale, f"test_only_includes entries no longer needed: {stale}")
    require(not failures, "uncovered embedded files:\n  " + "\n  ".join(failures))
    return len(built), count


def main():
    inputs = json.loads(INPUTS.read_text())
    try:
        paths = check_workflow(inputs)
        crates, count = check_includes(inputs)
    except Failure as error:
        print(f"TOSCTL_NIX_INPUTS_FAILED: {error}", file=sys.stderr)
        return 1
    print(f"TOSCTL_NIX_INPUTS_OK: {paths} workflow paths, {crates} crates, {count} embedded files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
