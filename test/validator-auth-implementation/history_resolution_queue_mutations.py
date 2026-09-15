"""Compile history-resolution queue mutations and require isolated named failures."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-anchor-cache.h")
BINARY = Path("build-p0/validator/auth/test-p0-history-resolution-queue")
SANITIZED = Path("build-p0-sanitized/validator/auth/test-p0-history-resolution-queue")

MUTATIONS = [
    ("active-coordinate-dedup", "active-duplicates-do-not-requeue",
     '      if (!active_coordinates_.contains(coordinate)) {\n'
     '        pending_.insert(coordinate);\n'
     '      }',
     '      pending_.insert(coordinate);', []),
    ("pending-coordinate-dedup", "pending-duplicates-coalesce",
     '  std::set<std::uint32_t> active_coordinates_;\n'
     '  std::set<std::uint32_t> pending_;',
     '  std::multiset<std::uint32_t> active_coordinates_;\n'
     '  std::multiset<std::uint32_t> pending_;', ["idle-request-starts-resolution"]),
    ("busy-request-retained", "busy-request-is-retained",
     '    if (active_ || pending_.empty()) {\n'
     '      return std::nullopt;\n'
     '    }',
     '    if (pending_.empty()) {\n'
     '      return std::nullopt;\n'
     '    }', ["pending-duplicates-coalesce", "completion-drains-pending",
              "drained-batch-starts-next-resolution"]),
    ("completion-drains", "completion-drains-pending",
     '    return next;\n'
     '  }\n\n'
     '  bool active() const {',
     '    return std::nullopt;\n'
     '  }\n\n'
     '  bool active() const {', ["pending-duplicates-coalesce", "drained-batch-starts-next-resolution"]),
    ("completion-clears-active", "completion-clears-inflight",
     '    active_ = false;\n'
     '    active_coordinates_.clear();',
     '', ["drained-batch-starts-next-resolution", "empty-completion-does-not-loop"]),
    ("empty-completion-stops", "empty-completion-does-not-loop",
     '    if (pending_.empty()) {\n'
     '      return std::nullopt;\n'
     '    }',
     '    if (pending_.empty()) {\n'
     '      return std::vector<std::uint32_t>{};\n'
     '    }', ["completion-clears-inflight"]),
]

SANITIZER_ENV = {
    "ASAN_OPTIONS": "detect_leaks=1:detect_stack_use_after_return=1",
    "UBSAN_OPTIONS": "halt_on_error=1",
}


def invoke(command: list[str], environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = None
    if environment:
        env = dict(os.environ)
        env.update(environment)
    return subprocess.run(command, capture_output=True, text=True, check=False, env=env)


def build(sanitized: bool = False) -> bool:
    tree = "build-p0-sanitized" if sanitized else "build-p0"
    binary = SANITIZED if sanitized else BINARY
    binary.unlink(missing_ok=True)
    return invoke(["cmake", "--build", tree, "--target", "test-p0-history-resolution-queue", "-j48"]).returncode == 0


def run(selector: str | None = None, sanitized: bool = False) -> subprocess.CompletedProcess[str]:
    command = [str(SANITIZED if sanitized else BINARY)]
    if selector:
        command.append(selector)
    return invoke(command, SANITIZER_ENV if sanitized else None)


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (result.returncode == 0 and result.stderr == "" and
            lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"] and
            sum(line.startswith("CASE_PASS ") for line in lines) == expected)


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (result.returncode == 1 and
            result.stdout.splitlines() == [f"SETUP_OK {case}"] and
            result.stderr.splitlines() == [f"ASSERTION_FAILED {case}"])


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("artifacts/history-resolution-queue-mutations")
    out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if not build():
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    listed = run("--list")
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or listed.stderr != "" or not cases:
        print("CASE-INVENTORY-FAILED", file=sys.stderr)
        return 1
    if not passing(run(), len(cases)):
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1
    if Path("build-p0-sanitized").is_dir():
        if not build(True) or not passing(run(sanitized=True), len(cases)):
            print("SANITIZED-BASELINE-NOT-PASSING", file=sys.stderr)
            return 1

    records: list[dict[str, object]] = []
    failures = 0
    try:
        for guard, case, before, after, companions in MUTATIONS:
            if original.count(before) != 1:
                print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
                failures += 1
                continue
            changed = original.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            compiled = build()
            named_run = run(case) if compiled else None
            named = named_run is not None and named_failure(named_run, case)
            spared = [name for name in cases if name != case and name not in companions]
            isolated = compiled and all(passing(run(name), 1) for name in spared)

            SOURCE.write_text(original)
            restored = build() and passing(run(), len(cases))
            record: dict[str, object] = {
                "guard": guard,
                "case": case,
                "declared_companions": companions,
                "edit_reached_source": reached,
                "compiled": compiled,
                "named_assertion_failed": named,
                "only_declared_cases_broke": isolated,
                "restored_baseline": restored,
                "source_unchanged": SOURCE.read_text() == original,
            }
            if named_run is not None:
                record.update({
                    "named_returncode": named_run.returncode,
                    "named_stdout": named_run.stdout,
                    "named_stderr": named_run.stderr,
                })
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "named_assertion_failed",
                                                "only_declared_cases_broke", "restored_baseline", "source_unchanged")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    if Path("build-p0-sanitized").is_dir():
        sanitized_restored = build(True) and passing(run(sanitized=True), len(cases))
        if not sanitized_restored:
            failures += 1
    (out / "mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
