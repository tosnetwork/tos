#!/usr/bin/env python3
"""Relevance and verdict for the platform matrix (.github/workflows/platform-matrix.yml).

`changes` decides whether a change can affect a platform build. It fails safe: a
change is irrelevant only when the diff succeeded, listed at least one file, and
every listed file is documentation. Any error, an empty list, a new branch or a
force push makes the change relevant.

`gate` judges the members' results against the set the event requires: every
platform member for a relevant pull request or push, every member for the nightly
run or a manual dispatch, none for a documentation-only change. An expected member
passes only by succeeding; skipped, cancelled or failed fails the gate, and so does
an unexpected member that failed, a member missing from `needs`, or a job in
`needs` that the matrix does not define.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = HERE / "platform-matrix.json"
ZERO_SHA = "0" * 40
FULL_EVENTS = ("schedule", "workflow_dispatch")


def load_config(path: Path = CONFIG) -> dict:
    return json.loads(path.read_text())


def glob_regex(pattern: str) -> re.Pattern[str]:
    """A path glob in the GitHub sense: `*` stays within a directory, `**` crosses them."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def is_documentation(path: str, patterns: list[str]) -> bool:
    return any(glob_regex(p).match(path) for p in patterns)


def decide(files: list[str] | None, patterns: list[str]) -> tuple[bool, str]:
    """(relevant, reason). Unknown or empty file lists are relevant."""
    if files is None:
        return True, "the changed files could not be determined"
    if not files:
        return True, "the diff listed no files"
    code = [f for f in files if not is_documentation(f, patterns)]
    if code:
        return True, f"{len(code)} of {len(files)} changed files can affect a build"
    return False, f"documentation-only change ({len(files)} files)"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def commit_exists(sha: str) -> bool:
    if not re.fullmatch(r"[0-9a-f]{40}", sha or "") or sha == ZERO_SHA:
        return False
    return (
        subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
        ).returncode
        == 0
    )


def diff_paths(old: str, new: str) -> list[str]:
    """Every path the diff touches. Without rename detection a rename is its
    deletion and its addition, so moving a source into doc/ still names the source."""
    listed = git("diff", "--name-only", "--no-renames", "-z", old, new)
    return [path for path in listed.split("\0") if path]


def changed_files(event: str, env: dict[str, str]) -> list[str] | None:
    """The files a change touches, or None when that cannot be known."""
    if event == "pull_request":
        base_ref, head = env.get("BASE_REF", ""), env.get("HEAD_SHA", "")
        if not base_ref or not commit_exists(head):
            return None
        base = git("merge-base", f"origin/{base_ref}", head).strip()
        return diff_paths(base, head)
    if event == "push":
        before, after = env.get("BEFORE", ""), env.get("AFTER", "")
        if not commit_exists(before) or not commit_exists(after):
            return None
        return diff_paths(before, after)
    return None


def write_output(name: str, value: str) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def summary(text: str) -> None:
    print(text)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")


def run_changes(event: str, env: dict[str, str], config: dict) -> tuple[bool, str]:
    if event in FULL_EVENTS:
        return True, f"{event} runs every member"
    try:
        files = changed_files(event, env)
    except (subprocess.CalledProcessError, OSError) as error:
        return True, f"the diff failed ({error.__class__.__name__}); treated as relevant"
    return decide(files, config["documentation_only"])


def expected_members(event: str, relevant: bool, config: dict) -> set[str]:
    if not relevant:
        return set()
    tiers = {"platform"} | ({"nightly"} if event in FULL_EVENTS else set())
    return {name for name, member in config["members"].items() if member["tier"] in tiers}


def evaluate(event: str, needs: dict, config: dict) -> tuple[bool, list[str]]:
    """(passed, report lines)."""
    problems: list[str] = []
    changes = needs.get("changes")
    relevant = None
    if not isinstance(changes, dict) or changes.get("result") != "success":
        problems.append(
            f"the relevance job did not succeed ({(changes or {}).get('result', 'missing')})"
        )
    else:
        value = (changes.get("outputs") or {}).get("relevant")
        if value not in ("true", "false"):
            problems.append(f"the relevance job gave no valid answer ({value!r})")
        else:
            relevant = value == "true"
    if event in FULL_EVENTS and relevant is False:
        # A full run always runs every member; "not relevant" can only be an error.
        problems.append(f"the relevance job answered false for a full {event} run")
        relevant = True
    members = config["members"]
    for job in sorted(set(needs) - set(members) - {"changes"}):
        problems.append(f"{job} is in needs but not a matrix member")
    expected = expected_members(event, relevant, config) if relevant is not None else set(members)
    lines = ["| member | expected | result |", "|---|---|---|"]
    for name in sorted(members):
        result = (needs.get(name) or {}).get("result", "missing")
        is_expected = name in expected
        lines.append(f"| {name} | {'yes' if is_expected else 'no'} | {result} |")
        if name not in needs:
            problems.append(f"{name} is missing from needs")
        elif is_expected and result != "success":
            problems.append(f"{name} was expected to succeed and is {result}")
        elif not is_expected and result in ("failure", "cancelled"):
            problems.append(f"{name} ran although not expected and is {result}")
    if relevant is False and not problems:
        lines.insert(0, "not applicable: documentation-only change\n")
    lines.extend(f"- {p}" for p in problems)
    return not problems, lines


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("changes")
    sub.add_parser("gate")
    args = parser.parse_args(argv)
    config = load_config()
    event = os.environ.get("EVENT_NAME", "")
    if args.command == "changes":
        try:
            relevant, reason = run_changes(event, dict(os.environ), config)
        except Exception as error:  # noqa: BLE001 - any failure must fail safe
            relevant, reason = True, f"relevance failed ({error!r}); treated as relevant"
        write_output("relevant", "true" if relevant else "false")
        summary(f"relevant={'true' if relevant else 'false'}: {reason}")
        return 0
    try:
        needs = json.loads(os.environ.get("NEEDS_JSON", ""))
    except json.JSONDecodeError:
        summary("platform gate: needs is not valid JSON")
        return 1
    passed, lines = evaluate(event, needs if isinstance(needs, dict) else {}, config)
    summary("\n".join(lines))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
