#!/usr/bin/env python3
"""Every Linux build workflow has a trigger that can fire in this repository.

The workflows inherited with the tree named branches this repository does not
have (master, testnet), so the full arm64 build, both AppImage builds and the
other platforms never ran, and nothing said so. Linux x86-64 and arm64 are the
supported platforms; a build of either that cannot start is not coverage.

Checked for each .github/workflows/build-tos-linux-*.yml:
- a push or pull_request branch filter names only branches that exist here;
- at least one automatic trigger can fire: a push to such a branch, a pull
  request, a version tag or a schedule (dispatch alone does not count);
- the full shared builds run on every push to main, unfiltered by path:
  every list of what the build reads missed something, so neither a paths
  nor a paths-ignore filter is accepted.

Standard library only: this runs in the builder image before any Python
dependency is installed. The `on:` block is read by a small parser that
refuses every shape it does not know, so a gap in it fails here instead of
passing quietly.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
BRANCHES = {"main"}
SHARED_BUILDS = ("build-tos-linux-x86-64-shared.yml", "build-tos-linux-arm64-shared.yml")
EVENTS = {"push", "pull_request", "workflow_dispatch", "workflow_call", "schedule"}
LIST_KEYS = {"branches", "branches-ignore", "tags", "paths", "paths-ignore", "types"}


class UnsupportedTriggers(ValueError):
    pass


def _scalar(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    if not text or any(c in text for c in "{}[]&*!|>") or text[0] in "'\"":
        raise UnsupportedTriggers(f"unsupported scalar {text!r}")
    return text


def _inline_list(text: str) -> list[str]:
    text = text.strip()
    if not (text.startswith("[") and text.endswith("]")):
        raise UnsupportedTriggers(f"unsupported list {text!r}")
    body = text[1:-1].strip()
    return [_scalar(item) for item in body.split(",")] if body else []


def parse_on(text: str) -> dict[str, dict[str, list[str]] | None]:
    """The workflow's top-level `on:` block as {event: {key: [values]} or None}."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.fullmatch(r"on:\s*(#.*)?", line)), None)
    if start is None:
        if any(line.startswith(("on:", '"on":', "'on':", "true:")) for line in lines):
            raise UnsupportedTriggers("only a block-style `on:` mapping is supported")
        raise UnsupportedTriggers("no top-level `on:` block")
    events: dict[str, dict[str, list[str]] | None] = {}
    event = key = None
    for raw in lines[start + 1 :]:
        if "\t" in raw:
            raise UnsupportedTriggers("tab in the `on:` block")
        line = re.sub(r"\s+#.*$", "", raw).rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if indent == 2:
            m = re.fullmatch(r"([A-Za-z_]+):\s*(.*)", stripped)
            if not m or m.group(1) not in EVENTS:
                raise UnsupportedTriggers(f"unsupported event line {stripped!r}")
            if m.group(2):
                raise UnsupportedTriggers(f"unsupported inline event value {stripped!r}")
            event, key = m.group(1), None
            if event in events:
                raise UnsupportedTriggers(f"event {event} listed twice")
            events[event] = None
        elif indent == 4 and event is not None:
            if event == "schedule":
                if not re.fullmatch(r"- cron: .+", stripped):
                    raise UnsupportedTriggers(f"unsupported schedule entry {stripped!r}")
                continue
            m = re.fullmatch(r"([A-Za-z_-]+):\s*(.*)", stripped)
            if not m:
                raise UnsupportedTriggers(f"unsupported filter line {stripped!r}")
            spec = events[event] = events[event] or {}
            key = m.group(1)
            if event == "workflow_call":
                continue
            if key not in LIST_KEYS:
                raise UnsupportedTriggers(f"unsupported filter {key!r} under {event}")
            if key in spec:
                raise UnsupportedTriggers(f"filter {key} listed twice under {event}")
            spec[key] = _inline_list(m.group(2)) if m.group(2) else []
        elif indent == 6 and event is not None and key is not None:
            if event == "workflow_call":
                continue
            if not stripped.startswith("- "):
                raise UnsupportedTriggers(f"unsupported list item {stripped!r}")
            events[event][key].append(_scalar(stripped[2:]))
        elif event == "workflow_call" and indent > 4:
            continue
        else:
            raise UnsupportedTriggers(f"unexpected indentation in {raw!r}")
    if not events:
        raise UnsupportedTriggers("empty `on:` block")
    return events


def problems(name: str, on: dict) -> list[str]:
    found = []
    automatic = False
    for event in ("push", "pull_request"):
        if event not in on:
            continue
        spec = on[event] or {}
        if "branches-ignore" in spec:
            found.append(f"{name}: {event} uses branches-ignore")
        branches = spec.get("branches")
        if branches is not None:
            unknown = sorted(set(branches) - BRANCHES)
            if unknown:
                found.append(f"{name}: {event} names branches this repository does not have: {unknown}")
            if set(branches) & BRANCHES:
                automatic = True
        elif event == "pull_request" or "tags" not in spec:
            automatic = True
        if event == "push" and spec.get("tags"):
            automatic = True
    if "schedule" in on:
        automatic = True
    if not automatic:
        found.append(f"{name}: no automatic trigger can fire here (dispatch or workflow_call only)")
    if name in SHARED_BUILDS:
        push = on.get("push") or {}
        if push.get("branches") != ["main"]:
            found.append(f"{name}: does not run on every push to main")
        for key in ("paths", "paths-ignore"):
            if key in push:
                found.append(f"{name}: its push trigger is filtered by {key}")
    return found


def tree_problems(workflows: Path = WORKFLOWS) -> list[str]:
    found = []
    files = sorted(workflows.glob("build-tos-linux-*.yml"))
    if not files:
        return [f"no build-tos-linux-*.yml under {workflows}"]
    for path in files:
        try:
            on = parse_on(path.read_text())
        except UnsupportedTriggers as exc:
            found.append(f"{path.name}: cannot read its triggers: {exc}")
            continue
        found += problems(path.name, on)
    for name in SHARED_BUILDS:
        if not (workflows / name).exists():
            found.append(f"{name} is missing")
    return found


class TreeTest(unittest.TestCase):
    def test_every_linux_build_can_run(self) -> None:
        self.assertEqual(tree_problems(), [])

    def test_the_parser_reads_every_current_linux_build(self) -> None:
        # What each workflow's triggers are, read back: a parser that dropped
        # or invented a filter would change these.
        expected = {
            "build-tos-linux-arm64-appimage.yml": {"push": {"tags": ["v*"]}, "workflow_dispatch": None,
                                                   "workflow_call": None},
            "build-tos-linux-x86-64-appimage.yml": {"push": {"tags": ["v*"]}, "workflow_dispatch": None,
                                                    "workflow_call": None},
            "build-tos-linux-x86-64-werror.yml": {
                "push": {"branches": ["main"]},
                "pull_request": {"branches": ["main"], "types": ["opened", "reopened", "synchronize", "ready_for_review"]},
                "workflow_dispatch": None,
                "workflow_call": None,
            },
        }
        files = sorted(WORKFLOWS.glob("build-tos-linux-*.yml"))
        self.assertEqual({p.name for p in files},
                         set(expected) | set(SHARED_BUILDS), "a Linux build workflow was added or removed")
        for path in files:
            on = parse_on(path.read_text())
            if path.name in SHARED_BUILDS:
                self.assertEqual(on, {"push": {"branches": ["main"]}, "workflow_dispatch": None}, path.name)
            else:
                self.assertEqual(on, expected[path.name], path.name)


class ParserTest(unittest.TestCase):
    def parse(self, block: str) -> dict:
        return parse_on("name: x\n\non:\n" + block + "\njobs:\n  a:\n")

    def test_block_and_inline_lists_and_comments(self) -> None:
        on = self.parse("  # comment\n  push:\n    branches: [main]  # trailing\n    paths:\n      - 'a/**'\n"
                        "      - b.txt\n  pull_request:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 0 * * 0'\n"
                        "  workflow_call:\n    inputs:\n      x:\n        type: string\n")
        self.assertEqual(on, {"push": {"branches": ["main"], "paths": ["a/**", "b.txt"]}, "pull_request": None,
                              "workflow_dispatch": None, "schedule": None, "workflow_call": {}})

    def test_unsupported_forms_are_refused(self) -> None:
        bad = {
            "flow mapping": "  push: {branches: [main]}\n",
            "unknown event": "  release:\n",
            "unknown filter": "  push:\n    branch: [main]\n",
            "tab": "  push:\n\tbranches: [main]\n",
            "unterminated list": "  push:\n    branches: [main\n",
            "anchor": "  push:\n    branches: &b [main]\n",
            "duplicate event": "  push:\n  push:\n",
            "duplicate filter": "  push:\n    branches: [main]\n    branches: [x]\n",
            "bad indentation": "  push:\n     branches: [main]\n",
            "bad list item": "  push:\n    paths:\n      a/**\n",
            "empty block": "",
        }
        for label, block in bad.items():
            with self.assertRaises(UnsupportedTriggers, msg=label):
                self.parse(block)

    def test_inline_on_and_missing_on_are_refused(self) -> None:
        for text in ("on: [push]\njobs: {}\n", "on: push\n", "name: x\njobs: {}\n"):
            with self.assertRaises(UnsupportedTriggers, msg=text):
                parse_on(text)

    def test_an_unreadable_workflow_is_a_problem(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            for name in SHARED_BUILDS:
                (Path(d) / name).write_text("on: [push]\n")
            found = tree_problems(Path(d))
        self.assertTrue(all("cannot read its triggers" in p for p in found), found)
        self.assertEqual(len(found), 2)


class RuleTest(unittest.TestCase):
    def test_a_build_on_missing_branches_is_refused(self) -> None:
        on = {"pull_request": {"branches": ["master", "testnet"]}, "push": {"branches": ["master"]}}
        found = problems("build-tos-linux-arm64-appimage.yml", on)
        self.assertTrue(any("does not have" in p for p in found), found)
        self.assertTrue(any("no automatic trigger" in p for p in found), found)

    def test_dispatch_only_is_refused(self) -> None:
        found = problems("build-tos-linux-x.yml", {"workflow_dispatch": None, "workflow_call": None})
        self.assertEqual(found, ["build-tos-linux-x.yml: no automatic trigger can fire here (dispatch or workflow_call only)"])

    def test_tags_schedule_and_main_count(self) -> None:
        for on in ({"push": {"tags": ["v*"]}}, {"schedule": None}, {"push": {"branches": ["main"]}},
                   {"pull_request": None}):
            self.assertEqual(problems("build-tos-linux-x.yml", on), [], on)

    def test_a_shared_build_runs_on_every_push_to_main(self) -> None:
        name = "build-tos-linux-arm64-shared.yml"
        self.assertEqual(problems(name, {"push": {"branches": ["main"]}, "workflow_dispatch": None}), [])
        for key in ("paths", "paths-ignore"):
            found = problems(name, {"push": {"branches": ["main"], key: ["doc/**"]}})
            self.assertEqual(found, [f"{name}: its push trigger is filtered by {key}"], key)
        found = problems(name, {"push": {"tags": ["v*"]}, "workflow_dispatch": None})
        self.assertEqual(found, [f"{name}: does not run on every push to main"])

if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
