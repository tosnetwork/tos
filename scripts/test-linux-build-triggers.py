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
- the full shared builds' path filters include their own workflow file and
  the Rust toolchain pin, so a change to the build itself runs it.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
BRANCHES = {"main"}
SHARED_BUILDS = ("build-tos-linux-x86-64-shared.yml", "build-tos-linux-arm64-shared.yml")


def triggers(doc: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {event: None for event in on}
    return on or {}


def problems(name: str, doc: dict) -> list[str]:
    found = []
    on = triggers(doc)
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
        paths = (on.get("push") or {}).get("paths") or []
        if f".github/workflows/{name}" not in paths:
            found.append(f"{name}: its push path filter does not include its own workflow file")
        # install-rust-toolchain.sh installs what this file pins: a pin change
        # alone must rebuild.
        if "rust-toolchain.toml" not in paths:
            found.append(f"{name}: its push path filter does not include rust-toolchain.toml")
    return found


def tree_problems(workflows: Path = WORKFLOWS) -> list[str]:
    found = []
    files = sorted(workflows.glob("build-tos-linux-*.yml"))
    if not files:
        return [f"no build-tos-linux-*.yml under {workflows}"]
    for path in files:
        found += problems(path.name, yaml.safe_load(path.read_text()) or {})
    for name in SHARED_BUILDS:
        if not (workflows / name).exists():
            found.append(f"{name} is missing")
    return found


class TreeTest(unittest.TestCase):
    def test_every_linux_build_can_run(self) -> None:
        self.assertEqual(tree_problems(), [])


class RuleTest(unittest.TestCase):
    def test_a_build_on_missing_branches_is_refused(self) -> None:
        doc = {"on": {"pull_request": {"branches": ["master", "testnet"]}, "push": {"branches": ["master"]}}}
        found = problems("build-tos-linux-arm64-appimage.yml", doc)
        self.assertTrue(any("does not have" in p for p in found), found)
        self.assertTrue(any("no automatic trigger" in p for p in found), found)

    def test_dispatch_only_is_refused(self) -> None:
        found = problems("build-tos-linux-x.yml", {"on": {"workflow_dispatch": None, "workflow_call": None}})
        self.assertEqual(found, ["build-tos-linux-x.yml: no automatic trigger can fire here (dispatch or workflow_call only)"])

    def test_tags_schedule_and_main_count(self) -> None:
        for on in ({"push": {"tags": ["v*"]}}, {"schedule": [{"cron": "0 0 * * 0"}]}, {"push": {"branches": ["main"]}},
                   {"pull_request": None}):
            self.assertEqual(problems("build-tos-linux-x.yml", {"on": on}), [], on)

    def test_a_shared_build_must_watch_its_own_file(self) -> None:
        name = "build-tos-linux-arm64-shared.yml"
        doc = {"on": {"push": {"branches": ["main"], "paths": ["**/*.cpp", "rust-toolchain.toml"]}}}
        self.assertEqual(problems(name, doc), [f"{name}: its push path filter does not include its own workflow file"])
        doc["on"]["push"]["paths"].append(f".github/workflows/{name}")
        self.assertEqual(problems(name, doc), [])

    def test_a_shared_build_must_watch_the_rust_toolchain_pin(self) -> None:
        name = "build-tos-linux-x86-64-shared.yml"
        doc = {"on": {"push": {"branches": ["main"], "paths": [f".github/workflows/{name}"]}}}
        self.assertEqual(problems(name, doc), [f"{name}: its push path filter does not include rust-toolchain.toml"])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
