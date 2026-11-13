#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the coverage gate (coverage/handlers.py check). Each failure mode is shown to fail."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any

HANDLERS = Path(__file__).resolve().parent.parent / "coverage" / "handlers.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("coverage_handlers", HANDLERS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h: Any = load()


class GateTests(unittest.TestCase):
    base: Path = Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        (self.base / "vm-handlers-covered.txt").write_text("a.cpp:exec_one\na.cpp:exec_two\n")
        (self.base / "vm-handlers-unreachable.txt").write_text("a.cpp:exec_dead\tnot registered\n")
        (self.base / "vm-handlers-gaps.txt").write_text(
            "a.cpp:exec_deep\tneeds a special balance\n"
        )
        (self.base / "components.json").write_text(json.dumps({"crypto/vm/": 60.0}))

    def report(self, handlers: dict[str, bool], vm: float = 60.0) -> Path:
        path = self.base / "report.json"
        path.write_text(json.dumps({"handlers": handlers, "components": {"crypto/vm/": vm}}))
        return path

    def good(self) -> dict[str, bool]:
        return {
            "a.cpp:exec_one": True,
            "a.cpp:exec_two": True,
            "a.cpp:exec_dead": False,
            "a.cpp:exec_deep": False,
        }

    def test_baseline_report_passes(self) -> None:
        self.assertEqual(h.check(self.report(self.good()), self.base), 0)

    def test_covered_handler_no_longer_executed_fails(self) -> None:
        handlers = {**self.good(), "a.cpp:exec_two": False}
        self.assertEqual(h.check(self.report(handlers), self.base), 1)

    def test_unclassified_handler_fails(self) -> None:
        handlers = {**self.good(), "a.cpp:exec_new": True}
        self.assertEqual(h.check(self.report(handlers), self.base), 1)

    def test_removed_baseline_handler_fails(self) -> None:
        handlers = self.good()
        del handlers["a.cpp:exec_one"]
        self.assertEqual(h.check(self.report(handlers), self.base), 1)

    def test_component_drop_beyond_slack_fails(self) -> None:
        self.assertEqual(h.check(self.report(self.good(), vm=60.0 - h.SLACK + 0.01), self.base), 0)
        self.assertEqual(h.check(self.report(self.good(), vm=60.0 - h.SLACK - 0.01), self.base), 1)

    def test_listed_handler_needs_a_reason(self) -> None:
        (self.base / "vm-handlers-gaps.txt").write_text("a.cpp:exec_deep\n")
        self.assertEqual(h.check(self.report(self.good()), self.base), 1)

    def test_empty_baseline_fails(self) -> None:
        (self.base / "vm-handlers-covered.txt").write_text("# nothing\n")
        self.assertEqual(h.check(self.report(self.good()), self.base), 1)


if __name__ == "__main__":
    unittest.main()
