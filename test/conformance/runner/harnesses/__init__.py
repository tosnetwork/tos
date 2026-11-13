# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Per-harness fixture validators. Each module in this package describes one harness:

    NAME: str
    CONTEXT_REQUIRED, CONTEXT_ALLOWED: frozenset[str]
    EFFECT_SHAPES: dict[str | None, frozenset[str]]   keys of each effect, by "outcome" (None: one shape)
    validate_context(ctx, where) -> None
    validate_effects(eff, where) -> None

schema/harness/<NAME>-v1.schema.json documents the same keys; test_conformance.py checks they agree.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Mapping
from types import ModuleType
from typing import Any, Protocol, cast


class Harness(Protocol):
    NAME: str
    CONTEXT_REQUIRED: frozenset[str]
    CONTEXT_ALLOWED: frozenset[str]
    EFFECT_SHAPES: Mapping[str | None, frozenset[str]]

    def validate_context(self, ctx: Mapping[str, Any], where: str) -> None: ...

    def validate_effects(self, eff: Mapping[str, Any], where: str) -> None: ...


def _load() -> dict[str, Harness]:
    found: dict[str, Harness] = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        module: ModuleType = importlib.import_module(f"{__name__}.{info.name}")
        harness = cast(Harness, cast(object, module))
        if harness.NAME != info.name:
            raise RuntimeError(f"harness module {info.name} declares NAME {harness.NAME}")
        found[harness.NAME] = harness
    return found


HARNESSES: dict[str, Harness] = _load()
