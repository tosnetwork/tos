# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Validation primitives shared by the runner and the per-harness modules in harnesses/."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, cast

Json = dict[str, Any]

BOC_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
HASH_RE = re.compile(r"^[0-9A-F]{64}$")
BLOB_RE = re.compile(r"^[0-9a-f]{64}$")
SEED_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
FIXTURE_ID_RE = re.compile(r"^[A-Za-z0-9._:/+-]{1,200}$")
FAMILY_RE = re.compile(r"^[a-z0-9-]{1,64}$")
SOURCE_RE = re.compile(r"^(authored|fuzz|replay|migrated:[a-z0-9_./-]+)$")
INT_TEXT_RE = re.compile(r"^-?[0-9]{1,80}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})*$")


class FixtureError(Exception):
    """A fixture, context or target response does not have the required shape."""


def keys(obj: Mapping[str, Any], required: set[str], allowed: set[str], where: str) -> None:
    missing = required - obj.keys()
    extra = obj.keys() - allowed
    if missing:
        raise FixtureError(f"{where}: missing {sorted(missing)}")
    if extra:
        raise FixtureError(f"{where}: unexpected {sorted(extra)}")


def integer(value: object, where: str, low: int | None = None, high: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FixtureError(f"{where}: integer required")
    if (low is not None and value < low) or (high is not None and value > high):
        raise FixtureError(f"{where}: {value} out of range")
    return value


def boolean(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise FixtureError(f"{where}: boolean required")
    return value


def text(value: object, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise FixtureError(f"{where}: invalid value")
    return value


def any_text(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise FixtureError(f"{where}: string required")
    return value


def obj(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise FixtureError(f"{where}: object required")
    return cast(Mapping[str, Any], value)


def array(value: object, where: str, max_items: int | None = None) -> list[Any]:
    if not isinstance(value, list):
        raise FixtureError(f"{where}: array required")
    items = cast(list[Any], value)
    if max_items is not None and len(items) > max_items:
        raise FixtureError(f"{where}: more than {max_items} items")
    return items


def boc(value: object, where: str) -> None:
    """A base64 BOC, or a reference {"blob": "<sha256 of the BOC bytes>"} into the family's blob file."""
    if isinstance(value, dict):
        ref = cast(Mapping[str, Any], value)
        keys(ref, {"blob"}, {"blob"}, where)
        text(ref["blob"], BLOB_RE, f"{where}.blob")
        return
    text(value, BOC_RE, where)


def cell_hash(value: object, where: str) -> None:
    text(value, HASH_RE, where)


def optional_hash(value: object, where: str) -> None:
    if value is not None:
        cell_hash(value, where)


def stack_item(value: object, where: str, depth: int = 0) -> None:
    if depth > 32:
        raise FixtureError(f"{where}: nesting too deep")
    item = obj(value, where)
    kind = item.get("type")
    if kind in ("null", "nan"):
        keys(item, {"type"}, {"type"}, where)
    elif kind == "int":
        keys(item, {"type", "value"}, {"type", "value"}, where)
        text(item["value"], INT_TEXT_RE, f"{where}.value")
    elif kind in ("cell", "slice"):
        keys(item, {"type", "boc"}, {"type", "boc"}, where)
        boc(item["boc"], f"{where}.boc")
    elif kind == "tuple":
        keys(item, {"type", "items"}, {"type", "items"}, where)
        for i, sub in enumerate(array(item["items"], f"{where}.items", 255)):
            stack_item(sub, f"{where}.items[{i}]", depth + 1)
    else:
        raise FixtureError(f"{where}: unknown stack item type {kind!r}")


def string_list(value: object, where: str) -> None:
    for i, item in enumerate(array(value, where)):
        any_text(item, f"{where}[{i}]")


def outcome_shape(
    eff: Mapping[str, Any], shapes: Mapping[str | None, frozenset[str]], where: str
) -> str | None:
    """Check the effect's keys against the shape selected by its "outcome" (or the single shape)."""
    if None in shapes:
        shape = shapes[None]
        keys(eff, set(shape), set(shape), where)
        return None
    outcome = eff.get("outcome")
    if not isinstance(outcome, str) or outcome not in shapes:
        raise FixtureError(f"{where}.outcome: invalid {outcome!r}")
    shape = shapes[outcome]
    keys(eff, set(shape), set(shape), where)
    return outcome
