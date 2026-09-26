#!/usr/bin/env python3
"""Derive node-scoped full BlockIdExt IDs from retained native log bytes."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any


MARKER = re.compile(
    rb"BlockFinalizedInMasterchain.*?"
    rb"\{block=\(-1,8000000000000000,(?P<height>\d+)\):"
    rb"(?P<root>[0-9A-Fa-f]{64}):(?P<file>[0-9A-Fa-f]{64})\}"
)
STAMP = re.compile(rb"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+\]")


class MarkerError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MarkerError(message)


def read_log_prefix(path: Path, db_root: Path) -> tuple[bytes, dict[str, Any]]:
    """Read one stable raw prefix while the node may still append to its log."""
    db = db_root.resolve(strict=True)
    require(path == db / "log", "native log is not the node DB log")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size > 0,
                "native log is not a nonempty regular file")
        raw = b""
        while len(raw) < before.st_size:
            part = os.read(descriptor, before.st_size - len(raw))
            require(bool(part), "native log was truncated during read")
            raw += part
        after = os.fstat(descriptor)
        named = path.stat()
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                == (named.st_dev, named.st_ino) and after.st_size >= before.st_size,
                "native log inode changed or was truncated")
        os.lseek(descriptor, 0, os.SEEK_SET)
        require(os.read(descriptor, before.st_size) == raw,
                "native log prefix changed during capture")
        return raw, {"path": str(path), "dev": before.st_dev,
                     "ino": before.st_ino, "prefix_bytes": len(raw),
                     "sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(descriptor)


def read_log_tail(path: Path, source: dict[str, Any], offset: int) -> bytes:
    """Read only newly appended bytes while retaining the original log inode."""
    require(type(offset) is int and offset >= source["prefix_bytes"],
            "native log poll offset precedes initial original")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require((before.st_dev, before.st_ino) == (source["dev"], source["ino"])
                and before.st_size >= offset, "native log changed inode or was truncated")
        os.lseek(descriptor, offset, os.SEEK_SET)
        remaining = before.st_size - offset
        parts = []
        while remaining:
            part = os.read(descriptor, remaining)
            require(bool(part), "native log truncated during incremental read")
            parts.append(part)
            remaining -= len(part)
        named = path.stat()
        after = os.fstat(descriptor)
        require((named.st_dev, named.st_ino) == (before.st_dev, before.st_ino)
                == (after.st_dev, after.st_ino) and after.st_size >= before.st_size,
                "native log changed during incremental read")
        return b"".join(parts)
    finally:
        os.close(descriptor)


def adapt(raw: bytes, source: dict[str, Any], *, node: str, pid: int,
          start_ticks: int, db_root: Path, first: int, last: int) -> dict[str, Any]:
    """Bind native marker bytes to a single process generation and height window."""
    db = db_root.resolve(strict=True)
    require(bool(node) and type(pid) is int and pid > 1
            and type(start_ticks) is int and start_ticks > 0,
            "missing node or process generation")
    require(type(first) is int and type(last) is int and first > 0
            and first + 2 <= last <= first + 256, "invalid governance height window")
    require(source.get("path") == str(db / "log")
            and source.get("sha256") == hashlib.sha256(raw).hexdigest()
            and source.get("prefix_bytes") == len(raw)
            and type(source.get("dev")) is int and type(source.get("ino")) is int,
            "raw native log source or SHA differs")
    ids: dict[str, list[Any]] = {}
    lines: dict[str, int] = {}
    for number, line in enumerate(raw.splitlines(), 1):
        match = MARKER.search(line)
        if match is None:
            continue
        require(STAMP.search(line) is not None, "native marker lacks timestamp")
        height = int(match["height"])
        root = match["root"].decode().lower()
        file = match["file"].decode().lower()
        require(int(root, 16) != 0 and int(file, 16) != 0,
                "native marker has zero root/file hash")
        if not first <= height <= last:
            continue
        key = str(height)
        block = [-1, -(1 << 63), height, root, file]
        require(key not in ids or ids[key] == block,
                "native log has conflicting full ID at one height")
        ids[key] = block
        lines.setdefault(key, number)
    require(set(ids) == {str(height) for height in range(first, last + 1)},
            "native log lacks a governance-window height")
    return {"schema": "tos.z01.native-markers.v1", "node": node,
            "passed": True, "pid": pid, "start_ticks": start_ticks,
            "db_root": str(db), "db_dev": db.stat().st_dev,
            "db_ino": db.stat().st_ino, "source": source,
            "ids": ids, "lines": lines}
