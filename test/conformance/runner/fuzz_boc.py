# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Bag-of-cells codec and inbound-message layout for the fuzz diagnosis tools (minimize.py).

Only what shrinking needs: parse a standard BOC with one root, rebuild cells from bits and references,
serialize without index or checksum, and locate the StateInit and body of an inbound message
(crypto/block/block.tlb). Hashes are not computed; the targets check every BOC they are given.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

BOC_MAGIC = bytes.fromhex("b5ee9c72")
MAX_CELLS = 1 << 16
MAX_BITS = 1023
MAX_REFS = 4


class BocError(Exception):
    """The bytes are not a supported bag of cells, or a cell does not have the expected layout."""


@dataclass(frozen=True, eq=True)
class Cell:
    bits: tuple[int, ...] = ()
    refs: tuple[Cell, ...] = ()
    special: bool = False
    level: int = 0

    @staticmethod
    def make(bits: Sequence[int], refs: Sequence[Cell] = (), special: bool = False) -> Cell:
        if len(bits) > MAX_BITS or len(refs) > MAX_REFS:
            raise BocError(f"cell overflow: {len(bits)} bits, {len(refs)} refs")
        return Cell(tuple(bits), tuple(refs), special, 0)

    def tree_size(self) -> int:
        """Bits plus references over the whole tree, counting a shared cell once per path (a size measure)."""
        return len(self.bits) + sum(1 + ref.tree_size() for ref in self.refs)


def _uint(raw: bytes, at: int, size: int) -> int:
    if at + size > len(raw):
        raise BocError("truncated bag of cells")
    return int.from_bytes(raw[at : at + size], "big")


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _data_bits(data: bytes, d2: int) -> tuple[int, ...]:
    bits = [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]
    if d2 % 2:
        # The last byte carries a completion tag: a 1 followed by zeros.
        while bits and bits[-1] == 0:
            bits.pop()
        if not bits:
            raise BocError("missing completion tag")
        bits.pop()
    return tuple(bits)


def deserialize(raw: bytes) -> Cell:
    if raw[:4] != BOC_MAGIC:
        raise BocError("not a standard bag of cells")
    flags = _uint(raw, 4, 1)
    has_index, has_crc, size = bool(flags & 0x80), bool(flags & 0x40), flags & 0x07
    off_bytes = _uint(raw, 5, 1)
    if not 1 <= size <= 4 or not 1 <= off_bytes <= 8:
        raise BocError("invalid size fields")
    at = 6
    cells = _uint(raw, at, size)
    roots = _uint(raw, at + size, size)
    at += 3 * size
    total = _uint(raw, at, off_bytes)
    at += off_bytes
    if roots != 1 or not 1 <= cells <= MAX_CELLS:
        raise BocError("exactly one root and a bounded cell count are required")
    root_index = _uint(raw, at, size)
    at += size
    if has_index:
        at += cells * off_bytes
    body_end = at + total
    if has_crc:
        if body_end + 4 != len(raw):
            raise BocError("size mismatch")
        if crc32c(raw[:body_end]) != int.from_bytes(raw[body_end:], "little"):
            raise BocError("checksum mismatch")
    elif body_end != len(raw):
        raise BocError("size mismatch")
    parsed: list[tuple[tuple[int, ...], list[int], bool, int]] = []
    while at < body_end:
        d1, d2 = _uint(raw, at, 1), _uint(raw, at + 1, 1)
        at += 2
        nrefs, special, with_hashes, level = d1 & 7, bool(d1 & 8), bool(d1 & 16), d1 >> 5
        if nrefs > MAX_REFS:
            raise BocError("absent cells are not supported")
        if with_hashes:
            at += (bin(level).count("1") + 1) * 34
        length = (d2 + 1) // 2
        data = raw[at : at + length]
        if len(data) != length:
            raise BocError("truncated cell")
        at += length
        refs = [_uint(raw, at + i * size, size) for i in range(nrefs)]
        at += nrefs * size
        parsed.append((_data_bits(data, d2), refs, special, level))
    if len(parsed) != cells or root_index >= cells:
        raise BocError("cell count mismatch")
    built: dict[int, Cell] = {}
    for index in range(cells - 1, -1, -1):
        bits, refs, special, level = parsed[index]
        if any(ref <= index or ref >= cells for ref in refs):
            raise BocError("references must point forward")
        built[index] = Cell(bits, tuple(built[ref] for ref in refs), special, level)
    return built[root_index]


def _order(root: Cell) -> list[Cell]:
    """Distinct cells, every parent before its children (reverse post-order)."""
    seen: set[Cell] = set()
    post: list[Cell] = []
    stack: list[tuple[Cell, int]] = [(root, 0)]
    while stack:
        cell, child = stack.pop()
        if child == 0 and cell in seen:
            continue
        if child < len(cell.refs):
            stack.append((cell, child + 1))
            stack.append((cell.refs[child], 0))
            continue
        if cell not in seen:
            seen.add(cell)
            post.append(cell)
    post.reverse()
    if len(post) > MAX_CELLS:
        raise BocError("too many cells")
    return post


def _cell_data(cell: Cell) -> bytes:
    bits = list(cell.bits)
    if len(bits) % 8:
        bits.append(1)
        bits.extend([0] * (-len(bits) % 8))
    return bytes(
        sum(bit << (7 - i) for i, bit in enumerate(bits[k : k + 8])) for k in range(0, len(bits), 8)
    )


def serialize(root: Cell, with_index: bool = False, with_crc: bool = False) -> bytes:
    order = _order(root)
    position = {cell: i for i, cell in enumerate(order)}
    size = max(1, (len(order).bit_length() + 7) // 8)
    blobs: list[bytes] = []
    for cell in order:
        d1 = len(cell.refs) + 8 * int(cell.special) + 32 * cell.level
        d2 = (len(cell.bits) + 7) // 8 + len(cell.bits) // 8
        refs = b"".join(position[ref].to_bytes(size, "big") for ref in cell.refs)
        blobs.append(bytes([d1, d2]) + _cell_data(cell) + refs)
    total = sum(len(b) for b in blobs)
    off_bytes = max(1, (total.bit_length() + 7) // 8)
    flags = size | (0x80 if with_index else 0) | (0x40 if with_crc else 0)
    out = bytearray(BOC_MAGIC + bytes([flags, off_bytes]))
    for value in (len(order), 1, 0):
        out += value.to_bytes(size, "big")
    out += total.to_bytes(off_bytes, "big") + (0).to_bytes(size, "big")
    if with_index:
        offset = 0
        for blob in blobs:
            offset += len(blob)
            out += offset.to_bytes(off_bytes, "big")
    for blob in blobs:
        out += blob
    if with_crc:
        out += crc32c(bytes(out)).to_bytes(4, "little")
    return bytes(out)


def from_b64(text: str) -> Cell:
    try:
        return deserialize(base64.b64decode(text, validate=True))
    except (ValueError, IndexError) as exc:
        raise BocError(str(exc)) from exc


def to_b64(cell: Cell) -> str:
    return base64.b64encode(serialize(cell)).decode("ascii")


# ---------------------------------------------------------------------------------------------
# Reading a cell in order


class Reader:
    def __init__(self, cell: Cell) -> None:
        self.cell = cell
        self.pos = 0
        self.ref = 0

    def take(self, n: int) -> int:
        if n < 0 or self.pos + n > len(self.cell.bits):
            raise BocError("cell underflow")
        value = 0
        for bit in self.cell.bits[self.pos : self.pos + n]:
            value = value << 1 | bit
        self.pos += n
        return value

    def take_ref(self) -> Cell:
        if self.ref >= len(self.cell.refs):
            raise BocError("reference underflow")
        self.ref += 1
        return self.cell.refs[self.ref - 1]

    def var_uint(self, length_bits: int) -> int:
        return self.take(8 * self.take(length_bits))

    def maybe_anycast(self) -> None:
        if self.take(1):
            self.take(self.take(5))

    def address_int(self) -> None:
        tag = self.take(2)
        if tag == 0b10:
            self.maybe_anycast()
            self.take(8 + 256)
        elif tag == 0b11:
            self.maybe_anycast()
            length = self.take(9)
            self.take(32 + length)
        else:
            raise BocError("MsgAddressInt expected")

    def address_ext(self) -> None:
        if self.take(2) == 0b01:
            self.take(self.take(9))

    def currency_collection(self) -> None:
        self.var_uint(4)
        if self.take(1):
            self.take_ref()


@dataclass(frozen=True)
class MessageLayout:
    """Positions within an inbound message cell: the end of CommonMsgInfo, the end of the init field."""

    header_bits: int
    header_refs: int
    init_bits: int
    init_refs: int
    has_init: bool
    body_inline: bool


def message_layout(message: Cell) -> MessageLayout:
    r = Reader(message)
    if r.take(1) == 0:  # int_msg_info
        r.take(3)
        r.address_int()
        r.address_int()
        r.currency_collection()
        r.var_uint(4)  # extra_flags
        r.var_uint(4)  # fwd_fee
        r.take(64 + 32)
    elif r.take(1) == 0:  # ext_in_msg_info
        r.address_ext()
        r.address_int()
        r.var_uint(4)
    else:
        raise BocError("an outbound message is not an inbound message")
    header_bits, header_refs = r.pos, r.ref
    has_init = bool(r.take(1))
    if has_init:
        if r.take(1):
            r.take_ref()
        else:
            if r.take(1):
                r.take(5)
            if r.take(1):
                r.take(2)
            for _ in range(3):  # code, data, library
                if r.take(1):
                    r.take_ref()
    init_bits, init_refs = r.pos, r.ref
    body_inline = r.take(1) == 0
    if not body_inline and r.ref >= len(message.refs):
        raise BocError("body reference missing")
    return MessageLayout(header_bits, header_refs, init_bits, init_refs, has_init, body_inline)


def message_body(message: Cell, layout: MessageLayout) -> Cell:
    if layout.body_inline:
        return Cell.make(message.bits[layout.init_bits + 1 :], message.refs[layout.init_refs :])
    return message.refs[layout.init_refs]


def with_body(message: Cell, layout: MessageLayout, body: Cell, keep_init: bool = True) -> Cell:
    """The message with its body replaced (inline when it fits) and optionally its init dropped."""
    if keep_init:
        bits = list(message.bits[: layout.init_bits])
        refs = list(message.refs[: layout.init_refs])
    else:
        bits = [*message.bits[: layout.header_bits], 0]
        refs = list(message.refs[: layout.header_refs])
    if len(bits) + 1 + len(body.bits) <= MAX_BITS and len(refs) + len(body.refs) <= MAX_REFS:
        return Cell.make([*bits, 0, *body.bits], [*refs, *body.refs])
    return Cell.make([*bits, 1], [*refs, body])


def cell_variants(cell: Cell, depth: int = 0) -> Iterator[Cell]:
    """Smaller variants of an ordinary cell tree: data prefixes, fewer references, a subtree hoisted to the
    root, and the same reductions applied inside each reference."""
    if cell.special:
        return
    n = len(cell.bits)
    for keep in sorted({0, n // 2, max(0, n - 8), max(0, n - 1)}):
        if keep < n:
            yield Cell.make(cell.bits[:keep], cell.refs)
    for i in range(len(cell.refs)):
        yield Cell.make(cell.bits, cell.refs[:i] + cell.refs[i + 1 :])
    for ref in cell.refs:
        if not ref.special:
            yield ref
    if depth < 4:
        for i, ref in enumerate(cell.refs):
            for smaller in cell_variants(ref, depth + 1):
                yield Cell.make(cell.bits, cell.refs[:i] + (smaller,) + cell.refs[i + 1 :])
