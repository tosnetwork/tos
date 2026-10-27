"""Bounded single-root ordinary/library BOCs for transaction fixture oracles.

Hashing uses the existing Cell representation, with iterative postorder cache
replacement. Depth counts edges; work counts pre-visits (including shared-edge
cache hits), not unique cells. Rust may revisit a hash at a greater depth;
Python instead propagates exact subtree depths to catch that deeper path.
"""

import base64

from cells import Cell, LibraryReference

MAX_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 1024
MAX_WORK = 2_000_000


def prime(root, *, max_depth=MAX_DEPTH, max_work=MAX_WORK):
    pending = [(root, 0, False)]
    active, done = set(), {}
    work = 0
    while pending:
        assert len(pending) <= max_work, "root pending-work limit"
        cell, path_depth, finish = pending.pop()
        key = id(cell)
        if finish:
            active.remove(key)
            # Cell is mutable: neither caller nor serialized caches are trusted.
            cell.__dict__.pop("depth", None)
            cell.__dict__.pop("hash", None)
            depth = cell.depth
            assert depth <= max_depth, "root edge-depth limit"
            cell.hash
            done[key] = depth
            continue
        work += 1
        assert work <= max_work, "root visit-work limit"
        assert key not in active, "cyclic root graph"
        assert path_depth <= max_depth, "root edge-depth limit"
        if key in done:
            assert path_depth + done[key] <= max_depth, "root edge-depth limit"
            continue
        assert len(cell.bits) <= 1023 and len(cell.refs) <= 4, "invalid root cell shape"
        active.add(key)
        # Stack growth is bounded before extending it, including finish events.
        assert len(pending) + 1 + len(cell.refs) <= max_work, "root pending-work limit"
        pending.append((cell, path_depth, True))
        pending.extend((child, path_depth + 1, False) for child in reversed(cell.refs))
    return root


def crc32c(data):
    table = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        table.append(value)
    crc = 0xFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 255] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF).to_bytes(4, "little")


def from_boc(data, *, allow_library=False, max_depth=MAX_DEPTH, max_work=MAX_WORK):
    if isinstance(data, str):
        assert len(data) <= (MAX_BYTES + 2) // 3 * 4, "root BOC byte limit"
        data = base64.b64decode(data, validate=True)
    assert len(data) <= MAX_BYTES, "root BOC byte limit"
    assert len(data) >= 6 and data[:4] == bytes.fromhex("b5ee9c72"), "invalid root BOC header"
    flags, ow = data[4:6]
    w = flags & 7
    assert 1 <= w <= 4 and 1 <= ow <= 8 and not flags & 24, "invalid root BOC widths/flags"
    assert not flags & 32 or flags & 128, "root BOC cache bits require index"
    pos, end = 6, len(data) - (4 if flags & 64 else 0)

    def take(n):
        nonlocal pos
        assert n >= 0 and pos + n <= end, "truncated root BOC"
        result = data[pos : pos + n]
        pos += n
        return result

    def integer(n):
        return int.from_bytes(take(n), "big")

    count, roots, absent, size = integer(w), integer(w), integer(w), integer(ow)
    assert 0 < count <= max_work, "root BOC declared-cell limit"
    assert roots == 1 and absent == 0, "root BOC requires one complete root"
    root = integer(w)
    assert root < count, "invalid root BOC root index"
    assert size >= count * (2 + w) - w, "root BOC impossible cell count"
    index_bytes = count * ow if flags & 128 else 0
    assert pos + index_bytes + size == end, "root BOC size/truncation mismatch"
    if flags & 64:
        assert crc32c(data[:-4]) == data[-4:], "root BOC CRC32C mismatch"
    indices = [integer(ow) >> bool(flags & 32) for _ in range(count)] if flags & 128 else None
    start = pos
    records = []
    # Scan lengths and every reference before allocating a Cell graph.
    for index in range(count):
        d1, d2 = integer(1), integer(1)
        refs, exotic = d1 & 7, bool(d1 & 8)
        assert refs <= 4 and d1 >> 5 == 0, "unsupported root cell descriptor"
        assert not exotic or (allow_library and refs == 0), "unsupported root exotic cell"
        if d1 & 16:
            take(34)  # Level-zero stored hash/depth; recompute from actual bits/refs.
        raw = take((d2 + 1) // 2)
        if d2 & 1:
            assert raw and raw[-1] & 127, "invalid root BOC top-up"
        links = [integer(w) for _ in range(refs)]
        assert all(index < child < count for child in links), "invalid root BOC reference"
        if indices is not None:
            assert indices[index] == pos - start, "invalid root BOC cell index"
        records.append((raw, bool(d2 & 1), exotic, links))
    assert pos == end, "root BOC trailing cell data"
    cells = []
    for raw, top_up, exotic, _ in records:
        bits = "".join(f"{byte:08b}" for byte in raw)
        if top_up:
            bits = bits[: bits.rfind("1")]
        if exotic:
            assert len(bits) == 264 and bits[:8] == "00000010", "unsupported root exotic type"
            cell = LibraryReference(int(bits[8:], 2))
        else:
            cell = Cell(bits)
        cells.append(cell)
    for cell, (_, _, _, links) in zip(cells, records, strict=True):
        cell.refs = [cells[child] for child in links]
    return prime(cells[root], max_depth=max_depth, max_work=max_work)
