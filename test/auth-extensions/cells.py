"""Small ordinary-cell codec for the native authentication regression harness.

It deliberately rejects exotic cells; this is test infrastructure, not an SDK.
The transaction and account layouts are read from crypto/block/block.tlb.
"""
import base64
import hashlib
from functools import cached_property


class Cell:
    def __init__(self, bits='', refs=()):
        self.bits, self.refs = bits, list(refs)
        assert len(bits) <= 1023 and len(self.refs) <= 4

    def uint(self, value, width):
        assert 0 <= value < (1 << width)
        self.bits += f'{value:0{width}b}' if width else ''
        assert len(self.bits) <= 1023
        return self

    def sint(self, value, width):
        return self.uint(value % (1 << width), width)

    def raw(self, data):
        return self.uint(int.from_bytes(data, 'big'), len(data) * 8)

    def ref(self, cell):
        self.refs.append(cell)
        assert len(self.refs) <= 4
        return self

    def maybe(self, cell):
        self.uint(cell is not None, 1)
        return self.ref(cell) if cell is not None else self

    def varuint(self, value, n):
        width = (n - 1).bit_length()
        size = (value.bit_length() + 7) // 8
        assert size < n
        return self.uint(size, width).uint(value, size * 8)

    def coins(self, value):
        return self.varuint(value, 16)

    def addr(self, addr):
        wc, h = addr
        return self.uint(4, 3).sint(wc, 8).uint(h, 256)

    def slice(self):
        return Slice(self)

    def prefix(self):
        n = len(self.bits)
        bits = self.bits
        if n % 8:
            bits += '1' + '0' * (7 - n % 8)
        data = int(bits or '0', 2).to_bytes(len(bits) // 8, 'big')
        return bytes([len(self.refs), n // 8 + (n + 7) // 8]) + data

    @cached_property
    def depth(self):
        return 0 if not self.refs else 1 + max(c.depth for c in self.refs)

    @cached_property
    def hash(self):
        return hashlib.sha256(self.prefix() + b''.join(c.depth.to_bytes(2, 'big') for c in self.refs)
                              + b''.join(c.hash for c in self.refs)).digest()

    def boc(self):
        cells, seen = [], set()
        def visit(c):
            if id(c) in seen:
                return
            seen.add(id(c))
            for r in c.refs:
                visit(r)
            cells.append(c)
        visit(self)
        cells.reverse()
        indices = {id(c): i for i, c in enumerate(cells)}
        w = max(1, (len(cells).bit_length() + 7) // 8)
        data = b''.join(c.prefix() + b''.join(indices[id(r)].to_bytes(w, 'big') for r in c.refs) for c in cells)
        ow = max(1, (len(data).bit_length() + 7) // 8)
        return (bytes.fromhex('b5ee9c72') + bytes([w, ow]) + len(cells).to_bytes(w, 'big')
                + (1).to_bytes(w, 'big') + bytes(w) + len(data).to_bytes(ow, 'big') + bytes(w) + data)

    def b64(self):
        return base64.b64encode(self.boc())


class Slice:
    def __init__(self, cell):
        self.bits, self.refs = cell.bits, list(cell.refs)

    def uint(self, width):
        assert len(self.bits) >= width
        v = int(self.bits[:width] or '0', 2)
        self.bits = self.bits[width:]
        return v

    def sint(self, width):
        v = self.uint(width)
        return v - (1 << width) if v >> (width - 1) else v

    def ref(self):
        return self.refs.pop(0)

    def maybe(self):
        return self.ref() if self.uint(1) else None

    def varuint(self, n):
        return self.uint(self.uint((n - 1).bit_length()) * 8)

    def coins(self):
        return self.varuint(16)

    def addr(self):
        assert self.uint(3) == 4
        return self.sint(8), self.uint(256)

    def end(self):
        assert not self.bits and not self.refs


def from_boc(data):
    if isinstance(data, str):
        data = base64.b64decode(data)
    assert data[:4] == bytes.fromhex('b5ee9c72')
    flags, ow = data[4:6]
    w = flags & 7
    pos = 6
    def read(n):
        nonlocal pos
        v = int.from_bytes(data[pos:pos+n], 'big')
        pos += n
        return v
    count, roots, absent, size = read(w), read(w), read(w), read(ow)
    assert roots == 1 and absent == 0
    root = read(w)
    if flags & 128:
        pos += count * ow
    cells, refs = [], []
    for _ in range(count):
        d1, d2 = read(1), read(1)
        assert d1 & 8 == 0, 'exotic cells are outside this harness'
        if d1 & 16:
            pos += (1 + (d1 >> 5).bit_count()) * 34
        b = data[pos:pos+(d2+1)//2]
        pos += len(b)
        bits = ''.join(f'{x:08b}' for x in b)
        if d2 & 1:
            assert '1' in bits
            bits = bits[:bits.rfind('1')]
        cells.append(Cell(bits))
        refs.append([read(w) for _ in range(d1 & 7)])
    for c, indices in zip(cells, refs):
        c.refs = [cells[i] for i in indices]
    return cells[root]


def read_dict(root, width):
    result = {}
    def walk(c, n, prefix):
        s = c.slice()
        if s.uint(1) == 0:
            k = 0
            while s.uint(1):
                k += 1
            label = s.uint(k)
        elif s.uint(1) == 0:
            k = s.uint(n.bit_length())
            label = s.uint(k)
        else:
            bit, k = s.uint(1), s.uint(n.bit_length())
            label = (1 << k) - 1 if bit else 0
        p = (prefix << k) | label
        if k == n:
            result[p] = Cell(s.bits, s.refs)
        else:
            walk(s.ref(), n-k-1, p << 1)
            walk(s.ref(), n-k-1, (p << 1) | 1)
    if root is not None:
        walk(root, width, 0)
    return result


def make_dict(entries, width):
    def build(items, n):
        keys = list(items)
        k = n
        if len(keys) > 1:
            k = n - (min(keys) ^ max(keys)).bit_length()
        label = keys[0] >> (n-k)
        c = Cell().uint(2, 2).uint(k, n.bit_length()).uint(label, k)
        if k == n:
            v = items[keys[0]]
            return Cell(c.bits + v.bits, v.refs)
        rem = n-k-1
        for bit in (0, 1):
            c.ref(build({x & ((1 << rem)-1): v for x, v in items.items() if ((x >> rem) & 1) == bit}, rem))
        return c
    return build(entries, width) if entries else None
