/**
 * Minimal TVM cell model: enough to build ordinary (level-0) cells, compute
 * their standard representation hash, and parse a standard BOC.
 *
 * The representation hash of an ordinary cell is
 *   sha256(d1 || d2 || data || depth(ref_i)... || hash(ref_i)...)
 * with d1 = refs, d2 = floor(b/8) + ceil(b/8), data padded with a single 1
 * bit then zeros when b is not byte aligned, ref depths as 16-bit big-endian.
 *
 * Exotic cells and non-zero levels are deliberately unsupported: nothing in
 * the .tos client protocol produces them, and rejecting them fails closed.
 */
import { sha256 } from '@noble/hashes/sha256';

export class Cell {
  readonly bitLen: number;
  readonly data: Uint8Array; // ceil(bitLen/8) bytes, unused low bits zero
  readonly refs: readonly Cell[];
  private cachedHash?: Uint8Array;
  private cachedDepth?: number;

  constructor(data: Uint8Array, bitLen: number, refs: readonly Cell[]) {
    if (bitLen > 1023) {
      throw new Error(`cell overflow: ${bitLen} bits`);
    }
    if (refs.length > 4) {
      throw new Error(`cell overflow: ${refs.length} refs`);
    }
    if (data.length !== Math.ceil(bitLen / 8)) {
      throw new Error('cell data length does not match bit length');
    }
    this.data = data;
    this.bitLen = bitLen;
    this.refs = refs;
  }

  /**
   * A stand-in for a cell known only by hash and depth (e.g. compiled
   * contract code pinned by the reproducible-build record). Its own contents
   * are unavailable; only hash() and depth() may be used.
   */
  static external(hash: Uint8Array, depth: number): Cell {
    if (hash.length !== 32) {
      throw new Error('external cell hash must be 32 bytes');
    }
    const c = new Cell(new Uint8Array(0), 0, []);
    c.cachedHash = hash.slice();
    c.cachedDepth = depth;
    return c;
  }

  depth(): number {
    if (this.cachedDepth === undefined) {
      let d = 0;
      for (const r of this.refs) {
        d = Math.max(d, r.depth() + 1);
      }
      this.cachedDepth = d;
    }
    return this.cachedDepth;
  }

  hash(): Uint8Array {
    if (this.cachedHash === undefined) {
      const b = this.bitLen;
      const dataBytes = Math.ceil(b / 8);
      const repr = new Uint8Array(2 + dataBytes + this.refs.length * (2 + 32));
      repr[0] = this.refs.length; // d1: ordinary, level 0
      repr[1] = Math.floor(b / 8) + Math.ceil(b / 8); // d2
      repr.set(this.data.subarray(0, dataBytes), 2);
      if (b % 8 !== 0) {
        // completion tag: single 1 bit after the data, then zeros
        const idx = 2 + dataBytes - 1;
        repr[idx] = (repr[idx] as number) | (0x80 >> b % 8);
      }
      let off = 2 + dataBytes;
      for (const r of this.refs) {
        const d = r.depth();
        repr[off] = d >> 8;
        repr[off + 1] = d & 0xff;
        off += 2;
      }
      for (const r of this.refs) {
        repr.set(r.hash(), off);
        off += 32;
      }
      this.cachedHash = sha256(repr);
    }
    return this.cachedHash;
  }

  hashHex(): string {
    return bytesToHex(this.hash());
  }

  beginParse(): Slice {
    return new Slice(this);
  }
}

export class Builder {
  private bits: number[] = [];
  private refs: Cell[] = [];

  storeBit(b: number): this {
    if (this.bits.length >= 1023) {
      throw new Error('cell overflow');
    }
    this.bits.push(b ? 1 : 0);
    return this;
  }

  storeBits(pattern: string): this {
    for (const ch of pattern) {
      if (ch !== '0' && ch !== '1') {
        throw new Error('bit pattern must contain only 0 and 1');
      }
      this.storeBit(ch === '1' ? 1 : 0);
    }
    return this;
  }

  storeUint(value: bigint | number, bitLen: number): this {
    let v = BigInt(value);
    if (v < 0n || v >= 1n << BigInt(bitLen)) {
      throw new Error(`uint${bitLen} out of range`);
    }
    for (let i = bitLen - 1; i >= 0; i--) {
      this.storeBit(Number((v >> BigInt(i)) & 1n));
    }
    return this;
  }

  storeInt(value: bigint | number, bitLen: number): this {
    let v = BigInt(value);
    const half = 1n << BigInt(bitLen - 1);
    if (v < -half || v >= half) {
      throw new Error(`int${bitLen} out of range`);
    }
    if (v < 0n) {
      v += 1n << BigInt(bitLen);
    }
    return this.storeUint(v, bitLen);
  }

  storeBytes(bytes: Uint8Array): this {
    for (const byte of bytes) {
      this.storeUint(byte, 8);
    }
    return this;
  }

  /** VarUInteger 16 (Tomis / coins). */
  storeCoins(value: bigint | number): this {
    let v = BigInt(value);
    if (v < 0n) {
      throw new Error('coins must be non-negative');
    }
    let byteLen = 0;
    for (let probe = v; probe > 0n; probe >>= 8n) {
      byteLen++;
    }
    if (byteLen > 15) {
      throw new Error('coins out of range');
    }
    this.storeUint(byteLen, 4);
    if (byteLen > 0) {
      this.storeUint(v, byteLen * 8);
    }
    return this;
  }

  storeRef(ref: Cell): this {
    if (this.refs.length >= 4) {
      throw new Error('cell overflow: refs');
    }
    this.refs.push(ref);
    return this;
  }

  get bitLength(): number {
    return this.bits.length;
  }

  endCell(): Cell {
    const data = new Uint8Array(Math.ceil(this.bits.length / 8));
    this.bits.forEach((bit, i) => {
      if (bit) {
        const idx = i >> 3;
        data[idx] = (data[idx] as number) | (0x80 >> (i & 7));
      }
    });
    return new Cell(data, this.bits.length, this.refs);
  }
}

/** Sequential bit reader over a cell. */
export class Slice {
  private pos = 0;
  private refPos = 0;

  constructor(private readonly cell: Cell) {}

  get remainingBits(): number {
    return this.cell.bitLen - this.pos;
  }

  get remainingRefs(): number {
    return this.cell.refs.length - this.refPos;
  }

  loadBit(): number {
    if (this.pos >= this.cell.bitLen) {
      throw new Error('cell underflow');
    }
    const byte = this.cell.data[this.pos >> 3] as number;
    const bit = (byte >> (7 - (this.pos & 7))) & 1;
    this.pos++;
    return bit;
  }

  loadUint(bitLen: number): bigint {
    let v = 0n;
    for (let i = 0; i < bitLen; i++) {
      v = (v << 1n) | BigInt(this.loadBit());
    }
    return v;
  }

  loadBytes(byteLen: number): Uint8Array {
    const out = new Uint8Array(byteLen);
    for (let i = 0; i < byteLen; i++) {
      out[i] = Number(this.loadUint(8));
    }
    return out;
  }

  loadRef(): Cell {
    if (this.refPos >= this.cell.refs.length) {
      throw new Error('cell underflow: refs');
    }
    return this.cell.refs[this.refPos++] as Cell;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 ? '0' + hex : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error('invalid hex');
    }
    out[i] = byte;
  }
  return out;
}

/**
 * Parse a standard BOC (serialized bag of cells) into its root cell.
 * Ordinary cells only; exotic cells and multiple roots are rejected.
 */
export function parseBoc(boc: Uint8Array): Cell {
  const view = new DataView(boc.buffer, boc.byteOffset, boc.byteLength);
  if (boc.length < 10 || view.getUint32(0) !== 0xb5ee9c72) {
    throw new Error('not a standard BOC');
  }
  const flagsByte = boc[4] as number;
  const hasIdx = (flagsByte & 0x80) !== 0;
  const hasCrc = (flagsByte & 0x40) !== 0;
  const refByteSize = flagsByte & 0x07;
  const offByteSize = boc[5] as number;
  let p = 6;
  const readInt = (size: number): number => {
    let v = 0;
    for (let i = 0; i < size; i++) {
      v = v * 256 + (boc[p++] as number);
    }
    return v;
  };
  const cellCount = readInt(refByteSize);
  const rootCount = readInt(refByteSize);
  const absentCount = readInt(refByteSize);
  const totalCellsSize = readInt(offByteSize);
  if (rootCount !== 1 || absentCount !== 0) {
    throw new Error('unsupported BOC shape');
  }
  const rootIdx = readInt(refByteSize);
  if (hasIdx) {
    p += cellCount * offByteSize;
  }
  const cellsStart = p;
  if (cellsStart + totalCellsSize > boc.length) {
    throw new Error('truncated BOC');
  }
  type RawCell = { data: Uint8Array; bitLen: number; refIdx: number[] };
  const raw: RawCell[] = [];
  for (let i = 0; i < cellCount; i++) {
    const d1 = boc[p] as number;
    const d2 = boc[p + 1] as number;
    p += 2;
    if ((d1 & 0x08) !== 0) {
      throw new Error('exotic cells are not supported');
    }
    const refs = d1 & 0x07;
    const dataBytes = (d2 + 1) >> 1;
    const fullBytes = (d2 & 1) === 0;
    const bytes = boc.subarray(p, p + dataBytes);
    p += dataBytes;
    let bitLen = dataBytes * 8;
    if (!fullBytes) {
      // strip completion tag: last 1 bit and everything after it
      const last = bytes[dataBytes - 1] as number;
      let drop = 1;
      while (drop <= 8 && ((last >> (drop - 1)) & 1) === 0) {
        drop++;
      }
      bitLen -= drop;
    }
    const refIdx: number[] = [];
    for (let r = 0; r < refs; r++) {
      refIdx.push(readInt(refByteSize));
    }
    const data = new Uint8Array(Math.ceil(bitLen / 8));
    data.set(bytes.subarray(0, data.length));
    if (bitLen % 8 !== 0) {
      const mask = 0xff << (8 - (bitLen % 8));
      const idx = data.length - 1;
      data[idx] = (data[idx] as number) & mask;
    }
    raw.push({ data, bitLen, refIdx });
  }
  void hasCrc; // trailing CRC, if present, is simply ignored
  const built: (Cell | undefined)[] = new Array(cellCount);
  const build = (i: number, guard: number): Cell => {
    if (guard > cellCount) {
      throw new Error('cyclic BOC');
    }
    const cached = built[i];
    if (cached) {
      return cached;
    }
    const rc = raw[i];
    if (!rc) {
      throw new Error('BOC ref out of range');
    }
    const refs = rc.refIdx.map((j) => build(j, guard + 1));
    const cell = new Cell(rc.data, rc.bitLen, refs);
    built[i] = cell;
    return cell;
  };
  return build(rootIdx, 0);
}
