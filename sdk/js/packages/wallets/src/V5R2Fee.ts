import { Address, Cell, beginCell } from "@tos/core";

export type V5R2FeeClass = "rescue-auth" | "pop" | "prepare";
export interface V5R2FeeBinding {
  vault: Address;
  configHash: Uint8Array;
  epoch0: number;
  leaf: number;
  validUntil: number;
  value: bigint;
}

/** Structural class validation. PQ signatures and immutable pairing require separate verification. */
export function validateV5R2FeePayload(kind: V5R2FeeClass, payload: Cell): void {
  const formats = {
    "rescue-auth": [0x53554233, 0x41553252, 1019, 1],
    pop: [0x50505333, 0x504f5033, 616, 2],
    prepare: [0x46505233, 0x50525033, 875, 1],
  } as const;
  const format = formats[kind];
  if (format === undefined) throw new Error("unknown fee class");
  if (payload.isExotic || payload.level() !== 0) throw new Error("ordinary fee payload required");
  const s = payload.beginParse();
  if (s.remainingBits !== 32 || s.remainingRefs !== 2) throw new Error("fee payload shape");
  if (s.loadUint(32) !== format[0]) throw new Error("fee class/submission mismatch");
  const request = s.loadRef();
  if (request.isExotic || request.level() !== 0) throw new Error("ordinary fee request required");
  const r = request.beginParse();
  if (r.remainingBits !== format[2] || r.remainingRefs !== format[3])
    throw new Error("fee request shape");
  if (r.loadUint(32) !== format[1]) throw new Error("fee request constructor");
  if (kind === "rescue-auth") {
    r.skip(811);
    if (r.loadUint(8) !== 2) throw new Error("fee vault cannot fund primary AUTH");
  }
}

/**
 * LMS fee intent framing. This does not reserve an OTS leaf, sign, validate live
 * solvency, or authorize assets. Reserve the exact digest durably before signing;
 * verify and persist the resulting signature before export. Retry cached bytes.
 */
export class V5R2FeeIntent {
  readonly #cell: Cell;
  readonly #leaf: number;
  constructor(b: V5R2FeeBinding, kind: V5R2FeeClass, payload: Cell, provenTime: number) {
    validateV5R2FeePayload(kind, payload);
    for (const value of [b.epoch0, b.validUntil, provenTime]) {
      if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
        throw new Error("fee time must be uint32");
    }
    if (b.validUntil - provenTime < 1 || b.validUntil - provenTime > 3600)
      throw new Error("fee TTL must be 1..=3600 seconds");
    if (!Number.isInteger(b.leaf) || b.leaf < 0 || b.leaf >= 1 << 20)
      throw new Error("fee tree exhausted or invalid leaf");
    if (provenTime < b.epoch0) throw new Error("before fee epoch");
    if (Math.floor(b.leaf / 4) !== Math.floor((provenTime - b.epoch0) / 3600))
      throw new Error("new fee signature requires current slot");
    if (b.vault.workchain !== 0) throw new Error("basechain only");
    if (b.configHash.length !== 32) throw new Error("fee config hash must be 32 bytes");
    if (b.value <= 0n || b.value >= 1n << 120n)
      throw new Error("fee value must be positive canonical Coins");
    this.#leaf = b.leaf;
    this.#cell = beginCell()
      .storeUint(0x46454534, 32)
      .storeBuffer(new TextEncoder().encode("TOS-RESCUE-FEE-v1"))
      .storeUint(kind === "rescue-auth" ? 1 : kind === "pop" ? 2 : 3, 8)
      .storeAddress(b.vault)
      .storeBuffer(b.configHash)
      .storeUint(b.leaf, 32)
      .storeUint(b.validUntil, 32)
      .storeCoins(b.value)
      .storeRef(payload)
      .endCell();
  }
  get cell(): Cell {
    return this.#cell;
  }
  get leaf(): number {
    return this.#leaf;
  }
  get digest(): Uint8Array {
    return this.#cell.hash().slice();
  }

  /** Exact cached HSS signature framing; current proof/admission checks still precede broadcast. */
  encodeExternal(signature: Uint8Array): Cell {
    if (signature.length !== 2832) throw new Error("fee signature length");
    const view = new DataView(signature.buffer, signature.byteOffset, signature.byteLength);
    if (
      view.getUint32(0) !== 0 ||
      view.getUint32(4) !== this.#leaf ||
      view.getUint32(8) !== 3 ||
      view.getUint32(2188) !== 8
    )
      throw new Error("fee signature profile/leaf mismatch");
    let tail: Cell | undefined;
    for (let offset = Math.floor((signature.length - 1) / 127) * 127; offset >= 0; offset -= 127) {
      const b = beginCell().storeBuffer(
        signature.subarray(offset, Math.min(offset + 127, signature.length)),
      );
      if (tail !== undefined) b.storeRef(tail);
      tail = b.endCell();
    }
    if (tail === undefined) throw new Error("empty fee signature");
    return beginCell().storeRef(this.#cell).storeRef(tail).endCell();
  }
}
