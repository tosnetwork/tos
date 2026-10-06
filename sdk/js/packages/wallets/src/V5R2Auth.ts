import { Address, Cell, beginCell } from "@tos/core";

/** PQ-only wire roles. Custody and authenticated chain reads are separate. */
export type V5R2Role = "primary" | "rescue";
export type V5R2Action =
  | { kind: "execute"; actions: Cell }
  | { kind: "configure"; replacement?: { metadata: Cell; vaultInit: Cell } }
  | { kind: "lock" }
  | { kind: "migrate"; moduleInit: Cell; metadata: Cell; vaultInit: Cell };

export interface V5R2Binding {
  globalId: number;
  network: Uint8Array;
  wallet: Address;
  module: Address;
  epoch: bigint;
  nonce: bigint;
  validUntil: number;
}

/** Validate the entire strict V5 send list before exposing a signing digest. */
export function validateV5R2Actions(actions: Cell): void {
  let current = actions;
  let count = 0;
  for (;;) {
    const s = current.beginParse();
    if (s.remainingBits === 0) {
      if (s.remainingRefs !== 0) throw new Error("action tail must be empty");
      return;
    }
    if (count >= 255) throw new Error("at most 255 send actions");
    if (s.remainingBits !== 40 || s.remainingRefs !== 2) throw new Error("send action shape");
    if (s.loadUint(32) !== 0x0ec3c86d) throw new Error("only send actions are allowed");
    const mode = s.loadUint(8);
    if ((mode & 2) === 0 || (mode & 44) !== 0 || (mode & 192) === 192) {
      throw new Error("forbidden send mode");
    }
    current = s.loadRef();
    count += 1;
  }
}

function encodeAction(action: V5R2Action): [number, Cell] {
  const b = beginCell();
  switch (action.kind) {
    case "execute":
      validateV5R2Actions(action.actions);
      return [0, b.storeUint(0x45584543, 32).storeRef(action.actions).endCell()];
    case "configure": {
      b.storeUint(0x434f4e46, 32).storeUint(2, 2).storeBit(action.replacement !== undefined);
      if (action.replacement !== undefined) {
        b.storeRef(beginCell().storeRef(action.replacement.metadata).storeRef(action.replacement.vaultInit).endCell());
      }
      return [1, b.endCell()];
    }
    case "lock":
      return [3, b.storeUint(0x4c4f434b, 32).storeUint(1, 8).endCell()];
    case "migrate":
      return [4, b.storeUint(0x4d494752, 32).storeRef(action.moduleInit).storeRef(action.metadata).storeRef(action.vaultInit).endCell()];
    default:
      throw new Error("unknown V5R2 action");
  }
}

/**
 * Immutable AUTH v2 framing, with no classical signing API. Inputs must come
 * from verified current state. Encoding is neither proof nor signature approval.
 */
export class V5R2AuthRequest {
  readonly #cell: Cell;
  readonly #role: V5R2Role;
  readonly #signingDigest: Uint8Array;

  constructor(binding: V5R2Binding, role: V5R2Role, action: V5R2Action, provenTime: number) {
    if (role !== "primary" && role !== "rescue") throw new Error("unknown AUTH role");
    if (!Number.isInteger(provenTime) || provenTime < 0 || provenTime > 0xffffffff ||
        !Number.isInteger(binding.validUntil) || binding.validUntil > 0xffffffff ||
        binding.validUntil - provenTime < 1 || binding.validUntil - provenTime > 3600) {
      throw new Error("AUTH TTL must be 1..=3600 seconds");
    }
    if (binding.network.length !== 32) throw new Error("network must be 32 bytes");
    if (binding.wallet.workchain !== 0 || binding.module.workchain !== 0) throw new Error("basechain only");
    if (binding.wallet.equals(binding.module)) throw new Error("wallet and module must differ");
    const [kind, payload] = encodeAction(action);
    if (role === "primary" && kind !== 0) throw new Error("primary may only execute");
    this.#role = role;
    this.#cell = beginCell().storeUint(0x41553252, 32).storeInt(binding.globalId, 32)
      .storeBuffer(binding.network).storeAddress(binding.wallet).storeBuffer(binding.module.hash)
      .storeUint(role === "primary" ? 1 : 2, 8).storeUint(binding.epoch, 64)
      .storeUint(binding.nonce, 64).storeUint(binding.validUntil, 32).storeUint(kind, 8)
      .storeRef(payload).endCell();
    this.#signingDigest = beginCell().storeBuffer(new TextEncoder().encode("TOS-AUTH"))
      .storeRef(this.cell).endCell().hash().slice();
  }

  get cell(): Cell { return this.#cell; }
  get role(): V5R2Role { return this.#role; }
  get digest(): Uint8Array { return this.#signingDigest.slice(); }
  get signingContext(): Uint8Array {
    return new TextEncoder().encode(this.role === "primary"
      ? "TOS-AUTH-V2-ML-DSA-44-v1" : "TOS-AUTH-SLH-DSA-SHA2-128S-v1");
  }
  get signatureBytes(): number { return this.role === "primary" ? 2420 : 7856; }

  /** SUB3 internal module submission. Exact length is framing, not verification. */
  encodeSubmission(signature: Uint8Array): Cell {
    if (signature.length !== this.signatureBytes) throw new Error("wrong PQ signature length");
    let tail: Cell | undefined;
    for (let offset = Math.floor((signature.length - 1) / 127) * 127; offset >= 0; offset -= 127) {
      const b = beginCell().storeBuffer(signature.subarray(offset, Math.min(offset + 127, signature.length)));
      if (tail !== undefined) b.storeRef(tail);
      tail = b.endCell();
    }
    if (tail === undefined) throw new Error("empty signature");
    return beginCell().storeUint(0x53554233, 32).storeRef(this.cell).storeRef(tail).endCell();
  }
}
