import { Address, Cell, beginCell } from "@tos/core";
import type { V5R2Role } from "./V5R2Auth.js";
import type { V5R2Policy } from "./WalletV5R2.js";

export interface V5R2RecoveryBinding {
  globalId: number;
  network: Uint8Array;
  wallet: Address;
  module: Address;
  validUntil: number;
}
function validateBinding(b: V5R2RecoveryBinding, time: number): void {
  if (
    !Number.isInteger(time) ||
    time < 0 ||
    time > 0xffffffff ||
    !Number.isInteger(b.validUntil) ||
    b.validUntil > 0xffffffff ||
    b.validUntil - time < 1 ||
    b.validUntil - time > 3600
  )
    throw new Error("recovery TTL must be 1..=3600 seconds");
  if (b.network.length !== 32) throw new Error("network must be 32 bytes");
  if (b.wallet.workchain !== 0 || b.module.workchain !== 0) throw new Error("basechain only");
  if (b.wallet.equals(b.module)) throw new Error("wallet and module must differ");
}
function submission(tag: number, request: Cell, role: V5R2Role, signature: Uint8Array): Cell {
  if (signature.length !== (role === "primary" ? 2420 : 7856))
    throw new Error("wrong PQ signature length");
  let tail: Cell | undefined;
  for (let offset = Math.floor((signature.length - 1) / 127) * 127; offset >= 0; offset -= 127) {
    const b = beginCell().storeBuffer(
      signature.subarray(offset, Math.min(offset + 127, signature.length)),
    );
    if (tail !== undefined) b.storeRef(tail);
    tail = b.endCell();
  }
  if (tail === undefined) throw new Error("empty signature");
  return beginCell().storeUint(tag, 32).storeRef(request).storeRef(tail).endCell();
}

/** Per-key POP framing. Caller must generate a fresh challenge and verify funded receipts. */
export class V5R2PopRequest {
  readonly #cell: Cell;
  readonly #role: V5R2Role;
  readonly #digest: Uint8Array;
  constructor(
    b: V5R2RecoveryBinding,
    role: V5R2Role,
    policy: V5R2Policy,
    primaryKeyChainHash: Uint8Array,
    rescueKey: Uint8Array,
    challenge: Uint8Array,
    provenTime: number,
  ) {
    validateBinding(b, provenTime);
    if (role !== "primary" && role !== "rescue") throw new Error("unknown POP role");
    if (policy !== "ready" && policy !== "required") throw new Error("unknown rescue policy");
    if (primaryKeyChainHash.length !== 32 || rescueKey.length !== 32)
      throw new Error("POP key bindings must be 32 bytes");
    if (challenge.length !== 32 || !challenge.some((x) => x !== 0))
      throw new Error("POP challenge must be nonzero and 32 bytes");
    const parties = beginCell().storeAddress(b.wallet).storeBuffer(b.module.hash).endCell();
    const keys = beginCell()
      .storeUint(1, 8)
      .storeBuffer(primaryKeyChainHash)
      .storeBuffer(rescueKey)
      .storeUint(policy === "ready" ? 1 : 2, 8)
      .endCell();
    this.#role = role;
    this.#cell = beginCell()
      .storeUint(0x504f5033, 32)
      .storeInt(b.globalId, 32)
      .storeBuffer(b.network)
      .storeUint(role === "primary" ? 1 : 2, 8)
      .storeBuffer(challenge)
      .storeUint(b.validUntil, 32)
      .storeRef(parties)
      .storeRef(keys)
      .endCell();
    this.#digest = beginCell()
      .storeBuffer(new TextEncoder().encode("TOS-POP1"))
      .storeRef(this.#cell)
      .endCell()
      .hash()
      .slice();
  }
  get cell(): Cell {
    return this.#cell;
  }
  get role(): V5R2Role {
    return this.#role;
  }
  get digest(): Uint8Array {
    return this.#digest.slice();
  }
  get signingContext(): Uint8Array {
    return new TextEncoder().encode("TOS-RESCUE-POP-v1");
  }
  encodeSubmission(signature: Uint8Array): Cell {
    return submission(0x50505333, this.#cell, this.#role, signature);
  }
}

export interface V5R2PreparationPlan {
  moduleAmount: bigint;
  vaultAmount: bigint;
  moduleInit: Cell;
  metadata: Cell;
  vaultInit: Cell;
}
/** SLH-only bounded deployment intent; pairing, live fee fit and delivery require separate checks. */
export class V5R2PreparationRequest {
  readonly #cell: Cell;
  readonly #deploymentValue: bigint;
  constructor(b: V5R2RecoveryBinding, plan: V5R2PreparationPlan, provenTime: number) {
    validateBinding(b, provenTime);
    if (plan.moduleAmount <= 0n || plan.vaultAmount <= 0n)
      throw new Error("deployment amounts must be positive");
    if (plan.moduleAmount >= 1n << 120n || plan.vaultAmount >= 1n << 120n)
      throw new Error("deployment amount exceeds Coins encoding");
    // BigInt addition is exact; the two validated Coins fields bound this total
    // below 2^121, without an unreachable fixed-width overflow guard.
    this.#deploymentValue = plan.moduleAmount + plan.vaultAmount;
    const targets = beginCell()
      .storeCoins(plan.moduleAmount)
      .storeCoins(plan.vaultAmount)
      .storeRef(plan.moduleInit)
      .storeRef(plan.metadata)
      .storeRef(plan.vaultInit)
      .endCell();
    this.#cell = beginCell()
      .storeUint(0x50525033, 32)
      .storeInt(b.globalId, 32)
      .storeBuffer(b.network)
      .storeAddress(b.wallet)
      .storeBuffer(b.module.hash)
      .storeUint(b.validUntil, 32)
      .storeRef(targets)
      .endCell();
  }
  get cell(): Cell {
    return this.#cell;
  }
  get digest(): Uint8Array {
    return this.#cell.hash().slice();
  }
  get deploymentValue(): bigint {
    return this.#deploymentValue;
  }
  get signingContext(): Uint8Array {
    return new TextEncoder().encode("TOS-RESCUE-FEE-PREP-v1");
  }
  encodeSubmission(signature: Uint8Array): Cell {
    return submission(0x46505233, this.#cell, "rescue", signature);
  }
}
