import { Address, Cell, beginCell, bytesToHex } from "@tos/core";

export type V5R2Policy = "ready" | "required";
export interface V5R2CodeBundle {
  wallet: Cell;
  module: Cell;
  vault: Cell;
}
/** Pins must come from an independently authenticated release, never an RPC response. */
export interface V5R2CodePins { wallet: string; module: string; vault: string; }
export interface V5R2GenesisParameters {
  globalId: number;
  network: Uint8Array;
  walletId: number;
  primaryKey: Uint8Array;
  rescueKey: Uint8Array;
  policy: V5R2Policy;
  feeTreeId: Uint8Array;
  feePublicKey: Uint8Array;
  epoch0: number;
}

function requireBytes(value: Uint8Array, size: number, name: string): void {
  if (value.length !== size) throw new Error(`${name} must be ${size} bytes`);
}
function checkCode(code: Cell, pin: string): void {
  if (!/^[0-9a-f]{64}$/.test(pin) || bytesToHex(code.hash()) !== pin) throw new Error("genesis code pin mismatch");
  const seen = new Set<Cell>(); const pending = [code];
  while (pending.length) {
    const current = pending.pop();
    if (current === undefined || seen.has(current)) continue;
    if (current.isExotic || current.level() !== 0) throw new Error("ordinary level-zero code required");
    seen.add(current);
    pending.push(...current.refs);
  }
}
function stateInit(code: Cell, data: Cell): Cell {
  return beginCell().storeUint(6, 5).storeRef(code).storeRef(data).endCell();
}
function keyChain(bytes: Uint8Array): Cell {
  let tail: Cell | undefined;
  for (let offset = Math.floor((bytes.length - 1) / 127) * 127; offset >= 0; offset -= 127) {
    const b = beginCell().storeBuffer(bytes.subarray(offset, Math.min(offset + 127, bytes.length)));
    if (tail !== undefined) b.storeRef(tail);
    tail = b.endCell();
  }
  if (tail === undefined) throw new Error("empty public key");
  return tail;
}
function pairedVault(p: V5R2GenesisParameters, wallet: Address, module: Address, metadata: Cell, key: Cell) {
  const configHash = beginCell().storeUint(1, 8).storeInt(p.globalId, 32)
    .storeBuffer(p.network).storeAddress(wallet).storeAddress(module).storeRef(metadata).endCell().hash().slice();
  const prefix = beginCell().storeUint(0x41553252, 32).storeInt(p.globalId, 32)
    .storeBuffer(p.network).storeAddress(wallet).storeBuffer(module.hash).storeUint(2, 8).endCell();
  const parties = beginCell().storeAddress(wallet).storeBuffer(module.hash).endCell().hash();
  const data = beginCell().storeUint(3, 8).storeUint(0, 32).storeBuffer(configHash)
    .storeUint(p.epoch0, 32).storeAddress(module).storeBuffer(parties).storeRef(key).storeRef(prefix).endCell();
  return { data, configHash };
}

/**
 * Complete PQ-only StateInit construction DAG. This establishes pairing and
 * code identity, not possession, deployment, live policy or payment readiness.
 * Signing/transport do not use the classical Wallet interface.
 */
export class WalletV5R2 {
  readonly #code: V5R2CodeBundle;
  readonly #parameters: V5R2GenesisParameters;
  readonly #key: Cell;
  readonly moduleData: Cell;
  readonly moduleInit: Cell;
  readonly metadata: Cell;
  readonly walletData: Cell;
  readonly walletInit: Cell;
  readonly vaultData: Cell;
  readonly vaultInit: Cell;
  readonly address: Address;
  readonly moduleAddress: Address;
  readonly vaultAddress: Address;
  readonly #configHash: Uint8Array;

  constructor(code: V5R2CodeBundle, pins: V5R2CodePins, parameters: V5R2GenesisParameters) {
    for (const name of ["wallet", "module", "vault"] as const) checkCode(code[name], pins[name]);
    const p = { ...parameters, network: parameters.network.slice(), primaryKey: parameters.primaryKey.slice(),
      rescueKey: parameters.rescueKey.slice(), feeTreeId: parameters.feeTreeId.slice(), feePublicKey: parameters.feePublicKey.slice() };
    requireBytes(p.network, 32, "network"); requireBytes(p.primaryKey, 1312, "primary key");
    requireBytes(p.rescueKey, 32, "rescue key"); requireBytes(p.feeTreeId, 32, "fee tree ID");
    requireBytes(p.feePublicKey, 60, "fee public key");
    const view = new DataView(p.feePublicKey.buffer, p.feePublicKey.byteOffset, 60);
    if (view.getUint32(0) !== 1 || view.getUint32(4) !== 8 || view.getUint32(8) !== 3) throw new Error("genesis requires HSS L1 H20/W4");
    if (p.policy !== "ready" && p.policy !== "required") throw new Error("unknown rescue policy");
    this.#code = { ...code }; this.#parameters = p;
    this.moduleData = beginCell().storeUint(1, 8).storeInt(p.globalId, 32).storeBuffer(p.network)
      .storeUint(1, 8).storeRef(keyChain(p.primaryKey)).storeBuffer(p.rescueKey)
      .storeUint(p.policy === "ready" ? 1 : 2, 8).endCell();
    this.moduleInit = stateInit(code.module, this.moduleData);
    this.moduleAddress = new Address(0, this.moduleInit.hash().slice());
    this.#key = keyChain(p.feePublicKey);
    this.metadata = beginCell().storeUint(1, 8).storeUint(1, 8).storeBuffer(p.feeTreeId)
      .storeUint(p.epoch0, 32).storeUint(3600, 32).storeUint(4, 16).storeRef(this.#key).endCell();
    const auth = beginCell().storeUint(4, 8).storeUint(2, 2).storeUint(0, 16).storeUint(1, 64)
      .storeUint(0, 64).storeUint(0, 64).storeRef(this.moduleInit).storeRef(this.metadata).endCell();
    this.walletData = beginCell().storeBit(false).storeUint(0, 32).storeUint(p.walletId, 32)
      .storeBuffer(new Uint8Array(32)).storeBit(false).storeRef(auth).endCell();
    this.walletInit = stateInit(code.wallet, this.walletData);
    this.address = new Address(0, this.walletInit.hash().slice());
    const paired = pairedVault(p, this.address, this.moduleAddress, this.metadata, this.#key);
    this.vaultData = paired.data; this.#configHash = paired.configHash;
    this.vaultInit = stateInit(code.vault, this.vaultData);
    this.vaultAddress = new Address(0, this.vaultInit.hash().slice());
  }
  get configHash(): Uint8Array { return this.#configHash.slice(); }

  /** New pair targets the existing wallet address; assets remain at that address. */
  successorFor(wallet: Address) {
    if (wallet.workchain !== 0) throw new Error("basechain only");
    if (wallet.equals(this.moduleAddress)) throw new Error("successor wallet and module must differ");
    const paired = pairedVault(this.#parameters, wallet, this.moduleAddress, this.metadata, this.#key);
    const vaultInit = stateInit(this.#code.vault, paired.data);
    return { wallet, moduleData: this.moduleData, moduleInit: this.moduleInit, metadata: this.metadata,
      vaultData: paired.data, vaultInit, configHash: paired.configHash,
      vaultAddress: new Address(0, vaultInit.hash().slice()) };
  }
}
