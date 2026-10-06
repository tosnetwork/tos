import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Address, beginCell, bytesToHex } from "@tos/core";
import { WalletV5R2, type V5R2GenesisParameters } from "./WalletV5R2.js";

const byte = (n: number) => beginCell().storeUint(n, 8).endCell();
const hash = (n: number) => { const x = new Uint8Array(32); x[30] = n >> 8; x[31] = n & 255; return x; };
const code = { wallet: byte(1), module: byte(2), vault: byte(3) };
const pins = { wallet: bytesToHex(code.wallet.hash()), module: bytesToHex(code.module.hash()), vault: bytesToHex(code.vault.hash()) };
function params(): V5R2GenesisParameters {
  const key = new Uint8Array(60); const v = new DataView(key.buffer);
  v.setUint32(0, 1); v.setUint32(4, 8); v.setUint32(8, 3);
  key.fill(0x33, 12, 28); key.fill(0x44, 28);
  return { globalId: 42, network: hash(123), walletId: 42, primaryKey: new Uint8Array(1312).fill(0x11),
    rescueKey: new Uint8Array(32).fill(0x22), policy: "ready", feeTreeId: hash(456), feePublicKey: key, epoch0: 1779992790 };
}
function vectors(name: string) {
  return JSON.parse(readFileSync(new URL(
    `../../../../../tosctl/src/node-control/contracts/tests/fixtures/v5r2/${name}-wire.json`, import.meta.url), "utf8"));
}
describe("PQ-only V5R2 genesis and successor", () => {
  it("matches every Python/Rust genesis identity for both policies", () => {
    for (const row of vectors("genesis")) {
      const p = params(); p.policy = row.policy === 1 ? "ready" : "required";
      p.walletId = row.wallet_id; p.feeTreeId = hash(row.tree_id);
      const w = new WalletV5R2(code, pins, p);
      for (const [key, value] of Object.entries({ module_data: w.moduleData, module_init: w.moduleInit,
        metadata: w.metadata, wallet_data: w.walletData, wallet_init: w.walletInit,
        vault_data: w.vaultData, vault_init: w.vaultInit })) expect(bytesToHex(value.hash())).toBe(row[key]);
      expect(bytesToHex(w.configHash)).toBe(row.config_hash);
      expect(w.address.workchain).toBe(0);
      const state = w.walletData.beginParse();
      expect(state.loadBit()).toBe(false); state.loadUint(32); state.loadUint(32);
      expect(bytesToHex(state.loadBuffer(32))).toBe("00".repeat(32));
      expect(state.loadBit()).toBe(false);
    }
  });
  it("matches successor witnesses targeting the original wallet", () => {
    for (const row of vectors("successor")) {
      const p = params(); p.policy = row.policy === 1 ? "ready" : "required";
      p.walletId = row.wallet_id; p.feeTreeId = hash(row.tree_id);
      const w = new WalletV5R2(code, pins, p);
      const wallet = new Address(0, hash(row.wallet_id === 42 ? 100 : 101));
      const next = w.successorFor(wallet);
      expect(bytesToHex(next.vaultData.hash())).toBe(row.vault_data);
      expect(bytesToHex(next.vaultInit.hash())).toBe(row.vault_init);
      expect(bytesToHex(next.configHash)).toBe(row.config_hash);
      expect(bytesToHex(next.wallet.hash)).toBe(row.wallet_address);
      expect(() => w.successorFor(new Address(-1, wallet.hash))).toThrow("basechain only");
      expect(() => w.successorFor(w.moduleAddress)).toThrow("must differ");
    }
  });
  it("refuses replacement code or unauthenticated pins for all three programs", () => {
    for (const name of ["wallet", "module", "vault"] as const) {
      expect(() => new WalletV5R2({ ...code, [name]: byte(99) }, pins, params())).toThrow("code pin mismatch");
      expect(() => new WalletV5R2(code, { ...pins, [name]: "00".repeat(32) }, params())).toThrow("code pin mismatch");
    }
  });
  it("refuses every wrong key/namespace size and alternate HSS profile", () => {
    for (const [name, size] of [["network",32], ["primaryKey",1312], ["rescueKey",32], ["feeTreeId",32], ["feePublicKey",60]] as const) {
      for (const length of [size-1,size+1]) expect(() => new WalletV5R2(code,pins,
        { ...params(), [name]: new Uint8Array(length) })).toThrow("must be");
    }
    for (const offset of [0,4,8]) {
      const p = params(); new DataView(p.feePublicKey.buffer).setUint32(offset,99);
      expect(() => new WalletV5R2(code,pins,p)).toThrow("HSS L1 H20/W4");
    }
    expect(() => new WalletV5R2(code,pins,{ ...params(),policy: "invalid" as "ready" })).toThrow("unknown rescue policy");
  });
  it("does not retain mutable input key arrays", () => {
    const p = params(); const w = new WalletV5R2(code,pins,p); const wallet=new Address(0,hash(100));
    const original=bytesToHex(w.successorFor(wallet).vaultInit.hash());
    p.network.fill(0);p.feePublicKey.fill(0);p.primaryKey.fill(0);p.feeTreeId.fill(0);
    expect(bytesToHex(w.successorFor(wallet).vaultInit.hash())).toBe(original);
    const config=bytesToHex(w.configHash);w.configHash.fill(0);expect(bytesToHex(w.configHash)).toBe(config);
  });
});
