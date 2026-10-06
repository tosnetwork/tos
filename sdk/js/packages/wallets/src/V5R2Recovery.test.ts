import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Address, beginCell, bytesToHex } from "@tos/core";
import { V5R2PopRequest, V5R2PreparationRequest } from "./V5R2Recovery.js";
const hash = (n: number) => {
  const b = new Uint8Array(32);
  b[31] = n;
  return b;
};
const binding = () => ({
  globalId: 42,
  network: hash(123),
  wallet: new Address(0, hash(100)),
  module: new Address(0, hash(101)),
  validUntil: 1780000600,
});
const byte = (n: number) => beginCell().storeUint(n, 8).endCell();
const plan = (a = 1n, b = 1n) => ({
  moduleAmount: a,
  vaultAmount: b,
  moduleInit: byte(1),
  metadata: byte(2),
  vaultInit: byte(3),
});
const vectors = (name: string) =>
  JSON.parse(
    readFileSync(
      new URL(
        `../../../../../tosctl/src/node-control/contracts/tests/fixtures/v5r2/${name}-wire.json`,
        import.meta.url,
      ),
      "utf8",
    ),
  );
describe("V5R2 recovery wire", () => {
  it("matches independent POP vectors for both roles and policies", () => {
    for (const v of vectors("pop")) {
      const r = new V5R2PopRequest(
        binding(),
        v.role === 1 ? "primary" : "rescue",
        v.policy === 1 ? "ready" : "required",
        hash(111),
        hash(222),
        hash(99),
        1780000000,
      );
      expect(bytesToHex(r.cell.hash())).toBe(v.request_hash);
      expect(bytesToHex(r.digest)).toBe(v.digest);
      expect(
        bytesToHex(
          r.encodeSubmission(new Uint8Array(v.role === 1 ? 2420 : 7856).fill(0xa5)).hash(),
        ),
      ).toBe(v.submission_hash);
      expect(new TextDecoder().decode(r.signingContext)).toBe("TOS-RESCUE-POP-v1");
    }
  });
  it("matches independent preparation vectors including wide canonical Coins", () => {
    for (const v of vectors("prepare")) {
      const a = BigInt(v.module_amount),
        b = BigInt(v.vault_amount);
      const r = new V5R2PreparationRequest(binding(), plan(a, b), 1780000000);
      expect(bytesToHex(r.cell.hash())).toBe(v.request_hash);
      expect(bytesToHex(r.digest)).toBe(v.request_hash);
      expect(r.deploymentValue).toBe(a + b);
      expect(bytesToHex(r.encodeSubmission(new Uint8Array(7856).fill(0xa5)).hash())).toBe(
        v.submission_hash,
      );
    }
  });
  it("rejects zero or wrong-size challenges and malformed key bindings", () => {
    for (const c of [new Uint8Array(32), new Uint8Array(31).fill(1), new Uint8Array(33).fill(1)])
      expect(
        () =>
          new V5R2PopRequest(binding(), "primary", "ready", hash(111), hash(222), c, 1780000000),
      ).toThrow("POP challenge");
    expect(
      () =>
        new V5R2PopRequest(
          binding(),
          "primary",
          "ready",
          new Uint8Array(31),
          hash(222),
          hash(99),
          1780000000,
        ),
    ).toThrow("key bindings");
  });
  it("rejects expired and excessive TTL, wrong workchain and equal parties", () => {
    for (const delta of [0, -1, 3601]) {
      const b = { ...binding(), validUntil: 1780000000 + delta };
      expect(() => new V5R2PreparationRequest(b, plan(), 1780000000)).toThrow("recovery TTL");
      expect(
        () => new V5R2PopRequest(b, "rescue", "ready", hash(111), hash(222), hash(99), 1780000000),
      ).toThrow("recovery TTL");
    }
    expect(
      () =>
        new V5R2PreparationRequest(
          { ...binding(), wallet: new Address(-1, hash(100)) },
          plan(),
          1780000000,
        ),
    ).toThrow("basechain only");
    expect(
      () =>
        new V5R2PreparationRequest({ ...binding(), module: binding().wallet }, plan(), 1780000000),
    ).toThrow("must differ");
  });
  it("rejects invalid deployment values and classical or wrong-role signatures", () => {
    for (const value of [0n, -1n, 1n << 120n]) {
      expect(() => new V5R2PreparationRequest(binding(), plan(value, 1n), 1780000000)).toThrow();
      expect(() => new V5R2PreparationRequest(binding(), plan(1n, value), 1780000000)).toThrow();
    }
    const r = new V5R2PreparationRequest(binding(), plan(), 1780000000);
    for (const size of [64, 2420, 7855, 7857])
      expect(() => r.encodeSubmission(new Uint8Array(size))).toThrow("wrong PQ signature length");
    for (const role of ["primary", "rescue"] as const) {
      const pop = new V5R2PopRequest(
        binding(),
        role,
        "ready",
        hash(111),
        hash(222),
        hash(99),
        1780000000,
      );
      expect(() => pop.encodeSubmission(new Uint8Array(role === "primary" ? 7856 : 2420))).toThrow(
        "wrong PQ signature length",
      );
    }
  });
});
