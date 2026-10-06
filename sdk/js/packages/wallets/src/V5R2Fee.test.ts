import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Address, Cell, beginCell, bytesToHex } from "@tos/core";
import { V5R2AuthRequest } from "./V5R2Auth.js";
import { V5R2PopRequest, V5R2PreparationRequest } from "./V5R2Recovery.js";
import { V5R2FeeIntent, validateV5R2FeePayload, type V5R2FeeClass } from "./V5R2Fee.js";
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
const fee = () => ({
  vault: new Address(0, hash(103)),
  configHash: hash(104),
  epoch0: 1779992790,
  leaf: 8,
  validUntil: 1780000600,
  value: 5000000000n,
});
const byte = (n: number) => beginCell().storeUint(n, 8).endCell();
function payload(kind: V5R2FeeClass, role: "primary" | "rescue" = "rescue"): Cell {
  const sig = new Uint8Array(role === "primary" ? 2420 : 7856).fill(0xa5);
  if (kind === "rescue-auth")
    return new V5R2AuthRequest(
      { ...binding(), epoch: 1n, nonce: 0n },
      role,
      { kind: "execute", actions: beginCell().endCell() },
      1780000000,
    ).encodeSubmission(sig);
  if (kind === "pop")
    return new V5R2PopRequest(
      binding(),
      role,
      "required",
      hash(111),
      hash(222),
      hash(99),
      1780000000,
    ).encodeSubmission(sig);
  return new V5R2PreparationRequest(
    binding(),
    {
      moduleAmount: 10000000000n,
      vaultAmount: 20000000000n,
      moduleInit: byte(1),
      metadata: byte(2),
      vaultInit: byte(3),
    },
    1780000000,
  ).encodeSubmission(sig);
}
function signature(leaf = 8): Uint8Array {
  const s = new Uint8Array(2832).fill(0xa5),
    v = new DataView(s.buffer);
  for (const [offset, value] of [
    [0, 0],
    [4, leaf],
    [8, 3],
    [2188, 8],
  ])
    v.setUint32(offset!, value!);
  return s;
}
describe("V5R2 LMS fee framing", () => {
  it("matches all independent complete fee intent/external vectors", () => {
    const vectors = JSON.parse(
      readFileSync(
        new URL(
          "../../../../../tosctl/src/node-control/contracts/tests/fixtures/v5r2/fee-wire.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    for (const v of vectors) {
      const kind: V5R2FeeClass = v.kind === 1 ? "rescue-auth" : v.kind === 2 ? "pop" : "prepare";
      const r = new V5R2FeeIntent(
        { ...fee(), value: BigInt(v.value) },
        kind,
        payload(kind),
        1780000000,
      );
      expect(bytesToHex(r.digest)).toBe(v.intent_hash);
      expect(bytesToHex(r.encodeExternal(signature()).hash())).toBe(v.external_hash);
      let chain = r.encodeExternal(signature()).refs[1]!;
      let count = 1;
      while (chain.refs.length) {
        expect(chain.bits.length).toBe(1016);
        chain = chain.refs[0]!;
        count += 1;
      }
      expect(count).toBe(23);
      expect(chain.bits.length).toBe(38 * 8);
    }
  });
  it("forbids PRIMARY AUTH but permits either key's non-authorizing POP", () => {
    expect(
      () => new V5R2FeeIntent(fee(), "rescue-auth", payload("rescue-auth", "primary"), 1780000000),
    ).toThrow("cannot fund primary AUTH");
    for (const role of ["primary", "rescue"] as const)
      expect(() => new V5R2FeeIntent(fee(), "pop", payload("pop", role), 1780000000)).not.toThrow();
  });
  it("binds each class to the exact submission constructor and shape", () => {
    for (const kind of ["rescue-auth", "pop", "prepare"] as const) {
      for (const other of ["rescue-auth", "pop", "prepare"] as const)
        if (kind !== other)
          expect(() => validateV5R2FeePayload(kind, payload(other))).toThrow(
            "class/submission mismatch",
          );
      expect(() => validateV5R2FeePayload(kind, byte(1))).toThrow("fee payload shape");
    }
  });
  it("bounds slots, TTL, terminal leaf, time, namespace and amount before signing", () => {
    const p = payload("rescue-auth");
    for (const leaf of [8, 9, 10, 11])
      expect(
        () => new V5R2FeeIntent({ ...fee(), leaf }, "rescue-auth", p, 1780000000),
      ).not.toThrow();
    for (const leaf of [4, 7, 12])
      expect(() => new V5R2FeeIntent({ ...fee(), leaf }, "rescue-auth", p, 1780000000)).toThrow(
        "current slot",
      );
    for (const leaf of [-1, 1 << 20, 1.5])
      expect(() => new V5R2FeeIntent({ ...fee(), leaf }, "rescue-auth", p, 1780000000)).toThrow(
        "invalid leaf",
      );
    for (const delta of [0, -1, 3601])
      expect(
        () =>
          new V5R2FeeIntent(
            { ...fee(), validUntil: 1780000000 + delta },
            "rescue-auth",
            p,
            1780000000,
          ),
      ).toThrow("fee TTL");
    for (const value of [0n, -1n, 1n << 120n])
      expect(() => new V5R2FeeIntent({ ...fee(), value }, "rescue-auth", p, 1780000000)).toThrow(
        "positive canonical Coins",
      );
    expect(
      () => new V5R2FeeIntent({ ...fee(), epoch0: 1780000001 }, "rescue-auth", p, 1780000000),
    ).toThrow("before fee epoch");
    expect(
      () =>
        new V5R2FeeIntent(
          { ...fee(), vault: new Address(-1, hash(103)) },
          "rescue-auth",
          p,
          1780000000,
        ),
    ).toThrow("basechain only");
    expect(
      () =>
        new V5R2FeeIntent(
          { ...fee(), configHash: new Uint8Array(31) },
          "rescue-auth",
          p,
          1780000000,
        ),
    ).toThrow("config hash");
  });
  it("refuses signature aliases, wrong leaves, truncations and extensions", () => {
    const r = new V5R2FeeIntent(fee(), "rescue-auth", payload("rescue-auth"), 1780000000);
    for (const size of [0, 64, 2831, 2833])
      expect(() => r.encodeExternal(new Uint8Array(size))).toThrow("fee signature length");
    for (const offset of [0, 4, 8, 2188]) {
      const s = signature();
      new DataView(s.buffer).setUint32(offset, 99);
      expect(() => r.encodeExternal(s)).toThrow("profile/leaf mismatch");
    }
  });
});
