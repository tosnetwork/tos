import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Address, beginCell, bytesToHex } from "@tos/core";
import { V5R2AuthRequest, validateV5R2Actions, type V5R2Action } from "./V5R2Auth.js";

const hash = (last: number) => { const x = new Uint8Array(32); x[31] = last; return x; };
const binding = () => ({ globalId: 42, network: hash(123), wallet: new Address(0, hash(100)),
  module: new Address(0, hash(101)), epoch: 1n, nonce: 0n, validUntil: 1780000600 });
const empty = () => beginCell().endCell();
const byte = (n: number) => beginCell().storeUint(n, 8).endCell();
const actionCell = (mode: number, previous = empty(), tag = 0x0ec3c86d) =>
  beginCell().storeUint(tag, 32).storeUint(mode, 8).storeRef(previous).storeRef(empty()).endCell();
const request = (action: V5R2Action = { kind: "execute", actions: empty() }) =>
  new V5R2AuthRequest(binding(), "rescue", action, 1780000000);

describe("V5R2 AUTH framing", () => {
  it("matches all independently generated Rust/Python request, digest and submission vectors", () => {
    const cases = JSON.parse(readFileSync(new URL(
      "../../../../../tosctl/src/node-control/contracts/tests/fixtures/v5r2/auth-wire.json", import.meta.url), "utf8"));
    for (const v of cases) {
      const action: V5R2Action = v.kind === 0 ? { kind: "execute", actions: empty() }
        : v.kind === 1 ? { kind: "configure", ...(v.replacement ? { replacement: { metadata: byte(1), vaultInit: byte(2) } } : {}) }
        : v.kind === 3 ? { kind: "lock" }
        : { kind: "migrate", moduleInit: byte(1), metadata: byte(2), vaultInit: byte(3) };
      const r = new V5R2AuthRequest(binding(), v.role === 1 ? "primary" : "rescue", action, 1780000000);
      expect(bytesToHex(r.cell.hash())).toBe(v.request_hash);
      expect(bytesToHex(r.digest)).toBe(v.digest);
      expect(bytesToHex(r.encodeSubmission(new Uint8Array(r.signatureBytes).fill(0xa5)).hash())).toBe(v.submission_hash);
    }
  });
  it("checks all 256 mode bytes and the oldest action", () => {
    const allowed = [2, 3, 18, 19, 66, 67, 82, 83, 130, 131, 146, 147];
    for (let mode = 0; mode < 256; mode += 1) {
      const validate = () => validateV5R2Actions(actionCell(mode));
      if (allowed.includes(mode)) expect(validate).not.toThrow(); else expect(validate).toThrow("forbidden send mode");
    }
    expect(() => validateV5R2Actions(actionCell(3, actionCell(32)))).toThrow("forbidden send mode");
  });
  it("bounds the complete list and forbids authority actions and malformed tails", () => {
    let actions = empty();
    for (let n = 0; n <= 256; n += 1) {
      if (n <= 255) expect(() => validateV5R2Actions(actions)).not.toThrow();
      else expect(() => validateV5R2Actions(actions)).toThrow("at most 255");
      actions = actionCell(3, actions);
    }
    for (const tag of [0xad4de08e, 0x36e6b809, 0]) {
      expect(() => validateV5R2Actions(actionCell(3, empty(), tag))).toThrow("only send actions");
    }
    expect(() => validateV5R2Actions(beginCell().storeRef(empty()).endCell())).toThrow("tail must be empty");
    expect(() => validateV5R2Actions(byte(1))).toThrow("send action shape");
  });
  it("refuses PRIMARY control and classical signature lengths", () => {
    for (const a of [{ kind: "configure" }, { kind: "lock" },
      { kind: "migrate", moduleInit: byte(1), metadata: byte(2), vaultInit: byte(3) }] as V5R2Action[]) {
      expect(() => new V5R2AuthRequest(binding(), "primary", a, 1780000000)).toThrow("primary may only execute");
    }
    for (const role of ["primary", "rescue"] as const) {
      const r = new V5R2AuthRequest(binding(), role, { kind: "execute", actions: empty() }, 1780000000);
      for (const n of [0, 64, r.signatureBytes - 1, r.signatureBytes + 1]) {
        expect(() => r.encodeSubmission(new Uint8Array(n))).toThrow("wrong PQ signature length");
      }
    }
  });
  it("enforces proven TTL, workchain, identities and unsigned counter bounds", () => {
    for (const delta of [0, -1, 3601]) expect(() => new V5R2AuthRequest(
      { ...binding(), validUntil: 1780000000 + delta }, "rescue", { kind: "lock" }, 1780000000)).toThrow("AUTH TTL");
    for (const delta of [1, 3600]) expect(() => new V5R2AuthRequest(
      { ...binding(), validUntil: 1780000000 + delta }, "rescue", { kind: "lock" }, 1780000000)).not.toThrow();
    for (const b of [{ ...binding(), wallet: new Address(-1, hash(100)) },
      { ...binding(), module: new Address(-1, hash(101)) }]) {
      expect(() => new V5R2AuthRequest(b, "rescue", { kind: "lock" }, 1780000000)).toThrow("basechain only");
    }
    expect(() => new V5R2AuthRequest({ ...binding(), module: binding().wallet }, "rescue", { kind: "lock" }, 1780000000)).toThrow("must differ");
    for (const nonce of [-1n, 1n << 64n]) expect(() => new V5R2AuthRequest(
      { ...binding(), nonce }, "rescue", { kind: "lock" }, 1780000000)).toThrow();
  });
  it("returns isolated digest/context buffers", () => {
    const r = request(); const digest = bytesToHex(r.digest);
    r.digest.fill(0); r.signingContext.fill(0);
    expect(bytesToHex(r.digest)).toBe(digest);
    expect(new TextDecoder().decode(r.signingContext)).toBe("TOS-AUTH-SLH-DSA-SHA2-128S-v1");
  });
});
