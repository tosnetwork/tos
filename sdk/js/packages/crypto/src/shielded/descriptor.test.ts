// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Section 2.4 descriptors, against the Rust reference.
 *
 * A descriptor is 2573 bytes of derived material, so the vector carries its
 * hash: matching that means every field is at the offset the Rust wallet puts
 * it at, which a round trip on this side alone would not establish.
 */

import { describe, expect, it } from "vitest";

import { DESCRIPTOR_BYTES, fromBytes, issue, requireDomain, toBytes } from "./descriptor.js";
import vectors from "./generated/wallet-vectors.json" with { type: "json" };
import { PoolInstance, outputDataHash } from "./keys.js";

const fromHex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const frHex = (value: bigint): string => {
  const out = new Uint8Array(32);
  let rest = value;
  for (let at = 31; at >= 0; at -= 1) {
    out[at] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return hex(out);
};

describe("section 2.4 descriptors", () => {
  it("serialises to the bytes the Rust reference serialises", () => {
    for (const instance of vectors.instances) {
      const wallet = new PoolInstance(fromHex(instance.seed), BigInt(instance.execution_domain));
      for (const entry of instance.indices) {
        const bytes = toBytes(issue(wallet, BigInt(entry.index)));
        expect(bytes.length).toBe(DESCRIPTOR_BYTES);
        expect(frHex(outputDataHash(bytes)), `descriptor at ${entry.index}`).toBe(
          entry.descriptor_sha,
        );
      }
    }
  });

  it("round trips, and names the pool it is for", () => {
    const first = vectors.instances[0];
    if (first === undefined) {
      throw new Error("the vector file has no instances");
    }
    const domain = BigInt(first.execution_domain);
    const wallet = new PoolInstance(fromHex(first.seed), domain);
    const descriptor = issue(wallet, 11n);
    const bytes = toBytes(descriptor);
    const back = fromBytes(bytes);

    expect(back.noteKeyIndex).toBe(11n);
    expect(back.executionDomain).toBe(domain);
    expect(back.ownerNfKeyHash).toBe(descriptor.ownerNfKeyHash);
    expect(hex(back.pqAuthPublicKey)).toBe(hex(descriptor.pqAuthPublicKey));
    expect(hex(back.mlkemEncapsulationKey)).toBe(hex(descriptor.mlkemEncapsulationKey));
    expect(hex(toBytes(back))).toBe(hex(bytes));

    expect(() => requireDomain(back, domain)).not.toThrow();
    expect(() => requireDomain(back, domain + 1n)).toThrow();
  });

  it("refuses bytes that are not a descriptor", () => {
    const first = vectors.instances[0];
    if (first === undefined) {
      throw new Error("the vector file has no instances");
    }
    const wallet = new PoolInstance(fromHex(first.seed), BigInt(first.execution_domain));
    const bytes = toBytes(issue(wallet, 0n));

    const wrongMagic = Uint8Array.from(bytes);
    wrongMagic.set([0x52], 0);
    expect(() => fromBytes(wrongMagic)).toThrow();

    const wrongVersion = Uint8Array.from(bytes);
    wrongVersion.set([2], 4);
    expect(() => fromBytes(wrongVersion)).toThrow();

    expect(() => fromBytes(bytes.slice(0, DESCRIPTOR_BYTES - 1))).toThrow();

    // A field element at or above the modulus is not a field element.
    const wrongDomain = Uint8Array.from(bytes);
    wrongDomain.fill(0xff, 5, 37);
    expect(() => fromBytes(wrongDomain)).toThrow();
  });
});
