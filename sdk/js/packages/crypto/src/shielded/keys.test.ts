// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * The TypeScript key hierarchy against the Rust reference.
 *
 * `generated/wallet-vectors.json` is written by
 * `tools/shielded-pool-wallet/src/bin/wallet-vectors.rs`, and that
 * implementation is the one driven against the pool in the sandbox. Holding
 * this to those numbers is what makes the two the same wallet, rather than two
 * readings of the same document by the same person.
 */

import { describe, expect, it } from "vitest";

import vectors from "./generated/wallet-vectors.json" with { type: "json" };
import {
  PoolInstance,
  executionDomain,
  frBe32,
  outputDataHash,
  pqAuthKeyHash,
  publicRecipientHash,
  recoveryTemplateHash,
} from "./keys.js";

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const fromHex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
/** A required element; the repository compiles with `noUncheckedIndexedAccess`. */
function need<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`the vector file is missing ${what}`);
  }
  return value;
}

describe("section 2 key hierarchy", () => {
  it("derives what the Rust reference derives, for every seed and domain", () => {
    expect(vectors.instances.length).toBeGreaterThan(1);
    for (const instance of vectors.instances) {
      const wallet = new PoolInstance(fromHex(instance.seed), BigInt(instance.execution_domain));

      const { d, z } = wallet.mlkemSeed();
      expect(hex(d), "ML-KEM d").toBe(instance.mlkem_d);
      expect(hex(z), "ML-KEM z").toBe(instance.mlkem_z);
      // The encapsulation key is 1184 bytes, so the vector carries a digest of
      // it. That it matches means the two libraries' KeyGen_internal agree.
      expect(
        hex(frBe32(pqAuthKeyHash(wallet.mlkemEncapsulationKey()))),
        "ML-KEM encapsulation key",
      ).toBe(instance.mlkem_encapsulation_key_sha);

      for (const entry of instance.indices) {
        const index = BigInt(entry.index);
        expect(wallet.ownerNfKey(index).toString(), `owner key at ${index}`).toBe(
          entry.owner_nf_key,
        );
        expect(wallet.ownerNfKeyHash(index).toString(), `owner hash at ${index}`).toBe(
          entry.owner_nf_key_hash,
        );
        expect(hex(wallet.mldsaSeed(index)), `ML-DSA seed at ${index}`).toBe(entry.mldsa_seed);
        expect(wallet.pqAuthKeyHash(index).toString(), `PQ key hash at ${index}`).toBe(
          entry.mldsa_public_key_hash,
        );
      }
    }
  });

  it("separates two domains and two mnemonics", () => {
    // The vectors carry both halves; this is the property they establish,
    // stated so a regenerated file that lost it would be noticed.
    const seen = new Map<string, string>();
    for (const instance of vectors.instances) {
      for (const entry of instance.indices) {
        const where = `${instance.seed}/${instance.execution_domain}`;
        const key = `${entry.index}`;
        const previous = seen.get(`${key}:${entry.owner_nf_key}`);
        expect(previous, `index ${key} derives one key under ${where} and ${previous}`).toBe(
          undefined,
        );
        seen.set(`${key}:${entry.owner_nf_key}`, where);
      }
    }
  });

  it("computes the derived public inputs the contract recomputes", () => {
    const derived = vectors.derived_inputs;
    const payload = Uint8Array.from({ length: 1233 }, (_, i) => (i & 0xff) ^ 0x21);
    expect(outputDataHash(payload).toString()).toBe(derived.output_data_hash);

    const first = need(vectors.instances[0], "an instance");
    const wallet = new PoolInstance(fromHex(first.seed), BigInt(first.execution_domain));
    expect(pqAuthKeyHash(wallet.mldsaPublicKey(0n)).toString()).toBe(derived.pq_auth_key_hash);
    expect(publicRecipientHash(new Uint8Array(32).fill(0x42)).toString()).toBe(
      derived.public_recipient_hash,
    );
    expect(executionDomain(-239, new Uint8Array(32).fill(0x7a)).toString()).toBe(
      derived.execution_domain,
    );
    expect(recoveryTemplateHash(0x5eedn, 0x1234n).toString()).toBe(derived.recovery_template_hash);
  });

  it("signs with the key the note is locked to", () => {
    const wallet = new PoolInstance(new Uint8Array(32).fill(0x11), 7n);
    const signature = wallet.signIntent(3n, 0x1234n);
    expect(signature.length).toBe(2420);
    expect(wallet.mldsaPublicKey(3n).length).toBe(1312);
  });

  it("rejects a field element at or above the modulus", async () => {
    const { frFromBe32 } = await import("./keys.js");
    expect(() => frFromBe32(new Uint8Array(32).fill(0xff))).toThrow();
    expect(() => frFromBe32(new Uint8Array(31))).toThrow();
  });
});
