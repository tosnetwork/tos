// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Section 3 delivery and section 3.1 import, against the Rust reference.
 *
 * The vectors carry whole payloads that the Rust wallet sealed. Sealing is
 * randomised, so they cannot be compared byte for byte -- but opening one is
 * deterministic, and a TypeScript wallet that opens what the Rust one sealed
 * is the only evidence that two independent ML-KEM implementations, two
 * XChaCha20-Poly1305 implementations and two SHAKE256 key schedules
 * interoperate. Reading both against the profile would not establish it.
 */

import { describe, expect, it } from "vitest";

import { Refused, decodePlaintext, encodePlaintext, importNote, open, seal } from "./delivery.js";
import vectors from "./generated/wallet-vectors.json" with { type: "json" };
import { PoolInstance, outputDataHash } from "./keys.js";

const fromHex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

/** A required element; the repository compiles with `noUncheckedIndexedAccess`. */
function need<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`the vector file is missing ${what}`);
  }
  return value;
}

function firstInstance() {
  return need(vectors.instances[0], "an instance");
}

function wallet(): PoolInstance {
  const instance = firstInstance();
  return new PoolInstance(fromHex(instance.seed), BigInt(instance.execution_domain));
}

describe("section 3 delivery", () => {
  it("opens every payload the Rust wallet sealed", () => {
    expect(vectors.plaintexts.length).toBeGreaterThan(0);
    for (const vector of vectors.plaintexts) {
      const sealed = fromHex(vector.sealed);
      expect(sealed.length, `${vector.kind} payload length`).toBe(vector.sealed_length);

      const opened = open(wallet(), sealed, vector.slot);
      expect(opened.kind, `${vector.kind} kind`).toBe(vector.kind);
      expect(opened.noteKeyIndex.toString(), `${vector.kind} index`).toBe(
        String(vector.note_key_index),
      );
      expect(opened.amount.toString(), `${vector.kind} amount`).toBe(vector.amount);
      expect(opened.noteSecret.toString(), `${vector.kind} secret`).toBe(vector.note_secret);

      // And the plaintext encoding itself, which is a fixed vector.
      expect(hex(encodePlaintext(opened)), `${vector.kind} plaintext bytes`).toBe(
        vector.plaintext_bytes,
      );
    }
  });

  it("reaches the same note the Rust wallet reached", () => {
    for (const vector of vectors.plaintexts) {
      const instance = wallet();
      const opened = open(instance, fromHex(vector.sealed), vector.slot);
      const chainHash = outputDataHash(fromHex(vector.sealed));
      const note = importNote(instance, opened, {
        outputDataHash: chainHash,
        noteBody: BigInt(vector.note_body_from_chain_hash),
      });
      expect(note.ownerCommitment.toString(), `${vector.kind} owner`).toBe(vector.owner_commitment);
      expect(note.noteBody.toString(), `${vector.kind} note body`).toBe(
        vector.note_body_from_chain_hash,
      );
      expect(note.spendable, `${vector.kind} spendable`).toBe(vector.spendable);
    }
  });

  it("round trips its own sealing", () => {
    const instance = wallet();
    const plaintext = {
      slot: 1,
      kind: "Ordinary" as const,
      amount: 42n,
      noteSecret: 0x1234n,
      ownerNfKeyHash: instance.ownerNfKeyHash(9n),
      noteKeyIndex: 9n,
      pqAuthKeyHash: instance.pqAuthKeyHash(9n),
    };
    const sealed = seal(instance.mlkemEncapsulationKey(), instance.executionDomain, plaintext);
    expect(sealed.length).toBe(1233);
    expect(open(instance, sealed, 1)).toEqual(plaintext);

    // Bound to its slot and to its domain, so neither can be replayed.
    expect(() => open(instance, sealed, 2)).toThrow(Refused);
    const elsewhere = new PoolInstance(fromHex(firstInstance().seed), 999n);
    expect(() => open(elsewhere, sealed, 1)).toThrow(Refused);
  });

  it("refuses malformed plaintexts by shape, each for its own reason", () => {
    const instance = wallet();
    const good = encodePlaintext({
      slot: 0,
      kind: "Ordinary",
      amount: 1n,
      noteSecret: 9n,
      ownerNfKeyHash: 1n,
      noteKeyIndex: 0n,
      pqAuthKeyHash: 2n,
    });
    const refusal = (bytes: Uint8Array, slot = 0): string => {
      try {
        decodePlaintext(bytes, slot);
      } catch (error) {
        return (error as Refused).why;
      }
      throw new Error("a malformed plaintext was accepted");
    };

    expect(refusal(good.slice(0, 127))).toBe("PlaintextLength");
    const magic = Uint8Array.from(good);
    magic.set([0x52], 0);
    expect(refusal(magic)).toBe("Magic");
    const version = Uint8Array.from(good);
    version[4] = 2;
    expect(refusal(version)).toBe("Version");
    expect(refusal(good, 1)).toBe("Slot");
    for (const flags of [0x0004, 0x8000, 0x0003]) {
      const wrong = Uint8Array.from(good);
      new DataView(wrong.buffer).setUint16(6, flags, false);
      expect(refusal(wrong), `flags ${flags}`).toBe("Flags");
    }
    const zero = Uint8Array.from(good);
    zero.fill(0, 24, 56);
    expect(refusal(zero)).toBe("NoteSecretZero");
    const huge = Uint8Array.from(good);
    huge.fill(0xff, 24, 56);
    expect(refusal(huge)).toBe("NoteSecretNotCanonical");
    expect(instance.executionDomain).toBeTypeOf("bigint");
  });

  it("refuses a payload whose fields this wallet does not derive", () => {
    const instance = wallet();
    const vector = need(vectors.plaintexts[0], "a plaintext vector");
    const opened = open(instance, fromHex(vector.sealed), vector.slot);
    const chain = {
      outputDataHash: outputDataHash(fromHex(vector.sealed)),
      noteBody: BigInt(vector.note_body_from_chain_hash),
    };

    const why = (mutate: (p: typeof opened) => void): string => {
      const broken = { ...opened };
      mutate(broken);
      try {
        importNote(instance, broken, chain);
      } catch (error) {
        return (error as Refused).why;
      }
      throw new Error("a broken payload was imported");
    };

    expect(
      why((p) => {
        p.ownerNfKeyHash = 1n;
      }),
    ).toBe("OwnerNfKeyHash");
    expect(
      why((p) => {
        p.pqAuthKeyHash = 2n;
      }),
    ).toBe("PqAuthKeyHash");
    expect(
      why((p) => {
        p.amount = 0n;
      }),
    ).toBe("Amount");
    expect(
      why((p) => {
        p.amount = 1n << 120n;
      }),
    ).toBe("Amount");
    // Everything in the payload stays consistent; it simply describes a note
    // other than the one the chain published.
    expect(
      why((p) => {
        p.noteSecret = 7n;
      }),
    ).toBe("NoteBodyMismatch");
  });
});
