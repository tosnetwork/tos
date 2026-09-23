// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Section 2: the V1 key hierarchy.
 *
 * The mnemonic is the root and nothing else is stored. Every key is recomputed
 * from the seed and a note index, which is what makes mnemonic-only recovery
 * possible: a restored wallet does not reconstruct a keystore, it recomputes
 * the keys and asks the chain which ones were used.
 *
 * Everything below the instance master is derived from `poolInstanceMaster`,
 * never from the mnemonic-global `poolMaster`. That is what stops the same
 * mnemonic and index from producing the same key on two pools, and it is why
 * the execution domain -- a deployment fact -- reaches this far into a wallet.
 */

import { sha256 } from "@noble/hashes/sha2";
import { shake256 } from "@noble/hashes/sha3";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";

import { MODULUS } from "./generated/poseidon2-params.js";
import { type Fr, h7 } from "./poseidon2.js";

/** Frozen sizes, sections 2.2 and 2.3. */
export const MLKEM_ENCAPSULATION_KEY_BYTES = 1184;
export const MLKEM_CIPHERTEXT_BYTES = 1088;
export const MLDSA_PUBLIC_KEY_BYTES = 1312;
export const MLDSA_SIGNATURE_BYTES = 2420;
export const SHARED_SECRET_BYTES = 32;

/** Section 9.4: exactly 28 ASCII bytes, and it never varies. */
export const SIGNATURE_CONTEXT = new TextEncoder().encode("TOS-SHIELDED-POOL-MLDSA44-v1");

const ascii = (text: string): Uint8Array => new TextEncoder().encode(text);

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function shake(parts: Uint8Array[], length: number): Uint8Array {
  return shake256(concat(...parts), { dkLen: length });
}

/** A field element as its 32 canonical big-endian bytes. */
export function frBe32(value: Fr): Uint8Array {
  const out = new Uint8Array(32);
  let rest = ((value % MODULUS) + MODULUS) % MODULUS;
  for (let at = 31; at >= 0; at -= 1) {
    out[at] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

/** The inverse, rejecting anything at or above the modulus. */
export function frFromBe32(bytes: Uint8Array): Fr {
  if (bytes.length !== 32) {
    throw new Error(`a field element is 32 bytes, not ${bytes.length}`);
  }
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  if (value >= MODULUS) {
    throw new Error("a field element at or above the modulus");
  }
  return value;
}

/** `reduce_to_field(SHA256(tag || body))`, section 3 and section 8's shape. */
export function taggedHash(tag: string, body: Uint8Array): Fr {
  const digest = sha256(concat(ascii(tag), body));
  let value = 0n;
  for (const byte of digest) {
    value = (value << 8n) | BigInt(byte);
  }
  return value % MODULUS;
}

/** Public inputs 6, 7 and 8. */
export const outputDataHash = (bytes: Uint8Array): Fr =>
  taggedHash("TOS-SHIELDED-OUTPUT-DATA-v1", bytes);

/** Section 4.1, and public inputs 9 and 10. */
export const pqAuthKeyHash = (publicKey: Uint8Array): Fr =>
  taggedHash("TOS-SHIELDED-MLDSA44-PK-v1", publicKey);

/** Public input 13. A transfer's is zero and never reaches this. */
export const publicRecipientHash = (account: Uint8Array): Fr =>
  taggedHash("TOS-SHIELDED-RECIPIENT-v1", account);

/**
 * Section 8, and public input 15. A deployment fact: it binds the chain and
 * the particular pool account, so a proof made for one pool cannot be replayed
 * against another.
 */
export function executionDomain(globalId: number, poolAccount: Uint8Array): Fr {
  const body = new Uint8Array(4 + 1 + 32 + 2);
  new DataView(body.buffer).setInt32(0, globalId, false);
  body[4] = 0;
  body.set(poolAccount, 5);
  body[37] = 0;
  body[38] = 1;
  return taggedHash("TOS-SHIELDED-EXEC-v1", body);
}

/** Section 15.1, and public input 16. Poseidon2, not SHA-256: its operands are already field elements. */
export const recoveryTemplateHash = (ownerCommitment: Fr, recoveryDataHash: Fr): Fr =>
  h7("RECOVERY-TEMPLATE", [ownerCommitment, recoveryDataHash, 0n, 0n, 0n, 0n, 0n]);

/** The mnemonic-global base, never used to derive a key directly. */
export const poolMaster = (tosSeed: Uint8Array): Uint8Array =>
  shake([ascii("TOS-SHIELDED-POOL-MASTER-v1"), tosSeed], 64);

function beU64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

/** Everything a wallet holds for one pool on one chain. */
export class PoolInstance {
  private readonly master: Uint8Array;

  readonly executionDomain: Fr;

  constructor(tosSeed: Uint8Array, executionDomain: Fr) {
    this.master = shake(
      [ascii("TOS-SHIELDED-POOL-INSTANCE-v1"), poolMaster(tosSeed), frBe32(executionDomain)],
      64,
    );
    this.executionDomain = executionDomain;
  }

  /**
   * Section 2.1. A derivation that reduces to zero is not usable, so attempt
   * zero is the bare bytes and each retry appends its own counter. Returning
   * the first non-zero result keeps the mapping from index to key
   * deterministic, which a recovering wallet depends on.
   */
  ownerNfKey(noteKeyIndex: bigint): Fr {
    const index = beU64(noteKeyIndex);
    for (let retry = 0; retry <= 255; retry += 1) {
      const parts = [ascii("TOS-SHIELDED-OWNER-NF-v1"), this.master, index];
      if (retry > 0) {
        parts.push(Uint8Array.of(retry));
      }
      const wide = shake(parts, 64);
      let value = 0n;
      for (const byte of wide) {
        value = (value << 8n) | BigInt(byte);
      }
      const reduced = value % MODULUS;
      if (reduced !== 0n) {
        return reduced;
      }
    }
    throw new Error(`no non-zero owner-nullifier key for index ${noteKeyIndex}`);
  }

  ownerNfKeyHash(noteKeyIndex: bigint): Fr {
    return h7("OWNER-NF-HASH", [this.ownerNfKey(noteKeyIndex), 0n, 0n, 0n, 0n, 0n, 0n]);
  }

  /** Section 2.2: the 64-byte (d, z) seed FIPS 203 permits storing. */
  mlkemSeed(): { d: Uint8Array; z: Uint8Array } {
    return {
      d: shake([ascii("TOS-SHIELDED-MLKEM-D-v1"), this.master], 32),
      z: shake([ascii("TOS-SHIELDED-MLKEM-Z-v1"), this.master], 32),
    };
  }

  mlkemKeys(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const { d, z } = this.mlkemSeed();
    return ml_kem768.keygen(concat(d, z));
  }

  mlkemEncapsulationKey(): Uint8Array {
    return this.mlkemKeys().publicKey;
  }

  /** Section 2.3: a different ML-DSA key per note, from the same index. */
  mldsaSeed(noteKeyIndex: bigint): Uint8Array {
    return shake([ascii("TOS-SHIELDED-MLDSA44-KEY-v1"), this.master, beU64(noteKeyIndex)], 32);
  }

  mldsaKeys(noteKeyIndex: bigint): { publicKey: Uint8Array; secretKey: Uint8Array } {
    return ml_dsa44.keygen(this.mldsaSeed(noteKeyIndex));
  }

  mldsaPublicKey(noteKeyIndex: bigint): Uint8Array {
    return this.mldsaKeys(noteKeyIndex).publicKey;
  }

  pqAuthKeyHash(noteKeyIndex: bigint): Fr {
    return pqAuthKeyHash(this.mldsaPublicKey(noteKeyIndex));
  }

  /** Section 9.4: over the digest's 32 big-endian bytes, under the context. */
  signIntent(noteKeyIndex: bigint, intentDigest: Fr): Uint8Array {
    const { secretKey } = this.mldsaKeys(noteKeyIndex);
    return ml_dsa44.sign(secretKey, frBe32(intentDigest), SIGNATURE_CONTEXT);
  }

  /** Only the holder of the mnemonic can do this. */
  decapsulate(ciphertext: Uint8Array): Uint8Array {
    return ml_kem768.decapsulate(ciphertext, this.mlkemKeys().secretKey);
  }
}

/** Section 3 step 1: encapsulate to a recipient's key. */
export function encapsulateTo(encapsulationKey: Uint8Array): {
  sharedSecret: Uint8Array;
  cipherText: Uint8Array;
} {
  return ml_kem768.encapsulate(encapsulationKey);
}
