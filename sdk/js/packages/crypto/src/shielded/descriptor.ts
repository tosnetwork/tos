// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Section 2.4: the recipient descriptor.
 *
 * What a payee hands a payer. It never goes on chain; it is the off-chain
 * object that says "send to this index, under this domain, with this key".
 *
 * A descriptor is single use, and section 2.5 is careful that this is a wallet
 * issuance rule and not a consensus one. A payer who kept an old descriptor
 * can send to it again whenever they like, so the wallet's job is to behave
 * deterministically when they do rather than to assume they will not.
 */

import {
  MLDSA_PUBLIC_KEY_BYTES,
  MLKEM_ENCAPSULATION_KEY_BYTES,
  type PoolInstance,
  frBe32,
  frFromBe32,
} from "./keys.js";
import type { Fr } from "./poseidon2.js";

export const MAGIC = 0x53484431;
export const VERSION = 1;
/** 4 + 1 + 32 + 8 + 32 + 1312 + 1184. */
export const DESCRIPTOR_BYTES = 2573;

const DOMAIN_AT = 5;
const INDEX_AT = DOMAIN_AT + 32;
const OWNER_AT = INDEX_AT + 8;
const PQ_AT = OWNER_AT + 32;
const MLKEM_AT = PQ_AT + MLDSA_PUBLIC_KEY_BYTES;

export interface Descriptor {
  executionDomain: Fr;
  noteKeyIndex: bigint;
  ownerNfKeyHash: Fr;
  pqAuthPublicKey: Uint8Array;
  mlkemEncapsulationKey: Uint8Array;
}

/** Everything in a descriptor is derived, so issuing one is choosing an index. */
export function issue(instance: PoolInstance, noteKeyIndex: bigint): Descriptor {
  return {
    executionDomain: instance.executionDomain,
    noteKeyIndex,
    ownerNfKeyHash: instance.ownerNfKeyHash(noteKeyIndex),
    pqAuthPublicKey: instance.mldsaPublicKey(noteKeyIndex),
    mlkemEncapsulationKey: instance.mlkemEncapsulationKey(),
  };
}

export function toBytes(descriptor: Descriptor): Uint8Array {
  const out = new Uint8Array(DESCRIPTOR_BYTES);
  const view = new DataView(out.buffer);
  view.setUint32(0, MAGIC, false);
  out[4] = VERSION;
  out.set(frBe32(descriptor.executionDomain), DOMAIN_AT);
  view.setBigUint64(INDEX_AT, descriptor.noteKeyIndex, false);
  out.set(frBe32(descriptor.ownerNfKeyHash), OWNER_AT);
  out.set(descriptor.pqAuthPublicKey, PQ_AT);
  out.set(descriptor.mlkemEncapsulationKey, MLKEM_AT);
  return out;
}

/**
 * Rejects rather than reduces: a descriptor carrying a non-canonical field
 * element is not a descriptor whose domain happens to be large.
 */
export function fromBytes(bytes: Uint8Array): Descriptor {
  if (bytes.length !== DESCRIPTOR_BYTES) {
    throw new Error(`a descriptor is ${DESCRIPTOR_BYTES} bytes, not ${bytes.length}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, false) !== MAGIC) {
    throw new Error("not a descriptor");
  }
  if (bytes[4] !== VERSION) {
    throw new Error(`descriptor version ${bytes[4]}`);
  }
  return {
    executionDomain: frFromBe32(bytes.slice(DOMAIN_AT, DOMAIN_AT + 32)),
    noteKeyIndex: view.getBigUint64(INDEX_AT, false),
    ownerNfKeyHash: frFromBe32(bytes.slice(OWNER_AT, OWNER_AT + 32)),
    pqAuthPublicKey: bytes.slice(PQ_AT, PQ_AT + MLDSA_PUBLIC_KEY_BYTES),
    mlkemEncapsulationKey: bytes.slice(MLKEM_AT, MLKEM_AT + MLKEM_ENCAPSULATION_KEY_BYTES),
  };
}

/**
 * A descriptor is valid only for the exact execution domain of the pool it
 * names. Paying one under another domain would produce a note whose keys the
 * recipient cannot derive.
 */
export function requireDomain(descriptor: Descriptor, executionDomain: Fr): void {
  if (descriptor.executionDomain !== executionDomain) {
    throw new Error("a descriptor for another execution domain");
  }
}
