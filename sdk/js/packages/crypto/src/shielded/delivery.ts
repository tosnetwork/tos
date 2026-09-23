// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Section 3: the 1233 bytes that travel with a note, and section 3.1's rules
 * for believing them.
 *
 * Every output carries exactly these bytes, real or dummy, so the payload
 * length says nothing about which outputs are real. The contract hashes them
 * and puts the hash in the public input vector; it never looks inside.
 *
 * Which is why opening one is not the end of importing a note. The payer wrote
 * the plaintext and the contract could not check it against anything, so every
 * field is checked here against something outside the payload: the hashes
 * against what this wallet's own index derives, and the note the plaintext
 * describes against the note body the transaction published.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { shake256 } from "@noble/hashes/sha3";

import {
  MLKEM_CIPHERTEXT_BYTES,
  type PoolInstance,
  encapsulateTo,
  frBe32,
  frFromBe32,
  recoveryTemplateHash,
} from "./keys.js";
import { type Fr, h7 } from "./poseidon2.js";
import { dummyOwnerNfHash } from "./poseidon2.js";

export const PLAINTEXT_BYTES = 128;
export const AEAD_CIPHERTEXT_BYTES = PLAINTEXT_BYTES + 16;
/** Section 3: `1 + 1088 + 144`. */
export const OUTPUT_DATA_BYTES = 1 + MLKEM_CIPHERTEXT_BYTES + AEAD_CIPHERTEXT_BYTES;

export const MAGIC = 0x53484e31;
export const VERSION = 1;
export const FLAG_DUMMY = 0x0001;
export const FLAG_RECOVERY = 0x0002;

/** What an output slot says about itself. */
export type Kind = "Ordinary" | "Dummy" | "Recovery";

/** Exactly which section 3.1 rule a payload broke. */
export type Rejection =
  | "Undecryptable"
  | "PlaintextLength"
  | "Magic"
  | "Version"
  | "Slot"
  | "Flags"
  | "NoteSecretNotCanonical"
  | "NoteSecretZero"
  | "Amount"
  | "OwnerNfKeyHash"
  | "PqAuthKeyHash"
  | "NoteBodyMismatch";

export class Refused extends Error {
  constructor(readonly why: Rejection) {
    super(`payload rejected: ${why}`);
    this.name = "Refused";
  }
}

export interface Plaintext {
  slot: number;
  kind: Kind;
  amount: bigint;
  noteSecret: Fr;
  ownerNfKeyHash: Fr;
  noteKeyIndex: bigint;
  pqAuthKeyHash: Fr;
}

const flagsOf = (kind: Kind): number =>
  kind === "Ordinary" ? 0 : kind === "Dummy" ? FLAG_DUMMY : FLAG_RECOVERY;

function kindOf(flags: number): Kind {
  if (flags === 0) return "Ordinary";
  if (flags === FLAG_DUMMY) return "Dummy";
  if (flags === FLAG_RECOVERY) return "Recovery";
  throw new Refused("Flags");
}

export function encodePlaintext(plaintext: Plaintext): Uint8Array {
  const out = new Uint8Array(PLAINTEXT_BYTES);
  const view = new DataView(out.buffer);
  view.setUint32(0, MAGIC, false);
  out[4] = VERSION;
  out[5] = plaintext.slot;
  view.setUint16(6, flagsOf(plaintext.kind), false);
  let amount = plaintext.amount;
  for (let at = 23; at >= 8; at -= 1) {
    out[at] = Number(amount & 0xffn);
    amount >>= 8n;
  }
  out.set(frBe32(plaintext.noteSecret), 24);
  out.set(frBe32(plaintext.ownerNfKeyHash), 56);
  view.setBigUint64(88, plaintext.noteKeyIndex, false);
  out.set(frBe32(plaintext.pqAuthKeyHash), 96);
  return out;
}

/** Section 3.1's common checks: everything judgeable from the bytes alone. */
export function decodePlaintext(bytes: Uint8Array, slot: number): Plaintext {
  if (bytes.length !== PLAINTEXT_BYTES) throw new Refused("PlaintextLength");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, false) !== MAGIC) throw new Refused("Magic");
  if (bytes[4] !== VERSION) throw new Refused("Version");
  if (bytes[5] !== slot) throw new Refused("Slot");
  const kind = kindOf(view.getUint16(6, false));

  let amount = 0n;
  for (const byte of bytes.slice(8, 24)) {
    amount = (amount << 8n) | BigInt(byte);
  }

  const field = (at: number): Fr => {
    try {
      return frFromBe32(bytes.slice(at, at + 32));
    } catch {
      throw new Refused("NoteSecretNotCanonical");
    }
  };
  const noteSecret = field(24);
  if (noteSecret === 0n) throw new Refused("NoteSecretZero");

  return {
    slot,
    kind,
    amount,
    noteSecret,
    ownerNfKeyHash: field(56),
    noteKeyIndex: view.getBigUint64(88, false),
    pqAuthKeyHash: field(96),
  };
}

/**
 * Section 3 step 3: the AEAD key and nonce, bound to the domain and the slot
 * so one shared secret cannot encrypt two slots the same way.
 */
function keyAndNonce(
  sharedSecret: Uint8Array,
  executionDomain: Fr,
  slot: number,
): { key: Uint8Array; nonce: Uint8Array } {
  const input = new Uint8Array(28 + 32 + 32 + 1);
  input.set(new TextEncoder().encode("TOS-SHIELDED-DELIVERY-KDF-v1"), 0);
  input.set(sharedSecret, 28);
  input.set(frBe32(executionDomain), 60);
  input[92] = slot;
  const out = shake256(input, { dkLen: 56 });
  return { key: out.slice(0, 32), nonce: out.slice(32, 56) };
}

/** Section 3 step 4. */
function aad(executionDomain: Fr, slot: number): Uint8Array {
  const out = new Uint8Array(33);
  out.set(frBe32(executionDomain), 0);
  out[32] = slot;
  return out;
}

/** Seals a plaintext to a recipient's ML-KEM key: the exact 1233 bytes. */
export function seal(
  encapsulationKey: Uint8Array,
  executionDomain: Fr,
  plaintext: Plaintext,
): Uint8Array {
  const { sharedSecret, cipherText } = encapsulateTo(encapsulationKey);
  const { key, nonce } = keyAndNonce(sharedSecret, executionDomain, plaintext.slot);
  const sealed = xchacha20poly1305(key, nonce, aad(executionDomain, plaintext.slot)).encrypt(
    encodePlaintext(plaintext),
  );
  if (sealed.length !== AEAD_CIPHERTEXT_BYTES) {
    throw new Error(`a ${sealed.length}-byte AEAD ciphertext`);
  }
  const out = new Uint8Array(OUTPUT_DATA_BYTES);
  out[0] = VERSION;
  out.set(cipherText, 1);
  out.set(sealed, 1 + MLKEM_CIPHERTEXT_BYTES);
  return out;
}

/**
 * The other half. Failing to open is the ordinary case, not an error: most
 * payloads on a chain belong to somebody else.
 */
export function open(instance: PoolInstance, outputData: Uint8Array, slot: number): Plaintext {
  if (outputData.length !== OUTPUT_DATA_BYTES || outputData[0] !== VERSION) {
    throw new Refused("PlaintextLength");
  }
  let sharedSecret: Uint8Array;
  try {
    sharedSecret = instance.decapsulate(outputData.slice(1, 1 + MLKEM_CIPHERTEXT_BYTES));
  } catch {
    throw new Refused("Undecryptable");
  }
  const domain = instance.executionDomain;
  const { key, nonce } = keyAndNonce(sharedSecret, domain, slot);
  let opened: Uint8Array;
  try {
    opened = xchacha20poly1305(key, nonce, aad(domain, slot)).decrypt(
      outputData.slice(1 + MLKEM_CIPHERTEXT_BYTES),
    );
  } catch {
    throw new Refused("Undecryptable");
  }
  return decodePlaintext(opened, slot);
}

/** Section 4.1's commitment, and the note body it goes into. */
export const ownerCommitment = (ownerNfKeyHash: Fr, pqAuthKeyHash: Fr, noteSecret: Fr): Fr =>
  h7("OWNER-COMMITMENT", [ownerNfKeyHash, pqAuthKeyHash, noteSecret, 0n, 0n, 0n, 0n]);

export const noteBodyCommitment = (owner: Fr, amount: bigint, outputDataHash: Fr): Fr =>
  h7("NOTE-BODY", [owner, amount, outputDataHash, 0n, 0n, 0n, 0n]);

/** What the chain says about the slot a payload arrived in. */
export interface ChainSlot {
  /** The hash the contract itself computed over the bytes that arrived. */
  outputDataHash: Fr;
  /** The note body the transaction published for this slot. */
  noteBody: Fr;
}

export interface Imported {
  kind: Kind;
  noteKeyIndex: bigint;
  amount: bigint;
  noteSecret: Fr;
  ownerCommitment: Fr;
  noteBody: Fr;
  spendable: boolean;
}

/** Section 11: every amount is bounded, and a note's is no exception. */
const AMOUNT_LIMIT = 1n << 120n;

/** Section 3.1 in full, for one decrypted payload against one published slot. */
export function importNote(
  instance: PoolInstance,
  plaintext: Plaintext,
  slot: ChainSlot,
): Imported {
  const derivedOwner = instance.ownerNfKeyHash(plaintext.noteKeyIndex);
  const derivedPq = instance.pqAuthKeyHash(plaintext.noteKeyIndex);

  // A dummy names the fixed constant, not this wallet's owner hash. The index
  // is still the wallet's and is still consumed; what differs is that the note
  // it describes is owned by nobody.
  const expectedOwner = plaintext.kind === "Dummy" ? dummyOwnerNfHash() : derivedOwner;
  if (plaintext.ownerNfKeyHash !== expectedOwner) throw new Refused("OwnerNfKeyHash");
  if (plaintext.pqAuthKeyHash !== derivedPq) throw new Refused("PqAuthKeyHash");

  const amountOk =
    plaintext.kind === "Ordinary"
      ? plaintext.amount > 0n && plaintext.amount < AMOUNT_LIMIT
      : plaintext.amount === 0n;
  if (!amountOk) throw new Refused("Amount");

  const owner = ownerCommitment(
    plaintext.ownerNfKeyHash,
    plaintext.pqAuthKeyHash,
    plaintext.noteSecret,
  );

  // A recovery template is not a note yet -- its amount is unknown until a
  // bounce returns -- so it is checked against the template hash the
  // withdrawal signed, not against a published note body.
  if (plaintext.kind === "Recovery") {
    const template = recoveryTemplateHash(owner, slot.outputDataHash);
    if (template !== slot.noteBody) throw new Refused("NoteBodyMismatch");
    return {
      kind: plaintext.kind,
      noteKeyIndex: plaintext.noteKeyIndex,
      amount: 0n,
      noteSecret: plaintext.noteSecret,
      ownerCommitment: owner,
      noteBody: template,
      spendable: false,
    };
  }

  const noteBody = noteBodyCommitment(owner, plaintext.amount, slot.outputDataHash);
  if (noteBody !== slot.noteBody) throw new Refused("NoteBodyMismatch");

  return {
    kind: plaintext.kind,
    noteKeyIndex: plaintext.noteKeyIndex,
    amount: plaintext.amount,
    noteSecret: plaintext.noteSecret,
    ownerCommitment: owner,
    noteBody,
    spendable: plaintext.kind === "Ordinary",
  };
}
