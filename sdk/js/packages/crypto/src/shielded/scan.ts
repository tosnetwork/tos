// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Mnemonic-only recovery.
 *
 * A restored wallet has a mnemonic and nothing else. It does not know which
 * indices it used, how many notes it holds, or what they are worth. What it
 * does is try to open every payload the chain carries and let the ones that
 * open say which indices were used -- which works precisely because the ML-KEM
 * key is long-lived within an execution domain while the owner and ML-DSA keys
 * are not.
 *
 * Section 2.5 is the awkward part and the reason this is not just a loop.
 * "Single use" is a rule a wallet follows when issuing, not one the chain
 * enforces. A payer who kept a descriptor can pay it again, and the recovered
 * wallet has to import both notes, keep both spendable, and never hand that
 * index out again. Discarding the second would lose money to somebody else's
 * mistake.
 */

import {
  type ChainSlot,
  type Imported,
  Refused,
  type Rejection,
  importNote,
  open,
} from "./delivery.js";
import type { PoolInstance } from "./keys.js";

/** One output slot as the chain carries it. */
export interface ObservedOutput {
  /** Which of the three slots of its transaction, or slot 0 for a deposit. */
  slot: number;
  /** The exact bytes, as the contract hashed them. */
  outputData: Uint8Array;
  /** What the chain published about the slot. */
  chain: ChainSlot;
}

/**
 * A payload that opened but did not belong to a valid local note. Section 3.1
 * requires these to be kept rather than dropped, so a malformed or malicious
 * delivery can be shown to somebody.
 */
export interface Diagnostic {
  slot: number;
  why: Rejection;
}

/** What a restored wallet knows after scanning. */
export interface Recovered {
  /** Every note this wallet owns, in the order the chain carried them. */
  notes: Imported[];
  /** The next index it is safe to issue. */
  nextNoteKeyIndex: bigint;
  /** Indices seen more than once, which must never be issued again. */
  reused: bigint[];
  /** Payloads that opened and were refused, with the rule each broke. */
  diagnostics: Diagnostic[];
}

/** Spendable balance: a dummy carries none, a recovery template none yet. */
export const balanceOf = (recovered: Recovered): bigint =>
  recovered.notes.filter((note) => note.spendable).reduce((sum, note) => sum + note.amount, 0n);

/** Whether this index may be issued. */
export const mayIssue = (recovered: Recovered, index: bigint): boolean =>
  index >= recovered.nextNoteKeyIndex && !recovered.reused.includes(index);

/** Every index a scan found in use, whatever it was used for. */
export const usedIndices = (recovered: Recovered): bigint[] => {
  const seen = new Set<bigint>();
  for (const note of recovered.notes) {
    seen.add(note.noteKeyIndex);
  }
  return [...seen].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
};

/**
 * Scan every output the chain carries and recover what belongs to this wallet.
 *
 * A payload that will not open is the ordinary case -- most of a chain belongs
 * to other people -- and is not recorded. A payload that opens and is then
 * refused is recorded, because that one is about this wallet.
 */
export function recover(instance: PoolInstance, outputs: readonly ObservedOutput[]): Recovered {
  const notes: Imported[] = [];
  const diagnostics: Diagnostic[] = [];
  const counts = new Map<bigint, number>();

  for (const output of outputs) {
    let plaintext: ReturnType<typeof open>;
    try {
      plaintext = open(instance, output.outputData, output.slot);
    } catch (error) {
      if (error instanceof Refused) {
        // Not ours, or not a payload at all. Both are silence.
        if (error.why !== "Undecryptable") {
          diagnostics.push({ slot: output.slot, why: error.why });
        }
        continue;
      }
      throw error;
    }
    try {
      const note = importNote(instance, plaintext, output.chain);
      // Section 2.5 rule 3: import all of them. A second note at the same
      // index is a privacy problem, not a reason to lose it.
      counts.set(note.noteKeyIndex, (counts.get(note.noteKeyIndex) ?? 0) + 1);
      notes.push(note);
    } catch (error) {
      if (error instanceof Refused) {
        diagnostics.push({ slot: output.slot, why: error.why });
        continue;
      }
      throw error;
    }
  }

  // Section 2.5 rule 2: the next index is past every index that was used,
  // whatever kind of output used it. A dummy consumes an index too.
  let nextNoteKeyIndex = 0n;
  for (const index of counts.keys()) {
    if (index + 1n > nextNoteKeyIndex) {
      nextNoteKeyIndex = index + 1n;
    }
  }
  // Rule 4: an index that carried more than one note is burnt for good.
  const reused = [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([index]) => index)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  return { notes, nextNoteKeyIndex, reused, diagnostics };
}
