// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Mnemonic-only recovery, against the Rust reference.
 *
 * There is no chain on this side, so what pins the TypeScript is that the same
 * observed outputs produce the same conclusions: which notes, which balance,
 * which index next, which indices are burnt, and which payloads opened and
 * were then refused.
 *
 * The scenario in the vector file has a case for every rule of section 2.5 --
 * indices with a gap, a dummy that consumes one without carrying balance,
 * somebody else's payload, two notes at one index, and a payload that opens
 * and is refused. A wallet that got any of them wrong would disagree here.
 */

import { describe, expect, it } from "vitest";

import vectors from "./generated/wallet-vectors.json" with { type: "json" };
import { PoolInstance } from "./keys.js";
import { type ObservedOutput, balanceOf, mayIssue, recover, usedIndices } from "./scan.js";

const fromHex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));

function scenario(): { wallet: PoolInstance; outputs: ObservedOutput[] } {
  const { seed, execution_domain, outputs } = vectors.recovery;
  return {
    wallet: new PoolInstance(fromHex(seed), BigInt(execution_domain)),
    outputs: outputs.map((entry) => ({
      slot: entry.slot,
      outputData: fromHex(entry.sealed),
      chain: {
        outputDataHash: BigInt(entry.output_data_hash),
        noteBody: BigInt(entry.note_body),
      },
    })),
  };
}

describe("mnemonic-only recovery", () => {
  it("reaches the same conclusions as the Rust reference", () => {
    const { wallet, outputs } = scenario();
    const expected = vectors.recovery.expected;
    const recovered = recover(wallet, outputs);

    expect(
      recovered.notes.map((note) => ({
        kind: note.kind,
        index: Number(note.noteKeyIndex),
        amount: note.amount.toString(),
        spendable: note.spendable,
        note_body: note.noteBody.toString(),
      })),
    ).toEqual(expected.notes);
    expect(balanceOf(recovered).toString()).toBe(expected.balance);
    expect(Number(recovered.nextNoteKeyIndex)).toBe(expected.next_note_key_index);
    expect(recovered.reused.map(Number)).toEqual(expected.reused);
    expect(recovered.diagnostics.map((entry) => entry.why)).toEqual(expected.diagnostics);
  });

  it("leaves no trace of a payload addressed to somebody else", () => {
    const { wallet, outputs } = scenario();
    const recovered = recover(wallet, outputs);
    // Six outputs went in. One of them is a stranger's: it does not open, so
    // it is neither a note nor a diagnostic. A wallet that recorded it would
    // be telling its owner about somebody else's payment.
    expect(outputs.length).toBe(6);
    expect(recovered.notes.length + recovered.diagnostics.length).toBe(5);
  });

  it("keeps both notes a reused descriptor produced, and burns the index", () => {
    const { wallet, outputs } = scenario();
    const recovered = recover(wallet, outputs);
    const atFour = recovered.notes.filter((note) => note.noteKeyIndex === 4n);
    expect(atFour.length, "the second payment to a used descriptor was lost").toBe(2);
    expect(atFour.every((note) => note.spendable)).toBe(true);
    // Two different notes, not one seen twice.
    expect(atFour[0]?.noteBody).not.toBe(atFour[1]?.noteBody);
    expect(recovered.reused).toContain(4n);
    expect(mayIssue(recovered, 4n)).toBe(false);
  });

  it("counts a dummy's index as used and its value as nothing", () => {
    const { wallet, outputs } = scenario();
    const recovered = recover(wallet, outputs);
    const dummies = recovered.notes.filter((note) => note.kind === "Dummy");
    expect(dummies.length).toBe(1);
    expect(dummies[0]?.amount).toBe(0n);
    expect(dummies[0]?.spendable).toBe(false);
    // The dummy is at the highest index, so the next one is past it.
    expect(recovered.nextNoteKeyIndex).toBe(7n);
    expect(mayIssue(recovered, 6n)).toBe(false);
    expect(mayIssue(recovered, 7n)).toBe(true);
  });

  it("finds the gaps as well as the notes", () => {
    const { wallet, outputs } = scenario();
    const recovered = recover(wallet, outputs);
    // Indices 0, 4 and 6 are used; 1, 2, 3 and 5 are not. A wallet that
    // counted rather than looked would reissue 1.
    expect(usedIndices(recovered).map(Number)).toEqual([0, 4, 6]);
    for (const index of [0n, 4n, 6n]) {
      expect(mayIssue(recovered, index), `index ${index}`).toBe(false);
    }
  });
});
