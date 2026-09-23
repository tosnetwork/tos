// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * The TypeScript permutation against the vectors the two VMs are checked
 * against.
 *
 * These vectors are not this implementation's own output written down. They
 * come out of `crypto/poseidon2/manifest-gen`, which executes the pinned
 * upstream reference, and the C++ VM and the Rust VM are held to the same
 * table. A third implementation that agrees with them agrees with the chain.
 */

import { describe, expect, it } from "vitest";

import {
  DOMAINS,
  EMPTY_ROOTS,
  HASH_VECTORS,
  MODULUS,
  PERM_VECTORS,
  ROUNDS_F,
  ROUNDS_P,
  STATE_WIDTH,
} from "./generated/poseidon2-params.js";
import { dummyOwnerNfHash, h7, permute } from "./poseidon2.js";

describe("Poseidon2 t=8", () => {
  it("reproduces every permutation vector", () => {
    expect(PERM_VECTORS.length).toBeGreaterThan(0);
    for (const [index, vector] of PERM_VECTORS.entries()) {
      expect(permute(vector.input), `permutation vector ${index}`).toEqual(vector.output);
    }
  });

  it("reproduces every hash vector, and through h7 as well", () => {
    expect(HASH_VECTORS.length).toBeGreaterThan(0);
    for (const vector of HASH_VECTORS) {
      // A hash vector carries the whole eight-element state, domain constant
      // included, so it pins the permutation and the constant at once.
      expect(vector.input.length, vector.label).toBe(8);
      expect(permute(vector.input)[0], `hash vector ${vector.label}`).toEqual(vector.output);

      // The label is the domain and a variant suffix. Taking the domain from
      // the table and the arguments from the vector is what proves h7 puts
      // them where the vector has them.
      const label = vector.label.split("/")[0];
      if (label === undefined) {
        throw new Error(`a hash vector with no label: ${vector.label}`);
      }
      expect(vector.input[0], `${vector.label}: the domain lane`).toBe(DOMAINS[label]);
      expect(h7(label, vector.input.slice(1)), `h7 ${vector.label}`).toEqual(vector.output);
    }
  });

  it("carries the frozen shape", () => {
    expect(STATE_WIDTH).toBe(8);
    expect(ROUNDS_F).toBe(8);
    expect(ROUNDS_P).toBe(57);
    expect(MODULUS.toString(16)).toBe(
      "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
    );
  });

  it("rejects a state that is not eight elements", () => {
    expect(() => permute([1n, 2n, 3n])).toThrow();
    expect(() => h7("NOTE-BODY", [1n])).toThrow();
    expect(() => h7("NO-SUCH-DOMAIN", [0n, 0n, 0n, 0n, 0n, 0n, 0n])).toThrow();
  });

  it("names the dummy owner hash as the domain constant, not a hash of it", () => {
    expect(dummyOwnerNfHash()).toBe(DOMAINS["DUMMY-OWNER-NF"]);
  });

  it("rebuilds the empty-subtree ladder the tree is measured from", () => {
    // Section 5: the ladder is COMMIT-NODE applied to seven copies of the
    // level below, starting from zero. Recomputing it rather than trusting
    // the generated table is what would catch a table generated from
    // different parameters.
    let level = 0n;
    expect(EMPTY_ROOTS[0]).toBe(0n);
    for (let depth = 1; depth < EMPTY_ROOTS.length; depth += 1) {
      level = h7("COMMIT-NODE", [level, level, level, level, level, level, level]);
      expect(EMPTY_ROOTS[depth], `empty root at level ${depth}`).toBe(level);
    }
  });
});
