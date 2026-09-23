// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * The shielded pool's wallet side: work package D of the V1 implementation
 * profile.
 *
 * A wallet stores a mnemonic and nothing else. Every key is recomputed from
 * the seed and a note index, and a restored wallet finds what it owns by
 * trying to open every payload the chain carries.
 *
 * The reference implementation is `tools/shielded-pool-wallet`, which is
 * driven against the pool in the sandbox; this is held to it by the vectors in
 * `generated/`, not by both being read against the profile.
 */

export {
  type ChainSlot,
  type Imported,
  importNote,
  type Kind,
  type Plaintext,
  type Rejection,
  Refused,
  decodePlaintext,
  encodePlaintext,
  noteBodyCommitment,
  open,
  ownerCommitment,
  OUTPUT_DATA_BYTES,
  PLAINTEXT_BYTES,
  seal,
} from "./delivery.js";
export {
  type Descriptor,
  DESCRIPTOR_BYTES,
  fromBytes as descriptorFromBytes,
  issue as issueDescriptor,
  requireDomain as requireDescriptorDomain,
  toBytes as descriptorToBytes,
} from "./descriptor.js";
export {
  executionDomain,
  frBe32,
  frFromBe32,
  MLDSA_PUBLIC_KEY_BYTES,
  MLDSA_SIGNATURE_BYTES,
  MLKEM_CIPHERTEXT_BYTES,
  MLKEM_ENCAPSULATION_KEY_BYTES,
  outputDataHash,
  PoolInstance,
  poolMaster,
  pqAuthKeyHash,
  publicRecipientHash,
  recoveryTemplateHash,
  SIGNATURE_CONTEXT,
} from "./keys.js";
export { type Fr, dummyOwnerNfHash, h7, permute } from "./poseidon2.js";
export {
  balanceOf,
  type Diagnostic,
  mayIssue,
  type ObservedOutput,
  recover,
  type Recovered,
  usedIndices,
} from "./scan.js";
