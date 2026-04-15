import { hmac_sha512 } from "../primitives/hmac.js";
import { keyPairFromSeed } from "../keys.js";
import type { KeyPair } from "../types.js";

const ED25519_CURVE = "ed25519 seed";
const HARDENED_OFFSET = 0x80000000;

interface HDKeysState {
  key: Uint8Array;
  chainCode: Uint8Array;
}

/**
 * Derive the master key + chain code from a seed using HMAC-SHA512.
 */
async function getED25519MasterKeyFromSeed(
  seed: Uint8Array,
): Promise<HDKeysState> {
  const I = await hmac_sha512(ED25519_CURVE, seed);
  return {
    key: I.slice(0, 32),
    chainCode: I.slice(32),
  };
}

/**
 * Derive a hardened child key from a parent HD state.
 */
async function deriveED25519HardenedKey(
  parent: HDKeysState,
  index: number,
): Promise<HDKeysState> {
  if (index >= HARDENED_OFFSET) {
    throw new Error("Key index must be less than offset");
  }

  // data = 0x00 || parent.key (32 bytes) || uint32be(index + HARDENED_OFFSET)
  const data = new Uint8Array(1 + 32 + 4);
  data[0] = 0x00;
  data.set(parent.key, 1);
  const idx = index + HARDENED_OFFSET;
  data[33] = (idx >>> 24) & 0xff;
  data[34] = (idx >>> 16) & 0xff;
  data[35] = (idx >>> 8) & 0xff;
  data[36] = idx & 0xff;

  const I = await hmac_sha512(parent.chainCode, data);
  return {
    key: I.slice(0, 32),
    chainCode: I.slice(32),
  };
}

/**
 * Derive an Ed25519 key pair by walking a BIP-32-Ed25519 hardened path.
 *
 * Starting from a master key derived from the seed, each path index
 * produces a hardened child key using HMAC-SHA512.
 *
 * @param seed - 64-byte HD seed (e.g. from {@link mnemonicToHDSeed})
 * @param path - Array of path indices (each < 0x80000000; hardened offset is added internally)
 * @returns The derived Ed25519 KeyPair
 *
 * @example
 * ```typescript
 * const seed = await mnemonicToHDSeed(mnemonic);
 * const keys = await deriveEd25519Path(seed, [44, 607, 0]);
 * console.log(keys.publicKey.length); // 32
 * ```
 */
export async function deriveEd25519Path(
  seed: Uint8Array,
  path: number[],
): Promise<KeyPair> {
  let state = await getED25519MasterKeyFromSeed(seed);
  for (const index of path) {
    state = await deriveED25519HardenedKey(state, index);
  }
  return keyPairFromSeed(state.key);
}
