import {
  naclSignKeyPairFromSeed,
  naclSignKeyPairFromSecretKey,
  naclSignDetached,
  naclSignDetachedVerify,
} from "./primitives/nacl.js";
import type { KeyPair } from "./types.js";

/**
 * Derive an Ed25519 key pair from a 32-byte seed.
 *
 * @param seed - 32-byte random seed
 * @returns KeyPair with publicKey (32 bytes) and secretKey (64 bytes)
 *
 * @example
 * ```typescript
 * const seed = new Uint8Array(32); // fill with random bytes
 * const keys = keyPairFromSeed(seed);
 * console.log(keys.publicKey.length);  // 32
 * console.log(keys.secretKey.length);  // 64
 * ```
 */
export function keyPairFromSeed(seed: Uint8Array): KeyPair {
  const kp = naclSignKeyPairFromSeed(seed);
  return {
    publicKey: new Uint8Array(kp.publicKey),
    secretKey: new Uint8Array(kp.secretKey),
  };
}

/**
 * Reconstruct an Ed25519 key pair from a 64-byte secret key.
 *
 * @param secretKey - 64-byte Ed25519 secret key
 * @returns KeyPair with both publicKey and secretKey
 *
 * @example
 * ```typescript
 * const keys = keyPairFromSecretKey(existingSecretKey);
 * ```
 */
export function keyPairFromSecretKey(secretKey: Uint8Array): KeyPair {
  const kp = naclSignKeyPairFromSecretKey(secretKey);
  return {
    publicKey: new Uint8Array(kp.publicKey),
    secretKey: new Uint8Array(kp.secretKey),
  };
}

/**
 * Create an Ed25519 detached signature.
 *
 * @param data      - Message bytes to sign (typically a cell hash)
 * @param secretKey - 64-byte Ed25519 secret key
 * @returns 64-byte Ed25519 signature
 *
 * @example
 * ```typescript
 * const signature = sign(cell.hash(), keys.secretKey);
 * console.log(signature.length); // 64
 * ```
 */
export function sign(data: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return new Uint8Array(naclSignDetached(data, secretKey));
}

/**
 * Verify an Ed25519 detached signature.
 *
 * @param data      - Original message bytes
 * @param signature - 64-byte signature to verify
 * @param publicKey - 32-byte Ed25519 public key
 * @returns true if the signature is valid
 *
 * @example
 * ```typescript
 * const isValid = signVerify(data, signature, keys.publicKey);
 * console.log(isValid); // true or false
 * ```
 */
export function signVerify(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return naclSignDetachedVerify(data, signature, publicKey);
}
