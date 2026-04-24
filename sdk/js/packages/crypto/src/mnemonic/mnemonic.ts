import { hmac_sha512 } from "../primitives/hmac.js";
import { pbkdf2_sha512 } from "../primitives/pbkdf2.js";
import { keyPairFromSeed } from "../keys.js";
import type { KeyPair } from "../types.js";
import { wordlist } from "./wordlist.js";

const PBKDF_ITERATIONS = 100000;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function normalizeMnemonic(mnemonic: string[]): string[] {
  return mnemonic.map((w) => w.toLowerCase().trim());
}

/**
 * Compute entropy from a mnemonic array, following the TOS C++ implementation:
 *   hmac_sha512(mnemonic_words_joined_by_space, password)
 */
async function mnemonicToEntropy(
  mnemonicArray: string[],
  password?: string | null,
): Promise<Uint8Array> {
  return hmac_sha512(mnemonicArray.join(" "), password && password.length > 0 ? password : "");
}

/**
 * Check if entropy qualifies as a "basic seed".
 * pbkdf2_sha512(entropy, seed version salt, iterations/256, 64)[0] === 0
 */
async function isBasicSeed(entropy: Uint8Array): Promise<boolean> {
  const seed = await pbkdf2_sha512(
    entropy,
    "TOS seed version",
    Math.max(1, Math.floor(PBKDF_ITERATIONS / 256)),
    64,
  );
  return seed[0] === 0;
}

/**
 * Check if entropy qualifies as a "password seed".
 * pbkdf2_sha512(entropy, fast seed version salt, 1, 64)[0] === 1
 */
async function isPasswordSeed(entropy: Uint8Array): Promise<boolean> {
  const seed = await pbkdf2_sha512(entropy, "TOS fast seed version", 1, 64);
  return seed[0] === 1;
}

/**
 * Whether the mnemonic requires a password to unlock.
 */
async function isPasswordNeeded(mnemonicArray: string[]): Promise<boolean> {
  const passlessEntropy = await mnemonicToEntropy(mnemonicArray);
  return (
    (await isPasswordSeed(passlessEntropy)) &&
    !(await isBasicSeed(passlessEntropy))
  );
}

/**
 * Derive a seed from a mnemonic using PBKDF2.
 */
async function mnemonicToSeed(
  mnemonicArray: string[],
  salt: string,
  password?: string | null,
): Promise<Uint8Array> {
  const entropy = await mnemonicToEntropy(mnemonicArray, password);
  const seed = await pbkdf2_sha512(entropy, salt, PBKDF_ITERATIONS, 64);
  entropy.fill(0); // wipe intermediate secret
  return seed;
}

// ---------------------------------------------------------------------------
// Secure random helpers (isomorphic)
// ---------------------------------------------------------------------------

function getRandomBytes(size: number): Uint8Array {
  // Available in Node.js 18+, Chrome 90+, Firefox 90+, Safari 15+.
  if (typeof globalThis !== "undefined" && globalThis.crypto?.getRandomValues) {
    const buf = new Uint8Array(size);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  throw new Error(
    "crypto.getRandomValues is not available. Ensure you are running in " +
    "Node.js 18+ or a modern browser with a secure context (HTTPS).",
  );
}

/**
 * Generate a secure random integer in [min, max).
 */
async function getSecureRandomNumber(min: number, max: number): Promise<number> {
  if (min >= max) throw new Error("min must be less than max");
  const range = max - min;
  const bitsNeeded = Math.ceil(Math.log2(range));
  if (bitsNeeded > 53) {
    throw new Error("Range is too large");
  }
  const bytesNeeded = Math.ceil(bitsNeeded / 8);
  const mask = Math.pow(2, bitsNeeded) - 1;

  while (true) {
    const res = getRandomBytes(bytesNeeded);
    let power = (bytesNeeded - 1) * 8;
    let numberValue = 0;
    for (let i = 0; i < bytesNeeded; i++) {
      numberValue += res[i]! * Math.pow(2, power);
      power -= 8;
    }
    numberValue = numberValue & mask;
    if (numberValue >= range) {
      continue;
    }
    return min + numberValue;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a new TOS-compatible mnemonic phrase.
 *
 * Generates random words from the BIP-39 wordlist and verifies that they
 * produce a valid basic seed before returning.
 *
 * @param wordCount - Number of words (24 or 12). Default: 24.
 * @returns Array of mnemonic words
 *
 * @example
 * ```typescript
 * const mnemonic = await mnemonicGenerate();
 * console.log(mnemonic); // ["word1", "word2", ..., "word24"]
 *
 * const short = await mnemonicGenerate(12);
 * console.log(short.length); // 12
 * ```
 */
export async function mnemonicGenerate(
  wordCount: 24 | 12 = 24,
): Promise<string[]> {
  let mnemonicArray: string[];
  while (true) {
    mnemonicArray = [];
    for (let i = 0; i < wordCount; i++) {
      const idx = await getSecureRandomNumber(0, wordlist.length);
      mnemonicArray.push(wordlist[idx]!);
    }

    // Must qualify as a basic seed (without password)
    if (!(await isBasicSeed(await mnemonicToEntropy(mnemonicArray)))) {
      continue;
    }
    break;
  }
  return mnemonicArray;
}

/**
 * Validate a TOS-compatible mnemonic phrase.
 *
 * Checks that all words are in the wordlist and that the mnemonic
 * produces a valid basic seed.
 *
 * @param mnemonic  - Array of mnemonic words
 * @param password  - Optional password (for password-protected mnemonics)
 * @returns true if the mnemonic is valid
 *
 * @example
 * ```typescript
 * const isValid = await mnemonicValidate(mnemonic);
 * if (!isValid) throw new Error("Invalid mnemonic");
 * ```
 */
export async function mnemonicValidate(
  mnemonic: string[],
  password?: string | null,
): Promise<boolean> {
  const normalized = normalizeMnemonic(mnemonic);

  // All words must be in the wordlist
  for (const word of normalized) {
    if (wordlist.indexOf(word) < 0) {
      return false;
    }
  }

  // If a password is supplied the mnemonic must be a password-type seed
  if (password && password.length > 0) {
    if (!(await isPasswordNeeded(normalized))) {
      return false;
    }
  }

  // Must be a basic seed
  return isBasicSeed(await mnemonicToEntropy(normalized, password));
}

/**
 * Derive an Ed25519 key pair from a mnemonic phrase.
 *
 * This is the main way to go from a mnemonic to signing keys.
 * The derivation uses PBKDF2-HMAC-SHA512 with 100,000 iterations.
 *
 * @param mnemonic  - Array of mnemonic words
 * @param password  - Optional password (for password-protected mnemonics)
 * @returns Ed25519 KeyPair with publicKey (32 bytes) and secretKey (64 bytes)
 *
 * @example
 * ```typescript
 * const mnemonic = await mnemonicGenerate();
 * const keys = await mnemonicToPrivateKey(mnemonic);
 *
 * // Use keys to create a wallet
 * const wallet = WalletV4R2.create({ publicKey: keys.publicKey });
 * ```
 */
export async function mnemonicToPrivateKey(
  mnemonic: string[],
  password?: string | null,
): Promise<KeyPair> {
  const normalized = normalizeMnemonic(mnemonic);
  const seed = await mnemonicToSeed(normalized, "TOS default seed", password);
  const kp = keyPairFromSeed(seed.slice(0, 32));
  seed.fill(0); // wipe sensitive seed material
  return kp;
}

/**
 * Derive a 64-byte HD seed from a mnemonic for hierarchical key derivation.
 *
 * Use this seed with {@link deriveEd25519Path} to derive child keys.
 *
 * @param mnemonic  - Array of mnemonic words
 * @param password  - Optional password
 * @returns 64-byte seed suitable for HD key derivation
 *
 * @example
 * ```typescript
 * const seed = await mnemonicToHDSeed(mnemonic);
 * const childKeys = await deriveEd25519Path(seed, [0, 1]);
 * ```
 */
export async function mnemonicToHDSeed(
  mnemonic: string[],
  password?: string | null,
): Promise<Uint8Array> {
  const normalized = normalizeMnemonic(mnemonic);
  return mnemonicToSeed(normalized, "TOS HD Keys seed", password);
}
