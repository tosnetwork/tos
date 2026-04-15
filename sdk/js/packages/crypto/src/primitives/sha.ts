/**
 * Isomorphic SHA-256 and SHA-512 using the Web Crypto API.
 *
 * Works in Node.js 18+ (globalThis.crypto) and browsers.
 * Returns Promise<Uint8Array> -- no Buffer dependency.
 */

function getSubtle(): SubtleCrypto {
  // Available in Node.js 18+, Chrome 90+, Firefox 90+, Safari 15+.
  if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error(
    "SubtleCrypto is not available. Ensure you are running in Node.js 18+ " +
    "or a modern browser with a secure context (HTTPS).",
  );
}

function toBytes(source: Uint8Array | string): Uint8Array {
  if (typeof source === "string") {
    return new TextEncoder().encode(source);
  }
  return source;
}

/**
 * Compute a SHA-256 hash using the Web Crypto API.
 *
 * @param source - Data to hash (bytes or UTF-8 string)
 * @returns 32-byte SHA-256 digest
 *
 * @example
 * ```typescript
 * const hash = await sha256("hello world");
 * const hash2 = await sha256(new Uint8Array([1, 2, 3]));
 * ```
 */
export async function sha256(source: Uint8Array | string): Promise<Uint8Array> {
  const data = toBytes(source);
  const hash = await getSubtle().digest("SHA-256", data as BufferSource);
  return new Uint8Array(hash);
}

/**
 * Compute a SHA-512 hash using the Web Crypto API.
 *
 * @param source - Data to hash (bytes or UTF-8 string)
 * @returns 64-byte SHA-512 digest
 *
 * @example
 * ```typescript
 * const hash = await sha512("hello world");
 * ```
 */
export async function sha512(source: Uint8Array | string): Promise<Uint8Array> {
  const data = toBytes(source);
  const hash = await getSubtle().digest("SHA-512", data as BufferSource);
  return new Uint8Array(hash);
}
