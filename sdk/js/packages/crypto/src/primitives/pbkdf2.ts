/**
 * PBKDF2 with HMAC-SHA512 using the Web Crypto API.
 *
 * Isomorphic: works in Node.js 18+ and browsers.
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
 * Derive key bytes using PBKDF2 with HMAC-SHA512 via the Web Crypto API.
 *
 * @param password   - The password or key material (string or bytes)
 * @param salt       - The salt (string or bytes)
 * @param iterations - PBKDF2 iteration count
 * @param keyLength  - Desired output length in bytes
 * @returns Derived key as Uint8Array
 *
 * @example
 * ```typescript
 * const key = await pbkdf2_sha512("password", "salt", 100000, 64);
 * console.log(key.length); // 64
 * ```
 */
export async function pbkdf2_sha512(
  password: Uint8Array | string,
  salt: Uint8Array | string,
  iterations: number,
  keyLength: number,
): Promise<Uint8Array> {
  const subtle = getSubtle();
  const passwordBytes = toBytes(password);
  const saltBytes = toBytes(salt);

  const baseKey = await subtle.importKey(
    "raw",
    passwordBytes as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const bits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-512",
      salt: saltBytes as BufferSource,
      iterations,
    },
    baseKey,
    keyLength * 8, // length in bits
  );

  return new Uint8Array(bits);
}
