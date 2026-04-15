/**
 * HMAC-SHA512 using the Web Crypto API.
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
 * Compute HMAC-SHA512 using the Web Crypto API.
 *
 * @param key  - HMAC key (string or bytes)
 * @param data - Data to authenticate (string or bytes)
 * @returns 64-byte HMAC-SHA512 digest
 *
 * @example
 * ```typescript
 * const mac = await hmac_sha512("secret-key", "message data");
 * console.log(mac.length); // 64
 * ```
 */
export async function hmac_sha512(
  key: Uint8Array | string,
  data: Uint8Array | string,
): Promise<Uint8Array> {
  const subtle = getSubtle();
  const keyBytes = toBytes(key);
  const dataBytes = toBytes(data);

  const cryptoKey = await subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );

  const sig = await subtle.sign("HMAC", cryptoKey, dataBytes as BufferSource);
  return new Uint8Array(sig);
}
