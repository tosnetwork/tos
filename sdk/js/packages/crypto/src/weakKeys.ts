/**
 * Ed25519 public keys that must not become a wallet's or any other
 * authority's key: small-order points and non-canonical encodings,
 * prohibited as a set.
 *
 * For a key in the 8-torsion subgroup a signature can be forged with no
 * secret (R a torsion point, S = 0); the repository's contract tests
 * demonstrate it for the identity and order-2 point with the sign bit set and
 * for the canonical order-2 point. Not every encoding below takes a forgery
 * (the on-chain signature check refuses the all-zero key and the canonical
 * identity itself), but all are refused. This is the same set the contracts
 * refuse (crypto/smartcont/strong-ed25519-key.fc), compared on the 32 encoded
 * bytes:
 *
 * - the eight canonical encodings of the torsion subgroup;
 * - the identity and the order-2 point with the sign bit set (x = 0, so the
 *   sign bit names no other point: non-canonical aliases whose y is in range);
 * - every encoding whose y is at least 2^255 - 19, with either sign bit.
 */

// The torsion encodings below 0xec in the first byte, with the sign bit
// (bit 7 of the last byte) forced on: each covers itself and its sign-bit twin.
const TORSION_WITH_SIGN_BIT: readonly string[] = [
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * True when `publicKey` is one of the prohibited weak or non-canonical encodings.
 *
 * @param publicKey - A 32-byte Ed25519 public key
 * @throws Error if `publicKey` is not 32 bytes
 */
export function isWeakEd25519PublicKey(publicKey: Uint8Array): boolean {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new Error("an Ed25519 public key is 32 bytes");
  }
  // y's lowest byte >= 0xec: y >= 2^255 - 19 (and the order-2 point and its
  // alias at 0xec) exactly when bytes 1..30 are all 0xff and y's top byte is
  // 0x7f, with either sign bit.
  if ((publicKey[0] ?? 0) >= 0xec) {
    for (let i = 1; i < 31; i++) {
      if (publicKey[i] !== 0xff) {
        return false;
      }
    }
    return ((publicKey[31] ?? 0) & 0x7f) === 0x7f;
  }
  const eitherSign = new Uint8Array(publicKey);
  eitherSign[31] = (eitherSign[31] ?? 0) | 0x80;
  return TORSION_WITH_SIGN_BIT.includes(hex(eitherSign));
}
