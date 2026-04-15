/**
 * A key pair consisting of a public key and a secret key.
 */
export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}
