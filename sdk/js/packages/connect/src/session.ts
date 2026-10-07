/**
 * Session encryption layer for @tos/connect.
 *
 * Uses NaCl box (Curve25519 + XSalsa20-Poly1305) via `tweetnacl`.
 * Each message gets a fresh random 24-byte nonce prepended to the ciphertext.
 */

import nacl from "tweetnacl";
import { bytesToHex, hexToBytes, randomBytes } from "./utils.js";
import type { ConnectStorage, PersistedSession, ConnectedWallet } from "./types.js";

/** Size of a NaCl box nonce in bytes. */
const NONCE_SIZE = 24;

// ---------------------------------------------------------------------------
// Key-pair management
// ---------------------------------------------------------------------------

export interface SessionKeypair {
  /** Our Curve25519 public key (used as clientId). */
  publicKey: Uint8Array;
  /** Our Curve25519 secret key. */
  secretKey: Uint8Array;
}

/** Generate a fresh Curve25519 keypair for a new session. */
export function generateSessionKeypair(): SessionKeypair {
  const kp = nacl.box.keyPair();
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

/** Reject low-order Curve25519 peers: their shared secret is public. */
export function isSafePeerPublicKey(key: Uint8Array, secret: Uint8Array): boolean {
  return key.length === 32 && secret.length === 32 &&
    nacl.scalarMult(secret, key).some((byte) => byte !== 0);
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt a plaintext message for a specific wallet public key.
 *
 * @param plaintext     Raw bytes to encrypt
 * @param theirPublicKey  Wallet's Curve25519 public key
 * @param ourSecretKey    Our Curve25519 secret key
 * @returns `nonce || ciphertext` as a single Uint8Array
 */
export function encryptMessage(
  plaintext: Uint8Array,
  theirPublicKey: Uint8Array,
  ourSecretKey: Uint8Array,
): Uint8Array {
  const nonce = randomBytes(NONCE_SIZE);
  const encrypted = nacl.box(plaintext, nonce, theirPublicKey, ourSecretKey);
  if (!encrypted) {
    throw new Error("NaCl box encryption failed");
  }
  // Prepend nonce: [nonce (24) | ciphertext]
  const result = new Uint8Array(NONCE_SIZE + encrypted.length);
  result.set(nonce, 0);
  result.set(encrypted, NONCE_SIZE);
  return result;
}

/**
 * Decrypt an incoming message from a wallet.
 *
 * @param combined        `nonce || ciphertext` as received
 * @param theirPublicKey  Wallet's Curve25519 public key
 * @param ourSecretKey    Our Curve25519 secret key
 * @returns Decrypted plaintext bytes, or `null` if decryption fails
 */
export function decryptMessage(
  combined: Uint8Array,
  theirPublicKey: Uint8Array,
  ourSecretKey: Uint8Array,
): Uint8Array | null {
  if (combined.length <= NONCE_SIZE) {
    return null;
  }
  const nonce = combined.slice(0, NONCE_SIZE);
  const ciphertext = combined.slice(NONCE_SIZE);
  return nacl.box.open(ciphertext, nonce, theirPublicKey, ourSecretKey);
}

// ---------------------------------------------------------------------------
// Session persistence
// ---------------------------------------------------------------------------

// Older sessions accepted unauthenticated first senders and cannot be restored.
const SESSION_STORAGE_KEY = "session_v3";

/**
 * Save session state to storage.
 */
export async function saveSession(
  storage: ConnectStorage,
  keypair: SessionKeypair,
  walletPublicKey: Uint8Array,
  bridgeUrl: string,
  wallet: ConnectedWallet,
  ttl: number,
): Promise<void> {
  const data: PersistedSession = {
    secretKey: bytesToHex(keypair.secretKey),
    clientId: bytesToHex(keypair.publicKey),
    walletPublicKey: bytesToHex(walletPublicKey),
    bridgeUrl,
    wallet,
    createdAt: Date.now(),
    ttl,
  };
  await storage.setItem(SESSION_STORAGE_KEY, JSON.stringify(data));
}

/**
 * Load a previously persisted session.
 *
 * Returns `null` if no session is found or if the session has expired.
 */
export async function loadSession(
  storage: ConnectStorage,
): Promise<{
  keypair: SessionKeypair;
  walletPublicKey: Uint8Array;
  bridgeUrl: string;
  wallet: ConnectedWallet;
} | null> {
  const raw = await storage.getItem(SESSION_STORAGE_KEY);
  if (!raw) return null;

  let data: PersistedSession;
  try {
    data = JSON.parse(raw) as PersistedSession;
  } catch {
    return null;
  }

  // Validate required fields
  if (typeof data.secretKey !== 'string' || typeof data.clientId !== 'string' ||
      typeof data.walletPublicKey !== 'string' || typeof data.bridgeUrl !== 'string' ||
      typeof data.createdAt !== 'number' || typeof data.ttl !== 'number' || !data.wallet) {
    await clearSession(storage);
    return null;
  }

  // Check TTL
  const elapsed = (Date.now() - data.createdAt) / 1000;
  if (elapsed >= data.ttl) {
    await storage.removeItem(SESSION_STORAGE_KEY);
    return null;
  }

  if (![data.secretKey, data.clientId, data.walletPublicKey].every((key) => /^[0-9a-fA-F]{64}$/.test(key))) {
    await clearSession(storage);
    return null;
  }
  const secretKey = hexToBytes(data.secretKey);
  const publicKey = hexToBytes(data.clientId);
  const walletPublicKey = hexToBytes(data.walletPublicKey);
  if (!isSafePeerPublicKey(walletPublicKey, secretKey) ||
      bytesToHex(nacl.box.keyPair.fromSecretKey(secretKey).publicKey) !== bytesToHex(publicKey)) {
    await clearSession(storage);
    return null;
  }
  return {
    keypair: { publicKey, secretKey },
    walletPublicKey,
    bridgeUrl: data.bridgeUrl,
    wallet: data.wallet,
  };
}

/**
 * Remove persisted session data from storage.
 */
export async function clearSession(storage: ConnectStorage): Promise<void> {
  await storage.removeItem(SESSION_STORAGE_KEY);
}
