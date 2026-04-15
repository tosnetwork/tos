import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  generateSessionKeypair,
  encryptMessage,
  decryptMessage,
  saveSession,
  loadSession,
  clearSession,
} from "./session.js";
import { MemoryStorageAdapter } from "./storage.js";
import type { ConnectedWallet } from "./types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A minimal ConnectedWallet fixture for session persistence tests. */
function makeWallet(): ConnectedWallet {
  return {
    device: {
      platform: "ios",
      appName: "toswallet",
      appVersion: "1.0.0",
      maxProtocolVersion: 2,
      features: [],
    },
    account: {
      address: "0:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      chain: "-239",
      publicKey: "aabbccdd",
    },
  };
}

// ---------------------------------------------------------------------------
// generateSessionKeypair
// ---------------------------------------------------------------------------

describe("generateSessionKeypair", () => {
  it("returns a publicKey and secretKey", () => {
    const kp = generateSessionKeypair();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.secretKey).toBeInstanceOf(Uint8Array);
  });

  it("publicKey is 32 bytes", () => {
    const kp = generateSessionKeypair();
    expect(kp.publicKey.length).toBe(32);
  });

  it("secretKey is 32 bytes", () => {
    const kp = generateSessionKeypair();
    expect(kp.secretKey.length).toBe(32);
  });

  it("generates different keypairs each call", () => {
    const a = generateSessionKeypair();
    const b = generateSessionKeypair();
    expect(a.publicKey).not.toEqual(b.publicKey);
    expect(a.secretKey).not.toEqual(b.secretKey);
  });
});

// ---------------------------------------------------------------------------
// encryptMessage / decryptMessage
// ---------------------------------------------------------------------------

describe("encryptMessage / decryptMessage", () => {
  it("round-trips: encrypt then decrypt returns the original plaintext", () => {
    const alice = generateSessionKeypair();
    const bob = generateSessionKeypair();

    const plaintext = new TextEncoder().encode("hello TOS");
    const encrypted = encryptMessage(plaintext, bob.publicKey, alice.secretKey);

    expect(encrypted).toBeInstanceOf(Uint8Array);
    // Encrypted payload must be longer than plaintext (nonce + overhead)
    expect(encrypted.length).toBeGreaterThan(plaintext.length);

    const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
    expect(decrypted).not.toBeNull();
    expect(new TextDecoder().decode(decrypted!)).toBe("hello TOS");
  });

  it("round-trips with empty plaintext", () => {
    const alice = generateSessionKeypair();
    const bob = generateSessionKeypair();

    const plaintext = new Uint8Array(0);
    const encrypted = encryptMessage(plaintext, bob.publicKey, alice.secretKey);
    const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
    expect(decrypted).not.toBeNull();
    expect(decrypted!.length).toBe(0);
  });

  it("decryption with wrong key returns null", () => {
    const alice = generateSessionKeypair();
    const bob = generateSessionKeypair();
    const eve = generateSessionKeypair();

    const plaintext = new TextEncoder().encode("secret");
    const encrypted = encryptMessage(plaintext, bob.publicKey, alice.secretKey);

    // Eve tries to decrypt with her own secret key
    const result = decryptMessage(encrypted, alice.publicKey, eve.secretKey);
    expect(result).toBeNull();
  });

  it("decryption with truncated ciphertext returns null", () => {
    const alice = generateSessionKeypair();
    const bob = generateSessionKeypair();

    // Only 24 bytes (just the nonce, no ciphertext)
    const tooShort = new Uint8Array(24);
    const result = decryptMessage(tooShort, alice.publicKey, bob.secretKey);
    expect(result).toBeNull();
  });

  it("decryption with empty input returns null", () => {
    const alice = generateSessionKeypair();
    const bob = generateSessionKeypair();

    const result = decryptMessage(new Uint8Array(0), alice.publicKey, bob.secretKey);
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// saveSession / loadSession / clearSession
// ---------------------------------------------------------------------------

describe("Session persistence", () => {
  let storage: MemoryStorageAdapter;
  const bridgeUrl = "https://bridge.tos.network/bridge";

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  it("saveSession / loadSession round-trip", async () => {
    const kp = generateSessionKeypair();
    const walletPk = generateSessionKeypair().publicKey;
    const wallet = makeWallet();

    await saveSession(storage, kp, walletPk, bridgeUrl, wallet, 86400);

    const loaded = await loadSession(storage);
    expect(loaded).not.toBeNull();
    expect(loaded!.bridgeUrl).toBe(bridgeUrl);
    expect(loaded!.wallet.account.address).toBe(wallet.account.address);
    expect(loaded!.keypair.publicKey).toEqual(kp.publicKey);
    expect(loaded!.keypair.secretKey).toEqual(kp.secretKey);
    expect(loaded!.walletPublicKey).toEqual(walletPk);
  });

  it("loadSession returns null when storage is empty", async () => {
    const loaded = await loadSession(storage);
    expect(loaded).toBeNull();
  });

  it("loadSession returns null for expired sessions", async () => {
    vi.useFakeTimers();
    try {
      const kp = generateSessionKeypair();
      const walletPk = generateSessionKeypair().publicKey;
      const wallet = makeWallet();

      // Save with TTL of 1 second
      await saveSession(storage, kp, walletPk, bridgeUrl, wallet, 1);

      // Advance time by 2 seconds
      vi.advanceTimersByTime(2000);

      const loaded = await loadSession(storage);
      expect(loaded).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("loadSession returns null for corrupt JSON", async () => {
    await storage.setItem("session_v2", "not-valid-json{{{");
    const loaded = await loadSession(storage);
    expect(loaded).toBeNull();
  });

  it("clearSession removes session data", async () => {
    const kp = generateSessionKeypair();
    const walletPk = generateSessionKeypair().publicKey;
    const wallet = makeWallet();

    await saveSession(storage, kp, walletPk, bridgeUrl, wallet, 86400);

    // Verify it exists
    const before = await loadSession(storage);
    expect(before).not.toBeNull();

    // Clear it
    await clearSession(storage);

    // Verify it's gone
    const after = await loadSession(storage);
    expect(after).toBeNull();
  });

  it("expired session is removed from storage on load", async () => {
    vi.useFakeTimers();
    try {
      const kp = generateSessionKeypair();
      const walletPk = generateSessionKeypair().publicKey;
      const wallet = makeWallet();

      await saveSession(storage, kp, walletPk, bridgeUrl, wallet, 1);
      vi.advanceTimersByTime(2000);

      await loadSession(storage);

      // The underlying storage key should have been removed
      const raw = await storage.getItem("session_v2");
      expect(raw).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
