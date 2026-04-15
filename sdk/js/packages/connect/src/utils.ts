/**
 * Utility helpers for @tos/connect.
 *
 * - Hex encoding/decoding for Uint8Array
 * - Universal link generation
 * - Random ID generation
 * - SSR guards
 */

import { bytesToHex, hexToBytes } from "@tos/core";

// ---------------------------------------------------------------------------
// Hex helpers (re-exported from @tos/core for internal convenience)
// ---------------------------------------------------------------------------

export { bytesToHex, hexToBytes };

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

/** Generate `n` cryptographically random bytes. */
export function randomBytes(n: number): Uint8Array {
  if (typeof globalThis.crypto !== "undefined" && typeof globalThis.crypto.getRandomValues === "function") {
    const buf = new Uint8Array(n);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  // Fallback for very old Node (pre-19) — dynamic import would be async,
  // so we just throw; tweetnacl.randomBytes works everywhere anyway.
  throw new Error("No secure random source available");
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

/** Generate a random hex request ID. */
export function generateRequestId(): string {
  return bytesToHex(randomBytes(16));
}

// ---------------------------------------------------------------------------
// Universal link generation
// ---------------------------------------------------------------------------

/**
 * Build a universal link URL that a wallet app can open.
 *
 * The link encodes the TOS Connect parameters as query params under the
 * wallet's universal-link prefix.
 *
 * @param universalLink  Wallet's universal link base (e.g. `https://wallet.tos.network/connect`)
 * @param clientId       Hex-encoded Curve25519 public key (our client ID)
 * @param requestJson    JSON-serialized connect request
 * @param bridgeUrl      The bridge URL for SSE back-channel
 * @param protocolVersion Protocol version number
 * @returns Fully-formed URL string
 */
export function buildUniversalLink(
  universalLink: string,
  clientId: string,
  requestJson: string,
  bridgeUrl: string,
  protocolVersion: number,
): string {
  const url = new URL(universalLink);
  url.searchParams.set("v", String(protocolVersion));
  url.searchParams.set("id", clientId);
  url.searchParams.set("r", requestJson);

  // Only add bridge URL if it differs from the default
  url.searchParams.set("ret", "back");

  // Encode the bridge URL
  const encodedBridge = encodeURIComponent(bridgeUrl);
  // Use a direct param rather than nested encoding
  const separator = url.search ? "&" : "?";
  return `${url.toString()}${separator}bridge=${encodedBridge}`;
}

// ---------------------------------------------------------------------------
// SSR guard
// ---------------------------------------------------------------------------

/** Returns `true` when running in a browser-like environment. */
export function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

// ---------------------------------------------------------------------------
// Base64 URL helpers
// ---------------------------------------------------------------------------

/** Encode bytes to URL-safe base64 (no padding). */
export function toBase64Url(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]!);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode URL-safe base64 (with or without padding) to bytes. */
export function fromBase64Url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Timeout helper
// ---------------------------------------------------------------------------

/**
 * Create a promise that rejects after `ms` milliseconds, or can be
 * canceled via an AbortSignal.
 */
export function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  errorMessage: string,
  signal?: AbortSignal,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error(errorMessage));
      }
    }, ms);

    const onAbort = () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new DOMException("The operation was aborted.", "AbortError"));
      }
    };

    if (signal) {
      if (signal.aborted) {
        clearTimeout(timer);
        reject(new DOMException("The operation was aborted.", "AbortError"));
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
    }

    promise.then(
      (value) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          resolve(value);
        }
      },
      (err: unknown) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          reject(err);
        }
      },
    );
  });
}
