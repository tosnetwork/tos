/**
 * ConnectStorage implementations.
 *
 * - LocalStorageAdapter — uses `window.localStorage` (browser).
 * - MemoryStorageAdapter — plain in-memory map (SSR / tests).
 */

import type { ConnectStorage } from "./types.js";

// ---------------------------------------------------------------------------
// localStorage adapter
// ---------------------------------------------------------------------------

const STORAGE_PREFIX = "@tos/connect:";

/**
 * Browser `localStorage` backed storage.
 *
 * All keys are prefixed with `@tos/connect:` to avoid collisions.
 * Falls back to `MemoryStorageAdapter` when `localStorage` is unavailable.
 */
export class LocalStorageAdapter implements ConnectStorage {
  private readonly prefix: string;

  constructor(prefix = STORAGE_PREFIX) {
    this.prefix = prefix;
  }

  async getItem(key: string): Promise<string | null> {
    try {
      return localStorage.getItem(this.prefix + key);
    } catch {
      return null;
    }
  }

  async setItem(key: string, value: string): Promise<void> {
    try {
      localStorage.setItem(this.prefix + key, value);
    } catch {
      // Quota exceeded or restricted environment — silently ignore.
    }
  }

  async removeItem(key: string): Promise<void> {
    try {
      localStorage.removeItem(this.prefix + key);
    } catch {
      // Restricted environment — silently ignore.
    }
  }
}

// ---------------------------------------------------------------------------
// In-memory adapter
// ---------------------------------------------------------------------------

/**
 * In-memory storage for SSR, tests, or environments without `localStorage`.
 */
export class MemoryStorageAdapter implements ConnectStorage {
  private readonly store = new Map<string, string>();

  async getItem(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async setItem(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async removeItem(key: string): Promise<void> {
    this.store.delete(key);
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Returns a `LocalStorageAdapter` when running in a browser, otherwise
 * falls back to `MemoryStorageAdapter`.
 */
export function createDefaultStorage(): ConnectStorage {
  if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
    return new LocalStorageAdapter();
  }
  return new MemoryStorageAdapter();
}
