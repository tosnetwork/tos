/**
 * @tos/react — Minimal query cache store powered by useSyncExternalStore.
 *
 * Each cache entry is keyed by a serialised query key (string) and holds the
 * latest data, error state, and a generation counter that increments on every
 * write so that React knows to re-render.
 *
 * @internal Not part of the public API.
 */

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

interface CacheEntry<T = unknown> {
  data: T | undefined;
  error: Error | null;
  isLoading: boolean;
  /** Monotonically increasing counter — bumped on every state change. */
  generation: number;
}

// ---------------------------------------------------------------------------
// Store singleton
// ---------------------------------------------------------------------------

type Listener = () => void;

const EMPTY_ENTRY: CacheEntry = Object.freeze({ data: undefined, isLoading: false, error: null, generation: 0 });

const cache = new Map<string, CacheEntry>();
const listeners = new Set<Listener>();

function emitChange(): void {
  for (const fn of listeners) {
    fn();
  }
}

function getEntry<T>(key: string): CacheEntry<T> {
  const existing = cache.get(key) as CacheEntry<T> | undefined;
  if (existing) return existing;
  const fresh: CacheEntry<T> = {
    data: undefined,
    error: null,
    isLoading: false,
    generation: 0,
  };
  cache.set(key, fresh as CacheEntry);
  return fresh;
}

// ---------------------------------------------------------------------------
// Public helpers consumed by useQuery
// ---------------------------------------------------------------------------

/** Subscribe to store changes (for useSyncExternalStore). */
export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Read a snapshot of the cache entry (for useSyncExternalStore). */
export function getSnapshot<T>(key: string): CacheEntry<T> {
  return (cache.get(key) as CacheEntry<T> | undefined) ?? (EMPTY_ENTRY as CacheEntry<T>);
}

/** Mark a key as loading. */
export function setLoading(key: string): void {
  const entry = getEntry(key);
  if (entry.isLoading) return; // already loading, skip redundant emit
  const next: CacheEntry = {
    data: entry.data,
    error: entry.error,
    isLoading: true,
    generation: entry.generation + 1,
  };
  cache.set(key, next);
  emitChange();
}

/** Store successful data for a key. */
export function setData<T>(key: string, data: T): void {
  const entry = getEntry(key);
  const next: CacheEntry = {
    data,
    error: null,
    isLoading: false,
    generation: entry.generation + 1,
  };
  cache.set(key, next);
  emitChange();
}

/** Store an error for a key. */
export function setError(key: string, error: Error): void {
  const entry = getEntry(key);
  const next: CacheEntry = {
    data: entry.data,
    error,
    isLoading: false,
    generation: entry.generation + 1,
  };
  cache.set(key, next);
  emitChange();
}

/** Remove a cache entry entirely. */
export function invalidate(key: string): void {
  if (!cache.has(key)) return;
  cache.delete(key);
  emitChange();
}

/** Serialise an array of key segments into a single cache key. */
export function serializeKey(parts: string[]): string {
  return parts.join("\0");
}
