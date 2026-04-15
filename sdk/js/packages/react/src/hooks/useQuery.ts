/**
 * @tos/react — Generic internal useQuery hook.
 *
 * Manages fetching, caching, refetching, and interval-based polling via
 * `useSyncExternalStore` and the shared cache store.
 *
 * @internal Not exported from the public API.
 */

import { useCallback, useEffect, useRef, useSyncExternalStore } from "react";
import { TosError } from "@tos/client";
import {
  subscribe,
  getSnapshot,
  setLoading,
  setData,
  setError,
  serializeKey,
} from "../store.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseQueryOptions<T> {
  /** Cache key segments. Changes to the key trigger a new fetch. */
  queryKey: string[];
  /** The async function that produces data. */
  queryFn: () => Promise<T>;
  /** When `false`, the query is paused (default `true`). */
  enabled?: boolean;
  /** Auto-refetch interval in milliseconds. `0` / `undefined` = disabled. */
  refetchInterval?: number;
}

export interface UseQueryResult<T> {
  data: T | undefined;
  isLoading: boolean;
  error: TosError | null;
  refetch: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useQuery<T>(options: UseQueryOptions<T>): UseQueryResult<T> {
  const { queryKey, queryFn, enabled = true, refetchInterval } = options;

  const key = serializeKey(queryKey);

  // Stable snapshot selector — useSyncExternalStore requires referential
  // stability for the getSnapshot callback between renders with the same key.
  const getSnapshotBound = useCallback(() => getSnapshot<T>(key), [key]);

  const entry = useSyncExternalStore(subscribe, getSnapshotBound, getSnapshotBound);

  // Keep a ref to the latest queryFn so the fetch closure always calls the
  // current version, even if the caller passes an unstable lambda.
  const queryFnRef = useRef(queryFn);
  queryFnRef.current = queryFn;

  // Track the current key so we can skip stale responses.
  const activeKeyRef = useRef(key);
  activeKeyRef.current = key;

  // Fetch implementation.
  const doFetch = useCallback(() => {
    const fetchKey = activeKeyRef.current;
    setLoading(fetchKey);

    queryFnRef
      .current()
      .then((result) => {
        // Only apply if the key hasn't changed while the request was in flight.
        if (activeKeyRef.current === fetchKey) {
          setData(fetchKey, result);
        }
      })
      .catch((err: unknown) => {
        if (activeKeyRef.current !== fetchKey) return;
        const tosErr =
          err instanceof TosError
            ? err
            : new TosError(
                err instanceof Error ? err.message : String(err),
                "QUERY_ERROR",
                err instanceof Error ? err : undefined,
              );
        setError(fetchKey, tosErr);
      });
  }, []);

  // Kick off the initial fetch and re-fetch when key or enabled changes.
  useEffect(() => {
    if (!enabled) return;
    doFetch();
  }, [key, enabled, doFetch]);

  // Interval-based refetch.
  useEffect(() => {
    if (!enabled || !refetchInterval || refetchInterval <= 0) return;
    const id = setInterval(() => {
      doFetch();
    }, refetchInterval);
    return () => clearInterval(id);
  }, [key, enabled, refetchInterval, doFetch]);

  return {
    data: entry.data,
    isLoading: entry.isLoading,
    error: entry.error as TosError | null,
    refetch: doFetch,
  };
}
