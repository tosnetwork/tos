/**
 * @tos/react — Internal types.
 *
 * @packageDocumentation
 */

import type { TosError } from "@tos/client";

// ---------------------------------------------------------------------------
// Query hook result
// ---------------------------------------------------------------------------

/** Standard result shape returned by all read (query) hooks. */
export interface QueryResult<T> {
  /** The resolved data, or `undefined` while loading / on error. */
  data: T | undefined;
  /** `true` during the initial fetch (no cached data yet). */
  isLoading: boolean;
  /** The most recent error, or `null` when healthy. */
  error: TosError | null;
  /** Manually trigger a refetch. */
  refetch: () => void;
}

/** Options common to all query hooks. */
export interface QueryOptions {
  /** When `false`, the query is paused. Defaults to `true`. */
  enabled?: boolean;
  /** Auto-refetch interval in milliseconds. `0` or `undefined` disables. */
  refetchInterval?: number;
}

// ---------------------------------------------------------------------------
// Mutation hook result
// ---------------------------------------------------------------------------

/** Standard result shape returned by all mutation hooks. */
export interface MutationResult<TArgs, TResult> {
  /** Fire the mutation (fire-and-forget). */
  mutate: (args: TArgs) => void;
  /** Fire the mutation and await the result. */
  mutateAsync: (args: TArgs) => Promise<TResult>;
  /** The result of the last successful mutation, or `undefined`. */
  data: TResult | undefined;
  /** `true` while the mutation is in flight. */
  isPending: boolean;
  /** `true` after a successful mutation (until reset). */
  isSuccess: boolean;
  /** `true` after a failed mutation (until reset). */
  isError: boolean;
  /** The error from the last mutation, or `null`. */
  error: TosError | null;
  /** Reset the mutation state back to idle. */
  reset: () => void;
}

// ---------------------------------------------------------------------------
// Infinite query result (used by useTransactions)
// ---------------------------------------------------------------------------

/** Result shape for infinite/paginated queries. */
export interface InfiniteQueryResult<T> {
  /** All pages of data accumulated so far. */
  data: T[];
  /** `true` during the initial fetch. */
  isLoading: boolean;
  /** `true` while fetching the next page. */
  isFetchingNextPage: boolean;
  /** The most recent error, or `null`. */
  error: TosError | null;
  /** Whether more pages are available. */
  hasNextPage: boolean;
  /** Fetch the next page of results. */
  fetchNextPage: () => void;
  /** Manually refetch from the beginning. */
  refetch: () => void;
}

// ---------------------------------------------------------------------------
// Sender (injected by @tos/connect-react)
// ---------------------------------------------------------------------------

/** A minimal sender interface for signing and sending transactions. */
export interface Sender {
  /** Send an internal message. */
  send(args: {
    to: string;
    value: bigint;
    body?: unknown;
    bounce?: boolean;
  }): Promise<{ hash?: string; status?: number }>;
}
