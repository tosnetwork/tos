/**
 * @tos/react — Generic internal useMutation hook.
 *
 * Manages async write operations with `isPending`, `isSuccess`, `isError`
 * state tracking and a `reset()` helper.
 *
 * @internal Not exported from the public API.
 */

import { useCallback, useRef, useState } from "react";
import { TosError } from "@tos/client";
import type { MutationResult } from "../types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseMutationOptions<TArgs, TResult> {
  mutationFn: (args: TArgs) => Promise<TResult>;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

type MutationStatus = "idle" | "pending" | "success" | "error";

interface MutationState<TResult> {
  status: MutationStatus;
  data: TResult | undefined;
  error: TosError | null;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useMutation<TArgs, TResult>(
  options: UseMutationOptions<TArgs, TResult>,
): MutationResult<TArgs, TResult> {
  const mutationFnRef = useRef(options.mutationFn);
  mutationFnRef.current = options.mutationFn;

  const [state, setState] = useState<MutationState<TResult>>({
    status: "idle",
    data: undefined,
    error: null,
  });

  // Monotonically increasing id to discard stale responses when multiple
  // mutations fire in rapid succession.
  const inflightId = useRef(0);

  const mutateAsync = useCallback(async (args: TArgs): Promise<TResult> => {
    const id = ++inflightId.current;
    setState({ status: "pending", data: undefined, error: null });

    try {
      const result = await mutationFnRef.current(args);
      if (inflightId.current === id) {
        setState({ status: "success", data: result, error: null });
      }
      return result;
    } catch (err: unknown) {
      const tosErr =
        err instanceof TosError
          ? err
          : new TosError(
              err instanceof Error ? err.message : String(err),
              "MUTATION_ERROR",
              err instanceof Error ? err : undefined,
            );
      if (inflightId.current === id) {
        setState({ status: "error", data: undefined, error: tosErr });
      }
      throw tosErr;
    }
  }, []);

  const mutate = useCallback(
    (args: TArgs) => {
      mutateAsync(args).catch(() => {
        // Error is surfaced via state.error — swallow the promise rejection.
      });
    },
    [mutateAsync],
  );

  const reset = useCallback(() => {
    setState({ status: "idle", data: undefined, error: null });
  }, []);

  return {
    mutate,
    mutateAsync,
    data: state.data,
    isPending: state.status === "pending",
    isSuccess: state.status === "success",
    isError: state.status === "error",
    error: state.error,
    reset,
  };
}
