/**
 * @tos/connect-react — useSignData hook.
 *
 * Mutation-style hook for requesting a data signature from the
 * connected wallet.
 *
 * @packageDocumentation
 */

import { useCallback, useContext, useEffect, useRef, useState } from "react";
import { TosError } from "@tos/client";
import type { SignDataRequest, SignDataResponse } from "@tos/connect";
import { ConnectContext } from "../context.js";
import type { UseSignDataResult } from "../types.js";

/**
 * Request the connected wallet to sign arbitrary data.
 *
 * @example
 * ```tsx
 * const { signData, signDataAsync, isPending, data, error } = useSignData();
 *
 * // Fire-and-forget:
 * signData({ schemaCrc: 0, cell: base64Cell });
 *
 * // Await the result:
 * const response = await signDataAsync({ schemaCrc: 0, cell: base64Cell });
 * ```
 */
export function useSignData(): UseSignDataResult {
  const ctx = useContext(ConnectContext);

  const [data, setData] = useState<SignDataResponse | undefined>(undefined);
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<TosError | null>(null);

  // Guard against state updates after unmount
  const mountedRef = useRef(true);
  useEffect(() => { return () => { mountedRef.current = false; }; }, []);

  // Ref to the latest connector so the callbacks are always current
  const connectorRef = useRef(ctx?.connector ?? null);
  connectorRef.current = ctx?.connector ?? null;

  const signDataAsync = useCallback(
    async (request: SignDataRequest): Promise<SignDataResponse> => {
      const connector = connectorRef.current;
      if (!connector) {
        throw new TosError("No wallet connected", "NOT_CONNECTED");
      }
      if (!connector.signData) {
        throw new TosError("Wallet does not support signData", "UNSUPPORTED_FEATURE");
      }

      if (mountedRef.current) {
        setIsPending(true);
        setError(null);
      }

      try {
        const result = await connector.signData(request);
        if (mountedRef.current) {
          setData(result);
          setIsPending(false);
        }
        return result;
      } catch (err: unknown) {
        const tosErr =
          err instanceof TosError
            ? err
            : new TosError(
                err instanceof Error ? err.message : String(err),
                "SIGN_DATA_ERROR",
                err instanceof Error ? err : undefined,
              );
        if (mountedRef.current) {
          setError(tosErr);
          setIsPending(false);
        }
        throw tosErr;
      }
    },
    [],
  );

  const signData = useCallback(
    (request: SignDataRequest) => {
      signDataAsync(request).catch(() => {
        // Error is already stored in state — fire-and-forget.
      });
    },
    [signDataAsync],
  );

  return {
    signData,
    signDataAsync,
    data,
    isPending,
    error,
  };
}
