/**
 * @tos/connect-react — useOnDisconnect hook.
 *
 * Fires a callback whenever the wallet disconnects (including external
 * disconnects initiated by the wallet itself).
 *
 * @packageDocumentation
 */

import { useContext, useEffect, useRef } from "react";
import { ConnectContext } from "../context.js";

/**
 * Register a callback that fires when the wallet disconnects.
 *
 * The callback is kept in a ref so it is always current without
 * causing the effect to re-subscribe.
 *
 * @example
 * ```tsx
 * useOnDisconnect(() => {
 *   console.log("Wallet disconnected!");
 *   router.push("/");
 * });
 * ```
 */
export function useOnDisconnect(callback: () => void): void {
  const ctx = useContext(ConnectContext);
  const callbackRef = useRef(callback);
  callbackRef.current = callback;

  const prevWalletRef = useRef(ctx?.wallet ?? null);

  useEffect(() => {
    const currentWallet = ctx?.wallet ?? null;
    const previousWallet = prevWalletRef.current;

    // Detect transition from connected to disconnected
    if (previousWallet !== null && currentWallet === null) {
      callbackRef.current();
    }

    prevWalletRef.current = currentWallet;
  }, [ctx?.wallet]);
}
