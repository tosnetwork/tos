/**
 * @tos/connect-react — useConnect hook.
 *
 * Returns connect/disconnect actions and the current connection state.
 *
 * @packageDocumentation
 */

import { useContext, useMemo } from "react";
import { ConnectContext } from "../context.js";
import type { UseConnectResult } from "../types.js";

/**
 * Access connect and disconnect actions.
 *
 * @example
 * ```tsx
 * const { connect, disconnect, connected, connecting } = useConnect();
 *
 * // Connect to a specific wallet:
 * connect(walletInfo);
 *
 * // Disconnect:
 * await disconnect();
 * ```
 */
export function useConnect(): UseConnectResult {
  const ctx = useContext(ConnectContext);

  return useMemo<UseConnectResult>(() => {
    if (!ctx) {
      return {
        connect: () => {},
        disconnect: async () => {},
        connected: false,
        connecting: false,
      };
    }

    return {
      connect: ctx.connect,
      disconnect: ctx.disconnect,
      connected: ctx.wallet !== null,
      connecting: ctx.connecting,
    };
  }, [ctx]);
}
