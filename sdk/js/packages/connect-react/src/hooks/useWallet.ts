/**
 * @tos/connect-react — useWallet hook.
 *
 * Returns the currently connected wallet state: address, public key,
 * chain, the full ConnectedWallet object, and a disconnect function.
 *
 * Subscribes to TosConnect.onStatusChange internally so re-renders
 * happen automatically when the wallet connects or disconnects.
 *
 * @packageDocumentation
 */

import { useContext, useMemo } from "react";
import { Address } from "@tos/core";
import { ConnectContext } from "../context.js";
import type { UseWalletResult } from "../types.js";

/**
 * Access the connected wallet state.
 *
 * @example
 * ```tsx
 * const { connected, address, disconnect } = useWallet();
 * ```
 */
export function useWallet(): UseWalletResult {
  const ctx = useContext(ConnectContext);

  return useMemo<UseWalletResult>(() => {
    // SSR or outside provider — safe defaults
    if (!ctx || !ctx.wallet) {
      const noop = async () => {};
      return {
        connected: false,
        address: null,
        publicKey: null,
        chain: null,
        wallet: null,
        disconnect: ctx?.disconnect ?? noop,
      };
    }

    const { wallet, disconnect } = ctx;
    const account = wallet.account;

    // Parse the raw address string to an Address instance
    let address: Address | null = null;
    try {
      address = Address.parse(account.address);
    } catch {
      // Malformed address — leave as null.
    }

    // Decode hex public key to Uint8Array
    let publicKey: Uint8Array | null = null;
    if (account.publicKey) {
      try {
        const hex = account.publicKey;
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
        }
        publicKey = bytes;
      } catch {
        // Invalid hex — leave as null.
      }
    }

    return {
      connected: true,
      address,
      publicKey,
      chain: account.chain,
      wallet,
      disconnect,
    };
  }, [ctx]);
}
