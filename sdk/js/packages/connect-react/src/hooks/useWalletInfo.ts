/**
 * @tos/connect-react — useWalletInfo hook.
 *
 * Returns metadata about the connected wallet: name, icon, platform,
 * and advertised features.
 *
 * @packageDocumentation
 */

import { useContext, useMemo } from "react";
import { ConnectContext } from "../context.js";
import type { UseWalletInfoResult } from "../types.js";

/**
 * Access metadata about the connected wallet.
 *
 * @example
 * ```tsx
 * const { name, icon, platform, features } = useWalletInfo();
 *
 * return name ? <img src={icon!} alt={name} /> : null;
 * ```
 */
export function useWalletInfo(): UseWalletInfoResult {
  const ctx = useContext(ConnectContext);

  return useMemo<UseWalletInfoResult>(() => {
    if (!ctx || !ctx.wallet) {
      return {
        name: null,
        icon: null,
        platform: null,
        features: null,
      };
    }

    const { device } = ctx.wallet;

    return {
      name: device.appName ?? null,
      icon: null, // Icon URL is not in DeviceInfo; available from WalletInfo during discovery
      platform: device.platform ?? null,
      features: device.features ?? null,
    };
  }, [ctx]);
}
