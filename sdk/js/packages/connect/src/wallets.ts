/**
 * Default wallet list and wallet discovery for @tos/connect.
 */

import type { WalletInfo } from "./types.js";

/** The built-in default wallet list. */
export const defaultWallets: WalletInfo[] = [
  {
    name: "TOS Wallet",
    appName: "toswallet",
    imageUrl: "https://wallet.tos.network/icon.png",
    platforms: ["ios", "android", "chrome", "web"],
    universalLink: "https://wallet.tos.network/connect",
    bridgeUrl: "https://bridge.tos.network/bridge",
  },
];

/**
 * Fetch a remote wallet list and merge with the built-in defaults.
 *
 * The remote list is expected to be a JSON array of `WalletInfo` objects.
 * On network failure the built-in list is returned as-is.
 *
 * @param sourceUrl  URL to a JSON wallet-list endpoint (optional).
 * @param signal     Optional abort signal.
 */
export async function fetchWalletList(
  sourceUrl?: string,
  signal?: AbortSignal,
): Promise<WalletInfo[]> {
  if (!sourceUrl) {
    return [...defaultWallets];
  }

  try {
    const response = await fetch(sourceUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal,
    });

    if (!response.ok) {
      return [...defaultWallets];
    }

    const remote = (await response.json()) as unknown;

    if (!Array.isArray(remote)) {
      return [...defaultWallets];
    }

    // Merge: remote wallets first (they may be more up-to-date), then any
    // defaults whose appName wasn't present in the remote list.
    const remoteAppNames = new Set(
      (remote as WalletInfo[]).map((w) => w.appName),
    );

    const merged: WalletInfo[] = [...(remote as WalletInfo[])];
    for (const wallet of defaultWallets) {
      if (!remoteAppNames.has(wallet.appName)) {
        merged.push(wallet);
      }
    }

    return merged;
  } catch {
    return [...defaultWallets];
  }
}
