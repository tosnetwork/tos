/**
 * Injected wallet provider detection and wrapper for @tos/connect.
 *
 * Wallets running as browser extensions inject themselves on `window.tos`.
 * This module provides helpers to detect and interact with those providers.
 */

import type {
  InjectedTosProvider,
  ConnectRequest,
  ConnectedWallet,
  ConnectEventPayload,
  SendTransactionRequest,
  SendTransactionRpcRequest,
  SendTransactionResponse,
  SignDataRequest,
  SignDataRpcRequest,
  SignDataResponse,
  WalletEvent,
  WalletInfo,
} from "./types.js";
import {
  TosConnectError,
  userRejectedError,
  walletNotFoundError,
} from "./errors.js";
import { isBrowser } from "./utils.js";

// ---------------------------------------------------------------------------
// Global augmentation for `window.tos`
// ---------------------------------------------------------------------------

declare global {
  interface Window {
    tos?: {
      provider?: InjectedTosProvider;
      providers?: InjectedTosProvider[];
    };
  }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/**
 * Returns all injected TOS wallet providers found on the page.
 *
 * The result is an empty array in SSR environments.
 */
export function getInjectedProviders(): InjectedTosProvider[] {
  if (!isBrowser()) return [];

  const providers: InjectedTosProvider[] = [];

  if (window.tos?.providers && Array.isArray(window.tos.providers)) {
    providers.push(...window.tos.providers);
  } else if (window.tos?.provider) {
    providers.push(window.tos.provider);
  }

  return providers;
}

/**
 * Check if a specific wallet (by jsBridgeKey) has an injected provider.
 */
export function isWalletInjected(wallet: WalletInfo): boolean {
  if (!isBrowser()) return false;
  if (wallet.injected === true) return true;
  if (!wallet.jsBridgeKey) return false;
  // Check keyed providers map for a provider matching this wallet's jsBridgeKey.
  const providers = window.tos?.providers as
    | Record<string, InjectedTosProvider>
    | undefined;
  if (providers && providers[wallet.jsBridgeKey]) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// InjectedBridge — wraps an InjectedTosProvider for the TosConnect class
// ---------------------------------------------------------------------------

/**
 * Wraps an `InjectedTosProvider` with the same interface that TosConnect
 * expects, translating errors to `TosConnectError`.
 */
export class InjectedBridge {
  private readonly provider: InjectedTosProvider;
  private eventUnsubscribe: (() => void) | null = null;

  constructor(provider: InjectedTosProvider) {
    this.provider = provider;
  }

  /**
   * Connect to the injected wallet.
   *
   * @param protocolVersion  Protocol version number.
   * @param request          Connect request with manifest URL and items.
   * @returns The connected wallet info.
   */
  async connect(
    protocolVersion: number,
    request: ConnectRequest,
  ): Promise<ConnectedWallet> {
    try {
      const payload = await this.provider.connect(protocolVersion, request);
      return payloadToConnectedWallet(payload);
    } catch (err) {
      if (err instanceof TosConnectError) throw err;
      throw userRejectedError(
        err instanceof Error ? err.message : "Injected connect failed",
      );
    }
  }

  /**
   * Try to restore a previous connection (if the wallet remembers us).
   */
  async restoreConnection(): Promise<ConnectedWallet> {
    try {
      const payload = await this.provider.restoreConnection();
      return payloadToConnectedWallet(payload);
    } catch (err) {
      if (err instanceof TosConnectError) throw err;
      throw new TosConnectError(
        err instanceof Error ? err.message : "Injected restore failed",
        "SESSION_RESTORE_FAILED",
      );
    }
  }

  /**
   * Disconnect from the injected wallet.
   */
  async disconnect(): Promise<void> {
    this.stopListening();
    try {
      await this.provider.disconnect();
    } catch {
      // Ignore errors during disconnect.
    }
  }

  /**
   * Send a transaction via the injected wallet.
   */
  async sendTransaction(
    request: SendTransactionRequest,
  ): Promise<SendTransactionResponse> {
    try {
      const rpcRequest: SendTransactionRpcRequest = {
        method: "sendTransaction",
        params: [JSON.stringify(request)],
        id: crypto.randomUUID?.() ?? String(Date.now()),
      };
      return await this.provider.sendTransaction(rpcRequest);
    } catch (err) {
      if (err instanceof TosConnectError) throw err;
      throw userRejectedError(
        err instanceof Error ? err.message : "Injected sendTransaction failed",
      );
    }
  }

  /**
   * Sign arbitrary data via the injected wallet.
   */
  async signData(request: SignDataRequest): Promise<SignDataResponse> {
    if (!this.provider.signData) {
      throw new TosConnectError(
        "Wallet does not support signData",
        "TX_INVALID",
      );
    }
    try {
      const rpcRequest: SignDataRpcRequest = {
        method: "signData",
        params: [JSON.stringify(request)],
        id: crypto.randomUUID?.() ?? String(Date.now()),
      };
      return await this.provider.signData(rpcRequest);
    } catch (err) {
      if (err instanceof TosConnectError) throw err;
      throw userRejectedError(
        err instanceof Error ? err.message : "Injected signData failed",
      );
    }
  }

  /**
   * Listen for wallet events (disconnect, etc.).
   */
  startListening(callback: (event: WalletEvent) => void): void {
    this.stopListening();
    this.eventUnsubscribe = this.provider.listen(callback);
  }

  /**
   * Stop listening for wallet events.
   */
  stopListening(): void {
    if (this.eventUnsubscribe) {
      this.eventUnsubscribe();
      this.eventUnsubscribe = null;
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function payloadToConnectedWallet(payload: ConnectEventPayload): ConnectedWallet {
  const addrItem = payload.items.find((i) => i.name === "ton_addr");
  if (!addrItem || addrItem.name !== "ton_addr") {
    throw walletNotFoundError("Wallet did not return an address");
  }

  return {
    device: payload.device,
    account: {
      address: addrItem.address,
      chain: addrItem.network,
      publicKey: addrItem.publicKey,
      walletStateInit: addrItem.walletStateInit,
    },
    connectItems: payload.items,
  };
}

/**
 * Find the matching InjectedTosProvider for a WalletInfo.
 *
 * Returns `null` if the wallet is not injected.
 */
export function findInjectedProvider(
  wallet: WalletInfo,
): InjectedTosProvider | null {
  if (!isBrowser() || !wallet.jsBridgeKey) return null;

  // Check keyed providers map first.
  const providers = window.tos?.providers as
    | Record<string, InjectedTosProvider>
    | undefined;
  if (providers && providers[wallet.jsBridgeKey]) {
    return providers[wallet.jsBridgeKey]!;
  }

  return null;
}
