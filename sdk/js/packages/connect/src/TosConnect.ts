/**
 * TosConnect — main entry point for wallet-DApp communication.
 *
 * Supports two transport modes:
 * 1. **HTTP bridge** — messages are relayed via a server, encrypted end-to-end
 *    with NaCl box. The DApp opens a universal link for the wallet, then
 *    listens on an SSE stream for the response.
 * 2. **Injected provider** — the wallet extension injects itself into the page
 *    and communication happens in-process.
 *
 * The class is framework-agnostic: no React, no DOM manipulation.
 */

import type {
  ConnectedAccount,
  ConnectedWallet,
  ConnectItem,
  ConnectRequest,
  ConnectStorage,
  SendTransactionRequest,
  SendTransactionResponse,
  SignDataRequest,
  SignDataResponse,
  WalletEvent,
  WalletInfo,
  ConnectEventPayload,
  ConnectErrorPayload,
  TonAddressItemReply,
} from "./types.js";
import {
  TosConnectError,
  ConnectErrorCodes,
  bridgeUnreachableError,
  sessionExpiredError,
  sessionRestoreFailedError,
  txTimeoutError,
  userRejectedError,
} from "./errors.js";
import {
  generateSessionKeypair,
  saveSession,
  loadSession,
  clearSession,
  type SessionKeypair,
} from "./session.js";
import { BridgeClient } from "./bridge.js";
import {
  InjectedBridge,
  findInjectedProvider,
} from "./injected.js";
import { createDefaultStorage } from "./storage.js";
import { fetchWalletList } from "./wallets.js";
import {
  buildUniversalLink,
  bytesToHex,
  hexToBytes,
  generateRequestId,
} from "./utils.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface TosConnectOptions {
  /** URL to the DApp's manifest.json (required). */
  manifestUrl: string;
  /** Bridge base URL (default: "https://bridge.tos.network/bridge"). */
  bridgeUrl?: string;
  /** Custom storage adapter (default: localStorage or memory). */
  storage?: ConnectStorage;
  /** URL to a remote wallet-list JSON endpoint. */
  walletsListSource?: string;
  /** Session time-to-live in seconds (default: 86400 = 24 h). */
  sessionTtl?: number;
  /** SSE reconnection configuration. */
  reconnect?: {
    enabled?: boolean;
    maxRetries?: number;
    backoffMs?: number;
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_BRIDGE_URL = "https://bridge.tos.network/bridge";
const DEFAULT_SESSION_TTL = 86400; // 24 hours

/** Timeout for waiting for an RPC response from the wallet (5 minutes). */
const RPC_TIMEOUT_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

type StatusCallback = (wallet: ConnectedWallet | null) => void;
type ErrorCallback = (error: TosConnectError) => void;

interface PendingRpc {
  resolve: (value: string) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

// ---------------------------------------------------------------------------
// TosConnect
// ---------------------------------------------------------------------------

export class TosConnect {
  /** Protocol version implemented by this SDK. */
  static readonly PROTOCOL_VERSION = 2;

  private readonly manifestUrl: string;
  private readonly defaultBridgeUrl: string;
  private readonly storage: ConnectStorage;
  private readonly walletsListSource?: string;
  private readonly sessionTtl: number;
  private readonly reconnectConfig?: {
    enabled?: boolean;
    maxRetries?: number;
    backoffMs?: number;
  };

  private _wallet: ConnectedWallet | null = null;
  private _keypair: SessionKeypair | null = null;
  private _walletPublicKey: Uint8Array | null = null;

  private bridgeClient: BridgeClient | null = null;
  private injectedBridge: InjectedBridge | null = null;
  private activeBridgeUrl: string | null = null;
  private _paused = false;

  private statusCallbacks: StatusCallback[] = [];
  private errorCallbacks: ErrorCallback[] = [];
  private pendingRpc = new Map<string, PendingRpc>();

  // -----------------------------------------------------------------------
  // Constructor
  // -----------------------------------------------------------------------

  constructor(options: TosConnectOptions) {
    this.manifestUrl = options.manifestUrl;
    this.defaultBridgeUrl = options.bridgeUrl ?? DEFAULT_BRIDGE_URL;
    this.storage = options.storage ?? createDefaultStorage();
    this.walletsListSource = options.walletsListSource;
    this.sessionTtl = options.sessionTtl ?? DEFAULT_SESSION_TTL;
    this.reconnectConfig = options.reconnect;
  }

  // -----------------------------------------------------------------------
  // Public getters
  // -----------------------------------------------------------------------

  /** Whether a wallet is currently connected. */
  get connected(): boolean {
    return this._wallet !== null;
  }

  /** The connected account, or `null`. */
  get account(): ConnectedAccount | null {
    return this._wallet?.account ?? null;
  }

  /** The full connected wallet info, or `null`. */
  get wallet(): ConnectedWallet | null {
    return this._wallet;
  }

  // -----------------------------------------------------------------------
  // connect()
  // -----------------------------------------------------------------------

  /**
   * Initiate a connection to a wallet.
   *
   * For **HTTP bridge** wallets this returns a universal-link URL string that
   * the DApp should present to the user (QR code, deep-link button, etc.).
   *
   * For **injected** wallets the connection happens immediately and the method
   * returns `null`.
   *
   * @param wallet   The wallet to connect to (from `getWallets()`).
   * @param request  Optional list of connect items to request.
   * @returns Universal link string, or `null` for injected wallets.
   */
  connect(
    wallet: WalletInfo,
    request?: { items?: ConnectItem[] },
  ): string | null {
    // Reset any previous state.
    this.teardown();

    const connectRequest: ConnectRequest = {
      manifestUrl: this.manifestUrl,
      items: request?.items ?? [{ name: "ton_addr" }],
    };

    // ------ Injected path ------
    const injectedProvider = findInjectedProvider(wallet);
    if (injectedProvider) {
      this.injectedBridge = new InjectedBridge(injectedProvider);

      // Fire-and-forget the async connect; results come via status callbacks.
      void this.connectInjected(connectRequest);

      return null;
    }

    // ------ HTTP bridge path ------
    const keypair = generateSessionKeypair();
    this._keypair = keypair;
    const bridgeUrl = wallet.bridgeUrl ?? this.defaultBridgeUrl;
    this.activeBridgeUrl = bridgeUrl;

    // Start listening for the wallet's connect response.
    this.startBridgeClient(keypair, bridgeUrl);

    // Build the universal link the DApp should present.
    if (!wallet.universalLink) {
      // No universal link — the DApp must surface the bridge URL / QR some
      // other way. We still start listening.
      return null;
    }

    const clientId = bytesToHex(keypair.publicKey);
    const requestJson = JSON.stringify(connectRequest);

    return buildUniversalLink(
      wallet.universalLink,
      clientId,
      requestJson,
      bridgeUrl,
      TosConnect.PROTOCOL_VERSION,
    );
  }

  // -----------------------------------------------------------------------
  // restoreConnection()
  // -----------------------------------------------------------------------

  /**
   * Attempt to restore a previous session from storage.
   *
   * If a valid (non-expired) session exists, the SSE listener is re-opened
   * and the wallet is marked as connected.
   *
   * @throws {TosConnectError} with code SESSION_RESTORE_FAILED if the stored
   *   session is invalid or expired.
   */
  async restoreConnection(): Promise<void> {
    // Try injected first.
    if (this.injectedBridge) {
      try {
        const wallet = await this.injectedBridge.restoreConnection();
        this.setConnectedWallet(wallet);
        return;
      } catch {
        this.injectedBridge = null;
      }
    }

    // Try persisted bridge session.
    const session = await loadSession(this.storage);
    if (!session) {
      throw sessionRestoreFailedError("No persisted session found");
    }

    this._keypair = session.keypair;
    this._walletPublicKey = session.walletPublicKey;
    this.activeBridgeUrl = session.bridgeUrl;
    this._wallet = session.wallet;

    // Re-open the SSE stream.
    this.startBridgeClient(
      session.keypair,
      session.bridgeUrl,
      session.walletPublicKey,
    );

    this.notifyStatusChange(this._wallet);
  }

  // -----------------------------------------------------------------------
  // disconnect()
  // -----------------------------------------------------------------------

  /**
   * Disconnect from the current wallet.
   *
   * Sends a disconnect notification to the wallet, clears the session,
   * and tears down all listeners.
   */
  async disconnect(): Promise<void> {
    if (this.injectedBridge) {
      await this.injectedBridge.disconnect();
    } else if (this.bridgeClient && this._walletPublicKey) {
      // Best-effort disconnect notification via bridge.
      try {
        await this.bridgeClient.send(
          JSON.stringify({
            method: "disconnect",
            params: [],
            id: generateRequestId(),
          }),
        );
      } catch {
        // Ignore — we're disconnecting anyway.
      }
    }

    await clearSession(this.storage);
    this.teardown();
    this.notifyStatusChange(null);
  }

  // -----------------------------------------------------------------------
  // pauseConnection / unpauseConnection
  // -----------------------------------------------------------------------

  /**
   * Pause the SSE connection (e.g. when the page goes to background).
   *
   * No messages will be received while paused.
   */
  pauseConnection(): void {
    this._paused = true;
    this.bridgeClient?.pause();
  }

  /**
   * Resume a previously paused connection.
   */
  async unpauseConnection(): Promise<void> {
    this._paused = false;
    this.bridgeClient?.resume();
  }

  // -----------------------------------------------------------------------
  // onStatusChange
  // -----------------------------------------------------------------------

  /**
   * Register a callback to be invoked when the connection status changes.
   *
   * @param callback  Called with the connected wallet (or `null` on disconnect).
   * @param onError   Called when an error occurs (e.g. session expired).
   * @returns Unsubscribe function.
   */
  onStatusChange(
    callback: StatusCallback,
    onError?: ErrorCallback,
  ): () => void {
    this.statusCallbacks.push(callback);
    if (onError) {
      this.errorCallbacks.push(onError);
    }

    return () => {
      this.statusCallbacks = this.statusCallbacks.filter((cb) => cb !== callback);
      if (onError) {
        this.errorCallbacks = this.errorCallbacks.filter((cb) => cb !== onError);
      }
    };
  }

  // -----------------------------------------------------------------------
  // sendTransaction
  // -----------------------------------------------------------------------

  /**
   * Request the wallet to sign and send a transaction.
   *
   * @param request  The transaction to send.
   * @param opts     Optional abort signal and sent callback.
   * @returns The signed BOC from the wallet.
   */
  async sendTransaction(
    request: SendTransactionRequest,
    opts?: { signal?: AbortSignal; onRequestSent?: () => void },
  ): Promise<SendTransactionResponse> {
    this.ensureConnected();

    if (this.injectedBridge) {
      return this.injectedBridge.sendTransaction(request);
    }

    const id = generateRequestId();
    const rpcMessage = JSON.stringify({
      method: "sendTransaction",
      params: [JSON.stringify(request)],
      id,
    });

    const resultPromise = this.waitForRpcResponse(id, opts?.signal);

    await this.bridgeClient!.send(rpcMessage);
    opts?.onRequestSent?.();

    const resultStr = await resultPromise;
    try {
      return JSON.parse(resultStr) as SendTransactionResponse;
    } catch {
      throw new TosConnectError(
        "Failed to parse sendTransaction response",
        "TX_INVALID",
        ConnectErrorCodes.TX_INVALID,
      );
    }
  }

  // -----------------------------------------------------------------------
  // signData
  // -----------------------------------------------------------------------

  /**
   * Request the wallet to sign arbitrary data.
   *
   * @param request  The data to sign.
   * @param opts     Optional abort signal.
   */
  async signData(
    request: SignDataRequest,
    opts?: { signal?: AbortSignal },
  ): Promise<SignDataResponse> {
    this.ensureConnected();

    if (this.injectedBridge) {
      return this.injectedBridge.signData(request);
    }

    const id = generateRequestId();
    const rpcMessage = JSON.stringify({
      method: "signData",
      params: [JSON.stringify(request)],
      id,
    });

    const resultPromise = this.waitForRpcResponse(id, opts?.signal);
    await this.bridgeClient!.send(rpcMessage);

    const resultStr = await resultPromise;
    try {
      return JSON.parse(resultStr) as SignDataResponse;
    } catch {
      throw new TosConnectError(
        "Failed to parse signData response",
        "TX_INVALID",
        ConnectErrorCodes.TX_INVALID,
      );
    }
  }

  // -----------------------------------------------------------------------
  // getWallets
  // -----------------------------------------------------------------------

  /**
   * Fetch the list of supported wallets.
   *
   * Merges the remote wallet-list source (if configured) with the built-in
   * defaults.
   */
  async getWallets(): Promise<WalletInfo[]> {
    return fetchWalletList(this.walletsListSource);
  }

  // -----------------------------------------------------------------------
  // Private: injected flow
  // -----------------------------------------------------------------------

  private async connectInjected(request: ConnectRequest): Promise<void> {
    try {
      const wallet = await this.injectedBridge!.connect(
        TosConnect.PROTOCOL_VERSION,
        request,
      );

      this.setConnectedWallet(wallet);

      // Listen for disconnect events.
      this.injectedBridge!.startListening((event: WalletEvent) => {
        if (event.event === "disconnect") {
          void clearSession(this.storage);
          this._wallet = null;
          this.notifyStatusChange(null);
        }
      });

      this.notifyStatusChange(wallet);
    } catch (err) {
      const tosErr =
        err instanceof TosConnectError
          ? err
          : userRejectedError(
              err instanceof Error ? err.message : "Injected connect failed",
            );
      this.notifyError(tosErr);
    }
  }

  // -----------------------------------------------------------------------
  // Private: bridge flow
  // -----------------------------------------------------------------------

  private startBridgeClient(
    keypair: SessionKeypair,
    bridgeUrl: string,
    walletPublicKey?: Uint8Array,
  ): void {
    this.bridgeClient?.close();

    this.bridgeClient = new BridgeClient(
      {
        bridgeUrl,
        keypair,
        walletPublicKey,
        defaultTtl: this.sessionTtl,
      },
      this.reconnectConfig,
    );

    if (walletPublicKey) {
      this.bridgeClient.setWalletPublicKey(walletPublicKey);
    }

    this.bridgeClient.onMessage((msg) => {
      this.handleBridgeMessage(msg.from, msg.data);
    });

    this.bridgeClient.onError((err) => {
      const tosErr =
        err instanceof TosConnectError
          ? err
          : bridgeUnreachableError(err.message);
      this.notifyError(tosErr);
    });

    if (!this._paused) {
      this.bridgeClient.listen();
    }
  }

  private handleBridgeMessage(fromHex: string, data: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      return; // Not JSON — ignore.
    }

    // Is this a wallet event (connect / disconnect)?
    if (isWalletEvent(parsed)) {
      this.handleWalletEvent(fromHex, parsed);
      return;
    }

    // Is this an RPC response?
    if (isRpcResponse(parsed)) {
      this.handleRpcResponse(parsed);
      return;
    }
  }

  private handleWalletEvent(fromHex: string, event: WalletEvent): void {
    switch (event.event) {
      case "connect": {
        const payload = event.payload as ConnectEventPayload;
        const addrItem = payload.items.find(
          (i) => i.name === "ton_addr",
        ) as TonAddressItemReply | undefined;

        if (!addrItem) {
          this.notifyError(
            new TosConnectError(
              "Wallet connect response missing address",
              "WALLET_NOT_FOUND",
            ),
          );
          return;
        }

        // Store the wallet's public key for future message encryption.
        const walletPk = hexToBytes(fromHex);
        this._walletPublicKey = walletPk;
        this.bridgeClient?.setWalletPublicKey(walletPk);

        const wallet: ConnectedWallet = {
          device: payload.device,
          account: {
            address: addrItem.address,
            chain: addrItem.network,
            publicKey: addrItem.publicKey,
            walletStateInit: addrItem.walletStateInit,
          },
          connectItems: payload.items,
        };

        this.setConnectedWallet(wallet);

        // Persist the session.
        void saveSession(
          this.storage,
          this._keypair!,
          walletPk,
          this.activeBridgeUrl!,
          wallet,
          this.sessionTtl,
        );

        this.notifyStatusChange(wallet);
        break;
      }

      case "connect_error": {
        const errorPayload = event.payload as ConnectErrorPayload;
        this.notifyError(
          new TosConnectError(
            errorPayload.message || "Wallet refused to connect",
            "USER_REJECTED",
            errorPayload.code,
          ),
        );
        break;
      }

      case "disconnect": {
        void clearSession(this.storage);
        this._wallet = null;
        this.notifyStatusChange(null);
        break;
      }
    }
  }

  private handleRpcResponse(response: RpcResponse): void {
    const pending = this.pendingRpc.get(response.id);
    if (!pending) return;

    this.pendingRpc.delete(response.id);
    clearTimeout(pending.timer);

    if (response.error) {
      const code = response.error.code;
      const message = response.error.message || "Wallet returned an error";

      if (code === 300) {
        pending.reject(userRejectedError(message));
      } else {
        pending.reject(
          new TosConnectError(message, "TX_REJECTED", code),
        );
      }
      return;
    }

    if (response.result !== undefined) {
      pending.resolve(response.result);
    } else {
      pending.reject(
        new TosConnectError("Empty response from wallet", "TX_INVALID"),
      );
    }
  }

  // -----------------------------------------------------------------------
  // Private: RPC wait
  // -----------------------------------------------------------------------

  private waitForRpcResponse(
    id: string,
    signal?: AbortSignal,
  ): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      if (signal?.aborted) {
        reject(new DOMException("The operation was aborted.", "AbortError"));
        return;
      }

      const timer = setTimeout(() => {
        this.pendingRpc.delete(id);
        reject(txTimeoutError());
      }, RPC_TIMEOUT_MS);

      const entry: PendingRpc = { resolve, reject, timer };
      this.pendingRpc.set(id, entry);

      if (signal) {
        const onAbort = () => {
          const pending = this.pendingRpc.get(id);
          if (pending) {
            this.pendingRpc.delete(id);
            clearTimeout(pending.timer);
            pending.reject(
              new DOMException("The operation was aborted.", "AbortError"),
            );
          }
        };
        signal.addEventListener("abort", onAbort, { once: true });
      }
    });
  }

  // -----------------------------------------------------------------------
  // Private: helpers
  // -----------------------------------------------------------------------

  private setConnectedWallet(wallet: ConnectedWallet): void {
    this._wallet = wallet;
  }

  private ensureConnected(): void {
    if (!this._wallet) {
      throw sessionExpiredError("No active wallet connection");
    }
  }

  private notifyStatusChange(wallet: ConnectedWallet | null): void {
    for (const cb of this.statusCallbacks) {
      try {
        cb(wallet);
      } catch {
        // Don't let a bad callback break the loop.
      }
    }
  }

  private notifyError(error: TosConnectError): void {
    for (const cb of this.errorCallbacks) {
      try {
        cb(error);
      } catch {
        // Don't let a bad callback break the loop.
      }
    }
  }

  private teardown(): void {
    // Cancel all pending RPCs.
    for (const [id, pending] of this.pendingRpc) {
      clearTimeout(pending.timer);
      pending.reject(
        new TosConnectError("Connection torn down", "SESSION_EXPIRED"),
      );
      this.pendingRpc.delete(id);
    }

    this.bridgeClient?.close();
    this.bridgeClient = null;
    this.injectedBridge?.stopListening();
    this.injectedBridge = null;
    this._wallet = null;
    this._keypair = null;
    this._walletPublicKey = null;
    this.activeBridgeUrl = null;
  }
}

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

interface RpcResponse {
  id: string;
  result?: string;
  error?: { code: number; message: string; data?: unknown };
}

function isWalletEvent(data: unknown): data is WalletEvent {
  return (
    typeof data === "object" &&
    data !== null &&
    "event" in data &&
    typeof (data as WalletEvent).event === "string"
  );
}

function isRpcResponse(data: unknown): data is RpcResponse {
  return (
    typeof data === "object" &&
    data !== null &&
    "id" in data &&
    typeof (data as RpcResponse).id === "string" &&
    ("result" in data || "error" in data)
  );
}
