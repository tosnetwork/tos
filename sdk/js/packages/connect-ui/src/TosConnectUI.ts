/**
 * TosConnectUI — main entry point for @tos/connect-ui.
 *
 * Creates and manages the connect button, wallet selection modal,
 * and account menu. Internally delegates all protocol operations
 * to a TosConnect instance from @tos/connect.
 *
 * Usage:
 * ```ts
 * import { TosConnectUI } from "@tos/connect-ui";
 *
 * const ui = new TosConnectUI({
 *   manifestUrl: "https://myapp.com/tonconnect-manifest.json",
 *   buttonRootId: "tos-connect-button",
 * });
 * ```
 */

import type {
  ConnectedAccount,
  ConnectedWallet,
  ConnectRequest,
  SendTransactionRequest,
  SendTransactionResponse,
  WalletInfo,
} from "@tos/connect";
import { Address } from "@tos/core";

import { I18nManager } from "./i18n/index.js";
import { ThemeManager, type ThemeMode } from "./styles/theme.js";
import { ConnectButton } from "./components/ConnectButton.js";
import { ConnectModal } from "./components/ConnectModal.js";
import { isBrowser } from "./utils.js";

// ---------------------------------------------------------------------------
// Default wallet list (popular TOS wallets)
// ---------------------------------------------------------------------------

const DEFAULT_WALLETS: WalletInfo[] = [
  {
    name: "TOS Wallet",
    appName: "toswallet",
    imageUrl: "https://wallet.tos.network/assets/icon.png",
    platforms: ["ios", "android", "chrome", "web"],
    universalLink: "https://wallet.tos.network/connect",
    bridgeUrl: "https://bridge.tos.network/bridge",
    jsBridgeKey: "tosWallet",
  },
  {
    name: "TOS Keeper",
    appName: "toskeeper",
    imageUrl: "https://keeper.tos.network/assets/icon.png",
    platforms: ["ios", "android", "chrome", "firefox"],
    universalLink: "https://keeper.tos.network/connect",
    bridgeUrl: "https://bridge.tos.network/bridge",
    jsBridgeKey: "tosKeeper",
  },
  {
    name: "TOS Hub",
    appName: "toshub",
    imageUrl: "https://hub.tos.network/assets/icon.png",
    platforms: ["web", "chrome"],
    universalLink: "https://hub.tos.network/connect",
    bridgeUrl: "https://bridge.tos.network/bridge",
    jsBridgeKey: "tosHub",
  },
];

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface TosConnectUIOptions {
  /** URL of the DApp manifest JSON. */
  manifestUrl: string;
  /** ID of the DOM element to mount the connect button into. */
  buttonRootId?: string;
  /** Bridge URL override (defaults to wallet-specific or global default). */
  bridgeUrl?: string;
  /** Theme mode: "light", "dark", or "auto" (follows system). */
  theme?: ThemeMode;
  /** Language code for the UI. */
  language?: string;
  /** Additional wallets to show (merged with defaults). */
  wallets?: WalletInfo[];
}

// ---------------------------------------------------------------------------
// TosConnectUI
// ---------------------------------------------------------------------------

export class TosConnectUI {
  private readonly manifestUrl: string;
  private readonly bridgeUrl: string | undefined;
  private readonly i18n: I18nManager;
  private readonly themeManager: ThemeManager;
  private readonly buttonThemeManager: ThemeManager;

  private button: ConnectButton | null = null;
  private modal: ConnectModal | null = null;

  private _wallet: ConnectedWallet | null = null;
  private _balance: string | null = null;
  private _balanceTimer: ReturnType<typeof setInterval> | null = null;
  private _modalState: "opened" | "closed" = "closed";

  private readonly statusChangeCallbacks: Array<{
    callback: (wallet: ConnectedWallet | null) => void;
    onError?: (error: unknown) => void;
  }> = [];
  private readonly modalStateChangeCallbacks: Array<(state: "opened" | "closed") => void> = [];
  private readonly walletList: WalletInfo[];

  private destroyed = false;

  constructor(options: TosConnectUIOptions) {
    this.manifestUrl = options.manifestUrl;
    this.bridgeUrl = options.bridgeUrl;

    // Initialize i18n
    this.i18n = new I18nManager(options.language);

    // Initialize theme
    this.themeManager = new ThemeManager(options.theme ?? "auto");
    this.buttonThemeManager = new ThemeManager(options.theme ?? "auto");

    // Build wallet list: injected wallets first, then defaults, then custom
    this.walletList = this.buildWalletList(options.wallets);

    // Mount button if root ID provided
    if (options.buttonRootId && isBrowser()) {
      // Defer mount to allow DOM to be ready
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => {
          this.mountButton(options.buttonRootId!);
        }, { once: true });
      } else {
        this.mountButton(options.buttonRootId);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Connection state (readonly)
  // -----------------------------------------------------------------------

  /** Whether a wallet is currently connected. */
  get connected(): boolean {
    return this._wallet !== null;
  }

  /** The connected account, or null. */
  get account(): ConnectedAccount | null {
    return this._wallet?.account ?? null;
  }

  /** The connected wallet info, or null. */
  get wallet(): ConnectedWallet | null {
    return this._wallet;
  }

  // -----------------------------------------------------------------------
  // Connection lifecycle
  // -----------------------------------------------------------------------

  /**
   * Initiate a connection to a wallet.
   *
   * For injected wallets, connects directly.
   * For bridge wallets, returns a universal link string to display as QR code.
   *
   * @returns Universal link string (for bridge wallets) or null (for injected).
   */
  connect(wallet: WalletInfo, request?: ConnectRequest): string | null {
    this.ensureNotDestroyed();

    // Build the connect request
    const connectRequest: ConnectRequest = request ?? {
      manifestUrl: this.manifestUrl,
      items: [{ name: "ton_addr" }],
    };

    if (wallet.injected && wallet.jsBridgeKey) {
      // Injected wallet: connect directly
      this.connectInjected(wallet, connectRequest);
      return null;
    }

    // Bridge wallet: generate universal link
    const bridgeUrl = wallet.bridgeUrl ?? this.bridgeUrl ?? "https://bridge.tos.network/bridge";
    const universalLink = wallet.universalLink;
    if (!universalLink) return null;

    // Build the universal link with connect parameters
    const params = new URLSearchParams({
      v: "2",
      id: this.generateClientId(),
      r: JSON.stringify(connectRequest),
    });

    const link = `${universalLink}?${params.toString()}`;

    // Start listening for the bridge response
    this.listenForBridgeResponse(wallet, bridgeUrl);

    return link;
  }

  /**
   * Restore a previously established connection from storage.
   */
  async restoreConnection(): Promise<void> {
    this.ensureNotDestroyed();

    // Try to restore from localStorage
    if (!isBrowser()) return;

    try {
      const stored = localStorage.getItem("@tos/connect-ui:wallet");
      if (stored) {
        const wallet = JSON.parse(stored) as ConnectedWallet;
        this.setWallet(wallet);
      }
    } catch {
      // Silently fail — no session to restore
    }
  }

  /**
   * Disconnect the current wallet.
   */
  async disconnect(): Promise<void> {
    this.ensureNotDestroyed();

    this._wallet = null;
    this.stopBalancePolling();
    this.button?.update(null);
    this.notifyStatusChange(null);

    // Clear persisted session
    if (isBrowser()) {
      try {
        localStorage.removeItem("@tos/connect-ui:wallet");
      } catch {
        // Ignore storage errors
      }
    }
  }

  /**
   * Register a callback for wallet connection status changes.
   * @returns Unsubscribe function.
   */
  onStatusChange(
    callback: (wallet: ConnectedWallet | null) => void,
    onError?: (error: unknown) => void,
  ): () => void {
    const entry = { callback, onError };
    this.statusChangeCallbacks.push(entry);
    return () => {
      const idx = this.statusChangeCallbacks.indexOf(entry);
      if (idx !== -1) this.statusChangeCallbacks.splice(idx, 1);
    };
  }

  // -----------------------------------------------------------------------
  // Transactions
  // -----------------------------------------------------------------------

  /**
   * Send a transaction through the connected wallet.
   */
  async sendTransaction(
    _request: SendTransactionRequest,
    _opts?: { signal?: AbortSignal },
  ): Promise<SendTransactionResponse> {
    this.ensureNotDestroyed();

    if (!this._wallet) {
      throw new Error("No wallet connected");
    }

    // In a real implementation, this would delegate to TosConnect.
    // Since TosConnect is being built in parallel, we provide the interface
    // and throw a clear error if the protocol layer isn't available.
    throw new Error(
      "sendTransaction requires a fully initialized TosConnect protocol layer. " +
      "Ensure @tos/connect is properly integrated.",
    );
  }

  // -----------------------------------------------------------------------
  // Modal API
  // -----------------------------------------------------------------------

  /** Open the wallet selection modal. */
  openModal(): void {
    this.ensureNotDestroyed();
    if (!isBrowser()) return;
    if (this.modal?.isOpen) return;

    this.modal = new ConnectModal(
      this.i18n,
      this.themeManager,
      this.walletList,
      {
        onSelectWallet: (wallet) => this.handleWalletSelected(wallet),
        onClose: () => this.closeModal(),
        getUniversalLink: (wallet) => this.connect(wallet),
      },
    );

    this.modal.open();
    this.setModalState("opened");
  }

  /** Close the wallet selection modal. */
  closeModal(): void {
    if (!this.modal) return;

    this.modal.close().catch(() => {
      // Ensure cleanup even if animation fails
      this.modal?.destroy();
    });

    this.modal = null;
    this.setModalState("closed");
  }

  /** Current modal state. */
  get modalState(): "opened" | "closed" {
    return this._modalState;
  }

  /**
   * Register a callback for modal state changes.
   * @returns Unsubscribe function.
   */
  onModalStateChange(callback: (state: "opened" | "closed") => void): () => void {
    this.modalStateChangeCallbacks.push(callback);
    return () => {
      const idx = this.modalStateChangeCallbacks.indexOf(callback);
      if (idx !== -1) this.modalStateChangeCallbacks.splice(idx, 1);
    };
  }

  // -----------------------------------------------------------------------
  // Wallet discovery
  // -----------------------------------------------------------------------

  /** Get the list of available wallets (injected + defaults + custom). */
  async getWallets(): Promise<WalletInfo[]> {
    this.ensureNotDestroyed();
    return this.walletList;
  }

  // -----------------------------------------------------------------------
  // Cleanup
  // -----------------------------------------------------------------------

  /** Destroy the UI, removing all DOM elements and event listeners. */
  destroy(): void {
    this.destroyed = true;
    this.stopBalancePolling();
    this.button?.destroy();
    this.button = null;
    this.modal?.destroy();
    this.modal = null;
    this.themeManager.detach();
    this.buttonThemeManager.detach();
    this.statusChangeCallbacks.length = 0;
    this.modalStateChangeCallbacks.length = 0;
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /** Mount the connect button into the DOM. */
  private mountButton(rootId: string): void {
    if (this.destroyed) return;

    this.button = new ConnectButton(this.i18n, this.buttonThemeManager, {
      onClickDisconnected: () => this.openModal(),
      onClickConnected: () => {
        // Account menu is handled inside ConnectButton
      },
      onDisconnect: () => {
        this.disconnect();
      },
      getWallet: () => this._wallet,
      getAccount: () => this._wallet?.account ?? null,
      getFriendlyAddress: () => this.getFriendlyAddress(),
      getBalance: () => this._balance,
    });

    this.button.mount(rootId);

    // Update button if already connected
    if (this._wallet) {
      this.button.update(this._wallet);
    }
  }

  /** Build the combined wallet list with injected detection. */
  private buildWalletList(customWallets?: WalletInfo[]): WalletInfo[] {
    const injected = this.detectInjectedWallets();
    const defaults = [...DEFAULT_WALLETS];
    const custom = customWallets ?? [];

    // Mark default wallets as injected if they match
    const injectedKeys = new Set(injected.map((w) => w.jsBridgeKey));
    for (const wallet of defaults) {
      if (wallet.jsBridgeKey && injectedKeys.has(wallet.jsBridgeKey)) {
        wallet.injected = true;
      }
    }

    // Deduplicate by appName
    const seen = new Set<string>();
    const result: WalletInfo[] = [];

    // Injected wallets first (if not already in defaults)
    for (const wallet of injected) {
      if (!seen.has(wallet.appName)) {
        seen.add(wallet.appName);
        // Don't add pure injected wallets separately if they're in defaults
        const inDefaults = defaults.some((d) => d.jsBridgeKey === wallet.jsBridgeKey);
        if (!inDefaults) {
          result.push(wallet);
        }
      }
    }

    // Default wallets (injected ones first)
    const sortedDefaults = defaults.sort((a, b) => {
      if (a.injected && !b.injected) return -1;
      if (!a.injected && b.injected) return 1;
      return 0;
    });

    for (const wallet of sortedDefaults) {
      if (!seen.has(wallet.appName)) {
        seen.add(wallet.appName);
        result.push(wallet);
      }
    }

    // Custom wallets
    for (const wallet of custom) {
      if (!seen.has(wallet.appName)) {
        seen.add(wallet.appName);
        result.push(wallet);
      }
    }

    return result;
  }

  /** Detect injected wallet providers on the page. */
  private detectInjectedWallets(): WalletInfo[] {
    if (!isBrowser()) return [];

    const wallets: WalletInfo[] = [];

    try {
      const tosGlobal = (window as unknown as Record<string, unknown>)["tos"] as
        | { provider?: Record<string, unknown>; providers?: Record<string, unknown> }
        | undefined;

      if (tosGlobal?.provider) {
        // Single provider
        wallets.push({
          name: "TOS Wallet",
          appName: "toswallet",
          imageUrl: "https://wallet.tos.network/assets/icon.png",
          platforms: ["chrome"],
          injected: true,
          jsBridgeKey: "tosWallet",
        });
      }

      if (tosGlobal?.providers) {
        for (const [key, _provider] of Object.entries(tosGlobal.providers)) {
          wallets.push({
            name: key,
            appName: key.toLowerCase(),
            imageUrl: "",
            platforms: ["chrome"],
            injected: true,
            jsBridgeKey: key,
          });
        }
      }
    } catch {
      // Ignore errors during detection
    }

    return wallets;
  }

  /** Handle wallet selection from the modal. */
  private handleWalletSelected(wallet: WalletInfo): void {
    if (wallet.injected && wallet.jsBridgeKey) {
      // Show connecting state
      this.modal?.showConnecting(wallet);

      // Connect to injected wallet
      const connectRequest: ConnectRequest = {
        manifestUrl: this.manifestUrl,
        items: [{ name: "ton_addr" }],
      };
      this.connectInjected(wallet, connectRequest);
    } else {
      // Bridge wallet: generate link and show QR
      const link = this.connect(wallet);
      if (link) {
        this.modal?.showQRCode(wallet, link);
      }
    }
  }

  /** Connect to an injected wallet provider. */
  private async connectInjected(wallet: WalletInfo, request: ConnectRequest): Promise<void> {
    try {
      type TosProvider = { connect: (v: number, r: ConnectRequest) => Promise<{ items: unknown[]; device: unknown }> };
      type TosGlobal = { provider?: TosProvider; providers?: Record<string, TosProvider> };

      const tosGlobal = (window as unknown as Record<string, unknown>)["tos"] as
        TosGlobal | undefined;

      // Look up the specific provider by jsBridgeKey, falling back to the default
      const provider = (wallet.jsBridgeKey && tosGlobal?.providers?.[wallet.jsBridgeKey])
        ?? tosGlobal?.provider;

      if (!provider) {
        throw new Error(`Injected wallet provider not found: ${wallet.name}`);
      }

      const result = await provider.connect(2, request);

      // Extract account info from connect items
      const addrItem = (result.items as Array<{ name: string; address?: string; network?: string; publicKey?: string; walletStateInit?: string }>)
        .find((item) => item.name === "ton_addr");

      if (!addrItem?.address) {
        throw new Error("Wallet did not return an address");
      }

      const connectedWallet: ConnectedWallet = {
        device: result.device as ConnectedWallet["device"],
        account: {
          address: addrItem.address,
          chain: (addrItem.network ?? "-239") as ConnectedWallet["account"]["chain"],
          publicKey: addrItem.publicKey,
          walletStateInit: addrItem.walletStateInit,
        },
        connectItems: result.items as ConnectedWallet["connectItems"],
      };

      this.setWallet(connectedWallet);
      this.closeModal();
    } catch (error) {
      this.notifyError(error);
      // Show wallet list again on failure
      this.closeModal();
    }
  }

  /** Listen for a bridge response (stub — requires @tos/connect protocol layer). */
  private listenForBridgeResponse(_wallet: WalletInfo, _bridgeUrl: string): void {
    // Bridge SSE listening will be delegated to the TosConnect instance
    // when it becomes available. For now, the QR code is displayed and
    // the connection completes when connectInjected is called or when
    // the bridge integration is wired up.
  }

  /** Generate a client ID for bridge connections. */
  private generateClientId(): string {
    const bytes = new Uint8Array(32);
    if (isBrowser() && window.crypto) {
      window.crypto.getRandomValues(bytes);
    } else {
      // Fallback (not cryptographically secure, but functional for ID generation)
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /** Set the connected wallet and notify listeners. */
  private setWallet(wallet: ConnectedWallet): void {
    this._wallet = wallet;
    this.button?.update(wallet);
    this.notifyStatusChange(wallet);

    // Start balance polling
    this.startBalancePolling(wallet.account.address);

    // Persist to localStorage
    if (isBrowser()) {
      try {
        localStorage.setItem("@tos/connect-ui:wallet", JSON.stringify(wallet));
      } catch {
        // Ignore storage errors
      }
    }
  }

  /** Start polling the account balance every 10 seconds. */
  private startBalancePolling(address: string): void {
    this.stopBalancePolling();

    const fetchBalance = async (): Promise<void> => {
      try {
        const endpoint = this.bridgeUrl?.replace("/bridge", "") ?? "https://rpc.tos.network";
        const rpcUrl = endpoint.endsWith("/bridge")
          ? endpoint.replace("/bridge", "")
          : endpoint.includes("bridge.")
            ? endpoint.replace("bridge.", "rpc.")
            : "https://rpc.tos.network";

        const res = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            id: 1,
            jsonrpc: "2.0",
            method: "getAddressBalance",
            params: { address },
          }),
        });

        if (res.ok) {
          const json = (await res.json()) as { result?: string };
          if (json.result !== undefined) {
            this._balance = json.result;
            // Re-render button with updated balance
            if (this._wallet) {
              this.button?.update(this._wallet);
            }
          }
        }
      } catch {
        // Silently fail — balance display is best-effort
      }
    };

    // Initial fetch
    void fetchBalance();

    // Poll every 10 seconds
    this._balanceTimer = setInterval(() => void fetchBalance(), 10_000);
  }

  /** Stop balance polling. */
  private stopBalancePolling(): void {
    if (this._balanceTimer !== null) {
      clearInterval(this._balanceTimer);
      this._balanceTimer = null;
    }
    this._balance = null;
  }

  /** Get the friendly (base64) address of the connected account. */
  private getFriendlyAddress(): string {
    const account = this._wallet?.account;
    if (!account) return "";

    try {
      const addr = Address.parse(account.address);
      return addr.toString({ urlSafe: true, bounceable: true });
    } catch {
      // Fallback if address parsing fails
      return account.address;
    }
  }

  /** Notify all status-change subscribers. */
  private notifyStatusChange(wallet: ConnectedWallet | null): void {
    for (const { callback } of this.statusChangeCallbacks) {
      try {
        callback(wallet);
      } catch {
        // Don't let subscriber errors break the flow
      }
    }
  }

  /** Notify error callbacks on subscribers. */
  private notifyError(error: unknown): void {
    for (const { onError } of this.statusChangeCallbacks) {
      if (onError) {
        try {
          onError(error);
        } catch {
          // Don't let subscriber errors break the flow
        }
      }
    }
  }

  /** Set modal state and notify listeners. */
  private setModalState(state: "opened" | "closed"): void {
    this._modalState = state;
    for (const callback of this.modalStateChangeCallbacks) {
      try {
        callback(state);
      } catch {
        // Don't let subscriber errors break the flow
      }
    }
  }

  /** Throw if the instance has been destroyed. */
  private ensureNotDestroyed(): void {
    if (this.destroyed) {
      throw new Error("TosConnectUI has been destroyed");
    }
  }
}
