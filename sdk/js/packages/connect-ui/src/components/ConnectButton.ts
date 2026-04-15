/**
 * Connect Button component for @tos/connect-ui.
 *
 * A self-contained vanilla JS button that:
 * - Shows "Connect Wallet" when disconnected
 * - Shows shortened address when connected
 * - Manages its own Shadow DOM for style isolation
 */

import type { ConnectedAccount, ConnectedWallet } from "@tos/connect";
import type { I18nManager } from "../i18n/index.js";
import type { ThemeManager } from "../styles/theme.js";
import { shortenAddress, formatBalance, createElement, isBrowser } from "../utils.js";
import { AccountMenu } from "./AccountMenu.js";

// ---------------------------------------------------------------------------
// SVG Icons
// ---------------------------------------------------------------------------

const WALLET_ICON = `<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <rect x="2" y="4" width="16" height="13" rx="2"/>
  <path d="M2 8h16"/>
  <circle cx="14" cy="12" r="1.5" fill="currentColor" stroke="none"/>
</svg>`;

// ---------------------------------------------------------------------------
// ConnectButton
// ---------------------------------------------------------------------------

export interface ConnectButtonCallbacks {
  onClickDisconnected: () => void;
  onClickConnected: () => void;
  onDisconnect: () => void;
  getWallet: () => ConnectedWallet | null;
  getAccount: () => ConnectedAccount | null;
  getFriendlyAddress: () => string;
  getBalance: () => string | null;
}

export class ConnectButton {
  private host: HTMLElement | null = null;
  private shadow: ShadowRoot | null = null;
  private buttonEl: HTMLButtonElement | null = null;
  private wrapperEl: HTMLElement | null = null;
  private accountMenu: AccountMenu | null = null;
  private readonly cleanupHandlers: Array<() => void> = [];
  private isConnected = false;

  constructor(
    private readonly i18n: I18nManager,
    private readonly theme: ThemeManager,
    private readonly callbacks: ConnectButtonCallbacks,
  ) {}

  /**
   * Mount the button into a container element (by ID or element reference).
   */
  mount(target: string | HTMLElement): void {
    if (!isBrowser()) return;

    const container = typeof target === "string"
      ? document.getElementById(target)
      : target;

    if (!container) {
      console.warn(`[TOS Connect UI] Button mount target not found: ${target}`);
      return;
    }

    // Create host element with shadow DOM
    this.host = document.createElement("div");
    this.host.setAttribute("data-tos-connect-button", "");
    container.appendChild(this.host);

    this.shadow = this.host.attachShadow({ mode: "open" });

    // Inject styles
    const styleEl = document.createElement("style");
    styleEl.textContent = this.getStyles();
    this.shadow.appendChild(styleEl);

    // Apply theme to the shadow host
    this.theme.attach(this.host);

    // Create the wrapper (for positioning account menu)
    this.wrapperEl = createElement("div", "tos-button-wrapper");
    this.shadow.appendChild(this.wrapperEl);

    // Create the button
    this.buttonEl = createElement("button", "tos-connect-button");
    this.buttonEl.setAttribute("type", "button");
    this.wrapperEl.appendChild(this.buttonEl);

    // Initial render
    this.renderDisconnected();

    // Click handler
    const handleClick = (): void => {
      if (this.isConnected) {
        this.toggleAccountMenu();
      } else {
        this.callbacks.onClickDisconnected();
      }
    };

    this.buttonEl.addEventListener("click", handleClick);
    this.cleanupHandlers.push(() => {
      this.buttonEl?.removeEventListener("click", handleClick);
    });
  }

  /** Update the button to reflect the current connection state. */
  update(wallet: ConnectedWallet | null): void {
    if (!this.buttonEl) return;

    if (wallet) {
      this.isConnected = true;
      this.renderConnected(wallet);
    } else {
      this.isConnected = false;
      this.renderDisconnected();
      this.closeAccountMenu();
    }
  }

  /** Render the disconnected state. */
  private renderDisconnected(): void {
    if (!this.buttonEl) return;

    this.buttonEl.className = "tos-connect-button";
    this.buttonEl.innerHTML = "";
    this.buttonEl.setAttribute("aria-label", this.i18n.t("connectWallet"));

    const icon = createElement("span", "tos-connect-button__icon");
    icon.innerHTML = WALLET_ICON;
    this.buttonEl.appendChild(icon);

    const text = document.createTextNode(this.i18n.t("connectWallet"));
    this.buttonEl.appendChild(text);
  }

  /** Render the connected state with address and balance. */
  private renderConnected(_wallet: ConnectedWallet): void {
    if (!this.buttonEl) return;

    const friendlyAddress = this.callbacks.getFriendlyAddress();
    const shortAddr = shortenAddress(friendlyAddress);
    const balance = this.callbacks.getBalance();

    this.buttonEl.className = "tos-connect-button tos-connect-button--connected";
    this.buttonEl.innerHTML = "";
    this.buttonEl.setAttribute("aria-label", `${this.i18n.t("connected")}: ${shortAddr}`);

    const addrSpan = createElement("span", "tos-connect-button__address");
    addrSpan.textContent = shortAddr;
    this.buttonEl.appendChild(addrSpan);

    if (balance !== null) {
      const diamond = createElement("span", "tos-connect-button__diamond");
      diamond.textContent = "\u25c6";
      this.buttonEl.appendChild(diamond);

      const balanceSpan = createElement("span", "tos-connect-button__balance");
      balanceSpan.textContent = `${formatBalance(balance)} TOS`;
      this.buttonEl.appendChild(balanceSpan);
    }
  }

  /** Toggle the account menu dropdown. */
  private toggleAccountMenu(): void {
    if (this.accountMenu?.isOpen) {
      this.closeAccountMenu();
      return;
    }

    const account = this.callbacks.getAccount();
    if (!account) return;

    const friendlyAddress = this.callbacks.getFriendlyAddress();

    this.accountMenu = new AccountMenu(this.i18n);
    const menuEl = this.accountMenu.render(account, friendlyAddress, {
      onDisconnect: () => {
        this.closeAccountMenu();
        this.callbacks.onDisconnect();
      },
      onClose: () => {
        this.closeAccountMenu();
      },
    });

    this.wrapperEl?.appendChild(menuEl);
  }

  /** Close the account menu. */
  private closeAccountMenu(): void {
    if (this.accountMenu) {
      this.accountMenu.destroy();
      this.accountMenu = null;
    }
  }

  /** Get the combined CSS for the shadow DOM. */
  private getStyles(): string {
    // Inline the CSS so shadow DOM is self-contained
    return `
      :host {
        --tos-connect-accent: #0088CC;
        --tos-connect-bg: #ffffff;
        --tos-connect-text: #1a1a2e;
        --tos-connect-border: #e5e7eb;
        --tos-connect-modal-bg: #ffffff;
        --tos-connect-button-bg: #0088CC;
        --tos-connect-button-text: #ffffff;
        --tos-connect-radius: 12px;
        --tos-connect-secondary-bg: #f5f5f7;
        --tos-connect-secondary-text: #6b7280;
        --tos-connect-hover-bg: #f0f0f2;
        --tos-connect-overlay: rgba(0, 0, 0, 0.5);
        --tos-connect-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
        --tos-connect-success: #10b981;
        --tos-connect-error: #ef4444;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        font-size: 14px;
        line-height: 1.5;
        color: var(--tos-connect-text);
        -webkit-font-smoothing: antialiased;
        display: inline-block;
      }

      :host([data-tos-theme="dark"]) {
        --tos-connect-accent: #0098e1;
        --tos-connect-bg: #1a1a2e;
        --tos-connect-text: #f0f0f0;
        --tos-connect-border: #2d2d44;
        --tos-connect-modal-bg: #1a1a2e;
        --tos-connect-button-bg: #0098e1;
        --tos-connect-button-text: #ffffff;
        --tos-connect-secondary-bg: #232340;
        --tos-connect-secondary-text: #9ca3af;
        --tos-connect-hover-bg: #2d2d44;
        --tos-connect-overlay: rgba(0, 0, 0, 0.7);
        --tos-connect-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        --tos-connect-success: #34d399;
        --tos-connect-error: #f87171;
      }

      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

      .tos-button-wrapper {
        position: relative;
        display: inline-block;
      }

      .tos-connect-button {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 10px 20px;
        border: none;
        border-radius: var(--tos-connect-radius);
        background: var(--tos-connect-button-bg);
        color: var(--tos-connect-button-text);
        font-family: inherit;
        font-size: 14px;
        font-weight: 600;
        line-height: 1.4;
        cursor: pointer;
        transition: background-color 0.2s ease, transform 0.1s ease, box-shadow 0.2s ease;
        white-space: nowrap;
        user-select: none;
        -webkit-user-select: none;
        outline: none;
        position: relative;
      }

      .tos-connect-button:hover {
        filter: brightness(1.1);
        box-shadow: 0 2px 8px rgba(0, 136, 204, 0.3);
      }

      .tos-connect-button:active { transform: scale(0.97); }

      .tos-connect-button:focus-visible {
        outline: 2px solid var(--tos-connect-accent);
        outline-offset: 2px;
      }

      .tos-connect-button--connected {
        background: var(--tos-connect-secondary-bg);
        color: var(--tos-connect-text);
        border: 1px solid var(--tos-connect-border);
        padding: 8px 16px;
      }

      .tos-connect-button--connected:hover {
        filter: none;
        background: var(--tos-connect-hover-bg);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
      }

      .tos-connect-button__icon {
        width: 20px;
        height: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .tos-connect-button__icon svg { width: 100%; height: 100%; }

      .tos-connect-button__address {
        font-weight: 500;
        font-size: 13px;
        font-family: "SF Mono", "Fira Code", "Fira Mono", Menlo, Consolas, monospace;
      }

      .tos-connect-button__diamond {
        color: var(--tos-connect-accent);
        font-size: 12px;
      }

      .tos-connect-button__balance {
        font-weight: 500;
        font-size: 13px;
      }

      /* Account menu */
      .tos-account-menu {
        position: absolute;
        top: calc(100% + 8px);
        right: 0;
        min-width: 280px;
        background: var(--tos-connect-modal-bg);
        border: 1px solid var(--tos-connect-border);
        border-radius: var(--tos-connect-radius);
        box-shadow: var(--tos-connect-shadow);
        overflow: hidden;
        z-index: 999998;
      }

      .tos-account-menu__header {
        padding: 16px 16px 12px;
        border-bottom: 1px solid var(--tos-connect-border);
      }

      .tos-account-menu__chain {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        padding: 3px 8px;
        border-radius: 6px;
        margin-bottom: 8px;
      }

      .tos-account-menu__chain--mainnet {
        background: rgba(16, 185, 129, 0.12);
        color: var(--tos-connect-success);
      }

      .tos-account-menu__chain--testnet {
        background: rgba(239, 68, 68, 0.12);
        color: var(--tos-connect-error);
      }

      .tos-account-menu__address-row {
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .tos-account-menu__address {
        flex: 1;
        font-size: 12px;
        font-family: "SF Mono", "Fira Code", "Fira Mono", Menlo, Consolas, monospace;
        color: var(--tos-connect-text);
        word-break: break-all;
        line-height: 1.6;
      }

      .tos-account-menu__copy-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        border: none;
        border-radius: 6px;
        background: var(--tos-connect-secondary-bg);
        color: var(--tos-connect-secondary-text);
        cursor: pointer;
        flex-shrink: 0;
        transition: background-color 0.15s ease, color 0.15s ease;
      }

      .tos-account-menu__copy-btn:hover {
        background: var(--tos-connect-hover-bg);
        color: var(--tos-connect-text);
      }

      .tos-account-menu__copy-btn:focus-visible {
        outline: 2px solid var(--tos-connect-accent);
        outline-offset: 2px;
      }

      .tos-account-menu__copy-btn svg { width: 14px; height: 14px; }

      .tos-account-menu__copy-btn--copied {
        color: var(--tos-connect-success);
      }

      .tos-account-menu__actions { padding: 8px; }

      .tos-account-menu__disconnect {
        display: flex;
        align-items: center;
        gap: 8px;
        width: 100%;
        padding: 10px 12px;
        border: none;
        border-radius: 8px;
        background: transparent;
        color: var(--tos-connect-error);
        font-family: inherit;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: background-color 0.15s ease;
      }

      .tos-account-menu__disconnect:hover {
        background: rgba(239, 68, 68, 0.08);
      }

      .tos-account-menu__disconnect:focus-visible {
        outline: 2px solid var(--tos-connect-error);
        outline-offset: -2px;
      }

      .tos-account-menu__disconnect svg { width: 16px; height: 16px; }

      @keyframes tos-scale-in {
        from { opacity: 0; transform: scale(0.92); }
        to { opacity: 1; transform: scale(1); }
      }

      @keyframes tos-scale-out {
        from { opacity: 1; transform: scale(1); }
        to { opacity: 0; transform: scale(0.92); }
      }

      .tos-account-menu--entering {
        animation: tos-scale-in 0.15s ease-out forwards;
        transform-origin: top right;
      }

      .tos-account-menu--leaving {
        animation: tos-scale-out 0.12s ease-in forwards;
        transform-origin: top right;
      }

      @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
          animation-duration: 0.01ms !important;
          transition-duration: 0.01ms !important;
        }
      }

      @media (max-width: 480px) {
        .tos-account-menu {
          position: fixed;
          top: auto;
          bottom: 0;
          left: 0;
          right: 0;
          min-width: 100%;
          border-radius: var(--tos-connect-radius) var(--tos-connect-radius) 0 0;
        }
      }
    `;
  }

  /** Destroy the button and clean up. */
  destroy(): void {
    this.closeAccountMenu();
    for (const cleanup of this.cleanupHandlers) {
      cleanup();
    }
    this.cleanupHandlers.length = 0;
    this.theme.detach();
    if (this.host?.parentNode) {
      this.host.parentNode.removeChild(this.host);
    }
    this.host = null;
    this.shadow = null;
    this.buttonEl = null;
    this.wrapperEl = null;
  }
}
