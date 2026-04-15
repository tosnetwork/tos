/**
 * Connect Modal component for @tos/connect-ui.
 *
 * A full-screen overlay modal with:
 * - Wallet selection grid (injected + bridge wallets)
 * - QR code view for bridge wallet connections
 * - Connecting spinner state
 * - Focus trap and keyboard navigation
 * - Animated open/close transitions
 */

import type { WalletInfo } from "@tos/connect";
import type { I18nManager } from "../i18n/index.js";
import type { ThemeManager } from "../styles/theme.js";
import { createElement, clearElement, isBrowser } from "../utils.js";
import { generateQRCodeSVG } from "./QRCode.js";

// ---------------------------------------------------------------------------
// SVG Icons
// ---------------------------------------------------------------------------

const CLOSE_ICON = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
  <line x1="4" y1="4" x2="12" y2="12"/>
  <line x1="12" y1="4" x2="4" y2="12"/>
</svg>`;

const BACK_ICON = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <polyline points="10 3 5 8 10 13"/>
</svg>`;

const LINK_ICON = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <path d="M6 10l4-4"/>
  <path d="M8.5 3.5l2-2a2.12 2.12 0 0 1 3 3l-2 2"/>
  <path d="M7.5 12.5l-2 2a2.12 2.12 0 0 1-3-3l2-2"/>
</svg>`;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ModalView = "wallets" | "qr" | "connecting";

export interface ConnectModalCallbacks {
  onSelectWallet: (wallet: WalletInfo) => void;
  onClose: () => void;
  getUniversalLink: (wallet: WalletInfo) => string | null;
}

// ---------------------------------------------------------------------------
// ConnectModal
// ---------------------------------------------------------------------------

export class ConnectModal {
  private host: HTMLElement | null = null;
  private shadow: ShadowRoot | null = null;
  private overlayEl: HTMLElement | null = null;
  private modalEl: HTMLElement | null = null;
  private bodyEl: HTMLElement | null = null;
  private titleEl: HTMLElement | null = null;
  private backBtn: HTMLButtonElement | null = null;

  private currentView: ModalView = "wallets";
  private selectedWallet: WalletInfo | null = null;
  private previouslyFocused: Element | null = null;
  private readonly cleanupHandlers: Array<() => void> = [];

  constructor(
    private readonly i18n: I18nManager,
    private readonly theme: ThemeManager,
    private readonly wallets: WalletInfo[],
    private readonly callbacks: ConnectModalCallbacks,
  ) {}

  /**
   * Open the modal by creating DOM elements and inserting into the document.
   */
  open(): void {
    if (!isBrowser()) return;
    if (this.host) return; // Already open

    // Save current focus for restoration
    this.previouslyFocused = document.activeElement;

    // Create host in body for overlay positioning
    this.host = document.createElement("div");
    this.host.setAttribute("data-tos-connect-modal", "");
    document.body.appendChild(this.host);

    this.shadow = this.host.attachShadow({ mode: "open" });

    // Inject styles
    const styleEl = document.createElement("style");
    styleEl.textContent = this.getStyles();
    this.shadow.appendChild(styleEl);

    // Apply theme
    this.theme.attach(this.host);

    // Build overlay
    this.overlayEl = createElement("div", [
      "tos-modal-overlay",
      "tos-modal-overlay--entering",
    ]);
    this.overlayEl.setAttribute("role", "dialog");
    this.overlayEl.setAttribute("aria-modal", "true");
    this.overlayEl.setAttribute("aria-label", this.i18n.t("chooseWallet"));

    // Build modal container
    this.modalEl = createElement("div", [
      "tos-modal",
      "tos-modal--entering",
    ]);

    // --- Header ---
    const header = createElement("div", "tos-modal__header");

    // Back button (hidden initially)
    this.backBtn = createElement("button", "tos-modal__back-btn") as HTMLButtonElement;
    this.backBtn.setAttribute("type", "button");
    this.backBtn.setAttribute("aria-label", this.i18n.t("backToWallets"));
    this.backBtn.innerHTML = BACK_ICON;
    this.backBtn.style.display = "none";
    header.appendChild(this.backBtn);

    const handleBack = (): void => {
      this.showWalletList();
    };
    this.backBtn.addEventListener("click", handleBack);
    this.cleanupHandlers.push(() => this.backBtn?.removeEventListener("click", handleBack));

    // Title
    this.titleEl = createElement("div", "tos-modal__title");
    this.titleEl.textContent = this.i18n.t("chooseWallet");
    header.appendChild(this.titleEl);

    // Close button
    const closeBtn = createElement("button", "tos-modal__close-btn") as HTMLButtonElement;
    closeBtn.setAttribute("type", "button");
    closeBtn.setAttribute("aria-label", this.i18n.t("close"));
    closeBtn.innerHTML = CLOSE_ICON;
    header.appendChild(closeBtn);

    const handleCloseClick = (): void => {
      this.callbacks.onClose();
    };
    closeBtn.addEventListener("click", handleCloseClick);
    this.cleanupHandlers.push(() => closeBtn.removeEventListener("click", handleCloseClick));

    this.modalEl.appendChild(header);

    // --- Body ---
    this.bodyEl = createElement("div", "tos-modal__body");
    this.modalEl.appendChild(this.bodyEl);

    this.overlayEl.appendChild(this.modalEl);
    this.shadow.appendChild(this.overlayEl);

    // Overlay click to close
    const handleOverlayClick = (e: MouseEvent): void => {
      if (e.target === this.overlayEl) {
        this.callbacks.onClose();
      }
    };
    this.overlayEl.addEventListener("click", handleOverlayClick);
    this.cleanupHandlers.push(() => this.overlayEl?.removeEventListener("click", handleOverlayClick));

    // Escape key to close
    const handleKeyDown = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.preventDefault();
        this.callbacks.onClose();
        return;
      }
      // Focus trap
      if (e.key === "Tab" && this.modalEl) {
        this.trapFocus(e);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    this.cleanupHandlers.push(() => document.removeEventListener("keydown", handleKeyDown));

    // Prevent body scroll
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    this.cleanupHandlers.push(() => {
      document.body.style.overflow = originalOverflow;
    });

    // Show the wallet list
    this.showWalletList();

    // Focus the close button
    requestAnimationFrame(() => {
      closeBtn.focus();
    });
  }

  /**
   * Close the modal with exit animation.
   */
  async close(): Promise<void> {
    if (!this.overlayEl || !this.modalEl) return;

    this.overlayEl.classList.remove("tos-modal-overlay--entering");
    this.overlayEl.classList.add("tos-modal-overlay--leaving");
    this.modalEl.classList.remove("tos-modal--entering");
    this.modalEl.classList.add("tos-modal--leaving");

    await new Promise<void>((resolve) => {
      const handler = (): void => resolve();
      this.modalEl?.addEventListener("animationend", handler, { once: true });
      setTimeout(resolve, 300);
    });

    this.destroy();

    // Restore focus
    if (this.previouslyFocused instanceof HTMLElement) {
      this.previouslyFocused.focus();
    }
    this.previouslyFocused = null;
  }

  /**
   * Show the QR code view for a specific wallet.
   */
  showQRCode(wallet: WalletInfo, universalLink: string): void {
    this.currentView = "qr";
    this.selectedWallet = wallet;
    if (!this.bodyEl || !this.titleEl || !this.backBtn) return;

    clearElement(this.bodyEl);
    this.titleEl.textContent = wallet.name;
    this.backBtn.style.display = "";

    const qrView = createElement("div", ["tos-qr-view", "tos-qr-view--entering"]);

    // QR code SVG
    const qrContainer = createElement("div", "tos-qr-view__container");
    qrContainer.innerHTML = generateQRCodeSVG({
      value: universalLink,
      size: 260,
      showLogo: true,
      errorCorrectionLevel: "M",
    });
    qrView.appendChild(qrContainer);

    // Hint text
    const hint = createElement("p", "tos-qr-view__hint");
    hint.textContent = this.i18n.t("scanQR");
    qrView.appendChild(hint);

    // Deep link button
    if (wallet.universalLink) {
      const deeplink = createElement("a", "tos-qr-view__deeplink");
      deeplink.setAttribute("href", universalLink);
      deeplink.setAttribute("target", "_blank");
      deeplink.setAttribute("rel", "noopener noreferrer");
      deeplink.innerHTML = LINK_ICON;
      const linkLabel = document.createElement("span");
      linkLabel.textContent = this.i18n.t("openInWalletApp");
      deeplink.appendChild(linkLabel);
      qrView.appendChild(deeplink);
    }

    this.bodyEl.appendChild(qrView);
  }

  /**
   * Show the connecting spinner state.
   */
  showConnecting(wallet: WalletInfo): void {
    this.currentView = "connecting";
    this.selectedWallet = wallet;
    if (!this.bodyEl || !this.titleEl || !this.backBtn) return;

    clearElement(this.bodyEl);
    this.titleEl.textContent = wallet.name;
    this.backBtn.style.display = "";

    const connecting = createElement("div", "tos-connecting");

    const spinner = createElement("div", "tos-connecting__spinner");
    connecting.appendChild(spinner);

    const text = createElement("p", "tos-connecting__text");
    text.textContent = this.i18n.t("connecting");
    connecting.appendChild(text);

    this.bodyEl.appendChild(connecting);
  }

  /** Whether the modal is currently open. */
  get isOpen(): boolean {
    return this.host !== null;
  }

  /** Get the current view state of the modal. */
  get view(): ModalView {
    return this.currentView;
  }

  /** Get the currently selected wallet (if any). */
  get activeWallet(): WalletInfo | null {
    return this.selectedWallet;
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  /** Show the wallet selection grid. */
  private showWalletList(): void {
    this.currentView = "wallets";
    this.selectedWallet = null;
    if (!this.bodyEl || !this.titleEl || !this.backBtn) return;

    clearElement(this.bodyEl);
    this.titleEl.textContent = this.i18n.t("chooseWallet");
    this.backBtn.style.display = "none";

    const grid = createElement("div", "tos-wallet-grid");
    grid.setAttribute("role", "list");

    for (const wallet of this.wallets) {
      const item = this.createWalletItem(wallet);
      grid.appendChild(item);
    }

    this.bodyEl.appendChild(grid);
  }

  /** Create a single wallet item element. */
  private createWalletItem(wallet: WalletInfo): HTMLElement {
    const item = createElement("div", "tos-wallet-item");
    item.setAttribute("role", "listitem");
    item.setAttribute("tabindex", "0");
    item.setAttribute("aria-label", wallet.name);

    // Wallet icon
    const icon = createElement("img", "tos-wallet-item__icon") as HTMLImageElement;
    icon.src = wallet.imageUrl;
    icon.alt = `${wallet.name} icon`;
    icon.loading = "lazy";
    // Fallback for broken images
    icon.onerror = () => {
      icon.style.display = "none";
      const fallback = createElement("div", "tos-wallet-item__icon");
      fallback.style.display = "flex";
      fallback.style.alignItems = "center";
      fallback.style.justifyContent = "center";
      fallback.style.fontSize = "20px";
      fallback.textContent = wallet.name.charAt(0).toUpperCase();
      item.insertBefore(fallback, item.firstChild);
    };
    item.appendChild(icon);

    // Info
    const info = createElement("div", "tos-wallet-item__info");

    const name = createElement("div", "tos-wallet-item__name");
    name.textContent = wallet.name;
    info.appendChild(name);

    // Show "Installed" badge for injected wallets
    if (wallet.injected) {
      const badge = createElement("div", "tos-wallet-item__badge");
      badge.textContent = "Installed";
      info.appendChild(badge);
    }

    item.appendChild(info);

    // Click handler
    const handleClick = (): void => {
      this.callbacks.onSelectWallet(wallet);
    };
    item.addEventListener("click", handleClick);
    this.cleanupHandlers.push(() => item.removeEventListener("click", handleClick));

    // Keyboard activation
    const handleKeyPress = (e: KeyboardEvent): void => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        this.callbacks.onSelectWallet(wallet);
      }
    };
    item.addEventListener("keydown", handleKeyPress);
    this.cleanupHandlers.push(() => item.removeEventListener("keydown", handleKeyPress));

    return item;
  }

  /** Trap focus inside the modal for accessibility. */
  private trapFocus(e: KeyboardEvent): void {
    if (!this.modalEl) return;

    const focusableSelectors = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
    const focusable = Array.from(
      this.modalEl.querySelectorAll<HTMLElement>(focusableSelectors),
    ).filter((el) => !el.hasAttribute("disabled") && el.offsetParent !== null);

    if (focusable.length === 0) return;

    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;

    // Get the active element, considering shadow DOM
    const active = this.shadow?.activeElement ?? document.activeElement;

    if (e.shiftKey) {
      if (active === first || !this.modalEl.contains(active as Node)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (active === last || !this.modalEl.contains(active as Node)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  /** Get the CSS for the modal shadow DOM. */
  private getStyles(): string {
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

      /* Overlay */
      .tos-modal-overlay {
        position: fixed;
        inset: 0;
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        background: var(--tos-connect-overlay);
        backdrop-filter: blur(4px);
        -webkit-backdrop-filter: blur(4px);
        padding: 16px;
      }

      /* Modal container */
      .tos-modal {
        position: relative;
        width: 100%;
        max-width: 400px;
        max-height: calc(100vh - 32px);
        background: var(--tos-connect-modal-bg);
        border-radius: calc(var(--tos-connect-radius) + 4px);
        box-shadow: var(--tos-connect-shadow);
        overflow: hidden;
        display: flex;
        flex-direction: column;
      }

      /* Header */
      .tos-modal__header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 20px 24px 12px;
        gap: 12px;
      }

      .tos-modal__title {
        font-size: 18px;
        font-weight: 700;
        color: var(--tos-connect-text);
        flex: 1;
      }

      .tos-modal__back-btn,
      .tos-modal__close-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        border: none;
        border-radius: 8px;
        background: var(--tos-connect-secondary-bg);
        color: var(--tos-connect-secondary-text);
        cursor: pointer;
        transition: background-color 0.15s ease, color 0.15s ease;
        flex-shrink: 0;
      }

      .tos-modal__back-btn:hover,
      .tos-modal__close-btn:hover {
        background: var(--tos-connect-hover-bg);
        color: var(--tos-connect-text);
      }

      .tos-modal__back-btn:focus-visible,
      .tos-modal__close-btn:focus-visible {
        outline: 2px solid var(--tos-connect-accent);
        outline-offset: 2px;
      }

      .tos-modal__back-btn svg,
      .tos-modal__close-btn svg { width: 16px; height: 16px; }

      /* Body */
      .tos-modal__body {
        padding: 8px 24px 24px;
        overflow-y: auto;
        flex: 1;
      }

      /* Wallet grid */
      .tos-wallet-grid {
        display: grid;
        grid-template-columns: 1fr;
        gap: 8px;
      }

      .tos-wallet-item {
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 12px 14px;
        border: 1px solid var(--tos-connect-border);
        border-radius: var(--tos-connect-radius);
        background: var(--tos-connect-bg);
        cursor: pointer;
        transition: background-color 0.15s ease, border-color 0.15s ease, transform 0.1s ease;
        user-select: none;
        -webkit-user-select: none;
      }

      .tos-wallet-item:hover {
        background: var(--tos-connect-hover-bg);
        border-color: var(--tos-connect-accent);
      }

      .tos-wallet-item:active { transform: scale(0.98); }

      .tos-wallet-item:focus-visible {
        outline: 2px solid var(--tos-connect-accent);
        outline-offset: 2px;
      }

      .tos-wallet-item__icon {
        width: 44px;
        height: 44px;
        border-radius: 10px;
        object-fit: cover;
        flex-shrink: 0;
        background: var(--tos-connect-secondary-bg);
      }

      .tos-wallet-item__info {
        display: flex;
        flex-direction: column;
        gap: 2px;
        flex: 1;
        min-width: 0;
      }

      .tos-wallet-item__name {
        font-size: 15px;
        font-weight: 600;
        color: var(--tos-connect-text);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .tos-wallet-item__badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 11px;
        font-weight: 500;
        color: var(--tos-connect-success);
        width: fit-content;
      }

      .tos-wallet-item__badge::before {
        content: "";
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: currentColor;
      }

      /* QR code view */
      .tos-qr-view {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 20px;
        padding: 8px 0 0;
      }

      .tos-qr-view__container {
        position: relative;
        width: 260px;
        height: 260px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #ffffff;
        border-radius: var(--tos-connect-radius);
        padding: 16px;
      }

      .tos-qr-view__container svg { width: 100%; height: 100%; }

      .tos-qr-view__hint {
        font-size: 13px;
        color: var(--tos-connect-secondary-text);
        text-align: center;
      }

      .tos-qr-view__deeplink {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        width: 100%;
        padding: 12px 20px;
        border: none;
        border-radius: var(--tos-connect-radius);
        background: var(--tos-connect-accent);
        color: #ffffff;
        font-family: inherit;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: filter 0.15s ease;
        text-decoration: none;
      }

      .tos-qr-view__deeplink:hover { filter: brightness(1.1); }

      .tos-qr-view__deeplink:focus-visible {
        outline: 2px solid var(--tos-connect-accent);
        outline-offset: 2px;
      }

      .tos-qr-view__deeplink svg { width: 16px; height: 16px; }

      /* Connecting state */
      .tos-connecting {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
        padding: 32px 0;
      }

      .tos-connecting__spinner {
        width: 40px;
        height: 40px;
        border: 3px solid var(--tos-connect-border);
        border-top-color: var(--tos-connect-accent);
        border-radius: 50%;
        animation: tos-spin 0.8s linear infinite;
      }

      .tos-connecting__text {
        font-size: 14px;
        color: var(--tos-connect-secondary-text);
      }

      /* Animations */
      @keyframes tos-fade-in {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      @keyframes tos-fade-out {
        from { opacity: 1; }
        to { opacity: 0; }
      }

      @keyframes tos-slide-up {
        from { opacity: 0; transform: translateY(24px) scale(0.96); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }

      @keyframes tos-slide-down {
        from { opacity: 1; transform: translateY(0) scale(1); }
        to { opacity: 0; transform: translateY(24px) scale(0.96); }
      }

      @keyframes tos-spin {
        to { transform: rotate(360deg); }
      }

      .tos-modal-overlay--entering { animation: tos-fade-in 0.2s ease-out forwards; }
      .tos-modal-overlay--leaving { animation: tos-fade-out 0.15s ease-in forwards; }
      .tos-modal--entering { animation: tos-slide-up 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
      .tos-modal--leaving { animation: tos-slide-down 0.15s ease-in forwards; }

      .tos-qr-view--entering { animation: tos-fade-in 0.2s ease-out forwards; }

      @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
        }
      }

      @media (max-width: 480px) {
        .tos-modal {
          max-width: 100%;
          max-height: 85vh;
          border-radius: var(--tos-connect-radius) var(--tos-connect-radius) 0 0;
          margin-top: auto;
        }

        .tos-modal-overlay {
          align-items: flex-end;
          padding: 0;
        }

        .tos-qr-view__container { width: 220px; height: 220px; }
      }
    `;
  }

  /** Destroy the modal and clean up all resources. */
  destroy(): void {
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
    this.overlayEl = null;
    this.modalEl = null;
    this.bodyEl = null;
    this.titleEl = null;
    this.backBtn = null;
    this.selectedWallet = null;
    this.currentView = "wallets";
  }
}
