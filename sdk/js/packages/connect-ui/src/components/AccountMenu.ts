/**
 * Account menu dropdown component for @tos/connect-ui.
 *
 * Shows when the user clicks the connected button:
 * - Full address with copy button
 * - Chain badge (mainnet / testnet)
 * - Disconnect button
 */

import type { ConnectedAccount } from "@tos/connect";
import type { I18nManager } from "../i18n/index.js";
import { copyToClipboard, createElement } from "../utils.js";

// ---------------------------------------------------------------------------
// SVG Icons
// ---------------------------------------------------------------------------

const COPY_ICON = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <rect x="5" y="5" width="9" height="9" rx="1.5"/>
  <path d="M3 11V3a1.5 1.5 0 0 1 1.5-1.5H11"/>
</svg>`;

const CHECK_ICON = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <polyline points="3.5 8.5 6.5 11.5 12.5 4.5"/>
</svg>`;

const DISCONNECT_ICON = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <path d="M6 2H3a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>
  <polyline points="10 12 14 8 10 4"/>
  <line x1="14" y1="8" x2="6" y2="8"/>
</svg>`;

// ---------------------------------------------------------------------------
// AccountMenu
// ---------------------------------------------------------------------------

export interface AccountMenuCallbacks {
  onDisconnect: () => void;
  onClose: () => void;
}

export class AccountMenu {
  private container: HTMLElement | null = null;
  private copyTimeout: ReturnType<typeof setTimeout> | null = null;
  private readonly cleanupHandlers: Array<() => void> = [];

  constructor(
    private readonly i18n: I18nManager,
  ) {}

  /**
   * Render the account menu and return the root element.
   * The caller is responsible for positioning and inserting it into the DOM.
   */
  render(
    account: ConnectedAccount,
    friendlyAddress: string,
    callbacks: AccountMenuCallbacks,
  ): HTMLElement {
    this.destroy();

    const menu = createElement("div", "tos-account-menu");
    menu.classList.add("tos-account-menu--entering");
    menu.setAttribute("role", "menu");
    menu.setAttribute("aria-label", "Account menu");

    // --- Header section ---
    const header = createElement("div", "tos-account-menu__header");

    // Chain badge
    const chain = account.chain;
    const isMainnet = chain === "-239";
    const chainBadge = createElement("div", [
      "tos-account-menu__chain",
      isMainnet ? "tos-account-menu__chain--mainnet" : "tos-account-menu__chain--testnet",
    ]);
    chainBadge.textContent = isMainnet ? "Mainnet" : "Testnet";
    header.appendChild(chainBadge);

    // Address row
    const addressRow = createElement("div", "tos-account-menu__address-row");

    const addressEl = createElement("div", "tos-account-menu__address");
    addressEl.textContent = friendlyAddress;
    addressRow.appendChild(addressEl);

    // Copy button
    const copyBtn = createElement("button", "tos-account-menu__copy-btn");
    copyBtn.setAttribute("type", "button");
    copyBtn.setAttribute("aria-label", this.i18n.t("copyAddress"));
    copyBtn.setAttribute("role", "menuitem");
    copyBtn.innerHTML = COPY_ICON;

    const handleCopy = async (): Promise<void> => {
      const success = await copyToClipboard(friendlyAddress);
      if (success) {
        copyBtn.innerHTML = CHECK_ICON;
        copyBtn.classList.add("tos-account-menu__copy-btn--copied");
        copyBtn.setAttribute("aria-label", this.i18n.t("copied"));

        if (this.copyTimeout) clearTimeout(this.copyTimeout);
        this.copyTimeout = setTimeout(() => {
          copyBtn.innerHTML = COPY_ICON;
          copyBtn.classList.remove("tos-account-menu__copy-btn--copied");
          copyBtn.setAttribute("aria-label", this.i18n.t("copyAddress"));
          this.copyTimeout = null;
        }, 2000);
      }
    };

    copyBtn.addEventListener("click", handleCopy);
    this.cleanupHandlers.push(() => copyBtn.removeEventListener("click", handleCopy));

    addressRow.appendChild(copyBtn);
    header.appendChild(addressRow);
    menu.appendChild(header);

    // --- Actions section ---
    const actions = createElement("div", "tos-account-menu__actions");

    const disconnectBtn = createElement("button", "tos-account-menu__disconnect");
    disconnectBtn.setAttribute("type", "button");
    disconnectBtn.setAttribute("role", "menuitem");
    disconnectBtn.innerHTML = DISCONNECT_ICON;
    const label = document.createElement("span");
    label.textContent = this.i18n.t("disconnect");
    disconnectBtn.appendChild(label);

    const handleDisconnect = (): void => {
      callbacks.onDisconnect();
    };
    disconnectBtn.addEventListener("click", handleDisconnect);
    this.cleanupHandlers.push(() => disconnectBtn.removeEventListener("click", handleDisconnect));

    actions.appendChild(disconnectBtn);
    menu.appendChild(actions);

    // Click outside to close
    const handleClickOutside = (e: MouseEvent): void => {
      if (e.composedPath().includes(menu)) return;
      callbacks.onClose();
    };

    // Defer so the current click doesn't immediately close it
    requestAnimationFrame(() => {
      document.addEventListener("click", handleClickOutside, true);
    });
    this.cleanupHandlers.push(() => document.removeEventListener("click", handleClickOutside, true));

    this.container = menu;
    return menu;
  }

  /** Animate out and destroy. */
  async animateOut(): Promise<void> {
    if (!this.container) return;
    this.container.classList.remove("tos-account-menu--entering");
    this.container.classList.add("tos-account-menu--leaving");
    await new Promise<void>((resolve) => {
      const handler = (): void => {
        resolve();
      };
      this.container!.addEventListener("animationend", handler, { once: true });
      // Fallback in case animationend doesn't fire
      setTimeout(resolve, 200);
    });
    this.destroy();
  }

  /** Clean up DOM and event listeners. */
  destroy(): void {
    if (this.copyTimeout) {
      clearTimeout(this.copyTimeout);
      this.copyTimeout = null;
    }
    for (const cleanup of this.cleanupHandlers) {
      cleanup();
    }
    this.cleanupHandlers.length = 0;
    if (this.container?.parentNode) {
      this.container.parentNode.removeChild(this.container);
    }
    this.container = null;
  }

  /** Whether the menu is currently visible. */
  get isOpen(): boolean {
    return this.container !== null;
  }
}
