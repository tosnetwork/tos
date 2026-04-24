/**
 * @tos/connect-ui
 *
 * Framework-agnostic UI components for TOS wallet connection.
 * Pure vanilla JS + CSS with Shadow DOM isolation.
 *
 * @example
 * ```ts
 * import { TosConnectUI } from "@tos/connect-ui";
 *
 * const ui = new TosConnectUI({
 *   manifestUrl: "https://myapp.com/tosconnect-manifest.json",
 *   buttonRootId: "tos-connect-button",
 *   theme: "auto",
 *   language: "en",
 * });
 *
 * // Listen for connection changes
 * ui.onStatusChange((wallet) => {
 *   if (wallet) {
 *     console.log("Connected:", wallet.account.address);
 *   } else {
 *     console.log("Disconnected");
 *   }
 * });
 *
 * // Or open the modal programmatically
 * ui.openModal();
 * ```
 *
 * @packageDocumentation
 */

// Main class
export { TosConnectUI } from "./TosConnectUI.js";
export type { TosConnectUIOptions } from "./TosConnectUI.js";

// Components (for advanced use cases / custom composition)
export { ConnectButton } from "./components/ConnectButton.js";
export type { ConnectButtonCallbacks } from "./components/ConnectButton.js";
export { ConnectModal } from "./components/ConnectModal.js";
export type { ConnectModalCallbacks, ModalView } from "./components/ConnectModal.js";
export { AccountMenu } from "./components/AccountMenu.js";
export type { AccountMenuCallbacks } from "./components/AccountMenu.js";
export { generateQRCodeSVG, createQRCodeElement } from "./components/QRCode.js";
export type { QRCodeOptions } from "./components/QRCode.js";

// Theme
export { ThemeManager } from "./styles/theme.js";
export type { ThemeMode, ThemeColors } from "./styles/theme.js";

// i18n
export { I18nManager } from "./i18n/index.js";
export type { TranslationKeys, LocaleCode } from "./i18n/index.js";

// Utilities
export {
  shortenAddress,
  formatBalance,
  copyToClipboard,
  isBrowser,
  prefersDarkMode,
} from "./utils.js";

// Re-export commonly used types from @tos/connect
export type {
  ConnectedAccount,
  ConnectedWallet,
  ConnectRequest,
  SendTransactionRequest,
  SendTransactionResponse,
  WalletInfo,
} from "@tos/connect";
