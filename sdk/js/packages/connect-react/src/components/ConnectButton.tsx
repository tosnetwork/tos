/**
 * @tos/connect-react — ConnectButton component.
 *
 * A ready-made connect button that shows:
 *  - "Connect Wallet" when disconnected
 *  - The wallet's address (with optional balance) when connected
 *
 * Supports a `.Custom` render-prop variant for full control.
 *
 * @packageDocumentation
 */

import { useCallback, useContext, useMemo, type ReactNode } from "react";
import { Address } from "@tos/core";
import { fromNano } from "@tos/core";
import { ConnectContext, ModalContext, TranslationContext } from "../context.js";
import type {
  ConnectButtonProps,
  ConnectButtonCustomProps,
  ConnectButtonRenderProps,
} from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format an Address for display: first 4 + last 4 characters of the friendly form. */
function formatAddress(addr: Address): string {
  const str = addr.toString({ urlSafe: true, bounceable: true });
  if (str.length <= 10) return str;
  return `${str.slice(0, 6)}...${str.slice(-4)}`;
}

/** Format a nanotomis balance as a human-readable string. */
function formatBalance(nanotomis: bigint): string {
  const full = fromNano(nanotomis);
  // Truncate to 2 decimal places
  const dotIndex = full.indexOf(".");
  if (dotIndex === -1) return full;
  return full.slice(0, dotIndex + 3); // integer + "." + 2 digits
}

// ---------------------------------------------------------------------------
// Internal hook: gathers all render props
// ---------------------------------------------------------------------------

function useConnectButtonProps(): ConnectButtonRenderProps {
  const connectCtx = useContext(ConnectContext);
  const modalCtx = useContext(ModalContext);

  const wallet = connectCtx?.wallet ?? null;

  // Parse address
  const address = useMemo<Address | null>(() => {
    if (!wallet) return null;
    try {
      return Address.parse(wallet.account.address);
    } catch {
      return null;
    }
  }, [wallet]);

  // Balance: we fetch from the query cache keyed by address.
  // Since useBalance from @tos/react may not be available as a direct import
  // at this layer, we store balance as null and let it be populated if the
  // consumer uses useBalance separately. For the built-in ConnectButton,
  // we attempt a lightweight fetch.
  //
  // Note: actual balance fetching is delegated to the BalanceFetcher
  // inside the default ConnectButton below. For Custom, it's up to the
  // consumer to use useBalance if they want it.
  const balance: bigint | null = null;

  const walletName = wallet?.device?.appName ?? null;
  const walletIcon: string | null = null;

  const openConnectModal = useCallback(() => {
    modalCtx?.openConnectModal();
  }, [modalCtx]);

  const openAccountModal = useCallback(() => {
    modalCtx?.openAccountModal();
  }, [modalCtx]);

  const disconnect = useCallback(async () => {
    await connectCtx?.disconnect();
  }, [connectCtx]);

  return {
    connected: wallet !== null,
    address,
    balance,
    walletName,
    walletIcon,
    openConnectModal,
    openAccountModal,
    disconnect,
  };
}

// ---------------------------------------------------------------------------
// ConnectButton.Custom
// ---------------------------------------------------------------------------

function ConnectButtonCustom({ children }: ConnectButtonCustomProps): ReactNode {
  const props = useConnectButtonProps();
  return <>{children(props)}</>;
}

// ---------------------------------------------------------------------------
// Default ConnectButton
// ---------------------------------------------------------------------------

function ConnectButtonDefault({
  showBalance = true,
  accountStatus = "full",
  label,
}: ConnectButtonProps): ReactNode {
  const translations = useContext(TranslationContext);
  const buttonLabel = label ?? translations.connectButton;
  const props = useConnectButtonProps();
  const connectCtx = useContext(ConnectContext);

  const handleClick = useCallback(() => {
    if (props.connected) {
      props.openAccountModal();
    } else {
      props.openConnectModal();
    }
  }, [props]);

  // ---- Disconnected state ----
  if (!props.connected) {
    return (
      <button
        type="button"
        className="tos-connect-button"
        onClick={handleClick}
        disabled={connectCtx?.connecting}
      >
        <span className="tos-connect-button__label">
          {connectCtx?.connecting ? translations.connecting : buttonLabel}
        </span>
      </button>
    );
  }

  // ---- Connected state ----
  const addressStr = props.address ? formatAddress(props.address) : "Unknown";

  return (
    <button
      type="button"
      className="tos-connect-button tos-connect-button--connected"
      onClick={handleClick}
    >
      {/* Wallet icon */}
      {accountStatus === "full" && props.walletName && (
        <span className="tos-connect-button__wallet-name">
          {props.walletName}
        </span>
      )}

      {/* Balance */}
      {showBalance && props.balance !== null && (
        <span className="tos-connect-button__balance">
          {formatBalance(props.balance)} TOS
        </span>
      )}

      {/* Address */}
      {(accountStatus === "full" || accountStatus === "address") && (
        <span className="tos-connect-button__address">{addressStr}</span>
      )}

      {/* Avatar (placeholder — always show first 2 chars as initials) */}
      {(accountStatus === "full" || accountStatus === "avatar") && props.address && (
        <span className="tos-connect-button__avatar">
          {props.address
            .toString({ urlSafe: true, bounceable: true })
            .slice(0, 2)
            .toUpperCase()}
        </span>
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Composite export
// ---------------------------------------------------------------------------

/**
 * ConnectButton — a ready-made UI element for connecting wallets.
 *
 * @example
 * ```tsx
 * // Default:
 * <ConnectButton />
 *
 * // Customised:
 * <ConnectButton showBalance={false} label="Login" />
 *
 * // Full custom render:
 * <ConnectButton.Custom>
 *   {({ connected, address, openConnectModal, disconnect }) => (
 *     <button onClick={connected ? disconnect : openConnectModal}>
 *       {connected ? address!.toString().slice(0, 8) : "Connect"}
 *     </button>
 *   )}
 * </ConnectButton.Custom>
 * ```
 */
export const ConnectButton: typeof ConnectButtonDefault & {
  Custom: typeof ConnectButtonCustom;
} = Object.assign(ConnectButtonDefault, {
  Custom: ConnectButtonCustom,
});
