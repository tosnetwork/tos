/**
 * @tos/connect-react — useConnectModal hook.
 *
 * Controls the connect modal's visibility. Delegates to TosConnectUI
 * when available, otherwise manages internal boolean state.
 *
 * @packageDocumentation
 */

import { useContext, useMemo } from "react";
import { ModalContext } from "../context.js";
import type { UseConnectModalResult } from "../types.js";

/**
 * Open and close the wallet connect modal.
 *
 * @example
 * ```tsx
 * const { open, close, isOpen } = useConnectModal();
 *
 * return <button onClick={open}>Connect</button>;
 * ```
 */
export function useConnectModal(): UseConnectModalResult {
  const ctx = useContext(ModalContext);

  return useMemo<UseConnectModalResult>(() => {
    if (!ctx) {
      return {
        open: () => {},
        close: () => {},
        isOpen: false,
      };
    }

    return {
      open: ctx.openConnectModal,
      close: ctx.closeConnectModal,
      isOpen: ctx.connectModalOpen,
    };
  }, [ctx]);
}
