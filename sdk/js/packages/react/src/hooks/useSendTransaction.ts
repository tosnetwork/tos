/**
 * @tos/react — useSendTransaction hook.
 *
 * Mutation hook for sending TOS transactions.  When a {@link Sender} is
 * available in the {@link SenderContext} (typically injected by
 * `@tos/connect-react`), the transaction is routed through the connected
 * wallet.  Otherwise the mutation will reject with a descriptive error.
 */

import { useContext } from "react";
import type { Address, Cell } from "@tos/core";
import { TosError } from "@tos/client";
import type { SendConfirmation } from "@tos/client";
import { SenderContext } from "../context.js";
import { useMutation } from "./useMutation.js";

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/** Arguments accepted by `sendTransaction`. */
export interface SendTransactionArgs {
  /** Destination address. */
  to: Address | string;
  /** Value in nanoTOS. */
  value: bigint;
  /** Optional message body cell. */
  body?: Cell;
  /** Whether the message should bounce on failure. Default `true`. */
  bounce?: boolean;
}

// ---------------------------------------------------------------------------
// Result (aliased for convenience)
// ---------------------------------------------------------------------------

export interface UseSendTransactionResult {
  /** Fire-and-forget send. */
  sendTransaction: (args: SendTransactionArgs) => void;
  /** Async send — resolves with confirmation. */
  sendTransactionAsync: (args: SendTransactionArgs) => Promise<SendConfirmation>;
  data: SendConfirmation | undefined;
  isPending: boolean;
  isSuccess: boolean;
  isError: boolean;
  error: TosError | null;
  reset: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Mutation hook for sending a TOS transaction.
 *
 * @example
 * ```tsx
 * function Send() {
 *   const { sendTransaction, isPending } = useSendTransaction();
 *   return (
 *     <button
 *       disabled={isPending}
 *       onClick={() => sendTransaction({ to: "0:abc...", value: 1_000_000_000n })}
 *     >
 *       Send 1 TOS
 *     </button>
 *   );
 * }
 * ```
 */
export function useSendTransaction(): UseSendTransactionResult {
  const sender = useContext(SenderContext);

  const mutation = useMutation<SendTransactionArgs, SendConfirmation>({
    mutationFn: async (args) => {
      if (!sender) {
        throw new TosError(
          "No sender available. Wrap your app with a wallet provider " +
            "(e.g. @tos/connect-react) that injects a Sender into SenderContext.",
          "NO_SENDER",
        );
      }

      const result = await sender.send({
        to: String(args.to),
        value: args.value,
        body: args.body,
        bounce: args.bounce,
      });

      return result as SendConfirmation;
    },
  });

  return {
    sendTransaction: mutation.mutate,
    sendTransactionAsync: mutation.mutateAsync,
    data: mutation.data,
    isPending: mutation.isPending,
    isSuccess: mutation.isSuccess,
    isError: mutation.isError,
    error: mutation.error,
    reset: mutation.reset,
  };
}
