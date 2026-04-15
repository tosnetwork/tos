/**
 * @tos/react — useContractWrite hook.
 *
 * Mutation hook for writing to a smart contract (sending an internal message
 * with address + value + body).  Routes through the {@link SenderContext},
 * similar to {@link useSendTransaction}.
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

/** Arguments for a contract write operation. */
export interface ContractWriteArgs {
  /** Contract address. */
  address: Address | string;
  /** Value to attach in nanoTOS. */
  value: bigint;
  /** Message body cell. */
  body?: Cell;
  /** Whether the message should bounce on failure. Default `true`. */
  bounce?: boolean;
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

export interface UseContractWriteResult {
  /** Fire-and-forget write. */
  write: (args: ContractWriteArgs) => void;
  /** Async write — resolves with confirmation. */
  writeAsync: (args: ContractWriteArgs) => Promise<SendConfirmation>;
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
 * Mutation hook for calling a smart contract (write operation).
 *
 * @example
 * ```tsx
 * function Mint() {
 *   const { write, isPending } = useContractWrite();
 *   return (
 *     <button
 *       disabled={isPending}
 *       onClick={() => write({ address: jettonMinter, value: toNano("0.1"), body: mintBody })}
 *     >
 *       Mint
 *     </button>
 *   );
 * }
 * ```
 */
export function useContractWrite(): UseContractWriteResult {
  const sender = useContext(SenderContext);

  const mutation = useMutation<ContractWriteArgs, SendConfirmation>({
    mutationFn: async (args) => {
      if (!sender) {
        throw new TosError(
          "No sender available. Wrap your app with a wallet provider " +
            "(e.g. @tos/connect-react) that injects a Sender into SenderContext.",
          "NO_SENDER",
        );
      }

      const result = await sender.send({
        to: String(args.address),
        value: args.value,
        body: args.body,
        bounce: args.bounce,
      });

      return result as SendConfirmation;
    },
  });

  return {
    write: mutation.mutate,
    writeAsync: mutation.mutateAsync,
    data: mutation.data,
    isPending: mutation.isPending,
    isSuccess: mutation.isSuccess,
    isError: mutation.isError,
    error: mutation.error,
    reset: mutation.reset,
  };
}
