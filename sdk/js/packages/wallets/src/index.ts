/**
 * @tos/wallets — Wallet contract implementations for the TOS Blockchain.
 *
 * This package provides ready-to-use wallet contracts (V3R2, V4R2, V5R1,
 * and Highload V2) along with a KeyPairSigner for signing and submitting
 * transactions.
 *
 * @example
 * ```ts
 * import { WalletV4R2, KeyPairSigner } from "@tos/wallets";
 * import { keyPairFromSeed } from "@tos/crypto";
 *
 * const keyPair = keyPairFromSeed(seed);
 * const wallet = WalletV4R2.create({ publicKey: keyPair.publicKey });
 * console.log(wallet.address.toString());
 * ```
 */

// Types
export type {
  Wallet,
  OutMessage,
  CreateTransferArgs,
  CreateTransferAsyncArgs,
  SendTransferArgs,
} from "./types.js";

// Wallet implementations
import { WalletV3R2 } from "./WalletV3R2.js";
import { WalletV4R2 } from "./WalletV4R2.js";
import { WalletV5R1 } from "./WalletV5R1.js";
import { HighloadWalletV2, createQueryId } from "./HighloadWalletV2.js";

export { WalletV3R2, WalletV4R2, WalletV5R1, HighloadWalletV2, createQueryId };

// Signer
export { KeyPairSigner } from "./KeyPairSigner.js";

// Utilities
export { createInternalMessage } from "./utils.js";

// Compiled contract codes
export {
  WALLET_V3R2_CODE,
  WALLET_V4R2_CODE,
  WALLET_V5R1_CODE,
  HIGHLOAD_V2_CODE,
} from "./codes.js";

// ---------------------------------------------------------------------------
// Wallets registry
// ---------------------------------------------------------------------------

/**
 * Registry of all supported wallet contract implementations.
 *
 * Usage:
 * ```ts
 * import { Wallets } from "@tos/wallets";
 *
 * const wallet = Wallets.default.create({ publicKey });
 * // or
 * const v3wallet = Wallets.v3r2.create({ publicKey });
 * ```
 */
export const Wallets = {
  v3r2: WalletV3R2,
  v4r2: WalletV4R2,
  v5r1: WalletV5R1,
  highload: HighloadWalletV2,
  default: WalletV4R2,
} as const;
