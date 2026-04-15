/**
 * KeyPairSigner — a concrete Signer implementation backed by an Ed25519
 * key pair and an opened wallet contract.
 *
 * This signer bridges the Signer interface (used by ContractProvider.internal)
 * with wallet-specific transfer logic. When `send()` is called, it:
 * 1. Queries the wallet's current seqno
 * 2. Builds the transfer using the wallet's createTransfer
 * 3. Submits the signed BOC via the provider
 */

import { type Address, type Cell, type StateInit } from "@tos/core";
import type { KeyPair } from "@tos/crypto";
import { sign } from "@tos/crypto";
import type {
  Signer,
  SenderArguments,
  OpenedContract,
} from "@tos/client";
// Wallet type used via OpenedContract<any> to avoid ContractLike index signature mismatch
// import type { Wallet } from "./types.js";

// ---------------------------------------------------------------------------
// KeyPairSigner
// ---------------------------------------------------------------------------

/**
 * A concrete {@link Signer} implementation backed by an Ed25519 key pair.
 *
 * Bridges the Signer interface with wallet-specific transfer logic. When used
 * with `ContractProvider.internal()`, it automatically queries the wallet's
 * seqno, builds the transfer, signs it, and submits the external message.
 *
 * @example
 * ```typescript
 * import { KeyPairSigner, WalletV4R2 } from "@tos/wallets";
 * import { TosClient, open } from "@tos/client";
 * import { mnemonicToPrivateKey } from "@tos/crypto";
 *
 * const keys = await mnemonicToPrivateKey(mnemonic);
 * const wallet = open(WalletV4R2.create({ publicKey: keys.publicKey }), client);
 * const signer = new KeyPairSigner(keys, wallet);
 *
 * // Use signer to send a transfer
 * await wallet.sendTransfer(signer, {
 *   messages: [{ to: addr, value: toNano("1.5") }],
 * });
 * ```
 */
export class KeyPairSigner implements Signer {
  readonly address: Address;
  private readonly keyPair: KeyPair;
  private readonly wallet: OpenedContract<any>;

  /**
   * Create a new KeyPairSigner.
   *
   * @param keyPair - Ed25519 key pair (publicKey: 32 bytes, secretKey: 64 bytes)
   * @param wallet  - An opened wallet contract instance (already bound to a provider)
   */
  constructor(keyPair: KeyPair, wallet: OpenedContract<any>) {
    this.keyPair = keyPair;
    this.wallet = wallet;
    this.address = wallet.address;
  }

  /**
   * Sign a message hash using the Ed25519 secret key.
   *
   * @param message - The bytes to sign (typically a cell hash, 32 bytes)
   * @returns 64-byte Ed25519 signature
   */
  async sign(message: Uint8Array): Promise<Uint8Array> {
    return sign(message, this.keyPair.secretKey);
  }

  /**
   * Build and submit a transfer through the wallet contract.
   *
   * This method is called by ContractProvider.internal() when using
   * this signer as the `via` parameter. It:
   * 1. Queries the current seqno from the wallet
   * 2. Builds the signed transfer body via wallet.createTransfer
   * 3. Submits the external message via the provider
   */
  async send(args: SenderArguments): Promise<void> {
    await this.wallet.sendTransfer(this, {
      messages: [
        {
          to: args.to as unknown as Address,
          value: args.value,
          body: (args.body ?? undefined) as Cell | undefined,
          bounce: args.bounce ?? undefined,
          init: (args.init ?? undefined) as StateInit | undefined,
          mode: args.sendMode ?? undefined,
        },
      ],
    });
  }
}
