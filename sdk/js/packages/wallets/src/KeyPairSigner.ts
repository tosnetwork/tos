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

import { Address, Cell, type StateInit } from "@tos/core";
import type { KeyPair } from "@tos/crypto";
import { sign } from "@tos/crypto";
import type {
  Signer,
  SenderArguments,
  SendConfirmation,
} from "@tos/client";
import type { SendTransferArgs } from "./types.js";

interface TransferCapableWallet {
  readonly address: Address;
  sendTransfer(via: Signer, args: SendTransferArgs): Promise<SendConfirmation>;
}

function toAddress(address: SenderArguments["to"]): Address {
  if (typeof address === "string") {
    return Address.parse(address);
  }
  if (!(address instanceof Address)) {
    throw new TypeError("KeyPairSigner.send expects a concrete Address instance");
  }
  return address;
}

function toBody(body: SenderArguments["body"]): Cell | undefined {
  if (body == null) {
    return undefined;
  }
  if (!(body instanceof Cell)) {
    throw new TypeError("KeyPairSigner.send expects body to be a Cell when used with wallet transfers");
  }
  return body;
}

function toStateInit(init: SenderArguments["init"]): StateInit | undefined {
  if (init == null) {
    return undefined;
  }

  const code = init.code;
  const data = init.data;
  if (code == null || data == null) {
    throw new TypeError("KeyPairSigner.send expects init to include both code and data Cells");
  }
  if (!(code instanceof Cell) || !(data instanceof Cell)) {
    throw new TypeError("KeyPairSigner.send expects init.code/init.data to be Cells when used with wallet transfers");
  }

  return {
    code,
    data,
  };
}

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
  private readonly wallet: TransferCapableWallet;

  /**
   * Create a new KeyPairSigner.
   *
   * @param keyPair - Ed25519 key pair (publicKey: 32 bytes, secretKey: 64 bytes)
   * @param wallet  - An opened wallet contract instance (already bound to a provider)
   */
  constructor(keyPair: KeyPair, wallet: TransferCapableWallet) {
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
          to: toAddress(args.to),
          value: args.value,
          body: toBody(args.body),
          bounce: args.bounce ?? undefined,
          init: toStateInit(args.init),
          mode: args.sendMode ?? undefined,
        },
      ],
    });
  }
}
