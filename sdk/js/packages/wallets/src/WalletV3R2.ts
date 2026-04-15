/**
 * Wallet V3 revision 2 implementation.
 *
 * V3R2 is a widely-used standard wallet that supports:
 * - Up to 4 outgoing messages per external message
 * - Sequence number (replay protection)
 * - Wallet ID (allows multiple wallets from the same key pair)
 * - Message expiration (validUntil)
 *
 * Signing message format:
 *   walletId:uint32  validUntil:uint32  seqno:uint32
 *   [mode:uint8 message:^Cell]*
 *
 * External message body:
 *   signature:bits512  signingMessage
 *
 * Initial data layout:
 *   seqno:uint32  walletId:uint32  publicKey:bits256
 */

import {
  Address,
  Cell,
  beginCell,
  contractAddress,
  hexToBytes,
  type StateInit,
} from "@tos/core";
import { sign } from "@tos/crypto";
import type {
  ContractProvider,
  Signer,
  SendConfirmation,
} from "@tos/client";
import { WALLET_V3R2_CODE } from "./codes.js";
import type {
  Wallet,
  CreateTransferArgs,
  CreateTransferAsyncArgs,
  SendTransferArgs,
} from "./types.js";
import { storeOutMessages, defaultValidUntil } from "./utils.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default wallet ID base: 698983191 (0x29A9A317) */
const DEFAULT_WALLET_ID_BASE = 698983191;

/** Maximum number of outgoing messages per transfer */
const MAX_MESSAGES = 4;

// ---------------------------------------------------------------------------
// WalletV3R2
// ---------------------------------------------------------------------------

/**
 * Wallet V3 revision 2 -- the most widely used standard TOS wallet.
 *
 * Supports up to 4 outgoing messages per external message, sequence number
 * replay protection, wallet ID for multiple wallets from the same key pair,
 * and message expiration via validUntil.
 *
 * @example
 * ```typescript
 * import { WalletV3R2 } from "@tos/wallets";
 * import { mnemonicToPrivateKey } from "@tos/crypto";
 *
 * const keys = await mnemonicToPrivateKey(mnemonic);
 * const wallet = WalletV3R2.create({ publicKey: keys.publicKey });
 * console.log(wallet.address.toString());
 * ```
 */
export class WalletV3R2 implements Wallet {
  readonly address: Address;
  readonly init: StateInit;
  readonly walletId: number;
  readonly publicKey: Uint8Array;

  private constructor(
    address: Address,
    init: StateInit,
    publicKey: Uint8Array,
    walletId: number,
  ) {
    this.address = address;
    this.init = init;
    this.publicKey = publicKey;
    this.walletId = walletId;
  }

  /**
   * Create a new WalletV3R2 instance from a public key.
   *
   * The wallet address is computed deterministically from the code cell
   * and initial data (seqno=0, walletId, publicKey).
   *
   * @param args.publicKey - 32-byte Ed25519 public key
   * @param args.workchain - Workchain ID (default 0)
   * @param args.walletId - Custom wallet ID (default auto-computed)
   * @returns A new WalletV3R2 instance with computed address and init
   *
   * @example
   * ```typescript
   * const wallet = WalletV3R2.create({ publicKey: keys.publicKey });
   * console.log(wallet.address.toString());
   * ```
   */
  static create(args: {
    publicKey: Uint8Array;
    workchain?: number;
    walletId?: number;
  }): WalletV3R2 {
    const workchain = args.workchain ?? 0;
    const walletId = args.walletId ?? DEFAULT_WALLET_ID_BASE + workchain;

    const code = Cell.fromBoc(hexToBytes(WALLET_V3R2_CODE))[0]!;

    // Initial data: seqno(0):uint32 walletId:uint32 publicKey:bits256
    const data = beginCell()
      .storeUint(0, 32)              // seqno = 0
      .storeUint(walletId, 32)       // wallet ID
      .storeBuffer(args.publicKey)    // 256-bit public key
      .endCell();

    const init: StateInit = { code, data };
    const address = contractAddress(workchain, init);

    return new WalletV3R2(address, init, args.publicKey, walletId);
  }

  // -------------------------------------------------------------------------
  // Query methods (require ContractProvider)
  // -------------------------------------------------------------------------

  /**
   * Query the current on-chain sequence number.
   *
   * @param provider - Injected by `open()`
   * @returns The current seqno
   */
  async getSeqno(provider: ContractProvider): Promise<number> {
    const result = await provider.get("seqno", []);
    return result.stack.readNumber();
  }

  /**
   * Query the on-chain balance in nanoTOS.
   *
   * @param provider - Injected by `open()`
   * @returns Balance as a bigint
   */
  async getBalance(provider: ContractProvider): Promise<bigint> {
    const state = await provider.getState();
    return state.balance;
  }

  /**
   * Query the on-chain public key.
   *
   * @param provider - Injected by `open()`
   * @returns 32-byte public key
   */
  async getPublicKey(provider: ContractProvider): Promise<Uint8Array> {
    const result = await provider.get("get_public_key", []);
    const keyBigInt = result.stack.readBigNumber();
    return bigIntToBytes(keyBigInt, 32);
  }

  // -------------------------------------------------------------------------
  // Transfer building
  // -------------------------------------------------------------------------

  /**
   * Build a signing message (the payload before signature).
   */
  private buildSigningMessage(
    seqno: number,
    messages: CreateTransferArgs["messages"],
    validUntil?: number,
  ): Cell {
    if (messages.length < 1 || messages.length > MAX_MESSAGES) {
      throw new Error(
        `WalletV3R2: expected 1-${MAX_MESSAGES} messages, got ${messages.length}`,
      );
    }

    const until = validUntil ?? defaultValidUntil();
    const builder = beginCell()
      .storeUint(this.walletId, 32)
      .storeUint(until, 32)
      .storeUint(seqno, 32);

    storeOutMessages(messages, builder);

    return builder.endCell();
  }

  /**
   * Build and sign a transfer body cell synchronously.
   *
   * @param args - Transfer arguments including seqno, messages, and secretKey
   * @returns The signed external message body cell
   *
   * @example
   * ```typescript
   * const body = wallet.createTransfer({
   *   seqno: 1,
   *   secretKey: keys.secretKey,
   *   messages: [{ to: addr, value: toNano("1.5") }],
   * });
   * ```
   */
  createTransfer(args: CreateTransferArgs): Cell {
    const signingMessage = this.buildSigningMessage(
      args.seqno,
      args.messages,
      args.validUntil,
    );

    const signature = sign(signingMessage.hash(), args.secretKey);

    return beginCell()
      .storeBuffer(signature) // 512-bit signature
      .storeSlice(signingMessage.beginParse())
      .endCell();
  }

  /**
   * Build and sign a transfer body cell asynchronously (e.g., hardware wallet).
   *
   * @param args - Transfer arguments with an async signer callback
   * @returns The signed external message body cell
   */
  async createTransferAsync(args: CreateTransferAsyncArgs): Promise<Cell> {
    const signingMessage = this.buildSigningMessage(
      args.seqno,
      args.messages,
      args.validUntil,
    );

    const signature = await args.signer(signingMessage.hash());

    return beginCell()
      .storeBuffer(signature)
      .storeSlice(signingMessage.beginParse())
      .endCell();
  }

  /**
   * Query seqno, build, sign, and submit a transfer in one call.
   *
   * @param provider - Injected by `open()`
   * @param via - Signer (e.g., KeyPairSigner)
   * @param args - Transfer arguments (messages, validUntil)
   * @returns Send confirmation
   *
   * @example
   * ```typescript
   * await wallet.sendTransfer(signer, {
   *   messages: [{ to: addr, value: toNano("1.5"), body: comment("Hello") }],
   * });
   * ```
   */
  async sendTransfer(
    provider: ContractProvider,
    via: Signer,
    args: SendTransferArgs,
  ): Promise<SendConfirmation> {
    const seqno = await this.getSeqno(provider);
    const signingMessage = this.buildSigningMessage(
      seqno,
      args.messages,
      args.validUntil,
    );

    const signature = await via.sign(signingMessage.hash());

    const body = beginCell()
      .storeBuffer(signature)
      .storeSlice(signingMessage.beginParse())
      .endCell();

    return provider.external(body) as unknown as SendConfirmation;
  }

  /**
   * Deploy this wallet contract on-chain via an external message.
   *
   * @param provider - Injected by `open()`
   * @param via - Signer
   * @param _value - Unused (kept for interface compatibility)
   */
  async sendDeploy(
    provider: ContractProvider,
    via: Signer,
    _value: bigint,
  ): Promise<void> {
    // For external deploy: send an external message with seqno=0
    // For deploy, the signing message is just the header with no outgoing messages
    const deployMessage = beginCell()
      .storeUint(this.walletId, 32)
      .storeUint(0xFFFFFFFF, 32) // validUntil = max (for initial deploy)
      .storeUint(0, 32)          // seqno = 0
      .endCell();

    const signature = await via.sign(deployMessage.hash());

    const body = beginCell()
      .storeBuffer(signature)
      .storeSlice(deployMessage.beginParse())
      .endCell();

    await provider.external(body);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a BigInt to a Uint8Array of the specified byte length (big-endian).
 */
function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
  return bytes;
}
