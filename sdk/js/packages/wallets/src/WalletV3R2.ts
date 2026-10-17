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
 *   networkGlobalId:int32  walletId:uint32  validUntil:uint32  seqno:uint32
 *   [mode:uint8 message:^Cell]*
 *
 * The wallet code (crypto/smartcont/wallet3-code.fc) refuses a message whose
 * networkGlobalId differs from the executing network's GLOBALID (exit 36), so a
 * signature never replays on another network.
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
  PendingTransfer,
} from "@tos/client";
import { WALLET_V3R2_CODE } from "./codes.js";
import type {
  Wallet,
  CreateTransferArgs,
  CreateTransferAsyncArgs,
  SendTransferArgs,
} from "./types.js";
import { storeOutMessages, requireAffordable, requireWalletPublicKey, resolveValidUntil } from "./utils.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default wallet ID base: 698983191 (0x29A9A317) */
const DEFAULT_WALLET_ID_BASE = 698983191;

/** Maximum number of outgoing messages per transfer */
const MAX_MESSAGES = 4;

/**
 * Validate an explicitly supplied network global ID (ConfigParam 19, int32).
 *
 * The wallet code compares the leading int32 of every signed message with the
 * GLOBALID of the network executing it, so a message signed for one network is
 * refused on every other. There is deliberately no default.
 */
function requireNetworkGlobalId(value: number, wallet: string): number {
  if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
    throw new Error(`${wallet}: networkGlobalId must be an explicitly supplied signed int32 integer`);
  }
  return value;
}

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
 * const networkGlobalId = await client.getNetworkGlobalId();
 * const wallet = WalletV3R2.create({ publicKey: keys.publicKey, networkGlobalId });
 * console.log(wallet.address.toString());
 * ```
 */
export class WalletV3R2 implements Wallet {
  readonly address: Address;
  readonly init: StateInit;
  readonly walletId: number;
  readonly networkGlobalId: number;
  readonly publicKey: Uint8Array;

  private constructor(
    address: Address,
    init: StateInit,
    publicKey: Uint8Array,
    walletId: number,
    networkGlobalId: number,
  ) {
    this.address = address;
    this.init = init;
    this.publicKey = publicKey;
    this.walletId = walletId;
    this.networkGlobalId = networkGlobalId;
  }

  /**
   * Create a new WalletV3R2 instance from a public key.
   *
   * The wallet address is computed deterministically from the code cell
   * and initial data (seqno=0, walletId, publicKey); it does not depend on the
   * network, only the signed messages do.
   *
   * @param args.publicKey - 32-byte Ed25519 public key
   * @param args.networkGlobalId - Required network global ID (ConfigParam 19, int32)
   * @param args.workchain - Workchain ID (default 0)
   * @param args.walletId - Custom wallet ID (default auto-computed)
   * @returns A new WalletV3R2 instance with computed address and init
   *
   * @example
   * ```typescript
   * const wallet = WalletV3R2.create({ publicKey: keys.publicKey, networkGlobalId });
   * console.log(wallet.address.toString());
   * ```
   */
  static create(args: {
    publicKey: Uint8Array;
    networkGlobalId: number;
    workchain?: number;
    walletId?: number;
  }): WalletV3R2 {
    requireWalletPublicKey(args.publicKey, "WalletV3R2");
    const networkGlobalId = requireNetworkGlobalId(args.networkGlobalId, "WalletV3R2");
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

    return new WalletV3R2(address, init, args.publicKey, walletId, networkGlobalId);
  }

  // -------------------------------------------------------------------------
  // Query methods (require ContractProvider)
  // -------------------------------------------------------------------------

  /**
   * Query the current on-chain sequence number.
   *
   * @param provider - Injected by `open()`
   * @returns The current seqno
   * @throws TosNotDeployedError when the wallet is not deployed
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
    sendMode?: number,
  ): Cell {
    if (messages.length < 1 || messages.length > MAX_MESSAGES) {
      throw new Error(
        `WalletV3R2: expected 1-${MAX_MESSAGES} messages, got ${messages.length}`,
      );
    }

    const until = resolveValidUntil(validUntil, "WalletV3R2");
    const builder = beginCell()
      .storeInt(this.networkGlobalId, 32)
      .storeUint(this.walletId, 32)
      .storeUint(until, 32)
      .storeUint(seqno, 32);

    storeOutMessages(messages, builder, sendMode);

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
      args.sendMode,
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
      args.sendMode,
    );

    const signature = await args.signer(signingMessage.hash());

    return beginCell()
      .storeBuffer(signature)
      .storeSlice(signingMessage.beginParse())
      .endCell();
  }

  /**
   * Query seqno and balance, build, sign, and submit a transfer in one call.
   *
   * Refuses before signing when the wallet is not deployed
   * (`TosNotDeployedError`), when the values sent are not below the balance
   * (`INSUFFICIENT_BALANCE`; fees come out of the balance too), or when
   * `validUntil` is not in the future. The result only says the node accepted
   * the message: pass it to `waitForTransfer` to learn whether the transfer was
   * delivered. Messages go out with the ignore-errors flag by default, so one
   * the wallet cannot pay is skipped on chain while the seqno still advances.
   *
   * @param provider - Injected by `open()`
   * @param via - Signer (e.g., KeyPairSigner)
   * @param args - Transfer arguments (messages, validUntil)
   * @returns The message hash and the number of outgoing messages to expect
   *
   * @example
   * ```typescript
   * const sent = await wallet.sendTransfer(signer, {
   *   messages: [{ to: addr, value: toNano("1.5"), body: comment("Hello") }],
   * });
   * await waitForTransfer(client, wallet.address, sent);
   * ```
   */
  async sendTransfer(
    provider: ContractProvider,
    via: Signer,
    args: SendTransferArgs,
  ): Promise<PendingTransfer> {
    const seqno = await this.getSeqno(provider);
    const state = await provider.getState();
    requireAffordable(args.messages, state.balance, args.sendMode, "WalletV3R2");
    const signingMessage = this.buildSigningMessage(
      seqno,
      args.messages,
      args.validUntil,
      args.sendMode,
    );

    const signature = await via.sign(signingMessage.hash());

    const body = beginCell()
      .storeBuffer(signature)
      .storeSlice(signingMessage.beginParse())
      .endCell();

    const { hash } = await provider.external(body);
    return { hash, outMessages: args.messages.length };
  }

  /**
   * Deploy this wallet contract on-chain via an external message.
   *
   * @param provider - Injected by `open()`
   * @param via - Signer
   * @param _value - Unused (kept for interface compatibility)
   * @returns The external message hash, with no outgoing messages expected;
   *   confirm with `waitForTransfer`
   */
  async sendDeploy(
    provider: ContractProvider,
    via: Signer,
    _value: bigint,
  ): Promise<PendingTransfer> {
    // For external deploy: send an external message with seqno=0
    // For deploy, the signing message is just the header with no outgoing messages
    const deployMessage = beginCell()
      .storeInt(this.networkGlobalId, 32)
      .storeUint(this.walletId, 32)
      .storeUint(0xFFFFFFFF, 32) // validUntil = max (for initial deploy)
      .storeUint(0, 32)          // seqno = 0
      .endCell();

    const signature = await via.sign(deployMessage.hash());

    const body = beginCell()
      .storeBuffer(signature)
      .storeSlice(deployMessage.beginParse())
      .endCell();

    const { hash } = await provider.external(body);
    return { hash, outMessages: 0 };
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
