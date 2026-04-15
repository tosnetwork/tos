/**
 * Wallet V4 revision 2 implementation.
 *
 * V4R2 extends V3R2 with plugin support. The key difference in the
 * signing message is an additional `op:uint8` field after the seqno.
 *
 * Signing message format (simple transfer, op=0):
 *   walletId:uint32  validUntil:uint32  seqno:uint32  op:uint8(0)
 *   [mode:uint8 message:^Cell]*
 *
 * External message body:
 *   signature:bits512  signingMessage
 *
 * Initial data layout:
 *   seqno:uint32  walletId:uint32  publicKey:bits256  plugins:bit(0)
 *
 * Plugin operations:
 *   op=1: deploy and install plugin
 *   op=2: install plugin
 *   op=3: remove plugin
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
import { WALLET_V4R2_CODE } from "./codes.js";
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

/** Simple transfer opcode */
const OP_SIMPLE_TRANSFER = 0;

// ---------------------------------------------------------------------------
// WalletV4R2
// ---------------------------------------------------------------------------

/**
 * Wallet V4 revision 2 -- extends V3R2 with plugin support.
 *
 * The default and recommended wallet for most TOS users. Supports up to 4
 * outgoing messages per transaction, replay protection via seqno, and an
 * extensible plugin architecture.
 *
 * @example
 * ```typescript
 * import { WalletV4R2 } from "@tos/wallets";
 * import { mnemonicToPrivateKey } from "@tos/crypto";
 * import { TosClient, open } from "@tos/client";
 *
 * const keys = await mnemonicToPrivateKey(mnemonic);
 * const wallet = WalletV4R2.create({ publicKey: keys.publicKey });
 *
 * const client = new TosClient({ endpoint: "http://localhost:8081" });
 * const opened = open(wallet, client);
 * const balance = await opened.getBalance();
 * ```
 */
export class WalletV4R2 implements Wallet {
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
   * Create a new WalletV4R2 instance from a public key.
   *
   * The wallet address is computed deterministically from the code cell
   * and initial data (seqno=0, walletId, publicKey, empty plugins dict).
   *
   * @param args.publicKey - 32-byte Ed25519 public key
   * @param args.workchain - Workchain ID (default 0)
   * @param args.walletId - Custom wallet ID (default auto-computed)
   * @returns A new WalletV4R2 instance with computed address and init
   *
   * @example
   * ```typescript
   * const wallet = WalletV4R2.create({ publicKey: keys.publicKey });
   * console.log(wallet.address.toString());
   * ```
   */
  static create(args: {
    publicKey: Uint8Array;
    workchain?: number;
    walletId?: number;
  }): WalletV4R2 {
    const workchain = args.workchain ?? 0;
    const walletId = args.walletId ?? DEFAULT_WALLET_ID_BASE + workchain;

    const code = Cell.fromBoc(hexToBytes(WALLET_V4R2_CODE))[0]!;

    // Initial data: seqno(0):uint32 walletId:uint32 publicKey:bits256 plugins:bit(0)
    const data = beginCell()
      .storeUint(0, 32)              // seqno = 0
      .storeUint(walletId, 32)       // wallet ID
      .storeBuffer(args.publicKey)    // 256-bit public key
      .storeUint(0, 1)              // empty plugins dict
      .endCell();

    const init: StateInit = { code, data };
    const address = contractAddress(workchain, init);

    return new WalletV4R2(address, init, args.publicKey, walletId);
  }

  // -------------------------------------------------------------------------
  // Query methods (require ContractProvider)
  // -------------------------------------------------------------------------

  /** Query the current on-chain sequence number. */
  async getSeqno(provider: ContractProvider): Promise<number> {
    const result = await provider.get("seqno", []);
    return result.stack.readNumber();
  }

  /** Query the on-chain balance in nanoTOS. */
  async getBalance(provider: ContractProvider): Promise<bigint> {
    const state = await provider.getState();
    return state.balance;
  }

  /** Query the on-chain public key (32 bytes). */
  async getPublicKey(provider: ContractProvider): Promise<Uint8Array> {
    const result = await provider.get("get_public_key", []);
    const keyBigInt = result.stack.readBigNumber();
    return bigIntToBytes(keyBigInt, 32);
  }

  // -------------------------------------------------------------------------
  // Transfer building
  // -------------------------------------------------------------------------

  /**
   * Build a signing message for a simple transfer (op=0).
   */
  private buildSigningMessage(
    seqno: number,
    messages: CreateTransferArgs["messages"],
    validUntil?: number,
  ): Cell {
    if (messages.length < 1 || messages.length > MAX_MESSAGES) {
      throw new Error(
        `WalletV4R2: expected 1-${MAX_MESSAGES} messages, got ${messages.length}`,
      );
    }

    const until = validUntil ?? defaultValidUntil();
    const builder = beginCell()
      .storeUint(this.walletId, 32)
      .storeUint(until, 32)
      .storeUint(seqno, 32)
      .storeUint(OP_SIMPLE_TRANSFER, 8); // op = 0 for simple transfer

    storeOutMessages(messages, builder);

    return builder.endCell();
  }

  /**
   * Build and sign a transfer body cell synchronously.
   *
   * @param args - Transfer arguments including seqno, messages, and secretKey
   * @returns The signed external message body cell
   */
  createTransfer(args: CreateTransferArgs): Cell {
    const signingMessage = this.buildSigningMessage(
      args.seqno,
      args.messages,
      args.validUntil,
    );

    const signature = sign(signingMessage.hash(), args.secretKey);

    return beginCell()
      .storeBuffer(signature)
      .storeSlice(signingMessage.beginParse())
      .endCell();
  }

  /** Build and sign a transfer body cell asynchronously. */
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

    return provider.external(body);
  }

  /** Deploy this wallet contract on-chain via an external message. */
  async sendDeploy(
    provider: ContractProvider,
    via: Signer,
    _value: bigint,
  ): Promise<void> {
    // Deploy message: seqno=0 with validUntil=0xFFFFFFFF
    const deployMessage = beginCell()
      .storeUint(this.walletId, 32)
      .storeUint(0xFFFFFFFF, 32) // validUntil = max for initial deploy
      .storeUint(0, 32)          // seqno = 0
      .storeUint(OP_SIMPLE_TRANSFER, 8) // op = 0
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

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
  return bytes;
}
