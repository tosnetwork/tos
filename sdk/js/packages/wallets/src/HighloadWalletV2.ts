/**
 * Highload Wallet V2 implementation.
 *
 * Highload V2 is designed for services that need to send many messages
 * in a single transaction (up to 254 per external message). Unlike
 * standard wallets that chain messages as refs, Highload V2 stores
 * them in a Dictionary keyed by uint16 indices.
 *
 * Signing message format:
 *   walletId:uint32  queryId:uint64  messages:dict(uint16 -> ^Cell)
 *
 * The queryId serves as replay protection instead of a sequential seqno.
 * It is typically composed of: (timestamp << 32) | seqno_counter
 *
 * External message body:
 *   signature:bits512  ^signingMessage
 *
 * Note: Unlike standard wallets, the signing message is stored as a ref
 * (not inline) in the external body.
 *
 * Initial data layout:
 *   walletId:uint32  lastCleaned:uint64  publicKey:bits256  oldQueries:dict(empty)
 */

import {
  Address,
  Cell,
  beginCell,
  contractAddress,
  Dictionary,
  hexToBytes,
  type StateInit,
} from "@tos/core";
import { sign } from "@tos/crypto";
import type {
  ContractProvider,
  Signer,
  SendConfirmation,
} from "@tos/client";
import { HIGHLOAD_V2_CODE } from "./codes.js";
import type {
  Wallet,
  OutMessage,
  CreateTransferArgs,
  CreateTransferAsyncArgs,
  SendTransferArgs,
} from "./types.js";
import { createInternalMessage } from "./utils.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default wallet ID base: 698983191 (0x29A9A317) */
const DEFAULT_WALLET_ID_BASE = 698983191;

/** Maximum number of outgoing messages per transaction */
const MAX_MESSAGES = 254;

// ---------------------------------------------------------------------------
// Query ID helpers
// ---------------------------------------------------------------------------

/**
 * Generate a query ID from a timestamp and a counter for Highload Wallet V2.
 *
 * The query ID is computed as `(timestamp << 32) | counter`, providing replay
 * protection. Each query ID must be unique within the contract's TTL window.
 *
 * @param timestamp - UNIX timestamp in seconds (default: current time)
 * @param counter - Counter value (default: 0)
 * @returns A unique 64-bit query ID as a bigint
 *
 * @example
 * ```typescript
 * const queryId = createQueryId();            // auto timestamp, counter=0
 * const queryId2 = createQueryId(undefined, 1); // auto timestamp, counter=1
 * ```
 */
export function createQueryId(timestamp?: number, counter?: number): bigint {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const ctr = counter ?? 0;
  return (BigInt(ts) << 32n) | BigInt(ctr);
}

// ---------------------------------------------------------------------------
// Message dictionary builder
// ---------------------------------------------------------------------------

/**
 * Build a Dictionary<uint16, Cell> from outgoing messages.
 *
 * Each entry in the dictionary maps an index (0..N-1) to a Cell
 * containing: mode:uint8 + internal_message:^Cell
 */
function buildMessageDict(messages: OutMessage[]): Dictionary<number, Cell> {
  const dict = Dictionary.empty<number, Cell>(
    Dictionary.Keys.Uint(16),
    Dictionary.Values.Cell(),
  );

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i]!;
    const mode = msg.mode ?? 3; // default send mode
    const internalMsg = createInternalMessage(msg);

    // Each dict value is: mode:uint8 + message:^Cell
    const entry = beginCell()
      .storeUint(mode, 8)
      .storeRef(internalMsg)
      .endCell();

    dict.set(i, entry);
  }

  return dict;
}

// ---------------------------------------------------------------------------
// HighloadWalletV2
// ---------------------------------------------------------------------------

/**
 * Highload Wallet V2 -- designed for services that need to send many messages
 * in a single transaction (up to 254 per external message).
 *
 * Uses query IDs instead of sequential seqno for replay protection, making it
 * ideal for payment processors and high-throughput applications.
 *
 * @example
 * ```typescript
 * import { HighloadWalletV2, createQueryId } from "@tos/wallets";
 *
 * const wallet = HighloadWalletV2.create({ publicKey: keys.publicKey });
 * const queryId = createQueryId(); // timestamp-based
 * ```
 */
export class HighloadWalletV2 implements Wallet {
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
   * Create a new HighloadWalletV2 instance from a public key.
   *
   * The wallet address is computed deterministically from the code cell
   * and initial data.
   */
  static create(args: {
    publicKey: Uint8Array;
    workchain?: number;
    walletId?: number;
  }): HighloadWalletV2 {
    const workchain = args.workchain ?? 0;
    const walletId = args.walletId ?? DEFAULT_WALLET_ID_BASE + workchain;

    const code = Cell.fromBoc(hexToBytes(HIGHLOAD_V2_CODE))[0]!;

    // Initial data: walletId:uint32 lastCleaned:uint64 publicKey:bits256 oldQueries:dict(empty)
    const data = beginCell()
      .storeUint(walletId, 32)       // wallet ID
      .storeUint(0, 64)             // lastCleaned = 0
      .storeBuffer(args.publicKey)   // 256-bit public key
      .storeUint(0, 1)             // empty oldQueries dict
      .endCell();

    const init: StateInit = { code, data };
    const address = contractAddress(workchain, init);

    return new HighloadWalletV2(address, init, args.publicKey, walletId);
  }

  // -------------------------------------------------------------------------
  // Query methods (require ContractProvider)
  // -------------------------------------------------------------------------

  /**
   * Highload V2 does not use a traditional seqno. This method returns 0
   * as the "seqno" since replay protection is based on query IDs.
   * For actual query ID tracking, use getProcessed().
   */
  async getSeqno(_provider: ContractProvider): Promise<number> {
    // Highload V2 uses queryId-based replay protection, not seqno.
    // Return 0 to satisfy the Wallet interface.
    return 0;
  }

  async getBalance(provider: ContractProvider): Promise<bigint> {
    const state = await provider.getState();
    return state.balance;
  }

  async getPublicKey(provider: ContractProvider): Promise<Uint8Array> {
    const result = await provider.get("get_public_key", []);
    const keyBigInt = result.stack.readBigNumber();
    return bigIntToBytes(keyBigInt, 32);
  }

  // -------------------------------------------------------------------------
  // Transfer building
  // -------------------------------------------------------------------------

  /**
   * Build the signing message for a highload transfer.
   *
   * Format: walletId:uint32 queryId:uint64 messages:dict(uint16->Cell)
   *
   * @param queryId - Unique query identifier for replay protection.
   * @param messages - Up to 254 outgoing messages.
   */
  private buildSigningMessage(
    queryId: bigint,
    messages: OutMessage[],
  ): Cell {
    if (messages.length < 1 || messages.length > MAX_MESSAGES) {
      throw new Error(
        `HighloadWalletV2: expected 1-${MAX_MESSAGES} messages, got ${messages.length}`,
      );
    }

    const msgDict = buildMessageDict(messages);

    return beginCell()
      .storeUint(this.walletId, 32)
      .storeUint(queryId, 64)
      .storeDict(msgDict)
      .endCell();
  }

  /**
   * Create a transfer body cell.
   *
   * For Highload V2, the `seqno` field from CreateTransferArgs is used
   * as the counter component of the query ID. The timestamp component
   * is derived from validUntil or the current time.
   */
  createTransfer(args: CreateTransferArgs): Cell {
    const timestamp = args.validUntil
      ? args.validUntil - 60
      : Math.floor(Date.now() / 1000);
    const queryId = createQueryId(timestamp, args.seqno);

    const signingMessage = this.buildSigningMessage(
      queryId,
      args.messages,
    );

    const signature = sign(signingMessage.hash(), args.secretKey);

    // Highload V2: signature inline + signing message as ref
    return beginCell()
      .storeBuffer(signature)
      .storeRef(signingMessage)
      .endCell();
  }

  async createTransferAsync(args: CreateTransferAsyncArgs): Promise<Cell> {
    const timestamp = args.validUntil
      ? args.validUntil - 60
      : Math.floor(Date.now() / 1000);
    const queryId = createQueryId(timestamp, args.seqno);

    const signingMessage = this.buildSigningMessage(
      queryId,
      args.messages,
    );

    const signature = await args.signer(signingMessage.hash());

    return beginCell()
      .storeBuffer(signature)
      .storeRef(signingMessage)
      .endCell();
  }

  async sendTransfer(
    provider: ContractProvider,
    via: Signer,
    args: SendTransferArgs,
  ): Promise<SendConfirmation> {
    const timestamp = args.validUntil
      ? args.validUntil - 60
      : Math.floor(Date.now() / 1000);
    // Use timestamp-based query ID with counter=0
    const queryId = createQueryId(timestamp, 0);

    const signingMessage = this.buildSigningMessage(
      queryId,
      args.messages,
    );

    const signature = await via.sign(signingMessage.hash());

    const body = beginCell()
      .storeBuffer(signature)
      .storeRef(signingMessage)
      .endCell();

    return provider.external(body) as unknown as SendConfirmation;
  }

  async sendDeploy(
    provider: ContractProvider,
    via: Signer,
    _value: bigint,
  ): Promise<void> {
    // Deploy with a minimal message (empty dict would fail, so we use
    // a deploy-only external message with queryId=0)
    const emptyDict = Dictionary.empty<number, Cell>(
      Dictionary.Keys.Uint(16),
      Dictionary.Values.Cell(),
    );

    const deployMessage = beginCell()
      .storeUint(this.walletId, 32)
      .storeUint(0n, 64) // queryId = 0
      .storeDict(emptyDict)
      .endCell();

    const signature = await via.sign(deployMessage.hash());

    const body = beginCell()
      .storeBuffer(signature)
      .storeRef(deployMessage)
      .endCell();

    await provider.external(body);
  }

  // -------------------------------------------------------------------------
  // Highload-specific methods
  // -------------------------------------------------------------------------

  /**
   * Create a transfer with an explicit query ID.
   *
   * This is the preferred method for Highload V2 as it gives full
   * control over the query ID for replay protection.
   */
  createTransferWithQueryId(args: {
    queryId: bigint;
    messages: OutMessage[];
    secretKey: Uint8Array;
  }): Cell {
    const signingMessage = this.buildSigningMessage(
      args.queryId,
      args.messages,
    );

    const signature = sign(signingMessage.hash(), args.secretKey);

    return beginCell()
      .storeBuffer(signature)
      .storeRef(signingMessage)
      .endCell();
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
