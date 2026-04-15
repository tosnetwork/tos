/**
 * Wallet V5 revision 1 (W5) implementation.
 *
 * V5 is a next-generation wallet with a fundamentally different auth
 * structure compared to V3/V4. Key differences:
 *
 * - Supports both external and internal message authentication
 * - Uses an extensions dictionary for delegate contracts
 * - Actions-based transfer system (action list as a linked list of cells)
 * - The walletId encodes network global ID, workchain, version, and
 *   subwallet number rather than a simple integer
 *
 * External signing message format:
 *   opcode:uint32  walletId:uint32  validUntil:uint32  seqno:uint32
 *   inner_request:(Maybe ^OutList, has_extended_actions=false)
 *
 * External message body:
 *   signingMessage  signature:bits512
 *
 * Initial data layout:
 *   isSignatureAllowed:bool  seqno:uint32  walletId:uint32
 *   publicKey:bits256  extensions:dict(empty)
 *
 * Action list cell format (linked list):
 *   Each action: opcode:uint32  sendMode:uint8  outMessage:^Cell
 *   Actions chain via refs: action -> next_action -> ... -> empty_cell
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
import { WALLET_V5R1_CODE } from "./codes.js";
import type {
  Wallet,
  OutMessage,
  CreateTransferArgs,
  CreateTransferAsyncArgs,
  SendTransferArgs,
} from "./types.js";
import { createInternalMessage, defaultValidUntil } from "./utils.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * V5 wallet ID is composed of:
 *   networkGlobalId (int32) | workchain (int8) | walletVersion (uint8) | subwalletNumber (uint32)
 *
 * For TOS mainnet (globalId = -239), workchain 0, version 0, subwallet 0:
 *   walletId = 2147483409 (computed from the encoded fields)
 *
 * We use a simplified numeric walletId for consistency.
 */
const DEFAULT_NETWORK_GLOBAL_ID = -239;
// DEFAULT_WALLET_VERSION removed — TOS V5 uses plain subwallet_id, not packed context
const DEFAULT_SUBWALLET_NUMBER = 0;

/** Action opcode for sending a message */
const ACTION_SEND_MSG = 0x0ec3c86d;
/** External signed request opcode */
const AUTH_SIGNED_EXTERNAL = 0x7369676e;

/** Maximum number of outgoing messages per transfer */
const MAX_MESSAGES = 255;

// ---------------------------------------------------------------------------
// V5 Wallet ID encoding
// ---------------------------------------------------------------------------

/**
 * Default wallet ID (subwallet number) for V5.
 *
 * The TOS V5 contract stores wallet_id as a plain uint32 subwallet number.
 * The global_id (network anti-replay) is a separate field in the signed message,
 * checked against the on-chain GLOBALID TVM primitive.
 */

// ---------------------------------------------------------------------------
// Action list builder
// ---------------------------------------------------------------------------

/**
 * Build an action list cell from outgoing messages.
 *
 * Actions are stored as a linked list of cells:
 *   action_cell = action_send_msg opcode:uint32, mode:uint8, out_msg:^Cell, prev:^Cell
 * The chain terminates with an empty cell.
 */
function buildActionList(messages: OutMessage[]): Cell {
  return messages.reduce(
    (actions, msg) => beginCell()
      .storeRef(actions)
      .storeUint(ACTION_SEND_MSG, 32)
      .storeUint(msg.mode ?? 3, 8)
      .storeRef(createInternalMessage(msg))
      .endCell(),
    beginCell().endCell(),
  );
}

// ---------------------------------------------------------------------------
// WalletV5R1
// ---------------------------------------------------------------------------

/**
 * Wallet V5 revision 1 (W5) -- next-generation wallet with advanced features.
 *
 * V5 supports both external and internal message authentication, an extensions
 * dictionary for delegate contracts, and an actions-based transfer system
 * that allows up to 255 outgoing messages per transaction.
 *
 * @example
 * ```typescript
 * import { WalletV5R1 } from "@tos/wallets";
 *
 * const wallet = WalletV5R1.create({ publicKey: keys.publicKey });
 * console.log(wallet.address.toString());
 * ```
 */
export class WalletV5R1 implements Wallet {
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
   * Create a new WalletV5R1 instance from a public key.
   *
   * Unlike V3/V4, V5 encodes network global ID, workchain, version,
   * and subwallet number into the wallet ID.
   *
   * @param args.publicKey - 32-byte Ed25519 public key
   * @param args.workchain - Workchain ID (default 0)
   * @param args.networkGlobalId - Network global ID (default -239 for TOS mainnet)
   * @param args.walletVersion - Wallet version (default 0)
   * @param args.subwalletNumber - Subwallet number (default 0)
   * @returns A new WalletV5R1 instance with computed address and init
   *
   * @example
   * ```typescript
   * const wallet = WalletV5R1.create({ publicKey: keys.publicKey });
   * ```
   */
  static create(args: {
    publicKey: Uint8Array;
    workchain?: number;
    networkGlobalId?: number;
    subwalletNumber?: number;
  }): WalletV5R1 {
    const workchain = args.workchain ?? 0;
    const networkGlobalId = args.networkGlobalId ?? DEFAULT_NETWORK_GLOBAL_ID;
    const walletId = args.subwalletNumber ?? DEFAULT_SUBWALLET_NUMBER;

    const code = Cell.fromBoc(hexToBytes(WALLET_V5R1_CODE))[0]!;

    // Initial data layout (matches TOS V5 contract):
    //   isSignatureAllowed:bool(1)  seqno:uint32(0)
    //   walletId:uint32  publicKey:bits256  extensions:dict(empty)
    const data = beginCell()
      .storeBit(true)                // isSignatureAllowed = true
      .storeUint(0, 32)             // seqno = 0
      .storeUint(walletId, 32)      // walletId (unsigned, plain subwallet number)
      .storeBuffer(args.publicKey)   // 256-bit public key
      .storeUint(0, 1)             // empty extensions dict
      .endCell();

    const init: StateInit = { code, data };
    const address = contractAddress(workchain, init);

    return new WalletV5R1(address, init, args.publicKey, walletId, networkGlobalId);
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
   * Build a signing message for an external auth transfer.
   *
   * TOS V5 signed message format:
   *   opcode:uint32  global_id:int32  wallet_id:uint32
   *   valid_until:uint32  seqno:uint32
   *   out_actions:(Maybe ^OutList)  has_extended_actions:Bool(false)
   *   (signature appended after this body)
   */
  private buildSigningMessage(
    seqno: number,
    messages: OutMessage[],
    validUntil?: number,
  ): Cell {
    if (messages.length < 1 || messages.length > MAX_MESSAGES) {
      throw new Error(
        `WalletV5R1: expected 1-${MAX_MESSAGES} messages, got ${messages.length}`,
      );
    }

    const until = validUntil ?? defaultValidUntil();
    const actionList = buildActionList(messages);

    return beginCell()
      .storeUint(AUTH_SIGNED_EXTERNAL, 32)
      .storeInt(this.networkGlobalId, 32)  // global_id (anti-replay, checked via GLOBALID TVM)
      .storeUint(this.walletId, 32)        // wallet_id (plain subwallet number, unsigned)
      .storeUint(until, 32)
      .storeUint(seqno, 32)
      .storeMaybeRef(actionList)
      .storeBit(false)
      .endCell();
  }

  /** Build and sign a transfer body cell synchronously. */
  createTransfer(args: CreateTransferArgs): Cell {
    const signingMessage = this.buildSigningMessage(
      args.seqno,
      args.messages,
      args.validUntil,
    );

    const signature = sign(signingMessage.hash(), args.secretKey);

    return beginCell()
      .storeSlice(signingMessage.beginParse())
      .storeBuffer(signature)
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
      .storeSlice(signingMessage.beginParse())
      .storeBuffer(signature)
      .endCell();
  }

  /** Query seqno, build, sign, and submit a transfer in one call. */
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
      .storeSlice(signingMessage.beginParse())
      .storeBuffer(signature)
      .endCell();

    return provider.external(body);
  }

  /** Deploy this wallet contract on-chain via an external message. */
  async sendDeploy(
    provider: ContractProvider,
    via: Signer,
    _value: bigint,
  ): Promise<void> {
    const deployMessage = beginCell()
      .storeUint(AUTH_SIGNED_EXTERNAL, 32)
      .storeInt(this.networkGlobalId, 32) // global_id
      .storeUint(this.walletId, 32)       // wallet_id (unsigned)
      .storeUint(0xFFFFFFFF, 32)          // validUntil = max
      .storeUint(0, 32)                   // seqno = 0
      .storeMaybeRef(null)                // no out actions
      .storeBit(false)                    // no extended actions
      .endCell();

    const signature = await via.sign(deployMessage.hash());

    const body = beginCell()
      .storeSlice(deployMessage.beginParse())
      .storeBuffer(signature)
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
