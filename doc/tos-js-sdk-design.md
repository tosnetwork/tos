# TOS JS SDK Design

Version: v0.4-draft

## Purpose

Design document for `@tos/sdk` — the official TypeScript SDK for TOS Blockchain.

This SDK should be the primary interface for DApp developers, wallet builders, and tooling authors working with TOS from JavaScript/TypeScript environments.

## Design Principles

1. **Layered architecture** — each layer is independently useful; higher layers depend on lower layers, never the reverse.
2. **Familiar to Ethereum developers** — borrow conventions from ethers.js / viem where they apply (provider/signer separation, human-readable units, typed contracts).
3. **One correct way** — avoid the TON ecosystem problem of multiple incompatible SDKs. This is the canonical SDK.
4. **TypeScript-first** — full type safety, no `any` escapes, discriminated unions for on-chain types.
5. **Tree-shakeable** — ESM modules, no global state, no side effects on import.
6. **Isomorphic** — works in Node.js, browsers, and React Native without polyfill gymnastics.
7. **Zero guesswork** — structured errors, explicit failure modes, no silent fallbacks.
8. **Complete RPC coverage** — every C++ JSON-RPC method has a typed SDK method. No gaps.

## Reference Analysis

### What to adopt

| Source | What | Why |
|--------|------|-----|
| `@ton/core` | Cell/Slice/Builder fluent API, Address type | Proven, ergonomic, battle-tested |
| `@ton/core` | `Contract` + `ContractProvider` interface | Clean abstraction boundary between contract logic and transport |
| `@ton/crypto` | Mnemonic, HD key derivation, Ed25519 API surface | TON-compatible key derivation is required |
| ethers.js v6 | Provider/Signer separation | DApp developers expect this pattern |
| ethers.js v6 | `waitForTransaction()` pattern | Essential for DApp UX |
| viem | publicClient / walletClient separation | Cleaner than monolithic provider |
| viem | Standalone `readContract()` / `writeContract()` | Functional, tree-shakeable |

### What to avoid

| Source | Problem | Our approach |
|--------|---------|--------------|
| tonweb | God object (`TonWeb` class holds everything) | Decomposed modules, no god object |
| tonweb | Dual APIs (`call()` vs `call2()`) | One API, one return shape |
| tonweb | Hardcoded wallet code as base64 strings | Load from compiled artifacts or registry |
| tonweb | JavaScript-only, JSDoc types | TypeScript source, compiled to JS+DTS |
| `@ton/ton` | Tight coupling between contract wrappers and RPC | Contract wrappers are pure; transport is injected |
| `@ton/core` | `Object.freeze()` on everything | Prefer `readonly` types; freezing has runtime cost |
| ethers.js | Monolithic provider (all methods on one object) | Categorized action groups, inspired by viem |

## Package Structure

```
~/tos/sdk/js/
├── packages/
│   ├── core/              # @tos/core — Cell, Address, BOC, Slice, Builder
│   ├── crypto/            # @tos/crypto — Ed25519, Mnemonic, HD keys
│   ├── client/            # @tos/client — JSON-RPC client, Provider
│   ├── wallets/           # @tos/wallets — Wallet contract V3/V4/V5
│   ├── contracts/         # @tos/contracts — Jetton, NFT, DEX wrappers
│   └── sdk/               # @tos/sdk — Umbrella re-export package
├── tsconfig.json
├── package.json           # Workspace root (pnpm)
└── README.md
```

Monorepo workspace using pnpm workspaces. Each package is independently publishable to npm.

## Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4: Application Contracts                         │
│  @tos/contracts                                         │
│  Jetton, NFT, DEX, Governance, Staking wrappers         │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Wallet Contracts                              │
│  @tos/wallets                                           │
│  WalletV3, WalletV4, WalletV5, HighloadWallet           │
│  Transaction building, signing, multi-transfer           │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Client / Provider                             │
│  @tos/client                                            │
│  TosClient (JSON-RPC), TosProvider (abstract),           │
│  Account capability, contract execution                  │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Core Types                                    │
│  @tos/core          @tos/crypto                         │
│  Address, Cell,      Ed25519, Mnemonic,                  │
│  Slice, Builder,     HD derivation,                      │
│  BOC, Dictionary     KeyPair, sign/verify                │
└─────────────────────────────────────────────────────────┘
```

### Dependency rules

- `@tos/core` depends on nothing (except `@tos/crypto` as peer dependency for hashing)
- `@tos/crypto` depends on nothing (pure crypto primitives)
- `@tos/client` depends on `@tos/core`
- `@tos/wallets` depends on `@tos/core`, `@tos/crypto`, `@tos/client`
- `@tos/contracts` depends on `@tos/core`, `@tos/client`
- `@tos/sdk` re-exports all of the above

---

## Layer 1: @tos/core

### Address

```typescript
class Address {
  static parse(source: string): Address;       // auto-detect format
  static parseRaw(source: string): Address;    // "workchain:hex"
  static parseFriendly(source: string): Address; // base64 friendly
  static isValid(source: string): boolean;

  readonly workchain: number;
  readonly hash: Uint8Array; // 32 bytes

  toString(params?: { bounceable?: boolean; testOnly?: boolean }): string;
  toRawString(): string;
  equals(other: Address): boolean;
}
```

### Address Utilities

Aligned with C++ RPC: `detectAddress`, `packAddress`, `unpackAddress`.

```typescript
// Pure functions — no RPC needed, usable offline
function packAddress(address: string): string;      // raw -> friendly
function unpackAddress(address: string): string;     // friendly -> raw
function detectAddress(address: string): AddressInfo;

interface AddressInfo {
  raw_form: string;                                  // "0:abc...def"
  bounceable: { b64: string; b64url: string };
  non_bounceable: { b64: string; b64url: string };   // C++ uses snake_case
  given_type: string;                                 // "friendly_bounceable" | "friendly_non_bounceable" | "raw"
  test_only: boolean;
}
```

### Cell / Builder / Slice

Follow the proven `@ton/core` pattern — fluent builder, cursor-based slice.

Cell constraints: max 1023 bits, max 4 refs.

```typescript
// ── Builder (fluent, chainable) ──────────────────────────
const cell = beginCell()
  .storeUint(0x12345678, 32)     // unsigned int, N bits
  .storeInt(-42, 64)             // signed int, N bits
  .storeBit(true)                // single bit
  .storeBits(boolArray)          // multiple bits
  .storeCoins(toNano("1.5"))     // VarUInteger 16 (nano amounts)
  .storeAddress(address)         // MsgAddressInt (267 bits) or null (2 bits)
  .storeRef(childCell)           // cell reference (max 4)
  .storeMaybeRef(optionalCell)   // 1-bit flag + optional ref
  .storeStringTail("hello")     // snake-format string across cells
  .storeStringRefTail("long")   // string in ref chain
  .storeBuffer(uint8Array)       // raw bytes
  .storeBuilder(otherBuilder)    // append another builder
  .storeDict(dict)               // dictionary as cell
  .storeSlice(someSlice)         // copy bits from slice
  .endCell();                    // finalize -> Cell

// Builder query methods
builder.remainingBits;           // bits left (1023 - used)
builder.remainingRefs;           // refs left (4 - used)

// ── Slice (cursor-based parsing) ─────────────────────────
const slice = cell.beginParse();
const opcode = slice.loadUint(32);
const value = slice.loadInt(64);
const flag = slice.loadBit();
const amount = slice.loadCoins();
const addr = slice.loadAddress();
const addrOrNull = slice.loadMaybeAddress();
const child = slice.loadRef();
const childSlice = slice.loadRef().beginParse();
const text = slice.loadStringTail();
const maybe = slice.loadMaybeRef();
const buf = slice.loadBuffer(32);  // read N bytes
const dict = slice.loadDict(keyLen, keyType, valueType);
slice.skip(10);                    // skip N bits
slice.endParse();                  // throws if unconsumed bits remain

// Slice query methods (non-consuming)
slice.remainingBits;
slice.remainingRefs;
slice.preloadUint(32);             // peek without advancing cursor
slice.preloadRef();
```

### ExternalAddress

Required for some contract interactions (external message destinations):

```typescript
class ExternalAddress {
  static create(value: bigint, bits: number): ExternalAddress;
  readonly value: bigint;
  readonly bits: number;
}
```

### Cell Properties

```typescript
class Cell {
  // Serialization
  toBoc(opts?: { idx?: boolean; crc32?: boolean }): Uint8Array;
  toBase64(): string;
  static fromBoc(data: Uint8Array): Cell[];
  static fromBase64(b64: string): Cell;

  // Hash (SHA-256 of cell representation)
  hash(level?: number): Uint8Array;   // 32-byte hash

  // Parse
  beginParse(): Slice;

  // Inspect
  readonly bits: BitString;
  readonly refs: readonly Cell[];
  readonly type: CellType;       // ordinary, prunedBranch, merkleProof, merkleUpdate
  readonly isExotic: boolean;

  equals(other: Cell): boolean;
}
```

### Comment Encoding Helper

The most common DApp pattern — text comments on transfers:

```typescript
// Build a simple text comment body (op=0 + UTF-8 string)
function comment(text: string): Cell;

// Usage:
await wallet.sendTransfer(signer, {
  messages: [{ to: dest, value: toNano("1"), body: comment("Payment for invoice #123") }],
});
```

### BOC Serialization

```typescript
// Cell <-> binary
const boc: Uint8Array = cell.toBoc();
const cells: Cell[] = Cell.fromBoc(boc);

// Cell <-> base64 (convenience for RPC interaction)
const b64: string = cell.toBase64();
const cell = Cell.fromBase64(b64);
```

### Dictionary

```typescript
const dict = Dictionary.empty<Address, bigint>(
  Dictionary.Keys.Address(),
  Dictionary.Values.BigInt(64),
);
dict.set(address, 100n);
const val = dict.get(address);
```

### Tuple (TVM Stack)

```typescript
// For runGetMethod stack serialization — matches C++ stack entry types
type TupleItem =
  | { type: "int"; value: bigint }
  | { type: "cell"; cell: Cell }
  | { type: "slice"; cell: Cell }
  | { type: "tuple"; items: TupleItem[] }
  | { type: "null" };

class TupleReader {
  readBigNumber(): bigint;
  readNumber(): number;
  readAddress(): Address;
  readCell(): Cell;
  readCellOpt(): Cell | null;
  readBoolean(): boolean;
  readTuple(): TupleReader;
  remaining: number;
}
```

### Contract Address Derivation

Deterministic address from code + data (no RPC needed):

```typescript
function contractAddress(workchain: number, init: StateInit): Address;

// Usage: compute address before deployment
const addr = contractAddress(0, { code: walletCode, data: initialData });
```

### Unit Conversion

```typescript
function toNano(amount: string | number): bigint;   // "1.5" -> 1500000000n
function fromNano(amount: bigint): string;           // 1500000000n -> "1.5"
```

### Encoding Utilities

```typescript
// Base64 <-> Uint8Array (isomorphic, no Buffer dependency)
function base64ToBytes(b64: string): Uint8Array;
function bytesToBase64(bytes: Uint8Array): string;

// Hex <-> Uint8Array
function hexToBytes(hex: string): Uint8Array;
function bytesToHex(bytes: Uint8Array): string;

// Base64url variants
function base64UrlToBytes(b64url: string): Uint8Array;
function bytesToBase64Url(bytes: Uint8Array): string;
```

### Hash Utilities

```typescript
function detectHash(hash: string): HashInfo;

// Matches C++ ext.utils.detectedHash response
interface HashInfo {
  b64: string;       // standard base64
  b64url: string;    // url-safe base64
  hex: string;       // lowercase hex
}
```

---

## Layer 1: @tos/crypto

### Key Management

```typescript
// Mnemonic
function mnemonicGenerate(wordCount?: 24 | 12): Promise<string[]>;
function mnemonicValidate(mnemonic: string[]): Promise<boolean>;
function mnemonicToPrivateKey(mnemonic: string[]): Promise<KeyPair>;

// KeyPair
interface KeyPair {
  publicKey: Uint8Array;   // 32 bytes
  secretKey: Uint8Array;   // 64 bytes
}

// From seed
function keyPairFromSeed(seed: Uint8Array): KeyPair;
function keyPairFromSecretKey(secretKey: Uint8Array): KeyPair;

// Signing
function sign(data: Uint8Array, secretKey: Uint8Array): Uint8Array;
function signVerify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;

// Hashing
function sha256(data: Uint8Array): Promise<Uint8Array>;
function sha512(data: Uint8Array): Promise<Uint8Array>;

// HD derivation
function mnemonicToHDSeed(mnemonic: string[]): Promise<Uint8Array>;
function deriveEd25519Path(seed: Uint8Array, path: number[]): KeyPair;
```

---

## Layer 2: @tos/client

The client layer connects to TOS JSON-RPC nodes.

### Design: Categorized Actions (viem-inspired)

Methods are organized by domain. Each domain is a separate TypeScript interface.
`TosProvider` is the union of all domains — `TosClient` implements the full interface,
but consumers can accept narrower types (e.g., a function that only needs `AccountActions`).

```typescript
// Domain sub-interfaces — enable partial dependency and tree-shaking
interface AccountActions { /* account methods */ }
interface BlockActions { /* block methods */ }
interface TransactionActions { /* tx methods */ }
interface SendActions { /* send/submit methods */ }
interface ContractActions { /* runGetMethod */ }
interface ConfigActions { /* config methods */ }
interface PermissionActions { /* TOS-native capability/delegation */ }
interface IntentActions { /* TOS-native intent/signing/submit */ }

// Full provider = union of all domains
interface TosProvider extends
  AccountActions, BlockActions, TransactionActions,
  SendActions, ContractActions, ConfigActions,
  PermissionActions, IntentActions { /* + convenience methods */ }
```

### TosProvider — Full RPC Interface

All 42 C++ JSON-RPC methods are covered. Grouped by domain:

```typescript
interface TosProvider {

  // ── Account ───────────────────────────────────────────────
  // All account methods accept optional `seqno` to query at a specific masterchain block.
  getAddressInformation(address: Address, opts?: { seqno?: number }): Promise<AccountInfo>;
  getExtendedAddressInformation(address: Address, opts?: { seqno?: number }): Promise<ExtendedAccountInfo>;
  getWalletInformation(address: Address, opts?: { seqno?: number }): Promise<WalletInfo>;
  getBalance(address: Address, opts?: { seqno?: number }): Promise<bigint>;  // C++ returns string; SDK parses to bigint
  getState(address: Address, opts?: { seqno?: number }): Promise<"active" | "frozen" | "uninitialized">;

  // ── Account Permission (TOS-native) ──────────────────────
  getAccountCapability(address: Address, opts?: {
    seqno?: number;
    include_experimental?: boolean;  // C++ param: include_experimental
  }): Promise<AccountCapability>;
  getAccountDelegations(address: Address, opts?: {
    include_inactive?: boolean;
    status?: "active" | "expired" | "revoked";
  }): Promise<DelegationGrant[]>;
  getAccountSessions(address: Address, opts?: {
    include_inactive?: boolean;
    status?: string;
  }): Promise<SessionCapability[]>;
  getAccountAgents(address: Address, opts?: {
    include_inactive?: boolean;
    status?: string;
  }): Promise<AgentCapability[]>;

  // ── Blocks ────────────────────────────────────────────────
  getMasterchainInfo(): Promise<MasterchainInfo>;
  getConsensusBlock(): Promise<ConsensusBlock>;
  lookupBlock(workchain: number, shard: string, opts: {   // C++ shard is string
    seqno?: number;   // lookup by seqno
    lt?: string;      // OR by logical time
    unixtime?: number; // OR by unix time
  }): Promise<BlockIdExt>;
  getBlockHeader(workchain: number, shard: string, seqno: number): Promise<BlockHeader>;
  getShards(seqno?: number): Promise<ShardInfo[]>;  // C++ seqno is optional
  getMasterchainBlockSignatures(seqno: number): Promise<BlockSignatures>;
  getShardBlockProof(workchain: number, shard: string, seqno: number): Promise<ShardBlockProof>;

  // ── Transactions ──────────────────────────────────────────
  getTransactions(address: Address, opts?: {
    limit?: number;    // default 10, max 100
    lt?: string;       // must pair with hash
    hash?: string;     // must pair with lt (base64)
  }): Promise<Transaction[]>;
  getBlockTransactions(workchain: number, shard: string, seqno: number, opts?: {
    count?: number;    // default 40, max 256
    after_lt?: string;
    after_hash?: string;
  }): Promise<ShortTransaction[]>;
  getBlockTransactionsExt(workchain: number, shard: string, seqno: number, opts?: {
    count?: number;
    after_lt?: string;
    after_hash?: string;
  }): Promise<Transaction[]>;
  tryLocateTx(source: Address, destination: Address, created_lt: string): Promise<LocateResult>;
  tryLocateResultTx(source: Address, destination: Address, created_lt: string): Promise<LocateResult>;
  tryLocateSourceTx(source: Address, destination: Address, created_lt: string): Promise<LocateResult>;

  // ── Smart Contract Execution ──────────────────────────────
  runGetMethod(address: Address, method: string, opts?: {
    stack?: TupleItem[];
    seqno?: number;    // query at specific block
  }): Promise<RunResult>;

  // ── Send ──────────────────────────────────────────────────
  sendBoc(boc: Uint8Array): Promise<{ status: number }>;
  sendBocReturnHash(boc: Uint8Array): Promise<{ status: number; hash: string }>;
  sendQuery(address: Address, body: Cell, opts?: {  // used internally by wallets; exposed for deploy
    initCode?: Cell;
    initData?: Cell;
  }): Promise<{ hash: string }>;
  estimateFee(address: Address, body: Cell, opts?: {
    initCode?: Cell;
    initData?: Cell;
    ignoreChksig?: boolean;  // C++ param: ignore_chksig, default true
  }): Promise<FeeEstimate>;

  // ── Transaction Intent (TOS-native) ───────────────────────
  buildTransactionIntent(args: TransactionIntentRequest): Promise<TransactionIntent>;
  getSigningPayload(args: SigningPayloadRequest): Promise<SigningPayload>;
  submitSignedTransaction(args: SubmitSignedRequest): Promise<SubmissionResult>;

  // ── Config ────────────────────────────────────────────────
  getConfigParam(param: number, opts?: { seqno?: number }): Promise<Cell>;  // C++ param name is "param"
  getConfigAll(opts?: { seqno?: number }): Promise<ConfigAll>;

  // ── Libraries ─────────────────────────────────────────────
  getLibraries(libraryList: string[]): Promise<LibraryEntry[]>;  // C++ param: library_list

  // ── Token Data ────────────────────────────────────────────
  getTokenData(address: Address, opts?: { seqno?: number }): Promise<TokenData>;

  // ── Network ───────────────────────────────────────────────
  getOutMsgQueueSize(): Promise<OutMsgQueueSize>;
  isReady(): Promise<ReadyzResult>;

  // ── Convenience (SDK-level, not RPC) ──────────────────────
  waitForTransaction(address: Address, hash: string, opts?: WaitOpts): Promise<Transaction | null>;
}
```

### RPC Coverage Map

Every C++ JSON-RPC method maps to a typed SDK method:

| C++ RPC Method | SDK Method | Notes |
|----------------|------------|-------|
| `getAddressInformation` | `getAddressInformation()` | |
| `getExtendedAddressInformation` | `getExtendedAddressInformation()` | |
| `getWalletInformation` | `getWalletInformation()` | |
| `getAddressBalance` | `getBalance()` | Simplified name |
| `getAddressState` | `getState()` | Simplified name |
| `getAccountCapability` | `getAccountCapability()` | TOS-native |
| `getAccountDelegations` | `getAccountDelegations()` | TOS-native, deferred backend |
| `getAccountSessions` | `getAccountSessions()` | TOS-native, deferred backend |
| `getAccountAgents` | `getAccountAgents()` | TOS-native, deferred backend |
| `getMasterchainInfo` | `getMasterchainInfo()` | |
| `getConsensusBlock` | `getConsensusBlock()` | |
| `lookupBlock` | `lookupBlock()` | |
| `getBlockHeader` | `getBlockHeader()` | |
| `shards` / `getShards` | `getShards()` | |
| `getMasterchainBlockSignatures` | `getMasterchainBlockSignatures()` | |
| `getShardBlockProof` | `getShardBlockProof()` | |
| `getTransactions` | `getTransactions()` | |
| `getTransactionsStd` | `getTransactions()` | Same method, format option |
| `getBlockTransactions` | `getBlockTransactions()` | |
| `getBlockTransactionsExt` | `getBlockTransactionsExt()` | |
| `tryLocateTx` | `tryLocateTx()` | Returns `LocateResult` (found + block ID) |
| `tryLocateResultTx` | `tryLocateResultTx()` | Returns `LocateResult` |
| `tryLocateSourceTx` | `tryLocateSourceTx()` | Returns `LocateResult` |
| `runGetMethod` | `runGetMethod()` | |
| `runGetMethodStd` | `runGetMethod()` | Same method, format option |
| `sendBoc` | `sendBoc()` | |
| `sendBocReturnHash` | `sendBocReturnHash()` | |
| `sendBocReturnHashNoError` | `sendBocReturnHash()` | Merged; SDK never throws on send, returns status |
| `sendQuery` | `sendQuery()` | Exposed — needed for contract deploy and external messages |
| `estimateFee` | `estimateFee()` | Includes `ignoreChksig` option |
| `buildTransactionIntent` | `buildTransactionIntent()` | TOS-native |
| `getSigningPayload` | `getSigningPayload()` | TOS-native |
| `submitSignedTransaction` | `submitSignedTransaction()` | TOS-native |
| `getConfigParam` | `getConfigParam()` | |
| `getConfigAll` | `getConfigAll()` | |
| `getLibraries` | `getLibraries()` | |
| `getTokenData` | `getTokenData()` | |
| `getOutMsgQueueSize` | `getOutMsgQueueSize()` | |
| `detectAddress` | `detectAddress()` | In `@tos/core` (offline) |
| `detectHash` | `detectHash()` | In `@tos/core` (offline) |
| `packAddress` | `packAddress()` | In `@tos/core` (offline) |
| `unpackAddress` | `unpackAddress()` | In `@tos/core` (offline) |

### TosClient (JSON-RPC implementation)

```typescript
class TosClient implements TosProvider {
  constructor(options: {
    endpoint: string;            // e.g. "http://localhost:8081"
    apiKey?: string;             // X-API-Key header
    timeout?: number;            // per-request timeout in ms (default: 30000)
    fetch?: typeof globalThis.fetch; // custom fetch for non-browser envs
    retry?: {                    // automatic retry on transient failures
      maxRetries?: number;       // default: 3
      backoffMs?: number;        // default: 1000 (exponential)
    };
    onRequest?: (method: string, params: unknown) => void;  // logging hook
    onResponse?: (method: string, result: unknown, durationMs: number) => void;
    onError?: (method: string, error: TosRpcError) => void;
  });

  // All TosProvider methods implemented via JSON-RPC 2.0

  // Raw access for advanced use or future methods
  rawCall(method: string, params?: Record<string, unknown>): Promise<unknown>;

  // Current endpoint info
  readonly endpoint: string;
}
```

### Shared Response Types

Types that mirror the C++ JSON response shapes (all use snake_case to match wire format):

```typescript
// Block identifier — used across many responses
interface BlockIdExt {
  workchain: number;
  shard: string;         // C++ returns shard as string (int64)
  seqno: number;
  root_hash: string;     // base64
  file_hash: string;     // base64
}

// Account info response (getAddressInformation)
interface AccountInfo {
  balance: string;       // C++ returns balance as quoted string (nanotomis)
  code: string;          // base64 BOC
  data: string;          // base64 BOC
  last_transaction_id: { lt: string; hash: string };
  block_id: BlockIdExt;
  sync_utime: number;
  state: "active" | "frozen" | "uninitialized";
  frozen_hash: string;
}

// Wallet info response (getWalletInformation)
interface WalletInfo {
  wallet: boolean;
  balance: string;
  account_state: string;
  last_transaction_id: { lt: string; hash: string };
  wallet_type: string | null;    // "wallet v4 r2", "wallet v5 r1", etc.
  seqno: number | null;
  wallet_id: number | null;
}

// Fee estimation response
interface FeeEstimate {
  source_fees: {
    in_fwd_fee: number;
    storage_fee: number;
    gas_fee: number;
    fwd_fee: number;
  };
  destination_fees: unknown[];  // currently empty array
}

// Masterchain info
interface MasterchainInfo {
  last: BlockIdExt;
  state_root_hash: string;
  init: BlockIdExt;
}

// Consensus block
interface ConsensusBlock {
  consensus_block: number;
  timestamp: number;
}

// runGetMethod result
interface RunResult {
  gas_used: number;
  stack: TupleReader;          // SDK wraps raw stack into TupleReader
  exit_code: number;
  block_id: BlockIdExt;
}

// Transaction locator result
interface LocateResult {
  found: boolean;
  id: BlockIdExt;
}

// Readiness probe
interface ReadyzResult {
  ready: boolean;
  sync_lag_seconds: number;
  last_block_utime: number;
  node_time: number;
  last_block: BlockIdExt;
}

// Out message queue size
interface OutMsgQueueSize {
  sizes: Array<{ workchain: number; shard: string; size: number }>;
}

// Short transaction (from getBlockTransactions)
interface ShortTransaction {
  account: string;      // hex account ID
  lt: string;
  hash: string;         // base64
}

// Full transaction (from getTransactions / getBlockTransactionsExt)
interface Transaction {
  block_id: BlockIdExt;
  data: string;          // base64 BOC of full transaction cell
  utime: number;         // unix timestamp
  transaction_id: { lt: string; hash: string };
  fee: string;           // nanotomis as string
  account: string;       // hex account ID
  in_msg_hash: string;   // base64
}

// Token data (from getTokenData) — discriminated by @type
type TokenData =
  | { "@type": "ext.tokens.jettonMasterData";
      total_supply: string; mintable: boolean;
      admin_address: string; jetton_content: string; jetton_wallet_code: string }
  | { "@type": "ext.tokens.nftItemData";
      index: string; collection_address: string; owner_address: string; content: string }
  | { "@type": "ext.tokens.nftCollectionData";
      next_item_index: string; owner_address: string; collection_content: string };

// Config response
interface ConfigAll {
  config: Cell;          // full config cell
  config_params: Record<string, Cell | null>;  // individual params by ID
}

// Library entry (from getLibraries)
interface LibraryEntry {
  hash: string;          // base64
  data: string;          // base64 BOC
}

// Block header (from getBlockHeader)
interface BlockHeader {
  id: BlockIdExt;
  global_id: number;
  version: number;
  after_merge: boolean;
  before_split: boolean;
  after_split: boolean;
  want_merge: boolean;
  want_split: boolean;
  validator_list_hash_short: number;
  catchain_seqno: number;
  min_ref_mc_seqno: number;
  is_key_block: boolean;
  prev_key_block_seqno: number;
  start_lt: string;
  end_lt: string;
  gen_utime: number;
}

// Block signatures (from getMasterchainBlockSignatures)
interface BlockSignatures {
  id: BlockIdExt;
  signatures: Array<{ node_id_short: string; signature: string }>;  // both base64
}

// Shard info (from getShards)
type ShardInfo = BlockIdExt;

// Extended account info (from getExtendedAddressInformation)
interface ExtendedAccountInfo {
  address: { account_address: string };
  balance: number;
  last_transaction_id: { lt: string; hash: string };
  block_id: BlockIdExt;
  sync_utime: number;
  account_state: { code: string; data: string; frozen_hash: string };
  revision: number;
}

// Shard block proof
interface ShardBlockProof {
  masterchain_id: BlockIdExt;
  links: Array<{ id: BlockIdExt; proof: string }>;  // proof is base64
}
```

### Permission Types (TOS-native, deferred backend)

```typescript
// Matches C++ account.delegationGrant response shape
interface DelegationGrant {
  account: string;
  id: string;
  grantor: string;
  grantee: string;
  scope: string;           // "submit_only" | "bounded_transfer" | etc.
  constraints: {
    max_value: string | null;
    vesting_start: number | null;
    reserved_balance: string | null;
  };
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  revocable: boolean;
  status: "active" | "expired" | "revoked" | "unknown";
}

// Matches C++ account.sessionCapability
interface SessionCapability {
  account: string;
  session_id: string;
  principal: string;
  scope: string;
  created_at: number | null;
  expires_at: number | null;
  revocable: boolean;
  status: string;
}

// Matches C++ account.agentCapability
interface AgentCapability {
  account: string;
  agent_id: string;
  principal: string;
  scope: string;
  constraints: {
    threshold_n: number | null;
    threshold_k: number | null;
  };
  created_at: number | null;
  expires_at: number | null;
  revocable: boolean;
  status: string;
}
```

### Account Capability (TOS-native extension)

```typescript
interface AccountCapability {
  address: string;
  account_model: string;         // "wallet.v3r2" | "wallet.v4r2" | "wallet.v5r1" | "unknown"
  authorization_version: string; // "auth.v1"
  supports_delegation: boolean;
  supports_sessions: boolean;
  supports_agents: boolean;
  supports_sponsorship: boolean;
  account_state: "active" | "uninitialized" | "frozen";
  revision: number;
}
```

### Transaction Intent Types (TOS-native)

Aligned with C++ `json-rpc-server-send.cpp` parameter names:

```typescript
// buildTransactionIntent input — matches C++ params: address/from, body, init_code, init_data
interface TransactionIntentRequest {
  from: Address;
  body: Cell;                   // message body (C++ param: body, base64 BOC)
  initCode?: Cell;              // C++ param: init_code
  initData?: Cell;              // C++ param: init_data
  accountModel?: string;        // C++ param: account_model
  authorizationVersion?: string; // C++ param: authorization_version
  signer?: Address;             // override signer role
  submitter?: Address;          // override submitter role
  feePayer?: Address;           // override fee_payer role
}

// buildTransactionIntent response — matches C++ transaction.intent
interface TransactionIntent {
  from: string;
  account_model: string;
  authorization_version: string;
  action: {
    address: string;
    body: string;               // base64 BOC
    init_code: string;          // base64 BOC
    init_data: string;          // base64 BOC
  };
  authorization_roles: AuthorizationRoles;
  fee_intent: { mode: string };
  replay_protection: { mode: string };
}

interface AuthorizationRoles {
  signer: string;
  submitter: string;
  fee_payer: string;
  is_self_submitted: boolean;
  is_self_paid: boolean;
}

// getSigningPayload input — matches C++ params (same as buildTransactionIntent)
interface SigningPayloadRequest {
  from: Address;
  body: Cell;
  initCode?: Cell;
  initData?: Cell;
  accountModel?: string;
  authorizationVersion?: string;
  signer?: Address;
  submitter?: Address;
  feePayer?: Address;
}

// getSigningPayload response — matches C++ transaction.signingPayload
interface SigningPayload {
  payload_version: number;       // C++ returns int, not string
  payload_encoding: "boc_base64"; // C++ uses "boc_base64", not "base64"
  payload: string;               // base64-encoded external message BOC
  chain_id: number;              // C++ returns int
  replay_protection: { mode: string };
}

// submitSignedTransaction input — matches C++ params
interface SubmitSignedRequest {
  signedBoc: Uint8Array;         // C++ accepts: signed_message_boc | boc | payload
  signer?: Address;              // optional role metadata
  submitter?: Address;
  feePayer?: Address;
}

// submitSignedTransaction response — matches C++ transaction.submissionResult
interface SubmissionResult {
  accepted: boolean;
  transaction_hash: string;      // base64
  submission_id: string;         // base64
  status: number;                // C++ includes status field
  authorization_roles: AuthorizationRoles;
}
```

### ContractProvider (for contract wrappers)

Bridge between contract wrappers and transport — same pattern as `@ton/core`:

```typescript
interface ContractProvider {
  getState(): Promise<ContractState>;
  get(method: string, args: TupleItem[]): Promise<ContractGetResult>;
  internal(via: Signer, args: {
    value: bigint;
    body?: Cell;
    sendMode?: SendMode;
    bounce?: boolean;
  }): Promise<void>;
  external(message: Cell): Promise<void>;
}

interface ContractState {
  balance: bigint;
  state: "active" | "uninitialized" | "frozen";
  code: Cell | null;
  data: Cell | null;
  lastTransaction: { lt: bigint; hash: string } | null;
}

interface ContractGetResult {
  gasUsed: number;       // C++ returns int
  stack: TupleReader;
  exitCode: number;
}
```

### Signer (abstract)

Inspired by ethers.js Signer — async-friendly for hardware wallets:

```typescript
interface Signer {
  readonly address: Address;
  sign(message: Uint8Array): Promise<Uint8Array>;
  send(args: SenderArguments): Promise<void>;
}

interface SenderArguments {
  to: Address;
  value: bigint;
  body?: Cell;
  sendMode?: SendMode;
  bounce?: boolean;
  init?: StateInit;
}
```

### Concrete Signer: KeyPairSigner

```typescript
class KeyPairSigner implements Signer {
  constructor(keyPair: KeyPair, wallet: OpenedContract<Wallet>);

  readonly address: Address;
  sign(message: Uint8Array): Promise<Uint8Array>;
  send(args: SenderArguments): Promise<void>;
}
```

### open() — connect a contract to a provider

Inspired by `@ton/core`'s `openContract()`:

```typescript
type OpenedContract<T extends Contract> = {
  [K in keyof T]: T[K] extends (provider: ContractProvider, ...args: infer A) => infer R
    ? (...args: A) => R
    : T[K];
};

function open<T extends Contract>(contract: T, provider: TosProvider): OpenedContract<T>;

// Usage:
const wallet = open(WalletV4R2.create({ publicKey, workchain: 0 }), client);
const balance = await wallet.getBalance();  // no need to pass provider
await wallet.sendTransfer(signer, { messages: [...] });
```

### waitForTransaction

Essential for DApp UX — inspired by ethers.js:

```typescript
interface WaitOpts {
  timeout?: number;       // ms, default 60000
  pollInterval?: number;  // ms, default 1500
}

// Returns the matching transaction, or throws WAIT_TIMEOUT
await client.waitForTransaction(address, txHash);
await client.waitForTransaction(address, txHash, { timeout: 30000, pollInterval: 2000 });
```

---

## Layer 3: @tos/wallets

### Contract Base Interface

```typescript
interface Contract {
  readonly address: Address;
  readonly init?: StateInit;
}

interface StateInit {
  code: Cell;
  data: Cell;
}
```

### Wallet Interface

```typescript
interface Wallet extends Contract {
  // Read methods (require ContractProvider)
  getSeqno(provider: ContractProvider): Promise<number>;
  getBalance(provider: ContractProvider): Promise<bigint>;

  // Build a signed external message (offline, pure)
  createTransfer(args: {
    seqno: number;
    secretKey: Uint8Array;
    messages: OutMessage[];
    sendMode?: SendMode;
    validUntil?: number;      // unix timestamp; message expires after this time
  }): Cell;

  // Send via provider (online) — full form with Signer
  sendTransfer(provider: ContractProvider, via: Signer, args: {
    messages: OutMessage[];
    sendMode?: SendMode;
    timeout?: number;
  }): Promise<void>;

  // Send via provider — shorthand for single transfer (ethers.js-like simplicity)
  // When called via OpenedContract, provider is auto-injected:
  //   wallet.sendTransfer(secretKey, { to: "0:...", value: toNano("1") })
  sendTransfer(provider: ContractProvider, secretKey: Uint8Array, args: {
    to: Address | string;
    value: bigint;
    body?: Cell;
    bounce?: boolean;
    sendMode?: SendMode;
  }): Promise<void>;

  // Deploy (first-time init)
  sendDeploy(provider: ContractProvider, via: Signer, value: bigint): Promise<void>;
}

interface OutMessage {
  to: Address;
  value: bigint;
  body?: Cell;
  bounce?: boolean;
  init?: StateInit;
}

enum SendMode {
  CARRY_ALL_REMAINING_BALANCE = 128,
  CARRY_ALL_REMAINING_INCOMING_VALUE = 64,
  DESTROY_ACCOUNT_IF_ZERO = 32,
  PAY_GAS_SEPARATELY = 1,
  IGNORE_ERRORS = 2,
  NONE = 0,
}
```

### Wallet Implementations

```typescript
class WalletV3R2 implements Wallet {
  static create(args: { publicKey: Uint8Array; workchain?: number; walletId?: number }): WalletV3R2;
  // ... Wallet interface methods
}

class WalletV4R2 implements Wallet {
  static create(args: { publicKey: Uint8Array; workchain?: number; walletId?: number }): WalletV4R2;
  // ... Wallet interface methods
}

class WalletV5R1 implements Wallet {
  static create(args: { publicKey: Uint8Array; workchain?: number }): WalletV5R1;
  // ... Wallet interface methods
}

class HighloadWalletV2 implements Wallet {
  static create(args: { publicKey: Uint8Array; workchain?: number; walletId?: number }): HighloadWalletV2;
  // Supports batch: up to 254 messages in one tx
  // ... Wallet interface methods
}

// Named registry
const Wallets = {
  v3r2: WalletV3R2,
  v4r2: WalletV4R2,
  v5r1: WalletV5R1,
  highload: HighloadWalletV2,
  default: WalletV4R2,
} as const;
```

### Quick Start (ethers.js-level simplicity)

```typescript
import { TosClient, WalletV4R2, toNano, mnemonicToPrivateKey, open } from "@tos/sdk";

const client = new TosClient({ endpoint: "http://localhost:8081" });
const keys = await mnemonicToPrivateKey(["word1", "word2", /* ... 24 words */]);
const wallet = open(WalletV4R2.create({ publicKey: keys.publicKey }), client);

// Send 1.5 TOS
await wallet.sendTransfer(keys.secretKey, {
  to: "0:abc...def",
  value: toNano("1.5"),
});
```

### Full Usage (explicit control)

```typescript
import { TosClient, open, KeyPairSigner } from "@tos/client";
import { mnemonicToPrivateKey } from "@tos/crypto";
import { WalletV4R2 } from "@tos/wallets";
import { toNano, Address, beginCell, comment } from "@tos/core";

// 1. Connect to node
const client = new TosClient({ endpoint: "http://localhost:8081" });

// 2. Open wallet
const keyPair = await mnemonicToPrivateKey(mnemonic);
const wallet = open(
  WalletV4R2.create({ publicKey: keyPair.publicKey, workchain: 0 }),
  client,
);

// 3. Create signer
const signer = new KeyPairSigner(keyPair, wallet);

// 4. Send transfer with comment
await wallet.sendTransfer(signer, {
  messages: [{
    to: Address.parse("0:abc...def"),
    value: toNano("1.5"),
    body: comment("Payment for invoice #123"),
  }],
});

// 5. Wait for confirmation
const tx = await client.waitForTransaction(wallet.address, txHash);

// 6. Check account capability (TOS-native)
const cap = await client.getAccountCapability(wallet.address);
console.log(cap.account_model);        // "wallet.v4r2"
console.log(cap.supports_delegation);  // false
```

### Offline Signing Flow (hardware wallets, air-gapped)

```typescript
// Step 1: Build intent (online)
const intent = await client.buildTransactionIntent({
  from: wallet.address,
  messages: [{ to: dest, value: toNano("1.0") }],
});

// Step 2: Get signing payload (online)
const payload = await client.getSigningPayload(intent);

// Step 3: Sign offline (air-gapped device / hardware wallet)
const payloadBytes = base64ToBytes(payload.payload);  // SDK utility
const signature = sign(payloadBytes, secretKey);

// Step 4: Submit signed BOC (online)
const signedBoc = buildSignedBoc(payloadBytes, signature);  // SDK utility
const result = await client.submitSignedTransaction({
  signedBoc: signedBoc,
});
```

---

## Layer 4: @tos/contracts

### Jetton (Fungible Token — TEP-74)

```typescript
class JettonMinter implements Contract {
  static create(address: Address): JettonMinter;

  // Read
  getTotalSupply(provider: ContractProvider): Promise<bigint>;
  getAdminAddress(provider: ContractProvider): Promise<Address>;
  getJettonWalletAddress(provider: ContractProvider, owner: Address): Promise<Address>;
  getJettonData(provider: ContractProvider): Promise<JettonData>;
  getContent(provider: ContractProvider): Promise<JettonContent>;

  // Write
  sendMint(provider: ContractProvider, via: Signer, args: {
    to: Address;
    amount: bigint;
    value: bigint;
  }): Promise<void>;
  sendChangeAdmin(provider: ContractProvider, via: Signer, newAdmin: Address): Promise<void>;
}

class JettonWallet implements Contract {
  static create(address: Address): JettonWallet;

  // Read
  getBalance(provider: ContractProvider): Promise<bigint>;
  getOwner(provider: ContractProvider): Promise<Address>;
  getJettonMaster(provider: ContractProvider): Promise<Address>;

  // Write
  sendTransfer(provider: ContractProvider, via: Signer, args: {
    to: Address;
    amount: bigint;
    responseAddress?: Address;
    forwardAmount?: bigint;
    forwardPayload?: Cell;
  }): Promise<void>;

  sendBurn(provider: ContractProvider, via: Signer, args: {
    amount: bigint;
    responseAddress?: Address;
  }): Promise<void>;
}
```

### NFT (TEP-62)

```typescript
class NftCollection implements Contract {
  static create(address: Address): NftCollection;

  getCollectionData(provider: ContractProvider): Promise<NftCollectionData>;
  getNftAddressByIndex(provider: ContractProvider, index: bigint): Promise<Address>;
  getNftContent(provider: ContractProvider, index: bigint, individualContent: Cell): Promise<string>;

  sendMint(provider: ContractProvider, via: Signer, args: {
    index: bigint;
    owner: Address;
    content: Cell;
    value: bigint;
  }): Promise<void>;
}

class NftItem implements Contract {
  static create(address: Address): NftItem;

  getNftData(provider: ContractProvider): Promise<NftItemData>;

  sendTransfer(provider: ContractProvider, via: Signer, args: {
    to: Address;
    responseAddress?: Address;
    forwardAmount?: bigint;
    forwardPayload?: Cell;
  }): Promise<void>;
}
```

### Token Data (via RPC)

```typescript
// Uses getTokenData RPC — works for any standard token contract
const data = await client.getTokenData(Address.parse("0:jetton_or_nft_address"));
```

---

## Umbrella Package: @tos/sdk

Re-exports everything for convenience:

```typescript
// @tos/sdk re-exports all sub-packages
export * from "@tos/core";
export * from "@tos/crypto";
export * from "@tos/client";
export * from "@tos/wallets";
export * from "@tos/contracts";
```

Usage for developers who want simplicity:

```typescript
import { TosClient, WalletV4R2, toNano, mnemonicToPrivateKey, open } from "@tos/sdk";
```

---

## Structured Error Design

All SDK errors extend a base class with machine-readable codes:

```typescript
class TosError extends Error {
  readonly code: string;
  readonly cause?: Error;
}

class TosRpcError extends TosError {
  readonly rpcCode: number;
  readonly rpcData?: unknown;
}

class TosContractError extends TosError {
  readonly exitCode: number;     // TVM exit code
  readonly address: Address;
}

// Error codes
const ErrorCodes = {
  // Core
  INVALID_ADDRESS: "INVALID_ADDRESS",
  INVALID_BOC: "INVALID_BOC",
  CELL_OVERFLOW: "CELL_OVERFLOW",        // >1023 bits or >4 refs
  SLICE_UNDERFLOW: "SLICE_UNDERFLOW",    // read past end

  // RPC / Network
  RPC_TIMEOUT: "RPC_TIMEOUT",
  RPC_CONNECTION_FAILED: "RPC_CONNECTION_FAILED",
  RPC_METHOD_NOT_FOUND: "RPC_METHOD_NOT_FOUND",
  RPC_SERVER_ERROR: "RPC_SERVER_ERROR",
  NODE_NOT_READY: "NODE_NOT_READY",

  // Contract
  CONTRACT_NOT_DEPLOYED: "CONTRACT_NOT_DEPLOYED",
  GET_METHOD_FAILED: "GET_METHOD_FAILED",
  SEND_FAILED: "SEND_FAILED",
  INSUFFICIENT_BALANCE: "INSUFFICIENT_BALANCE",

  // Account capability (TOS-native)
  ACCOUNT_MODEL_UNSUPPORTED: "ACCOUNT_MODEL_UNSUPPORTED",
  ACCOUNT_CAPABILITY_UNKNOWN: "ACCOUNT_CAPABILITY_UNKNOWN",
  TRANSACTION_INTENT_UNSUPPORTED: "TRANSACTION_INTENT_UNSUPPORTED",
  SIGNING_PAYLOAD_UNAVAILABLE: "SIGNING_PAYLOAD_UNAVAILABLE",
  SIGNED_ARTIFACT_INVALID: "SIGNED_ARTIFACT_INVALID",
  FEATURE_DEFERRED: "FEATURE_DEFERRED",

  // Wait
  WAIT_TIMEOUT: "WAIT_TIMEOUT",
} as const;
```

---

## Differences from TON SDKs

| Aspect | TON (@ton/ton + tonweb) | TOS (@tos/sdk) |
|--------|------------------------|----------------|
| Package count | 3+ packages, independent repos | Monorepo workspace, versioned together |
| RPC coverage | Partial — many methods missing from typed SDK | Full — all 42 C++ methods mapped |
| Provider | TonClient (concrete class) | TosProvider (interface) + TosClient (impl) |
| Signer | Embedded in wallet | Separated — `Signer` interface (async-friendly) |
| Account capability | Not available | `getAccountCapability()` — TOS-native |
| Transaction intent | Not available | `buildTransactionIntent()` / `getSigningPayload()` |
| Authorization roles | Not modeled | signer / submitter / fee_payer separation |
| Error handling | Raw errors, no codes | `TosError` hierarchy with structured codes |
| waitForTransaction | Not available | Built-in polling with timeout |
| Entry point | `new TonWeb(provider)` god object | Composable imports, tree-shakeable |
| Address utilities | RPC-only | Offline in `@tos/core` |
| Build target | JS source (tonweb), TS compiled (@ton) | TypeScript source, ESM + CJS dual output |

## TOS-Specific Extensions (vs TON SDK)

These are capabilities unique to TOS that the SDK must surface:

1. **Account Capability Discovery** — `getAccountCapability()` returns machine-readable support flags
2. **Transaction Intent** — `buildTransactionIntent()` for structured tx construction
3. **Signing Payload** — `getSigningPayload()` for offline / hardware wallet signing
4. **Signed Submission** — `submitSignedTransaction()` with role metadata
5. **Authorization Roles** — signer / submitter / fee_payer separation in transaction metadata
6. **Permission Inspection** — `getAccountDelegations()` / `getAccountSessions()` / `getAccountAgents()` (deferred until backend is ready)
7. **Token Data** — `getTokenData()` for any standard token contract

---

## Build & Tooling

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Language | TypeScript 5.x | Type safety, IDE support |
| Module format | ESM primary, CJS fallback | Modern standard |
| Bundler | tsup (esbuild-based) | Fast, simple, dual-format output |
| Test framework | Vitest | Fast, ESM-native, compatible with Jest API |
| Package manager | pnpm | Workspace support, disk efficiency |
| Monorepo tool | pnpm workspaces | No extra tool needed |
| Linting | Biome | Fast, replaces ESLint + Prettier |
| CI | GitHub Actions | Standard for the TOS monorepo |

---

## Implementation Order

| Phase | Package | Scope | Depends on |
|-------|---------|-------|------------|
| Phase 1 | `@tos/core` | Address, Cell, Slice, Builder, BOC, Dictionary, Tuple, toNano/fromNano, address utils | Nothing |
| Phase 2 | `@tos/crypto` | Ed25519, Mnemonic, HD derivation (fork from @ton/crypto) | Nothing |
| Phase 3 | `@tos/client` | TosClient, TosProvider interface, all 42 RPC methods, waitForTransaction | Phase 1 |
| Phase 4 | `@tos/wallets` | WalletV3R2, V4R2, V5R1, HighloadV2, KeyPairSigner | Phase 1-3 |
| Phase 5 | `@tos/contracts` | JettonMinter, JettonWallet, NftCollection, NftItem | Phase 1, 3 |
| Phase 6 | `@tos/sdk` | Umbrella package, documentation, examples | Phase 1-5 |

Phase 1-3 are the minimum viable SDK. Phase 4-6 are needed before public launch.

---

## Acceptance Criteria

The SDK is ready for public use when:

- [ ] `@tos/core` passes all Cell/BOC serialization round-trip tests against C++ reference
- [ ] `@tos/crypto` generates keys compatible with existing TOS wallets
- [ ] `@tos/client` covers all 42 JSON-RPC methods with typed responses matching C++ wire format
- [ ] `@tos/client` can query a live TOS node end-to-end
- [ ] `@tos/client` response types use snake_case matching C++ JSON output
- [ ] `@tos/wallets` can create, sign, and submit a transfer on testnet
- [ ] `@tos/wallets` offline signing produces identical BOC to C++ reference
- [ ] `@tos/wallets` `contractAddress()` matches C++ address derivation
- [ ] `@tos/contracts` can mint and transfer a Jetton on testnet
- [ ] `waitForTransaction` works reliably with polling
- [ ] `comment()` helper produces correct op=0 text body
- [ ] Bundle size < 100KB gzipped for `@tos/core` + `@tos/client`
- [ ] Works in Node.js 18+, Chrome 90+, Firefox 90+, Safari 15+
- [ ] Zero `any` types in public API surface
- [ ] All public functions have JSDoc with usage examples

---

## Review Log

| Round | Angle | Issues Found | Fixed |
|-------|-------|-------------|-------|
| 1 | RPC alignment | TosProvider only had 16/42 methods; missing 26 RPC methods | Added all 42 methods with full coverage map |
| 2 | Ethereum pattern alignment | No waitForTransaction; no async Signer.sign() | Added waitForTransaction; made Signer.sign() async |
| 3 | Address utilities | detectAddress/packAddress/unpackAddress missing from @tos/core | Added as offline pure functions in @tos/core |
| 4 | Signer design | Signer too thin; no concrete implementation shown | Added KeyPairSigner class; async sign() for hardware wallets |
| 5 | Contract deployment | No deploy flow documented | Added sendDeploy() to Wallet interface |
| 6 | Offline signing flow | buildTransactionIntent/getSigningPayload usage not shown | Added full offline signing example |
| 7 | Missing types | TupleItem/TupleReader not defined; ContractState incomplete | Added Tuple types; added ContractState fields |
| 8 | Error completeness | Missing WAIT_TIMEOUT, NODE_NOT_READY, INSUFFICIENT_BALANCE | Added all missing error codes aligned with C++ error codes |
| 9 | Contract wrappers | JettonWallet missing getOwner/getJettonMaster; NFT missing content | Added missing read methods; added JettonContent |
| 10 | Consistency | detectHash missing; getTokenData not mentioned; SendMode enum absent | Added detectHash to core; getTokenData section; SendMode enum |
| 11 | C++ field casing | AddressInfo used camelCase; C++ returns snake_case (`raw_form`, `given_type`, `test_only`) | Fixed all fields to snake_case matching wire format |
| 12 | detectHash response | Had `inputType` field that doesn't exist in C++; missing `b64url` | Fixed to match C++ `ext.utils.detectedHash`: `b64`, `b64url`, `hex` |
| 13 | Optional seqno param | 10+ C++ methods accept optional `seqno` for historical block queries; SDK had none | Added `opts.seqno` to all account, config, token, runGetMethod methods |
| 14 | lookupBlock signature | Had `(workchain, shard, seqno)` — C++ supports seqno OR lt OR unixtime; shard is string not bigint | Fixed: shard as string, opts with seqno/lt/unixtime union |
| 15 | getBlockHeader/getShardBlockProof | Used `BlockId` type that was never defined; C++ takes separate workchain/shard/seqno params | Changed to explicit params matching C++ |
| 16 | getTransactions pagination | Had opaque `TransactionQuery` opts; C++ requires `lt`+`hash` pair with `limit` | Expanded to explicit `lt`, `hash`, `limit` params |
| 17 | estimateFee params | Missing `ignoreChksig` (C++ `ignore_chksig`, default true) | Added to opts |
| 18 | SigningPayload types | `payload_version` was string (C++ returns int); `payload_encoding` was "base64" (C++ uses "boc_base64"); `chain_id` was string (C++ returns int) | Fixed all to match C++ types |
| 19 | sendQuery missing | Was "not exposed" but needed for contract deploy and raw external messages | Exposed as `sendQuery()` |
| 20 | TransactionIntentRequest | Used `messages: OutAction[]` which doesn't match C++ params (address, body, init_code, init_data) | Rewrote to match C++ parameter names exactly |
| 21 | SubmissionResult incomplete | Missing `status` field that C++ returns | Added `status: number` |
| 22 | Missing response types | No definitions for BlockIdExt, FeeEstimate, MasterchainInfo, RunResult, etc. | Added 12 response type interfaces matching C++ shapes |
| 23 | Builder API incomplete | Missing storeBuffer, storeDict, storeStringRefTail, storeSlice, storeBuilder, storeBits | Added all missing Builder methods + remainingBits/remainingRefs |
| 24 | Missing ExternalAddress | Some contracts need ExternalAddress; only Address was defined | Added ExternalAddress class |
| 25 | Missing Cell.hash() | DApp devs need cell hash for tracking/verification; was absent | Added Cell.hash(), Cell.type, Cell.isExotic, Cell.equals() |
| 26 | Missing comment() helper | Text comment on transfer is the #1 DApp pattern; required manual beginCell() | Added `comment()` convenience function |
| 27 | Missing contractAddress() | Deterministic address derivation is essential for deploy; was absent | Added `contractAddress(workchain, init)` to @tos/core |
| 28 | TosClient config | No retry, no logging hooks, no error callbacks | Added retry config, onRequest/onResponse/onError hooks |
| 29 | getShards param | C++ seqno is optional (uses latest if absent); SDK required it | Made seqno optional |
| 30 | getOutMsgQueueSize response | Had `{ size: number }` but C++ returns `{ sizes: [{workchain, shard, size}] }` | Fixed to `OutMsgQueueSize` with array |
| 31 | ethers.js simplicity | End-to-end example requires 4 imports and 10+ lines; ethers.js is 3 lines | Added Quick Start section with 5-line example using `@tos/sdk` umbrella import |
| 32 | sendTransfer UX | Quick-start `sendTransfer(secretKey, {to, value})` form not in Wallet interface | Added shorthand overload accepting `secretKey` + `{to, value}` directly |
| 33 | getBalance return type | Returns `bigint` but C++ sends quoted string; no documentation of parsing | Added inline comment noting SDK parses string → bigint internally |
| 34 | Transaction type undefined | Most important response type (`Transaction`) was never defined | Added full `Transaction`, `TokenData`, `ConfigAll`, `LibraryEntry`, `BlockHeader`, `BlockSignatures`, `ExtendedAccountInfo`, `ShardBlockProof` types |
| 35 | TupleItem missing tuple | C++ runGetMethod stack supports nested tuples; SDK TupleItem had no `tuple` variant | Added `{ type: "tuple"; items: TupleItem[] }` |
| 36 | WaitOpts redundancy | `refetchInterval` duplicates `pollInterval` concept | Removed `refetchInterval`; simplified to `timeout` + `pollInterval` |
| 37 | ContractGetResult.gasUsed | Was `bigint` but C++ returns regular int (always 0 currently) | Changed to `number` |
| 38 | Monolithic interface | Doc claims "viem-inspired categorized actions" but TosProvider is one big interface | Added domain sub-interfaces (AccountActions, BlockActions, etc.) that TosProvider extends |
| 39 | Permission types undefined | `DelegationGrant`, `SessionCapability`, `AgentCapability` referenced but never defined | Added full type definitions matching C++ response shapes |
| 40 | AccountState undefined | `getState()` returned opaque `AccountState` type that was never defined | Changed to literal union: `"active" \| "frozen" \| "uninitialized"` |
| 41 | createTransfer `timeout` misleading | Named `timeout` but is a unix timestamp (validUntil), not a duration | Renamed to `validUntil` with clear doc comment |
| 42 | Buffer.from in offline example | `Buffer.from()` is Node-only; breaks isomorphic principle | Replaced with SDK's `base64ToBytes()` utility |
| 43 | Missing encoding utilities | No base64/hex conversion functions; needed everywhere, must be isomorphic | Added `base64ToBytes`, `bytesToBase64`, `hexToBytes`, `bytesToHex`, `base64UrlToBytes`, `bytesToBase64Url` |
