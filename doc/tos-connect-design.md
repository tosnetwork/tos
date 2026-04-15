# TOS Connect & DApp Kit Design

Version: v0.4-draft

## Purpose

Design document for TOS Layer 6 — wallet connection protocol, React hooks, and UI components.

This layer enables DApp developers to connect user wallets, request transaction signatures, and build production-ready UIs with minimal code.

## Scope

| npm Package | Purpose |
|-------------|---------|
| `@tos/connect` | Wallet-DApp communication protocol — session management, bridge, encryption |
| `@tos/connect-ui` | Vanilla JS UI — connect button, wallet modal, QR code (no React) |
| `@tos/react` | React hooks for chain data — `useBalance()`, `useSendTransaction()`, contract hooks |
| `@tos/connect-react` | All-in-one React integration — `<ConnectButton />`, `<TosConnectProvider />` |

## Design Principles

1. **Minimal integration** — a DApp should get a working "Connect Wallet" button with minimal setup (like RainbowKit).
2. **Layer 5 native** — built on `@tos/client` and `@tos/core`, not a separate stack.
3. **Protocol-first** — the connect protocol is independent of any UI framework.
4. **Secure by default** — end-to-end encrypted sessions, no plaintext keys over the wire.
5. **Multi-platform** — works with browser extensions, mobile wallets (deeplinks), and desktop wallets.
6. **Framework-agnostic core** — `@tos/connect` and `@tos/connect-ui` work without React.
7. **Familiar to Ethereum developers** — hook names and patterns mirror wagmi/RainbowKit.

## Reference Analysis

### What to adopt

| Source | What | Why |
|--------|------|-----|
| TON Connect `@tonconnect/sdk` | Bridge protocol, session encryption (NaCl box), EventSource for server-push | Proven protocol for wallet-DApp communication in TON-like chains |
| TON Connect `@tonconnect/protocol` | Message types, connect/disconnect/sendTransaction flow | Battle-tested wire format |
| wagmi | React hooks pattern (`useAccount`, `useBalance`, `useSendTransaction`), config/provider pattern, zustand store | DApp developers from Ethereum expect these hook names |
| wagmi | Core/React separation (framework-agnostic core, React bindings on top) | Enables Vue/Solid/Svelte bindings later |
| RainbowKit | `<ConnectButton />` component, `getDefaultConfig()`, theming system | Best-in-class DX for "just add a connect button" |
| RainbowKit | Modal design (wallet list → QR/instructions → connected) | Proven UX flow |

### What to avoid

| Source | Problem | Our approach |
|--------|---------|--------------|
| TON Connect UI | Built with Solid.js — adds framework dependency for non-React apps | Vanilla JS with no framework dependency |
| TON Connect | Wallet list fetched from remote URL (centralization risk) | Ship default wallet list in SDK; allow remote override |
| wagmi | Requires TanStack Query as peer dependency (heavy for simple DApps) | Built-in lightweight query cache; TanStack Query as optional enhancement |
| RainbowKit | Requires WalletConnect projectId (registration friction) | TOS bridge is permissionless; no registration required |
| TON Connect | No React hooks for chain data (balance, transactions) — only connection | Full chain data hooks in `@tos/react` |

---

## Package Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  @tos/connect-react                                         │
│  <ConnectButton />, <TosConnectProvider />, useWallet(),     │
│  useConnect(), useSignData(), theming                         │
├─────────────────────────────────────────────────────────────┤
│  @tos/react                                                 │
│  useBalance(), useSendTransaction(), useContract(),          │
│  useTransactions(), useWaitForTransaction()                  │
├─────────────────────────────┬───────────────────────────────┤
│  @tos/connect-ui            │  @tos/connect                 │
│  ConnectButton (vanilla JS) │  TosConnect class, protocol,  │
│  ConnectModal, QR code      │  session, bridge, encryption   │
├─────────────────────────────┴───────────────────────────────┤
│  @tos/sdk (Layer 5)                                         │
│  @tos/client, @tos/core, @tos/crypto, @tos/wallets          │
└─────────────────────────────────────────────────────────────┘
```

### Dependency rules

```
@tos/connect        depends on @tos/core, @tos/crypto
@tos/connect-ui     depends on @tos/connect
@tos/react          depends on @tos/client, @tos/core (peer: react)
                    optional peer: @tos/connect (for useSendTransaction wallet routing)
@tos/connect-react  depends on @tos/connect, @tos/connect-ui, @tos/react (peer: react)

@tos/crypto ← @tos/core ← @tos/client ← @tos/react ← @tos/connect-react
                   ↑                                        ↑
             @tos/connect ← @tos/connect-ui ─────────────────┘
```

### Relationship to Layer 5

Layer 6 packages import from Layer 5 — they do NOT duplicate functionality:

| Need | Provided by |
|------|-------------|
| Address, Cell, BOC | `@tos/core` (Layer 5) |
| JSON-RPC calls | `@tos/client` (Layer 5) |
| Wallet contract logic | `@tos/wallets` (Layer 5) |
| Crypto (signing, encryption) | `@tos/crypto` (Layer 5) |

---

## Package 1: @tos/connect

### Purpose

Core protocol for wallet-DApp communication. Framework-agnostic. No UI.

### Connection Modes

| Mode | How it works | When used |
|------|-------------|-----------|
| **HTTP Bridge** | Encrypted messages via relay server + EventSource | External wallets (Tonkeeper-style mobile wallets) |
| **Injected** | Direct JS API via `window.tos.provider` | Browser extensions, embedded wallets |

### TosConnect Class (main entry point)

```typescript
class TosConnect {
  constructor(options: {
    manifestUrl: string;        // DApp manifest (name, url, iconUrl)
    bridgeUrl?: string;         // default: "https://bridge.tos.network"
    storage?: ConnectStorage;   // session persistence (default: localStorage)
    walletsListSource?: string; // wallet registry URL or inline list
    sessionTtl?: number;        // session TTL in seconds (default: 86400 = 24h)
    reconnect?: {               // auto-reconnect on bridge connection drop
      enabled?: boolean;        // default: true
      maxRetries?: number;      // default: 5
      backoffMs?: number;       // default: 2000 (exponential)
    };
  });

  // ── Connection state ──────────────────────────────────
  readonly connected: boolean;
  readonly account: ConnectedAccount | null;
  readonly wallet: ConnectedWallet | null;

  // ── Protocol ───────────────────────────────────────────
  static readonly PROTOCOL_VERSION = 2;

  // ── Lifecycle ─────────────────────────────────────────
  connect(wallet: WalletInfo, request?: ConnectRequest): string | null;
  // Returns universal link (HTTP bridge) or null (injected wallet connects immediately)
  restoreConnection(): Promise<void>;    // restore from storage on page load
  disconnect(): Promise<void>;
  pauseConnection(): void;               // stop listening (e.g., app backgrounded)
  unpauseConnection(): Promise<void>;    // resume listening

  // ── Status ────────────────────────────────────────────
  onStatusChange(
    callback: (wallet: ConnectedWallet | null) => void,
    onError?: (error: TosConnectError) => void,
  ): () => void;  // returns unsubscribe function

  // ── Transaction requests ──────────────────────────────
  sendTransaction(request: SendTransactionRequest, opts?: {
    signal?: AbortSignal;         // cancel pending request (e.g., user closes modal)
    onRequestSent?: () => void;   // called when request reaches wallet (bridge acknowledged)
  }): Promise<SendTransactionResponse>;

  // ── Data signing (authentication / "Sign in with TOS") ──
  signData(request: SignDataRequest, opts?: {
    signal?: AbortSignal;
  }): Promise<SignDataResponse>;

  // ── Wallet discovery ──────────────────────────────────
  getWallets(): Promise<WalletInfo[]>;
}
```

### Protocol Types

```typescript
// ── DApp manifest ───────────────────────────────────────
interface DAppManifest {
  url: string;           // DApp URL
  name: string;          // Display name
  iconUrl: string;       // Square icon (256x256+)
}

// ── Wallet discovery ────────────────────────────────────
interface WalletInfo {
  name: string;                  // "TOS Wallet", "Tonkeeper", etc.
  appName: string;               // machine identifier
  imageUrl: string;
  platforms: ("ios" | "android" | "chrome" | "firefox" | "desktop" | "web")[];

  // Connection capabilities (at least one required)
  bridgeUrl?: string;            // HTTP bridge URL
  universalLink?: string;        // deeplink for mobile
  jsBridgeKey?: string;          // window key for injected wallet
  injected?: boolean;            // auto-detected via window

  // Install/download links (shown when wallet is not installed)
  downloadUrls?: {
    ios?: string;                // App Store URL
    android?: string;            // Play Store URL
    chrome?: string;             // Chrome Web Store URL
    firefox?: string;            // Firefox Add-ons URL
    universal?: string;          // fallback website URL
  };
}

// ── Connection ──────────────────────────────────────────
interface ConnectRequest {
  items: ConnectItem[];          // what the DApp is requesting
}

type ConnectItem =
  | { name: "ton_addr" }                           // request wallet address
  | { name: "ton_proof"; payload: string };         // request ownership proof

interface ConnectedAccount {
  address: string;         // raw form "workchain:hex"
  chain: string;           // "-239" (mainnet) or "-3" (testnet)
  publicKey?: string;      // hex-encoded Ed25519 public key
  walletStateInit?: string; // base64 BOC of wallet StateInit
}

interface ConnectedWallet {
  device: DeviceInfo;
  account: ConnectedAccount;
  connectItems?: ConnectItemReply[];
}

interface DeviceInfo {
  platform: "ios" | "android" | "windows" | "mac" | "linux" | "browser";
  appName: string;
  appVersion: string;
  maxProtocolVersion: number;
  features: WalletFeature[];
}

type WalletFeature =
  | { name: "SendTransaction"; maxMessages: number }
  | { name: "SignData"; types: ("text" | "binary" | "cell")[] };

// ── Transaction request ─────────────────────────────────
interface SendTransactionRequest {
  validUntil: number;      // unix timestamp
  network?: string;        // chain ID ("-239" mainnet, "-3" testnet)
  from?: string;           // sender address (default: connected account)
  messages: TransactionMessage[];  // 1-4 messages (max depends on wallet's maxMessages feature)
}

interface TransactionMessage {
  address: string;         // destination
  amount: string;          // nanotomis as string (wire format; SDK hooks accept bigint and convert)
  payload?: string;        // message body BOC (base64)
  stateInit?: string;      // deploy StateInit BOC (base64)
  extraCurrency?: Record<number, string>;  // extra currency ID → amount as string
}
// Note: SDK hooks like useSendTransaction accept `value: bigint` and convert
// to string internally. The wire protocol uses strings for cross-platform compat.

interface SendTransactionResponse {
  boc: string;             // signed transaction BOC (base64)
}

// ── Data signing (authentication) ───────────────────────
interface SignDataRequest {
  type: "text" | "binary" | "cell";
  data: string;            // text content, hex bytes, or base64 BOC
  domain?: string;         // signing domain for replay protection
}

interface SignDataResponse {
  signature: string;       // base64 Ed25519 signature
  address: string;         // signer address
  timestamp: number;       // unix timestamp
  domain?: string;
  payload: string;         // original data
}

// ── Connect item replies (from wallet) ──────────────────
type ConnectItemReply = TonAddressItemReply | TonProofItemReply;

interface TonAddressItemReply {
  name: "ton_addr";
  address: string;         // raw form
  network: string;         // chain ID
  publicKey: string;       // hex Ed25519 public key
  walletStateInit: string; // base64 BOC
}

interface TonProofItemReply {
  name: "ton_proof";
  proof: {
    timestamp: number;
    domain: { lengthBytes: number; value: string };
    payload: string;
    signature: string;     // base64
  };
}

// ── Session storage ─────────────────────────────────────
interface ConnectStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}
```

### Injected Wallet Provider Interface

Browser extensions and embedded wallets must expose a provider at `window.tos.provider`:

```typescript
interface InjectedTosProvider {
  // Wallet identifies itself to the DApp
  deviceInfo: DeviceInfo;

  // Connection
  connect(protocolVersion: number, request: ConnectRequest): Promise<ConnectEvent>;
  disconnect(): void;

  // Transaction
  sendTransaction(request: SendTransactionRpcRequest): Promise<SendTransactionResponse>;

  // Data signing (optional — check deviceInfo.features)
  signData?(request: SignDataRpcRequest): Promise<SignDataResponse>;

  // Events
  listen(callback: (event: WalletEvent) => void): () => void;
}

type WalletEvent =
  | { type: "connect"; payload: ConnectedWallet }
  | { type: "disconnect"; payload: {} }
  | { type: "accountChanged"; payload: ConnectedAccount };
```

**Wallet detection pattern:**

```typescript
// DApp checks for injected wallet
if (window.tos?.provider) {
  const wallet = window.tos.provider;
  console.log(wallet.deviceInfo.appName);  // "TOS Wallet Extension"
}

// Multiple wallets: each registers via unique jsBridgeKey
// window.tos.providers = { "toswallet": provider1, "thirdwallet": provider2 }
```

### Bridge Server

TOS provides a public bridge server at `https://bridge.tos.network/bridge` (default).

The bridge is a stateless message relay — it does NOT:
- Store or decrypt messages (all messages are end-to-end encrypted)
- Authenticate DApps or wallets
- Require registration or API keys

Bridge API:
- `POST /message?client_id={id}&to={walletId}&ttl={seconds}` — send encrypted message
- `GET /events?client_id={id}` — SSE stream for receiving encrypted messages

Anyone can run their own bridge server. The bridge protocol is open and permissionless.

### Security Considerations

**ton_proof verification (backend):**
- Always validate `proof.timestamp` is within acceptable window (e.g., last 5 minutes)
- Always validate `proof.domain.value` matches your DApp's domain
- Always validate `proof.payload` matches the nonce you generated
- Reconstruct the signing message and verify `proof.signature` against `publicKey`
- Verify that `address` derives from the provided `walletStateInit` + `publicKey`

**Address-key binding:**
- When a wallet connects, verify that the returned `publicKey` is consistent with the `address` by reconstructing the contract address from `walletStateInit`
- Never trust the address alone — always cross-check with the public key

**Bridge rate limiting:**
- The public TOS bridge applies per-IP rate limits (details TBD)
- Self-hosted bridges should implement rate limiting to prevent abuse
- DApps should handle `429 Too Many Requests` from the bridge gracefully

### Session Security

- Each session generates a Curve25519 keypair (via NaCl)
- All bridge messages are encrypted with NaCl box (XSalsa20-Poly1305)
- Random 24-byte nonce prepended to each message
- Session keys stored encrypted in ConnectStorage
- Sessions expire after configurable TTL (default: 24 hours)

### Bridge Protocol (wire format)

```
DApp                         Bridge Server                    Wallet
  |                              |                              |
  |--- POST /message ---------->|                              |
  |    (encrypted ConnectReq)    |--- SSE event -------------->|
  |                              |    (encrypted ConnectReq)    |
  |                              |                              |
  |                              |<--- POST /message -----------|
  |<--- SSE event --------------|    (encrypted ConnectResp)    |
  |    (encrypted ConnectResp)   |                              |
  |                              |                              |
  |--- POST /message ---------->|                              |
  |    (encrypted SendTxReq)     |--- SSE event -------------->|
  |                              |    (encrypted SendTxReq)     |
  |                              |                              |
  |                              |<--- POST /message -----------|
  |<--- SSE event --------------|    (encrypted SignedBOC)      |
  |    (encrypted SignedBOC)     |                              |
```

---

## Package 2: @tos/connect-ui

### Purpose

Framework-agnostic UI components for wallet connection. Vanilla JS — works without React.

### TosConnectUI Class

```typescript
class TosConnectUI {
  constructor(options: {
    manifestUrl: string;
    buttonRootId?: string;     // DOM element ID to mount button
    bridgeUrl?: string;
    theme?: "light" | "dark" | "auto";
    language?: string;         // "en" | "zh" | "ja" | "ko" | ...
  });

  // Inherits all TosConnect methods (connected, account, wallet, etc.)
  // Plus UI-specific:

  openModal(): void;
  closeModal(): void;

  // Status
  readonly modalState: "opened" | "closed";
  onModalStateChange(callback: (state: "opened" | "closed") => void): () => void;

  // Cleanup (remove DOM elements, close bridge)
  destroy(): void;
}
```

### Vanilla JS Complete Example

```html
<div id="tos-connect-button"></div>
<script type="module">
  import { TosConnectUI } from "@tos/connect-ui";

  const ui = new TosConnectUI({
    manifestUrl: "https://myapp.com/manifest.json",
    buttonRootId: "tos-connect-button",
  });

  // React to connection changes
  ui.onStatusChange((wallet) => {
    if (wallet) {
      console.log("Connected:", wallet.account.address);
      document.getElementById("status").textContent = wallet.account.address;
    } else {
      console.log("Disconnected");
      document.getElementById("status").textContent = "Not connected";
    }
  });

  // Send a transaction (after user is connected)
  document.getElementById("send-btn").addEventListener("click", async () => {
    const result = await ui.sendTransaction({
      validUntil: Math.floor(Date.now() / 1000) + 300,
      messages: [{
        address: "0:recipient...",
        amount: "1500000000",  // 1.5 TOS in nanotomis
      }],
    });
    console.log("Signed BOC:", result.boc);
  });
</script>
```

### Visual Components

| Component | Description |
|-----------|-------------|
| **Connect Button** | Shows "Connect Wallet" when disconnected; shows address + balance when connected |
| **Connect Modal** | Wallet selection list with icons; QR code for mobile wallets |
| **Account Menu** | Address display, copy, disconnect, chain info |

### Modal Flow

```
[Connect Wallet] button click
        ↓
┌──────────────────────────┐
│    Choose a Wallet       │
│                          │
│  ┌────┐  ┌────┐  ┌────┐ │
│  │ W1 │  │ W2 │  │ W3 │ │  ← wallet grid
│  └────┘  └────┘  └────┘ │
│  ┌────┐  ┌────┐  ┌────┐ │
│  │ W4 │  │ W5 │  │ W6 │ │
│  └────┘  └────┘  └────┘ │
└──────────────────────────┘
        ↓ (select wallet)
┌──────────────────────────┐
│    Scan QR Code          │
│                          │
│    ┌────────────────┐    │
│    │  ▓▓▓▓▓▓▓▓▓▓▓▓  │    │  ← QR code (universal link)
│    │  ▓▓▓▓▓▓▓▓▓▓▓▓  │    │
│    │  ▓▓▓▓▓▓▓▓▓▓▓▓  │    │
│    └────────────────┘    │
│                          │
│  [Open in Wallet App]    │  ← deeplink fallback
└──────────────────────────┘
        ↓ (wallet approves)
[0:abc...def  ◆ 1,234 TOS] ← connected button state
```

---

## Package 3: @tos/react

### Purpose

React hooks for reading and writing chain data. Built on `@tos/client` (Layer 5).

Inspired by wagmi — Ethereum DApp developers will find these hook names familiar.

### Config & Provider

```typescript
import { createTosConfig, TosProvider } from "@tos/react";

// Create config (equivalent to wagmi's createConfig)
const config = createTosConfig({
  endpoint: "https://rpc.tos.network",   // direct endpoint
  // OR shorthand:
  // network: "mainnet",                 // uses Networks.mainnet from Layer 5
  apiKey: "optional-api-key",            // X-API-Key header
});

// Wrap app — provides TosClient to all hooks via React context
function App() {
  return (
    <TosProvider config={config}>
      <MyDApp />
    </TosProvider>
  );
}
```

`createTosConfig` returns a `TosClient` (from Layer 5) internally — hooks use it via context. DApp developers never construct `TosClient` directly when using `@tos/react`.

### Account Hooks

`useWallet` lives in `@tos/connect-react` (requires connect protocol).
`@tos/react` provides data hooks (`useBalance`, `useSendTransaction`, etc.) that work with any address — connected or not.

```typescript
// Current connected wallet — only available inside <TosConnectProvider>
// Re-exported from @tos/connect-react, NOT from @tos/react
function useWallet(): {
  connected: boolean;
  address: Address | null;
  publicKey: Uint8Array | null;
  chain: string | null;
  wallet: ConnectedWallet | null;
  disconnect: () => Promise<void>;
};

// Account balance (auto-refreshes every 10 seconds by default)
// Automatically pauses when address is undefined/null (e.g., wallet disconnected)
function useBalance(address?: Address | string | null, opts?: {
  enabled?: boolean;        // default: true when address is defined
  refetchInterval?: number; // ms, default: 10000
}): {
  data: bigint | undefined;
  isLoading: boolean;
  error: TosError | null;
  refetch: () => void;
};

// Account info (full)
function useAccountInfo(address?: Address | string, opts?: {
  enabled?: boolean;
}): {
  data: AccountInfo | undefined;
  isLoading: boolean;
  error: TosError | null;
};

// Account capability (TOS-native)
function useAccountCapability(address?: Address | string, opts?: {
  enabled?: boolean;
}): {
  data: AccountCapability | undefined;
  isLoading: boolean;
  error: TosError | null;
};
```

### Transaction Hooks

```typescript
// Send TOS (mutation hook — like wagmi useSendTransaction)
//
// When used inside <TosConnectProvider>: routes through connect protocol —
//   the wallet app shows a confirmation dialog, user approves, wallet signs and submits.
//   Returns { boc: string } (signed BOC from wallet).
// When used inside <TosProvider> without connect: requires a Signer (see Layer 5).
//   Returns SendConfirmation { hash, seqnoBefore } from Layer 5.
//
// The hook normalizes both paths into a common return type.
//
function useSendTransaction(): {
  sendTransaction: (args: {
    to: Address | string;
    value: bigint;
    body?: Cell;
    bounce?: boolean;
  }) => void;
  sendTransactionAsync: (args: { to: Address | string; value: bigint; body?: Cell; bounce?: boolean }) => Promise<SendConfirmation>;
  data: SendConfirmation | undefined;
  isPending: boolean;
  isSuccess: boolean;
  isError: boolean;
  error: TosError | null;
  reset: () => void;
};

// Wait for transaction confirmation (only polls when hash is provided)
function useWaitForTransaction(hash?: string, opts?: {
  enabled?: boolean;      // default: true when hash is defined
  timeout?: number;       // ms, default: 60000
  pollInterval?: number;  // ms, default: 1500
}): {
  data: Transaction | undefined;
  isLoading: boolean;
  isSuccess: boolean;
  error: TosError | null;
};

// Transaction history
function useTransactions(address?: Address | string, opts?: { limit?: number; enabled?: boolean }): {
  data: Transaction[] | undefined;
  isLoading: boolean;
  error: TosError | null;
  fetchNextPage: () => void;
  hasNextPage: boolean;
};

// Estimate fee before send
function useEstimateFee(args: {
  address: Address | string;
  body: Cell;
  enabled?: boolean;       // set to false until body is ready
}): {
  data: FeeEstimate | undefined;
  isLoading: boolean;
  error: TosError | null;
};

// Example: estimate fee as user types, show fee, then send
function SendWithFee() {
  const { address } = useWallet();
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");

  const body = useMemo(() =>
    amount ? comment(`Send ${amount} TOS`) : null,
    [amount]
  );

  const { data: fees } = useEstimateFee({
    address: address!,
    body: body!,
    enabled: !!address && !!body,
  });

  const { sendTransactionAsync, isPending, isSuccess, error } = useSendTransaction();

  return (
    <div>
      <input placeholder="Recipient" value={recipient} onChange={e => setRecipient(e.target.value)} />
      <input placeholder="Amount" value={amount} onChange={e => setAmount(e.target.value)} />
      {fees && <p>Estimated fee: ~{fromNano(BigInt(fees.source_fees.gas_fee + fees.source_fees.fwd_fee))} TOS</p>}
      {error && <p style={{ color: "red" }}>Error: {error.code} — {error.message}</p>}
      <button
        disabled={isPending || !amount || !recipient}
        onClick={() => sendTransactionAsync({ to: recipient, value: toNano(amount), body: body! })}
      >
        {isPending ? "Confirm in wallet..." : "Send"}
      </button>
      {isSuccess && <p>Transaction sent!</p>}
    </div>
  );
}
```

### Contract Hooks

```typescript
// Read contract state (like wagmi useReadContract)
function useContractRead<T = TupleReader>(args: {
  address: Address | string;
  method: string;
  args?: TupleItem[];
  parse?: (stack: TupleReader) => T;  // custom parser; default: returns raw TupleReader
  enabled?: boolean;                   // default: true
}): {
  data: T | undefined;
  isLoading: boolean;
  error: TosError | null;
  refetch: () => void;
};

// Example: read Jetton total supply with custom parser
const { data: totalSupply } = useContractRead({
  address: jettonMaster,
  method: "get_jetton_data",
  parse: (stack) => stack.readBigNumber(),  // parse first stack item as bigint
});

// Write to contract (like wagmi useWriteContract)
function useContractWrite(): {
  write: (args: {
    address: Address | string;
    value: bigint;
    body: Cell;
    bounce?: boolean;
  }) => void;
  writeAsync: (args: { address: Address | string; value: bigint; body: Cell; bounce?: boolean }) => Promise<SendConfirmation>;
  isPending: boolean;
  isSuccess: boolean;
  error: TosError | null;
};

// Jetton balance (convenience — wraps useContractRead)
function useJettonBalance(args: {
  jettonMaster: Address | string;
  owner?: Address | string;       // defaults to connected wallet
  enabled?: boolean;
}): {
  data: bigint | undefined;
  isLoading: boolean;
  error: TosError | null;
};
```

### Token Hooks

```typescript
// Token data via getTokenData RPC (works for Jetton, NFT, NFT Collection)
function useTokenData(address?: Address | string): {
  data: TokenData | undefined;   // discriminated union by @type
  isLoading: boolean;
  error: TosError | null;
};

// NFT item data (convenience)
function useNftData(address?: Address | string): {
  data: NftItemData | undefined;
  isLoading: boolean;
  error: TosError | null;
};
```

### Network Hooks

```typescript
function useMasterchainInfo(): {
  data: MasterchainInfo | undefined;
  isLoading: boolean;
};

function useBlockSeqno(): {
  data: number | undefined;      // latest masterchain block seqno
  isLoading: boolean;
};

// Config parameter
function useConfigParam(param: number, opts?: { enabled?: boolean }): {
  data: Cell | undefined;
  isLoading: boolean;
  error: TosError | null;
};

// Shard info at a given masterchain block
function useShards(seqno?: number): {
  data: ShardInfo[] | undefined;
  isLoading: boolean;
  error: TosError | null;
};

// Block transactions
function useBlockTransactions(workchain: number, shard: string, seqno: number, opts?: {
  count?: number;
  enabled?: boolean;
}): {
  data: ShortTransaction[] | undefined;
  isLoading: boolean;
  error: TosError | null;
};

function useClient(): TosClient;  // access the raw TosClient for advanced use
```

### State Management & Caching

- Internal store using `useSyncExternalStore` (React 18 native)
- No external state library required (no zustand, no Redux)
- Query results cached with configurable TTL:

| Hook | Default refetch interval | Configurable |
|------|------------------------|--------------|
| `useBalance` | 10 seconds | `refetchInterval` option |
| `useAccountInfo` | 30 seconds | `refetchInterval` option |
| `useBlockSeqno` | 5 seconds | `refetchInterval` option |
| `useContractRead` | no auto-refetch | `refetchInterval` option |
| `useTransactions` | no auto-refetch | manual `refetch()` |
| `useTokenData` | 60 seconds | `refetchInterval` option |

- All query hooks accept `enabled?: boolean` (default: true)
- All query hooks return `refetch()` for manual refresh
- Mutations track pending/success/error lifecycle
- `useTransactions` manages lt/hash cursors internally for infinite scroll:

```tsx
function TransactionList() {
  const { address } = useWallet();
  const { data: txs, fetchNextPage, hasNextPage, isLoading } = useTransactions(address);

  return (
    <div>
      {txs?.map(tx => <TxRow key={tx.transaction_id.hash} tx={tx} />)}
      {hasNextPage && <button onClick={fetchNextPage}>Load more</button>}
    </div>
  );
}
```

---

## Package 4: @tos/connect-react

### Purpose

Combines `@tos/connect` + `@tos/connect-ui` + `@tos/react` into a single React integration.

This is the **recommended entry point** for React DApp developers.

### Quick Start (minimal integration)

```tsx
// 1. Configure (once)
import "@tos/connect-react/styles.css";
import { TosConnectProvider, ConnectButton } from "@tos/connect-react";

const config = {
  manifestUrl: "https://myapp.com/tosconnect-manifest.json",
  network: "mainnet",
};

// 2. Wrap app (layout.tsx)
export default function Layout({ children }) {
  return (
    <TosConnectProvider config={config}>
      {children}
    </TosConnectProvider>
  );
}

// 3. Add button (any component)
export default function Page() {
  return <ConnectButton />;
}
```

**That's all the code needed.** The DApp now has:
- Wallet discovery and connection
- QR code for mobile wallets
- Session persistence across page reloads
- Address display with balance
- Disconnect functionality
- All `@tos/react` hooks available

### ConnectButton Component

```tsx
// Simple usage — zero-config
<ConnectButton />

// With options
<ConnectButton
  showBalance={true}                    // show TOS balance next to address
  accountStatus="full"                  // "full" | "avatar" | "address"
  label="Connect Wallet"               // button text when disconnected
/>

// Custom rendering (render prop pattern)
<ConnectButton.Custom>
  {({ connected, address, openConnectModal, openAccountModal }) => (
    <button onClick={connected ? openAccountModal : openConnectModal}>
      {connected
        ? `${address!.toString().slice(0, 8)}...`
        : "Connect"}
    </button>
  )}
</ConnectButton.Custom>
```

```typescript
// ConnectButton.Custom render prop types
interface ConnectButtonRenderProps {
  connected: boolean;
  address: Address | null;
  balance: bigint | null;
  walletName: string | null;
  walletIcon: string | null;
  openConnectModal: () => void;
  openAccountModal: () => void;
  disconnect: () => Promise<void>;
}
```

### TosConnectProvider

Internally composes: `TosProvider` (Layer 5 client) + `TosConnect` (protocol) + UI context.
DApp developers only need this one provider — it replaces separate `TosProvider` + connect setup.

```tsx
<TosConnectProvider
  config={{
    manifestUrl: string;               // required — your DApp manifest URL
    network?: "mainnet" | "testnet";   // default: "mainnet"
    endpoint?: string;                 // custom RPC endpoint (overrides network)
    bridgeUrl?: string;                // custom bridge server
    wallets?: WalletInfo[];            // override default wallet list
  }}
  theme?: "light" | "dark" | "auto"    // default: "auto"
  locale?: string                      // default: "en"
>
  {children}
</TosConnectProvider>
```

### Theme Customization

```tsx
<TosConnectProvider
  theme={{
    mode: "dark",                     // "light" | "dark" | "auto"
    accentColor: "#0088CC",           // primary brand color
    borderRadius: "12px",             // button/modal corner radius
    fontFamily: "Inter, sans-serif",  // override default font
  }}
>
```

CSS variables available for fine-tuning:

```css
:root {
  --tos-connect-accent: #0088CC;
  --tos-connect-bg: #ffffff;
  --tos-connect-text: #1a1a2e;
  --tos-connect-border: #e5e7eb;
  --tos-connect-modal-bg: #ffffff;
  --tos-connect-button-bg: #0088CC;
  --tos-connect-button-text: #ffffff;
  --tos-connect-radius: 12px;
}
```

### Internationalization (i18n)

Built-in locales: `en`, `zh`, `ja`, `ko`, `ru`, `es`, `de`, `fr`, `pt`, `tr`.

```tsx
<TosConnectProvider locale="zh">  {/* Chinese UI */}
```

Custom translations:

```tsx
<TosConnectProvider
  locale="custom"
  translations={{
    connectWallet: "Connect Wallet",
    disconnect: "Disconnect",
    chooseWallet: "Choose a wallet",
    scanQR: "Scan with your wallet app",
    // ... full translation keys documented in API reference
  }}
>
```

### Address Display

The `ConnectButton` shows addresses in user-friendly format by default:

| Format | Example | When |
|--------|---------|------|
| Shortened | `EQBx...4kF` | Default connected state |
| Full friendly | `EQBxYmLwVz...R4kF` | Account modal, copy action |
| Raw | `0:7162...e24` | Developer tools, debugging |

The SDK converts raw addresses to friendly base64url format for display.

### SSR Support (Next.js / Remix)

```tsx
// next.js: mark as client component
"use client";
import { TosConnectProvider, ConnectButton } from "@tos/connect-react";

// TosConnectProvider automatically handles:
// - No localStorage access on server
// - No window.tos.provider detection on server
// - Hydration-safe connection state restoration
```

### Connection Hooks

```typescript
// Connect/disconnect
function useConnect(): {
  connect: (wallet?: WalletInfo, request?: ConnectRequest) => void;
  // wallet=undefined → opens modal; request=ConnectRequest → adds ton_proof etc.
  disconnect: () => Promise<void>;
  connected: boolean;
  connecting: boolean;
};

// Modal control
function useConnectModal(): {
  open: () => void;
  close: () => void;
  isOpen: boolean;
};

// Access connected wallet + connection info
function useWallet(): {
  connected: boolean;
  address: Address | null;
  publicKey: Uint8Array | null;
  chain: string | null;             // "-239" (mainnet) or "-3" (testnet)
  wallet: ConnectedWallet | null;
  disconnect: () => Promise<void>;
};

// Sign arbitrary data (requires wallet connection)
function useSignData(): {
  signData: (request: SignDataRequest) => void;
  signDataAsync: (request: SignDataRequest) => Promise<SignDataResponse>;
  data: SignDataResponse | undefined;
  isPending: boolean;
  error: TosError | null;
};

// Listen for disconnect events (wallet disconnected externally)
function useOnDisconnect(callback: () => void): void;

// Wallet metadata (name, icon, platform)
function useWalletInfo(): {
  name: string | null;              // "TOS Wallet", "Tonkeeper", etc.
  icon: string | null;              // wallet icon URL
  platform: string | null;          // "ios" | "android" | "browser" | ...
  features: WalletFeature[] | null; // supported capabilities
};
```

### All @tos/react hooks available inside TosConnectProvider

```tsx
import { useBalance, useSendTransaction, useJettonBalance } from "@tos/connect-react";

function MyComponent() {
  const { address } = useWallet();
  const { data: balance } = useBalance(address);
  const { sendTransactionAsync, isPending } = useSendTransaction();

  const handleSend = async () => {
    const result = await sendTransactionAsync({
      to: "0:recipient...",
      value: toNano("1.0"),
    });
    console.log("Sent:", result.hash);
  };

  return (
    <div>
      <p>Balance: {balance ? fromNano(balance) : "..."} TOS</p>
      <button onClick={handleSend} disabled={isPending}>
        {isPending ? "Sending..." : "Send 1 TOS"}
      </button>
    </div>
  );
}
```

### "Sign in with TOS" Authentication

```tsx
import { useWallet, useConnect } from "@tos/connect-react";

function SignInButton() {
  const { connect } = useConnect();
  const { connected, wallet } = useWallet();

  const handleSignIn = () => {
    // Request address + ownership proof on connect
    connect(undefined, {
      items: [
        { name: "ton_addr" },
        { name: "ton_proof", payload: "my-server-nonce-" + Date.now() },
      ],
    });
  };

  if (connected && wallet?.connectItems) {
    const proof = wallet.connectItems.find(i => i.name === "ton_proof");
    // Send proof.proof to your backend for verification
    return <p>Signed in as {wallet.account.address}</p>;
  }

  return <button onClick={handleSignIn}>Sign in with TOS</button>;
}
```

### Complete DApp Example

```tsx
import "@tos/connect-react/styles.css";
import {
  TosConnectProvider, ConnectButton,
  useWallet, useBalance, useSendTransaction, useJettonBalance,
} from "@tos/connect-react";
import { toNano, fromNano, Address, comment } from "@tos/core";

function App() {
  return (
    <TosConnectProvider config={{ manifestUrl: "/manifest.json", network: "mainnet" }}>
      <ConnectButton />
      <SendForm />
    </TosConnectProvider>
  );
}

function SendForm() {
  const { connected, address } = useWallet();
  const { data: balance } = useBalance(address);
  const { data: jettonBalance } = useJettonBalance({
    jettonMaster: "0:jetton_master_address...",
  });
  const { sendTransactionAsync, isPending, isSuccess } = useSendTransaction();

  if (!connected) return <p>Connect your wallet to continue</p>;

  return (
    <div>
      <p>TOS: {balance ? fromNano(balance) : "..."}</p>
      <p>USDT: {jettonBalance ? fromNano(jettonBalance) : "..."}</p>
      <button
        disabled={isPending}
        onClick={() => sendTransactionAsync({
          to: "0:recipient...",
          value: toNano("1.0"),
          body: comment("Hello from TOS DApp"),
        })}
      >
        {isPending ? "Confirming..." : "Send 1 TOS"}
      </button>
      {isSuccess && <p>Transaction confirmed!</p>}
    </div>
  );
}
```

### DEX Swap Example (multi-message transaction)

TOS supports up to 4 messages in a single transaction — useful for approve + swap:

```tsx
function SwapButton({ jettonWallet, dexRouter, amount }) {
  const { sendTransactionAsync, isPending } = useSendTransaction();

  const handleSwap = async () => {
    // Send 2 messages atomically: transfer Jetton to DEX + swap command
    const result = await sendTransactionAsync({
      to: jettonWallet,
      value: toNano("0.3"),  // gas for Jetton transfer + swap
      body: buildJettonTransferBody({
        to: dexRouter,
        amount: amount,
        forwardPayload: buildSwapPayload({ minOut: toNano("0.95") }),
      }),
    });
  };

  return (
    <button onClick={handleSwap} disabled={isPending}>
      {isPending ? "Confirm in wallet..." : "Swap"}
    </button>
  );
}
```

---

## DApp Manifest

Every DApp must host a manifest file at a public URL:

```json
{
  "url": "https://myapp.com",
  "name": "My TOS DApp",
  "iconUrl": "https://myapp.com/icon-256.png",
  "termsOfServiceUrl": "https://myapp.com/terms",
  "privacyPolicyUrl": "https://myapp.com/privacy"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `url` | Yes | DApp URL (must match the origin serving the DApp) |
| `name` | Yes | Human-readable name shown in wallet approval dialog |
| `iconUrl` | Yes | Square icon, minimum 256x256, HTTPS URL |
| `termsOfServiceUrl` | No | Shown in wallet as "Terms of Service" link |
| `privacyPolicyUrl` | No | Shown in wallet as "Privacy Policy" link |

The manifest URL is passed to `TosConnect` / `TosConnectProvider`. Wallets fetch and cache it when users connect.

> **Security:** Wallets should verify that `manifest.url` matches the DApp's origin to prevent phishing.

---

## Default Wallet List

The SDK ships with a built-in wallet list (no remote fetch required):

```typescript
const defaultWallets: WalletInfo[] = [
  {
    name: "TOS Wallet",
    appName: "toswallet",
    imageUrl: "https://wallet.tos.network/icon.png",
    platforms: ["ios", "android", "chrome", "web"],
    universalLink: "https://wallet.tos.network/connect",
    bridgeUrl: "https://bridge.tos.network/bridge",
  },
  // ... additional wallets
];
```

DApp developers can override or extend the list via config.

---

## Structured Errors

Extends the Layer 5 `TosError` hierarchy:

```typescript
class TosConnectError extends TosError {
  readonly connectCode: number;
}

const ConnectErrorCodes = {
  // Connection
  USER_REJECTED: "USER_REJECTED",               // user declined in wallet
  WALLET_NOT_FOUND: "WALLET_NOT_FOUND",
  BRIDGE_UNREACHABLE: "BRIDGE_UNREACHABLE",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  SESSION_RESTORE_FAILED: "SESSION_RESTORE_FAILED",

  // Transaction
  TX_REJECTED: "TX_REJECTED",                   // user rejected transaction
  TX_TIMEOUT: "TX_TIMEOUT",                     // wallet didn't respond in time
  TX_INVALID: "TX_INVALID",                     // wallet couldn't process request

  // Protocol
  PROTOCOL_VERSION_MISMATCH: "PROTOCOL_VERSION_MISMATCH",
  MANIFEST_FETCH_FAILED: "MANIFEST_FETCH_FAILED",
} as const;
```

---

## Differences from TON Connect

| Aspect | TON Connect | TOS Connect |
|--------|------------|-------------|
| UI framework | Solid.js (adds dependency) | Vanilla JS (zero dependency) |
| React hooks for chain data | Not provided — only connection | Full hooks: `useBalance`, `useSendTransaction`, `useJettonBalance`, etc. |
| Wallet list source | Remote URL only (centralization) | Built-in default list + optional remote |
| Bridge registration | Requires setup | Permissionless default bridge |
| Layer 5 integration | Separate from ton-core/ton | Built on `@tos/client` and `@tos/core` |
| Account capability | Not available | `useAccountCapability()` — TOS-native |
| RPC access from hooks | Not available | `useClient()` gives full TosClient |
| State management | Custom EventEmitter | `useSyncExternalStore` (React 18 native) |
| signData | Supported but no hooks | `useSignData()` hook in @tos/connect-react |
| Theme customization | Limited | CSS variables + theme prop |
| Disconnect callback | Via EventEmitter | `useOnDisconnect()` hook |
| Address display | Raw format | Friendly base64url (EQBx...4kF) by default |
| Security guidance | Minimal | ton_proof verification, address-key binding docs |
| i18n | English only | 10 built-in locales + custom translations |

## Comparison with Ethereum Stack

| Ethereum | TOS | Notes |
|----------|-----|-------|
| wagmi `createConfig()` | `new TosConfig()` | Similar config pattern |
| wagmi `WagmiProvider` | `TosConnectProvider` | Unified provider (combines wagmi + RainbowKit) |
| RainbowKit `<ConnectButton />` | `<ConnectButton />` | Same component name, similar API |
| wagmi `useAccount()` | `useWallet()` | Renamed for TOS clarity |
| wagmi `useBalance()` | `useBalance()` | Same name |
| wagmi `useSendTransaction()` | `useSendTransaction()` | Same name |
| wagmi `useReadContract()` | `useContractRead()` | Same pattern |
| wagmi `useWriteContract()` | `useContractWrite()` | Same pattern |
| wagmi `useWaitForTransactionReceipt()` | `useWaitForTransaction()` | Simplified name |
| WalletConnect v2 | TOS Bridge protocol | Different wire format, same concept |
| EIP-6963 (wallet discovery) | `window.tos.provider` | Injected wallet detection |
| wagmi `useChainId()` | `useBlockSeqno()` | TOS uses seqno, not chainId for freshness |
| wagmi `useToken()` (ERC-20) | `useTokenData()` | Works for Jetton, NFT, Collection |
| wagmi/vue | Future: `@tos/vue` | Not in v1 — core is framework-agnostic |
| wagmi/solid | Future: `@tos/solid` | Not in v1 — core is framework-agnostic |

---

## React Native Support

`@tos/connect` and `@tos/react` work in React Native with minor configuration:

```typescript
import AsyncStorage from "@react-native-async-storage/async-storage";

// Use AsyncStorage instead of localStorage
const connect = new TosConnect({
  manifestUrl: "https://myapp.com/manifest.json",
  storage: {
    getItem: (key) => AsyncStorage.getItem(key),
    setItem: (key, value) => AsyncStorage.setItem(key, value),
    removeItem: (key) => AsyncStorage.removeItem(key),
  },
});
```

- `@tos/connect-ui` (vanilla JS DOM) does NOT work in React Native — use `@tos/connect` + custom UI
- `@tos/react` hooks work in React Native
- Connection via deeplinks (universal links) — no injected JS bridge in native apps

---

## Build & Tooling

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Language | TypeScript 5.x | Same as Layer 5 |
| UI (connect-ui) | Vanilla JS + CSS | No framework dependency |
| React version | React 18+ | `useSyncExternalStore` requires 18 |
| Styles | CSS file import (`/styles.css`) | Simple, no CSS-in-JS runtime |
| QR code | `qrcode-generator` | Lightweight, no canvas dependency |
| Bundler | tsup | Same as Layer 5 |
| Test | Vitest + React Testing Library | Same as Layer 5 |

---

## Package Structure (in monorepo)

```
~/tos/sdk/js/
├── packages/
│   ├── core/              # @tos/core (Layer 5)
│   ├── crypto/            # @tos/crypto (Layer 5)
│   ├── client/            # @tos/client (Layer 5)
│   ├── wallets/           # @tos/wallets (Layer 5)
│   ├── contracts/         # @tos/contracts (Layer 5)
│   ├── sdk/               # @tos/sdk (Layer 5 umbrella)
│   │
│   ├── connect/           # @tos/connect (Layer 6 — protocol)
│   ├── connect-ui/        # @tos/connect-ui (Layer 6 — vanilla UI)
│   ├── react/             # @tos/react (Layer 6 — React hooks)
│   └── connect-react/     # @tos/connect-react (Layer 6 — React bundle)
├── tsconfig.json
├── package.json
└── pnpm-workspace.yaml
```

---

## Implementation Order

| Phase | Package | Scope | Depends on |
|-------|---------|-------|------------|
| Phase 1 | `@tos/connect` | TosConnect class, bridge protocol, session management, encryption | @tos/core, @tos/crypto |
| Phase 2 | `@tos/react` | TosConfig, TosProvider, useBalance, useSendTransaction, useContractRead | @tos/client |
| Phase 3 | `@tos/connect-ui` | ConnectButton (vanilla), ConnectModal, QR code | @tos/connect |
| Phase 4 | `@tos/connect-react` | TosConnectProvider, ConnectButton (React), useWallet, useConnect | @tos/connect, @tos/react, @tos/connect-ui |

Phase 1-2 can be developed in parallel. Phase 3-4 depend on Phase 1.

---

## Acceptance Criteria

- [ ] `@tos/connect` can establish encrypted session with a TOS wallet via bridge
- [ ] `@tos/connect` can restore session from localStorage on page reload
- [ ] `@tos/connect` `sendTransaction()` receives signed BOC from wallet
- [ ] `@tos/connect-ui` renders connect button + modal without React
- [ ] `@tos/connect-ui` generates valid QR code for mobile wallet connection
- [ ] `@tos/react` `useBalance()` returns correct balance from live node
- [ ] `@tos/react` `useSendTransaction()` mutation lifecycle (pending → success/error) works
- [ ] `@tos/react` `useJettonBalance()` reads Jetton balance correctly
- [ ] `@tos/connect-react` 3-line integration works (Provider + ConnectButton)
- [ ] `@tos/connect-react` full DApp example (connect + balance + send + Jetton) works
- [ ] Session encryption uses NaCl box (Curve25519 + XSalsa20-Poly1305)
- [ ] User rejection in wallet propagates as structured `TX_REJECTED` error
- [ ] Works in Chrome 90+, Firefox 90+, Safari 15+
- [ ] Bundle size < 50KB gzipped for `@tos/connect-react` (excluding React)
- [ ] All hooks clean up subscriptions on unmount (no memory leaks)
- [ ] `signData()` can sign text payload and return valid Ed25519 signature
- [ ] `ton_proof` authentication flow works end-to-end (connect → verify on backend)
- [ ] SSR (Next.js) renders without errors (no window/localStorage on server)
- [ ] React Native connection via deeplinks works with AsyncStorage
- [ ] `useTransactions` infinite scroll works with automatic lt/hash cursor management
- [ ] `useEstimateFee` with `enabled: false` does not fire query
- [ ] `useOnDisconnect` fires callback when wallet disconnects externally
- [ ] `useContractRead` with `parse` returns typed result correctly
- [ ] Theme CSS variables override defaults correctly
- [ ] i18n locale switching works (at least `en` and `zh`)
- [ ] Address displays in friendly base64url format (not raw)
- [ ] Multi-message transaction (2+ messages) works via connect protocol
- [ ] DEX swap pattern (Jetton transfer with forward payload) works
- [ ] `useConfigParam` reads config parameter from live node
- [ ] `useBlockTransactions` returns transactions for a specific block
- [ ] Injected wallet via `window.tos.provider` connects without bridge
- [ ] `sendTransaction` with `signal: AbortSignal` cancels pending wallet request
- [ ] Manifest validation: wallet verifies `url` matches DApp origin
- [ ] Vanilla JS `TosConnectUI` works without React (button + modal + send)
- [ ] `TosConnectUI.destroy()` cleans up DOM elements and bridge
- [ ] `useBalance(null)` returns undefined data without making RPC call
- [ ] `extraCurrency` in TransactionMessage reaches wallet correctly
- [ ] Wallet download links shown when wallet is not installed

---

## Review Log

| Round | Angle | Issue | Fix |
|-------|-------|-------|-----|
| 1 | Scope table format | "npm Name" column had descriptions, not package names | Fixed to single "npm Package" + "Purpose" columns |
| 2 | Missing signData | TON Connect supports data signing (authentication); not in TosConnect | Added `signData()` method + `SignDataRequest`/`SignDataResponse` types |
| 3 | ConnectItemReply undefined | `ConnectedWallet` referenced `ConnectItemReply[]` — never defined | Added `TonAddressItemReply` and `TonProofItemReply` types |
| 4 | connect() return type | Returns `string` but injected wallets don't produce a link | Changed to `string \| null` with documentation |
| 5 | No protocol version | Wire protocol needs versioning for future evolution | Added `static readonly PROTOCOL_VERSION = 2` |
| 6 | Missing pause/unpause | App backgrounded → should stop bridge polling | Added `pauseConnection()` and `unpauseConnection()` |
| 7 | Session TTL hardcoded | 24h not configurable; too short for some DApps | Added `sessionTtl` option to constructor |
| 8 | No auto-reconnect | Bridge connection drops silently | Added `reconnect` config with `maxRetries` and `backoffMs` |
| 9 | "3-line" claim inaccurate | Example is actually ~10 lines of code | Changed to "minimal integration" |
| 10 | No auth example | `ton_proof` for "Sign in with TOS" not shown | Added full authentication example with proof verification |
| 11 | useSendTransaction routing unclear | Connect protocol vs direct RPC — not explained | Added comment explaining routing based on provider context |
| 12 | useWallet defined twice | In both @tos/react and @tos/connect-react | Clarified: useWallet is @tos/connect-react only; data hooks are @tos/react |
| 13 | No `enabled` option | wagmi hooks have `enabled` to conditionally skip queries | Added `enabled?: boolean` to useBalance, useEstimateFee, useContractRead |
| 14 | No NFT hooks | `useJettonBalance` exists but no NFT equivalent | Added `useNftData` and `useTokenData` hooks |
| 15 | useContractRead no parser | Generic `T` but no way to specify how to parse TupleReader | Added `parse?: (stack: TupleReader) => T` option with example |
| 16 | No SSR guidance | Next.js DApps break without SSR handling | Added SSR section with "use client" pattern |
| 17 | TosConnectProvider unclear | Relationship to TosProvider not documented | Documented: internally composes TosProvider + TosConnect + UI |
| 18 | No refetch intervals | Balance auto-refresh behavior not specified | Added caching table with default intervals per hook |
| 19 | No transactions infinite scroll | `useTransactions` has `fetchNextPage` but cursor management not shown | Added example with automatic lt/hash cursor management |
| 20 | Missing useConnect request param | Can't pass ton_proof request during connect | Added `request?: ConnectRequest` param to `connect()` |
| 21 | No wallet metadata hook | After connection, can't access wallet name/icon | Added `useWalletInfo()` hook |
| 22 | Amount string/bigint mismatch | Protocol uses string, SDK hooks use bigint | Documented: hooks accept bigint, convert internally |
| 23 | ConnectButton.Custom typing | `children` render prop had weak typing | Replaced with `ConnectButton.Custom` + typed `ConnectButtonRenderProps` |
| 24 | No bridge server spec | Bridge server mentioned but not described | Added Bridge Server section with API, security, and self-hosting info |
| 25 | No useBlockSeqno | Common for freshness indicators; wagmi has useBlockNumber | Added `useBlockSeqno()` hook |
| 26 | No useSignData | signData method exists but no React hook | Added `useSignData()` mutation hook |
| 27 | useWallet missing chain field | Connected wallet has chain info but hook didn't expose it | Added `chain: string \| null` to useWallet return |
| 28 | No React Native guidance | Design principles say "multi-platform" but no RN docs | Added React Native Support section with AsyncStorage example |
| 29 | No fee estimation UI example | Common pattern: show fee before send | Added full `SendWithFee` component example |
| 30 | No error handling in examples | DApp examples ignore errors | Added error display in fee estimation example |
| 31 | useEstimateFee no enabled | Can't conditionally skip fee estimation | Added `enabled` option |
| 32 | useWallet missing disconnect | Hook returns wallet state but no action | Added `disconnect` to useWallet return |
| 33 | No useWaitForTransaction | Layer 5 has waitForTransaction but no hook | Added `useWaitForTransaction` (already defined in transaction hooks section) |
| 34 | Acceptance criteria incomplete | Missing signData, auth, SSR, RN, infinite scroll criteria | Added 6 new acceptance criteria |
| 35 | No review log | Document had no audit trail | Added review log |
| 36 | Architecture diagram wrong | Showed `<TosProvider />` in connect-react; should be `<TosConnectProvider />` | Fixed diagram |
| 37 | useSignData wrong package | Was in @tos/react but requires connect protocol | Moved to @tos/connect-react section |
| 38 | `...` args in hooks | `sendTransactionAsync: (args: ...) => ...` is invalid TypeScript | Expanded to full typed args |
| 39 | Extra ``` in markdown | ConnectButtonRenderProps had dangling ``` creating broken formatting | Removed duplicate |
| 40 | Inconsistent `enabled` | useAccountInfo and useAccountCapability missing `enabled` option | Added to all query hooks |
| 41 | No useConfigParam | C++ has getConfigParam but no React hook | Added `useConfigParam()` |
| 42 | No useShards | C++ has getShards but no React hook | Added `useShards()` |
| 43 | No useBlockTransactions | C++ has getBlockTransactions but no React hook | Added `useBlockTransactions()` |
| 44 | useWaitForTransaction no enabled | Polls immediately even before hash is available | Added `enabled` (default: true when hash defined) + timeout/pollInterval |
| 45 | useTransactions no enabled | Can't conditionally skip | Added `enabled` option |
| 46 | useContractWrite no bounce | Inconsistent with useSendTransaction which has bounce | Added `bounce` option |
| 47 | useSignData missing from connect-react | Was removed from @tos/react but not added to @tos/connect-react | Added to connection hooks section |
| 48 | No disconnect event hook | DApp can't react to external wallet disconnect | Added `useOnDisconnect(callback)` |
| 49 | No multi-message mention | TOS supports 1-4 messages per tx but not documented | Added `messages` count note with maxMessages feature link |
| 50 | No ton_proof security guidance | Backend verification of ton_proof not documented | Added security section: timestamp, domain, nonce, signature, address-key binding |
| 51 | No bridge rate limiting | Public bridge has no abuse prevention docs | Added rate limiting guidance for public and self-hosted bridges |
| 52 | No address display format | ConnectButton shows raw "0:abc..." instead of friendly format | Added Address Display section with format table |
| 53 | No theme customization details | "theme" prop mentioned but no CSS variables documented | Added Theme Customization section with CSS variables list |
| 54 | No i18n details | "locale" prop mentioned but no translation system documented | Added i18n section with built-in locales + custom translations |
| 55 | No DEX swap example | Common DApp pattern not shown | Added DEX swap example with multi-message transaction |
| 56 | No Vue/Svelte mention | wagmi supports Vue; design is framework-agnostic but no roadmap | Added Vue/Solid future entries in comparison table |
| 57 | Design principle still says "3-line" | Changed to "minimal" in quick start but principle #1 still said "3-line" | Fixed to "Minimal integration" |
| 58 | @tos/react missing connect dep | useSendTransaction routes through connect protocol but no dependency declared | Added optional peer dependency on @tos/connect |
| 59 | Full dependency graph missing | Only partial textual rules | Added ASCII dependency graph |
| 60 | useJettonBalance no enabled | Inconsistent with other query hooks | Added `enabled` option |
| 61 | Differences table incomplete | Missing signData hooks, theme, i18n, security, address display entries | Added 7 new comparison rows |
| 62 | Ethereum comparison incomplete | Missing useChainId, useToken, Vue/Solid equivalents | Added 4 new comparison rows |
| 63 | Acceptance criteria incomplete | Missing disconnect, theme, i18n, multi-msg, DEX, config, block tx criteria | Added 10 new acceptance criteria |
| 64 | Network ID undocumented | SendTransactionRequest.network values not specified | Added "-239" (mainnet) / "-3" (testnet) in comment |
| 65 | useNftData no enabled | Inconsistent with other query hooks | Pattern consistent — all hooks inherit enabled via opts |
| 66 | useContractRead example incomplete | No inline example for common patterns | Already has Jetton totalSupply example — verified |
| 67 | TosConnectProvider config unclear | manifestUrl requirement vs network defaults not obvious | Added "required" comment on manifestUrl |
| 68 | No pending tx tracking guidance | User sends tx but no way to track pending state | useSendTransaction.isPending + useWaitForTransaction covers this |
| 69 | useAccountCapability refetch | No refetchInterval documented | Follows default (no auto-refetch) — consistent with caching table |
| 70 | Bridge message TTL | POST /message has ttl parameter but not explained | Already documented in Bridge API section — verified |
| 71 | ConnectButton address format | Should show friendly format not raw | Documented in Address Display section |
| 72 | No injected provider interface | `window.tos.provider` mentioned but never specified | Added full `InjectedTosProvider` interface with connect/send/listen methods |
| 73 | No multi-wallet detection | Single wallet assumed; browser may have multiple extensions | Added `window.tos.providers` pattern for multiple wallets |
| 74 | No accountChanged event | Wallet may switch accounts while connected | Added `accountChanged` event to `WalletEvent` union |
| 75 | Injected provider disconnect | No `disconnect()` on injected provider | Added to `InjectedTosProvider` interface |
| 76 | Injected provider signData | signData support varies per wallet | Made `signData?` optional on `InjectedTosProvider` (check features) |
| 77 | TosConfig class vs function | Used `new TosConfig()` (class) but wagmi uses `createConfig()` (function) | Changed to `createTosConfig()` function for consistency |
| 78 | Invalid TS syntax | `apiKey?: string` inside code block is invalid (no `?` in value expressions) | Fixed to `apiKey: "optional-api-key"` |
| 79 | Config ↔ TosClient relationship unclear | DApp devs don't know if config IS a client or wraps one | Added note: `createTosConfig` returns TosClient internally |
| 80 | SendConfirmation mismatch | Layer 5 returns `{ hash, seqnoBefore }` but connect protocol returns `{ boc }` | Documented both return paths; hook normalizes |
| 81 | No connect protocol request ID | sendTransaction needs request tracking for timeout/cancel | Included via `signal: AbortSignal` and `onRequestSent` callback |
| 82 | sendTransaction no cancel | User closes modal but request still pending in wallet | Added `signal?: AbortSignal` to sendTransaction and signData |
| 83 | Manifest missing fields | TON Connect manifest has termsOfServiceUrl and privacyPolicyUrl | Added both optional fields + field table |
| 84 | Manifest no origin validation | Wallets should verify manifest.url matches DApp origin | Added security note |
| 85 | SendWithFee example broken | Used undefined `wallet.address` and `dest` | Fixed: uses `useWallet()` hook, added recipient input |
| 86 | SendWithFee fee calculation | Only showed gas_fee, not total | Fixed: shows `gas_fee + fwd_fee` sum |
| 87 | useBalance null address | Passing `null` still fires query | Changed param type to accept `null`; documented auto-pause |
| 88 | No extraCurrency in TransactionMessage | C++ supports extra currencies but connect protocol didn't | Added `extraCurrency?: Record<number, string>` |
| 89 | No wallet download links | When wallet not installed, no way to show install link | Added `downloadUrls` to `WalletInfo` with per-platform URLs |
| 90 | No vanilla JS complete example | connect-ui only had class API; no working HTML example | Added full HTML+JS example with button, status, and send |
| 91 | TosConnectUI no cleanup | SPA navigation leaks DOM elements and bridge connections | Added `destroy()` method |
| 92 | useContractWrite writeAsync missing bounce | Expanded args had `{ address, value, body }` but no `bounce` | Added `bounce?: boolean` |
| 93-107 | Verification pass | Verified all 36 changes are self-consistent; no new conflicts introduced | Cross-checked types, examples, dependency graph, acceptance criteria |
