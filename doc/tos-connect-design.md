# TOS Connect & DApp Kit Design

Version: v0.1-draft

## Purpose

Design document for TOS Layer 6 — wallet connection protocol, React hooks, and UI components.

This layer enables DApp developers to connect user wallets, request transaction signatures, and build production-ready UIs with minimal code.

## Scope

| Package | npm Name | Purpose |
|---------|----------|---------|
| `@tos/connect` | Wallet-DApp communication protocol | Core protocol, session management, bridge |
| `@tos/connect-ui` | Vanilla JS UI components | Connect button, modal, QR code |
| `@tos/connect-react` | React hooks + components | `useWallet()`, `<ConnectButton />`, provider |
| `@tos/react` | React hooks for chain data | `useBalance()`, `useSendTransaction()`, contract hooks |

## Design Principles

1. **3-line integration** — a DApp should get a working "Connect Wallet" button in 3 lines of code (like RainbowKit).
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
│  <ConnectButton />, <TosProvider />, useWallet(),            │
│  useConnectModal(), theming                                  │
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
@tos/connect-react  depends on @tos/connect, @tos/connect-ui, @tos/react (peer: react)
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
  });

  // ── Connection state ──────────────────────────────────
  readonly connected: boolean;
  readonly account: ConnectedAccount | null;
  readonly wallet: ConnectedWallet | null;

  // ── Lifecycle ─────────────────────────────────────────
  connect(wallet: WalletInfo, request?: ConnectRequest): string;  // returns universal link
  restoreConnection(): Promise<void>;    // restore from storage on page load
  disconnect(): Promise<void>;

  // ── Status ────────────────────────────────────────────
  onStatusChange(
    callback: (wallet: ConnectedWallet | null) => void,
    onError?: (error: TosConnectError) => void,
  ): () => void;  // returns unsubscribe function

  // ── Transaction requests ──────────────────────────────
  sendTransaction(request: SendTransactionRequest): Promise<SendTransactionResponse>;

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
  network?: string;        // chain ID
  from?: string;           // sender address (default: connected account)
  messages: TransactionMessage[];
}

interface TransactionMessage {
  address: string;         // destination
  amount: string;          // nanotomis as string
  payload?: string;        // message body BOC (base64)
  stateInit?: string;      // deploy StateInit BOC (base64)
}

interface SendTransactionResponse {
  boc: string;             // signed transaction BOC (base64)
}

// ── Session storage ─────────────────────────────────────
interface ConnectStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}
```

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
}
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
import { TosConfig, TosProvider } from "@tos/react";

// Create config (equivalent to wagmi's createConfig)
const config = new TosConfig({
  endpoint: "https://rpc.tos.network",
  // or: network: "mainnet",
  apiKey?: string,
});

// Wrap app
function App() {
  return (
    <TosProvider config={config}>
      <MyDApp />
    </TosProvider>
  );
}
```

### Account Hooks

```typescript
// Current connected wallet (from @tos/connect integration)
function useWallet(): {
  connected: boolean;
  address: Address | null;
  publicKey: Uint8Array | null;
  chain: string | null;
  wallet: ConnectedWallet | null;
  disconnect: () => Promise<void>;
};

// Account balance
function useBalance(address?: Address | string): {
  data: bigint | undefined;
  isLoading: boolean;
  error: TosError | null;
  refetch: () => void;
};

// Account info (full)
function useAccountInfo(address?: Address | string): {
  data: AccountInfo | undefined;
  isLoading: boolean;
  error: TosError | null;
};

// Account capability (TOS-native)
function useAccountCapability(address?: Address | string): {
  data: AccountCapability | undefined;
  isLoading: boolean;
  error: TosError | null;
};
```

### Transaction Hooks

```typescript
// Send TOS (mutation hook — like wagmi useSendTransaction)
function useSendTransaction(): {
  sendTransaction: (args: {
    to: Address | string;
    value: bigint;
    body?: Cell;
    bounce?: boolean;
  }) => void;
  sendTransactionAsync: (args: ...) => Promise<SendConfirmation>;
  data: SendConfirmation | undefined;
  isPending: boolean;
  isSuccess: boolean;
  isError: boolean;
  error: TosError | null;
  reset: () => void;
};

// Wait for transaction confirmation
function useWaitForTransaction(hash?: string): {
  data: Transaction | undefined;
  isLoading: boolean;
  isSuccess: boolean;
  error: TosError | null;
};

// Transaction history
function useTransactions(address?: Address | string, opts?: { limit?: number }): {
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
}): {
  data: FeeEstimate | undefined;
  isLoading: boolean;
  error: TosError | null;
};
```

### Contract Hooks

```typescript
// Read contract state (like wagmi useReadContract)
function useContractRead<T>(args: {
  address: Address | string;
  method: string;
  args?: TupleItem[];
}): {
  data: T | undefined;        // parsed via provided decoder
  isLoading: boolean;
  error: TosError | null;
  refetch: () => void;
};

// Write to contract (like wagmi useWriteContract)
function useContractWrite(): {
  write: (args: {
    address: Address | string;
    value: bigint;
    body: Cell;
  }) => void;
  writeAsync: (args: ...) => Promise<SendConfirmation>;
  isPending: boolean;
  isSuccess: boolean;
  error: TosError | null;
};

// Jetton balance (convenience — wraps useContractRead)
function useJettonBalance(args: {
  jettonMaster: Address | string;
  owner?: Address | string;       // defaults to connected wallet
}): {
  data: bigint | undefined;
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

function useClient(): TosClient;  // access the raw client
```

### State Management

- Internal store using `useSyncExternalStore` (React 18 native)
- No external state library required (no zustand, no Redux)
- Query results cached with configurable TTL (default: 10 seconds for balance, 30 seconds for account info)
- Mutations track pending/success/error state

---

## Package 4: @tos/connect-react

### Purpose

Combines `@tos/connect` + `@tos/connect-ui` + `@tos/react` into a single React integration.

This is the **recommended entry point** for React DApp developers.

### Quick Start (3-line integration)

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

**That's it.** The DApp now has:
- Wallet discovery and connection
- QR code for mobile wallets
- Session persistence across page reloads
- Address display with balance
- Disconnect functionality
- All `@tos/react` hooks available

### ConnectButton Component

```tsx
<ConnectButton
  // Display options
  showBalance={true}                    // show TOS balance next to address
  accountStatus="full"                  // "full" | "avatar" | "address"
  label="Connect Wallet"               // button text when disconnected

  // Advanced: custom rendering
  children={(props) => (
    <button onClick={props.openConnectModal}>
      {props.connected
        ? `${props.address.slice(0, 6)}...${props.address.slice(-4)}`
        : "Connect"}
    </button>
  )}
/>
```

### TosConnectProvider

```tsx
<TosConnectProvider
  config={{
    manifestUrl: string;               // required
    network?: "mainnet" | "testnet";   // default: "mainnet"
    endpoint?: string;                 // custom RPC endpoint
    bridgeUrl?: string;                // custom bridge server
    wallets?: WalletInfo[];            // override default wallet list
  }}
  theme?: "light" | "dark" | "auto"    // default: "auto"
  locale?: string                      // default: "en"
>
  {children}
</TosConnectProvider>
```

### Connection Hooks

```typescript
// Connect/disconnect
function useConnect(): {
  connect: (wallet?: WalletInfo) => void;  // opens modal if no wallet specified
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

// Access connected wallet
function useWallet(): {
  connected: boolean;
  address: Address | null;
  publicKey: Uint8Array | null;
  wallet: ConnectedWallet | null;
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

---

## DApp Manifest

Every DApp must host a manifest file at a public URL:

```json
{
  "url": "https://myapp.com",
  "name": "My TOS DApp",
  "iconUrl": "https://myapp.com/icon-256.png"
}
```

The manifest URL is passed to `TosConnect` / `TosConnectProvider`. Wallets display this info when asking the user to approve the connection.

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
