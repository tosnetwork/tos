/**
 * HTTP bridge client for @tos/connect.
 *
 * - POST /message  — send an encrypted message to the wallet
 * - GET  /events   — SSE stream for incoming wallet messages
 *
 * All payloads are NaCl-box encrypted end-to-end; the bridge only relays
 * opaque blobs.
 */

import { bytesToHex } from "./utils.js";
import { encryptMessage, decryptMessage, type SessionKeypair } from "./session.js";
import { bridgeUnreachableError, TosConnectError } from "./errors.js";
import { toBase64Url, fromBase64Url } from "./utils.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BridgeClientOptions {
  /** Full bridge base URL (e.g. "https://bridge.tos.network/bridge"). */
  bridgeUrl: string;
  /** Our session keypair. */
  keypair: SessionKeypair;
  /** Wallet's Curve25519 public key (set after connect). */
  walletPublicKey?: Uint8Array;
  /** Default message TTL in seconds. */
  defaultTtl?: number;
}

export interface BridgeMessage {
  /** Hex-encoded sender public key. */
  from: string;
  /** Decrypted payload as UTF-8 string. */
  data: string;
}

type MessageHandler = (message: BridgeMessage) => void;
type ErrorHandler = (error: Error) => void;

// ---------------------------------------------------------------------------
// BridgeClient
// ---------------------------------------------------------------------------

export class BridgeClient {
  private readonly bridgeUrl: string;
  private readonly keypair: SessionKeypair;
  private walletPublicKey: Uint8Array | null;
  private readonly defaultTtl: number;

  private eventSource: EventSource | null = null;
  private messageHandlers: MessageHandler[] = [];
  private errorHandlers: ErrorHandler[] = [];
  private _closed = false;

  /** Reconnection configuration. */
  private reconnectEnabled: boolean;
  private maxRetries: number;
  private backoffMs: number;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    options: BridgeClientOptions,
    reconnect?: { enabled?: boolean; maxRetries?: number; backoffMs?: number },
  ) {
    this.bridgeUrl = options.bridgeUrl.replace(/\/+$/, "");
    this.keypair = options.keypair;
    this.walletPublicKey = options.walletPublicKey ?? null;
    this.defaultTtl = options.defaultTtl ?? 300;
    this.reconnectEnabled = reconnect?.enabled ?? true;
    this.maxRetries = reconnect?.maxRetries ?? 5;
    this.backoffMs = reconnect?.backoffMs ?? 1500;
  }

  /** Our hex-encoded client ID (Curve25519 public key). */
  get clientId(): string {
    return bytesToHex(this.keypair.publicKey);
  }

  /** Set the wallet's public key (known after connect handshake). */
  setWalletPublicKey(key: Uint8Array): void {
    this.walletPublicKey = key;
  }

  // -----------------------------------------------------------------------
  // Send
  // -----------------------------------------------------------------------

  /**
   * Send an encrypted message to the wallet via the bridge.
   *
   * @param data  UTF-8 string payload (typically JSON).
   * @param recipientPublicKey  Override recipient (defaults to walletPublicKey).
   * @param ttl   Message TTL in seconds.
   */
  async send(
    data: string,
    recipientPublicKey?: Uint8Array,
    ttl?: number,
  ): Promise<void> {
    const target = recipientPublicKey ?? this.walletPublicKey;
    if (!target) {
      throw new TosConnectError(
        "Cannot send: wallet public key not set",
        "BRIDGE_UNREACHABLE",
      );
    }

    const plaintext = new TextEncoder().encode(data);
    const encrypted = encryptMessage(plaintext, target, this.keypair.secretKey);
    const body = toBase64Url(encrypted);

    const recipientId = bytesToHex(target);
    const url = `${this.bridgeUrl}/message?client_id=${this.clientId}&to=${recipientId}&ttl=${ttl ?? this.defaultTtl}`;

    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body,
      });
    } catch (err) {
      throw bridgeUnreachableError(
        `Failed to POST to bridge: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!response.ok) {
      throw bridgeUnreachableError(
        `Bridge returned HTTP ${response.status}: ${response.statusText}`,
      );
    }
  }

  // -----------------------------------------------------------------------
  // SSE Event stream
  // -----------------------------------------------------------------------

  /**
   * Open an SSE connection to the bridge to receive wallet messages.
   *
   * Messages are decrypted automatically and dispatched to handlers.
   */
  listen(): void {
    if (this._closed) return;
    this.closeEventSource();

    const url = `${this.bridgeUrl}/events?client_id=${this.clientId}`;

    // EventSource is only available in browser-like environments.
    if (typeof EventSource === "undefined") {
      for (const handler of this.errorHandlers) {
        handler(new Error("EventSource is not available in this environment"));
      }
      return;
    }

    const es = new EventSource(url);
    this.eventSource = es;

    es.onopen = () => {
      this.reconnectAttempt = 0;
    };

    es.onmessage = (event: MessageEvent) => {
      try {
        const raw = JSON.parse(event.data as string) as {
          from: string;
          message: string;
        };

        const senderPk = hexToBytesSafe(raw.from);
        if (!senderPk) return;

        const encryptedBytes = fromBase64Url(raw.message);
        const decrypted = decryptMessage(
          encryptedBytes,
          senderPk,
          this.keypair.secretKey,
        );
        if (!decrypted) return;

        const decoded = new TextDecoder().decode(decrypted);
        const msg: BridgeMessage = { from: raw.from, data: decoded };

        for (const handler of this.messageHandlers) {
          handler(msg);
        }
      } catch {
        // Malformed message — skip silently.
      }
    };

    es.onerror = () => {
      if (this._closed) return;
      this.closeEventSource();
      this.scheduleReconnect();
    };
  }

  /** Register a handler for incoming (decrypted) messages. */
  onMessage(handler: MessageHandler): () => void {
    this.messageHandlers.push(handler);
    return () => {
      this.messageHandlers = this.messageHandlers.filter((h) => h !== handler);
    };
  }

  /** Register a handler for bridge errors. */
  onError(handler: ErrorHandler): () => void {
    this.errorHandlers.push(handler);
    return () => {
      this.errorHandlers = this.errorHandlers.filter((h) => h !== handler);
    };
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  /** Pause the SSE connection (e.g. when the tab goes to background). */
  pause(): void {
    this.closeEventSource();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  /** Resume the SSE connection. */
  resume(): void {
    if (!this._closed) {
      this.reconnectAttempt = 0;
      this.listen();
    }
  }

  /** Permanently close the bridge client. */
  close(): void {
    this._closed = true;
    this.closeEventSource();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.messageHandlers = [];
    this.errorHandlers = [];
  }

  get closed(): boolean {
    return this._closed;
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  private closeEventSource(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  private scheduleReconnect(): void {
    if (!this.reconnectEnabled) return;
    if (this.reconnectAttempt >= this.maxRetries) {
      for (const handler of this.errorHandlers) {
        handler(
          bridgeUnreachableError(
            `SSE reconnect failed after ${this.maxRetries} attempts`,
          ),
        );
      }
      return;
    }

    const delay = this.backoffMs * Math.pow(2, this.reconnectAttempt);
    this.reconnectAttempt++;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.listen();
    }, delay);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytesSafe(hex: string): Uint8Array | null {
  try {
    if (hex.length % 2 !== 0) return null;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      const byte = parseInt(hex.substring(i, i + 2), 16);
      if (Number.isNaN(byte)) return null;
      bytes[i / 2] = byte;
    }
    return bytes;
  } catch {
    return null;
  }
}
