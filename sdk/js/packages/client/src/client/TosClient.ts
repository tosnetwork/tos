/**
 * @tos/client — TosClient implementation.
 *
 * Full JSON-RPC 2.0 client that implements the {@link TosProvider} interface.
 * Uses `globalThis.fetch` for isomorphic HTTP.
 */

import type { TosProvider, AddressLike, CellLike, TupleItemLike, BlockQueryOpts } from "../provider/TosProvider.js";
import type {
  AccountInfo,
  ExtendedAccountInfo,
  WalletInfo,
  FeeEstimate,
  MasterchainInfo,
  ConsensusBlock,
  RunResult,
  LocateResult,
  ReadyzResult,
  OutMsgQueueSize,
  BlockIdExt,
  BlockHeader,
  BlockSignatures,
  ShardInfo,
  ShardBlockProof,
  ConfigAll,
  LibraryEntry,
  TokenData,
  AccountCapability,
  DelegationGrant,
  SessionCapability,
  AgentCapability,
  TransactionIntentRequest,
  TransactionIntent,
  SigningPayloadRequest,
  SigningPayload,
  SubmitSignedRequest,
  SubmissionResult,
  BlockTransactions,
  BlockTransactionsExt,
  Transaction,
  SendBocResult,
  SendBocHashResult,
  SendQueryResult,
} from "../types.js";
import { TosError, TosRpcError, ErrorCodes } from "../errors.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface TosClientOptions {
  /** JSON-RPC endpoint URL (required). */
  endpoint: string;
  /** Optional API key sent as `X-API-Key` header. */
  apiKey?: string;
  /** Per-request timeout in milliseconds (default 30 000). */
  timeout?: number;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof globalThis.fetch;
  /** Maximum retry attempts on transient failures (default 3, 0 = no retry). */
  retry?: number;
  /** Hook called before each HTTP request. */
  onRequest?: (method: string, params: Record<string, unknown>) => void;
  /** Hook called after a successful HTTP response. */
  onResponse?: (method: string, result: unknown) => void;
  /** Hook called on error. */
  onError?: (method: string, error: Error) => void;
}

// ---------------------------------------------------------------------------
// TosClient
// ---------------------------------------------------------------------------

/**
 * Full JSON-RPC 2.0 client for the TOS blockchain.
 *
 * Implements the {@link TosProvider} interface with automatic retries,
 * configurable timeouts, and optional API key authentication.
 *
 * @example
 * ```typescript
 * const client = new TosClient({ endpoint: "https://rpc.tos.network" });
 *
 * // Query account balance
 * const info = await client.getAddressInformation("0:abc...");
 * console.log(info.balance);
 *
 * // Run a get method
 * const result = await client.runGetMethod("0:abc...", "seqno");
 * ```
 */
export class TosClient implements TosProvider {
  private readonly endpoint: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly maxRetries: number;
  private readonly onRequest?: TosClientOptions["onRequest"];
  private readonly onResponse?: TosClientOptions["onResponse"];
  private readonly onError?: TosClientOptions["onError"];
  private requestId = 0;

  /**
   * Create a new TOS JSON-RPC client.
   *
   * @param options - Client configuration (endpoint is required)
   *
   * @example
   * ```typescript
   * // Simple usage
   * const client = new TosClient({ endpoint: "http://localhost:8081" });
   *
   * // With API key and custom timeout
   * const client = new TosClient({
   *   endpoint: "https://rpc.tos.network",
   *   apiKey: "your-api-key",
   *   timeout: 10_000,
   * });
   *
   * // Using network presets
   * const client = new TosClient({ ...Networks.mainnet, apiKey: "..." });
   * ```
   */
  constructor(options: TosClientOptions) {
    this.endpoint = options.endpoint.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeout ?? 30_000;
    this.fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.maxRetries = options.retry ?? 3;
    this.onRequest = options.onRequest;
    this.onResponse = options.onResponse;
    this.onError = options.onError;
  }

  // -----------------------------------------------------------------------
  // Low-level JSON-RPC transport
  // -----------------------------------------------------------------------

  /**
   * Execute a raw JSON-RPC call with automatic retry on transient failures.
   *
   * @param method - The JSON-RPC method name
   * @param params - Method parameters
   * @returns The JSON-RPC result
   * @throws {TosRpcError} On deterministic RPC errors
   * @throws {TosError} On timeout or exhausted retries
   *
   * @example
   * ```typescript
   * const info = await client.rawCall("getAddressInformation", { address: "0:abc..." });
   * ```
   */
  async rawCall<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    this.onRequest?.(method, params);

    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: ++this.requestId,
      method,
      params,
    });

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 200ms, 400ms, 800ms, ...
        const delay = Math.min(200 * Math.pow(2, attempt - 1), 5000);
        await sleep(delay);
      }

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        let response: Response;
        try {
          response = await this.fetchFn(this.endpoint, {
            method: "POST",
            headers,
            body,
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timer);
        }

        const responseText = await response.text();
        const json = parseJsonRpcResponse(response, responseText);

        if (json.error) {
          const rpcErr = new TosRpcError(
            json.error.message ?? "RPC error",
            json.error.code ?? ErrorCodes.INTERNAL_ERROR,
            json.error.data,
          );
          this.onError?.(method, rpcErr);
          throw rpcErr;
        }

        const result = json.result as T;
        this.onResponse?.(method, result);
        return result;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        // Do not retry on RPC errors (they are deterministic).
        if (err instanceof TosRpcError) {
          throw err;
        }

        if (err instanceof TosError && !isRetryableError(err)) {
          throw err;
        }

        // AbortError = timeout
        if (lastError.name === "AbortError") {
          lastError = new TosError(
            `Request to ${method} timed out after ${this.timeoutMs}ms`,
            ErrorCodes.TIMEOUT,
            lastError,
          );
        }

        this.onError?.(method, lastError);

        // Last attempt — don't retry.
        if (attempt === this.maxRetries) {
          break;
        }
      }
    }

    throw new TosError(
      `Request to ${method} failed after ${this.maxRetries + 1} attempts: ${lastError?.message}`,
      ErrorCodes.RETRY_EXHAUSTED,
      lastError,
    );
  }

  // -----------------------------------------------------------------------
  // AccountActions
  // -----------------------------------------------------------------------

  /**
   * Get account information including balance, state, code, and data.
   *
   * @param address - Account address (raw string or AddressLike object)
   * @param opts - Optional block query options (e.g. specific seqno)
   * @returns Account information
   *
   * @example
   * ```typescript
   * const info = await client.getAddressInformation("0:abc...");
   * console.log(info.balance, info.state);
   * ```
   */
  async getAddressInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AccountInfo> {
    return this.rawCall<AccountInfo>("getAddressInformation", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  /**
   * Get extended account information with additional details.
   *
   * @param address - Account address
   * @param opts - Optional block query options
   * @returns Extended account information
   */
  async getExtendedAddressInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<ExtendedAccountInfo> {
    return this.rawCall<ExtendedAccountInfo>("getExtendedAddressInformation", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  /**
   * Get wallet-specific information including seqno and wallet type.
   *
   * @param address - Wallet address
   * @param opts - Optional block query options
   * @returns Wallet information including seqno
   */
  async getWalletInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<WalletInfo> {
    return this.rawCall<WalletInfo>("getWalletInformation", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  /**
   * Get the account balance in nanoTOS as a string.
   *
   * @param address - Account address
   * @param opts - Optional block query options
   * @returns Balance string in nanoTOS
   */
  async getBalance(address: AddressLike | string, opts?: BlockQueryOpts): Promise<string> {
    return this.rawCall<string>("getAddressBalance", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  async getState(address: AddressLike | string, opts?: BlockQueryOpts): Promise<string> {
    return this.rawCall<string>("getAddressState", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  async getAccountCapability(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AccountCapability> {
    return this.rawCall<AccountCapability>("getAccountCapability", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  async getAccountDelegations(address: AddressLike | string, opts?: BlockQueryOpts): Promise<DelegationGrant[]> {
    const result = await this.rawCall<{ delegations: DelegationGrant[] }>("getAccountDelegations", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
    return result.delegations ?? [];
  }

  async getAccountSessions(address: AddressLike | string, opts?: BlockQueryOpts): Promise<SessionCapability[]> {
    const result = await this.rawCall<{ sessions: SessionCapability[] }>("getAccountSessions", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
    return result.sessions ?? [];
  }

  async getAccountAgents(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AgentCapability[]> {
    const result = await this.rawCall<{ agents: AgentCapability[] }>("getAccountAgents", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
    return result.agents ?? [];
  }

  // -----------------------------------------------------------------------
  // BlockActions
  // -----------------------------------------------------------------------

  /**
   * Get the current masterchain block info.
   *
   * @returns Masterchain info including the latest seqno
   *
   * @example
   * ```typescript
   * const info = await client.getMasterchainInfo();
   * console.log(info.last.seqno);
   * ```
   */
  async getMasterchainInfo(): Promise<MasterchainInfo> {
    return this.rawCall<MasterchainInfo>("getMasterchainInfo");
  }

  async getConsensusBlock(): Promise<ConsensusBlock> {
    return this.rawCall<ConsensusBlock>("getConsensusBlock");
  }

  async lookupBlock(
    workchain: number,
    shard: string,
    seqno: number,
    opts?: { lt?: string; utime?: number },
  ): Promise<BlockIdExt> {
    return this.rawCall<BlockIdExt>("lookupBlock", {
      workchain,
      shard,
      seqno,
      ...(opts?.lt != null ? { lt: opts.lt } : {}),
      ...(opts?.utime != null ? { unixtime: opts.utime } : {}),
    });
  }

  async getBlockHeader(workchain: number, shard: string, seqno: number): Promise<BlockHeader> {
    return this.rawCall<BlockHeader>("getBlockHeader", { workchain, shard, seqno });
  }

  async getShards(seqno: number): Promise<ShardInfo> {
    return this.rawCall<ShardInfo>("shards", { seqno });
  }

  async getMasterchainBlockSignatures(seqno: number): Promise<BlockSignatures> {
    return this.rawCall<BlockSignatures>("getMasterchainBlockSignatures", { seqno });
  }

  async getShardBlockProof(workchain: number, shard: string, seqno: number): Promise<ShardBlockProof> {
    return this.rawCall<ShardBlockProof>("getShardBlockProof", { workchain, shard, seqno });
  }

  // -----------------------------------------------------------------------
  // TransactionActions
  // -----------------------------------------------------------------------

  async getTransactions(
    address: AddressLike | string,
    limit: number,
    opts?: { lt?: string; hash?: string; to_lt?: string; archival?: boolean },
  ): Promise<Transaction[]> {
    return this.rawCall<Transaction[]>("getTransactions", {
      address: toAddrString(address),
      limit,
      ...(opts?.lt != null ? { lt: opts.lt } : {}),
      ...(opts?.hash != null ? { hash: opts.hash } : {}),
      ...(opts?.to_lt != null ? { to_lt: opts.to_lt } : {}),
      ...(opts?.archival != null ? { archival: opts.archival } : {}),
    });
  }

  async getBlockTransactions(
    workchain: number,
    shard: string,
    seqno: number,
    opts?: { count?: number; after_lt?: string; after_hash?: string },
  ): Promise<BlockTransactions> {
    return this.rawCall<BlockTransactions>("getBlockTransactions", {
      workchain,
      shard,
      seqno,
      ...(opts?.count != null ? { count: opts.count } : {}),
      ...(opts?.after_lt != null ? { after_lt: opts.after_lt } : {}),
      ...(opts?.after_hash != null ? { after_hash: opts.after_hash } : {}),
    });
  }

  async getBlockTransactionsExt(
    workchain: number,
    shard: string,
    seqno: number,
    opts?: { count?: number; after_lt?: string; after_hash?: string },
  ): Promise<BlockTransactionsExt> {
    return this.rawCall<BlockTransactionsExt>("getBlockTransactionsExt", {
      workchain,
      shard,
      seqno,
      ...(opts?.count != null ? { count: opts.count } : {}),
      ...(opts?.after_lt != null ? { after_lt: opts.after_lt } : {}),
      ...(opts?.after_hash != null ? { after_hash: opts.after_hash } : {}),
    });
  }

  async tryLocateTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult> {
    return this.rawCall<LocateResult>("tryLocateTx", {
      source: toAddrString(source),
      destination: toAddrString(destination),
      created_lt,
    });
  }

  async tryLocateResultTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult> {
    return this.rawCall<LocateResult>("tryLocateResultTx", {
      source: toAddrString(source),
      destination: toAddrString(destination),
      created_lt,
    });
  }

  async tryLocateSourceTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult> {
    return this.rawCall<LocateResult>("tryLocateSourceTx", {
      source: toAddrString(source),
      destination: toAddrString(destination),
      created_lt,
    });
  }

  // -----------------------------------------------------------------------
  // ContractActions
  // -----------------------------------------------------------------------

  /**
   * Execute a get-method on a smart contract.
   *
   * @param address - Contract address
   * @param method - Get-method name or numeric ID
   * @param stack - Optional TVM stack arguments
   * @param opts - Optional block query options
   * @returns The get-method result including exit code and stack
   *
   * @example
   * ```typescript
   * const result = await client.runGetMethod("0:abc...", "seqno");
   * console.log(result.exit_code, result.stack);
   * ```
   */
  async runGetMethod(
    address: AddressLike | string,
    method: string | number,
    stack?: TupleItemLike[],
    opts?: BlockQueryOpts,
  ): Promise<RunResult> {
    return this.rawCall<RunResult>("runGetMethod", {
      address: toAddrString(address),
      method,
      stack: serializeStack(stack ?? []),
      ...seqnoParam(opts),
    });
  }

  // -----------------------------------------------------------------------
  // SendActions
  // -----------------------------------------------------------------------

  /**
   * Send a serialized BOC (external message) to the network.
   *
   * @param boc - Serialized message as a Cell, Uint8Array, or base64 string
   * @returns Send result with status
   *
   * @example
   * ```typescript
   * await client.sendBoc(signedMessageCell.toBoc());
   * ```
   */
  async sendBoc(boc: CellLike | Uint8Array | string): Promise<SendBocResult> {
    return this.rawCall<SendBocResult>("sendBoc", {
      boc: toBocString(boc),
    });
  }

  /**
   * Send a serialized BOC and return the transaction hash.
   *
   * @param boc - Serialized message as a Cell, Uint8Array, or base64 string
   * @returns Send result with the message hash
   */
  async sendBocReturnHash(boc: CellLike | Uint8Array | string): Promise<SendBocHashResult> {
    return this.rawCall<SendBocHashResult>("sendBocReturnHash", {
      boc: toBocString(boc),
    });
  }

  async sendQuery(body: {
    address: AddressLike | string;
    body: CellLike | string;
    init_code?: CellLike | string;
    init_data?: CellLike | string;
  }): Promise<SendQueryResult> {
    return this.rawCall<SendQueryResult>("sendQuery", {
      address: toAddrString(body.address),
      body: toBocString(body.body),
      ...(body.init_code != null ? { init_code: toBocString(body.init_code) } : {}),
      ...(body.init_data != null ? { init_data: toBocString(body.init_data) } : {}),
    });
  }

  /**
   * Estimate the fee for a message without actually sending it.
   *
   * @param address - Target contract address
   * @param body - Message body as a Cell or base64 string
   * @param init_code - Optional init code for deploy
   * @param init_data - Optional init data for deploy
   * @param ignore_chksig - Whether to ignore signature verification
   * @returns Fee estimate
   */
  async estimateFee(
    address: AddressLike | string,
    body: CellLike | string,
    init_code?: CellLike | string,
    init_data?: CellLike | string,
    ignore_chksig?: boolean,
  ): Promise<FeeEstimate> {
    return this.rawCall<FeeEstimate>("estimateFee", {
      address: toAddrString(address),
      body: toBocString(body),
      ...(init_code != null ? { init_code: toBocString(init_code) } : {}),
      ...(init_data != null ? { init_data: toBocString(init_data) } : {}),
      ...(ignore_chksig != null ? { ignore_chksig } : {}),
    });
  }

  // -----------------------------------------------------------------------
  // IntentActions
  // -----------------------------------------------------------------------

  async buildTransactionIntent(request: TransactionIntentRequest): Promise<TransactionIntent> {
    return this.rawCall<TransactionIntent>("buildTransactionIntent", { ...request });
  }

  async getSigningPayload(request: SigningPayloadRequest): Promise<SigningPayload> {
    return this.rawCall<SigningPayload>("getSigningPayload", { ...request });
  }

  async submitSignedTransaction(request: SubmitSignedRequest): Promise<SubmissionResult> {
    return this.rawCall<SubmissionResult>("submitSignedTransaction", { ...request });
  }

  // -----------------------------------------------------------------------
  // ConfigActions
  // -----------------------------------------------------------------------

  async getConfigParam(param: number, opts?: BlockQueryOpts): Promise<{ config: { bytes: string } }> {
    return this.rawCall<{ config: { bytes: string } }>("getConfigParam", {
      param,
      ...seqnoParam(opts),
    });
  }

  async getConfigAll(opts?: BlockQueryOpts): Promise<ConfigAll> {
    return this.rawCall<ConfigAll>("getConfigAll", {
      ...seqnoParam(opts),
    });
  }

  async getLibraries(libraryList: string[]): Promise<LibraryEntry[]> {
    const result = await this.rawCall<{ result: LibraryEntry[] }>("getLibraries", {
      library_list: libraryList,
    });
    return result.result ?? [];
  }

  async getTokenData(address: AddressLike | string): Promise<TokenData> {
    return this.rawCall<TokenData>("getTokenData", {
      address: toAddrString(address),
    });
  }

  async getOutMsgQueueSize(): Promise<OutMsgQueueSize> {
    return this.rawCall<OutMsgQueueSize>("getOutMsgQueueSize");
  }

  async isReady(): Promise<ReadyzResult> {
    return this.rawCall<ReadyzResult>("readyz");
  }
}

// ---------------------------------------------------------------------------
// JSON-RPC response shape
// ---------------------------------------------------------------------------

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

function parseJsonRpcResponse(response: Response, responseText: string): JsonRpcResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(responseText) as unknown;
  } catch (cause) {
    throw new TosError(
      `Invalid JSON response (${response.status}) from ${response.url || "RPC endpoint"}`,
      ErrorCodes.INVALID_RESPONSE,
      cause instanceof Error ? cause : undefined,
    );
  }

  if (!isJsonRpcResponse(parsed)) {
    throw new TosError(
      `Invalid JSON-RPC response (${response.status}) from ${response.url || "RPC endpoint"}`,
      ErrorCodes.INVALID_RESPONSE,
    );
  }

  if (!response.ok) {
    if (parsed.error) {
      return parsed;
    }
    // 4xx = client error (not retryable), 5xx = server error (retryable)
    const code = response.status >= 400 && response.status < 500
      ? ErrorCodes.CLIENT_ERROR
      : ErrorCodes.NETWORK_ERROR;
    throw new TosError(
      `HTTP ${response.status} ${response.statusText || "request failed"}`,
      code,
    );
  }

  return parsed;
}

function isJsonRpcResponse(value: unknown): value is JsonRpcResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return candidate["jsonrpc"] === "2.0"
    && ("result" in candidate || "error" in candidate);
}

function isRetryableError(error: TosError): boolean {
  return error.code === ErrorCodes.NETWORK_ERROR || error.code === ErrorCodes.TIMEOUT;
}

// ---------------------------------------------------------------------------
// Parameter serialization helpers
// ---------------------------------------------------------------------------

function toAddrString(address: AddressLike | string): string {
  if (typeof address === "string") return address;
  return address.toRawString();
}

function toBocString(value: CellLike | Uint8Array | string): string {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return bytesToBase64(value);
  // CellLike — serialize via toBoc(), then base64-encode the result.
  const boc = value.toBoc();
  // toBoc() may return a Uint8Array (e.g. @tos/core Cell) or an object with
  // toString("base64") (legacy compat).  Handle both without relying on Buffer.
  if (boc instanceof Uint8Array) return bytesToBase64(boc);
  return boc.toString("base64");
}

function seqnoParam(opts?: BlockQueryOpts): Record<string, number> {
  if (opts?.seqno != null && opts.seqno > 0) {
    return { seqno: opts.seqno };
  }
  return {};
}

function serializeStack(stack: TupleItemLike[]): unknown[] {
  return stack.map((item) => {
    switch (item.type) {
      case "int":
        // C++ expects hex-prefixed string for integer stack entries
        return ["num", "0x" + item.value.toString(16)];
      case "cell":
        return ["cell", { bytes: toBocString(item.cell) }];
      case "slice":
        return ["slice", { bytes: toBocString(item.cell) }];
      case "builder":
        return ["builder", { bytes: toBocString(item.cell) }];
      case "null":
        return ["null", ""];
      default:
        return ["null", ""];
    }
  });
}

function bytesToBase64(bytes: Uint8Array): string {
  // Pure-JS base64 encoding -- works in Node.js 16+ and all modern browsers.
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
